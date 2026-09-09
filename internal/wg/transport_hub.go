package wg

import (
	"errors"
	"fmt"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// EndpointSender is implemented by transports that can route outgoing
// datagrams by peer endpoint. transportBind uses it when present.
type EndpointSender interface {
	// SendTo delivers one datagram towards the endpoint that wireguard-go
	// associated with the packet (which encodes the destination peer for us).
	SendTo(data []byte, ep conn.Endpoint) error
}

// HubTransport routes outbound datagrams from the bastion's wireguard-go hub
// device to per-daemon WebSocket control channels. Endpoints carry a unique
// per-daemon token (see api.endpointToken); the transport maps token -> sink.
//
// Inbound datagrams from any daemon are funnelled into the hub device through
// the single ReceiveFunc registered via SetRecvCB (the device demultiplexes
// by peer identity internally).
type HubTransport struct {
	mu     sync.RWMutex
	byPort map[uint16]DatagramWriter
	cb     func([]byte)
}

// NewHubTransport creates an empty hub routing transport. Register must be
// called for each connected daemon before it can receive datagrams.
func NewHubTransport() *HubTransport {
	return &HubTransport{byPort: map[uint16]DatagramWriter{}}
}

// Register binds a daemon sink to its endpoint token.
func (h *HubTransport) Register(token uint16, w DatagramWriter) {
	h.mu.Lock()
	h.byPort[token] = w
	h.mu.Unlock()
}

// Unregister removes a daemon sink. Identity-guarded: on a daemon reconnect
// the new connection re-registers the same token before the old connection's
// read loop finally errors, so an unconditional delete would drop datagrams
// for the live connection (the old handler's deferred Unregister firing
// last). Only the registration owned by the given writer is removed.
func (h *HubTransport) Unregister(token uint16, owner DatagramWriter) {
	h.mu.Lock()
	if cur, ok := h.byPort[token]; ok && cur == owner {
		delete(h.byPort, token)
	}
	h.mu.Unlock()
}

// Lookup returns the sink bound to a token.
func (h *HubTransport) Lookup(token uint16) (DatagramWriter, bool) {
	h.mu.RLock()
	w, ok := h.byPort[token]
	h.mu.RUnlock()
	return w, ok
}

// SendTo sends a datagram to the peer encoded in ep (a loopEndpoint whose
// port is the daemon token).
func (h *HubTransport) SendTo(data []byte, ep conn.Endpoint) error {
	var token uint16
	switch e := ep.(type) {
	case loopEndpoint:
		token = e.port
	default:
		return errors.New("hub transport: unexpected endpoint type")
	}
	h.mu.RLock()
	w, ok := h.byPort[token]
	h.mu.RUnlock()
	if !ok {
		// Fast path stays allocation-free; only build the census for the
		// (rare) miss so the error message is actionable.
		h.mu.RLock()
		keys := make([]uint16, 0, len(h.byPort))
		for k := range h.byPort {
			keys = append(keys, k)
		}
		h.mu.RUnlock()
		return fmt.Errorf("hub transport: no daemon attached for token %d (have %v)", token, keys)
	}
	return w.WriteDatagram(data)
}

// Transport interface plumbing ----------------------------------------------

func (h *HubTransport) SetRecvCB(cb func(data []byte)) { h.cb = cb }

func (h *HubTransport) Send(data []byte) error {
	return errors.New("hub transport requires SendTo with endpoint")
}

// Deliver funnels an inbound datagram into the hub device.
func (h *HubTransport) Deliver(data []byte) {
	if h.cb != nil {
		h.cb(data)
	}
}

func (h *HubTransport) Close() error { return nil }

var _ Transport = (*HubTransport)(nil)
var _ EndpointSender = (*HubTransport)(nil)
