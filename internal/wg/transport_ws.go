package wg

import (
	"sync/atomic"
)

// WebsocketTransport carries WireGuard datagrams inside the persistent
// control-channel WebSocket between daemon and bastion (D1). Datagrams are
// binary WebSocket frames; JSON control messages live on the same connection
// as text frames and are handled by the agent / ws_daemon handler.
//
// The transport does not own the read loop: the entity that owns the
// WebSocket (the daemon agent or the bastion ws handler) reads frames and
// calls Deliver for each binary frame. Send is safe for concurrent use.
type WebsocketTransport struct {
	conn   DatagramWriter
	gate   *recvGate
	closed atomic.Bool
}

// NewWebsocketTransport wraps a control-channel WebSocket for datagram I/O.
func NewWebsocketTransport(conn DatagramWriter) *WebsocketTransport {
	return &WebsocketTransport{conn: conn, gate: newRecvGate(1024)}
}

func (t *WebsocketTransport) SetRecvCB(cb func(data []byte)) { t.gate.setCB(cb) }

func (t *WebsocketTransport) Send(data []byte) error {
	if t.closed.Load() {
		return ErrTransportClosed
	}
	// wsproto.Conn serializes writes internally (control + datagrams share
	// one TCP stream); the peer direction needs no extra mutex.
	return t.conn.WriteDatagram(data)
}

func (t *WebsocketTransport) Deliver(data []byte) {
	if t.closed.Load() {
		return
	}
	t.gate.deliver(data)
}

func (t *WebsocketTransport) Close() error {
	t.closed.Store(true)
	return nil
}

var _ Transport = (*WebsocketTransport)(nil)
