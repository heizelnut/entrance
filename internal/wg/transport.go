package wg

import (
	"errors"
	"sync/atomic"
)

// ErrTransportClosed is returned by Transport.Send and Delivery callbacks
// after the transport has been closed.
var ErrTransportClosed = errors.New("wg transport closed")

// Transport moves encrypted WireGuard datagrams between a wireguard-go device
// (via transportBind, see bind.go) and its single remote peer.
//
// This is the abstraction that isolates all wireguard-go usage from the rest
// of the system — the control plane (bastion ↔ daemon) can carry the datagrams
// over any channel:
//
//   - WebsocketTransport (transport_ws.go): WireGuard rides inside the HTTPS
//     control-channel WebSocket — the phase 1 topology (D1).
//   - MemTransport: an in-memory pipe used by the rootless crypto test.
//   - UDPTransport (transport_udp.go): direct datagram transport, phase 2.
//
// Transports are single-peer. Datagram ordering is preserved.
type Transport interface {
	// Send delivers one datagram toward the remote peer. It is called from
	// the wireguard-go send path and must be safe for concurrent use.
	Send(data []byte) error
	// Deliver hands a datagram received from the remote peer to the local
	// wireguard-go device. It must be safe to call from any goroutine.
	Deliver(data []byte)
	// SetRecvCB registers the callback invoked by Deliver. It must be set
	// before the device starts processing packets. Datagrams delivered
	// before registration are queued (bounded) rather than dropped.
	SetRecvCB(cb func(data []byte))
	// Close releases all resources. Deliver after Close is a no-op.
	Close() error
}

// ---------- in-memory transport (rootless tests, single-host demos) ----------

// MemTransport is an in-memory Transport that pipes datagrams into a peer
// MemTransport. This is what makes the wireguard-go crypto test run without
// root: two wireguard-go devices connected over a memory pipe.
type MemTransport struct {
	peer *MemTransport
	gate *recvGate
	// Dropped counts queued datagrams evicted when the pre-callback buffer
	// overflowed (diagnostic; saturated buffers are vanishingly unlikely).
	Dropped atomic.Uint64
	closed  atomic.Bool
}

// NewMemPair creates two connected in-memory transports.
func NewMemPair() (a, b *MemTransport) {
	a = &MemTransport{gate: newRecvGate(1024)}
	b = &MemTransport{gate: newRecvGate(1024)}
	a.peer = b
	b.peer = a
	return a, b
}

func (m *MemTransport) SetRecvCB(cb func(data []byte)) { m.gate.setCB(cb) }

func (m *MemTransport) Send(data []byte) error {
	p := m.peer
	if p == nil || p.closed.Load() {
		return ErrTransportClosed
	}
	p.Deliver(data)
	return nil
}

// Deliver hands the datagram to the registered callback, or queues it until
// the callback is registered (kernel-socket semantics).
func (m *MemTransport) Deliver(data []byte) {
	cp := make([]byte, len(data))
	copy(cp, data)
	if !m.gate.deliver(cp) {
		m.Dropped.Add(1)
	}
}

func (m *MemTransport) Close() error {
	m.closed.Store(true)
	return nil
}
