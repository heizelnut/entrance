package wg

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/conn"
)

// transportBind implements wireguard-go's conn.Bind on top of a Transport.
//
// It binds a loopback-only UDP socket at 127.0.0.1:<port>. That socket is the
// wireguard-go device's official local address (the "loopback only" guarantee
// of D1 — no non-loopback interface is ever touched by the WG data plane).
// The socket is an anchor/endpoint identity for the device; datagrams
// themselves never traverse it:
//
//   - egress:  Bind.Send → transport.Send (over the control channel / memory pipe)
//   - ingress: transport recv side → bind.Deliver → queued → device ReceiveFunc
//
// wireguard-go calls the ReceiveFunc returned by Open in a "receive incoming"
// goroutine; we serve the next queued datagram from the current recv queue,
// and return net.ErrClosed once the bind is closed. wireguard-go's BindUpdate
// always closes then reopens the bind (e.g. on listen_port change), so Close
// is a soft reset that leaves the bind reopenable. Terminate is the final
// shutdown used when the device goes away.
//
// inboundDgram is a datagram queued for the device, tagged with the endpoint
// port the device should associate it with. Single-peer transports use the
// local anchor port; the hub binds per-daemon endpoint tokens (D1 routing).
type inboundDgram struct {
	port uint16
	data []byte
}

type transportBind struct {
	transport Transport
	localPort uint16

	mu   sync.RWMutex
	udp  *net.UDPConn
	recv chan inboundDgram
	stop chan struct{}
	open atomic.Bool

	terminated atomic.Bool
}

func newTransportBind(transport Transport, port uint16) *transportBind {
	return &transportBind{transport: transport, localPort: port}
}

// ----- wireguard-go conn.Bind interface -----

func (b *transportBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.terminated.Load() {
		return nil, 0, net.ErrClosed
	}
	if b.open.Swap(true) {
		b.closeLocked() // reset any previous (unexpected) open state
	}
	if b.localPort == 0 {
		b.localPort = port
	}
	laddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(b.localPort)}
	udp, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		return nil, 0, err
	}
	b.udp = udp
	b.recv = make(chan inboundDgram, 512)
	b.stop = make(chan struct{})
	// Bind the transport's receive path to this bind.
	b.transport.SetRecvCB(b.Deliver)
	local := b.localPort

	recvFn := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		b.mu.RLock()
		c, s := b.recv, b.stop
		b.mu.RUnlock()
		if c == nil {
			return 0, net.ErrClosed
		}
		select {
		case in := <-c:
			if len(packets) == 0 {
				return 0, nil
			}
			n := copy(packets[0], in.data[:])
			sizes[0] = n
			eps[0] = makeLoopEndpoint(in.port)
			return 1, nil
		case <-s:
			return 0, net.ErrClosed
		}
	}
	return []conn.ReceiveFunc{recvFn}, local, nil
}

// Deliver is the Transport receive entry point (registered via SetRecvCB).
// It applies backpressure by blocking while the device queue is full.
func (b *transportBind) Deliver(data []byte) {
	b.DeliverWithEP(b.localPort, data)
}

// DeliverWithEP queues a datagram tagged with the endpoint port the device
// should associate with it (the per-daemon token on the hub).
func (b *transportBind) DeliverWithEP(port uint16, data []byte) {
	if b.terminated.Load() {
		return
	}
	b.mu.RLock()
	c, s, open := b.recv, b.stop, b.open.Load()
	b.mu.RUnlock()
	if !open || c == nil {
		return
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	select {
	case c <- inboundDgram{port: port, data: cp}:
	case <-s:
	}
}

func (b *transportBind) SetMark(mark uint32) error { return nil }

func (b *transportBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if es, ok := b.transport.(EndpointSender); ok {
		for _, buf := range bufs {
			if err := es.SendTo(buf, ep); err != nil {
				return err
			}
		}
		return nil
	}
	for _, buf := range bufs {
		if err := b.transport.Send(buf); err != nil {
			return err
		}
	}
	return nil
}

func (b *transportBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	if !ap.Addr().IsLoopback() {
		return nil, errors.New("transport bind only supports loopback endpoints (got " + s + ")")
	}
	return loopEndpoint{ip: ap.Addr(), port: ap.Port()}, nil
}

func (b *transportBind) BatchSize() int { return 1 }

// Close resets the bind so wireguard-go can reopen it (BindUpdate pattern).
func (b *transportBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closeLocked()
	return nil
}

func (b *transportBind) closeLocked() {
	if !b.open.Swap(false) {
		return
	}
	if b.stop != nil {
		close(b.stop)
	}
	if b.udp != nil {
		_ = b.udp.Close()
		b.udp = nil
	}
	b.recv = nil
}

// Terminate irreversibly shuts the bind down (device gone).
func (b *transportBind) Terminate() {
	b.terminated.Store(true)
	b.Close()
}

// loopEndpoint is a wireguard-go conn.Endpoint whose src/dst is the local
// loopback socket. DstToBytes feeds the cookie-checker MAC computation; a
// stable fixed encoding is what matters.
type loopEndpoint struct {
	ip   netip.Addr
	port uint16
}

func makeLoopEndpoint(p uint16) conn.Endpoint {
	return loopEndpoint{ip: netip.AddrFrom4([4]byte{127, 0, 0, 1}), port: p}
}

func (e loopEndpoint) ClearSrc()           {}
func (e loopEndpoint) SrcToString() string { return netip.AddrPortFrom(e.ip, e.port).String() }
func (e loopEndpoint) DstToString() string { return netip.AddrPortFrom(e.ip, e.port).String() }
func (e loopEndpoint) SrcIP() netip.Addr   { return e.ip }
func (e loopEndpoint) DstIP() netip.Addr   { return e.ip }

// DstToBytes: 4-byte IPv4 + 2-byte big-endian port (matches StdNetEndpoint).
func (e loopEndpoint) DstToBytes() []byte {
	b := make([]byte, 0, 6)
	ip := e.ip.As4()
	b = append(b, ip[:]...)
	return binary.BigEndian.AppendUint16(b, e.port)
}

var _ conn.Bind = (*transportBind)(nil)
