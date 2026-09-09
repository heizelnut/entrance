package wg

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
)

// UDPTransport relays datagrams over a real UDP socket. It is the phase 2
// "wireguard directly over UDP" transport (D1): both sides send datagrams to
// the peer's public UDP endpoint the way classic WireGuard deployments do.
//
// Phase 1 note: the daemon deliberately does not open any inbound port; this
// transport exists as the stub for the optional phase 2 direct path and is
// exercised by unit tests on loopback.
type UDPTransport struct {
	mu       sync.Mutex // guards conn/peerAddr
	conn     *net.UDPConn
	peerAddr *net.UDPAddr
	gate     *recvGate
	closed   atomic.Bool
	recvWG   sync.WaitGroup

	bindAddrVal string
}

// NewUDPTransport constructs a UDP transport that binds to bindAddr and sends
// datagrams to peerAddr. It does not open the socket until Open is called.
func NewUDPTransport(bindAddr, peerAddr string) (*UDPTransport, error) {
	peer, err := net.ResolveUDPAddr("udp4", peerAddr)
	if err != nil {
		return nil, err
	}
	return &UDPTransport{
		peerAddr:    peer,
		bindAddrVal: bindAddr,
		gate:        newRecvGate(1024),
	}, nil
}

func (u *UDPTransport) SetRecvCB(cb func(data []byte)) { u.gate.setCB(cb) }

// Open binds the local socket and starts the receive loop.
func (u *UDPTransport) Open() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.conn != nil {
		return nil
	}
	laddr, err := net.ResolveUDPAddr("udp4", u.bindAddrVal)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		return err
	}
	u.conn = conn
	u.recvWG.Add(1)
	go u.recvLoop()
	return nil
}

func (u *UDPTransport) recvLoop() {
	defer u.recvWG.Done()
	buf := make([]byte, 65536)
	for {
		u.mu.Lock()
		conn := u.conn
		u.mu.Unlock()
		if conn == nil {
			return
		}
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if u.closed.Load() {
				return
			}
			continue
		}
		cp := make([]byte, n)
		copy(cp, buf[:n])
		u.gate.deliver(cp)
	}
}

func (u *UDPTransport) Send(data []byte) error {
	u.mu.Lock()
	conn := u.conn
	peer := u.peerAddr
	u.mu.Unlock()
	if conn == nil {
		return errors.New("udp transport not open")
	}
	if peer == nil {
		return errors.New("udp transport has no peer endpoint")
	}
	_, err := conn.WriteToUDP(append([]byte(nil), data...), peer)
	return err
}

func (u *UDPTransport) Deliver(data []byte) {
	u.gate.deliver(data)
}

func (u *UDPTransport) Close() error {
	if u.closed.Swap(true) {
		return nil
	}
	u.mu.Lock()
	conn := u.conn
	u.conn = nil
	u.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	u.recvWG.Wait()
	return nil
}

var _ Transport = (*UDPTransport)(nil)
