package daemon

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// proxyListener exposes one allowlisted port: connections received on the
// agent's listen address are spliced to a local target (127.0.0.1:<remapped>).
// The allowlist is enforced by the bastion at relay-creation time AND here at
// the application layer (D4) — a kernel-level bypass is impossible because
// the WG tunnel only ever carries relay-session traffic.
type proxyListener struct {
	ln         net.Listener
	targetPort int           // exposed target port
	localPort  int           // dialed local port (after remap)
	sem        chan struct{} // bound concurrent sessions
	closed     atomic.Bool
	wg         sync.WaitGroup
	onClose    func()
}

func (p *proxyListener) serve() {
	p.wg.Add(1)
	defer p.wg.Done()
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			// listener closed by us or by network error
			return
		}
		if p.closed.Load() {
			conn.Close()
			return
		}
		select {
		case p.sem <- struct{}{}:
		default:
			conn.Close() // session cap reached
			continue
		}
		p.wg.Add(1)
		go func(c net.Conn) {
			defer p.wg.Done()
			defer func() { <-p.sem }()
			p.handle(c)
		}(conn)
	}
}

func (p *proxyListener) handle(c net.Conn) {
	defer c.Close()
	peer, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(p.localPort)), 10*time.Second)
	if err != nil {
		return
	}
	defer peer.Close()
	// Full-close semantics: when EITHER direction ends (peer shut the tunnel
	// side, client disconnected, target died) close BOTH conns so no copy
	// goroutine can linger on an idle peer — an idle long-lived relay must not
	// block close() forever.
	var once sync.Once
	closeBoth := func() {
		once.Do(func() { c.Close(); peer.Close() })
	}
	done := make(chan struct{}, 2)
	copyDir := func(dst net.Conn, src net.Conn) {
		_, _ = io.Copy(dst, src)
		closeBoth()
		done <- struct{}{}
	}
	go copyDir(peer, c)
	go copyDir(c, peer)
	<-done
	<-done
}

func (p *proxyListener) close() {
	if p.closed.Swap(true) {
		return
	}
	_ = p.ln.Close()
	p.wg.Wait()
	if p.onClose != nil {
		p.onClose()
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	b := make([]byte, 0, 5)
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
