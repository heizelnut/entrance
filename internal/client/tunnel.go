package client

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// Tunnel exposes a daemon target port as a local TCP listener (the entrui
// "connect" engine and the e2e path): each accepted local connection opens
// the relay session's WebSocket and bridges bytes 1:1.
type Tunnel struct {
	LocalAddr  string
	DaemonID   int64
	TargetPort int

	client *Client
	ln     net.Listener
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Tunnel creates a relay session + local forward.
func (c *Client) Tunnel(ctx context.Context, daemonID int64, targetPort int) (*Tunnel, error) {
	resp, err := c.CreateRelay(ctx, daemonID, targetPort)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	t := &Tunnel{
		LocalAddr:  ln.Addr().String(),
		DaemonID:   daemonID,
		TargetPort: targetPort,
		client:     c,
		ln:         ln,
		ctx:        ctx,
		cancel:     cancel,
	}
	t.wg.Add(1)
	go t.acceptLoop(resp.SessionID)
	return t, nil
}

func (t *Tunnel) acceptLoop(sessionID string) {
	defer t.wg.Done()
	for {
		conn, err := t.ln.Accept()
		if err != nil {
			return
		}
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			t.bridge(sessionID, conn)
		}()
	}
}

func (t *Tunnel) bridge(sessionID string, local net.Conn) {
	defer local.Close()
	// Per-bridge context: cancelled by Tunnel.Close and on either direction's
	// EOF so no goroutine can block indefinitely in ws.Read/ws.Write.
	ctx, cancel := context.WithCancel(t.ctx)
	defer cancel()
	ws, err := t.client.RelayWS(ctx, sessionID)
	if err != nil {
		return
	}
	defer ws.Close(websocket.StatusNormalClosure, "")

	done := make(chan struct{}, 2)
	go func() {
		_ = copyConnToWS(ctx, local, ws)
		cancel()
		done <- struct{}{}
	}()
	go func() {
		_ = copyWSToConn(ctx, ws, local)
		cancel()
		done <- struct{}{}
	}()
	<-done
	<-done
}

// Close stops the listener and closes active bridges.
func (t *Tunnel) Close() error {
	t.cancel()
	err := t.ln.Close()
	t.wg.Wait()
	return err
}

// copyConnToWS streams TCP bytes as binary WS frames. The ctx bounds each
// write (cancellation + a per-write deadline against a wedged peer).
func copyConnToWS(ctx context.Context, r io.Reader, ws *websocket.Conn) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			werr := ws.Write(wctx, websocket.MessageBinary, buf[:n])
			cancel()
			if werr != nil {
				return werr
			}
		}
		if err != nil {
			return err
		}
	}
}

// copyWSToConn streams WS binary messages into the TCP conn.
func copyWSToConn(ctx context.Context, ws *websocket.Conn, w io.Writer) error {
	for {
		mt, data, err := ws.Read(ctx)
		if err != nil {
			return err
		}
		switch mt {
		case websocket.MessageBinary:
			if _, err := w.Write(data); err != nil {
				return err
			}
		case websocket.MessageText:
			// control frames ignored
		}
	}
}

// RelayEcho runs a quick end-to-end sanity check over a relay: dials the
// local tunnel and exchanges a line with the target service.
func (t *Tunnel) RelayEcho(ctx context.Context, payload []byte, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", t.LocalAddr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	deadline := time.Now().Add(timeout)
	conn.SetReadDeadline(deadline)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}
