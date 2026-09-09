package wsproto

import (
	"context"
	"encoding/json"
	"net"
	"sync"

	"github.com/coder/websocket"
)

// ErrClosed is returned by writes after the connection has been closed locally.
var ErrClosed = net.ErrClosed

// Frame kinds on the daemon control-channel WebSocket / relay WebSocket.
type FrameKind = websocket.MessageType

const (
	KindText   = websocket.MessageText
	KindBinary = websocket.MessageBinary
)

// Frame is one WebSocket message: either a WireGuard datagram (binary) or a
// JSON control message (text).
type Frame struct {
	Kind FrameKind
	Data []byte
}

// Conn wraps a coder/websocket connection with a write mutex so that control
// messages (text) and WG datagrams (binary) can be sent concurrently from
// different goroutines (heartbeat timer + WireGuard send path).
type Conn struct {
	ws     *websocket.Conn
	mu     sync.Mutex
	ctx    context.Context // long-lived write context
	cancel context.CancelFunc
}

// NewConn wraps an established websocket connection.
func NewConn(ws *websocket.Conn) *Conn {
	ctx, cancel := context.WithCancel(context.Background())
	return &Conn{ws: ws, ctx: ctx, cancel: cancel}
}

// WS exposes the underlying coder/websocket connection.
func (c *Conn) WS() *websocket.Conn { return c.ws }

// WriteDatagram sends one WireGuard datagram as a binary frame.
func (c *Conn) WriteDatagram(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ws == nil {
		return ErrClosed
	}
	return c.ws.Write(c.ctx, websocket.MessageBinary, data)
}

// WriteControl sends a JSON control message as a text frame.
func (c *Conn) WriteControl(v any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ws == nil {
		return ErrClosed
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.ws.Write(c.ctx, websocket.MessageText, b)
}

// WriteClose sends a text close control and then closes the socket.
func (c *Conn) WriteClose(reason string, code websocket.StatusCode) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ws == nil {
		return ErrClosed
	}
	if reason != "" {
		_ = c.ws.Write(c.ctx, websocket.MessageText, mustJSON(closeMsg{T: "close", Reason: reason}))
	}
	return c.ws.Close(code, reason)
}

// Read returns the next frame. Binary frames carry WG datagrams; text frames
// carry JSON control messages.
func (c *Conn) Read() (Frame, error) {
	if c.ws == nil {
		return Frame{}, ErrClosed
	}
	kind, data, err := c.ws.Read(c.ctx)
	if err != nil {
		return Frame{}, err
	}
	return Frame{Kind: kind, Data: data}, nil
}

// CloseRead spawns the coder/websocket close-read watcher (answers pings and
// surfaces remote closure). Runs until the connection is closed.
func (c *Conn) CloseRead() {
	_ = c.ws.CloseRead(c.ctx)
}

// Close closes the WebSocket cleanly.
func (c *Conn) Close(code websocket.StatusCode, reason string) error {
	c.mu.Lock()
	ws := c.ws
	c.ws = nil
	c.cancel()
	c.mu.Unlock()
	if ws == nil {
		return ErrClosed
	}
	return ws.Close(code, reason)
}

type closeMsg struct {
	T      string `json:"t"`
	Reason string `json:"reason,omitempty"`
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(`{"t":"close"}`)
	}
	return b
}
