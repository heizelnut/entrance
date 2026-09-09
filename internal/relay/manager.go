// Package relay manages bastion-side user data-plane sessions (D4): a relay
// session is a TCP connection from the bastion to a daemon target (the WG
// tunnel IP in prod, loopback in rootless dev/e2e), bridged 1:1 to the user's
// WebSocket.
package relay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// DialMode selects how the relay manager reaches a daemon target.
const (
	// DialWG dials the daemon's tunnel IP:port (production; requires the
	// kernel to route through the WG tunnel).
	DialWG = "wg"
	// DialLoopback dials 127.0.0.1:port (rootless dev/e2e with no TUN).
	DialLoopback = "loopback"
)

// Limits guard the relay surface against authenticated abuse (one session per
// user can otherwise open unbounded TCP conns + memory on the bastion).
const (
	MaxSessionsPerUser = 8
	MaxSessionsTotal   = 1024
	// AttachTimeout: a session created via POST /relays but never attached
	// (client aborted between the REST call and the WS upgrade) is reaped.
	AttachTimeout = 60 * time.Second
)

// Session is one live relay.
type Session struct {
	ID         string
	DaemonID   int64
	UserID     int64
	Target     string // dial address
	TargetPort int
	Protocol   string
	conn       net.Conn
	Created    time.Time
	mu         sync.Mutex
	ws         *websocket.Conn
	closed     bool
	done       bool // OnClose fired
}

// SessionInfo is a serializable view of a relay session.
type SessionInfo struct {
	ID         string    `json:"id"`
	DaemonID   int64     `json:"daemon_id"`
	TargetPort int       `json:"target_port"`
	Protocol   string    `json:"protocol"`
	Created    time.Time `json:"created_at"`
	Active     bool      `json:"active"`
}

// Dialer dials the daemon target for a relay. It is injectable so tests can
// run rootless in loopback mode.
type Dialer func(network, addr string, timeout time.Duration) (net.Conn, error)

// Manager owns all relay sessions.
type Manager struct {
	mu       sync.Mutex
	sessions map[string]*Session
	dialer   Dialer
	dialMode string
	// WGIPOf returns the tunnel IP of a daemon id (used in DialWG mode).
	WGIPOf func(daemonID int64) (string, error)
	Log    func(format string, args ...any)
	// OnClose is invoked once per session at teardown (any path: attach
	// completion, reaper, CloseDaemon, Stop). The api layer uses it to prune
	// the session's audit row.
	OnClose func(s *Session)

	// PerUserLimit and TotalLimit bound the session map (0 = unlimited).
	PerUserLimit int
	TotalLimit   int
	// AttachTimeout bounds how long a created-but-unattached session lives.
	AttachTimeout time.Duration

	reaperStop chan struct{}
}

// NewManager builds a relay manager with the given dial mode.
func NewManager(dialMode string, wgIPOf func(int64) (string, error)) *Manager {
	return &Manager{
		sessions:      map[string]*Session{},
		dialMode:      dialMode,
		WGIPOf:        wgIPOf,
		dialer:        net.DialTimeout,
		PerUserLimit:  MaxSessionsPerUser,
		TotalLimit:    MaxSessionsTotal,
		AttachTimeout: AttachTimeout,
	}
}

// SetDialer overrides the connection dialer (tests).
func (m *Manager) SetDialer(d Dialer) { m.dialer = d }

// Mode returns the dial mode in effect.
func (m *Manager) Mode() string { return m.dialMode }

// Start starts the orphan reaper. Call before serving traffic.
func (m *Manager) Start() {
	if m.AttachTimeout <= 0 {
		return
	}
	m.reaperStop = make(chan struct{})
	go m.reaper()
}

// Stop terminates the reaper and closes every session.
func (m *Manager) Stop() {
	if m.reaperStop != nil {
		close(m.reaperStop)
	}
	m.mu.Lock()
	victims := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		victims = append(victims, s)
	}
	m.sessions = map[string]*Session{}
	m.mu.Unlock()
	for _, s := range victims {
		s.closeBoth()
		m.notifyClosed(s)
	}
}

// reaper closes sessions that were never attached and idle attached sessions
// older than AttachTimeout. It keeps the session map bounded.
func (m *Manager) reaper() {
	ticker := time.NewTicker(m.AttachTimeout / 2)
	defer ticker.Stop()
	for {
		select {
		case <-m.reaperStop:
			return
		case <-ticker.C:
		}
		now := time.Now()
		m.mu.Lock()
		var idle []*Session
		for _, s := range m.sessions {
			s.mu.Lock()
			unattached := s.ws == nil && !s.closed
			attached := s.ws != nil && !s.closed
			s.mu.Unlock()
			switch {
			case unattached && now.Sub(s.Created) > m.AttachTimeout:
				idle = append(idle, s)
			case attached && now.Sub(s.Created) > 24*time.Hour:
				idle = append(idle, s)
			}
		}
		m.mu.Unlock()
		for _, s := range idle {
			m.logf("relay %s: reaped (max lifetime reached)", s.ID)
			s.closeBoth()
			m.remove(s.ID)
			m.notifyClosed(s)
		}
	}
}

func (m *Manager) logf(format string, args ...any) {
	if m.Log != nil {
		m.Log(format, args...)
	}
}

// countByUser counts live sessions for one user.
func (m *Manager) countByUser(userID int64) int {
	n := 0
	for _, s := range m.sessions {
		if !s.closed && s.UserID == userID {
			n++
		}
	}
	return n
}

// Create dials the daemon target and registers a session. The returned
// session is ready for the user's WebSocket to be attached via Attach.
func (m *Manager) Create(daemonID, userID int64, targetPort int, protocol string) (*Session, error) {
	var addr string
	switch m.dialMode {
	case DialLoopback:
		addr = "127.0.0.1:" + strconv.Itoa(targetPort)
	case DialWG:
		if m.WGIPOf == nil {
			return nil, errors.New("relay manager missing daemon IP resolver")
		}
		ip, err := m.WGIPOf(daemonID)
		if err != nil {
			return nil, err
		}
		addr = net.JoinHostPort(ip, strconv.Itoa(targetPort))
	default:
		return nil, errors.New("invalid relay dial mode " + m.dialMode)
	}

	m.mu.Lock()
	if m.TotalLimit > 0 && len(m.sessions) >= m.TotalLimit {
		m.mu.Unlock()
		return nil, errors.New("too many concurrent relay sessions")
	}
	if m.PerUserLimit > 0 {
		if n := m.countByUser(userID); n >= m.PerUserLimit {
			m.mu.Unlock()
			return nil, errors.New("too many concurrent relay sessions for this user")
		}
	}
	m.mu.Unlock()

	conn, err := m.dialer("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	id := newSessionID()
	s := &Session{
		ID:         id,
		DaemonID:   daemonID,
		UserID:     userID,
		Target:     addr,
		TargetPort: targetPort,
		Protocol:   protocol,
		conn:       conn,
		Created:    time.Now().UTC(),
	}
	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()
	m.logf("relay %s: dialed %s (daemon %d)", id, addr, daemonID)
	return s, nil
}

// Get returns the session with id.
func (m *Manager) Get(id string) (*Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok || s.closed {
		return nil, false
	}
	return s, true
}

// List returns active sessions (optionally for one daemon).
func (m *Manager) List(daemonID int64) []SessionInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []SessionInfo
	for _, s := range m.sessions {
		if s.closed {
			continue
		}
		if daemonID != 0 && s.DaemonID != daemonID {
			continue
		}
		out = append(out, SessionInfo{
			ID: s.ID, DaemonID: s.DaemonID, TargetPort: s.TargetPort,
			Protocol: s.Protocol, Created: s.Created, Active: !s.closed,
		})
	}
	return out
}

// CloseDaemon closes every session belonging to a daemon (used on revoke).
func (m *Manager) CloseDaemon(daemonID int64) {
	m.mu.Lock()
	var victims []*Session
	for _, s := range m.sessions {
		if s.DaemonID == daemonID && !s.closed {
			victims = append(victims, s)
		}
	}
	m.mu.Unlock()
	for _, s := range victims {
		s.closeBoth() // closes TCP conn AND the attached WebSocket
		m.remove(s.ID)
		m.notifyClosed(s)
	}
	m.logf("closed %d relay(s) for daemon %d", len(victims), daemonID)
}

// remove deletes the session from the map if still present.
func (m *Manager) remove(id string) {
	m.mu.Lock()
	if _, ok := m.sessions[id]; ok {
		delete(m.sessions, id)
	}
	m.mu.Unlock()
}

// Attach bridges the user's WebSocket to the session's TCP conn until one of
// them closes. It is blocking and must be called in a handler goroutine.
func (m *Manager) Attach(s *Session, ws *websocket.Conn) {
	s.mu.Lock()
	if s.ws != nil || s.closed {
		s.mu.Unlock()
		ws.Close(websocket.StatusInternalError, "session already in use")
		return
	}
	s.ws = ws
	s.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	connIO := io.ReadWriteCloser(s.conn)
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		bridgeTCPToWS(ctx, connIO, ws, cancel)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		bridgeWSToTCP(ctx, ws, connIO, cancel)
	}()
	<-done
	<-done

	// one side closed; tear down both
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	_ = connIO.Close()
	ws.Close(websocket.StatusNormalClosure, "session closed")
	m.remove(s.ID)
	m.notifyClosed(s)
	m.logf("relay %s: closed", s.ID)
}

// notifyClosed fires the OnClose hook exactly once per session.
func (m *Manager) notifyClosed(s *Session) {
	s.mu.Lock()
	done := s.done
	s.done = true
	s.mu.Unlock()
	if done {
		return
	}
	if m.OnClose != nil {
		m.OnClose(s)
	}
}

// closeBoth closes the TCP conn and, if attached, the WebSocket. Safe for
// concurrent use from the reaper, CloseDaemon, and the bridge teardown.
func (s *Session) closeBoth() {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
	ws := s.ws
	s.ws = nil
	s.mu.Unlock()
	if ws != nil {
		ws.Close(websocket.StatusNormalClosure, "session closing")
	}
}

// bridgeTCPToWS reads TCP bytes and writes them as binary WS frames.
func bridgeTCPToWS(ctx context.Context, r io.Reader, ws *websocket.Conn, cancel func()) {
	defer cancel()
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			wctx, c := context.WithTimeout(ctx, 10*time.Second)
			werr := ws.Write(wctx, websocket.MessageBinary, buf[:n])
			c()
			if werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// bridgeWSToTCP reads WS messages and writes the payload bytes to TCP. The
// ctx is cancelled by the peer direction (or CloseDaemon) so a wedged socket
// can never hold this goroutine forever.
func bridgeWSToTCP(ctx context.Context, ws *websocket.Conn, w io.Writer, cancel func()) {
	defer cancel()
	for {
		mt, data, err := ws.Read(ctx)
		if err != nil {
			return
		}
		switch mt {
		case websocket.MessageBinary:
			if _, err := w.Write(data); err != nil {
				return
			}
		case websocket.MessageText:
			// control; ignore
		}
	}
}

func newSessionID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
