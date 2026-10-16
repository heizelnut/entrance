// Package agent is the entranced side of the simplified Entrance: it dials the
// bastion over HTTPS, authenticates with a single token, and serves remote
// PTY shells when the (authenticated) bastion asks for one.
//
// The agent opens no inbound ports. It runs a shell only for the bastion it is
// configured to trust, and every shell session is logged to the audit log.
package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/creack/pty"

	"entrance/internal/proto"
)

// Version is reported to the bastion.
var Version = "0.2.0"

// Config configures the agent.
type Config struct {
	ServerURL string // https://bastion[:port]
	Token     string // single shared token
	Hostname  string
	Shell     string // default: $SHELL or /bin/sh
	CAFile    string // optional pinned bastion CA
	AuditLog  string // optional audit log path
}

// Agent is the running agent.
type Agent struct {
	cfg Config
	log *slog.Logger
}

// New builds an agent.
func New(cfg Config, log *slog.Logger) *Agent {
	if log == nil {
		log = slog.Default()
	}
	return &Agent{cfg: cfg, log: log}
}

// Run connects and reconnects until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return nil
		}
		err := a.session(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			a.log.Warn("agent session ended", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (a *Agent) session(ctx context.Context) error {
	u, err := agentURL(a.cfg.ServerURL)
	if err != nil {
		return err
	}
	opts := &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + a.cfg.Token}},
	}
	if a.cfg.CAFile != "" {
		pool, err := loadCA(a.cfg.CAFile)
		if err != nil {
			return err
		}
		opts.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	}
	ws, resp, err := websocket.Dial(ctx, u, opts)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return errors.New("agent token rejected (401): check --token")
		}
		return err
	}
	defer ws.CloseNow()

	c := &conn{ws: ws, log: a.log, cfg: a.cfg, sessions: map[string]*shell{}}
	if err := c.send(proto.Msg{
		T: proto.THello, Hostname: a.cfg.Hostname,
		OS: runtime.GOOS, Arch: runtime.GOARCH, Version: Version,
	}); err != nil {
		return err
	}
	a.log.Info("connected to bastion", "server", a.cfg.ServerURL, "hostname", a.cfg.Hostname)

	// Keepalive pings so dead links are noticed.
	pingCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-pingCtx.Done():
				return
			case <-t.C:
				_ = c.send(proto.Msg{T: proto.TPing})
			}
		}
	}()

	return c.readLoop(ctx)
}

// conn is one live agent<->bastion WebSocket.
type conn struct {
	ws  *websocket.Conn
	log *slog.Logger
	cfg Config

	wmu sync.Mutex // serializes writes to the socket

	mu       sync.Mutex
	sessions map[string]*shell
}

type shell struct {
	id  string
	f   *os.File
	cmd *exec.Cmd
}

func (c *conn) send(m proto.Msg) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	wctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return c.ws.Write(wctx, websocket.MessageText, b)
}

func (c *conn) readLoop(ctx context.Context) error {
	for {
		_, data, err := c.ws.Read(ctx)
		if err != nil {
			c.closeAll()
			return err
		}
		var m proto.Msg
		if err := json.Unmarshal(data, &m); err != nil {
			continue
		}
		switch m.T {
		case proto.TPing:
			_ = c.send(proto.Msg{T: proto.TPong})
		case proto.TPong:
			// keepalive ack
		case proto.TShellOpen:
			c.openShell(m)
		case proto.TShellData:
			c.writeShell(m.ID, m.Data)
		case proto.TShellResize:
			c.resizeShell(m.ID, m.Cols, m.Rows)
		case proto.TShellClose:
			c.closeShell(m.ID)
		}
	}
}

func (c *conn) openShell(m proto.Msg) {
	shellPath := c.cfg.Shell
	if shellPath == "" {
		shellPath = defaultShell()
	}
	cols, rows := m.Cols, m.Rows
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}
	cmd := exec.Command(shellPath)
	cmd.Env = append(os.Environ(), "TERM="+orDefault(m.Term, "xterm-256color"))
	f, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: cols, Rows: rows})
	if err != nil {
		_ = c.send(proto.Msg{T: proto.TError, ID: m.ID, Error: "start shell: " + err.Error()})
		return
	}
	s := &shell{id: m.ID, f: f, cmd: cmd}
	c.mu.Lock()
	c.sessions[m.ID] = s
	c.mu.Unlock()

	c.audit("shell opened id=%s shell=%s user=%s remote=b %s", m.ID, shellPath, currentUser(), c.cfg.ServerURL)
	c.log.Info("shell opened", "id", m.ID, "shell", shellPath, "user", currentUser())

	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, rerr := f.Read(buf)
			if n > 0 {
				out := make([]byte, n)
				copy(out, buf[:n])
				if serr := c.send(proto.Msg{T: proto.TShellData, ID: m.ID, Data: out}); serr != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		code := 0
		if cmd.ProcessState != nil {
			code = cmd.ProcessState.ExitCode()
		}
		_ = c.send(proto.Msg{T: proto.TShellExit, ID: m.ID, Code: &code})
		c.removeShell(m.ID)
		c.audit("shell closed id=%s code=%d", m.ID, code)
		c.log.Info("shell closed", "id", m.ID, "code", code)
	}()
}

func (c *conn) writeShell(id string, data []byte) {
	c.mu.Lock()
	s := c.sessions[id]
	c.mu.Unlock()
	if s == nil {
		return
	}
	_, _ = s.f.Write(data)
}

func (c *conn) resizeShell(id string, cols, rows uint16) {
	c.mu.Lock()
	s := c.sessions[id]
	c.mu.Unlock()
	if s == nil || cols == 0 || rows == 0 {
		return
	}
	_ = pty.Setsize(s.f, &pty.Winsize{Cols: cols, Rows: rows})
}

func (c *conn) closeShell(id string) {
	c.mu.Lock()
	s := c.sessions[id]
	delete(c.sessions, id)
	c.mu.Unlock()
	if s != nil {
		_ = s.f.Close()
		if s.cmd.Process != nil {
			_ = s.cmd.Process.Kill()
		}
	}
}

func (c *conn) removeShell(id string) {
	c.mu.Lock()
	delete(c.sessions, id)
	c.mu.Unlock()
}

func (c *conn) closeAll() {
	c.mu.Lock()
	ss := c.sessions
	c.sessions = map[string]*shell{}
	c.mu.Unlock()
	for _, s := range ss {
		_ = s.f.Close()
		if s.cmd.Process != nil {
			_ = s.cmd.Process.Kill()
		}
	}
}

// audit appends a line to the configured audit log (best effort).
func (c *conn) audit(format string, args ...any) {
	if c.cfg.AuditLog == "" {
		return
	}
	f, err := os.OpenFile(c.cfg.AuditLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	line := fmt.Sprintf("%s host=%s %s\n", time.Now().UTC().Format(time.RFC3339), c.cfg.Hostname, fmt.Sprintf(format, args...))
	_, _ = f.WriteString(line)
}

// --- helpers --------------------------------------------------------------

func agentURL(server string) (string, error) {
	s := strings.TrimRight(server, "/")
	switch {
	case strings.HasPrefix(s, "https://"):
		s = "wss://" + strings.TrimPrefix(s, "https://")
	case strings.HasPrefix(s, "http://"):
		s = "ws://" + strings.TrimPrefix(s, "http://")
	default:
		return "", fmt.Errorf("server URL must start with https:// (got %q)", server)
	}
	return s + "/agent", nil
}

func loadCA(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}
	return pool, nil
}

func defaultShell() string {
	if s := os.Getenv("SHELL"); s != "" {
		return s
	}
	return "/bin/sh"
}

func currentUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "?"
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
