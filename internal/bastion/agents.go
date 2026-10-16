package bastion

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"

	"entrance/internal/proto"
)

// agentConn is one connected agent and its multiplexed shells.
type agentConn struct {
	name   string
	info   proto.Host
	ws     *websocket.Conn
	log    *slog.Logger
	remote string

	wmu sync.Mutex // serializes writes to the agent socket

	mu     sync.Mutex
	shells map[string]*shellBridge
	closed bool
}

// handleAgent accepts an agent WebSocket. Auth is the single shared token.
func (b *Bastion) handleAgent(w http.ResponseWriter, r *http.Request) {
	if !b.checkToken(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	defer ws.CloseNow()

	// First frame must be hello.
	hctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	_, data, err := ws.Read(hctx)
	cancel()
	if err != nil {
		return
	}
	var hello proto.Msg
	if json.Unmarshal(data, &hello) != nil || hello.T != proto.THello {
		_ = ws.Close(websocket.StatusPolicyViolation, "expected hello")
		return
	}
	name := hello.Hostname
	if name == "" {
		name = clientIP(r)
	}
	ac := &agentConn{
		name: name, ws: ws, log: b.log, remote: clientIP(r),
		shells: map[string]*shellBridge{},
		info: proto.Host{
			Name: name, OS: hello.OS, Arch: hello.Arch, Version: hello.Version,
			Remote: clientIP(r), Online: true, Since: time.Now().UTC().Format(time.RFC3339),
		},
	}
	if err := b.st.TouchHost(name, hello.OS, hello.Arch, hello.Version, ac.remote); err != nil {
		b.log.Warn("persist host", "host", name, "err", err)
	}
	b.register(ac)
	defer b.unregister(ac)

	_ = ac.send(proto.Msg{T: proto.THelloAck})
	b.log.Info("agent connected", "host", name, "remote", ac.remote, "os", hello.OS, "arch", hello.Arch)
	ac.readLoop(r.Context())
	b.log.Info("agent disconnected", "host", name)
}

// readLoop routes agent frames to the matching shell bridge.
func (c *agentConn) readLoop(ctx context.Context) {
	for {
		_, data, err := c.ws.Read(ctx)
		if err != nil {
			break
		}
		var m proto.Msg
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		switch m.T {
		case proto.TShellData, proto.TShellExit, proto.TError:
			if br := c.bridge(m.ID); br != nil {
				_ = br.send(m)
				if m.T == proto.TShellExit {
					br.close()
					c.detach(m.ID)
				}
			}
		case proto.TPong:
			// keepalive ack
		}
	}
	// Fan out closure to any live shells.
	c.mu.Lock()
	c.closed = true
	brs := c.shells
	c.shells = map[string]*shellBridge{}
	c.mu.Unlock()
	for _, br := range brs {
		br.close()
	}
}

func (c *agentConn) send(m proto.Msg) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return c.ws.Write(ctx, websocket.MessageText, b)
}

func (c *agentConn) attach(id string, br *shellBridge) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		br.close()
		return
	}
	c.shells[id] = br
}

func (c *agentConn) detach(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.shells, id)
}

func (c *agentConn) bridge(id string) *shellBridge {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.shells[id]
}

// --- registry -------------------------------------------------------------

func (b *Bastion) register(ac *agentConn) {
	b.mu.Lock()
	// Replace any stale connection with the same name.
	old := b.agents[ac.name]
	b.agents[ac.name] = ac
	b.mu.Unlock()
	if old != nil {
		_ = old.ws.Close(websocket.StatusGoingAway, "replaced by new connection")
	}
}

func (b *Bastion) unregister(ac *agentConn) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.agents[ac.name] == ac {
		delete(b.agents, ac.name)
	}
}

func (b *Bastion) agent(name string) *agentConn {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.agents[name]
}

// handleHostsAPI lists connected and known hosts for the web UI.
func (b *Bastion) handleHostsAPI(w http.ResponseWriter, r *http.Request) {
	if !b.authed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	online := map[string]proto.Host{}
	b.mu.Lock()
	for name, ac := range b.agents {
		online[name] = ac.info
	}
	b.mu.Unlock()

	known, err := b.st.KnownHosts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]proto.Host, 0, len(known)+len(online))
	seen := map[string]bool{}
	for _, h := range known {
		host := proto.Host{Name: h.Name, OS: h.OS, Arch: h.Arch, Version: h.Version, Remote: h.Remote, Since: h.LastSeen}
		if on, ok := online[h.Name]; ok {
			host = on
		}
		out = append(out, host)
		seen[h.Name] = true
	}
	for name, on := range online {
		if !seen[name] {
			out = append(out, on)
		}
	}
	writeJSON(w, out)
}
