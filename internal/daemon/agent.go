package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"

	"entrance/internal/api"
	"entrance/internal/client"
	"entrance/internal/config"
	"entrance/internal/wg"
	"entrance/internal/wsproto"
)

// Version reported to the control plane.
var Version = "0.1.0"

// ExitRevoked is the agent exit code after token revocation (D7).
const ExitRevoked = 3

// Agent is the entranced agent: outbound-only control channel + WG device +
// allowlisted local listeners (D4/D7).
type Agent struct {
	cfg   config.DaemonConfig
	log   *slog.Logger
	state *stateStore
	c     *client.Client

	mu        sync.Mutex
	listeners map[int]*proxyListener

	devMu sync.Mutex
	dev   *wg.Device
}

// New prepares the agent: loads persisted state (or enrolls later).
func New(cfg config.DaemonConfig, log *slog.Logger) (*Agent, error) {
	if log == nil {
		log = slog.Default()
	}
	if cfg.DataDir == "" {
		return nil, errors.New("data dir required")
	}
	st, err := loadStateStore(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	c, err := client.New(client.Options{
		BaseURL: cfg.ServerURL,
		CAFile:  cfg.CAFile,
		Token:   st.get().Token,
		Timeout: 15 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	return &Agent{cfg: cfg, log: log, state: st, c: c, listeners: map[int]*proxyListener{}}, nil
}

// Run is the agent's main loop (D7): enroll → connect WS (exp backoff) →
// hello → heartbeat → apply config pushes → reconnect on drop. 401 ⇒ revoke.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.ensureEnrolled(ctx); err != nil {
		return err
	}
	a.log.Info("agent ready", "server", a.cfg.ServerURL, "hostname", a.cfg.Hostname,
		"daemon_id", a.state.get().DaemonID)

	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return nil
		}
		revoked, err := a.controlLoop(ctx)
		if err != nil && revoked {
			a.log.Error("daemon token revoked by control plane; deleting local token — re-enroll required")
			a.state.deleteToken()
			return &RevokedError{}
		}
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			a.log.Warn("control connection lost", "err", err)
		}
		a.closeWG()
		sleepCtx(ctx, backoff)
		backoff = nextBackoff(backoff)
	}
}

// RevokedError signals 401 revocation (agent must exit non-zero, D7).
type RevokedError struct{}

func (r *RevokedError) Error() string { return "daemon token revoked" }

// ensureEnrolled enrolls when no token exists yet: the agent generates its WG
// keypair locally; only the public key is transmitted (D2).
func (a *Agent) ensureEnrolled(ctx context.Context) error {
	if a.state.get().Token != "" {
		return nil
	}
	secret := a.cfg.EnrollSecret
	if secret == "" && a.cfg.EnrollSecretEnv != "" {
		if v := envOr(a.cfg.EnrollSecretEnv, ""); v != "" {
			secret = v
		}
	}
	if secret == "" {
		return errors.New("no saved token and no enrollment secret provided; run with the one-time secret from `entrance add-host`")
	}
	priv, pub, err := wg.GenerateKeyPair()
	if err != nil {
		return err
	}
	req := api.EnrollRequest{
		EnrollmentSecret: secret,
		Hostname:         a.cfg.Hostname,
		WGPublicKey:      pub,
		Version:          Version,
		AllowedPorts:     a.cfg.AllowedPorts,
		Remap:            a.cfg.Remap,
	}
	resp, err := a.c.Enroll(ctx, req)
	if err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
	}
	return a.state.update(func(st *State) {
		st.ServerURL = a.cfg.ServerURL
		st.DaemonID = resp.DaemonID
		st.Token = resp.Token
		st.WGPrivateKey = priv
		st.WGPublicKey = pub
		st.Hostname = a.cfg.Hostname
		st.Config = resp.Config
		if len(st.Config.AllowedPorts) == 0 {
			st.Config.AllowedPorts = a.cfg.AllowedPorts
		}
		if st.Config.Remap == nil {
			st.Config.Remap = a.cfg.Remap
		}
	})
}

// controlLoop maintains one control-channel WebSocket until it drops.
func (a *Agent) controlLoop(ctx context.Context) (bool, error) {
	st := a.state.get()
	ws, err := a.connectWS(ctx, st.Token)
	if err != nil {
		var ce *client.Error
		if errors.As(err, &ce) && ce.StatusCode == http.StatusUnauthorized {
			return true, err
		}
		return false, err
	}
	conn := wsproto.NewConn(ws)
	a.log.Debug("controlLoop: ws open")
	defer conn.Close(websocket.StatusNormalClosure, "closing")
	// No conn.CloseRead() here: coder/websocket treats any DATA message after
	// CloseRead as "unexpected" and closes with 1008, but this channel's
	// purpose is carrying WG datagrams + control frames. The continuous read
	// loop (below) already answers pings.

	if err := a.startWG(conn); err != nil {
		a.log.Warn("controlLoop: startWG failed", "err", err)
		conn.Close(websocket.StatusNormalClosure, "wg setup failed")
		return false, err
	}
	a.log.Debug("controlLoop: wg device up")
	defer a.closeWG()

	if err := a.reconcileListeners(ctx); err != nil {
		a.log.Warn("listener setup failed", "err", err)
	}

	if err := conn.WriteControl(wsproto.Control{
		T:            wsproto.THello,
		Version:      Version,
		AllowedPorts: a.effectivePorts(),
		Remap:        a.effectiveRemap(),
	}); err != nil {
		return false, err
	}

	// Reader goroutine keeps the loop responsive to the heartbeat ticker
	// while a frame read is in progress. conn is closed on loop exit (defer
	// above), which unblocks the in-flight Read and lets this goroutine stop.
	type frameOrErr struct {
		frame wsproto.Frame
		err   error
	}
	frames := make(chan frameOrErr, 64)
	go func() {
		for {
			f, err := conn.Read()
			select {
			case frames <- frameOrErr{f, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()

	hb := time.NewTicker(a.heartbeatInterval())
	defer hb.Stop()

	for {
		select {
		case <-ctx.Done():
			return false, nil
		case <-hb.C:
			if err := conn.WriteControl(wsproto.Control{T: wsproto.THeartbeat, Version: Version}); err != nil {
				return false, err
			}
		case fe := <-frames:
			if fe.err != nil {
				if isRevocationError(fe.err) {
					return true, fe.err
				}
				return false, fe.err
			}
			frame := fe.frame
			switch frame.Kind {
			case wsproto.KindBinary:
				a.devMu.Lock()
				if a.dev != nil {
					a.dev.Transport().Deliver(frame.Data)
				}
				a.devMu.Unlock()
			case wsproto.KindText:
				var ctl wsproto.Control
				if err := json.Unmarshal(frame.Data, &ctl); err != nil {
					a.log.Warn("bad control from bastion", "err", err)
					continue
				}
				if !a.handleControl(ctx, conn, &ctl) {
					return false, nil
				}
			}
		}
	}
}

func (a *Agent) connectWS(ctx context.Context, token string) (*websocket.Conn, error) {
	opts := *a.c.WS
	opts.HTTPHeader.Set("Authorization", "Bearer "+token)
	url := a.cfg.ServerURL + "/api/v1/daemons/me/ws"
	wctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, resp, err := websocket.Dial(wctx, url, &opts)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return nil, &client.Error{StatusCode: http.StatusUnauthorized, Message: "revoked"}
		}
		if resp != nil {
			_ = resp.Body.Close()
		}
		return nil, err
	}
	return conn, nil
}

// startWG creates the WG device bound to this control connection: stock
// wireguard-go crypto over the WebsocketTransport (D1).
func (a *Agent) startWG(conn *wsproto.Conn) error {
	a.devMu.Lock()
	defer a.devMu.Unlock()
	a.closeWGLocked()

	st := a.state.get()
	if st.Config.BastionWGPubKey == "" {
		return errors.New("bastion hub public key not provided in enroll config")
	}
	transport := wg.NewWebsocketTransport(conn)

	var tun wg.TUN
	fake := wg.NewFakeTUN()
	tun = fake
	if a.cfg.NetMode == "tun" {
		real, err := wg.OpenTun("entranced", 1420)
		if err != nil {
			a.log.Warn("unable to open TUN (root required); falling back to loopback", "err", err)
		} else {
			tun = real
			if name, err := real.Name(); err == nil {
				if err := wg.ConfigureInterface(name, a.baseListenAddr(st), "", st.Config.NetworkCIDR); err != nil {
					a.log.Warn("configure TUN", "err", err)
				}
			}
		}
	}
	dev, err := wg.NewDevice(wg.DeviceOptions{
		Transport: transport,
		Tun:       tun,
		PublicKey: st.WGPublicKey,
		Config: wg.Config{
			PrivateKey: st.WGPrivateKey,
			ListenPort: a.cfg.WGPort,
			Peers: []wg.PeerConfig{{
				PublicKey:  st.Config.BastionWGPubKey,
				AllowedIPs: []string{st.Config.BastionWGIP + "/32"},
				// Inert loopback anchor of the hub; routing happens via the
				// single-peer control channel (D1: NAT/endpoints irrelevant).
				Endpoint:            "127.0.0.1:" + strconv.Itoa(hubAnchorPort(st)),
				PersistentKeepalive: 25,
			}},
		},
	})
	if err != nil {
		return err
	}
	fake.BringUp()
	a.dev = dev
	a.log.Info("wg device up", "anchor", a.cfg.WGPort, "wg_ip", st.Config.WGIP)
	return nil
}

// handleControl processes bastion control messages; false ends the loop.
func (a *Agent) handleControl(ctx context.Context, conn *wsproto.Conn, ctl *wsproto.Control) bool {
	a.log.Debug("controlLoop: control", "type", ctl.T)
	switch ctl.T {
	case wsproto.THelloAck, wsproto.THeartbeatAck:
		if ctl.Config != nil {
			_ = a.applyConfig(ctl.Config)
		}
	case wsproto.TConfig:
		if ctl.Config != nil {
			_ = a.applyConfig(ctl.Config)
			_ = conn.WriteControl(wsproto.Control{T: wsproto.TConfigAck})
		}
	case wsproto.TClose:
		a.log.Info("bastion closed control channel", "reason", ctl.Reason)
		return false
	default:
		a.log.Warn("unknown control from bastion", "type", ctl.T)
	}
	return true
}

// applyConfig persists the pushed config and reconciles listeners.
func (a *Agent) applyConfig(cfg *wsproto.Config) error {
	if cfg == nil {
		return nil
	}
	_ = a.state.update(func(st *State) { st.Config = *cfg })
	return a.reconcileListeners(context.Background())
}

// reconcileListeners binds allowlisted ports on the listen address, dialing
// the (remapped) local target (D4).
func (a *Agent) reconcileListeners(ctx context.Context) error {
	st := a.state.get()
	bind := a.baseListenAddr(st)
	ports := st.Config.AllowedPorts
	if len(ports) == 0 {
		ports = a.cfg.AllowedPorts
	}
	remap := st.Config.Remap
	if remap == nil {
		remap = a.cfg.Remap
	}

	a.mu.Lock()
	var toClose []*proxyListener
	for port, pl := range a.listeners {
		if !contains(ports, port) {
			toClose = append(toClose, pl)
			delete(a.listeners, port)
		}
	}
	for _, port := range ports {
		if _, ok := a.listeners[port]; ok {
			continue
		}
		localPort := port
		if lp, ok := remap[port]; ok {
			localPort = lp
		}
		ln, err := net.Listen("tcp", net.JoinHostPort(bind, strconv.Itoa(port)))
		if err != nil {
			a.log.Warn("cannot bind allowlisted port", "addr", bind, "port", port, "err", err)
			continue
		}
		pl := &proxyListener{ln: ln, targetPort: port, localPort: localPort,
			sem: make(chan struct{}, 32)}
		a.listeners[port] = pl
		go pl.serve()
		a.log.Info("exposing port", "addr", bind+":"+strconv.Itoa(port), "dial", localPort)
	}
	a.mu.Unlock()

	// Wait outside the lock: active splice goroutines can stay blocked on an
	// idle peer until the conn dies, and holding a.mu would stall the control
	// loop (heartbeats) meanwhile.
	for _, pl := range toClose {
		pl.close()
	}
	return nil
}

// baseListenAddr is the agent's bind address: allocated tunnel IP in "tun"
// mode, 127.0.0.1 in loopback mode (rootless dev/e2e).
func (a *Agent) baseListenAddr(st State) string {
	if a.cfg.NetMode == "tun" {
		if ip := st.Config.WGIP; ip != "" {
			return ip
		}
	}
	return "127.0.0.1"
}

// listenAddr mirrors baseListenAddr (kept for API symmetry).
func (a *Agent) listenAddr(st State) string { return a.baseListenAddr(st) }

// effectivePorts/effectiveRemap report the STATE config (last applied), not
// the CLI defaults: reconnects must not clobber config previously pushed via
// TConfig with stale flag values. State is seeded from the CLI at enroll.
func (a *Agent) effectivePorts() []int {
	st := a.state.get()
	if len(st.Config.AllowedPorts) > 0 {
		return st.Config.AllowedPorts
	}
	return a.cfg.AllowedPorts
}

func (a *Agent) effectiveRemap() map[int]int {
	st := a.state.get()
	if len(st.Config.Remap) > 0 {
		return st.Config.Remap
	}
	if len(a.cfg.Remap) > 0 {
		return a.cfg.Remap
	}
	return nil
}

func (a *Agent) heartbeatInterval() time.Duration {
	return time.Duration(a.cfg.HeartbeatIntervalSec) * time.Second
}

func (a *Agent) closeWG() {
	a.devMu.Lock()
	defer a.devMu.Unlock()
	a.closeWGLocked()
}

// closeWGLocked tears down the WG device; caller must hold devMu.
func (a *Agent) closeWGLocked() {
	if a.dev != nil {
		a.dev.Close()
		a.dev = nil
	}
}

// hubAnchorPort is the hub's loopback WG anchor as the daemon sees it.
func hubAnchorPort(st State) int {
	if st.Config.BastionWGPort > 0 {
		return int(st.Config.BastionWGPort)
	}
	return 51820
}

// --- helpers ---

func contains(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func isRevocationError(err error) bool {
	var ce *websocket.CloseError
	if errors.As(err, &ce) {
		return ce.Code == websocket.StatusPolicyViolation
	}
	return false
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func nextBackoff(cur time.Duration) time.Duration {
	cur *= 2
	if cur > 60*time.Second {
		cur = 60 * time.Second
	}
	jitter := time.Duration(rand.Int63n(int64(cur / 2)))
	return cur - jitter/2 + jitter
}
