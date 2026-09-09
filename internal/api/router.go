package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"entrance/internal/auth"
	"entrance/internal/config"
	"entrance/internal/db"
	"entrance/internal/relay"
	"entrance/internal/wg"
)

// Hub connects the bastion's wireguard-go device to per-daemon WebSocket
// control channels: outbound datagrams are routed by an endpoint token
// unique per daemon (via the HubTransport); inbound datagrams run through
// the shared device.
type Hub struct {
	dev *wg.Device
}

// newHub wraps the hub device.
func newHub(dev *wg.Device) *Hub {
	return &Hub{dev: dev}
}

// Server is the bastion control plane.
type Server struct {
	cfg            config.ServerConfig
	log            *slog.Logger
	db             *db.DB
	relays         *relay.Manager
	hub            *Hub
	ipam           *wg.IPAM
	sessionTTL     time.Duration
	hubAddrMu      sync.Mutex // serializes hub peer-set changes
	trustedProxies []netip.Prefix
	loginLimiter   *ipLimiter
	daemonWGPort   uint16
}

// NewServer creates the bastion server: opens the WG hub device, ensures
// settings (hub keypair, network) and bootstraps the admin user on first run.
func NewServer(cfg config.ServerConfig, store *db.DB, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	ipam, err := wg.ParseNetwork(cfg.NetworkCIDR)
	if err != nil {
		return nil, err
	}
	hub, err := ensureHubDevice(cfg, store, ipam, log)
	if err != nil {
		return nil, err
	}

	wgIPOf := func(daemonID int64) (string, error) {
		dm, err := store.GetDaemonByID(daemonID)
		if err != nil {
			return "", err
		}
		return dm.WGIP, nil
	}
	relMgr := relay.NewManager(cfg.RelayDialMode, wgIPOf)
	relMgr.OnClose = func(s *relay.Session) {
		_ = store.DeleteRelayBySession(s.ID)
	}
	relMgr.Start()
	trusted, err := parseTrustedProxies(cfg.TrustedProxies)
	if err != nil {
		return nil, err
	}
	relMgr.Log = func(format string, args ...any) { log.Info("relay: "+format, args...) }

	s := &Server{
		cfg:            cfg,
		log:            log,
		db:             store,
		relays:         relMgr,
		hub:            newHub(hub),
		ipam:           ipam,
		sessionTTL:     time.Duration(cfg.SessionTTLDays) * 24 * time.Hour,
		trustedProxies: trusted,
		loginLimiter:   newIPLimiter(10, time.Minute),
		daemonWGPort:   cfg.DaemonWGPort,
	}

	if err := s.rebuildHubPeers(); err != nil {
		log.Error("rebuild hub peers", "err", err)
	}
	if err := s.bootstrapAdmin(); err != nil {
		return nil, err
	}
	return s, nil
}

// parseTrustedProxies parses the operator-configured proxy CIDR allowlist.
func parseTrustedProxies(cfgs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cfgs))
	for _, c := range cfgs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy cidr %q", c)
		}
		out = append(out, p)
	}
	return out, nil
}

// Close releases the relay sessions and hub device.
func (s *Server) Close() {
	s.relays.Stop()
	if s.hub != nil && s.hub.dev != nil {
		s.hub.dev.Close()
	}
}

func (s *Server) bootstrapAdmin() error {
	n, err := s.db.UserCount()
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if s.cfg.AdminPassword == "" {
		return errors.New("ENTRANCE_ADMIN_PASSWORD must be set on first run")
	}
	hash, err := auth.HashPassword(s.cfg.AdminPassword)
	if err != nil {
		return err
	}
	u, err := s.db.CreateUser("admin", hash, true)
	if err != nil {
		return err
	}
	s.log.Info("bootstrapped admin user", "username", u.Username)
	return nil
}

// ensureHubDevice loads or creates the hub WG keypair and brings up the hub
// device. In "loopback" relay mode (dev/e2e) the hub data plane runs on a
// fake TUN; in "wg" mode the operator is expected to provide a real TUN
// (root), which we attempt to open and configure.
func ensureHubDevice(cfg config.ServerConfig, store *db.DB, ipam *wg.IPAM, log *slog.Logger) (*wg.Device, error) {
	priv, err := store.GetSetting(settingWGPrivKey)
	if err != nil {
		return nil, err
	}
	var pub string
	if priv == "" {
		priv, pub, err = wg.GenerateKeyPair()
		if err != nil {
			return nil, err
		}
		if err := store.SetSetting(settingWGPrivKey, priv); err != nil {
			return nil, err
		}
		if err := store.SetSetting(settingWGPubKey, pub); err != nil {
			return nil, err
		}
	} else {
		pub, err = wg.PublicKeyFromPrivate(priv)
		if err != nil {
			return nil, err
		}
	}

	fakeTun := wg.NewFakeTUN()
	var tun wg.TUN = fakeTun
	if cfg.RelayDialMode == relay.DialWG {
		realTun, err := wg.OpenTun("entrance", 1420)
		if err != nil {
			log.Warn("unable to open real hub TUN (operator should configure)", "err", err)
		} else {
			tun = realTun
			if name, err := realTun.Name(); err == nil {
				if err := wg.ConfigureInterface(
					name, ipam.BastionIP().String(), "", cfg.NetworkCIDR); err != nil {
					log.Warn("configure hub TUN", "err", err)
				}
			}
		}
	}
	dev, err := wg.NewDevice(wg.DeviceOptions{
		Transport: wg.NewHubTransport(),
		Tun:       tun,
		PublicKey: pub,
		Config: wg.Config{
			PrivateKey: priv, // the hub identity must be applied to the device
			ListenPort: cfg.WGPort,
		},
	})
	if err != nil {
		return nil, err
	}
	fakeTun.BringUp() // no-op when a real TUN is in use (kernel emits EventUp)
	log.Info("hub wg device up", "public_key", pub[:8], "port", cfg.WGPort)
	return dev, nil
}

// rebuildHubPeers re-issues the full hub peer set from the DB.
func (s *Server) rebuildHubPeers() error {
	daemons, err := s.db.ListDaemons()
	if err != nil {
		return err
	}
	return s.applyHubPeers(daemons)
}

func (s *Server) applyHubPeers(daemons []*db.Daemon) error {
	s.hubAddrMu.Lock()
	defer s.hubAddrMu.Unlock()
	peers := make([]wg.PeerConfig, 0, len(daemons))
	for _, dm := range daemons {
		peers = append(peers, wg.PeerConfig{
			PublicKey:           dm.WGPublicKey,
			AllowedIPs:          []string{dm.WGIP + "/32"},
			Endpoint:            "127.0.0.1:" + endpointToken(dm.ID),
			PersistentKeepalive: 25,
		})
	}
	return s.hub.dev.ApplyPeerList(peers)
}

// endpointToken maps a daemon id to a unique loopback endpoint token (port
// namespace 20000..49999) used by the hub to route datagrams to the right
// daemon WebSocket. Tokens are inert identifiers — never dialed.
func endpointToken(daemonID int64) string {
	return strconv.Itoa(20000 + int(daemonID%30000))
}

const (
	settingWGPrivKey = "wg_private_key"
	settingWGPubKey  = "wg_public_key"
)

// ---------------------------------------------------------------------------
// HTTP helpers

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type errBody struct {
	Error string `json:"error"`
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errBody{Error: msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	dec := json.NewDecoder(&io.LimitedReader{R: r.Body, N: 1 << 20})
	dec.DisallowUnknownFields()
	err := dec.Decode(dst)
	if err != nil {
		if err != io.EOF {
			writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		} else {
			writeErr(w, http.StatusBadRequest, "empty request body")
		}
	}
	return err
}

// bearerToken extracts a Bearer token from the Authorization header. Tokens
// are never accepted from query parameters: they would land in proxy access
// logs, browser history, and Referer headers, and they weaken the WebSocket
// origin posture. All first-party clients (agent, entrui, tests) send the
// header.
func bearerToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	return ""
}
