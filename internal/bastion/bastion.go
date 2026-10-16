// Package bastion is the Entrance control plane: one HTTPS port that accepts
// outbound agent connections (single-token auth), authenticates the human
// admin with a WebAuthn passkey, and bridges browser terminals to agent PTYs.
package bastion

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"entrance/internal/store"
	"entrance/internal/tlssetup"
)

const (
	sessionCookie  = "entrance_session"
	ceremonyCookie = "entrance_ceremony"
)

// Config configures the bastion.
type Config struct {
	ListenAddr string
	DataDir    string
	Dev        bool
	Hostname   string // public host, e.g. localhost or bastion.example.com
	RPID       string // WebAuthn RP ID (default: hostname without port)
	Origin     string // WebAuthn origin (default: https://<hostname>)
	Token      string // single token: agent auth + passkey bootstrap
	SessionTTL time.Duration
	Shell      string // preferred shell advertised to agents ("" = agent default)
}

// Bastion is the running control plane.
type Bastion struct {
	cfg Config
	log *slog.Logger
	st  *store.Store
	wa  *webauthn.WebAuthn

	mu         sync.Mutex
	agents     map[string]*agentConn
	ceremonies map[string]ceremony
}

type ceremony struct {
	data    webauthn.SessionData
	expires time.Time
}

// New builds the bastion (opening the store and configuring WebAuthn).
func New(cfg Config, log *slog.Logger) (*Bastion, error) {
	if log == nil {
		log = slog.Default()
	}
	if cfg.Token == "" {
		return nil, errors.New("a --token is required (agent auth + passkey bootstrap)")
	}
	if cfg.RPID == "" {
		cfg.RPID = hostOnly(cfg.Hostname)
	}
	if cfg.Origin == "" {
		cfg.Origin = "https://" + cfg.Hostname
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 30 * 24 * time.Hour
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Entrance",
		RPID:          cfg.RPID,
		RPOrigins:     []string{cfg.Origin},
	})
	if err != nil {
		st.Close()
		return nil, err
	}
	return &Bastion{
		cfg: cfg, log: log, st: st, wa: wa,
		agents:     map[string]*agentConn{},
		ceremonies: map[string]ceremony{},
	}, nil
}

// Close releases the store.
func (b *Bastion) Close() error { return b.st.Close() }

// Run binds and serves until ctx is cancelled. In dev it serves plain HTTP on
// localhost: browsers treat http://localhost as a secure context, so WebAuthn
// works without a trusted certificate. Production uses ACME (TLS-ALPN-01).
func (b *Bastion) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", b.cfg.ListenAddr)
	if err != nil {
		return err
	}
	return b.Serve(ctx, ln)
}

// Serve serves on an already-bound listener (useful for tests).
func (b *Bastion) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           b.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	b.log.Info("bastion listening", "addr", ln.Addr().String(), "origin", b.cfg.Origin, "rpid", b.cfg.RPID, "dev", b.cfg.Dev)

	var err error
	if b.cfg.Dev {
		err = srv.Serve(ln)
	} else {
		tlsCfg, _, terr := tlssetup.TLSConfig(tlssetup.Config{Hostname: b.cfg.Hostname, DataDir: b.cfg.DataDir})
		if terr != nil {
			return terr
		}
		srv.TLSConfig = tlsCfg
		err = srv.ServeTLS(ln, "", "")
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (b *Bastion) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/agent", b.handleAgent)
	mux.HandleFunc("/ws/shell/", b.handleShellWS)
	mux.HandleFunc("/api/hosts", b.handleHostsAPI)
	mux.HandleFunc("/webauthn/register/begin", b.handleRegisterBegin)
	mux.HandleFunc("/webauthn/register/finish", b.handleRegisterFinish)
	mux.HandleFunc("/webauthn/login/begin", b.handleLoginBegin)
	mux.HandleFunc("/webauthn/login/finish", b.handleLoginFinish)
	mux.HandleFunc("/logout", b.handleLogout)
	mux.HandleFunc("/static/", b.handleStatic)
	mux.HandleFunc("/", b.handleIndex)
	return mux
}

// --- auth helpers ---------------------------------------------------------

// checkToken authenticates an agent with the single shared token.
func (b *Bastion) checkToken(r *http.Request) bool {
	tok := bearer(r)
	if tok == "" {
		tok = r.URL.Query().Get("token")
	}
	return subtle.ConstantTimeCompare([]byte(tok), []byte(b.cfg.Token)) == 1
}

// checkBootstrap authenticates a passkey-registration attempt with the token.
func (b *Bastion) checkBootstrap(r *http.Request) bool {
	tok := r.Header.Get("X-Bootstrap-Token")
	if tok == "" {
		tok = r.URL.Query().Get("bootstrap")
	}
	return subtle.ConstantTimeCompare([]byte(tok), []byte(b.cfg.Token)) == 1
}

// authed reports whether the request carries a valid browser session.
func (b *Bastion) authed(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	return b.st.ValidSession(c.Value)
}

func (b *Bastion) setSession(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: id, Path: "/", HttpOnly: true,
		Secure: true, SameSite: http.SameSiteLaxMode,
		MaxAge: int(b.cfg.SessionTTL / time.Second),
	})
}

func (b *Bastion) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", HttpOnly: true,
		Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// --- ceremony (WebAuthn challenge) bookkeeping ----------------------------

func (b *Bastion) putCeremony(sd webauthn.SessionData) string {
	id, _ := randomHex(16)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pruneCeremoniesLocked()
	b.ceremonies[id] = ceremony{data: sd, expires: time.Now().Add(5 * time.Minute)}
	return id
}

func (b *Bastion) takeCeremony(r *http.Request) (webauthn.SessionData, bool) {
	c, err := r.Cookie(ceremonyCookie)
	if err != nil {
		return webauthn.SessionData{}, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	ce, ok := b.ceremonies[c.Value]
	if !ok {
		return webauthn.SessionData{}, false
	}
	delete(b.ceremonies, c.Value)
	if time.Now().After(ce.expires) {
		return webauthn.SessionData{}, false
	}
	return ce.data, true
}

func (b *Bastion) pruneCeremoniesLocked() {
	now := time.Now()
	for k, v := range b.ceremonies {
		if now.After(v.expires) {
			delete(b.ceremonies, k)
		}
	}
}

// --- misc helpers ---------------------------------------------------------

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return h[7:]
	}
	return ""
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func (b *Bastion) handleStatic(w http.ResponseWriter, r *http.Request) {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		http.Error(w, "static unavailable", http.StatusInternalServerError)
		return
	}
	http.StripPrefix("/static/", http.FileServer(http.FS(sub))).ServeHTTP(w, r)
}

func (b *Bastion) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	page, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "missing UI", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(page)
}
