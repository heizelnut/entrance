package api

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"sync"
	"time"

	"entrance/internal/auth"
	"entrance/internal/db"
)

// context keys for authenticated principals.
type ctxKey int

const (
	ctxUser ctxKey = iota
	ctxDaemon
)

func hashToken(token string) string { return auth.HashToken(token) }

func userFrom(r *http.Request) *db.User     { return r.Context().Value(ctxUser).(*db.User) }
func daemonFrom(r *http.Request) *db.Daemon { return r.Context().Value(ctxDaemon).(*db.Daemon) }

// ipLimiter is a fixed-window per-IP rate limiter (login, D3). The map is
// pruned opportunistically so spoofed/rotating client IPs cannot grow it
// without bound.
type ipLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	seen     map[string]*ipWindow
	maxTrack int
}

type ipWindow struct {
	count   int
	resetAt time.Time
}

func newIPLimiter(limit int, window time.Duration) *ipLimiter {
	return &ipLimiter{limit: limit, window: window, seen: map[string]*ipWindow{}, maxTrack: 4096}
}

// Allow reports whether the IP may proceed.
func (l *ipLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	w, ok := l.seen[ip]
	if !ok || now.After(w.resetAt) {
		l.seen[ip] = &ipWindow{count: 1, resetAt: now.Add(l.window)}
		return true
	}
	w.count++
	return w.count <= l.limit
}

// pruneExpired drops stale windows when the table grows past maxTrack.
func (l *ipLimiter) pruneExpired(now time.Time) {
	if len(l.seen) <= l.maxTrack {
		return
	}
	for ip, w := range l.seen {
		if now.After(w.resetAt) {
			delete(l.seen, ip)
		}
	}
}

// clientIP extracts the effective client IP. X-Forwarded-For is only trusted
// from configured proxy CIDRs (or loopback in dev); otherwise it is ignored
// so remote users cannot spoof the login rate-limiter or audit IPs.
func (s *Server) clientIP(r *http.Request) string {
	direct := r.RemoteAddr
	host, _, err := net.SplitHostPort(direct)
	if err != nil {
		host = direct
	}
	peer, err := netip.ParseAddr(host)
	xf := r.Header.Get("X-Forwarded-For")
	if xf != "" && err == nil {
		trusted := s.trustedProxy(peer)
		// loopback is a trusted first hop by default (local nginx/dev)
		if trusted || peer.IsLoopback() {
			if ip, err := netip.ParseAddr(stringsFirst(xf)); err == nil {
				return ip.String()
			}
		}
	}
	return host
}

func (s *Server) trustedProxy(peer netip.Addr) bool {
	for _, p := range s.trustedProxies {
		if p.Contains(peer) {
			return true
		}
	}
	return false
}

func stringsFirst(csv string) string {
	for i := 0; i < len(csv); i++ {
		if csv[i] == ',' {
			return csv[:i]
		}
	}
	return csv
}

// statusRecorder tracks whether a response header was written so the recover
// middleware can emit a 500 when a handler panics before responding.
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wrote {
		r.wrote = true
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wrote {
		r.wrote = true
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack forwards WebSocket upgrades. Without this, coder/websocket's Accept
// fails with 501 "Not Implemented" (it requires http.Hijacker).
func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("underlying ResponseWriter does not implement http.Hijacker")
	}
	r.wrote = true // a hijacked connection has begun its own lifecycle
	return hj.Hijack()
}

// withRecover catches handler panics and returns 500.
func (s *Server) withRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w}
		defer func() {
			if recv := recover(); recv != nil {
				s.log.Error("panic", "err", recv, "stack", string(debug.Stack()))
				if !rec.wrote {
					writeErr(rec, http.StatusInternalServerError, "internal error")
				}
			}
		}()
		next.ServeHTTP(rec, r)
	})
}

// withLogging logs each request.
func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.log.Debug("http",
			"method", r.Method, "path", r.URL.Path,
			"remote", s.clientIP(r), "dur", time.Since(start))
	})
}

// requireUser authenticates a user session token.
func (s *Server) requireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			writeErr(w, http.StatusUnauthorized, "missing session token")
			return
		}
		sess, err := s.db.GetSessionByToken(hashToken(token), s.sessionTTL)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "invalid or expired session")
			return
		}
		user, err := s.db.GetUserByID(sess.UserID)
		if err != nil || user.DeactivatedAt != nil {
			writeErr(w, http.StatusUnauthorized, "invalid session")
			return
		}
		ctx := context.WithValue(r.Context(), ctxUser, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireDaemon authenticates a daemon bearer token (D3/D7).
func (s *Server) requireDaemon(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			writeErr(w, http.StatusUnauthorized, "missing daemon token")
			return
		}
		dm, err := s.db.GetDaemonByToken(hashToken(token))
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "invalid or revoked daemon token")
			return
		}
		ctx := context.WithValue(r.Context(), ctxDaemon, dm)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
