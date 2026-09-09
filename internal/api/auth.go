package api

import (
	"net/http"
	"time"

	"entrance/internal/auth"
)

// argon2Sem bounds concurrent password verifications: each costs ~64MB of
// memory, so unbounded concurrent logins are a memory-exhaustion vector.
var argon2Sem = make(chan struct{}, 4)

// POST /api/v1/auth/login — rate-limited username/password auth (D3).
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !s.loginLimiter.Allow(ip) {
		writeErr(w, http.StatusTooManyRequests, "too many login attempts; try later")
		return
	}
	var req LoginRequest
	if err := readJSON(w, r, &req); err != nil {
		return
	}
	if req.Username == "" || req.Password == "" {
		writeErr(w, http.StatusBadRequest, "username and password required")
		return
	}
	user, err := s.db.GetUserByUsername(req.Username)
	// Both the found and not-found paths burn a full argon2 verification
	// (dummy hash on miss) so response timing does not enumerate usernames.
	argon2Sem <- struct{}{}
	if err != nil {
		_ = auth.VerifyPassword(auth.DummyPasswordHash, req.Password)
		<-argon2Sem
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	ok := auth.VerifyPassword(user.PasswordHash, req.Password)
	<-argon2Sem
	if !ok {
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	token, err := auth.GenerateToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	sess, err := s.db.CreateSession(user.ID, auth.HashToken(token), s.sessionTTL)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "session creation failed")
		return
	}
	writeJSON(w, http.StatusOK, LoginResponse{
		SessionToken: token,
		ExpiresAt:    sess.ExpiresAt,
	})
}

// POST /api/v1/auth/logout — invalidate the session.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token != "" {
		_ = s.db.DeleteSession(auth.HashToken(token))
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// POST /api/v1/enroll-secrets — operator creates a single-use secret (D3).
func (s *Server) handleCreateEnrollSecret(w http.ResponseWriter, r *http.Request) {
	_ = userFrom(r)
	var req EnrollSecretRequest
	if err := readJSON(w, r, &req); err != nil {
		return
	}
	if req.Label == "" {
		writeErr(w, http.StatusBadRequest, "label required")
		return
	}
	secret, err := auth.GenerateToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "secret generation failed")
		return
	}
	hash, err := auth.HashPassword(secret) // argon2id, per D3
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "hashing failed")
		return
	}
	expires := time.Now().UTC().Add(enrollSecretTTL)
	if _, err := s.db.CreateEnrollSecret(hash, auth.HashToken(secret), req.Label, enrollSecretTTL); err != nil {
		writeErr(w, http.StatusInternalServerError, "secret creation failed")
		return
	}
	writeJSON(w, http.StatusCreated, EnrollSecretResponse{
		Secret:    secret,
		Label:     req.Label,
		ExpiresAt: expires,
	})
}

const enrollSecretTTL = 24 * time.Hour
