package api

import (
	"database/sql"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/coder/websocket"

	"entrance/internal/auth"
	"entrance/internal/db"
	"entrance/internal/wg"
	"entrance/internal/wsproto"
)

const daemonStaleAfter = 90 * time.Second

// POST /api/v1/daemons/enroll — consume an enrollment secret, allocate a WG
// address, drop a token (returned once), update the hub peer set (D2/D3).
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req EnrollRequest
	if err := readJSON(w, r, &req); err != nil {
		return
	}
	if req.Hostname == "" || len(req.Hostname) > 255 {
		writeErr(w, http.StatusBadRequest, "hostname required (max 255 chars)")
		return
	}
	if !wg.IsValidPublicKey(req.WGPublicKey) {
		writeErr(w, http.StatusBadRequest, "invalid wg_public_key")
		return
	}
	if len(req.AllowedPorts) > 64 || len(req.Remap) > 64 {
		writeErr(w, http.StatusBadRequest, "too many ports (max 64)")
		return
	}
	for _, p := range req.AllowedPorts {
		if p < 1 || p > 65535 {
			writeErr(w, http.StatusBadRequest, "invalid allowlisted port")
			return
		}
	}
	for from, to := range req.Remap {
		if from < 1 || from > 65535 || to < 1 || to > 65535 {
			writeErr(w, http.StatusBadRequest, "invalid remap port")
			return
		}
	}
	secretRow, err := s.db.GetUnexpiredEnrollSecretByLookup(
		auth.HashToken(req.EnrollmentSecret), time.Now().UTC())
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid or expired enrollment secret")
		return
	}
	if !auth.VerifyPassword(secretRow.SecretHash, req.EnrollmentSecret) {
		writeErr(w, http.StatusUnauthorized, "invalid enrollment secret")
		return
	}

	token, err := auth.GenerateToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	tokenHash := auth.HashToken(token)

	// Address allocation, daemon insert and secret consumption happen inside
	// ONE transaction: the wg_ip high-water mark cannot race with a concurrent
	// enroll, and the conditional secret UPDATE (used_at IS NULL) defeats
	// double-spend of the single-use secret. Argon2 verification stays outside
	// the tx so the single writer connection is not held for ~100ms of hashing.
	var addr netip.Addr
	var daemonID int64
	err = s.db.WithTx(func(tx *sql.Tx) error {
		maxIP, err := s.db.MaxWGIPTx(tx)
		if err != nil {
			return err
		}
		count, err := s.db.CountActiveDaemonsTx(tx)
		if err != nil {
			return err
		}
		addr, err = s.ipam.AddressForAllocation(parseAddr(maxIP), count)
		if err != nil {
			return err
		}
		id, err := s.db.CreateDaemon(tx, req.WGPublicKey, tokenHash, req.Hostname,
			addr.String(), req.Version, req.AllowedPorts, req.Remap)
		if err != nil {
			return err
		}
		daemonID = id
		return s.db.MarkEnrollSecretUsed(secretRow.ID, id, tx)
	})
	if err != nil {
		if errors.Is(err, db.ErrSecretAlreadyUsed) {
			writeErr(w, http.StatusUnauthorized, "invalid or expired enrollment secret")
			return
		}
		s.log.Warn("enroll failed", "err", err)
		writeErr(w, http.StatusServiceUnavailable, "enroll failed; try again")
		return
	}

	if err := s.rebuildHubPeers(); err != nil {
		s.log.Error("hub reconfig failed", "err", err)
	}

	// daemon config handed back once, at enroll
	cfg := wsproto.Config{
		WGIP:                 addr.String(),
		BastionWGIP:          s.ipam.BastionIP().String(),
		BastionWGPubKey:      s.hubPubKey(),
		BastionWGPort:        s.cfg.WGPort,
		NetworkCIDR:          s.ipam.Network(),
		AllowedPorts:         req.AllowedPorts,
		Remap:                req.Remap,
		HeartbeatIntervalSec: 30,
	}
	writeJSON(w, http.StatusCreated, EnrollResponse{
		DaemonID: daemonID,
		Token:    token,
		Config:   cfg,
	})
}

// GET /api/v1/daemons — user host list.
func (s *Server) handleListDaemons(w http.ResponseWriter, r *http.Request) {
	_ = userFrom(r)
	daemons, err := s.db.ListDaemons()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	out := make([]DaemonView, 0, len(daemons))
	now := time.Now().UTC()
	// One device Status() dump per request (not per daemon).
	var handshakes map[string]bool
	if s.hub.dev != nil {
		if st, err := s.hub.dev.Status(); err == nil {
			handshakes = make(map[string]bool, len(st))
			for _, p := range st {
				handshakes[p.PublicKey] = time.Since(p.LastHandshake) <= 3*time.Minute
			}
		}
	}
	for _, dm := range daemons {
		out = append(out, s.daemonView(dm, now, handshakes))
	}
	writeJSON(w, http.StatusOK, out)
}

// GET /api/v1/daemons/{id} — detail with relay stats.
func (s *Server) handleGetDaemon(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid daemon id")
		return
	}
	dm, err := s.db.GetDaemonByID(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "daemon not found")
		return
	}
	if dm.DeactivatedAt != nil {
		writeErr(w, http.StatusNotFound, "daemon not found")
		return
	}
	if rels := s.relays.List(dm.ID); len(rels) > 0 {
		dm.ActiveRelays = len(rels)
	}
	writeJSON(w, http.StatusOK, s.daemonView(dm, time.Now().UTC(), nil))
}

// DELETE /api/v1/daemons/{id} — revoke: close relays, remove hub peer, mark
// deactivated (token becomes invalid, D7).
func (s *Server) handleDeleteDaemon(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid daemon id")
		return
	}
	dm, err := s.db.GetDaemonByID(id)
	if err != nil || dm.DeactivatedAt != nil {
		writeErr(w, http.StatusNotFound, "daemon not found")
		return
	}
	s.relays.CloseDaemon(id)
	if err := s.db.DeactivateDaemon(id); err != nil {
		writeErr(w, http.StatusInternalServerError, "revoke failed")
		return
	}
	_ = s.rebuildHubPeers()
	// close the daemon's live control channel with a policy-violation close
	// frame so it immediately learns it was revoked (D7: 401-style revoke).
	hubT := s.hub.dev.Transport().(*wg.HubTransport)
	tok := uint16(mustPort(endpointToken(id)))
	if dw, ok := hubT.Lookup(tok); ok {
		if cc, ok := dw.(*wsproto.Conn); ok {
			_ = cc.WriteClose("daemon revoked", websocket.StatusPolicyViolation)
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// POST /api/v1/daemons/{id}/rotate — phase 2 stub: returns 501.
func (s *Server) handleRotateDaemonToken(w http.ResponseWriter, r *http.Request) {
	writeErr(w, http.StatusNotImplemented, "token rotation lands in phase 2")
}

// GET /api/v1/daemons/me — daemon config snapshot (D-API).
func (s *Server) handleDaemonMe(w http.ResponseWriter, r *http.Request) {
	dm := daemonFrom(r)
	writeJSON(w, http.StatusOK, MeResponse{Config: s.daemonConfig(dm)})
}

// POST /api/v1/daemons/me/heartbeat — daemon liveness + status report.
func (s *Server) handleDaemonHeartbeat(w http.ResponseWriter, r *http.Request) {
	dm := daemonFrom(r)
	var req HeartbeatRequest
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad heartbeat body")
		return
	}
	if err := s.db.UpdateDaemonStatus(dm.ID, orDefault(req.Version, dm.Version),
		req.AllowedPorts, req.Remap); err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	reply := HeartbeatResponse{Config: nil}
	if req.Error != "" {
		s.log.Warn("daemon reported error", "daemon", dm.ID, "err", req.Error)
	}
	writeJSON(w, http.StatusOK, reply)
}

func (s *Server) daemonView(dm *db.Daemon, now time.Time, handshakes map[string]bool) DaemonView {
	status := "pending"
	if !dm.LastSeenAt.IsZero() {
		if now.Sub(dm.LastSeenAt) <= daemonStaleAfter {
			status = "online"
		} else {
			status = "stale"
		}
	}
	handshake := false
	if handshakes != nil {
		handshake = handshakes[dm.WGPublicKey]
	} else if s.hub.dev != nil {
		handshake = s.hub.dev.HandshakeComplete(dm.WGPublicKey, 3*time.Minute)
	}
	return DaemonView{
		ID:           dm.ID,
		Hostname:     dm.Hostname,
		WGIP:         dm.WGIP,
		Version:      dm.Version,
		AllowedPorts: dm.AllowedPorts,
		Status:       status,
		CreatedAt:    dm.CreatedAt,
		LastSeenAt:   dm.LastSeenAt,
		ActiveRelays: dm.ActiveRelays,
		WGHandshake:  handshake,
	}
}

func (s *Server) daemonConfig(dm *db.Daemon) wsproto.Config {
	return wsproto.Config{
		WGIP:                 dm.WGIP,
		BastionWGIP:          s.ipam.BastionIP().String(),
		BastionWGPubKey:      s.hubPubKey(),
		BastionWGPort:        s.cfg.WGPort,
		NetworkCIDR:          s.ipam.Network(),
		AllowedPorts:         dm.AllowedPorts,
		Remap:                dm.Remap,
		HeartbeatIntervalSec: 30,
	}
}

// hubPubKey returns the hub's WG public key from settings.
func (s *Server) hubPubKey() string {
	pub, err := s.db.GetSetting(settingWGPubKey)
	if err != nil {
		return ""
	}
	return pub
}

func pathID(r *http.Request) (int64, bool) {
	raw := r.PathValue("id")
	id, err := strconv.ParseInt(raw, 10, 64)
	return id, err == nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// parseAddr parses a stored WG IP, tolerating empty.
func parseAddr(s string) netip.Addr {
	if s == "" {
		return netip.Addr{}
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return a
}
