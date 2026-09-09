package api

import (
	"net/http"

	"github.com/coder/websocket"

	"entrance/internal/relay"
)

// POST /api/v1/relays — user opens a data-plane session to a daemon target
// (D4). The bastion dials the daemon and registers the session; the user then
// attaches their WebSocket to /api/v1/relays/{id}/ws.
func (s *Server) handleCreateRelay(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	var req RelayCreateRequest
	if err := readJSON(w, r, &req); err != nil {
		return
	}
	if req.TargetPort < 1 || req.TargetPort > 65535 {
		writeErr(w, http.StatusBadRequest, "invalid target_port")
		return
	}
	if req.Protocol == "" {
		req.Protocol = "tcp"
	}
	if req.Protocol != "tcp" {
		writeErr(w, http.StatusBadRequest, "only tcp relays in phase 1")
		return
	}

	dm, err := s.db.GetDaemonByID(req.DaemonID)
	if err != nil || dm.DeactivatedAt != nil {
		writeErr(w, http.StatusNotFound, "daemon not found")
		return
	}
	if !portAllowed(dm.AllowedPorts, req.TargetPort) {
		writeErr(w, http.StatusForbidden, "target port not in daemon allowlist")
		return
	}

	sess, err := s.relays.Create(dm.ID, user.ID, req.TargetPort, req.Protocol)
	if err != nil {
		s.log.Warn("relay dial failed", "daemon", dm.ID, "port", req.TargetPort, "err", err)
		writeErr(w, http.StatusBadGateway, "unable to reach daemon target: "+err.Error())
		return
	}
	// record the relay row for daemon history/audit (pruned on close)
	if _, err := s.db.CreateRelay(dm.ID, user.ID, sess.ID, req.TargetPort, req.Protocol); err != nil {
		s.log.Warn("recording relay row failed", "err", err)
	}

	writeJSON(w, http.StatusCreated, RelayCreateResponse{
		SessionID: sess.ID,
		DaemonID:  dm.ID,
		Target:    sess.Target,
	})
}

// GET /api/v1/relays/{id}/ws — bridge the user's WebSocket to the session.
func (s *Server) handleRelayWS(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r)
	sess, ok := s.relays.Get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "relay session not found")
		return
	}
	if sess.UserID != user.ID {
		writeErr(w, http.StatusForbidden, "relay session belongs to another user")
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		return
	}
	s.relays.Attach(sess, ws)
}

func portAllowed(allowed []int, port int) bool {
	for _, p := range allowed {
		if p == port {
			return true
		}
	}
	return false
}

var _ = relay.SessionInfo{}
