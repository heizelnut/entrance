package api

import (
	"net/http"
	"strconv"
)

// Services are the operator-declared target services of a daemon; phase 2
// uses them for richer connect UX. Phase 1 keeps a small, real CRUD surface.

// GET /api/v1/daemons/{id}/services
func (s *Server) handleListServices(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid daemon id")
		return
	}
	svcs, err := s.db.ListServices(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	writeJSON(w, http.StatusOK, svcs)
}

// POST /api/v1/daemons/{id}/services
func (s *Server) handleCreateService(w http.ResponseWriter, r *http.Request) {
	_ = userFrom(r)
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
	var req ServiceCreateRequest
	if err := readJSON(w, r, &req); err != nil {
		return
	}
	if req.Name == "" || req.TargetPort < 1 || req.TargetPort > 65535 {
		writeErr(w, http.StatusBadRequest, "name and target_port required")
		return
	}
	local := req.LocalPort
	if local == 0 {
		local = req.TargetPort
	}
	if req.Protocol == "" {
		req.Protocol = "tcp"
	}
	svc, err := s.db.CreateService(id, req.Name, req.TargetPort, local, req.Protocol)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create failed")
		return
	}
	writeJSON(w, http.StatusCreated, svc)
}

// DELETE /api/v1/services/{id}
func (s *Server) handleDeleteService(w http.ResponseWriter, r *http.Request) {
	_ = userFrom(r)
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid service id")
		return
	}
	if err := s.db.DeleteService(id); err != nil {
		writeErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
