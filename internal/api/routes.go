package api

import "net/http"

// Routes wires the full control-plane HTTP surface (D-API).
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// health
	mux.HandleFunc("GET /healthz", s.handleHealth)

	// auth
	mux.Handle("POST /api/v1/auth/login", http.HandlerFunc(s.handleLogin))
	mux.Handle("POST /api/v1/auth/logout", s.requireUser(http.HandlerFunc(s.handleLogout)))

	// enrollment secrets (operator)
	mux.Handle("POST /api/v1/enroll-secrets", s.requireUser(http.HandlerFunc(s.handleCreateEnrollSecret)))

	// daemons
	mux.Handle("POST /api/v1/daemons/enroll", http.HandlerFunc(s.handleEnroll))
	mux.Handle("GET /api/v1/daemons/me", s.requireDaemon(http.HandlerFunc(s.handleDaemonMe)))
	mux.Handle("POST /api/v1/daemons/me/heartbeat", s.requireDaemon(http.HandlerFunc(s.handleDaemonHeartbeat)))
	mux.Handle("GET /api/v1/daemons/me/ws", s.requireDaemon(http.HandlerFunc(s.handleDaemonWS)))
	mux.Handle("GET /api/v1/daemons", s.requireUser(http.HandlerFunc(s.handleListDaemons)))
	mux.Handle("GET /api/v1/daemons/{id}", s.requireUser(http.HandlerFunc(s.handleGetDaemon)))
	mux.Handle("DELETE /api/v1/daemons/{id}", s.requireUser(http.HandlerFunc(s.handleDeleteDaemon)))
	mux.Handle("POST /api/v1/daemons/{id}/rotate", s.requireUser(http.HandlerFunc(s.handleRotateDaemonToken)))

	// relays (user data plane)
	mux.Handle("POST /api/v1/relays", s.requireUser(http.HandlerFunc(s.handleCreateRelay)))
	mux.Handle("GET /api/v1/relays/{id}/ws", s.requireUser(http.HandlerFunc(s.handleRelayWS)))

	// services
	mux.Handle("GET /api/v1/daemons/{id}/services", s.requireUser(http.HandlerFunc(s.handleListServices)))
	mux.Handle("POST /api/v1/daemons/{id}/services", s.requireUser(http.HandlerFunc(s.handleCreateService)))
	mux.Handle("DELETE /api/v1/services/{id}", s.requireUser(http.HandlerFunc(s.handleDeleteService)))

	return s.withRecover(s.withLogging(mux))
}
