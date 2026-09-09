package api

import (
	"time"

	"entrance/internal/wsproto"
)

// Request/response types for the control-plane API (see DESIGN D-API).

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	SessionToken string    `json:"session_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type EnrollSecretRequest struct {
	Label string `json:"label"`
}

type EnrollSecretResponse struct {
	Secret    string    `json:"secret"`
	Label     string    `json:"label"`
	ExpiresAt time.Time `json:"expires_at"`
}

type EnrollRequest struct {
	EnrollmentSecret string      `json:"enrollment_secret"`
	Hostname         string      `json:"hostname"`
	WGPublicKey      string      `json:"wg_public_key"`
	Version          string      `json:"version"`
	AllowedPorts     []int       `json:"allowed_ports,omitempty"`
	Remap            map[int]int `json:"remap,omitempty"`
}

type EnrollResponse struct {
	DaemonID int64          `json:"daemon_id"`
	Token    string         `json:"token"`
	Config   wsproto.Config `json:"config"`
}

type DaemonView struct {
	ID           int64     `json:"id"`
	Hostname     string    `json:"hostname"`
	WGIP         string    `json:"wg_ip"`
	Version      string    `json:"version"`
	AllowedPorts []int     `json:"allowed_ports"`
	Status       string    `json:"status"` // online | stale | pending
	CreatedAt    time.Time `json:"created_at"`
	LastSeenAt   time.Time `json:"last_seen_at"`
	ActiveRelays int       `json:"active_relays"`
	// WGHandshake reports whether the hub has completed a WireGuard handshake
	// with this daemon within the freshness window (diagnostics + e2e).
	WGHandshake bool `json:"wg_handshake"`
}

type HeartbeatRequest struct {
	Version      string      `json:"version"`
	Error        string      `json:"error,omitempty"`
	AllowedPorts []int       `json:"allowed_ports,omitempty"`
	Remap        map[int]int `json:"remap,omitempty"`
}

type HeartbeatResponse struct {
	Config *wsproto.Config `json:"config,omitempty"`
}

type MeResponse struct {
	Config wsproto.Config `json:"config"`
}

type RelayCreateRequest struct {
	DaemonID   int64  `json:"daemon_id"`
	TargetPort int    `json:"target_port"`
	Protocol   string `json:"protocol"` // tcp (only tcp in phase 1)
}

type RelayCreateResponse struct {
	SessionID string `json:"session_id"`
	DaemonID  int64  `json:"daemon_id"`
	Target    string `json:"target"`
}

type ServiceCreateRequest struct {
	Name       string `json:"name"`
	TargetPort int    `json:"target_port"`
	LocalPort  int    `json:"local_port"`
	Protocol   string `json:"protocol"`
}
