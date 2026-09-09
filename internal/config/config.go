// Package config holds the strong-typed runtime configuration for the
// entrance control plane and the entranced agent.
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// ServerConfig configures the bastion (control plane).
type ServerConfig struct {
	// ListenAddr is the HTTPS bind address of the bastion.
	// Dev: 127.0.0.1:8443; prod: 0.0.0.0:443.
	ListenAddr string
	// DataDir persists the SQLite database, keys, TLS certs (0700).
	DataDir string
	// Dev enables the self-signed dev certificate and loopback-only binding.
	Dev bool
	// Hostname is the public name used for ACME (prod) and certs (dev).
	Hostname string
	// AdminPassword bootstraps the admin user on first run (env
	// ENTRANCE_ADMIN_PASSWORD). When empty in prod, generation is attempted
	// from an env var each boot.
	AdminPassword string
	// NetworkCIDR is the WG address space (default 10.99.0.0/24, D2).
	NetworkCIDR string
	// RelayDialMode: "wg" dials the daemon's tunnel IP; "loopback" dials
	// 127.0.0.1 (used in dev/rootless e2e where no TUN exists).
	RelayDialMode string
	// WGPort is the bastion's loopback WG anchor port (default 51820).
	WGPort uint16
	// DaemonWGPort is the default loopback WG anchor port on daemons.
	DaemonWGPort uint16
	// SessionTTL is the user-session sliding expiry (default 30d).
	SessionTTLDays int
	// TrustedProxies is the CIDR allowlist whose X-Forwarded-For headers are
	// trusted (e.g. your reverse proxy / LB). Empty = only loopback peers may
	// present XFF (dev / local nginx).
	TrustedProxies []string
}

// DefaultServer returns server defaults (macOS-friendly for dev).
func DefaultServer() ServerConfig {
	return ServerConfig{
		ListenAddr:     "127.0.0.1:8443",
		Dev:            true,
		NetworkCIDR:    "10.99.0.0/24",
		RelayDialMode:  "loopback",
		WGPort:         51820,
		DaemonWGPort:   51821,
		SessionTTLDays: 30,
	}
}

// DaemonConfig configures the entranced agent.
type DaemonConfig struct {
	// ServerURL is the bastion base URL (https://...).
	ServerURL string
	// DataDir persists agent state (token, keys) at 0700.
	DataDir string
	// EnrollSecret is the one-time enrollment secret (used once).
	EnrollSecret string
	// EnrollSecretEnv is an env var holding the enrollment secret.
	EnrollSecretEnv string
	// CAFile pins the bastion TLS cert (dev cert / corporate CA).
	CAFile string
	// AllowedPorts is the local port allowlist, e.g. [22, 3389, 5432].
	AllowedPorts []int
	// BindAddr is where daemon service sockets bind: the tunnel IP in
	// "tun" mode (default, needs root) or 127.0.0.1 in "loopback" mode.
	BindAddr string
	// NetMode: "tun" (real TUN interface) or "loopback" (rootless).
	NetMode string
	// Remap maps exposed target ports to different local ports.
	Remap map[int]int
	// WGPort is the daemon's loopback WG anchor port (default 51821).
	WGPort uint16
	// Hostname reported to the bastion (default os.Hostname).
	Hostname string
	// HeartbeatIntervalSec (default 30).
	HeartbeatIntervalSec int
}

// DefaultDaemon returns agent defaults.
func DefaultDaemon() DaemonConfig {
	h, _ := os.Hostname()
	return DaemonConfig{
		DataDir:              "~/.entrance-agent",
		NetMode:              "loopback",
		WGPort:               51821,
		Hostname:             h,
		HeartbeatIntervalSec: 30,
	}
}

// ParsePortList parses "22,3389,5432" into [22 3389 5432].
func ParsePortList(s string) ([]int, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		out = append(out, p)
	}
	return out, nil
}

// ParseRemap parses "22=2222,5432=5433" into {22:2222, 5432:5433}.
func ParseRemap(s string) (map[int]int, error) {
	out := map[int]int{}
	if strings.TrimSpace(s) == "" {
		return out, nil
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		from, to, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("invalid remap %q (want from=to)", part)
		}
		a, err1 := strconv.Atoi(strings.TrimSpace(from))
		b, err2 := strconv.Atoi(strings.TrimSpace(to))
		if err1 != nil || err2 != nil || a < 1 || a > 65535 || b < 1 || b > 65535 {
			return nil, fmt.Errorf("invalid remap %q", part)
		}
		out[a] = b
	}
	return out, nil
}

// ListenAddrPort splits host:port, validating the combination.
func ListenAddrPort(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port in %q", addr)
	}
	return host, port, nil
}
