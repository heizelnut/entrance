package db

import (
	"encoding/json"
	"time"
)

// User is an admin/operator account (D3).
type User struct {
	ID            int64
	Username      string
	PasswordHash  string
	IsAdmin       bool
	CreatedAt     time.Time
	DeactivatedAt *time.Time
}

// Session is an opaque user session token (SHA-256 hashed in DB, 30d sliding).
type Session struct {
	TokenHash  string
	UserID     int64
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeenAt time.Time
}

// EnrollSecret is a single-use, expiring enrollment secret (D3).
type EnrollSecret struct {
	ID             int64
	SecretHash     string
	Label          string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	UsedAt         *time.Time
	UsedByDaemonID *int64
}

// Daemon is a registered agent (spoke).
type Daemon struct {
	ID            int64
	WGPublicKey   string
	TokenHash     string
	Hostname      string
	WGIP          string
	Version       string
	AllowedPorts  []int
	Remap         map[int]int
	CreatedAt     time.Time
	LastSeenAt    time.Time
	DeactivatedAt *time.Time
	ActiveRelays  int // computed, not stored
}

// Relay is a user data-plane session (D4).
type Relay struct {
	ID         int64
	DaemonID   int64
	TargetPort int
	Protocol   string
	UserID     int64
	CreatedAt  time.Time
}

// RelayStat bundles a relay with the daemon it targets.
type RelayStat struct {
	Relay
	DaemonID   int64  `json:"-"`
	DaemonName string `json:"daemon_name"`
}

// Service is a declared target service on a daemon.
type Service struct {
	ID         int64
	DaemonID   int64
	Name       string
	TargetPort int
	LocalPort  int
	Protocol   string
	Enabled    bool
	CreatedAt  time.Time
}

const timeFmt = time.RFC3339Nano

// formatTime writes timestamps with FIXED-width fractional seconds. RFC3339
// text is ordered lexicographically in SQLite; variable-width fractions (e.g.
// ".9Z" vs ".10Z") would sort incorrectly, so pad to a constant width.
func formatTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000000000Z") }

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(timeFmt, s)
}

func parseTimePtr(s string) *time.Time {
	t, err := parseTime(s)
	if err != nil || t.IsZero() {
		return nil
	}
	return &t
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return formatTime(t)
}

func parsePorts(s string) []int {
	var out []int
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

func encodePorts(p []int) string {
	if p == nil {
		p = []int{}
	}
	b, _ := json.Marshal(p)
	return string(b)
}

func parseRemap(s string) map[int]int {
	out := map[int]int{}
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

func encodeRemap(m map[int]int) string {
	if m == nil {
		m = map[int]int{}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
