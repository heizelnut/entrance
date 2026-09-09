package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"entrance/internal/config"
	"entrance/internal/db"
	"entrance/internal/wg"
)

// newTestServer boots an in-process control plane (FakeTUN hub, no root).
func newTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	cfg := config.DefaultServer()
	cfg.DataDir = filepath.Join(t.TempDir(), "data")
	cfg.Dev = true
	cfg.AdminPassword = "test-admin-pw"
	// unique anchor per test to avoid loopback port collisions
	cfg.WGPort = uint16(52000 + (time.Now().Nanosecond() % 20000))
	cfg.RelayDialMode = "loopback"
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := db.Open(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	srv, err := NewServer(cfg, store, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	ts := httptest.NewServer(srv.Routes())
	t.Cleanup(ts.Close)
	return srv, ts
}

type testClient struct {
	t    *testing.T
	base string
	tok  string
}

func (c *testClient) req(method, path string, body any, want int) []byte {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		c.t.Fatal(err)
	}
	if c.tok != "" {
		req.Header.Set("Authorization", "Bearer "+c.tok)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if want != 0 && resp.StatusCode != want {
		c.t.Fatalf("%s %s: status %d want %d: %s", method, path, resp.StatusCode, want, out)
	}
	return out
}

func (c *testClient) login(user, pass string) {
	var resp struct {
		SessionToken string `json:"session_token"`
	}
	_ = json.Unmarshal(c.req("POST", "/api/v1/auth/login",
		map[string]string{"username": user, "password": pass}, 200), &resp)
	c.tok = resp.SessionToken
}

func (c *testClient) enroll(secret string, port int) (string, string) {
	key, _, err := wg.GenerateKeyPair()
	if err != nil {
		c.t.Fatal(err)
	}
	body := map[string]any{
		"hostname":          "host-" + key[:4],
		"wg_public_key":     key,
		"enrollment_secret": secret,
		"allowed_ports":     []int{port},
	}
	var out struct {
		DaemonID int64  `json:"daemon_id"`
		Token    string `json:"token"`
		Config   struct {
			WGIP string `json:"wg_ip"`
		} `json:"config"`
	}
	_ = json.Unmarshal(c.req("POST", "/api/v1/daemons/enroll", body, 201), &out)
	return out.Config.WGIP, out.Token
}

func (c *testClient) newSecret(label string) string {
	var out struct {
		Secret string `json:"secret"`
	}
	_ = json.Unmarshal(c.req("POST", "/api/v1/enroll-secrets",
		map[string]string{"label": label}, 201), &out)
	return out.Secret
}

// TestEnrollIPAMSequential is the end-to-end regression for the
// lexicographic-IPAM bug: 12 sequential enrolls must produce .2..13 and the
// 13th .14 — previously the 11th+ enroll failed with a UNIQUE/500.
func TestEnrollIPAMSequential(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	_, ts := newTestServer(t)
	c := &testClient{t: t, base: ts.URL}
	c.login("admin", "test-admin-pw")
	seen := map[string]bool{}
	for i := 0; i < 12; i++ {
		ip, _ := c.enroll(c.newSecret(fmt.Sprintf("h%d", i)), 2200+i)
		if seen[ip] {
			t.Fatalf("duplicate wg_ip %s", ip)
		}
		seen[ip] = true
	}
	for i := 0; i < 12; i++ {
		want := fmt.Sprintf("10.99.0.%d", i+2)
		if !seen[want] {
			t.Fatalf("missing expected allocation %s (have %v)", want, seen)
		}
	}
}

// TestEnrollSecretSingleUse: the same enrollment secret cannot mint two hosts.
func TestEnrollSecretSingleUse(t *testing.T) {
	_, ts := newTestServer(t)
	c := &testClient{t: t, base: ts.URL}
	c.login("admin", "test-admin-pw")
	secret := c.newSecret("one-shot")
	c.enroll(secret, 22)
	key, _, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	out := c.req("POST", "/api/v1/daemons/enroll", map[string]any{
		"hostname":          "second",
		"wg_public_key":     key,
		"enrollment_secret": secret,
		"allowed_ports":     []int{22},
	}, 0)
	if bytes.Contains(out, []byte(`"daemon_id"`)) {
		t.Fatalf("single-use secret minted a second daemon: %s", out)
	}
}

// TestRelayAllowlist: a relay to a port outside the daemon's allowlist is
// rejected before any dial; an in-allowlist but unreachable port fails as 502.
func TestRelayAllowlist(t *testing.T) {
	_, ts := newTestServer(t)
	c := &testClient{t: t, base: ts.URL}
	c.login("admin", "test-admin-pw")
	_, tok := c.enroll(c.newSecret("allow"), 22999)
	c.tok = tok // act as… no: relays need a USER session
	c.login("admin", "test-admin-pw")
	var list []struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal(c.req("GET", "/api/v1/daemons", nil, 200), &list)
	if len(list) == 0 {
		t.Fatal("no daemons listed")
	}
	damID := list[0].ID
	// port is in the allowlist but nothing listens on it -> dial error -> 502
	c.req("POST", "/api/v1/relays", map[string]any{
		"daemon_id": damID, "target_port": 22999, "protocol": "tcp",
	}, http.StatusBadGateway)
	// not allowlisted -> 403 without dialing
	out := c.req("POST", "/api/v1/relays", map[string]any{
		"daemon_id": damID, "target_port": 22, "protocol": "tcp",
	}, http.StatusForbidden)
	if !strings.Contains(string(out), "allowlist") {
		t.Fatalf("expected allowlist message, got %s", out)
	}
}

// TestLoginRateLimited: more than 10 failed logins per IP gets throttled.
func TestLoginRateLimited(t *testing.T) {
	_, ts := newTestServer(t)
	c := &testClient{t: t, base: ts.URL}
	for i := 0; i < 11; i++ {
		want := http.StatusUnauthorized
		if i == 10 {
			want = http.StatusTooManyRequests
		}
		c.req("POST", "/api/v1/auth/login", map[string]string{
			"username": "admin", "password": fmt.Sprintf("wrong-%d", i),
		}, want)
	}
}
