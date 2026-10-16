package bastion

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"entrance/internal/agent"
	"entrance/internal/proto"
)

// startTestBastion boots a dev bastion on a random loopback port.
func startTestBastion(t *testing.T) (*Bastion, string) {
	t.Helper()
	b, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		DataDir:    t.TempDir(),
		Dev:        true,
		Hostname:   "localhost",
		RPID:       "localhost",
		Origin:     "http://localhost",
		Token:      "test-token",
	}, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = b.Serve(ctx, ln) }()
	return b, "http://" + ln.Addr().String()
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// TestAgentTokenRequired verifies the /agent endpoint rejects a bad token.
func TestAgentTokenRequired(t *testing.T) {
	_, base := startTestBastion(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	wsURL := "ws" + strings.TrimPrefix(base, "http") + "/agent"
	_, resp, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer wrong"}},
	})
	if err == nil {
		t.Fatal("expected dial to fail with a bad token")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %v, want 401", resp)
	}
}

// TestHostsAPIRefusesAnonymous verifies the host API requires a session.
func TestHostsAPIRefusesAnonymous(t *testing.T) {
	_, base := startTestBastion(t)
	res, err := http.Get(base + "/api/hosts")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.StatusCode)
	}
}

// TestShellEndToEnd runs the full path: agent connects with the token, an
// authenticated browser session opens a shell, and command output comes back.
func TestShellEndToEnd(t *testing.T) {
	b, base := startTestBastion(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a := agent.New(agent.Config{
		ServerURL: base, Token: "test-token", Hostname: "testhost", Shell: "/bin/sh",
	}, slog.Default())
	go func() { _ = a.Run(ctx) }()

	// Wait for the agent to register.
	deadline := time.Now().Add(8 * time.Second)
	for b.agent("testhost") == nil {
		if time.Now().After(deadline) {
			t.Fatal("agent did not connect")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Mint an admin session directly (WebAuthn needs a real authenticator).
	sid, err := b.st.CreateSession(time.Hour)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse(base)
	jar.SetCookies(u, []*http.Cookie{{Name: sessionCookie, Value: sid}})
	client := &http.Client{Jar: jar}

	wsURL := "ws" + strings.TrimPrefix(base, "http") + "/ws/shell/testhost?cols=80&rows=24"
	ws, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPClient: client})
	if err != nil {
		t.Fatalf("dial shell: %v", err)
	}
	defer ws.CloseNow()

	if err := ws.Write(ctx, websocket.MessageText, mustJSON(t, proto.Msg{
		T: proto.TShellData, Data: []byte("echo entrance-e2e-ok\n"),
	})); err != nil {
		t.Fatalf("write: %v", err)
	}

	rctx, rcancel := context.WithTimeout(ctx, 10*time.Second)
	defer rcancel()
	var got strings.Builder
	for !strings.Contains(got.String(), "entrance-e2e-ok") {
		_, data, err := ws.Read(rctx)
		if err != nil {
			t.Fatalf("read: %v (got %q)", err, got.String())
		}
		var m proto.Msg
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		switch m.T {
		case proto.TShellData:
			got.Write(m.Data)
		case proto.TError:
			t.Fatalf("agent error: %s", m.Error)
		}
	}
}
