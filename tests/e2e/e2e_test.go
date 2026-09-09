// Package e2e runs the phase-1 vertical slice end-to-end, rootless:
//
//	entrance (control plane, dev TLS on 127.0.0.1)
//	→ enroll entranced (agent, loopback mode — no TUN, no root)
//	→ WireGuard handshake completes over the HTTPS control channel
//	→ user relay session reaches a loopback echo service on the agent
//	→ revocation terminates the agent with the revoked exit code
//
// Everything runs on 127.0.0.1 with self-signed TLS pinned via --ca-file.
package e2e

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"entrance/internal/client"
)

var (
	entranceBin  string
	entrancedBin string
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "entrance-bin")
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e:", err)
		os.Exit(1)
	}
	defer os.RemoveAll(dir)
	entranceBin = filepath.Join(dir, "entrance")
	entrancedBin = filepath.Join(dir, "entranced")
	if err := build("entrance", "./cmd/entrance", entranceBin); err != nil {
		fmt.Fprintln(os.Stderr, "e2e build entrance:", err)
		os.Exit(1)
	}
	if err := build("entranced", "./cmd/entranced", entrancedBin); err != nil {
		fmt.Fprintln(os.Stderr, "e2e build entranced:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func build(name, pkg, out string) error {
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Dir = repoRoot()
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func repoRoot() string {
	dir, _ := os.Getwd() // tests/e2e
	return filepath.Dir(filepath.Dir(dir))
}

// TestVerticalSliceRootless is the full flow.
func TestVerticalSliceRootless(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}

	tmp := t.TempDir()
	ctrlDir := filepath.Join(tmp, "ctrl")
	daemonDir := filepath.Join(tmp, "agent")
	adminPassword := "correct-horse-battery-staple-9"

	port := freeTCPPort(t)
	baseURL := fmt.Sprintf("https://127.0.0.1:%d", port)
	// WG anchor ports derived from the (random) HTTP port so concurrent test
	// runs cannot collide on the fixed 51820/51821 defaults.
	hubWGPort := port + 10
	daemonWGPort := port + 11

	// --- start the control plane ---
	ctrl := exec.Command(entranceBin, "serve",
		"--data-dir", ctrlDir,
		"--dev",
		"--relay-mode", "loopback",
		"--listen", fmt.Sprintf("127.0.0.1:%d", port),
		"--wg-port", strconv.Itoa(hubWGPort),
	)
	ctrl.Env = append(os.Environ(), "ENTRANCE_ADMIN_PASSWORD="+adminPassword)
	ctrl.Stdout = os.Stderr
	ctrl.Stderr = os.Stderr
	if err := ctrl.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctrl.Process.Signal(os.Interrupt)
		_ = waitTimeout(ctrl, 5*time.Second)
	}()
	t.Cleanup(func() { _ = ctrl.Process.Kill() })

	// pin the dev cert
	caFile := filepath.Join(ctrlDir, "tls", "cert.pem")
	waitForFile(t, caFile, 15*time.Second)
	admin := newClient(t, baseURL, caFile)

	waitHealthy(t, admin, 20*time.Second)

	// --- login + enroll secret ---
	ctx := context.Background()
	if _, err := admin.Login(ctx, "admin", adminPassword); err != nil {
		t.Fatalf("login: %v", err)
	}
	sec, err := admin.CreateEnrollSecret(ctx, "e2e-host")
	if err != nil {
		t.Fatalf("enroll secret: %v", err)
	}

	// --- local echo service the agent will expose ---
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	echoPort := ln.Addr().(*net.TCPAddr).Port
	go echoServer(ln)

	// --- start the agent ---
	agent := exec.Command(entrancedBin,
		"--server", baseURL,
		"--data-dir", daemonDir,
		"--secret", sec.Secret,
		"--allow", fmt.Sprintf("%d", echoPort),
		"--ca-file", caFile,
		"--net-mode", "loopback",
		"--wg-port", strconv.Itoa(daemonWGPort),
		"--log-level", "debug",
	)
	agent.Stdout = os.Stderr
	agent.Stderr = os.Stderr
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = agent.Process.Kill() })

	// --- wait for the daemon to come online + WG handshake ---
	var daemonID int64
	waitFor(t, 30*time.Second, func() bool {
		hosts, err := admin.ListDaemons(ctx)
		if err != nil || len(hosts) == 0 {
			return false
		}
		daemonID = hosts[0].ID
		return hosts[0].Status == "online" && hosts[0].WGHandshake
	}, "daemon online with wg handshake")

	// --- echo over a relay session ---
	tunnel, err := admin.Tunnel(ctx, daemonID, echoPort)
	if err != nil {
		t.Fatalf("tunnel: %v", err)
	}
	defer tunnel.Close()
	payload := []byte("entrance-e2e-ping")
	got, err := tunnel.RelayEcho(ctx, payload, 10*time.Second)
	if err != nil {
		t.Fatalf("relay echo: %v", err)
	}
	if !bytes.Contains(got, payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}
	t.Logf("relay echo ok: %q", got)

	// --- revocation terminates the agent with ExitRevoked ---
	if err := admin.DeleteDaemon(ctx, daemonID); err != nil {
		t.Fatalf("delete daemon: %v", err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if agent.ProcessState != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = waitTimeout(agent, 15*time.Second)
	if code := agent.ProcessState.ExitCode(); code != 3 {
		t.Fatalf("expected agent exit code 3 (revoked), got %d", code)
	}
	t.Log("agent exited with revoked code 3")
}

// --- helpers ---

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func newClient(t *testing.T, baseURL, caFile string) *client.Client {
	t.Helper()
	c, err := client.New(client.Options{BaseURL: baseURL, CAFile: caFile})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func waitHealthy(t *testing.T, c *client.Client, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := c.HTTP.Get(c.BaseURL + "/healthz")
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("control plane not healthy within %s", timeout)
}

func waitForFile(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("file %s not created within %s", path, timeout)
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func waitTimeout(cmd *exec.Cmd, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		return fmt.Errorf("process did not exit within %s", timeout)
	}
}

func echoServer(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 4096)
			for {
				n, err := c.Read(buf)
				if n > 0 {
					if _, werr := c.Write(buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}(conn)
	}
}
