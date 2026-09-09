// Package client is the typed HTTP+WS client for the entrance control plane.
// It backs both the agent (entranced) and the user tooling (entrui).
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/coder/websocket"

	"entrance/internal/api"
)

// Client talks to one control plane instance.
type Client struct {
	BaseURL string
	Token   string // session token or daemon token
	HTTP    *http.Client
	WS      *websocket.DialOptions
}

// Options configures a Client.
type Options struct {
	BaseURL string
	Token   string
	// CAFile pins the control plane cert (dev/corporate). When empty the
	// system roots are used.
	CAFile string
	// Timeout for HTTP calls (0 = default 30s).
	Timeout time.Duration
}

// New builds a client.
func New(opts Options) (*Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12} // #nosec G402 — pinned or system roots
	if opts.CAFile != "" {
		pemData, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read ca file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("no certificates found in %s", opts.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	tr := &http.Transport{
		TLSClientConfig:     tlsCfg,
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		MaxIdleConnsPerHost: 8,
	}
	return &Client{
		BaseURL: opts.BaseURL,
		Token:   opts.Token,
		HTTP:    &http.Client{Transport: tr, Timeout: timeout},
		WS: &websocket.DialOptions{
			HTTPClient: &http.Client{Transport: tr.Clone()},
			HTTPHeader: http.Header{},
		},
	}, nil
}

// Error is returned for non-2xx responses.
type Error struct {
	StatusCode int
	Message    string
}

func (e *Error) Error() string {
	return fmt.Sprintf("api: %s (HTTP %d)", e.Message, e.StatusCode)
}

// do performs a JSON request.
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(respBody, &e)
		msg := e.Error
		if msg == "" {
			msg = string(respBody)
		}
		return &Error{StatusCode: resp.StatusCode, Message: msg}
	}
	if out != nil && len(respBody) > 0 {
		return json.Unmarshal(respBody, out)
	}
	return nil
}

// --- auth ---

func (c *Client) Login(ctx context.Context, username, password string) (*api.LoginResponse, error) {
	var out api.LoginResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/auth/login",
		api.LoginRequest{Username: username, Password: password}, &out); err != nil {
		return nil, err
	}
	c.Token = out.SessionToken
	return &out, nil
}

func (c *Client) Logout(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/api/v1/auth/logout", nil, nil)
}

// --- secrets & daemons ---

func (c *Client) CreateEnrollSecret(ctx context.Context, label string) (*api.EnrollSecretResponse, error) {
	var out api.EnrollSecretResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/enroll-secrets",
		api.EnrollSecretRequest{Label: label}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Enroll(ctx context.Context, req api.EnrollRequest) (*api.EnrollResponse, error) {
	var out api.EnrollResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/daemons/enroll", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ListDaemons(ctx context.Context) ([]api.DaemonView, error) {
	var out []api.DaemonView
	if err := c.do(ctx, http.MethodGet, "/api/v1/daemons", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) GetDaemon(ctx context.Context, id int64) (*api.DaemonView, error) {
	var out api.DaemonView
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/api/v1/daemons/%d", id), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) DeleteDaemon(ctx context.Context, id int64) error {
	return c.do(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/daemons/%d", id), nil, nil)
}

// --- relays ---

func (c *Client) CreateRelay(ctx context.Context, daemonID int64, port int) (*api.RelayCreateResponse, error) {
	var out api.RelayCreateResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/relays",
		api.RelayCreateRequest{DaemonID: daemonID, TargetPort: port, Protocol: "tcp"},
		&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RelayWS opens the relay WebSocket.
func (c *Client) RelayWS(ctx context.Context, sessionID string) (*websocket.Conn, error) {
	url := c.BaseURL + "/api/v1/relays/" + sessionID + "/ws"
	return c.dialWS(ctx, url)
}

// DaemonWS opens the daemon control-channel WebSocket.
func (c *Client) DaemonWS(ctx context.Context, urlSuffix string) (*websocket.Conn, error) {
	return c.dialWS(ctx, c.BaseURL+urlSuffix)
}

// dialWS opens a WebSocket with the bearer token in the Authorization
// header.
func (c *Client) dialWS(ctx context.Context, url string) (*websocket.Conn, error) {
	opts := *c.WS
	if c.Token != "" {
		opts.HTTPHeader.Set("Authorization", "Bearer "+c.Token)
	}
	conn, resp, err := websocket.Dial(ctx, url, &opts)
	if err != nil {
		if resp != nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			return nil, &Error{StatusCode: resp.StatusCode, Message: "websocket dial failed: " + err.Error()}
		}
		return nil, err
	}
	return conn, nil
}
