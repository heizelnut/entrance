package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"entrance/internal/api"
	"entrance/internal/client"
)

type apiDaemonView = api.DaemonView

// Session is the shared entrui state: credentials + client.
type Session struct {
	URL      string `json:"url"`
	CAFile   string `json:"ca_file,omitempty"`
	Username string `json:"username,omitempty"`
	Token    string `json:"token,omitempty"`
	TokenExp int64  `json:"token_expires_at,omitempty"`

	Client *client.Client `json:"-"`
	Path   string         `json:"-"`
	Log    []string       `json:"-"`

	// ConnectRequest is set by the TUI when the user picks a host; entrui's
	// non-interactive path consumes it after the TUI quits.
	ConnectRequest *ConnectRequest `json:"-"`
	Hosts          []apiDaemonView `json:"-"`
}

// LoadSession restores credentials from the config file (or creates an empty
// session) and builds the API client.
func LoadSession(cfgPath string) (*Session, error) {
	s := &Session{Path: cfgPath, Log: []string{}}
	if b, err := os.ReadFile(cfgPath); err == nil {
		if err := json.Unmarshal(b, s); err != nil {
			return nil, fmt.Errorf("parse %s: %w", cfgPath, err)
		}
	}
	if s.URL == "" {
		return nil, errors.New("no control plane URL configured; run `entrui login --url https://...`")
	}
	c, err := client.New(client.Options{BaseURL: s.URL, CAFile: s.CAFile, Token: s.Token})
	if err != nil {
		return nil, err
	}
	s.Client = c
	return s, nil
}

// Close writes the session back to disk.
func (s *Session) Close() error {
	return os.WriteFile(s.Path, mustJSON(s), 0o600)
}

func (s *Session) ensureDir() {
	if dir := filepath.Dir(s.Path); dir != "" {
		_ = os.MkdirAll(dir, 0o700)
	}
}

func (s *Session) save() {
	s.ensureDir()
	_ = os.WriteFile(s.Path, mustJSON(s), 0o600)
}

// AppendLog records a line in the session transcript (stream view).
func (s *Session) AppendLog(line string) {
	s.Log = append(s.Log, time.Now().Format("15:04:05")+" "+line)
	if len(s.Log) > 500 {
		s.Log = s.Log[len(s.Log)-500:]
	}
}

func mustJSON(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return []byte("{}")
	}
	return b
}

// --- app model ---

// view is the current screen.
type view int

const (
	viewLogin view = iota
	viewHosts
	viewConnect
	viewServices
)

// app is the root bubbletea model.
type app struct {
	session *Session
	view    view
	width   int
	height  int
	login   loginModel
	hosts   hostsModel
	connect connectModel
	svcs    servicesModel
}

// NewApp builds the root model.
func NewApp(s *Session) tea.Model {
	a := &app{session: s, view: viewHosts}
	a.login = newLoginModel(s, a)
	a.hosts = newHostsModel(s, a)
	a.connect = newConnectModel(s, a)
	a.svcs = newServicesModel(s, a)
	return a
}

func (a *app) Init() tea.Cmd {
	if a.session.Token == "" {
		a.view = viewLogin
		return a.login.Init()
	}
	return a.hosts.Init()
}

func (a *app) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = msg.Width, msg.Height
		return a, nil
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			a.session.AppendLog("exited")
			_ = a.session.Close()
			return a, tea.Quit
		}
	}
	switch a.view {
	case viewLogin:
		m, cmd := a.login.Update(msg)
		a.login = m
		return a, cmd
	case viewHosts:
		m, cmd := a.hosts.Update(msg)
		a.hosts = m
		return a, cmd
	case viewConnect:
		m := a.connect
		a.connect = m
		return a, nil
	case viewServices:
		m, cmd := a.svcs.Update(msg)
		a.svcs = m
		return a, cmd
	}
	return a, nil
}

func (a *app) View() string {
	switch a.view {
	case viewLogin:
		return a.login.View()
	case viewHosts:
		return a.hosts.View()
	case viewConnect:
		return a.connect.View()
	case viewServices:
		return a.svcs.View()
	}
	return ""
}

// ctx returns a cancellable context tied to the TUI lifetime.
func sessionCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}
