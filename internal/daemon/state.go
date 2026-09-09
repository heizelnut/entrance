// Package daemon implements the entranced agent: outbound-only enrollment,
// persistent state, the WG device lifecycle, and the local port allowlist
// (D7/D4).
package daemon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"entrance/internal/wsproto"
)

// stateFile is the agent's persisted state (mode 0600).
const stateFile = "state.json"

// State is everything the agent persists across restarts (D7 D2). The WG
// private key never leaves this file.
type State struct {
	ServerURL    string         `json:"server_url"`
	DaemonID     int64          `json:"daemon_id,omitempty"`
	Token        string         `json:"token"`
	WGPrivateKey string         `json:"wg_private_key"`
	WGPublicKey  string         `json:"wg_public_key"`
	Hostname     string         `json:"hostname"`
	Config       wsproto.Config `json:"config"`
}

// stateStore manages the state file with an in-process mutex.
type stateStore struct {
	mu    sync.Mutex
	path  string
	state State
}

func loadStateStore(dataDir string) (*stateStore, error) {
	p := filepath.Join(dataDir, stateFile)
	st := &stateStore{path: p}
	b, err := os.ReadFile(p)
	if err == nil {
		if err := json.Unmarshal(b, &st.state); err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return st, nil
}

func (s *stateStore) get() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

func (s *stateStore) update(mut func(*State)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	mut(&s.state)
	b, err := json.MarshalIndent(&s.state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// deleteToken invalidates the persisted token (used on 401 revocation).
func (s *stateStore) deleteToken() {
	s.mu.Lock()
	s.state.Token = ""
	s.state.DaemonID = 0
	s.mu.Unlock()
	_ = os.WriteFile(s.path, nil, 0o600)
}
