// Package store is the bastion's SQLite persistence: WebAuthn credentials,
// browser sessions, and the known-host registry. modernc.org/sqlite is pure
// Go, so the binary stays CGO_ENABLED=0.
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	_ "modernc.org/sqlite"
)

// Store wraps the SQLite database.
type Store struct{ *sql.DB }

const schema = `
CREATE TABLE IF NOT EXISTS credentials (
  id         BLOB PRIMARY KEY,
  data       BLOB NOT NULL,
  name       TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id         TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hosts (
  name       TEXT PRIMARY KEY,
  os         TEXT NOT NULL DEFAULT '',
  arch       TEXT NOT NULL DEFAULT '',
  version    TEXT NOT NULL DEFAULT '',
  remote     TEXT NOT NULL DEFAULT '',
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL
);
`

// Open opens (creating if needed) the SQLite database under dataDir.
func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	_ = os.Chmod(dataDir, 0o700)
	path := filepath.Join(dataDir, "entrance.db")
	dsn := "file:" + path +
		"?_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=synchronous(NORMAL)"
	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	raw.SetMaxOpenConns(1)
	if _, err := raw.Exec(schema); err != nil {
		raw.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{raw}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.DB.Close() }

// --- WebAuthn credentials -------------------------------------------------

// Credentials returns every registered passkey.
func (s *Store) Credentials() ([]webauthn.Credential, error) {
	rows, err := s.Query(`SELECT data FROM credentials ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []webauthn.Credential
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var c webauthn.Credential
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// HasCredentials reports whether any passkey is registered.
func (s *Store) HasCredentials() (bool, error) {
	var n int
	if err := s.QueryRow(`SELECT COUNT(*) FROM credentials`).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// AddCredential stores a newly registered passkey.
func (s *Store) AddCredential(c *webauthn.Credential, name string) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = s.Exec(`INSERT INTO credentials(id, data, name, created_at) VALUES(?,?,?,?)`,
		c.ID, data, name, time.Now().UTC().Format(time.RFC3339))
	return err
}

// UpdateCredential refreshes a credential after a successful login (sign count).
func (s *Store) UpdateCredential(c *webauthn.Credential) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = s.Exec(`UPDATE credentials SET data = ? WHERE id = ?`, data, c.ID)
	return err
}

// --- Browser sessions -----------------------------------------------------

// CreateSession mints an opaque browser session id with the given TTL.
func (s *Store) CreateSession(ttl time.Duration) (string, error) {
	id, err := randomHex(32)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	_, err = s.Exec(`INSERT INTO sessions(id, created_at, expires_at) VALUES(?,?,?)`,
		id, now.Format(time.RFC3339), now.Add(ttl).Format(time.RFC3339))
	return id, err
}

// ValidSession reports whether a session id exists and has not expired.
func (s *Store) ValidSession(id string) bool {
	if id == "" {
		return false
	}
	var expires string
	err := s.QueryRow(`SELECT expires_at FROM sessions WHERE id = ?`, id).Scan(&expires)
	if err != nil {
		return false
	}
	t, err := time.Parse(time.RFC3339, expires)
	if err != nil {
		return false
	}
	if time.Now().UTC().After(t) {
		_ = s.DeleteSession(id)
		return false
	}
	return true
}

// DeleteSession removes a session (logout).
func (s *Store) DeleteSession(id string) error {
	_, err := s.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	return err
}

// --- Known hosts ----------------------------------------------------------

// TouchHost upserts a host's metadata and last-seen time.
func (s *Store) TouchHost(name, osName, arch, version, remote string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.Exec(`
		INSERT INTO hosts(name, os, arch, version, remote, first_seen, last_seen)
		VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET
		  os=excluded.os, arch=excluded.arch, version=excluded.version,
		  remote=excluded.remote, last_seen=excluded.last_seen`,
		name, osName, arch, version, remote, now, now)
	return err
}

// Host is a known-host row.
type Host struct {
	Name     string
	OS       string
	Arch     string
	Version  string
	Remote   string
	LastSeen string
}

// KnownHosts returns every host ever seen, most recent first.
func (s *Store) KnownHosts() ([]Host, error) {
	rows, err := s.Query(`SELECT name, os, arch, version, remote, last_seen FROM hosts ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Host
	for rows.Next() {
		var h Host
		if err := rows.Scan(&h.Name, &h.OS, &h.Arch, &h.Version, &h.Remote, &h.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
