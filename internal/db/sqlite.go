package db

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// DB is the control-plane store. modernc.org/sqlite is pure Go so the whole
// binary cross-compiles with CGO_ENABLED=0 (D5).
type DB struct {
	*sql.DB
}

// Open opens (creating if needed) the SQLite database under dataDir with WAL,
// a busy timeout, and foreign keys enabled. Migrations are applied
// transactionally at open.
func Open(dataDir string) (*DB, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	// MkdirAll leaves the mode of an EXISTING dir untouched; tighten it: the
	// DB holds the WG private key, password hashes, and token hashes.
	_ = os.Chmod(dataDir, 0o700)
	path := filepath.Join(dataDir, "entrance.db")
	dsn := "file:" + path +
		"?_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=synchronous(NORMAL)" // safe under WAL; avoids an fsync per heartbeat
	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	raw.SetMaxOpenConns(1) // modernc sqlite is process-local; single writer
	d := &DB{raw}
	if err := d.migrate(); err != nil {
		raw.Close()
		return nil, err
	}
	return d, nil
}

// Close closes the underlying database.
func (d *DB) Close() error { return d.DB.Close() }

// migrate applies embedded migrations in filename order, recording versions.
func (d *DB) migrate() error {
	if _, err := d.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		var version int
		if _, err := fmt.Sscanf(e.Name(), "%d_", &version); err != nil || version == 0 {
			return fmt.Errorf("migration file name %q must start with a version", e.Name())
		}
		applied, err := d.isApplied(version)
		if err != nil {
			return err
		}
		if applied {
			continue
		}
		body, err := migrationsFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return err
		}
		// modernc sqlite driver does not execute multiple statements in one
		// Exec reliably; split on statement terminators at line starts.
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		for _, stmt := range splitStatements(string(body)) {
			if _, err := tx.Exec(stmt); err != nil {
				tx.Rollback()
				return fmt.Errorf("apply migration %s: %w", e.Name(), err)
			}
		}
		if _, err := tx.Exec(
			`INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)`,
			version, time.Now().UTC().Format(time.RFC3339)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (d *DB) isApplied(version int) (bool, error) {
	var n int
	err := d.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, version).Scan(&n)
	return n > 0, err
}

func splitStatements(s string) []string {
	var out []string
	var cur strings.Builder
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--") || trimmed == "" {
			continue
		}
		cur.WriteString(line)
		cur.WriteString("\n")
		if strings.HasSuffix(trimmed, ";") {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	return out
}
