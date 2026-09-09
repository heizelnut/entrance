package db

import (
	"database/sql"
	"errors"
	"time"
)

// ErrSecretAlreadyUsed is returned when an enrollment secret race-condenses:
// another enroll consumed it first.
var ErrSecretAlreadyUsed = errors.New("enrollment secret already used")

// EnrollSecret store: single-use, expiring enrollment secrets (D3), stored as
// argon2id hashes.

func (d *DB) CreateEnrollSecret(secretHash, lookupHash, label string, ttl time.Duration) (*EnrollSecret, error) {
	now := nowUTC()
	res, err := d.Exec(
		`INSERT INTO enroll_secrets(secret_hash, lookup_hash, label, created_at, expires_at) VALUES(?, ?, ?, ?, ?)`,
		secretHash, lookupHash, label, formatTime(now), formatTime(now.Add(ttl)))
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return d.GetEnrollSecretByID(id)
}

func (d *DB) GetEnrollSecretByID(id int64) (*EnrollSecret, error) {
	s := &EnrollSecret{}
	var created, expires string
	var used sql.NullString
	var usedBy sql.NullInt64
	err := d.QueryRow(`SELECT id, secret_hash, label, created_at, expires_at, used_at, used_by_daemon_id
		FROM enroll_secrets WHERE id = ?`, id).
		Scan(&s.ID, &s.SecretHash, &s.Label, &created, &expires, &used, &usedBy)
	if err != nil {
		return nil, normalizeRowErr(err)
	}
	s.CreatedAt, _ = parseTime(created)
	s.ExpiresAt, _ = parseTime(expires)
	if used.Valid {
		s.UsedAt = parseTimePtr(used.String)
	}
	if usedBy.Valid {
		s.UsedByDaemonID = &usedBy.Int64
	}
	return s, nil
}

// GetUnexpiredEnrollSecretByLookup finds a valid, unused, unexpired secret by
// its opaque lookup index (sha256 of the plaintext secret).
func (d *DB) GetUnexpiredEnrollSecretByLookup(lookup string, now time.Time) (*EnrollSecret, error) {
	s := &EnrollSecret{}
	var created, expires string
	var used sql.NullString
	var usedBy sql.NullInt64
	err := d.QueryRow(`SELECT id, secret_hash, label, created_at, expires_at, used_at, used_by_daemon_id
		FROM enroll_secrets
		WHERE lookup_hash = ? AND used_at IS NULL AND expires_at > ?
		ORDER BY expires_at DESC LIMIT 1`,
		lookup, formatTime(now)).
		Scan(&s.ID, &s.SecretHash, &s.Label, &created, &expires, &used, &usedBy)
	if err != nil {
		return nil, normalizeRowErr(err)
	}
	s.CreatedAt, _ = parseTime(created)
	s.ExpiresAt, _ = parseTime(expires)
	if used.Valid {
		s.UsedAt = parseTimePtr(used.String)
	}
	if usedBy.Valid {
		s.UsedByDaemonID = &usedBy.Int64
	}
	return s, nil
}

// MarkEnrollSecretUsed consumes the secret inside tx (atomic with enroll).
// Returns an error if the secret was already consumed — the WHERE used_at IS
// NULL guard makes single-use consumption race-safe.
func (d *DB) MarkEnrollSecretUsed(id int64, daemonID int64, tx *sql.Tx) error {
	res, err := tx.Exec(`UPDATE enroll_secrets SET used_at = ?, used_by_daemon_id = ?
		WHERE id = ? AND used_at IS NULL`,
		formatTime(nowUTC()), daemonID, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrSecretAlreadyUsed
	}
	return nil
}
