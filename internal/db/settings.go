package db

import (
	"database/sql"
	"errors"
	"time"
)

// ErrNotFound is returned by Get-ers when the row does not exist.
var ErrNotFound = errors.New("not found")

func nowUTC() time.Time { return time.Now().UTC() }

// WithTx runs fn inside a transaction.
func (d *DB) WithTx(fn func(tx *sql.Tx) error) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func normalizeRowErr(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// --- settings ---

// GetSetting returns a settings value ("" when unset).
func (d *DB) GetSetting(k string) (string, error) {
	var v string
	err := d.QueryRow(`SELECT v FROM settings WHERE k = ?`, k).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetSetting upserts a settings value.
func (d *DB) SetSetting(k, v string) error {
	_, err := d.Exec(`INSERT INTO settings(k, v) VALUES(?, ?)
		ON CONFLICT(k) DO UPDATE SET v = excluded.v`, k, v)
	return err
}
