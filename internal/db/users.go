package db

import (
	"database/sql"
)

// User store: admin bootstrap + auth lookups (D3).

func (d *DB) CreateUser(username, passwordHash string, isAdmin bool) (*User, error) {
	now := nowUTC()
	res, err := d.Exec(
		`INSERT INTO users(username, password_hash, is_admin, created_at) VALUES(?, ?, ?, ?)`,
		username, passwordHash, boolInt(isAdmin), formatTime(now))
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return d.GetUserByID(id)
}

func (d *DB) GetUserByID(id int64) (*User, error) {
	u := &User{}
	var created string
	var deactivated sql.NullString
	err := d.QueryRow(`SELECT id, username, password_hash, is_admin, created_at, deactivated_at
		FROM users WHERE id = ?`, id).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &u.IsAdmin, &created, &deactivated)
	if err != nil {
		return nil, normalizeRowErr(err)
	}
	u.CreatedAt, _ = parseTime(created)
	if deactivated.Valid {
		u.DeactivatedAt = parseTimePtr(deactivated.String)
	}
	return u, nil
}

func (d *DB) GetUserByUsername(username string) (*User, error) {
	u := &User{}
	var created string
	var deactivated sql.NullString
	err := d.QueryRow(`SELECT id, username, password_hash, is_admin, created_at, deactivated_at
		FROM users WHERE username = ? AND deactivated_at IS NULL`, username).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &u.IsAdmin, &created, &deactivated)
	if err != nil {
		return nil, normalizeRowErr(err)
	}
	u.CreatedAt, _ = parseTime(created)
	if deactivated.Valid {
		u.DeactivatedAt = parseTimePtr(deactivated.String)
	}
	return u, nil
}

// UserCount reports how many (active) users exist.
func (d *DB) UserCount() (int, error) {
	var n int
	err := d.QueryRow(`SELECT COUNT(*) FROM users WHERE deactivated_at IS NULL`).Scan(&n)
	return n, err
}
