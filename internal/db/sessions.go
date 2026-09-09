package db

import "time"

// Session store: opaque session tokens, SHA-256 hashed, 30d sliding (D3).

func (d *DB) CreateSession(userID int64, tokenHash string, ttl time.Duration) (*Session, error) {
	now := nowUTC()
	exp := now.Add(ttl)
	_, err := d.Exec(
		`INSERT INTO sessions(token_hash, user_id, created_at, expires_at, last_seen_at) VALUES(?, ?, ?, ?, ?)`,
		tokenHash, userID, formatTime(now), formatTime(exp), formatTime(now))
	if err != nil {
		return nil, err
	}
	return &Session{TokenHash: tokenHash, UserID: userID, CreatedAt: now, ExpiresAt: exp, LastSeenAt: now}, nil
}

// GetSessionByToken returns the session row, refreshing last_seen_at and
// sliding the expiry when more than half the TTL has elapsed.
func (d *DB) GetSessionByToken(tokenHash string, ttl time.Duration) (*Session, error) {
	s := &Session{}
	var created, expires, last string
	err := d.QueryRow(`SELECT token_hash, user_id, created_at, expires_at, last_seen_at
		FROM sessions WHERE token_hash = ?`, tokenHash).
		Scan(&s.TokenHash, &s.UserID, &created, &expires, &last)
	if err != nil {
		return nil, normalizeRowErr(err)
	}
	now := nowUTC()
	s.CreatedAt, _ = parseTime(created)
	s.ExpiresAt, _ = parseTime(expires)
	s.LastSeenAt, _ = parseTime(last)
	if now.After(s.ExpiresAt) {
		return nil, ErrNotFound // expired session
	}
	if now.After(s.CreatedAt.Add(ttl / 2)) {
		newExp := now.Add(ttl)
		_, _ = d.Exec(`UPDATE sessions SET expires_at = ?, last_seen_at = ? WHERE token_hash = ?`,
			formatTime(newExp), formatTime(now), tokenHash)
		s.ExpiresAt = newExp
		s.LastSeenAt = now
	}
	return s, nil
}

func (d *DB) DeleteSession(tokenHash string) error {
	_, err := d.Exec(`DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}
