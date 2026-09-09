package db

import "time"

// Relay store: user data-plane sessions (D4).

func (d *DB) CreateRelay(daemonID, userID int64, sessionID string, targetPort int, protocol string) (*Relay, error) {
	res, err := d.Exec(
		`INSERT INTO relays(daemon_id, target_port, protocol, user_id, session_id, created_at) VALUES(?, ?, ?, ?, ?, ?)`,
		daemonID, targetPort, protocol, userID, sessionID, formatTime(nowUTC()))
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	r := &Relay{ID: id, DaemonID: daemonID, TargetPort: targetPort, Protocol: protocol,
		UserID: userID, CreatedAt: nowUTC()}
	return r, nil
}

func (d *DB) GetRelayByID(id int64) (*Relay, error) {
	r := &Relay{}
	var created string
	err := d.QueryRow(`SELECT id, daemon_id, target_port, protocol, user_id, created_at
		FROM relays WHERE id = ?`, id).
		Scan(&r.ID, &r.DaemonID, &r.TargetPort, &r.Protocol, &r.UserID, &created)
	if err != nil {
		return nil, normalizeRowErr(err)
	}
	r.CreatedAt, _ = parseTime(created)
	return r, nil
}

func (d *DB) DeleteRelay(id int64) error {
	_, err := d.Exec(`DELETE FROM relays WHERE id = ?`, id)
	return err
}

// DeleteRelayBySession prunes the audit row once its session closes (keeps
// the relays table from growing without bound).
func (d *DB) DeleteRelayBySession(sessionID string) error {
	_, err := d.Exec(`DELETE FROM relays WHERE session_id = ?`, sessionID)
	return err
}

// ListDaemonRelays lists relay rows currently held for a daemon (used by the
// relay manager to close sessions on daemon deletion).
func (d *DB) ListDaemonRelays(daemonID int64) ([]*Relay, error) {
	rows, err := d.Query(`SELECT id, daemon_id, target_port, protocol, user_id, created_at
		FROM relays WHERE daemon_id = ?`, daemonID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Relay
	for rows.Next() {
		r := &Relay{}
		var created string
		if err := rows.Scan(&r.ID, &r.DaemonID, &r.TargetPort, &r.Protocol, &r.UserID, &created); err != nil {
			return nil, err
		}
		r.CreatedAt, _ = parseTime(created)
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- services (phase 2 config surface, small but real) ---

func (d *DB) CreateService(daemonID int64, name string, targetPort, localPort int, protocol string) (*Service, error) {
	res, err := d.Exec(
		`INSERT INTO services(daemon_id, name, target_port, local_port, protocol, enabled, created_at)
		 VALUES(?, ?, ?, ?, ?, 1, ?)`,
		daemonID, name, targetPort, localPort, protocol, formatTime(nowUTC()))
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return d.GetServiceByID(id)
}

func (d *DB) GetServiceByID(id int64) (*Service, error) {
	s := &Service{}
	var created string
	err := d.QueryRow(`SELECT id, daemon_id, name, target_port, local_port, protocol, enabled, created_at
		FROM services WHERE id = ?`, id).
		Scan(&s.ID, &s.DaemonID, &s.Name, &s.TargetPort, &s.LocalPort, &s.Protocol, &s.Enabled, &created)
	if err != nil {
		return nil, normalizeRowErr(err)
	}
	s.CreatedAt, _ = parseTime(created)
	return s, nil
}

func (d *DB) ListServices(daemonID int64) ([]*Service, error) {
	rows, err := d.Query(`SELECT id, daemon_id, name, target_port, local_port, protocol, enabled, created_at
		FROM services WHERE daemon_id = ? ORDER BY id`, daemonID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Service
	for rows.Next() {
		s := &Service{}
		var created string
		if err := rows.Scan(&s.ID, &s.DaemonID, &s.Name, &s.TargetPort, &s.LocalPort,
			&s.Protocol, &s.Enabled, &created); err != nil {
			return nil, err
		}
		s.CreatedAt, _ = parseTime(created)
		out = append(out, s)
	}
	return out, rows.Err()
}

func (d *DB) DeleteService(id int64) error {
	_, err := d.Exec(`DELETE FROM services WHERE id = ?`, id)
	return err
}

var _ = time.Now
