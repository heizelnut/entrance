package db

import (
	"database/sql"
	"net/netip"
)

// Daemon store: registered agents/spokes (D2, D7).

// CreateDaemon inserts a daemon row inside the caller's transaction (enroll is
// atomic with consuming the enrollment secret).
func (d *DB) CreateDaemon(tx *sql.Tx, pubKey, tokenHash, hostname, wgIP, version string, allowedPorts []int, remap map[int]int) (int64, error) {
	res, err := tx.Exec(
		`INSERT INTO daemons(wg_public_key, token_hash, hostname, wg_ip, version, allowed_ports, remap, created_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		pubKey, tokenHash, hostname, wgIP, version,
		encodePorts(allowedPorts), encodeRemap(remap), formatTime(nowUTC()))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetDaemonByToken finds an active daemon via its (SHA-256 hashed) token.
func (d *DB) GetDaemonByToken(tokenHash string) (*Daemon, error) {
	return d.scanDaemon(`SELECT id, wg_public_key, token_hash, hostname, wg_ip, version,
		allowed_ports, remap, created_at, last_seen_at, deactivated_at
		FROM daemons WHERE token_hash = ? AND deactivated_at IS NULL`, tokenHash)
}

func (d *DB) GetDaemonByID(id int64) (*Daemon, error) {
	return d.scanDaemon(`SELECT id, wg_public_key, token_hash, hostname, wg_ip, version,
		allowed_ports, remap, created_at, last_seen_at, deactivated_at
		FROM daemons WHERE id = ?`, id)
}

func (d *DB) scanDaemon(query string, arg any) (*Daemon, error) {
	dm := &Daemon{}
	var created string
	var last, deactivated sql.NullString
	var ports, remap string
	err := d.QueryRow(query, arg).
		Scan(&dm.ID, &dm.WGPublicKey, &dm.TokenHash, &dm.Hostname, &dm.WGIP,
			&dm.Version, &ports, &remap, &created, &last, &deactivated)
	if err != nil {
		return nil, normalizeRowErr(err)
	}
	dm.CreatedAt, _ = parseTime(created)
	if last.Valid {
		dm.LastSeenAt, _ = parseTime(last.String)
	}
	if deactivated.Valid {
		dm.DeactivatedAt = parseTimePtr(deactivated.String)
	}
	dm.AllowedPorts = parsePorts(ports)
	dm.Remap = parseRemap(remap)
	return dm, nil
}

// ListDaemons returns all active daemons plus their active relay count.
func (d *DB) ListDaemons() ([]*Daemon, error) {
	rows, err := d.Query(`SELECT d.id, d.wg_public_key, d.token_hash, d.hostname, d.wg_ip, d.version,
		d.allowed_ports, d.remap, d.created_at, d.last_seen_at, d.deactivated_at,
		(SELECT COUNT(*) FROM relays r WHERE r.daemon_id = d.id) as relays
		FROM daemons d WHERE d.deactivated_at IS NULL ORDER BY d.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Daemon
	for rows.Next() {
		dm := &Daemon{}
		var created string
		var last, deactivated sql.NullString
		var ports, remap string
		var relays int
		if err := rows.Scan(&dm.ID, &dm.WGPublicKey, &dm.TokenHash, &dm.Hostname, &dm.WGIP,
			&dm.Version, &ports, &remap, &created, &last, &deactivated, &relays); err != nil {
			return nil, err
		}
		dm.CreatedAt, _ = parseTime(created)
		if last.Valid {
			dm.LastSeenAt, _ = parseTime(last.String)
		}
		if deactivated.Valid {
			dm.DeactivatedAt = parseTimePtr(deactivated.String)
		}
		dm.AllowedPorts = parsePorts(ports)
		dm.Remap = parseRemap(remap)
		dm.ActiveRelays = relays
		out = append(out, dm)
	}
	return out, rows.Err()
}

// TouchDaemonHeartbeat updates last_seen_at.
func (d *DB) TouchDaemonHeartbeat(id int64) error {
	_, err := d.Exec(`UPDATE daemons SET last_seen_at = ? WHERE id = ?`, formatTime(nowUTC()), id)
	return err
}

// UpdateDaemonStatus refreshes version + allowed ports from the agent report.
func (d *DB) UpdateDaemonStatus(id int64, version string, allowedPorts []int, remap map[int]int) error {
	_, err := d.Exec(`UPDATE daemons SET version = ?, allowed_ports = ?, remap = ?, last_seen_at = ?
		WHERE id = ?`,
		version, encodePorts(allowedPorts), encodeRemap(remap), formatTime(nowUTC()), id)
	return err
}

// DeactivateDaemon revokes a daemon (soft delete; keeps audit row).
func (d *DB) DeactivateDaemon(id int64) error {
	_, err := d.Exec(`UPDATE daemons SET deactivated_at = ? WHERE id = ? AND deactivated_at IS NULL`,
		formatTime(nowUTC()), id)
	return err
}

// MaxWGIPTx returns the highest allocated WG IP among active daemons, or ""
// when none exist. Comparisons are numeric (netip), because the wg_ip column
// is TEXT and a lexicographic "max" breaks at two-digit octets (…0.9 vs …0.10).
// Must run inside the enroll transaction so allocation is atomic.
func (d *DB) MaxWGIPTx(tx *sql.Tx) (string, error) {
	rows, err := tx.Query(`SELECT wg_ip FROM daemons WHERE deactivated_at IS NULL`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var best netip.Addr
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return "", err
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		if !best.IsValid() || a.Compare(best) > 0 {
			best = a
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if !best.IsValid() {
		return "", nil
	}
	return best.String(), nil
}

// CountActiveDaemonsTx counts active daemons inside the caller's transaction
// (defensive allocation check; also the nth-daemon index for the first
// allocation).
func (d *DB) CountActiveDaemonsTx(tx *sql.Tx) (int64, error) {
	var n int64
	err := tx.QueryRow(`SELECT COUNT(*) FROM daemons WHERE deactivated_at IS NULL`).Scan(&n)
	return n, err
}
