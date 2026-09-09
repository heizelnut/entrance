package db

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenAndMigrate(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	if err := d.SetSetting("k1", "v1"); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetSetting("k1")
	if err != nil || got != "v1" {
		t.Fatalf("setting = %q, %v", got, err)
	}
}

func TestUserAndSessionRoundTrip(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	u, err := d.CreateUser("admin", "hash-abc", true)
	if err != nil {
		t.Fatal(err)
	}
	if u.ID == 0 || !u.IsAdmin {
		t.Fatalf("user = %+v", u)
	}
	byName, err := d.GetUserByUsername("admin")
	if err != nil || byName.ID != u.ID {
		t.Fatalf("byName = %+v, %v", byName, err)
	}

	s, err := d.CreateSession(u.ID, "tokhash", 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if s.ExpiresAt.IsZero() {
		t.Fatal("no expiry")
	}
	got, err := d.GetSessionByToken("tokhash", 30*24*time.Hour)
	if err != nil || got.UserID != u.ID {
		t.Fatalf("session = %+v, %v", got, err)
	}
	if err := d.DeleteSession("tokhash"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetSessionByToken("tokhash", time.Hour); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestEnrollSecretLifecycle(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	sec, err := d.CreateEnrollSecret("secrethash", "lookup-1", "host-1", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	found, err := d.GetUnexpiredEnrollSecretByLookup("lookup-1", time.Now())
	if err != nil || found.ID != sec.ID {
		t.Fatalf("found = %+v, %v", found, err)
	}
	// expired secret must not be found
	old, err := d.CreateEnrollSecret("oldhash", "lookup-old", "expired", -time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := d.GetUnexpiredEnrollSecretByLookup("lookup-old", time.Now()); err != ErrNotFound {
		t.Fatalf("expired secret found: %+v %v", got, err)
	}
	_ = old
}

func TestDaemonsAndRelays(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	u, _ := d.CreateUser("admin", "h", true)

	var id int64
	err = d.WithTx(func(tx *sql.Tx) error {
		var err error
		id, err = d.CreateDaemon(tx, "pubkey1", "tokenhash1", "host1", "10.99.0.2", "0.1.0",
			[]int{22, 5432}, map[int]int{22: 2222})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	dm, err := d.GetDaemonByToken("tokenhash1")
	if err != nil {
		t.Fatal(err)
	}
	if dm.WGIP != "10.99.0.2" || dm.Hostname != "host1" {
		t.Fatalf("daemon = %+v", dm)
	}
	if len(dm.AllowedPorts) != 2 || dm.AllowedPorts[0] != 22 {
		t.Fatalf("ports = %v", dm.AllowedPorts)
	}
	if dm.Remap[22] != 2222 {
		t.Fatalf("remap = %v", dm.Remap)
	}

	r, err := d.CreateRelay(id, u.ID, "sess-1", 22, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	list, _ := d.ListDaemonRelays(id)
	if len(list) != 1 || list[0].ID != r.ID {
		t.Fatalf("relays = %+v", list)
	}
	daemons, err := d.ListDaemons()
	if err != nil {
		t.Fatal(err)
	}
	if len(daemons) != 1 || daemons[0].ActiveRelays != 1 {
		t.Fatalf("daemons = %+v", daemons)
	}

	var maxIP string
	if err := d.WithTx(func(tx *sql.Tx) error {
		var err error
		maxIP, err = d.MaxWGIPTx(tx)
		return err
	}); err != nil || maxIP != "10.99.0.2" {
		t.Fatalf("max ip = %q, %v", maxIP, err)
	}

	if err := d.DeactivateDaemon(id); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetDaemonByToken("tokenhash1"); err != ErrNotFound {
		t.Fatalf("expected not found after deactivate, got %v", err)
	}
}

// TestMaxWGIPNumeric is the regression for the lexicographic-ordering bug:
// TEXT ordering made "10.99.0.9" sort above "10.99.0.10", so enrollment broke
// at the 11th host. MaxWGIPTx must pick the numerically highest address.
func TestMaxWGIPNumeric(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	// allocate .2 through .14 (13 daemons) in shuffled order incl. .9/.10/.11
	for i := 3; i <= 13; i++ {
		ip := fmt.Sprintf("10.99.0.%d", i)
		// insert intentionally out of order to defeat any implicit ordering
		if i%2 == 0 {
			key := fmt.Sprintf("%02dabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcde", i)
			if _, err := d.Exec(`INSERT INTO daemons(wg_public_key, token_hash, hostname, wg_ip, allowed_ports, remap, created_at)
				VALUES(?, ?, 'h', ?, '[]', '{}', ?)`,
				key, "th"+ip, ip, formatTime(nowUTC())); err != nil {
				t.Fatal(err)
			}
		}
	}
	for i := 3; i <= 13; i++ {
		ip := fmt.Sprintf("10.99.0.%d", i)
		if i%2 == 1 {
			key := fmt.Sprintf("%02dabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcde", i)
			if _, err := d.Exec(`INSERT INTO daemons(wg_public_key, token_hash, hostname, wg_ip, allowed_ports, remap, created_at)
				VALUES(?, ?, 'h', ?, '[]', '{}', ?)`,
				key, "th"+ip, ip, formatTime(nowUTC())); err != nil {
				t.Fatal(err)
			}
		}
	}
	var maxIP string
	if err := d.WithTx(func(tx *sql.Tx) error {
		var err error
		maxIP, err = d.MaxWGIPTx(tx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if maxIP != "10.99.0.13" {
		t.Fatalf("expected numeric max 10.99.0.13, got %q", maxIP)
	}
}
