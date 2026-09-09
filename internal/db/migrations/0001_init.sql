-- 0001_init.sql — entrance control plane schema (D5)

CREATE TABLE IF NOT EXISTS schema_migrations (
  version    INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
);

-- key/value settings (WG keys, network cidr, config)
CREATE TABLE IF NOT EXISTS settings (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  is_admin      INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL,
  deactivated_at TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash  TEXT PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  last_seen_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS enroll_secrets (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  secret_hash       TEXT NOT NULL UNIQUE,   -- argon2id hash (verify)
  lookup_hash       TEXT NOT NULL UNIQUE,   -- sha256 of plaintext (find row)
  label             TEXT NOT NULL,
  created_at        TEXT NOT NULL,
  expires_at        TEXT NOT NULL,
  used_at           TEXT,
  used_by_daemon_id INTEGER REFERENCES daemons(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_enroll_used ON enroll_secrets(used_at);

CREATE TABLE IF NOT EXISTS daemons (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  wg_public_key TEXT NOT NULL UNIQUE,
  token_hash    TEXT NOT NULL UNIQUE,
  hostname      TEXT NOT NULL,
  wg_ip         TEXT NOT NULL UNIQUE,
  version       TEXT NOT NULL DEFAULT '',
  allowed_ports TEXT NOT NULL DEFAULT '[]',
  remap         TEXT NOT NULL DEFAULT '{}',
  created_at    TEXT NOT NULL,
  last_seen_at  TEXT,
  deactivated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_daemons_status ON daemons(deactivated_at);

CREATE TABLE IF NOT EXISTS relays (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  daemon_id   INTEGER NOT NULL REFERENCES daemons(id) ON DELETE CASCADE,
  target_port INTEGER NOT NULL,
  protocol    TEXT NOT NULL DEFAULT 'tcp',
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_relays_daemon ON relays(daemon_id);

CREATE TABLE IF NOT EXISTS services (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  daemon_id   INTEGER NOT NULL REFERENCES daemons(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  target_port INTEGER NOT NULL,
  local_port  INTEGER NOT NULL,
  protocol    TEXT NOT NULL DEFAULT 'tcp',
  enabled     INTEGER NOT NULL DEFAULT 1,
  created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_services_daemon ON services(daemon_id);