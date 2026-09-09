# Entrance — Design

Self-hosted bastion access. No exposed ports on your network. One HTTPS port
on the bastion. WireGuard inside.

```
┌────────────┐   HTTPS :443 (single port)   ┌────────────────────┐
│  entrui    │─────────────────────────────▶│  entrance (VPS)    │
│  (TUI/ssh) │   REST API + relay WS        │  WireGuard hub     │
└────────────┘                              │  ACME certs        │
                                            └─────────┬──────────┘
                                                      │ outbound only,
                                                      │ also HTTPS :443
                                            ┌─────────▼──────────┐
                                            │  entranced (host)  │
                                            │  WireGuard spoke   │
                                            └─────────┬──────────┘
                                                      │ localhost only
                                            ┌─────────▼──────────┐
                                            │  ssh / web / db    │
                                            └────────────────────┘
```

## D1 — WG topology & transport

Hub-and-spoke WireGuard. `entrance` is the hub (its own keypair + one WG
device). Every `entranced` is a spoke (one device, one peer: the hub).

WireGuard datagrams **never** cross the public internet as UDP. Each side runs
wireguard-go in-process with a custom `conn.Bind` (`internal/wg/bind.go`)
whose egress goes through a `Transport` abstraction:

- **WebsocketTransport** — datagrams ride inside the persistent control-channel
  WebSocket between daemon and bastion (binary frames). Stock wireguard-go
  crypto; NAT traversal irrelevant; the bastion exposes **zero** sockets beyond
  its single HTTPS listener.
- **MemTransport** — in-process pipe for rootless tests.
- **UDPTransport** — direct UDP (phase 2, opt-in).

The hub device demultiplexes by peer: each daemon's control-channel WS is
registered against a unique endpoint token (`endpointToken(id)` = port
namespace 20000+); the `HubTransport` maps the endpoint wireguard-go stamps on
egress datagrams to the right daemon socket. Ingress from any daemon funnels
into the shared device, which routes by WG header.

## D2 — Key provisioning

- **Daemons generate their own WG keypair locally** — the private key never
  leaves the device. Enrollment transmits only the public key.
- The **bastion generates its hub keypair at first run** (stored in SQLite
  settings under `data/`, mode 0700).
- Addressing: default `10.99.0.0/24`, bastion `.1`, daemons allocated
  sequentially `.2+` (`internal/wg/ipam.go`). Allocation is strictly numeric
  (netip comparisons), **not** lexicographic, so `.9 → .10` works (regression:
  `internal/db/db_test.go TestMaxWGIPNumeric`, `internal/api/api_test.go
  TestEnrollIPAMSequential`).
- Phase 1: AllowedIPs is `/32` both directions — bastion ↔ daemon only.
- Optional per-peer PSK: phase 2.

## D3 — Auth model

Three credential layers, all hashed at rest:

1. **Enrollment secrets** — operator creates a single-use, 24h expiry secret
   (`entrance add-host <label>` or `POST /api/v1/enroll-secrets`). Stored as
   argon2id; archived behind a `lookup_hash` (sha256). Consumption is atomic:
   the enroll transaction updates the row only `WHERE used_at IS NULL` and
   aborts on 0 rows, so concurrent redemption cannot double-spend.
2. **Daemon tokens** — generated at enroll, returned once, persisted by the
   agent at mode 0600, stored server-side as SHA-256. `Authorization: Bearer`
   only (never query params). Revocation = `DELETE /api/v1/daemons/{id}`:
   relays closed, hub peer removed, token invalidated, and the live WS is
   closed with a 1008 frame so the agent exits with code 3 demanding re-enroll.
3. **User sessions** — single admin bootstrapped from `ENTRANCE_ADMIN_PASSWORD`
   on first run. argon2id (m=64M, t=3, p=4). Opaque 32-byte tokens, SHA-256 at
   rest, 30d sliding expiry. Login is rate-limited per IP (10/min) with a
   bounded map; unknown usernames burn a dummy argon2 verify so timing cannot
   enumerate accounts; a global semaphore (4) bounds concurrent verifications
   (each allocates ~64 MiB).

## D4 — Data plane / relay protocol

Daemon processes do **not** do IP forwarding. `entranced` binds the
operator-specified allowlisted ports (`--allow 22,3389,5432`, remap via
`--remap 2222=22`) on its tunnel IP (or 127.0.0.1 in `--net-mode loopback` for
rootless dev) and splices to `127.0.0.1:<port>`. The allowlist is enforced at
the application layer both on the bastion (relay creation rejects
non-allowlisted ports) and on the daemon (only those listeners exist).

Session flow: user → bastion HTTPS WS → bastion TCP dial `daemon_wg_ip:port`
→ kernel route into the WG tunnel → daemon TUN → `entranced` socket →
localhost service. Sessions are bastion-side (`internal/relay/manager.go`)
with per-user (8) and global (1024) caps, an attach deadline (60s, orphan
sessions reaped), and a 24h max lifetime. On teardown both directions are
closed so no goroutine or file descriptor leaks. Relay audit rows are pruned
when their session closes.

Production uses `--relay-mode wg` (dial the tunnel IP). `--relay-mode
loopback` is refused outside `--dev` because its dial targets are the
bastion's own 127.0.0.1 — a footgun that would proxy the bastion host.

## D5 — Persistence

SQLite via **modernc.org/sqlite** (pure Go → `CGO_ENABLED=0` cross-compile).
WAL, `synchronous=NORMAL`, `busy_timeout=5000`, foreign keys on, single
writer connection. Timestamps are fixed-width RFC3339 (constant 9-digit
fraction) so TEXT ordering is chronological. Migrations are embedded and
applied transactionally. Data dir defaults to `~/.entrance` (0700).

## D6 — TLS

`internal/tlssetup`: dev mode (`--dev`) generates a self-signed cert on first
run, prints its fingerprint (pin with `entranced --ca-file`), and binds
`127.0.0.1:8443`. Prod mode uses `golang.org/x/crypto/acme/autocert`
(**TLS-ALPN-01**, so ACME works through the same :443 listener — no port 80;
requires the host & port be reachable by the CA). TLS ≥ 1.2 both sides.

## D7 — Daemon lifecycle

`enroll → persist state (token, keys, config) → connect WS (exp backoff
1s→60s+jitter) → hello → heartbeat (30s) → apply config pushes → reconnect`.
A 1008 close on the channel = revoked → local token deleted, exit code 3.
The bastion marks daemons stale after 90s of silence. The reader leaf pumps
both control JSON (text frames) and WG datagrams (binary frames) without
blocking the heartbeat ticker.

## D8 — Ports

- Bastion: 443 (dev 8443), HTTPS only. ACME on the same socket.
- Daemon: none inbound (the WS dial is outbound).
- Phase 2 opt-in: direct-UDP 51820 on the bastion.

## API surface

| Method & path | Auth | Purpose |
|---|---|---|
| `GET /healthz` | — | liveness |
| `POST /api/v1/auth/login`, `/logout` | — / user | sessions (rate-limited) |
| `POST /api/v1/enroll-secrets` | user | single-use secret |
| `POST /api/v1/daemons/enroll` | secret | enroll → `{daemon_id, token, config}` |
| `GET /api/v1/daemons/me` | daemon | config snapshot |
| `POST /api/v1/daemons/me/heartbeat` | daemon | liveness + status |
| `GET /api/v1/daemons/me/ws` | daemon | control channel (WG datagrams + control JSON) |
| `GET /api/v1/daemons` / `{id}` / `DELETE /{id}` / `POST /{id}/rotate` | user | host list / detail / revoke / (phase 2) |
| `POST /api/v1/relays`, `GET /api/v1/relays/{id}/ws` | user | data plane |
| `GET/POST /api/v1/daemons/{id}/services`, `DELETE /api/v1/services/{id}` | user | named services (phase 2 surface) |

## Security posture

- No query-param tokens; Bearer headers only.
- X-Forwarded-For trusted only from configured proxy CIDRs (or loopback),
  so the login limiter cannot be spoofed.
- HTTP server timeouts set (slowloris defense); coder/websocket upgrade
  requires `http.Hijacker` (the recover middleware forwards it).
- Panics are recovered with a real status-recording ResponseWriter.
- SQL fully parameterized; no shell interpolation in netif helpers (fixed
  argv). Per-peer `/32` AllowedIPs blocks daemon↔daemon traffic.

## Known phase-2 items

Direct-UDP transport + kernel WG (Linux build tags), TOTP, embedded SSH
client in `entrui`, subnet-routing mode, audit retention job, token rotation,
multitenancy groundwork, web frontend on the same API.