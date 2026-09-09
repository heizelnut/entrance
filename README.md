# Entrance

Selfhosted bastion access — **no SSH, no exposed ports**, backed by WireGuard.

| Component | Role |
|---|---|
| `entrance` | Bastion control plane. One HTTPS port (443). Embedded ACME (TLS-ALPN-01 — no port 80). |
| `entranced` | Outbound-only agent on target hosts. Exposes **nothing** on the firewall; dials the control plane out. |
| `entrui` | TUI / CLI client for the same REST API the future web frontend will use. |

WireGuard runs **inside** the HTTPS control channel: `entranced` dials out,
the bastion bridges encrypted WG datagrams into its tunnel, and you reach
host services through relay sessions — all over the single HTTPS port.

```
entrui ──HTTPS──▶ entrance (VPS, :443) ◀──HTTPS── entranced (target host)
                        │                                 │
                        └──────── WireGuard hub ──────────┘ / spoke
                                          │
                                        ssh/db/web ── 127.0.0.1 only
```

## Why WireGuard-in-HTTPS

- **Zero open ports on your network** — the agent only dials out.
- **Single bastion port** — nothing else to firewall, ACME included.
- **Stock WireGuard crypto** — nothing reinvented (goal #3). wireguard-go in
  userspace on both ends; the tunnel rides a WebSocket.

## Quickstart (dev, rootless)

```bash
make build
make dev                       # control plane at https://127.0.0.1:8443
# in another terminal (uses the secret dev.sh prints):
./bin/entranced --server https://127.0.0.1:8443 \
    --secret <SECRET> --allow 22 --net-mode loopback --ca-file data/dev/tls/cert.pem
# in another terminal:
./bin/entrui login --url https://127.0.0.1:8443 --ca-file data/dev/tls/cert.pem
./bin/entrui hosts
./bin/entrui connect 1                 # tunnels to host 1, launches ssh
make e2e                               # automated rootless vertical slice
```

## Production (TUN mode, real WireGuard)

On the bastion (needs `CAP_NET_ADMIN` / root for the TUN interface):

```bash
ENTRANCE_ADMIN_PASSWORD='...' entrance serve \
    --relay-mode wg --hostname your.domain.com --data-dir /var/lib/entrance
```

`add-host` mints a one-time enrollment secret:

```bash
entrance add-host my-nas
# → wear-diameter-sauterel...   (single use, 24h)
```

On each target host:

```bash
sudo entranced --server https://your.domain.com \
    --secret wear-diameter-sauterel... \
    --allow 22,3389,5432 --remap 22=2222 --net-mode tun
```

The enrollment secret is consumed once; afterwards the agent runs from its
saved state (token + WG keys, mode 0600). Revoke a host any time:

```bash
entrui login --url https://your.domain.com
entrui hosts
entrui connect 1 ...      # relay sessions
# revoke live, from any API client or the TUI:
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
     https://your.domain.com/api/v1/daemons/1
```

Revocation closes the agent's channel (it exits with code 3, demanding
re-enroll) and drops its WG peer + relay sessions immediately.

### ACME / TLS

Prod uses `golang.org/x/crypto/acme/autocert` with **TLS-ALPN-01**, so
certificate issuance and renewal happen on the same `:443` socket — the
bastion stays a single open port. The agent pins the certificate if you
pass `--ca-file`. For dev the control plane self-signs and prints a
fingerprint.

## Requirements

- Go ≥ 1.26 to build.
- TUN mode needs privileges on the bastion and each agent
  (`CAP_NET_ADMIN`; root on macOS dev, where `utun` interfaces are used).
- Everything else — including `go test ./...` and the rootless e2e — needs
  no privileges at all. Linux/amd64+arm64 cross-compiles cleanly
  (`make cross-linux`, `CGO_ENABLED=0`).

## Repo layout

```
cmd/entrance cmd/entranced cmd/entrui   binaries
internal/api          control-plane HTTP+WS (REST for future frontends)
internal/daemon       agent lifecycle (enroll, WS, WG device, listeners)
internal/wg           wireguard-go integration (custom conn.Bind, transports)
internal/relay        bastion relay sessions (caps, reaping)
internal/client       typed HTTP+WS client (TUI + agent share it)
internal/{auth,db,tlssetup,tui,wsproto,config}
tests/e2e             rootless vertical slice
deploy/               systemd units + installer
```

See `DESIGN.md` for the full architecture and threat model.