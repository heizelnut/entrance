# Entrance

A tiny self-hosted bastion. **One HTTPS port, no inbound ports on your
machines.** Agents dial out to the bastion; you sign in with a passkey and get
a shell on any connected host.

```
browser ──passkey──▶ entrance (:443) ◀──HTTPS / WebSocket── entranced (your hosts)
                         │                                        │
                         └──────────── remote shell (PTY) ────────┘
```

| Binary | Role |
|---|---|
| `entrance` | Bastion. One HTTPS port; WebAuthn passkey auth; browser terminal. |
| `entranced` | Outbound-only agent. Opens **no** ports; serves PTY shells on request. |

## How it works

- **Transport:** a single WebSocket per agent, carried over HTTPS. There is no
  WireGuard, no TUN device, and no relay layer.
- **Auth:**
  - **agents** authenticate with one shared **token** (`--token`);
  - the **human admin** authenticates with a **WebAuthn passkey**.
- **Remote shell:** opening a host in the web UI makes the bastion ask the
  agent for a PTY and bridge it to an `xterm.js` terminal in your browser.
- **State:** one SQLite file (passkeys, sessions, known hosts). The agent is
  stateless.

## Quickstart (dev)

```bash
make dev        # bastion on http://localhost:8443, bootstrap token "local-dev"
# in another terminal:
make dev-agent  # an agent connecting to the local bastion
```

Open <http://localhost:8443>, expand **Register a new passkey**, enter the
bootstrap token (`local-dev`), and register. Then click the host to open a
shell.

> Dev serves plain HTTP on `localhost`: browsers treat that as a secure
> context, so passkeys work without a trusted certificate. Production is HTTPS.

## Production

Bastion (ports 80/443 must be reachable for ACME TLS-ALPN-01):

```bash
entrance --dev=false --listen :443 --hostname bastion.example.com \
    --token "$(openssl rand -hex 32)" --data-dir /var/lib/entrance
```

Agent on each host:

```bash
entranced --server https://bastion.example.com --token <TOKEN> \
    --audit-log /var/log/entranced-audit.log
```

See `deploy/` for systemd units.

## Security notes

- The single token authenticates agents **and** bootstraps the first passkey.
  Treat it as a root secret.
- A shell opened from the bastion runs **as the agent's user**, with no
  sandbox. Run the agent as an unprivileged user; the bastion is only as
  trusted as its passkey.
- With `--audit-log`, the agent logs every shell open/close (time, session id,
  shell, exit code).
- Not yet implemented: per-host tokens, command allow-listing, MFA beyond the
  passkey, recording full session transcripts. See `DESIGN.md`.

## Requirements

- Go ≥ 1.26 to build.
- No privileges required — neither the bastion nor the agent needs root, a TUN
  device, or a kernel module.
