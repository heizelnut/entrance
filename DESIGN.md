# Entrance — Design

Entrance is a minimal self-hosted bastion: agents behind NAT dial a single
public HTTPS port, and an authenticated admin gets a remote shell on each.

## Components

| Binary | Responsibility |
|---|---|
| `entrance` | HTTPS server, agent registry, WebAuthn admin auth, browser terminal, shell proxy |
| `entranced` | Outbound-only agent: connect, authenticate, serve PTYs |

## Transport

One WebSocket per agent at `wss://<bastion>/agent`, authenticated with a single
shared bearer token. All control messages and terminal bytes are JSON frames
(`internal/proto`). Shell stdin/stdout ride as base64 `shell_data` frames; the
bastion multiplexes many shells over the one channel by `id`.

This deliberately replaces the earlier WireGuard-in-HTTPS design: no TUN
device, no userspace WireGuard, no relay layer, no per-host keys. The bastion
never needs `CAP_NET_ADMIN`.

## Authentication

- **Agents** present `Authorization: Bearer <token>` when dialing `/agent`.
- **Admin** authenticates in the browser with a **WebAuthn passkey**. The first
  passkey is bootstrapped with the same token (`X-Bootstrap-Token`); afterwards
  login is passkey-only. Sessions are opaque ids in an `HttpOnly` cookie.

## Remote shell

```
browser ── /ws/shell/<host> ──▶ bastion ── shell_open ──▶ agent
        ◀── shell_data (stdout) ──        ◀── shell_data (stdout)
        ── shell_data (stdin) ──▶         ── shell_data (stdin) ──▶ PTY
        ── shell_resize ──▶               ── shell_resize ──▶
```

The agent runs the configured shell (`$SHELL`, or `--shell`) on a PTY and
streams bytes; exit is reported as `shell_exit`. Shell open/close events are
written to the agent's audit log.

## Persistence

`internal/store` (SQLite, pure Go): WebAuthn credentials, browser sessions,
and the known-host registry. WebAuthn ceremony challenges live in memory with a
5-minute TTL.

## Threat model

- **Trust boundary:** the bastion. Anyone with a valid passkey can open a shell
  on any connected agent, as that agent's user. There is no per-host
  authorization yet.
- **The token is a root secret.** It grants agent (shell) access to whoever can
  present it as a connection, and can bootstrap a passkey. Rotate by restarting
  the bastion with a new token (existing agents must be updated).
- **No sandboxing.** A shell is a shell. Run `entranced` as an unprivileged
  user, ideally on hosts where that is acceptable.
- **TLS:** production uses ACME (TLS-ALPN-01) so issuance rides the same `:443`
  socket. Dev is plain HTTP on `localhost` only.

## Not implemented (intentionally, for now)

Per-host tokens, command allow-listing, session recording, MFA beyond the
passkey, reverse port-forwarding, and a non-browser client.
