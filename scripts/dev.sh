#!/usr/bin/env bash
# dev.sh — one-host rootless playground.
#
#   1. starts a dev control plane on 127.0.0.1:8443 (self-signed),
#   2. prints an enrollment secret,
#   3. prints the command to start an agent in loopback mode exposing a port.
#
# Requires: go. The agent runs WITHOUT a TUN (loopback net mode) so WG traffic
# rides the control channel to a local echo: good for exercising the API/TUI.
set -euo pipefail
cd "$(dirname "$0")/.."

DATA=./data/dev
mkdir -p "$DATA"
PASS="${ENTRANCE_ADMIN_PASSWORD:-local-dev}"

echo "==> building"
go build -o ./bin/entrance ./cmd/entrance
go build -o ./bin/entranced ./cmd/entranced

echo "==> starting control plane on https://127.0.0.1:8443 (data: $DATA)"
ENTRANCE_ADMIN_PASSWORD="$PASS" ./bin/entrance serve --dev \
  --data-dir "$DATA" --listen 127.0.0.1:8443 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT

sleep 1
TOK=$(curl -sk -X POST https://127.0.0.1:8443/api/v1/auth/login \
  -d "{\"username\":\"admin\",\"password\":\"$PASS\"}" \
  | sed -E 's/.*"session_token":"([^"]+)".*/\1/')
SECRET=$(curl -sk -X POST -H "Authorization: Bearer $TOK" \
  https://127.0.0.1:8443/api/v1/enroll-secrets -d '{"label":"dev-host"}' \
  | sed -E 's/.*"secret":"([^"]+)".*/\1/')

echo
echo "control plane: https://127.0.0.1:8443  (user: admin / $PASS)"
echo "self-signed fingerprint: $(cat "$DATA/tls/cert.pem" | openssl x509 -noout -fingerprint -sha256 2>/dev/null || echo 'see server log')"
echo "enrollment secret: $SECRET"
echo
echo "agent (loopback mode, exposes local :22 to relays):"
echo "  ./bin/entranced --server https://127.0.0.1:8443 \\"
echo "      --secret $SECRET --allow 22 --ca-file $DATA/tls/cert.pem \\"
echo "      --net-mode loopback"
echo
echo "(control plane running; Ctrl-C to stop)"
wait $SRV