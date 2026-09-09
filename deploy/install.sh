#!/usr/bin/env bash
# install.sh — install entrance & entranced Linux binaries + systemd units.
#
#   sudo ./deploy/install.sh /path/to/bin-dir
#
# Point it at the output of `make cross-linux` (bin/linux-amd64).
set -euo pipefail
cd "$(dirname "$0")/.."

SRC="${1:-bin/linux-amd64}"
if [ ! -x "$SRC/entrance" ] || [ ! -x "$SRC/entranced" ]; then
  echo "expected $SRC/{entrance,entranced}; run 'make cross-linux' first" >&2
  exit 1
fi

install -m 0755 "$SRC/entrance" /usr/local/bin/entrance
install -m 0755 "$SRC/entranced" /usr/local/bin/entranced

if command -v systemctl >/dev/null; then
  id -u entrance >/dev/null 2>&1 || useradd --system --home /var/lib/entrance --shell /usr/sbin/nologin entrance
  install -d -m 0700 -o entrance -g entrance /var/lib/entrance
  install -m 0644 deploy/entrance.service /etc/systemd/system/
  install -m 0644 deploy/entranced.service /etc/systemd/system/
  systemctl daemon-reload
  echo "installed. Edit /etc/systemd/system/entrance.service (domain, admin password)"
  echo "then: systemctl enable --now entrance"
  echo "on each target host: systemctl enable --now entranced (after setting the enrollment secret)"
else
  echo "no systemd detected; binaries installed manually: /usr/local/bin/{entrance,entranced}"
fi