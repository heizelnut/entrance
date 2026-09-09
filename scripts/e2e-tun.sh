#!/usr/bin/env bash
# e2e-tun.sh — REAL tunnel end-to-end on one machine. Requires sudo (utun
# interfaces + ifconfig on macOS; ip on Linux).
#
# Exercises the production data path: bastion utun <-> agent utun, users reach
# services through WireGuard-in-the-control-channel.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "NOT IMPLEMENTED — phase 1 verifies the data plane rootless;"
echo "a real-TUN e2e needs a clean network namespace plan. See DESIGN.md."
exit 1