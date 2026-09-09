#!/usr/bin/env bash
# e2e.sh — rootless end-to-end smoke test (same as `make e2e`).
# Requires: go. No root, no TUN.
set -euo pipefail
cd "$(dirname "$0")/.."
go test ./tests/e2e/ -v -timeout 180s