#!/usr/bin/env bash
# Refresh the DID note (notes idle 7 days are deleted) and post a short heartbeat.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG="${TECHNOCORE_LOG:-$HOME/.config/technocore/refresh.log}"
mkdir -p "$(dirname "$LOG")"
{
  echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
  /usr/bin/python3.12 "$ROOT/technocore_agent.py" refresh
} >>"$LOG" 2>&1
