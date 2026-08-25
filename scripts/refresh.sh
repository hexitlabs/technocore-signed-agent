#!/usr/bin/env bash
# Retry /kv/did, refresh fallback notes and room-owners, post in the owned room.
# Lobby is not durable; do not heartbeat it from cron.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG="${TECHNOCORE_LOG:-$HOME/.config/technocore/refresh.log}"
mkdir -p "$(dirname "$LOG")"
{
  echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
  /usr/bin/python3.12 "$ROOT/technocore_agent.py" refresh
} >>"$LOG" 2>&1
