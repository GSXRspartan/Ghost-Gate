#!/usr/bin/env bash
# Drive the real Privacy Lab in headless Edge over CDP, verifying the Sapient connect UI.
#
# Companion to lab_matrix_check.sh / browser_admin_check.sh: same browser plumbing. This runs the
# connect ceremony against a MOCK window.tari injected before page load — it proves the UI wiring,
# not the physical wallet. The physical Sapient approval prompt is the operator's milestone.
#
#   scripts/lab_connect_check.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

EDGE="/mnt/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
NODE="/mnt/c/Program Files/nodejs/node.exe"
LAB_URL="${GG_LAB_URL:-http://127.0.0.1:7799/lab}"
WORK="${GG_CONNECT_BROWSER_WORK:-/tmp/gg-connect-browser}"
PORT=${CDP_PORT:-$((23000 + RANDOM % 20000))}

[ -x "$NODE" ] || { echo "no Windows node at $NODE"; exit 1; }
[ -f "$EDGE" ] || { echo "no Edge binary at $EDGE"; exit 1; }

cleanup() { kill "$EDGE_PID" 2>/dev/null || true; }
trap cleanup EXIT

PROFILE_WIN="C:\\Windows\\Temp\\edge-gg-connect-$$"
echo "== launching headless Edge on CDP :$PORT =="
"$EDGE" \
  --headless=new --disable-gpu --no-sandbox --no-first-run --no-default-browser-check \
  --remote-debugging-port="$PORT" --user-data-dir="$PROFILE_WIN" \
  about:blank >/dev/null 2>&1 &
EDGE_PID=$!

echo "== waiting for CDP =="
for _ in $(seq 1 80); do
  "$NODE" -e "fetch('http://127.0.0.1:$PORT/json/version').then(()=>process.exit(0)).catch(()=>process.exit(1))" 2>/dev/null && break
  sleep 0.25
done

WIN_SCRIPT="D:\\Codex\\ghost-gate-workspace\\ghost-gate\\scripts\\cdp-connect-check.mjs"
"$NODE" "$WIN_SCRIPT" "$PORT" "$LAB_URL"
