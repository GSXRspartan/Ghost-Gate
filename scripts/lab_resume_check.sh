#!/usr/bin/env bash
# Drive the real Privacy Lab in headless Edge over CDP, verifying the RESUME EXISTING PROOF flow.
#
# Companion to lab_connect_check.sh / lab_matrix_check.sh: same browser plumbing. The mock
# wallet RECORDS every call and REJECTS any shield request, so if the resume path ever drifted
# back to the shield flow, the assertions fail loudly. The physical Sapient signature prompt is
# the operator's milestone and stays theirs to confirm.
#
#   scripts/lab_resume_check.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

EDGE="/mnt/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
NODE="/mnt/c/Program Files/nodejs/node.exe"
LAB_URL="${GG_LAB_URL:-http://127.0.0.1:7897/lab}"
WORK="${GG_RESUME_BROWSER_WORK:-/tmp/gg-resume-browser}"
PORT=${CDP_PORT:-$((23000 + RANDOM % 20000))}

[ -x "$NODE" ] || { echo "no Windows node at $NODE"; exit 1; }
[ -f "$EDGE" ] || { echo "no Edge binary at $EDGE"; exit 1; }

cleanup() { kill "$EDGE_PID" 2>/dev/null || true; }
trap cleanup EXIT

PROFILE_WIN="C:\\Windows\\Temp\\edge-gg-resume-$$"
echo "== launching headless Edge on CDP :$PORT =="
"$EDGE" \
  --headless=new --disable-gpu --no-sandbox --no-first-run --no-default-browser-check \
  --remote-debugging-port="$PORT" --user-data-dir="$PROFILE_WIN" \
  about:blank >/dev/null 2>&1 &
EDGE_PID=$!

for i in $(seq 1 40); do
  if curl -s "http://127.0.0.1:$PORT/json/version" >/dev/null 2>&1; then break; fi
  sleep 0.25
done

echo "== driving the resume flow =="
"$NODE" "D:\\Codex\\ghost-gate-workspace\\ghost-gate\\scripts\\cdp-resume-check.mjs" "$PORT" "$LAB_URL"
