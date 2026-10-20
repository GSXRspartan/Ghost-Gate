#!/usr/bin/env bash
# Drive the real Privacy Lab in headless Edge over CDP, verifying the matrix rain.
#
# Companion to browser_admin_check.sh: same browser plumbing, same harness pattern. It renders
# the Lab at the acceptance sizes, screenshots both gutter streams two frames apart, and asserts
# the dashboard stays readable. Screenshots land in docs/screenshots/ so the acceptance record
# carries the visual evidence.
#
#   scripts/lab_matrix_check.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

EDGE="/mnt/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
NODE="/mnt/c/Program Files/nodejs/node.exe"
LAB_URL="${GG_LAB_URL:-http://127.0.0.1:7799/lab}"
OUT_DIR="${GG_MATRIX_OUT:-$(pwd)/docs/screenshots}"
WORK="${GG_MATRIX_BROWSER_WORK:-/tmp/gg-matrix-browser}"
PORT=${CDP_PORT:-$((21000 + RANDOM % 20000))}

[ -x "$NODE" ] || { echo "no Windows node at $NODE"; exit 1; }
[ -f "$EDGE" ] || { echo "no Edge binary at $EDGE"; exit 1; }
mkdir -p "$OUT_DIR"

cleanup() {
  kill "$EDGE_PID" 2>/dev/null || true
}
trap cleanup EXIT

PROFILE_WIN="C:\\Windows\\Temp\\edge-gg-matrix-$$"
echo "== launching headless Edge on CDP :$PORT (the operator's own browser is never touched) =="
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

WIN_SCRIPT="D:\\Codex\\ghost-gate-workspace\\ghost-gate\\scripts\\cdp-matrix-check.mjs"
WIN_OUT="D:\\Codex\\ghost-gate-workspace\\ghost-gate\\docs\\screenshots"
"$NODE" "$WIN_SCRIPT" "$PORT" "$LAB_URL" "$WIN_OUT"
