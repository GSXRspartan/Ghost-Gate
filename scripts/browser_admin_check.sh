#!/usr/bin/env bash
# Drive the real admin dashboard in headless Edge over CDP.
#
# Backend tests prove the API. This proves the page a non-technical administrator actually touches:
# it renders, the PASSKEY ceremony completes through the real WebAuthn API against a virtual
# authenticator, gates and tier checkboxes appear, a tier wired by clicking survives a reload, and a
# hostile display name or gate id renders as text instead of executing.
#
# It needs an admin server. This script starts one on a FRESH data directory (so the bootstrap
# token is known) unless you point GG_ADMIN_URL at an existing deployment.
#
#   scripts/browser_admin_check.sh
#   GG_ADMIN_URL=http://127.0.0.1:7812/admin GG_BOOTSTRAP=<token> scripts/browser_admin_check.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

EDGE="/mnt/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
NODE="/mnt/c/Program Files/nodejs/node.exe"
TARGET_DIR="${GG_TARGET_DIR:-${HOME}/gg-ootle-target}"
ADMIN_BIN="$TARGET_DIR/debug/ghost-gate-admin"
ADMIN_PORT="${GG_ADMIN_PORT:-7812}"
# Passkeys need a registrable domain as the relying party, so the harness browses through
# `localhost` (browsers accept it) rather than the 127.0.0.1 literal, exactly as an operator would.
ADMIN_URL="${GG_ADMIN_URL:-http://${GG_ADMIN_HOSTNAME:-localhost}:$ADMIN_PORT/admin}"
WORK="${GG_ADMIN_BROWSER_WORK:-/tmp/gg-admin-browser}"
PORT=${CDP_PORT:-$((20000 + RANDOM % 20000))}

[ -x "$NODE" ] || { echo "no Windows node at $NODE"; exit 1; }
[ -f "$EDGE" ] || { echo "no Edge binary at $EDGE"; exit 1; }
[ -x "$ADMIN_BIN" ] || { echo "build it first: cargo build -p ghost-gate-admin"; exit 1; }

OWN_SERVER=0
BOOTSTRAP="${GG_BOOTSTRAP:-}"
if [ -z "$ADMIN_URL" ] || [ "${GG_ADMIN_URL:-}" = "" ]; then :; fi
if ! curl -sf -m 2 "${ADMIN_URL%/admin}/admin/api/bootstrap" >/dev/null 2>&1; then
  echo "== starting a fresh admin server on $ADMIN_PORT (data $WORK) =="
  rm -rf "$WORK"; mkdir -p "$WORK"
  GG_ADMIN_DATA="$WORK/data" GG_ADMIN_BIND="127.0.0.1:$ADMIN_PORT" \
    GG_ADMIN_HOSTNAME="${GG_ADMIN_HOSTNAME:-localhost}" \
    GG_GENESIS_HASH="${GG_GENESIS_HASH:-00f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0}" \
    "$ADMIN_BIN" > "$WORK/admin.log" 2>&1 &
  ADMIN_PID=$!
  OWN_SERVER=1
  for _ in $(seq 1 60); do
    curl -sf -m 2 "${ADMIN_URL%/admin}/admin/api/bootstrap" >/dev/null 2>&1 && break
    sleep 0.25
  done
  BOOTSTRAP=$(cat "$WORK/data/bootstrap.token" 2>/dev/null || true)
  [ -n "$BOOTSTRAP" ] || { echo "no bootstrap token: $(cat "$WORK/admin.log")"; exit 1; }
fi

PROFILE_WIN="C:\\Windows\\Temp\\edge-gg-admin-$$"
cleanup() {
  kill "$EDGE_PID" 2>/dev/null || true
  [ "$OWN_SERVER" = "1" ] && kill "$ADMIN_PID" 2>/dev/null || true
}
trap cleanup EXIT

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

WIN_SCRIPT="D:\\Codex\\ghost-gate-workspace\\ghost-gate\\scripts\\cdp-admin-check.mjs"
"$NODE" "$WIN_SCRIPT" "$PORT" "$ADMIN_URL" "$BOOTSTRAP"
