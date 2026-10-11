#!/usr/bin/env bash
# Real-browser verification of the Haunted Vault's startup and gameplay.
#
# WHY THIS EXISTS: the reported bug ("nearly black, blurred, a 'Keep it' popup over the title on
# load") was a CSS/HTML defect invisible to the provider unit tests, which never render a page. So
# this drives a real headless Edge against the REAL served bridge on :7799 — not a mock, not a file
# — and asserts on computed styles, element visibility, navigation, and actual puzzle interaction.
#
# WHAT IT CHECKS
#   1. /game loads with the TITLE screen visible and every overlay hidden (the reported defect).
#   2. Enter Preview navigates to the Sanctum; preview banner shows; doors open as preview.
#   3. Preview touches NO challenge/prove/credential route (network assertion).
#   4. All three puzzles are actually played to completion (clicks, not element presence).
#   5. Relic + whisper reward dialogs appear and their dismiss button works.
#   6. Reload does not trap the player; returning to the menu works.
#   7. Console errors / failed requests are captured and reported.
#
# The game is served by the already-running bridge; this script starts nothing heavy.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
EDGE="/mnt/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
# A unique port and profile per run. CDP new-document scripts are registered per browser target and
# PERSIST for that target's lifetime, so reusing a port could attach to an earlier headless Edge
# whose recorders are still armed -- and double-record every flash. A fresh port guarantees a fresh
# browser. (The operator's own Edge is never touched: it does not listen on a CDP port.)
PORT=${CDP_PORT:-$((20000 + RANDOM % 20000))}
GAME_URL="http://127.0.0.1:7799/game"

# Edge binds its CDP port on the WINDOWS loopback; WSL's own curl cannot reach it. The harness must
# therefore run under the WINDOWS node, which shares that loopback and can also load the bridge on
# 127.0.0.1:7799 (Windows localhost -> WSL, via localhostForwarding). This is the same route the
# operator's Windows browser uses.
NODE="/mnt/c/Program Files/nodejs/node.exe"
[ -x "$NODE" ] || { echo "no Windows node at $NODE"; exit 1; }
[ -f "$EDGE" ] || { echo "no Edge binary at $EDGE"; exit 1; }
WIN_SCRIPT="D:\\Codex\\ghost-gate-workspace\\ghost-gate\\scripts\\cdp-game-check.mjs"

# Refresh the served assets are current (bridge serves from disk, but be explicit for operators).
echo "== game served: $(curl -s -o /dev/null -w '%{http_code}' "$GAME_URL") =="
echo "== launching headless Edge on CDP :$PORT (windows loopback) =="

PROFILE_WIN="C:\\Windows\\Temp\\edge-gg-$$"
"$EDGE" \
  --headless=new \
  --disable-gpu --no-sandbox --no-first-run --no-default-browser-check \
  --disable-features=Translate,msEdgeSidebarV2 \
  --remote-debugging-port="$PORT" \
  --user-data-dir="$PROFILE_WIN" \
  about:blank >/dev/null 2>&1 &
EDGE_PID=$!
cleanup() { kill "$EDGE_PID" 2>/dev/null || true; }
trap cleanup EXIT

# Wait for CDP to answer on the Windows loopback (via Windows node).
echo "== waiting for CDP =="
for _ in $(seq 1 60); do
  if "$NODE" -e "fetch('http://127.0.0.1:$PORT/json/version').then(r=>process.exit(0)).catch(()=>process.exit(1))" 2>/dev/null; then
    break
  fi
  sleep 0.25
done

echo "== running the CDP harness (windows node) =="
"$NODE" "$WIN_SCRIPT" "$PORT"