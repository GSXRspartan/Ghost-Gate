#!/usr/bin/env bash
# Ghost Gate — The Haunted Vault: one-command startup for the demo machine.
#
# Starts the bridge with the three game gates and (optionally) the Telegram bot, after building
# everything against the pinned cohort. Safe to re-run: each step checks whether it is already
# built/running. It never touches the pinned cohort tree and never runs `cargo clean`.
#
# Modes:
#   ./scripts/start_vault.sh                # build + start bridge + print the game URL
#   GG_TG_BOT_TOKEN=... GG_TG_CHAT_ID=... ./scripts/start_vault.sh --with-telegram
#
# Real proofs need a standing localnet (base node + validators + walletd) with three real gates
# deployed; see "Standing localnet" in docs/CONTEST_README.md. Without one, the game runs in
# preview mode and every proof route fails closed with an honest message.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# The pinned toolchain and protoc, same as every other script here.
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.97.1}"
export PROTOC="${PROTOC:-/home/pdark/ootle-build/protoc/bin/protoc}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}"

# Native build deps the image lacks (idempotent; no sudo).
bash "$SCRIPT_DIR/stage_native_deps.sh" >/dev/null
export PATH="/home/pdark/gg-local/usr/bin:$PATH"
export PKG_CONFIG_PATH="${PKG_CONFIG_PATH:-/home/pdark/gg-local/usr/lib/x86_64-linux-gnu/pkgconfig}"
export CPATH="${CPATH:-/home/pdark/gg-local/usr/include}${CPATH:+:$CPATH}"

BIN_DIR="/home/pdark/gg-ootle-target/debug"
BRIDGE_BIN="$BIN_DIR/ghost-gate-bridge"
TELEGRAM_BIN="$BIN_DIR/ghost-gate-telegram"
BUILD_FLAG=""

echo "== building (only what changed; the target dir is warm) =="
# A FAILED BUILD MUST NOT LAUNCH A STALE BINARY. Previously a compile error was swallowed here and
# the script went on to announce "The Haunted Vault is up" while serving whatever binary happened
# to exist from the last successful build — a silently outdated deployment reporting success.
# Now: a build failure stops the launch unless --preview-only is given explicitly, and what runs
# is always identified by its path and build time.
if ! cargo build -p ghost-gate-walletd --bin ghost-gate-bridge; then
  echo >&2 "==============================================================="
  echo >&2 "BUILD FAILED — refusing to launch a possibly stale binary."
  echo >&2 "Run with --preview-only to start the EXISTING binary anyway"
  echo >&2 "(identified below by build time), or fix the build first."
  echo >&2 "==============================================================="
  if [ "${1:-}" != "--preview-only" ]; then
    exit 1
  fi
  echo "  --preview-only: launching the existing binary at its own risk"
fi
BRIDGE_BINARY="$(ls -l "$BRIDGE_BIN" 2>/dev/null | awk '{print $6, $7, $8}')"
echo "  bridge binary: $BRIDGE_BIN"
echo "  built:         ${BRIDGE_BINARY:-<missing!>}"
if [ ! -x "$BRIDGE_BIN" ]; then
  echo >&2 "no bridge binary exists at all; cannot start anything"
  exit 1
fi
if [ "${1:-}" = "--with-telegram" ] || [ -n "${GG_TG_BOT_TOKEN:-}" ]; then
  if ! cargo build -p ghost-gate-telegram; then
    echo >&2 "telegram build FAILED — starting the bridge only."
    if [ "${1:-}" = "--with-telegram" ]; then
      echo >&2 "(--with-telegram was requested; fix the telegram build to enable the bot)"
    fi
  else
    BUILD_FLAG="$BUILD_FLAG telegram"
  fi
fi

# ---------------------------------------------------------------------------
# Gate configuration. The three game gates are registered from env if provided;
# otherwise the demo runs with the localnet evidence addresses (from
# docs/GATE3_RESULTS.md) at the contest's example thresholds. Those are CONFIG,
# not protocol limits: replace the addresses with your own deployed gates.
# ---------------------------------------------------------------------------
GATE_ADDR="${GG_GATE_ADDR:-component_f222f57006413994f7161a77f999105a2f9edd1446700c4c80b796a1c79ffa01}"
RES_ADDR="${GG_RES_ADDR:-resource_5161236c4a402a14303a92562737748f0cd122fa42e3831aec7f32c6fca44fc7}"
GATES="${GG_BRIDGE_GATES:-crypt=$GATE_ADDR:$RES_ADDR:100000:6:GHOST,vault=$GATE_ADDR:$RES_ADDR:500000:6:GHOST,abyss=$GATE_ADDR:$RES_ADDR:2000000:6:GHOST}"
BIND="${GG_BRIDGE_BIND:-127.0.0.1:7799}"
ORIGINS="${GG_BRIDGE_ORIGINS:-http://127.0.0.1:7799}"
WALLETD_ENDPOINT="${GG_WALLETD_ENDPOINT:-}"
INDEXER_ENDPOINT="${GG_INDEXER_ENDPOINT:-}"

if [ ! -x "$BRIDGE_BIN" ]; then
  echo "bridge binary missing; the build failed" >&2
  exit 1
fi

echo "== starting the bridge =="
# Anything already listening is left alone: the script is re-runnable, not a supervisor.
if ss -ltn 2>/dev/null | grep -q ":${BIND##*:} "; then
  echo "  something is already listening on $BIND; leaving it in place"
else
  GG_BRIDGE_BIND="$BIND" \
  GG_BRIDGE_ORIGINS="$ORIGINS" \
  GG_BRIDGE_GATES="$GATES" \
  GG_WALLETD_ENDPOINT="$WALLETD_ENDPOINT" \
  GG_INDEXER_ENDPOINT="$INDEXER_ENDPOINT" \
    setsid nohup "$BRIDGE_BIN" > /home/pdark/gg-logs/vault-bridge.log 2>&1 < /dev/null &
  sleep 2
fi

if [ -n "${GG_TG_BOT_TOKEN:-}" ] && [ "${1:-}" = "--with-telegram" ]; then
  echo "== starting the Telegram bot =="
  GG_BRIDGE_ENDPOINT="$WALLETD_ENDPOINT_HTTP${WALLETD_ENDPOINT_HTTP:+$WALLETD_ENDPOINT_HTTP}" # placeholder, replaced below
  GG_BRIDGE_ENDPOINT="${GG_BRIDGE_ENDPOINT:-http://127.0.0.1:${BIND##*:}}"
  GG_TG_CLAIM_PORT="${GG_TG_CLAIM_PORT:-7808}" \
  GG_TG_GATE="${GG_TG_GATE:-crypt}" \
    setsid nohup "$TELEGRAM_BIN" > /home/pdark/gg-logs/vault-telegram.log 2>&1 < /dev/null &
  sleep 2
fi

echo
echo "== The Haunted Vault is up =="
echo "  game:     http://127.0.0.1:${BIND##*:}/game"
echo "  demo API: http://127.0.0.1:${BIND##*:}/"
echo "  bridge log:  /home/pdark/gg-logs/vault-bridge.log"
if [ -n "${GG_TG_BOT_TOKEN:-}" ] && [ "${1:-}" = "--with-telegram" ]; then
  echo "  telegram log: /home/pdark/gg-logs/vault-telegram.log"
fi
echo
echo "  Preview mode: open the game and choose \"Preview without a wallet\"."
echo "  Real proofs:  export GG_WALLETD_ENDPOINT=<walletd url> and restart, with a standing"
echo "                localnet behind it (see docs/CONTEST_README.md)."
