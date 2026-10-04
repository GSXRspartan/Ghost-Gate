#!/usr/bin/env bash
# Sync the Windows checkout into the native Linux tree and run a cargo command in it.
#
# Split out from scripts/wsl_run.sh so it can be pointed at the shared warm target directory
# (/root/gg-ootle-target) rather than wsl_run.sh's own /root/gg-target. The cohort crates are only
# compiled once, in whichever target directory the cohort was built in, and pointing a second command
# at a different one silently recompiles the whole Ootle layer.
#
# The cohort switch lives in the root Cargo.toml's [workspace.dependencies]; nothing here decides it.
#
# Usage: scripts/gg_test.sh <cargo-subcommand> [args...]
#   scripts/gg_test.sh test -p ghost-gate-tests --test gate_engine -- --test-threads=2
set -uo pipefail
export PATH="/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

WINDOWS_ROOT="${WINDOWS_ROOT:-/mnt/c/Users/pdark/Documents/Codex/2026-10-01/ghost-gate-workspace}"
LINUX_ROOT="${LINUX_ROOT:-/root/gg}"
TARGET="${TARGET:-/root/gg-ootle-target}"
JOBS="${CARGO_BUILD_JOBS:-1}"
LOG="${LOG:-/root/gg-test.log}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Keep the Linux tree in step with the Windows source of truth. _sync.sh copies only this repository;
# the cohort trees are prepared separately (scripts/prepare_reference.sh, scripts/patch_test.sh).
bash "$SCRIPT_DIR/_sync.sh" "$WINDOWS_ROOT" "$LINUX_ROOT" || exit 1

cd "$LINUX_ROOT/ghost-gate" || exit 1

SUB="${1:-test}"
shift || true

{
  echo "=== $(date -Is) cargo $SUB $* (target=$TARGET jobs=$JOBS) ==="
} >> "$LOG"

env CARGO_TARGET_DIR="$TARGET" CARGO_BUILD_JOBS="$JOBS" RUST_BACKTRACE=1 \
  cargo "$SUB" "$@" 2>&1 | tee -a "$LOG"
exit "${PIPESTATUS[0]}"