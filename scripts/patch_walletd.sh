#!/usr/bin/env bash
# Type-check or run walletd's tests against the already-staged patched tree.
#
# Kept separate from scripts/patch_test.sh so that a walletd iteration does not pay for an rsync of
# the patched tree off /mnt/c, and so PATH is set here rather than inherited from Windows — a
# Windows PATH entry containing "(x86)" is a syntax error once bash re-parses it.
#
# Jobs default to 1: this box has ~3.3 GiB of RAM, and walletd's graph includes webrtc and a C++
# wasm-opt build. At higher parallelism the WSL VM is killed outright, which surfaces as a vanished
# connection rather than a compiler diagnostic.
#
# Usage: scripts/patch_walletd.sh check|test [cargo args...]

set -uo pipefail
export PATH="/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export RUST_BACKTRACE=1

TARGET="${TARGET:-/root/gg-ootle-target}"
STAGED="${STAGED:-/root/gg/_ootle-v042-ghost-gate}"
JOBS="${CARGO_BUILD_JOBS:-1}"

[ -f "$STAGED/Cargo.toml" ] || {
  echo "error: staged tree missing at $STAGED (run scripts/patch_test.sh check first)" >&2
  exit 1
}

cd "$STAGED" || exit 1

case "${1:-check}" in
  check) exec env CARGO_TARGET_DIR="$TARGET" CARGO_BUILD_JOBS="$JOBS" \
           cargo check -p tari_ootle_walletd --lib --tests "${@:2}" ;;
  test)  exec env CARGO_TARGET_DIR="$TARGET" CARGO_BUILD_JOBS="$JOBS" \
           cargo test  -p tari_ootle_walletd --lib "${@:2}" ;;
  *)     exec env CARGO_TARGET_DIR="$TARGET" CARGO_BUILD_JOBS="$JOBS" cargo "$@" ;;
esac