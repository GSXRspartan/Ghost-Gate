#!/usr/bin/env bash
# Run the patched Ootle wallet SDK's minimum-value-promise tests.
#
# Jobs are pinned to 1: this box has ~3.3 GiB of RAM and the workspace's dev-dependency graph
# (webrtc, wasm-opt's C++ build) exhausts it at higher parallelism, which kills the WSL VM rather
# than reporting a build error. The expensive dependencies are already compiled in the target dir.
#
# Usage: scripts/patch_sdk_test.sh [extra cargo args]

set -uo pipefail
export PATH="/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export RUST_BACKTRACE=1

TARGET="${TARGET:-/root/gg-ootle-target}"
STAGED="${STAGED:-/root/gg/_ootle-v042-ghost-gate}"
LOG="${LOG:-/root/patch-sdk.log}"
JOBS="${CARGO_BUILD_JOBS:-1}"

mkdir -p "$(dirname "$LOG")"
: > "$LOG"

cd "$STAGED" || { echo "error: staged tree missing at $STAGED" >&2; exit 1; }

# Foreground on purpose. A `setsid ... &` child does not survive this script exiting under
# `wsl.exe`: WSL tears the session down with the last foreground process, and the detached job dies
# with it — which looks like a silent no-op with an empty log.
#
# Build the SDK's own lib tests only. `-p ... --lib` keeps walletd (and therefore webrtc and the
# wasm-opt C++ build) out of the graph; the patch touches no walletd code path that this misses.
env CARGO_TARGET_DIR="$TARGET" CARGO_BUILD_JOBS="$JOBS" \
  cargo test -p tari_ootle_wallet_sdk --lib "$@" \
  2>&1 | tee "$LOG"
exit "${PIPESTATUS[0]}"