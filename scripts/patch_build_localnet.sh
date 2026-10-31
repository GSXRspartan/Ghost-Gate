#!/usr/bin/env bash
# Build the three binaries a live localnet needs, from the patched Ootle tree.
#
# The validator, indexer and walletd must all come from the same tree: the patched walletd is the
# whole point of Gate 3, and mixing a patched wallet with a pristine validator would be a different
# experiment than the one the gate describes.
#
# Jobs default to 1. This box has ~3.3 GiB of RAM, and walletd's graph (webrtc, wasm-opt's C++ build)
# exhausts it at higher parallelism -- the WSL VM is killed outright, which surfaces as a dropped
# connection rather than a compiler diagnostic.
#
# Debug profile: a localnet does not need optimised code, and debug links far faster.
#
# Usage: scripts/patch_build_localnet.sh
set -uo pipefail
export PATH="/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export RUST_BACKTRACE=1

TARGET="${TARGET:-/root/gg-ootle-target}"
STAGED="${STAGED:-/root/gg/_ootle-v042-ghost-gate}"
JOBS="${CARGO_BUILD_JOBS:-1}"
LOG="${LOG:-/root/localnet-build.log}"

# Package names, not binary names: applications/tari_walletd declares the package
# tari_ootle_walletd, so `-p tari_walletd` is rejected outright.
#
#   applications/tari_validator_node -> tari_validator_node
#   applications/tari_indexer        -> tari_indexer
#   applications/tari_walletd        -> tari_ootle_walletd
#
# The daemon's *binary* is tari_ootle_walletd, not tari_walletd -- worth knowing before writing a
# localnet config that tries to exec it.
#
# tari_indexer also has an `indexer-gen-openapi` bin, which this build skips by naming the package's
# main binary through --bin.
PACKAGES="${PACKAGES:--p tari_validator_node -p tari_indexer -p tari_ootle_walletd}"
BINS="${BINS:---bin tari_validator_node --bin tari_indexer --bin tari_ootle_walletd}"

[ -f "$STAGED/Cargo.toml" ] || { echo "error: staged tree missing at $STAGED" >&2; exit 1; }

cd "$STAGED" || exit 1
: > "$LOG"

echo "building: cargo build $PACKAGES $BINS" | tee -a "$LOG"
# shellcheck disable=SC2086
exec env CARGO_TARGET_DIR="$TARGET" CARGO_BUILD_JOBS="$JOBS" \
  cargo build $PACKAGES $BINS 2>&1 | tee -a "$LOG"
exit "${PIPESTATUS[0]}"