#!/usr/bin/env bash
# Sync the patched Ootle tree into WSL and build/test the wallet MVP patch.
#
# The patched tree is ../tari-ootle-v0.42.0-ghost-gate, a writable copy of the pinned reference
# carrying only the minimum-value-promise change (docs/wallet-mvp.patch). This script stages it at
# /root/gg/_ootle-v042-ghost-gate and runs the wallet SDK's tests against it.
#
# The pristine reference is never written to; scripts/wallet_mvp_patch.sh emits and checks the diff.

set -uo pipefail

export PATH="/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}"
export RUST_BACKTRACE=1

WINDOWS_ROOT="${WINDOWS_ROOT:-/mnt/c/Users/pdark/Documents/Codex/2026-10-01/ghost-gate-workspace}"
LINUX_ROOT="${LINUX_ROOT:-/root/gg}"
PATCHED_SRC="$WINDOWS_ROOT/tari-ootle-v0.42.0-ghost-gate"
PATCHED_DST="$LINUX_ROOT/_ootle-v042-ghost-gate"
TARGET="${TARGET:-/root/gg-ootle-target}"

if [ ! -f "$PATCHED_SRC/Cargo.toml" ]; then
  echo "error: patched tree missing at $PATCHED_SRC" >&2
  exit 1
fi

echo "[patch-test] staging patched tree -> $PATCHED_DST"
mkdir -p "$PATCHED_DST"
rsync -a --delete --exclude 'target/' --exclude '.git/' "$PATCHED_SRC/" "$PATCHED_DST/"

# The build script for template_builtin compiles the builtin templates into its own crate tree, and
# the nested cargo build inherits CARGO_TARGET_DIR — which would send the artifact somewhere the
# script does not look. The wallet SDK does not need the builtins, but building anything in that
# workspace can, so pre-build them with the variable unset.
echo "[patch-test] pre-building builtin templates (in-tree, CARGO_TARGET_DIR unset)"
( unset CARGO_TARGET_DIR
  for tpl in account nft_faucet faucet liquidity_pool burn_rate_governance; do
    dir="$PATCHED_DST/crates/template_builtin/templates/$tpl"
    [ -d "$dir" ] || continue
    ( cd "$dir" && cargo build --target wasm32-unknown-unknown --release >/dev/null 2>&1 ) || {
      echo "[patch-test] warning: could not pre-build $tpl" >&2
    }
  done
)

cd "$PATCHED_DST" || exit 1

case "${1:-test}" in
  check|build)
    shift || true
    exec cargo check -p tari_ootle_wallet_sdk --all-targets "$@"
    ;;
  test)
    shift || true
    exec cargo test -p tari_ootle_wallet_sdk -p tari_ootle_walletd "$@"
    ;;
  *)
    exec cargo "$@"
    ;;
esac