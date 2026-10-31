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

WINDOWS_ROOT="${WINDOWS_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
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

# walletd's `default` features include `web_ui`, so `include_dir!` expands against `web_ui/dist` at
# compile time. Upstream's build.rs creates that directory but deliberately leaves it empty in debug
# mode (it only fills it in release, by running the npm build), which leaves the macro with nothing
# to embed. Ghost Gate never serves the UI, so stage a placeholder asset rather than paying for a
# node toolchain in WSL. This is a staging concern, not part of the MVP patch.
WALLET_WEB_DIST="$PATCHED_DST/applications/tari_walletd/web_ui/dist"
mkdir -p "$WALLET_WEB_DIST"
[ -s "$WALLET_WEB_DIST/index.html" ] || \
  printf '<!doctype html><title>Ghost Gate build placeholder</title>\n' > "$WALLET_WEB_DIST/index.html"

# The build script for template_builtin compiles the builtin templates into its own crate tree, and
# the nested cargo build inherits CARGO_TARGET_DIR — which would send the artifact somewhere the
# script does not look. The wallet SDK does not need the builtins, but building anything in that
# workspace can, so pre-build them with the variable unset.
#
# Skipped for `sync`: the artifacts live under each template's own target/, which the rsync above
# excludes, so they are already there and re-invoking cargo for them costs minutes for nothing.
if [ "${1:-test}" != "sync" ]; then
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
fi

cd "$PATCHED_DST" || exit 1

case "${1:-test}" in
  sync)
    # Refresh the staged tree and the web_ui placeholder without building anything.
    #
    # This is how an edit to the Windows copy of the patched cohort reaches the Linux tree once the
    # workspace's pins point at it. The builtin templates are deliberately not rebuilt: they live
    # under a target/ directory, which the rsync above excludes, so they survive untouched.
    exit 0
    ;;
  check|build)
    shift || true
    exec cargo check -p tari_ootle_wallet_sdk --all-targets "$@"
    ;;
  check-walletd)
    # Type-check walletd's tests without linking. This is where the MVP request/handler tests live,
    # and it is the only step that needs walletd's dependency graph (webrtc, wasm-opt's C++ build) —
    # so it is kept separate from the SDK-only path above, which stays cheap enough to re-run often.
    shift || true
    exec cargo check -p tari_ootle_walletd --lib --tests "$@"
    ;;
  test-walletd)
    shift || true
    exec cargo test -p tari_ootle_walletd --lib "$@"
    ;;
  test)
    shift || true
    exec cargo test -p tari_ootle_wallet_sdk -p tari_ootle_walletd "$@"
    ;;
  *)
    exec cargo "$@"
    ;;
esac
