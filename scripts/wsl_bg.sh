#!/usr/bin/env bash
# Launch a Ghost Gate script or cargo command inside WSL, detached, logging to /root.
#
# The Windows shell tool kills a foreground WSL invocation when its own timeout expires, which
# kills in-flight cargo compiles. Launching detached with setsid means a long build survives and can
# be polled with scripts/wsl_status.sh.
#
# Usage:
#   scripts/wsl_bg.sh builtins                 # pre-build the builtin WASM templates
#   scripts/wsl_bg.sh test -p ghost-gate-core  # any cargo args

set -uo pipefail

export PATH="/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}"
export RUST_BACKTRACE=1

LINUX_ROOT="${LINUX_ROOT:-/root/gg}"
LOG="${LOG:-/root/gg-bg.log}"

case "${1:-}" in
  builtins)
    shift || true
    : > "$LOG"
    setsid bash "$LINUX_ROOT/ghost-gate/scripts/prepare_builtin_templates.sh" \
      "$LINUX_ROOT/_ootle-v042-build" </dev/null >> "$LOG" 2>&1 &
    disown
    echo "launched: builtin template prebuild -> $LOG"
    ;;
  *)
    : > "$LOG"
    cd "$LINUX_ROOT/ghost-gate" || exit 1
    setsid env CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/root/gg-target}" cargo "$@" </dev/null >> "$LOG" 2>&1 &
    disown
    echo "launched: cargo $* -> $LOG"
    ;;
esac
