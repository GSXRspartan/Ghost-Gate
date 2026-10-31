#!/usr/bin/env bash
# Sync the Windows checkout into a native-Linux WSL tree, then run a cargo command there.
#
# WHY WSL
#   The engine depends on wasmer with the Cranelift backend, and
#   wasmer-compiler-cranelift 7.4 has a hard compile_error on Windows:
#       #[cfg(target_os = "windows")]
#       compile_error!("The Cranelift compiler backend is not supported on Windows...");
#   There is no way to run the engine's own template tests on a Windows host, so every
#   engine-backed suite (Gates 0-3) runs here. Pure-Rust suites that do not pull in the
#   engine also run on Windows, which is useful for a quick inner loop.
#
# WHY A COPY
#   /mnt/c is a drvfs mount; cargo's many small file operations on it are dramatically
#   slower than on the WSL ext4 volume. The copy also keeps multi-gigabyte target dirs
#   off the Windows filesystem.
#
# The Windows checkout at $WINDOWS_ROOT/ghost-gate remains the source of truth. This
# script is a build/run environment only; nothing here is committed back.
#
# USAGE
#   scripts/wsl_run.sh                     # cargo test (workspace)
#   scripts/wsl_run.sh test --release      # arguments are passed through to cargo
#   scripts/wsl_run.sh build -p ghost-gate-core
#   scripts/wsl_run.sh sh                  # interactive shell in the synced tree
#   scripts/wsl_run.sh sync                # sync only
#
# ENVIRONMENT
#   WINDOWS_ROOT   drvfs path to the workspace root (default: this repo's parent)
#   LINUX_ROOT     native path for the synced tree (default /root/gg)
#   LINUX_TARGET   native cargo target dir   (default /root/gg-target)
#   DISTRO         WSL distro                 (default Ubuntu-22.04)
#   CARGO_BUILD_JOBS  parallelism (default 2; the box has 3 cores and ~3 GiB RAM)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WINDOWS_ROOT="${WINDOWS_ROOT:-$(cd "$REPO_DIR/.." && pwd)}"
LINUX_ROOT="${LINUX_ROOT:-/root/gg}"
LINUX_TARGET="${LINUX_TARGET:-/root/gg-target}"
DISTRO="${DISTRO:-Ubuntu-22.04}"
JOBS="${CARGO_BUILD_JOBS:-2}"

# This script is normally launched through the `bash` shim, which does not put the Windows
# system directory on PATH, so bare `wsl` is not resolvable from inside it. Prefer the
# absolute launcher and fall back to whatever `wsl` is on PATH.
if command -v wsl.exe >/dev/null 2>&1; then
  WSL=wsl.exe
elif command -v wsl >/dev/null 2>&1; then
  WSL=wsl
else
  echo "error: cannot find wsl.exe or wsl on PATH" >&2
  exit 1
fi

log() { printf '[wsl_run] %s\n' "$*" >&2; }

# The sync script lives on disk in the repo and is executed inside WSL by path.
# Piping it through stdin instead loses content: Windows translates the pipe handle
# when handing it to the WSL pty, and the script arrives truncated.
SYNC_SCRIPT="$SCRIPT_DIR/_sync.sh"

if ! "$WSL" -d "$DISTRO" -- true >/dev/null 2>&1; then
  echo "error: WSL distro '$DISTRO' is not runnable" >&2
  echo "       engine-backed tests require WSL; see the header of this script" >&2
  exit 1
fi

# Both the script and the source root must be given to WSL in /mnt/... form. wslpath
# runs inside WSL and only understands paths that already exist there, so the Windows
# forms are converted directly; the script's own directory is derived from $0, which the
# `bash` shim hands over as a /mnt/... path.
to_wsl_path() {
  printf '%s' "$1" | sed -e 's|^[A-Za-z]:[\\/]|/mnt/|' -e 's|\\|/|g'
}

if [ "${1:-test}" != "sync" ]; then
  log "syncing from $WINDOWS_ROOT"
  SCRIPT_WSL="$(to_wsl_path "$SYNC_SCRIPT")"
  ROOT_WSL="$(to_wsl_path "$WINDOWS_ROOT")"
  "$WSL" -d "$DISTRO" -- bash "$SCRIPT_WSL" "$ROOT_WSL" "$LINUX_ROOT" || {
    echo "error: sync failed" >&2
    exit 1
  }
fi

case "${1:-test}" in
  sync)
    exit 0
    ;;
  sh|shell)
    exec "$WSL" -d "$DISTRO" --cd "$LINUX_ROOT/ghost-gate" -- env \
      CARGO_TARGET_DIR="$LINUX_TARGET" \
      bash
    ;;
  *)
    CMD="${1:-test}"
    shift || true
    log "cargo $CMD $* (target: $LINUX_TARGET, jobs: $JOBS)"
    exec "$WSL" -d "$DISTRO" --cd "$LINUX_ROOT/ghost-gate" -- env \
      CARGO_TARGET_DIR="$LINUX_TARGET" \
      CARGO_BUILD_JOBS="$JOBS" \
      RUST_BACKTRACE=1 \
      bash -lc "cargo $CMD $*"
    ;;
esac