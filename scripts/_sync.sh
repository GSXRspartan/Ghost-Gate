#!/usr/bin/env bash
# Sync the Windows checkout into the native-Linux tree.
#
# Invoked by scripts/wsl_run.sh, never directly. Kept as a file rather than piped
# through stdin: piping a script into `wsl.exe ... bash -s` loses content on Windows
# because the pipe is translated between a Win32 handle and the WSL pty.
#
# Invoked as: _sync.sh <windows_root> <linux_root>

set -euo pipefail

WINDOWS_ROOT="$1"
LINUX_ROOT="$2"

mkdir -p "$LINUX_ROOT/ghost-gate"
if [ -d "$WINDOWS_ROOT/_ootle-v042-build" ]; then
  mkdir -p "$LINUX_ROOT/_ootle-v042-build"
fi

for name in ghost-gate _ootle-v042-build; do
  src="$WINDOWS_ROOT/$name"
  dst="$LINUX_ROOT/$name"
  if [ ! -d "$src" ]; then
    echo "[sync] $name not present at $src, skipping" >&2
    continue
  fi
  # --delete keeps the Linux tree from accumulating files deleted on Windows, which
  # would otherwise leave stale tests running. Build outputs and VCS metadata are
  # excluded: target dirs are per-platform and .git is not needed to build.
  rsync -a --delete \
    --exclude 'target/' \
    --exclude '.git/' \
    "$src/" "$dst/"
  echo "[sync] $name -> $dst" >&2
done

echo "[sync] done" >&2