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

# Only this repository is synced. The cohort trees (`_ootle-v042-build`, `_ootle-v042-ghost-gate`) are
# large, are prepared once by scripts/prepare_reference.sh and scripts/patch_test.sh, and are kept in
# sync by those scripts. Re-copying them on every run would cost minutes of rsync off /mnt/c to move
# bytes that have not changed, and a half-finished copy would be worse than a stale one.
#
# To refresh the patched cohort after editing the Windows copy of it, run:
#   scripts/patch_test.sh sync
for name in ghost-gate; do
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