#!/usr/bin/env bash
# Report which cargo target directories exist and how big they are.
#
# Two exist in practice: /root/gg-ootle-target (built for the patched wallet) and /root/gg-target
# (used by scripts/wsl_run.sh). Pointing a command at the wrong one recompiles the entire Ootle layer,
# so this is worth checking before a long build rather than after.
set -uo pipefail

for d in /root/gg-ootle-target /root/gg-target /root/gg/_ootle-v042-build/target; do
  if [ -d "$d" ]; then
    size=$(du -sh "$d" 2>/dev/null | cut -f1)
    n=$(ls -1 "$d/debug/deps" 2>/dev/null | wc -l)
    echo "$d  size=$size  deps=$n"
  else
    echo "$d  (absent)"
  fi
done