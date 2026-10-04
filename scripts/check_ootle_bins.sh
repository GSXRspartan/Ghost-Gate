#!/usr/bin/env bash
# Report which Ootle binaries are already built, and in which target directories.
# Determines whether a live localnet (validator + indexer + walletd) is a build away or a
# multi-hour one on this box.
set -uo pipefail

for dir in /root/gg-ootle-target/debug /root/gg/_ootle-v042-build/target/debug /root/gg/ghost-gate/target/debug; do
  echo "=== $dir ==="
  if [ ! -d "$dir" ]; then
    echo "  (absent)"
    continue
  fi
  found=0
  for bin in tari_validator_node tari_indexer tari_walletd tari_swarm_daemon tari_ootle_validator_node; do
    if [ -x "$dir/$bin" ]; then
      echo "  present: $bin ($(du -h "$dir/$bin" | cut -f1))"
      found=1
    fi
  done
  [ "$found" = 0 ] && echo "  no ootle binaries"
done