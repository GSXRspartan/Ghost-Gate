#!/usr/bin/env bash
# Report localnet build progress: whether cargo is still running, what it is doing, and whether any
# of the three binaries have landed.
set -uo pipefail

LOG="${LOG:-/root/localnet-build.log}"

echo "=== cargo processes ==="
pgrep -c cargo 2>/dev/null || echo 0

echo
echo "=== last compiled ==="
tail -3 "$LOG" 2>/dev/null || echo "(no log yet)"

echo
echo "=== errors so far ==="
grep -c "^error" "$LOG" 2>/dev/null || echo 0

echo
echo "=== binaries landed ==="
found=0
for bin in tari_validator_node tari_indexer tari_ootle_walletd; do
  if [ -x "/root/gg-ootle-target/debug/$bin" ]; then
    echo "  present: $bin ($(du -h "/root/gg-ootle-target/debug/$bin" | cut -f1))"
    found=1
  fi
done
[ "$found" = 0 ] && echo "  none yet"

echo
echo "=== free memory ==="
free -m | sed -n 2p