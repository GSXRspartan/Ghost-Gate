#!/usr/bin/env bash
# Report the WSL layout the Ghost Gate workspace depends on.
#
# The workspace pins the cohort at ../_ootle-v042-build, so the sibling directory names matter. This
# also checks whether the WSL copy of the repo is current, because a stale copy silently tests
# yesterday's code.
set -uo pipefail

echo "=== /root/gg ==="
ls -1 /root/gg 2>/dev/null

echo
echo "=== pinned cohort dir ==="
if [ -d /root/gg/_ootle-v042-build ]; then
  echo "present: /root/gg/_ootle-v042-build"
  ls -1 /root/gg/_ootle-v042-build/crates | head -5
else
  echo "ABSENT: /root/gg/_ootle-v042-build"
fi

echo
echo "=== staged patched tree ==="
if [ -d /root/gg/_ootle-v042-ghost-gate ]; then
  echo "present: /root/gg/_ootle-v042-ghost-gate"
  ls -1 /root/gg/_ootle-v042-ghost-gate/applications/tari_walletd/web_ui/dist 2>/dev/null | head -3
  echo "mvp field present in SDK params: $(grep -c minimum_value_promise \
    /root/gg/_ootle-v042-ghost-gate/crates/wallet/sdk/src/apis/stealth_transfer/params.rs)"
  echo "mvp integration test present: $(test -f \
    /root/gg/_ootle-v042-ghost-gate/applications/tari_walletd/src/handlers/accounts/create_stealth_transfer_statement_handler_tests/mvp_integration_tests.rs \
    && echo yes || echo no)"
else
  echo "ABSENT: /root/gg/_ootle-v042-ghost-gate"
fi

echo
echo "=== ghost-gate repo copy in WSL ==="
if [ -d /root/gg/ghost-gate ]; then
  echo "present: /root/gg/ghost-gate"
  echo "scripts: $(ls -1 /root/gg/ghost-gate/scripts 2>/dev/null | wc -l) files"
  echo "patch_walletd.sh present: $(test -f /root/gg/ghost-gate/scripts/patch_walletd.sh && echo yes || echo no)"
  echo "wallet_mvp_patch.ps1 present: $(test -f /root/gg/ghost-gate/scripts/wallet_mvp_patch.ps1 && echo yes || echo no)"
else
  echo "ABSENT: /root/gg/ghost-gate"
fi