#!/usr/bin/env bash
# Watches for the atomic-swap session's shared localnet to come up, and prints the exact wiring
# for Ghost Gate when it does.
#
# Per the operator's decision: reuse the shared Minotari L1 and the Ootle validator/indexer from
# that network; Ghost Gate runs its OWN MVP-patched walletd (built: /home/pdark/gg-ootle-target/
# debug/tari_ootle_walletd) with an independent wallet DB against it. Never modify, reset or stop
# that network; never start a competing L1.
#
# Usage:
#   scripts/await_localnet.sh          # poll until services appear, then print the wiring
#   scripts/await_localnet.sh --once   # check once and report

set -uo pipefail

SWARM_DATA="/mnt/d/Codex/purrivacy-localnet-v042/network-data"
SWARM_WEB="8080"
SCAN_FROM=12000
SCAN_TO=12600
ONCE="${1:-}"

say() { printf '%s\n' "$*"; }

swarm_alive() { ss -ltn 2>/dev/null | grep -q ":${SWARM_WEB} "; }

services_up() {
  # Any validator/indexer/walletd JSON-RPC port listening in the swarm's range.
  local found
  found=$(ss -ltn 2>/dev/null | awk -v from="$SCAN_FROM" -v to="$SCAN_TO" '
    $4 ~ /:[0-9]+$/ {
      split($4, a, ":"); port = a[length(a)];
      if (port+0 >= from && port+0 < to) print port;
    }' | sort -un)
  if [ -n "$found" ]; then
    say "listening ports in the swarm range: $(echo "$found" | tr '\n' ' ')"
    return 0
  fi
  return 1
}

if [ "$ONCE" = "--once" ]; then
  if swarm_alive && services_up; then
    say "the shared localnet appears UP; see the wiring steps below"
  else
    say "the shared localnet is not up yet (swarm webserver: $(swarm_alive && echo alive || echo down)); builds in progress"
  fi
  exit 0
fi

say "waiting for the shared localnet (swarm at 127.0.0.1:${SWARM_WEB}, instances in ${SCAN_FROM}-${SCAN_TO})…"
while true; do
  if services_up; then
    say ""
    say "== the shared localnet is up =="
    say "Next steps (operator):"
    say "  1. Identify the instances and their JSON-RPC ports from the swarm's web UI:"
    say "       http://127.0.0.1:${SWARM_WEB}"
    say "     The validator's jrpc port doubles as its web UI port; the indexer has its own."
    say "  2. Start Ghost Gate's OWN MVP-patched walletd (independent wallet DB, own data dir):"
    say "       RUSTUP_TOOLCHAIN=1.97.1 \\"
    say "       /home/pdark/gg-ootle-target/debug/tari_ootle_walletd \\"
    say "         --network localnet \\"
    say "         --listen-on 127.0.0.1:18130 \\"
    say "         --indexer-api-url http://127.0.0.1:<indexer_port> \\"
    say "         --base-path /home/pdark/gg-wallet-ghostgate \\"
    say "         --authentication none"
    say "     (Flags verified against the built binary's --help; --authentication none is for the"
    say "      local fixture run only — use an API key once the bridge authenticates.)"
    say "  3. Point the bridge at it and restart:"
    say "       GG_WALLETD_ENDPOINT='http://127.0.0.1:18130/json_rpc' scripts/start_vault.sh"
    say "  4. Deploy the game's gates through the new walletd (templates.publish_template +"
    say "     faucet.new + gate.new x3) — a script will be provided; see docs/CONTEST_README.md."
    say "  5. Fund the wallet (create_free_test_coins or the faucet template), then play."
    exit 0
  fi
  sleep 30
done
