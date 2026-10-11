#!/usr/bin/env bash
# Ghost Gate — first real manual proof, end to end.
#
# Run this ONCE the shared localnet is healthy (scripts/await_localnet.sh says so). It is the exact
# sequence for the first live consensus proof through Ghost Gate's own MVP-patched wallet daemon.
#
# It NEVER touches the shared localnet: it only starts OUR walletd against it, deploys OUR templates
# and gates, and restarts OUR bridge. The atomic-swap session owns the network itself.
#
# Usage:  scripts/first_real_proof.sh            # full sequence
#         GG_AUTHENTICATION=none scripts/first_real_proof.sh   # loopback fixture wallet, no API key
#
# Nothing here spends funds or signs anything on its own: publishing templates and deploying gates
# cost transaction fees from the deploying wallet, and the proof itself is triggered by the operator
# clicking "Break the seal" in the browser.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

BIN=/home/pdark/gg-ootle-target/debug
WALLETD_PORT="${GG_WALLETD_PORT:-18130}"
WALLETD_URL="http://127.0.0.1:${WALLETD_PORT}"
WALLETD_BASE="${GG_WALLETD_BASE:-/home/pdark/gg-wallet-ghostgate}"
BRIDGE_PORT="${GG_BRIDGE_PORT:-7799}"
LOGDIR=/home/pdark/gg-logs
mkdir -p "$LOGDIR"

say() { printf '\n== %s ==\n' "$1"; }

# ---------------------------------------------------------------- 0. preflight
say "0. preflight"
for b in ghost-gate-bridge deploy_vault tari_ootle_walletd; do
  [ -x "$BIN/$b" ] || { echo "missing $BIN/$b — the binaries must already be built (this script never builds)"; exit 1; }
done
echo "binaries present (not rebuilding)"
if ! curl -s -m 4 "http://127.0.0.1:${BRIDGE_PORT}/health" >/dev/null; then
  echo "note: no bridge on ${BRIDGE_PORT} yet; it will be (re)started at the end"
fi
echo "waiting for the shared localnet..."
bash scripts/await_localnet.sh || { echo "localnet still not up; rerun when it is"; exit 2; }

# ---------------------------------------------------------------- 1. indexer URL
say "1. discover the localnet's indexer"
INDEXER="${GG_INDEXER_ENDPOINT:-}"
if [ -z "$INDEXER" ]; then
  for p in $(ss -ltn 2>/dev/null | awk 'NR>1{print $4}' | sed 's/.*://' | sort -un); do
    if curl -s -m 2 "http://127.0.0.1:${p}/api/v1/health" 2>/dev/null | grep -qi "last_seen\|known_peers\|epoch"; then
      INDEXER="http://127.0.0.1:${p}"; break
    fi
    if curl -s -m 2 "http://127.0.0.1:${p}/api/v1/indexer/status" 2>/dev/null | grep -qi "epoch\|tip"; then
      INDEXER="http://127.0.0.1:${p}"; break
    fi
  done
fi
[ -n "$INDEXER" ] || { echo "could not auto-detect the indexer; rerun with GG_INDEXER_ENDPOINT=http://127.0.0.1:<port>"; exit 3; }
echo "indexer: $INDEXER"

# ---------------------------------------------------------------- 2. our patched walletd
say "2. start Ghost Gate's MVP-patched walletd"
if ss -ltn 2>/dev/null | grep -q ":${WALLETD_PORT} "; then
  echo "  already listening on ${WALLETD_PORT}; leaving it alone"
else
  AUTH_ARGS=()
  [ "${GG_AUTHENTICATION:-}" = "none" ] && AUTH_ARGS+=(--authentication none)
  setsid nohup "$BIN/tari_ootle_walletd" \
    --network localnet \
    --listen-on "127.0.0.1:${WALLETD_PORT}" \
    --indexer-api-url "$INDEXER" \
    --base-path "$WALLETD_BASE" \
    "${AUTH_ARGS[@]}" \
    > "$LOGDIR/gg-walletd.log" 2>&1 < /dev/null &
  sleep 6
fi
if ! curl -s -m 4 "${WALLETD_URL}/health" >/dev/null; then
  echo "walletd is not answering on ${WALLETD_URL}; see $LOGDIR/gg-walletd.log"; tail -20 "$LOGDIR/gg-walletd.log" || true; exit 4
fi
echo "walletd: ${WALLETD_URL}  (base-path ${WALLETD_BASE}, MVP-patched)"

# ---------------------------------------------------------------- 3. deploy
say "3. publish templates, mint the resource, deploy the three gates"
GG_WALLETD_ENDPOINT="$WALLETD_URL" \
GG_WALLETD_TOKEN="${GG_WALLETD_TOKEN:-}" \
  "$BIN/deploy_vault" | tee "$LOGDIR/deploy_vault.out"

# deploy_vault prints:   GG_BRIDGE_GATES='crypt=...,vault=...' \
# so take exactly what is between the single quotes (the trailing backslash is shell line-joining).
GATES="$(sed -n "s/.*GG_BRIDGE_GATES='\([^']*\)'.*/\1/p" "$LOGDIR/deploy_vault.out" | head -1)"
[ -n "$GATES" ] || { echo "deploy_vault did not print a bridge config line; see $LOGDIR/deploy_vault.out"; exit 5; }
echo "captured gate config (${#GATES} chars)"
case "$GATES" in
  crypt=*) ;;
  *) echo "the captured gate config does not look right: $GATES"; exit 5 ;;
esac

# ---------------------------------------------------------------- 4. restart bridge
say "4. restart the bridge on the deployed gates"
export GG_BRIDGE_BIND="127.0.0.1:${BRIDGE_PORT}"
export GG_BRIDGE_ORIGINS="http://127.0.0.1:${BRIDGE_PORT}"
export GG_BRIDGE_GATES="$GATES"
export GG_WALLETD_ENDPOINT="$WALLETD_URL"
export GG_WALLETD_TOKEN="${GG_WALLETD_TOKEN:-}"
export GG_INDEXER_ENDPOINT="$INDEXER"

OLD_PID="$(ss -ltnp 2>/dev/null | grep ":${BRIDGE_PORT} " | sed 's/.*pid=\([0-9]*\).*/\1/' | head -1 || true)"
[ -n "$OLD_PID" ] && { echo "stopping old bridge pid $OLD_PID"; kill "$OLD_PID" 2>/dev/null || true; sleep 2; }

setsid nohup "$BIN/ghost-gate-bridge" > "$LOGDIR/vault-bridge.log" 2>&1 < /dev/null &
sleep 3
curl -s -m 4 "http://127.0.0.1:${BRIDGE_PORT}/health" || { echo "bridge did not come up"; tail -20 "$LOGDIR/vault-bridge.log"; exit 6; }
echo
grep -E "gate\(s\)|crypt:|vault:|abyss:|wallet" "$LOGDIR/vault-bridge.log" | head -8

# ---------------------------------------------------------------- 5. hand to the operator
say "5. your turn — the operator"
cat <<EOF

The network is wired. Nothing has been proven yet: the proof is YOUR click.

  1. Open  http://127.0.0.1:${BRIDGE_PORT}/game   (hard-refresh: Ctrl+Shift+R)
  2. Click  "Connect a wallet". Ghost Gate should report the walletd adapter and its consensus
     proof mode. If it says no usable wallet answered, tell me — the wiring is wrong, not you.
  3. In The Crypt, click  "Break the seal". Approve the proof in the wallet daemon.
  4. When consensus decides, the door opens and you can  "Enter".

Proof of record: this is the first end-to-end consensus proof through the MVP-patched walletd.
If a step fails, send me the bridge log (${LOGDIR}/vault-bridge.log) and the walletd log
(${LOGDIR}/gg-walletd.log) — both are verbatim evidence, nothing is summarised away.

Logs: ${LOGDIR}/{vault-bridge.log,gg-walletd.log,deploy_vault.out}
EOF