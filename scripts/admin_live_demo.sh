#!/usr/bin/env bash
# The live wiring demonstration, start to finish, on one machine:
#
#   1. start the admin plane on a FRESH data directory
#   2. register the first administrator with a real Ristretto key, using the bootstrap token
#   3. create two applications: a production one (3 tiers) and a test deployment (10 tTARI lane)
#   4. add the gates, then wire the tiers (two steps: a grant may not name a gate that does not
#      exist yet, and the server refuses exactly that)
#   5. publish every gate — publishing is what freezes the version the bridge serves
#   6. start the bridge with NO GG_BRIDGE_GATES at all, only GG_BINDINGS_PATH
#   7. check: the bridge serves the admin-configured thresholds, the test lane does not bind, and a
#      forged access token is refused
#   8. add a gate live and watch the bridge pick it up with no restart
#
# Nothing here needs a wallet daemon, a node or a network: it is the control plane, exercised for
# real. Every step prints what it asserted.
#
# Usage: scripts/admin_live_demo.sh [work_dir]      (default /tmp/gg-admin-live-demo)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${1:-/tmp/gg-admin-live-demo}"
TARGET_DIR="${GG_TARGET_DIR:-${HOME}/gg-ootle-target}"
ADMIN_BIND="${GG_ADMIN_BIND:-127.0.0.1:7812}"
BRIDGE_BIND="${GG_BRIDGE_BIND:-127.0.0.1:7802}"
ORIGIN="http://${ADMIN_BIND}"
GENESIS="${GG_GENESIS_HASH:-00f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0}"
API="$ORIGIN/admin/api"
ADMIN_BIN="$TARGET_DIR/debug/ghost-gate-admin"
BRIDGE_BIN="$TARGET_DIR/debug/ghost-gate-bridge"
SIGN_BIN="$TARGET_DIR/debug/examples/wallet_sign"
COOKIE_FILE="$WORK/cookie.txt"
CSRF_FILE="$WORK/csrf.txt"
SECRET_FILE="$WORK/admin-secret.hex"

say() { printf '\n=== %s ===\n' "$1"; }
die() { printf 'FAILED: %s\n' "$1" >&2; exit 1; }
expect() { # expect <label> <actual> <wanted>
  if [ "$2" = "$3" ]; then printf '  ok   %-52s %s\n' "$1" "$2"; else printf '  FAIL %-52s got %s, wanted %s\n' "$1" "$2" "$3"; exit 1; fi
}
expect_contains() { # expect_contains <label> <haystack> <needle>
  case "$2" in
    *"$3"*) printf '  ok   %-52s %s\n' "$1" "$3" ;;
    *) printf '  FAIL %-52s %s does not contain %s\n' "$1" "$2" "$3"; exit 1 ;;
  esac
}
cleanup() {
  [ -n "${ADMIN_PID:-}" ] && kill "$ADMIN_PID" 2>/dev/null || true
  [ -n "${BRIDGE_PID:-}" ] && kill "$BRIDGE_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT

for bin in "$ADMIN_BIN" "$BRIDGE_BIN" "$SIGN_BIN"; do
  [ -x "$bin" ] || die "missing $bin — build first: cargo build -p ghost-gate-admin -p ghost-gate-walletd --bin ghost-gate-bridge --example wallet_sign"
done

rm -rf "$WORK"
mkdir -p "$WORK"

jq_field() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get(sys.argv[1],""))' "$1"; }

api() { # api <method> <path> [body]  — authenticated, CSRF'd when mutating
  local method="$1" path="$2" body="${3:-}"
  local args=(-s -m 10 -X "$method" "$ORIGIN$path" -H "Origin: $ORIGIN" -H "Cookie: $(cat "$COOKIE_FILE")")
  if [ -n "$body" ]; then
    args+=(-H "Content-Type: application/json" -H "X-GG-CSRF: $(cat "$CSRF_FILE")" -d "$body")
  fi
  curl "${args[@]}"
}

sign_and_post() { # sign_and_post <path> <json-with-__CH__> [stepup]
  local path="$1" template="$2" stepup="${3:-false}"
  local ch pk sig body
  ch=$(curl -s -m 10 -X POST "$API/auth/challenge" -H "Origin: $ORIGIN" \
        -d '{"kind":"login","method":"wallet"}' | jq_field challenge)
  [ -n "$ch" ] || die "no challenge from the server"
  sig=$("$SIGN_BIN" "$(cat "$SECRET_FILE")" "$ch")
  pk=$(printf '%s\n' "$sig" | sed -n 's/^publicKey=//p')
  local nonce sign
  nonce=$(printf '%s\n' "$sig" | sed -n 's/^publicNonce=//p')
  sign=$(printf '%s\n' "$sig" | sed -n 's/^signature=//p')
  body=$(printf '%s' "$template" | sed -e "s|__CH__|$ch|" -e "s|__PK__|$pk|" -e "s|__NONCE__|$nonce|" -e "s|__SIG__|$sign|" -e "s|__STEPUP__|$stepup|")
  curl -s -m 10 -X POST "$ORIGIN$path" -H "Origin: $ORIGIN" -H "Cookie: $(cat "$COOKIE_FILE" 2>/dev/null || true)" -d "$body"
}

gate_body() { # gate_body <id> <thresholdRaw> <grantsJson> <testLane>
  cat <<JSON
{"applicationId":"meme-coin","gate":{"gateId":"$1","name":"$1","resourceAddress":"resource_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","symbol":"GHOST","divisibility":6,"thresholdRaw":"$2","proofMode":"consensus","challengeDomain":"meme.localhost","sessionTtlOverrideSecs":null,"grants":$3,"enabled":true,"testLane":$4,"componentAddress":"component_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
JSON
}

say "1. admin plane on a fresh directory"
GG_ADMIN_DATA="$WORK/data" GG_ADMIN_BIND="$ADMIN_BIND" GG_GENESIS_HASH="$GENESIS" \
  "$ADMIN_BIN" > "$WORK/admin.log" 2>&1 &
ADMIN_PID=$!
for _ in $(seq 1 50); do
  curl -sf -m 2 "$API/bootstrap" >/dev/null 2>&1 && break
  sleep 0.2
done
TOKEN=$(cat "$WORK/data/bootstrap.token" 2>/dev/null || true)
[ -n "$TOKEN" ] || die "no bootstrap token on disk (see $WORK/admin.log)"
printf '  admin pid %s, data %s\n  bootstrap token %s…\n' "$ADMIN_PID" "$WORK/data" "${TOKEN:0:12}"

say "2. first administrator registers with a real wallet key"
"$SIGN_BIN" --generate | sed -n 's/^secret_key=//p' > "$SECRET_FILE"
ch=$(curl -s -m 10 -X POST "$API/auth/challenge" -H "Origin: $ORIGIN" -d '{"kind":"register","method":"wallet"}' | jq_field challenge)
sig=$("$SIGN_BIN" "$(cat "$SECRET_FILE")" "$ch")
pk=$(printf '%s\n' "$sig" | sed -n 's/^publicKey=//p'); nonce=$(printf '%s\n' "$sig" | sed -n 's/^publicNonce=//p'); s=$(printf '%s\n' "$sig" | sed -n 's/^signature=//p')
reg=$(curl -s -m 10 -i -X POST "$API/auth/register" -H "Origin: $ORIGIN" \
  -d "$(python3 -c 'import json,sys; print(json.dumps({"method":"wallet","challenge":sys.argv[1],"publicKey":sys.argv[2],"publicNonce":sys.argv[3],"signature":sys.argv[4],"label":"operator","bootstrapToken":sys.argv[5]}))' "$ch" "$pk" "$nonce" "$s" "$TOKEN")")
CRED=$(printf '%s' "$reg" | tail -1 | jq_field credentialId)
[ -n "$CRED" ] || die "registration failed: $(printf '%s' "$reg" | tail -1)"
printf '%s' "$reg" | grep -i '^set-cookie:' | head -1 | sed 's/^[Ss]et-[Cc]ookie: //' | cut -d';' -f1 > "$COOKIE_FILE"
printf '%s' "$reg" | tail -1 | jq_field csrf > "$CSRF_FILE"
# The credential id IS the public key, so a fresh key gives a fresh id every run.
case "$CRED" in wallet:*) printf '  ok   %-52s %s…\n' "credential id is the public key" "${CRED:0:16}";; *) die "unexpected credential id $CRED";; esac

say "2b. a stranger cannot register or log in after the first credential"
expect "second registration" "$(curl -s -m 10 -o /dev/null -w '%{http_code}' -X POST "$API/auth/register" -H "Origin: $ORIGIN" -d '{"method":"wallet","challenge":"x","publicKey":"y","publicNonce":"z","signature":"s","label":"intruder","bootstrapToken":"'"$TOKEN"'"}')" "403"
expect "login naming an unknown challenge" "$(curl -s -m 10 -o /dev/null -w '%{http_code}' -X POST "$API/auth/login" -H "Origin: $ORIGIN" -d '{"method":"wallet","challenge":"x","publicKey":"y","publicNonce":"z","signature":"s"}')" "400"
# A REAL signature from a key that is not registered: refused as a policy decision, not a parse error.
stranger_key=$("$SIGN_BIN" --generate | sed -n 's/^secret_key=//p')
ch2=$(curl -s -m 10 -X POST "$API/auth/challenge" -H "Origin: $ORIGIN" -d '{"kind":"login","method":"wallet"}' | jq_field challenge)
sig2=$("$SIGN_BIN" "$stranger_key" "$ch2")
expect_contains "login from an unregistered wallet" "$(curl -s -m 10 -X POST "$API/auth/login" -H "Origin: $ORIGIN" \
  -d "$(python3 -c 'import json,sys; print(json.dumps({"method":"wallet","challenge":sys.argv[1],"publicKey":sys.argv[2],"publicNonce":sys.argv[3],"signature":sys.argv[4]}))' "$ch2" \
     "$(printf '%s\n' "$sig2" | sed -n 's/^publicKey=//p')" "$(printf '%s\n' "$sig2" | sed -n 's/^publicNonce=//p')" "$(printf '%s\n' "$sig2" | sed -n 's/^signature=//p')")" \
  | jq_field error)" "that wallet is not a registered administrator"
# And a replayed login challenge is single-use.
expect "replaying a login challenge" "$(curl -s -m 10 -o /dev/null -w '%{http_code}' -X POST "$API/auth/login" -H "Origin: $ORIGIN" \
  -d "$(python3 -c 'import json,sys; print(json.dumps({"method":"wallet","challenge":sys.argv[1],"publicKey":sys.argv[2],"publicNonce":sys.argv[3],"signature":sys.argv[4]}))' "$ch2" \
     "$(printf '%s\n' "$sig2" | sed -n 's/^publicKey=//p')" "$(printf '%s\n' "$sig2" | sed -n 's/^publicNonce=//p')" "$(printf '%s\n' "$sig2" | sed -n 's/^signature=//p')")")" "400"
expect "cross-origin ceremony" "$(curl -s -m 10 -o /dev/null -w '%{http_code}' -X POST "$API/auth/challenge" -H 'Origin: https://evil.example' -d '{"kind":"login","method":"wallet"}')" "403"

say "3. two applications: production (3 tiers) and a test deployment (10 tTARI)"
expect "create meme-coin" "$(api POST /admin/api/app/create '{"applicationId":"meme-coin","displayName":"Meme Coin","topology":"hierarchical","defaultSessionTtl":604800,"production":true}' | jq_field created)" "meme-coin"
expect "create meme-coin-test" "$(api POST /admin/api/app/create '{"applicationId":"meme-coin-test","displayName":"Meme Coin (test)","topology":"independent","defaultSessionTtl":3600,"production":false}' | jq_field created)" "meme-coin-test"
expect_contains "unknown cohort refused" "$(api POST /admin/api/app/create '{"applicationId":"nope","displayName":"Nope","topology":"independent","defaultSessionTtl":3600,"production":true,"network":"atlantis","genesisHash":"00"}' | jq_field error)" 'is not a network name or a hex byte' 

say "4. gates first, tiers second (a grant may not name a gate that does not exist yet)"
for g in "bronze 100000000000" "silver 500000000000" "gold 1000000000000"; do
  set -- $g
  expect "add gate $1" "$(api POST /admin/api/gate/set "$(gate_body "$1" "$2" '[]' false)" | jq_field set)" "True"
done
expect "wire silver -> bronze" "$(api POST /admin/api/gate/set "$(gate_body silver 500000000000 '["bronze"]' false)" | jq_field set)" "True"
expect "wire gold -> silver,bronze" "$(api POST /admin/api/gate/set "$(gate_body gold 1000000000000 '["silver","bronze"]' false)" | jq_field set)" "True"
expect_contains "a grant to a nonexistent gate is refused" "$(api POST /admin/api/gate/set "$(gate_body bronze 100000000000 '["ghost"]' false)" | jq_field error)" 'grants "ghost", which is not a gate in this application'
conv=$(api POST /admin/api/convert '{"amount":"10","divisibility":6}')
expect "exact conversion: 10 at divisibility 6" "$(printf '%s' "$conv" | jq_field raw)" "10000000"
expect "the dashboard's JSON body is understood" "$(printf '%s' "$conv" | jq_field exact)" "True"
expect_contains "sub-unit amount refused, never rounded" "$(api POST /admin/api/convert '{"amount":"0.0000001","divisibility":6}' | jq_field error)" "cannot be represented exactly"
test_body="{\"applicationId\":\"meme-coin-test\",\"gate\":{\"gateId\":\"local-test\",\"name\":\"Local test gate\",\"resourceAddress\":\"resource_testtttttttttttttttttttttttttttttttttttttttttttttttttttttttttt\",\"symbol\":\"tTARI\",\"divisibility\":6,\"thresholdRaw\":\"10000000\",\"proofMode\":\"consensus\",\"challengeDomain\":\"test.localhost\",\"sessionTtlOverrideSecs\":null,\"grants\":[],\"enabled\":true,\"testLane\":true,\"componentAddress\":\"component_tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt\"}}"
expect "add the 10 tTARI test-lane gate" "$(api POST /admin/api/gate/set "$test_body" | jq_field set)" "True"

say "5. publish every gate (publishing freezes the version the bridge serves)"
for g in bronze silver gold; do
  expect "publish $g" "$(api POST /admin/api/policy/publish "{\"applicationId\":\"meme-coin\",\"gateId\":\"$g\",\"reason\":\"live demo\"}" | jq_field published)" "$g"
done
expect "publish local-test" "$(api POST /admin/api/policy/publish '{"applicationId":"meme-coin-test","gateId":"local-test","reason":"test lane"}' | jq_field published)" "local-test"
# The snapshot carries every published gate, including the test lane — the BRIDGE is what refuses to
# bind a test lane. Asserting the split here is what proves the separation is enforced at the right
# layer rather than by hiding the gate from the registry.
bound=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(len(d["gates"]))' "$WORK/data/bindings.json")
expect "bindings carry all 4 published gates" "$bound" "4"
expect "one of them is the test lane" "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(sum(1 for g in d["gates"] if g["test_lane"]))' "$WORK/data/bindings.json")" "1"
expect "bindings carry the cohort" "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(hex(d["gates"][0]["network"]))' "$WORK/data/bindings.json")" "0x10"
expect "bindings carry the ledger identity" "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["gates"][0]["genesis_hash"][:8])' "$WORK/data/bindings.json")" "${GENESIS:0:8}"

say "6. bridge with NO GG_BRIDGE_GATES — the admin plane is the only authority"
GG_BRIDGE_BIND="$BRIDGE_BIND" GG_BRIDGE_ORIGINS="http://$BRIDGE_BIND" GG_BINDINGS_PATH="$WORK/data" \
  env -u GG_BRIDGE_GATES "$BRIDGE_BIN" > "$WORK/bridge.log" 2>&1 &
BRIDGE_PID=$!
for _ in $(seq 1 50); do curl -sf -m 2 "http://$BRIDGE_BIND/gate/gold" >/dev/null 2>&1 && break; sleep 0.2; done
grep -q "access plane: registry-backed" "$WORK/bridge.log" || die "the bridge did not come up registry-backed (see $WORK/bridge.log)"
sed -n '1,8p' "$WORK/bridge.log" | sed 's/^/  | /'
gold=$(curl -s -m 5 "http://$BRIDGE_BIND/gate/gold")
expect "gold threshold comes from the registry" "$(printf '%s' "$gold" | jq_field threshold)" "1000000000000"
expect "gold symbol comes from the registry" "$(printf '%s' "$gold" | jq_field symbol)" "GHOST"
expect "gold resource comes from the registry" "$(printf '%s' "$gold" | jq_field resource_address)" "resource_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
expect "the test lane never binds" "$(curl -s -m 5 "http://$BRIDGE_BIND/gate/local-test" | jq_field error)" "GG: no such gate"

say "7. a forged access token is refused; so is a cross-origin visitor"
expect "forged token" "$(curl -s -m 5 "http://$BRIDGE_BIND/access/check?gate=gold&token=$(python3 -c 'print("a"*64)')" | jq_field authorized)" "False"
# No token at all is a malformed request (400), not a silent "false": the distinction matters when
# an integrator debugs why their check call is not reaching the decision.
expect "missing token" "$(curl -s -m 5 "http://$BRIDGE_BIND/access/check?gate=gold" | jq_field error)" "GG: access checks need token and gate"
# A well-formed call with an unknown token is a decision, and the decision is no.
expect "unknown token" "$(curl -s -m 5 "http://$BRIDGE_BIND/access/check?gate=gold&token=$(python3 -c 'print("b"*64)')" | jq_field authorized)" "False"
if grep -q 'origin' "$WORK/bridge.log"; then :; fi
expect "a hostile origin cannot read the gate" "$(curl -s -m 5 -o /dev/null -w '%{http_code}' -H 'Origin: https://evil.example' "http://$BRIDGE_BIND/gate/gold")" "403"

say "8. add a gate live — the bridge picks it up with no restart"
expect "step up" "$(sign_and_post /admin/api/auth/login '{"method":"wallet","challenge":"__CH__","publicKey":"__PK__","publicNonce":"__NONCE__","signature":"__SIG__","stepup":__STEPUP__}' true | jq_field stepup)" "True"
expect "add platinum" "$(api POST /admin/api/gate/set "$(gate_body platinum 5000000000000 '["gold","silver","bronze"]' false)" | jq_field set)" "True"
expect "publish platinum" "$(api POST /admin/api/policy/publish '{"applicationId":"meme-coin","gateId":"platinum","reason":"fourth gate, live"}' | jq_field published)" "platinum"
sleep 1
expect "the bridge now serves platinum" "$(curl -s -m 5 "http://$BRIDGE_BIND/gate/platinum" | jq_field threshold)" "5000000000000"

say "done — every line above was asserted, not described"
printf '  admin  %s   bridge http://%s\n  data   %s\n' "$ORIGIN/admin" "$BRIDGE_BIND" "$WORK/data"
