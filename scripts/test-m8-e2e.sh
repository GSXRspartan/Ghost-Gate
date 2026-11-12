#!/usr/bin/env bash
# Ghost Gate M8 — Process-level end-to-end admission test
#
# Runs three real compiled binaries as separate Linux processes against an HTTP Telegram fixture
# server. Never connects to the real Telegram API or any live network. No production credentials
# are used or required.
#
# Prerequisites (all built in WSL2):
#   cargo build -p ghost-gate-walletd --bin ghost-gate-bridge --bin gg-test-signer
#   cargo build -p ghost-gate-telegram
#
# Run from the repo root or the scripts/ directory:
#   bash scripts/test-m8-e2e.sh
#
# Tests:
#   T1 — happy path: valid keypair → proof accepted → approveChatJoinRequest called
#   T2 — wrong key: signature from a different keypair → proof rejected
#   T3 — replay: session already Redeemed → challenge refused
#   T4 — restart safety: bot restarted mid-lifecycle, session persists, claim succeeds

set -uo pipefail

# ── Paths ────────────────────────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# The workspace has a custom target-dir in .cargo/config.toml pointing to the Linux filesystem.
# Fall back to the conventional target/debug if the custom path is not present.
if [ -d "/home/darkp/gg-target/debug" ]; then
    BIN_DIR="/home/darkp/gg-target/debug"
elif [ -d "$REPO_ROOT/target/debug" ]; then
    BIN_DIR="$REPO_ROOT/target/debug"
else
    BIN_DIR="$REPO_ROOT/target/release"
fi

SIGNER="$BIN_DIR/gg-test-signer"
BRIDGE_BIN="$BIN_DIR/ghost-gate-bridge"
BOT_BIN="$BIN_DIR/ghost-gate-telegram"
TG_FIXTURE_PY="$SCRIPT_DIR/fixture-telegram-server.py"

for f in "$SIGNER" "$BRIDGE_BIN" "$BOT_BIN" "$TG_FIXTURE_PY"; do
    if [ ! -f "$f" ]; then
        echo "[ERROR] missing: $f"
        echo "        Build first: cargo build -p ghost-gate-walletd --bin ghost-gate-bridge --bin gg-test-signer && cargo build -p ghost-gate-telegram"
        exit 1
    fi
done

# ── Fixed test parameters ─────────────────────────────────────────────────────────────────────────
BRIDGE_PORT=7788
BOT_CLAIM_PORT=7808
FIXTURE_TG_PORT=7810
CHAT_ID=-1001234567890
GATE_ID="Crypt"
# 64-char policy hash (all 'ab' — a fixed test value that is never the real policy hash)
POLICY_HASH="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
NETWORK="0x26"
RESOURCE="resource_0101010101010101010101010101010101010101010101010101010101010101"
# UTXO address: resource_key (same 32 bytes) + fixed output hash from bot_admission unit tests
UTXO="utxo_0101010101010101010101010101010101010101010101010101010101010101_2c713522a4aaf79f2b219d869b5033d3d71d63c0537e5e0bbed2d717d8b2a67e"
THRESHOLD=10000000
# 32-byte HMAC key shared between bridge and bot (non-zero, test-only)
BOT_KEY="0102030405060708091011121314151617181920212223242526272829303132"

BRIDGE_BASE="http://127.0.0.1:$BRIDGE_PORT"
CLAIM_ORIGIN="$BRIDGE_BASE"  # GG_JOIN_BASE_URL — the allowed claim Origin

# ── Temp dirs ─────────────────────────────────────────────────────────────────────────────────────
TMPDIR="$(mktemp -d /tmp/gg-m8-XXXXXX)"
BOT_STORE_DIR="$TMPDIR/bot-store"
AUTH_DB_DIR="$TMPDIR/auth-db"
mkdir -p "$BOT_STORE_DIR" "$AUTH_DB_DIR"

# ── Process tracking ──────────────────────────────────────────────────────────────────────────────
BRIDGE_PID=""
BOT_PID=""
TG_PID=""

# ── Counters ──────────────────────────────────────────────────────────────────────────────────────
PASS=0
FAIL=0

# ── Helpers ───────────────────────────────────────────────────────────────────────────────────────
pass() { PASS=$((PASS+1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL+1)); echo "  [FAIL] $1"; }

cleanup() {
    echo ""
    echo "--- cleanup ---"
    [ -n "$BOT_PID" ]    && kill "$BOT_PID"    2>/dev/null && echo "  stopped bot    ($BOT_PID)"    || true
    [ -n "$BRIDGE_PID" ] && kill "$BRIDGE_PID" 2>/dev/null && echo "  stopped bridge ($BRIDGE_PID)" || true
    [ -n "$TG_PID" ]     && kill "$TG_PID"     2>/dev/null && echo "  stopped tg     ($TG_PID)"     || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

# Wait up to N seconds for a URL to respond with HTTP 200.
wait_http() {
    local url="$1" label="$2" max="${3:-15}"
    for i in $(seq 1 "$max"); do
        if curl -sf "$url" >/dev/null 2>&1; then
            echo "  $label ready (${i}s)"
            return 0
        fi
        sleep 1
    done
    echo "  $label did not become ready within ${max}s"
    return 1
}

# Wait up to N seconds for a TCP port to accept connections.
wait_port() {
    local port="$1" label="$2" max="${3:-15}"
    for i in $(seq 1 "$max"); do
        if bash -c "echo >/dev/tcp/127.0.0.1/$port" 2>/dev/null; then
            echo "  $label listening on port $port (${i}s)"
            return 0
        fi
        sleep 1
    done
    echo "  $label did not bind port $port within ${max}s"
    return 1
}

# GET fixture results, filtered to calls after the given index (0-based offset).
fixture_calls_from() {
    local offset="${1:-0}"
    curl -sf "http://127.0.0.1:$FIXTURE_TG_PORT/fixture/results" | \
        python3 -c "import json,sys; data=json.load(sys.stdin); print(json.dumps(data[$offset:]))"
}

# Extract bot_session from a sendMessage text. Reads JSON array of calls from stdin.
extract_session_id() {
    python3 -c "
import json, sys, urllib.parse
data = json.load(sys.stdin)
for call in data:
    if call.get('method') == 'sendMessage':
        text = call.get('params', {}).get('text', '')
        for token in text.split():
            if 'bot_session=' in token:
                q = urllib.parse.urlparse(token).query
                p = dict(urllib.parse.parse_qsl(q))
                if 'bot_session' in p:
                    print(p['bot_session'])
                    sys.exit(0)
sys.exit(1)
" 2>/dev/null
}

# Inject a Telegram /join command update. Args: update_id user_id.
inject_join() {
    local uid="$1" upd_id="$2"
    local body
    body=$(python3 -c "
import json, time
print(json.dumps({
    'update_id': $upd_id,
    'message': {
        'message_id': $upd_id, 'date': int(time.time()),
        'from': {'id': $uid, 'is_bot': False, 'first_name': 'TestUser', 'username': 'testuser'},
        'chat': {'id': $CHAT_ID, 'type': 'supergroup', 'title': 'Fixture Test Group'},
        'text': '/join',
        'entities': [{'offset': 0, 'length': 5, 'type': 'bot_command'}],
    }
}))
")
    curl -sf -X POST "http://127.0.0.1:$FIXTURE_TG_PORT/fixture/inject" \
        -H "Content-Type: application/json" -d "$body" >/dev/null
}

# Wait for a sendMessage to appear in fixture results after a given index. Returns session_id.
wait_for_session() {
    local offset="$1" label="$2"
    local sid=""
    for i in $(seq 1 15); do
        sleep 2
        sid=$(fixture_calls_from "$offset" | extract_session_id) && break || sid=""
    done
    if [ -z "$sid" ]; then
        fail "$label: bot did not send verify URL within 30s"
        fixture_calls_from "$offset" | python3 -c 'import json,sys; [print(c["method"]) for c in json.load(sys.stdin)]' || true
        echo ""
        return 1
    fi
    echo "  session_id: ${sid:0:12}…" >&2
    echo "$sid"
}

# Request a challenge for a session+substate. Outputs JSON.
get_challenge() {
    local session_id="$1"
    curl -sf -X POST "$BRIDGE_BASE/v1/bot/sessions/$session_id/challenge" \
        -H "Content-Type: application/json" \
        -d "{\"substate_id\": \"$UTXO\"}"
}

# Submit a proof. Args: session_id challenge_json secret_key_hex. Outputs JSON.
submit_proof() {
    local session_id="$1" challenge_json="$2" sk="$3"
    local challenge challenge_nonce
    challenge=$(echo "$challenge_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["challenge"])')
    challenge_nonce=$(echo "$challenge_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["challenge_nonce"])')

    local sig_json pk nonce sig
    sig_json=$("$SIGNER" sign "$NETWORK" "$RESOURCE" "$UTXO" "$challenge" "$sk")
    pk=$(echo "$sig_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["public_key"])')
    nonce=$(echo "$sig_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["public_nonce"])')
    sig=$(echo "$sig_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["signature"])')

    local body
    body=$(python3 -c "
import json
print(json.dumps({
    'gate_id': '$GATE_ID',
    'challenge_nonce': '$challenge_nonce',
    'session_commitment': '1111111111111111111111111111111111111111111111111111111111111111',
    'substate_id': '$UTXO',
    'public_key': '$pk',
    'public_nonce': '$nonce',
    'signature': '$sig',
}))
")
    curl -sf -X POST "$BRIDGE_BASE/v1/bot/sessions/$session_id/proof" \
        -H "Content-Type: application/json" -d "$body"
}

# POST the bot's claim endpoint. Args: session_id. Returns raw HTTP response body.
claim() {
    local session_id="$1"
    curl -s -X POST "http://127.0.0.1:$BOT_CLAIM_PORT/claim" \
        -H "Host: 127.0.0.1:$BOT_CLAIM_PORT" \
        -H "Origin: $CLAIM_ORIGIN" \
        -H "Content-Type: application/json" \
        -d "{\"bot_session_id\": \"$session_id\"}"
}

# Count fixture calls of a given method from an offset.
count_method() {
    local method="$1" offset="$2"
    fixture_calls_from "$offset" | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(sum(1 for c in data if c.get('method') == '$method'))
"
}

# ── Start infrastructure ───────────────────────────────────────────────────────────────────────────
echo "=== Ghost Gate M8 — End-to-End Admission Test ==="
echo ""

# Generate test keypair
echo "--- Step 0: generate test keypair ---"
KEYPAIR=$("$SIGNER" gen-keypair)
TEST_SK=$(echo "$KEYPAIR" | python3 -c 'import json,sys; print(json.load(sys.stdin)["secret_key"])')
TEST_PK=$(echo "$KEYPAIR" | python3 -c 'import json,sys; print(json.load(sys.stdin)["public_key"])')
echo "  public_key: ${TEST_PK:0:16}…"

GG_FIXTURE_UTXO="$UTXO:$TEST_PK:$THRESHOLD"

# Start fixture Telegram server
echo ""
echo "--- Starting fixture Telegram server on port $FIXTURE_TG_PORT ---"
python3 "$TG_FIXTURE_PY" "$FIXTURE_TG_PORT" "$CHAT_ID" \
    > "$TMPDIR/fixture-tg-stdout.log" \
    2> "$TMPDIR/fixture-tg-stderr.log" &
TG_PID=$!
wait_http "http://127.0.0.1:$FIXTURE_TG_PORT/fixture/results" "fixture-tg" 10 || {
    echo "  fixture-tg stderr:"; tail -5 "$TMPDIR/fixture-tg-stderr.log"; exit 1
}

# Start bridge
echo ""
echo "--- Starting bridge on $BRIDGE_BASE ---"
# GG_BRIDGE_GATES: credential-only gate (empty component address = no on-chain component)
BRIDGE_GATE="$GATE_ID=:$RESOURCE:$THRESHOLD:6:tTARI"
GG_BRIDGE_BIND="127.0.0.1:$BRIDGE_PORT" \
GG_BRIDGE_ORIGINS="$BRIDGE_BASE" \
GG_BRIDGE_RELYING_SITE="$BRIDGE_BASE" \
GG_BRIDGE_GATES="$BRIDGE_GATE" \
GG_TG_FIXTURE=1 \
GG_FIXTURE_UTXO="$GG_FIXTURE_UTXO" \
GG_BOT_KEY="$BOT_KEY" \
GG_BOT_AUTH_DB_DIR="$AUTH_DB_DIR" \
GG_BOT_GATE_ID="$GATE_ID" \
GG_BOT_POLICY_HASH="$POLICY_HASH" \
GG_BOT_NETWORK="$NETWORK" \
GG_BOT_RESOURCE="$RESOURCE" \
GG_BOT_THRESHOLD="$THRESHOLD" \
GG_BOT_CHAT_ID="$CHAT_ID" \
  "$BRIDGE_BIN" \
    > "$TMPDIR/bridge-stdout.log" \
    2> "$TMPDIR/bridge-stderr.log" &
BRIDGE_PID=$!
wait_http "$BRIDGE_BASE/health" "bridge" 20 || {
    echo "  bridge stderr:"; tail -20 "$TMPDIR/bridge-stderr.log"; exit 1
}

# Start bot (HTTP fixture mode)
echo ""
echo "--- Starting bot (HTTP fixture mode) ---"
GG_TG_FIXTURE=1 \
GG_TG_API_URL="http://127.0.0.1:$FIXTURE_TG_PORT" \
GG_TG_BOT_TOKEN="fixture_m8test" \
GG_TG_CHAT_ID="$CHAT_ID" \
GG_TG_FIXTURE_TEST_CHAT_ID="$CHAT_ID" \
GG_BOT_ESMERALDA_KEY="$BOT_KEY" \
GG_BOT_ESMERALDA_BRIDGE="$BRIDGE_BASE" \
GG_BOT_ESMERALDA_GATE_ID="$GATE_ID" \
GG_BOT_ESMERALDA_POLICY_HASH="$POLICY_HASH" \
GG_BOT_SESSION_STORE_DIR="$BOT_STORE_DIR" \
GG_JOIN_BASE_URL="$BRIDGE_BASE" \
GG_TG_CLAIM_PORT="$BOT_CLAIM_PORT" \
  "$BOT_BIN" \
    > "$TMPDIR/bot-stdout.log" \
    2> "$TMPDIR/bot-stderr.log" &
BOT_PID=$!
wait_port "$BOT_CLAIM_PORT" "bot-claim" 20 || {
    echo "  bot stderr:"; tail -20 "$TMPDIR/bot-stderr.log"; exit 1
}

# ── T1: Happy path ─────────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== T1: Happy path (valid keypair → approveChatJoinRequest) ==="

# Count how many fixture calls exist so far (to slice from after them)
CALL_OFFSET_T1=$(curl -sf "http://127.0.0.1:$FIXTURE_TG_PORT/fixture/results" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')

# Inject /join for user 55
inject_join 55 10001
echo "  injected /join for user 55 (update_id=10001)"

# Wait for the bot to send the verify URL
SESSION_ID_T1=$(wait_for_session "$CALL_OFFSET_T1" "T1") || { echo "  Skipping T1 remainder."; SESSION_ID_T1=""; }

if [ -n "$SESSION_ID_T1" ]; then
    # Get challenge
    CHALLENGE_JSON_T1=$(get_challenge "$SESSION_ID_T1")
    echo "  challenge: $(echo "$CHALLENGE_JSON_T1" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["challenge"][:20] + "…")')"

    # Submit valid proof
    PROOF_RESP_T1=$(submit_proof "$SESSION_ID_T1" "$CHALLENGE_JSON_T1" "$TEST_SK")
    VERIFIED_T1=$(echo "$PROOF_RESP_T1" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("verified", ""))' 2>/dev/null || echo "")

    if [ "$VERIFIED_T1" = "True" ] || [ "$VERIFIED_T1" = "true" ]; then
        echo "  proof accepted; triggering claim"
        CLAIM_RESP_T1=$(claim "$SESSION_ID_T1")
        CLAIM_STATE_T1=$(echo "$CLAIM_RESP_T1" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("state",""))' 2>/dev/null || echo "")
        echo "  claim response state: $CLAIM_STATE_T1"

        # Give the bot time to call approveChatJoinRequest
        sleep 4
        APPROVE_COUNT=$(count_method "approveChatJoinRequest" "$CALL_OFFSET_T1")
        if [ "$APPROVE_COUNT" -ge 1 ]; then
            pass "T1: approveChatJoinRequest called ($APPROVE_COUNT times)"
        else
            fail "T1: approveChatJoinRequest not called; claim state=$CLAIM_STATE_T1 proof=$PROOF_RESP_T1"
            echo "  bot stderr:"; tail -20 "$TMPDIR/bot-stderr.log"
        fi
    else
        fail "T1: proof rejected (expected verified=true); response: $PROOF_RESP_T1"
    fi
fi

# ── T2: Wrong key ──────────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== T2: Wrong key (attacker's signature rejected) ==="

# Generate an attacker keypair (different from TEST_SK/TEST_PK)
ATTACKER_KEYPAIR=$("$SIGNER" gen-keypair)
ATTACKER_SK=$(echo "$ATTACKER_KEYPAIR" | python3 -c 'import json,sys; print(json.load(sys.stdin)["secret_key"])')
echo "  attacker_pk: $(echo "$ATTACKER_KEYPAIR" | python3 -c 'import json,sys; print(json.load(sys.stdin)["public_key"][:16])')…"

CALL_OFFSET_T2=$(curl -sf "http://127.0.0.1:$FIXTURE_TG_PORT/fixture/results" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')
inject_join 56 10002
echo "  injected /join for user 56 (update_id=10002)"

SESSION_ID_T2=$(wait_for_session "$CALL_OFFSET_T2" "T2") || { echo "  Skipping T2 remainder."; SESSION_ID_T2=""; }

if [ -n "$SESSION_ID_T2" ]; then
    CHALLENGE_JSON_T2=$(get_challenge "$SESSION_ID_T2")

        # Build attacker's proof body using gg-test-signer; submit_proof uses -sf so we need -s here.
    ATCK_CHALLENGE=$(echo "$CHALLENGE_JSON_T2" | python3 -c 'import json,sys; print(json.load(sys.stdin)["challenge"])')
    ATCK_NONCE=$(echo "$CHALLENGE_JSON_T2" | python3 -c 'import json,sys; print(json.load(sys.stdin)["challenge_nonce"])')
    ATCK_SIG_JSON=$("$SIGNER" sign "$NETWORK" "$RESOURCE" "$UTXO" "$ATCK_CHALLENGE" "$ATTACKER_SK")
    ATCK_PK=$(echo "$ATCK_SIG_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["public_key"])')
    ATCK_SN=$(echo "$ATCK_SIG_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["public_nonce"])')
    ATCK_SS=$(echo "$ATCK_SIG_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["signature"])')
    ATCK_BODY=$(python3 -c "
import json
print(json.dumps({'gate_id':'$GATE_ID','challenge_nonce':'$ATCK_NONCE',
    'session_commitment':'1111111111111111111111111111111111111111111111111111111111111111',
    'substate_id':'$UTXO','public_key':'$ATCK_PK','public_nonce':'$ATCK_SN','signature':'$ATCK_SS'}))")
    HTTP_CODE_T2=$(curl -so /dev/null -w "%{http_code}" -X POST \
        "$BRIDGE_BASE/v1/bot/sessions/$SESSION_ID_T2/proof" \
        -H "Content-Type: application/json" -d "$ATCK_BODY" 2>/dev/null)

    if [ "$HTTP_CODE_T2" = "400" ] || [ "$HTTP_CODE_T2" = "403" ] || [ "$HTTP_CODE_T2" = "422" ]; then
        pass "T2: attacker's proof rejected (HTTP $HTTP_CODE_T2)"
    else
        ATCK_BODY_RESP=$(curl -s -X POST "$BRIDGE_BASE/v1/bot/sessions/$SESSION_ID_T2/proof" \
            -H "Content-Type: application/json" -d "$ATCK_BODY" 2>/dev/null)
        VERIFIED_T2=$(echo "$ATCK_BODY_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("verified",""))' 2>/dev/null || echo "")
        if [ "$VERIFIED_T2" != "True" ] && [ "$VERIFIED_T2" != "true" ]; then
            pass "T2: attacker's proof rejected (HTTP $HTTP_CODE_T2, verified=$VERIFIED_T2)"
        else
            fail "T2: attacker's proof accepted (HTTP $HTTP_CODE_T2); bridge must reject wrong-key proofs"
        fi
    fi
fi

# ── T3: Replay (session already Redeemed) ─────────────────────────────────────────────────────────
echo ""
echo "=== T3: Replay (session T1 is Redeemed — challenge must be refused) ==="
if [ -n "${SESSION_ID_T1:-}" ]; then
    HTTP_CODE_T3=$(curl -so /dev/null -w "%{http_code}" -X POST \
        "$BRIDGE_BASE/v1/bot/sessions/$SESSION_ID_T1/challenge" \
        -H "Content-Type: application/json" \
        -d "{\"substate_id\": \"$UTXO\"}" 2>/dev/null)
    if [ "$HTTP_CODE_T3" = "403" ] || [ "$HTTP_CODE_T3" = "404" ] || [ "$HTTP_CODE_T3" = "400" ]; then
        pass "T3: challenge on redeemed session refused (HTTP $HTTP_CODE_T3)"
    else
        fail "T3: expected 40x on redeemed session, got HTTP $HTTP_CODE_T3"
    fi
else
    echo "  Skipping T3 — T1 session_id not available"
fi

# ── T4: Restart safety ────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== T4: Restart safety (bot killed mid-lifecycle, session persists) ==="

CALL_OFFSET_T4=$(curl -sf "http://127.0.0.1:$FIXTURE_TG_PORT/fixture/results" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')
inject_join 57 10003
echo "  injected /join for user 57 (update_id=10003)"

SESSION_ID_T4=$(wait_for_session "$CALL_OFFSET_T4" "T4") || { echo "  Skipping T4 remainder."; SESSION_ID_T4=""; }

if [ -n "$SESSION_ID_T4" ]; then
    CHALLENGE_JSON_T4=$(get_challenge "$SESSION_ID_T4")
    echo "  challenge obtained; submitting proof then killing bot"

    PROOF_RESP_T4=$(submit_proof "$SESSION_ID_T4" "$CHALLENGE_JSON_T4" "$TEST_SK")
    VERIFIED_T4=$(echo "$PROOF_RESP_T4" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("verified",""))' 2>/dev/null || echo "")

    if [ "$VERIFIED_T4" = "True" ] || [ "$VERIFIED_T4" = "true" ]; then
        echo "  proof accepted; killing bot before claim"
        kill "$BOT_PID" 2>/dev/null || true
        sleep 1
        BOT_PID=""

        # Restart bot
        echo "  restarting bot"
        GG_TG_FIXTURE=1 \
        GG_TG_API_URL="http://127.0.0.1:$FIXTURE_TG_PORT" \
        GG_TG_BOT_TOKEN="fixture_m8test" \
        GG_TG_CHAT_ID="$CHAT_ID" \
        GG_TG_FIXTURE_TEST_CHAT_ID="$CHAT_ID" \
        GG_BOT_ESMERALDA_KEY="$BOT_KEY" \
        GG_BOT_ESMERALDA_BRIDGE="$BRIDGE_BASE" \
        GG_BOT_ESMERALDA_GATE_ID="$GATE_ID" \
        GG_BOT_ESMERALDA_POLICY_HASH="$POLICY_HASH" \
        GG_BOT_SESSION_STORE_DIR="$BOT_STORE_DIR" \
        GG_JOIN_BASE_URL="$BRIDGE_BASE" \
        GG_TG_CLAIM_PORT="$BOT_CLAIM_PORT" \
          "$BOT_BIN" \
            >> "$TMPDIR/bot-stdout.log" \
            2>> "$TMPDIR/bot-stderr.log" &
        BOT_PID=$!

        wait_port "$BOT_CLAIM_PORT" "bot-claim (restarted)" 20 || {
            echo "  bot stderr:"; tail -20 "$TMPDIR/bot-stderr.log"
            fail "T4: restarted bot did not bind claim port"
        }

        # Claim against the restarted bot — it should still have the session in its store
        echo "  claiming session on restarted bot"
        CLAIM_RESP_T4=$(claim "$SESSION_ID_T4")
        CLAIM_STATE_T4=$(echo "$CLAIM_RESP_T4" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("state",""))' 2>/dev/null || echo "")
        echo "  claim response state: $CLAIM_STATE_T4"

        sleep 4
        APPROVE_COUNT_T4=$(count_method "approveChatJoinRequest" "$CALL_OFFSET_T4")
        if [ "$APPROVE_COUNT_T4" -ge 1 ]; then
            pass "T4: session survived restart; approveChatJoinRequest called after restart"
        else
            fail "T4: approveChatJoinRequest not called after restart; claim=$CLAIM_RESP_T4"
            echo "  bot stderr (last 20):"; tail -20 "$TMPDIR/bot-stderr.log"
        fi
    else
        fail "T4: proof rejected (cannot test restart without a Verified session); response: $PROOF_RESP_T4"
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Results: $PASS pass, $FAIL fail ==="
if [ "$FAIL" -eq 0 ]; then
    echo "M8 E2E: ALL PASS"
    exit 0
else
    echo "M8 E2E: FAILED ($FAIL test(s))"
    echo ""
    echo "--- bridge logs (last 30) ---"
    tail -30 "$TMPDIR/bridge-stderr.log" || true
    echo ""
    echo "--- bot logs (last 30) ---"
    tail -30 "$TMPDIR/bot-stderr.log" || true
    exit 1
fi
