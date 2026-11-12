#!/usr/bin/env bash
# Ghost Gate M12 — session-backed admission: negative paths beyond the M8 baseline.
#
# M8 (test-m8-e2e.sh) proved T1 happy path, T2 wrong key, T3 replayed challenge, T4 restart
# safety for the Telegram admission flow. This script adds the M12 negatives against the SAME
# real compiled binaries and the same HTTP Telegram fixture server:
#
#   T5  — chat mismatch: a session-creation HMAC whose chat differs from the bridge's
#         configured chat is refused (identity is policy, never caller-supplied)
#   T6  — happy-path setup (user 65): proof verified, claim granted, approveChatJoinRequest
#         called — the setup T9 needs
#   T9  — duplicate claim: a second /claim for an already-redeemed session is refused
#   T7  — insufficient output: a fixture UTXO whose floor is below the threshold refuses
#         with the BelowThreshold refusal
#   T8  — frozen output: a fixture UTXO marked frozen refuses with the Frozen refusal (M10)
#   T11 — lab-signature replay: a signature framed over the RAW NONCE (what the credential-only
#         M11 Lab flow signs) is refused by the Telegram path even with the correct key —
#         the process-level proof of the unit test in bot_admission.rs
#
# Never connects to the real Telegram API or any live network. No production credentials.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
for cand in "/home/darkp/gg-target/debug" "/home/pdark/gg-ootle-target/debug" "$REPO_ROOT/target/debug"; do
    if [ -f "$cand/ghost-gate-bridge" ]; then BIN_DIR="$cand"; break; fi
done
BIN_DIR="${BIN_DIR:-$REPO_ROOT/target/release}"

SIGNER="$BIN_DIR/gg-test-signer"
BRIDGE_BIN="$BIN_DIR/ghost-gate-bridge"
BOT_BIN="$BIN_DIR/ghost-gate-telegram"
TG_FIXTURE_PY="$SCRIPT_DIR/fixture-telegram-server.py"

for f in "$SIGNER" "$BRIDGE_BIN" "$BOT_BIN" "$TG_FIXTURE_PY"; do
    if [ ! -f "$f" ]; then
        echo "[ERROR] missing: $f (build: cargo build -p ghost-gate-walletd --bin ghost-gate-bridge --bin gg-test-signer && cargo build -p ghost-gate-telegram)"
        exit 1
    fi
done

BRIDGE_PORT=7789
BOT_CLAIM_PORT=7809
FIXTURE_TG_PORT=7811
CHAT_ID=-1001234567890
GATE_ID="esme"
POLICY_HASH="feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface"
NETWORK="0x26"
RESOURCE="resource_0101010101010101010101010101010101010101010101010101010101010101"
UTXO_MAIN="utxo_0101010101010101010101010101010101010101010101010101010101010101_1111111111111111111111111111111111111111111111111111111111111111"
UTXO_LOW="utxo_0101010101010101010101010101010101010101010101010101010101010101_2222222222222222222222222222222222222222222222222222222222222222"
UTXO_FROZEN="utxo_0101010101010101010101010101010101010101010101010101010101010101_3333333333333333333333333333333333333333333333333333333333333333"
THRESHOLD=100000000
BOT_KEY="0102030405060708091011121314151617181920212223242526272829303132"
BRIDGE_BASE="http://127.0.0.1:$BRIDGE_PORT"

TMPDIR="$(mktemp -d /tmp/gg-m12-XXXXXX)"
BOT_STORE_DIR="$TMPDIR/bot-store"
AUTH_DB_DIR="$TMPDIR/auth-db"
mkdir -p "$BOT_STORE_DIR" "$AUTH_DB_DIR"

BRIDGE_PID=""; BOT_PID=""; TG_PID=""
PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL+1)); echo "  [FAIL] $1"; }

cleanup() {
    echo ""; echo "--- cleanup ---"
    [ -n "$BOT_PID" ]    && kill "$BOT_PID"    2>/dev/null || true
    [ -n "$BRIDGE_PID" ] && kill "$BRIDGE_PID"  2>/dev/null || true
    [ -n "$TG_PID" ]     && kill "$TG_PID"     2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

wait_http() {
    local url="$1" label="$2" max="${3:-15}"
    for i in $(seq 1 "$max"); do
        if curl -sf "$url" >/dev/null 2>&1; then echo "  $label ready (${i}s)"; return 0; fi
        sleep 1
    done
    echo "  $label did not become ready within ${max}s"; return 1
}
wait_port() {
    local port="$1" label="$2" max="${3:-15}"
    for i in $(seq 1 "$max"); do
        if bash -c "echo >/dev/tcp/127.0.0.1/$port" 2>/dev/null; then echo "  $label listening (${i}s)"; return 0; fi
        sleep 1
    done
    echo "  $label did not bind port $port"; return 1
}
fixture_calls_from() {
    local offset="${1:-0}"
    curl -sf "http://127.0.0.1:$FIXTURE_TG_PORT/fixture/results" | \
        python3 -c "import json,sys; data=json.load(sys.stdin); print(json.dumps(data[$offset:]))"
}
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
                    print(p['bot_session']); sys.exit(0)
sys.exit(1)
" 2>/dev/null
}
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
        'chat': {'id': $CHAT_ID, 'type': 'supergroup', 'title': 'M12 Fixture Group'},
        'text': '/join',
        'entities': [{'offset': 0, 'length': 5, 'type': 'bot_command'}],
    }
}))")
    curl -sf -X POST "http://127.0.0.1:$FIXTURE_TG_PORT/fixture/inject" \
        -H "Content-Type: application/json" -d "$body" >/dev/null
}
wait_for_session() {
    local offset="$1" label="$2" sid=""
    for i in $(seq 1 15); do
        sleep 2
        sid=$(fixture_calls_from "$offset" | extract_session_id) && break || sid=""
    done
    if [ -z "$sid" ]; then fail "$label: bot did not send a verify URL within 30s"; return 1; fi
    echo "$sid"
}
get_challenge() {
    curl -sf -X POST "$BRIDGE_BASE/v1/bot/sessions/$1/challenge" \
        -H "Content-Type: application/json" -d "{\"substate_id\": \"$2\"}"
}
# sign_and_submit session_id challenge_json sk utxo [challenge_override]
# challenge_override signs the RAW NONCE instead of the bridge's challenge string (T11).
sign_and_submit() {
    local session_id="$1" challenge_json="$2" sk="$3" utxo="$4" override="${5:-}"
    local challenge challenge_nonce signed
    challenge=$(echo "$challenge_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["challenge"])')
    challenge_nonce=$(echo "$challenge_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["challenge_nonce"])')
    signed="${override:-$challenge}"
    local sig_json pk nonce sig
    sig_json=$("$SIGNER" sign "$NETWORK" "$RESOURCE" "$utxo" "$signed" "$sk")
    pk=$(echo "$sig_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["public_key"])')
    nonce=$(echo "$sig_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["public_nonce"])')
    sig=$(echo "$sig_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["signature"])')
    local body
    body=$(python3 -c "
import json
print(json.dumps({
    'gate_id': '$GATE_ID', 'challenge_nonce': '$challenge_nonce',
    'session_commitment': '22'.repeat(32) if False else '22'*32,
    'substate_id': '$utxo',
    'public_key': '$pk', 'public_nonce': '$nonce', 'signature': '$sig',
}))")
    curl -s -X POST "$BRIDGE_BASE/v1/bot/sessions/$session_id/proof" \
        -H "Content-Type: application/json" -d "$body"
}
claim() {
    curl -s -X POST "http://127.0.0.1:$BOT_CLAIM_PORT/claim" \
        -H "Host: 127.0.0.1:$BOT_CLAIM_PORT" \
        -H "Origin: $BRIDGE_BASE" \
        -H "Content-Type: application/json" \
        -d "{\"bot_session_id\": \"$1\"}"
}
count_method() {
    local method="$1" offset="$2"
    fixture_calls_from "$offset" | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(sum(1 for c in data if c.get('method') == '$method'))
"
}

echo "=== Ghost Gate M12 — session-backed admission negatives ==="

# --- keypairs: one per fixture UTXO ---
KP_MAIN=$("$SIGNER" gen-keypair)
SK_MAIN=$(echo "$KP_MAIN" | python3 -c 'import json,sys; print(json.load(sys.stdin)["secret_key"])')
PK_MAIN=$(echo "$KP_MAIN" | python3 -c 'import json,sys; print(json.load(sys.stdin)["public_key"])')
KP_LOW=$("$SIGNER" gen-keypair)
SK_LOW=$(echo "$KP_LOW" | python3 -c 'import json,sys; print(json.load(sys.stdin)["secret_key"])')
PK_LOW=$(echo "$KP_LOW" | python3 -c 'import json,sys; print(json.load(sys.stdin)["public_key"])')
KP_FROZEN=$("$SIGNER" gen-keypair)
SK_FROZEN=$(echo "$KP_FROZEN" | python3 -c 'import json,sys; print(json.load(sys.stdin)["secret_key"])')
PK_FROZEN=$(echo "$KP_FROZEN" | python3 -c 'import json,sys; print(json.load(sys.stdin)["public_key"])')

GG_FIXTURE_UTXO="$UTXO_MAIN:$PK_MAIN:$THRESHOLD,$UTXO_LOW:$PK_LOW:5000000,$UTXO_FROZEN:$PK_FROZEN:$THRESHOLD:frozen"

echo ""
echo "--- starting fixture Telegram server on $FIXTURE_TG_PORT ---"
python3 "$TG_FIXTURE_PY" "$FIXTURE_TG_PORT" "$CHAT_ID" \
    > "$TMPDIR/fixture-tg-stdout.log" 2> "$TMPDIR/fixture-tg-stderr.log" &
TG_PID=$!
wait_http "http://127.0.0.1:$FIXTURE_TG_PORT/fixture/results" "fixture-tg" 10 || {
    echo "  fixture-tg stderr:"; tail -5 "$TMPDIR/fixture-tg-stderr.log"; exit 1
}

echo ""
echo "--- starting bridge on $BRIDGE_BASE (fixture chain + admission) ---"
GG_BRIDGE_BIND="127.0.0.1:$BRIDGE_PORT" \
GG_BRIDGE_ORIGINS="$BRIDGE_BASE" \
GG_BRIDGE_RELYING_SITE="$BRIDGE_BASE" \
GG_BRIDGE_GATES="$GATE_ID=:$RESOURCE:$THRESHOLD:6:tTARI" \
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
  "$BRIDGE_BIN" > "$TMPDIR/bridge-stdout.log" 2> "$TMPDIR/bridge-stderr.log" &
BRIDGE_PID=$!
wait_http "$BRIDGE_BASE/health" "bridge" 20 || {
    echo "  bridge stderr:"; tail -20 "$TMPDIR/bridge-stderr.log"; exit 1
}

echo ""
echo "--- starting bot (HTTP fixture mode) ---"
GG_TG_FIXTURE=1 \
GG_TG_API_URL="http://127.0.0.1:$FIXTURE_TG_PORT" \
GG_TG_BOT_TOKEN="fixture_m12test" \
GG_TG_CHAT_ID="$CHAT_ID" \
GG_TG_FIXTURE_TEST_CHAT_ID="$CHAT_ID" \
GG_BOT_ESMERALDA_KEY="$BOT_KEY" \
GG_BOT_ESMERALDA_BRIDGE="$BRIDGE_BASE" \
GG_BOT_ESMERALDA_GATE_ID="$GATE_ID" \
GG_BOT_ESMERALDA_POLICY_HASH="$POLICY_HASH" \
GG_BOT_SESSION_STORE_DIR="$BOT_STORE_DIR" \
GG_JOIN_BASE_URL="$BRIDGE_BASE" \
GG_TG_CLAIM_PORT="$BOT_CLAIM_PORT" \
  "$BOT_BIN" > "$TMPDIR/bot-stdout.log" 2> "$TMPDIR/bot-stderr.log" &
BOT_PID=$!
wait_port "$BOT_CLAIM_PORT" "bot-claim" 20 || {
    echo "  bot stderr:"; tail -20 "$TMPDIR/bot-stderr.log"; exit 1
}

# ---------------------------------------------------------------------------
echo ""
echo "=== T5: chat mismatch at session creation is refused ==="
T5_BODY=$(python3 -c "
import json, time
print(json.dumps({
    'update_id': 50001, 'telegram_user_id': 77, 'telegram_chat_id': -100999,
    'gate_id': '$GATE_ID', 'policy_hash': '$POLICY_HASH',
    'sent_unix': int(time.time()),
}))")
T5_SIG=$(python3 -c "
import hmac, hashlib, sys
key = bytes.fromhex('$BOT_KEY')
domain = b'ghost-gate/bot-session/v1\x00POST\x00/v1/bot/sessions\x00'
print(hmac.new(key, domain + '''$T5_BODY'''.encode(), hashlib.sha256).hexdigest())")
T5_STATUS=$(curl -s -o /tmp/t5.out -w "%{http_code}" -X POST "$BRIDGE_BASE/v1/bot/sessions" \
    -H "Content-Type: application/json" -H "GG-Bot-HMAC: $T5_SIG" -d "$T5_BODY")
if [ "$T5_STATUS" = "403" ]; then
    pass "T5: a session whose chat differs from policy is refused (HTTP $T5_STATUS)"
else
    fail "T5: expected 403 for a chat mismatch, got $T5_STATUS: $(cat /tmp/t5.out)"
fi

# ---------------------------------------------------------------------------
echo ""
echo "=== T6: happy path setup (user 65) — verified, claimed, approved ==="
OFFSET_T6=$(curl -sf "http://127.0.0.1:$FIXTURE_TG_PORT/fixture/results" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')
inject_join 65 60001
SESSION_T6=$(wait_for_session "$OFFSET_T6" "T6") || SESSION_T6=""
if [ -n "$SESSION_T6" ]; then
    CH_T6=$(get_challenge "$SESSION_T6" "$UTXO_MAIN")
    PROOF_T6=$(sign_and_submit "$SESSION_T6" "$CH_T6" "$SK_MAIN" "$UTXO_MAIN")
    VER_T6=$(echo "$PROOF_T6" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("verified",""))' 2>/dev/null || echo "")
    if [ "$VER_T6" = "True" ] || [ "$VER_T6" = "true" ]; then
        pass "T6: proof verified against the fixture chain"
        CLAIM_T6=$(claim "$SESSION_T6")
        STATE_T6=$(echo "$CLAIM_T6" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("state",""))' 2>/dev/null || echo "")
        sleep 4
        APPROVES=$(count_method "approveChatJoinRequest" "$OFFSET_T6")
        if [ "$STATE_T6" = "granted" ] && [ "$APPROVES" -ge 1 ]; then
            pass "T6: claim granted and approveChatJoinRequest called ($APPROVES)"
        else
            fail "T6: claim state=$STATE_T6 approvals=$APPROVES; bot stderr:"; tail -15 "$TMPDIR/bot-stderr.log"
        fi
    else
        fail "T6: proof not verified: $PROOF_T6"
    fi
fi

# ---------------------------------------------------------------------------
echo ""
echo "=== T9: duplicate claim on a redeemed session is refused ==="
if [ -n "$SESSION_T6" ]; then
    CLAIM_T9=$(claim "$SESSION_T6")
    STATE_T9=$(echo "$CLAIM_T9" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("state",""))' 2>/dev/null || echo "")
    if [ "$STATE_T9" = "refused" ]; then
        pass "T9: a second claim for a redeemed session is refused"
    else
        fail "T9: expected refused, got state=$STATE_T9 body=$CLAIM_T9"
    fi
else
    echo "  skipped (no T6 session)"
fi

# ---------------------------------------------------------------------------
echo ""
echo "=== T7: an output below the threshold is refused ==="
OFFSET_T7=$(curl -sf "http://127.0.0.1:$FIXTURE_TG_PORT/fixture/results" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')
inject_join 66 60002
SESSION_T7=$(wait_for_session "$OFFSET_T7" "T7") || SESSION_T7=""
if [ -n "$SESSION_T7" ]; then
    CH_T7=$(get_challenge "$SESSION_T7" "$UTXO_LOW")
    PROOF_T7=$(sign_and_submit "$SESSION_T7" "$CH_T7" "$SK_LOW" "$UTXO_LOW")
    if echo "$PROOF_T7" | grep -q "below this gate's"; then
        pass "T7: BelowThreshold refusal names the floor: $(echo "$PROOF_T7" | head -c 140)…"
    else
        fail "T7: expected the BelowThreshold refusal, got: $PROOF_T7"
    fi
fi

# ---------------------------------------------------------------------------
echo ""
echo "=== T8: a frozen output is refused (M10 eligibility, process level) ==="
OFFSET_T8=$(curl -sf "http://127.0.0.1:$FIXTURE_TG_PORT/fixture/results" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')
inject_join 67 60003
SESSION_T8=$(wait_for_session "$OFFSET_T8" "T8") || SESSION_T8=""
if [ -n "$SESSION_T8" ]; then
    CH_T8=$(get_challenge "$SESSION_T8" "$UTXO_FROZEN")
    PROOF_T8=$(sign_and_submit "$SESSION_T8" "$CH_T8" "$SK_FROZEN" "$UTXO_FROZEN")
    if echo "$PROOF_T8" | grep -q "frozen"; then
        pass "T8: frozen-output refusal: $(echo "$PROOF_T8" | head -c 140)…"
    else
        fail "T8: expected the frozen refusal, got: $PROOF_T8"
    fi
fi

# ---------------------------------------------------------------------------
echo ""
echo "=== T11: a credential-only (M11 Lab) signature cannot open a Telegram session ==="
OFFSET_T11=$(curl -sf "http://127.0.0.1:$FIXTURE_TG_PORT/fixture/results" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')
inject_join 68 60004
SESSION_T11=$(wait_for_session "$OFFSET_T11" "T11") || SESSION_T11=""
if [ -n "$SESSION_T11" ]; then
    CH_T11=$(get_challenge "$SESSION_T11" "$UTXO_MAIN")
    NONCE_T11=$(echo "$CH_T11" | python3 -c 'import json,sys; print(json.load(sys.stdin)["challenge_nonce"])')
    # Sign the RAW NONCE — the string the M11 credential-only Lab hands the wallet —
    # with the CORRECT key for the output, and submit it as the Telegram proof.
    PROOF_T11=$(sign_and_submit "$SESSION_T11" "$CH_T11" "$SK_MAIN" "$UTXO_MAIN" "$NONCE_T11")
    if echo "$PROOF_T11" | grep -q "signature does not verify"; then
        pass "T11: the lab-framed signature is refused: $(echo "$PROOF_T11" | head -c 140)…"
    else
        fail "T11: expected the signature refusal, got: $PROOF_T11"
    fi
fi

# ---------------------------------------------------------------------------
echo ""
echo "=== M12 results: $PASS passed, $FAIL failed ==="
[ "$FAIL" = "0" ] || exit 1
exit 0
