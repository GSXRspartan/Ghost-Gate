#!/usr/bin/env bash
# Ghost Gate M6+ — Dual-network authorization separation test
#
# Starts two ghost-gate-bridge binaries on different loopback ports with different
# network bytes and HMAC keys (simulating Esmeralda + Mainnet deployments).
# Verifies that sessions and HMAC signatures from one network are not accepted
# by the other, and that each bridge maintains a fully separate authorization DB.
#
# Usage (inside WSL2 or any Linux):
#   bash /mnt/c/Users/pdark/Documents/Codex/ghost-gate-laptop/scripts/test-m6-dual-network.sh

set -euo pipefail

BRIDGE_BIN="$HOME/ghost-gate-linux-target/debug/ghost-gate-bridge"

PORT_A=7791
PORT_B=7792
URL_A="http://127.0.0.1:$PORT_A"
URL_B="http://127.0.0.1:$PORT_B"

# Distinct keys — one per network, 32 bytes each, non-zero
KEY_A="aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"
KEY_B="11223344112233441122334411223344112233441122334411223344112233aa"

POLICY_HASH="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
RESOURCE_ADDR="resource_0101010101010101010101010101010101010101010101010101010101010101"
GATE_ID="test-gate"
CHAT_ID="-1001234567890"

TEST_DIR="$(mktemp -d /tmp/gg-dual-net-XXXXXX)"
mkdir -p "$TEST_DIR/auth-a" "$TEST_DIR/auth-b"

PASS=0
FAIL=0
PID_A=""
PID_B=""

# Domain hex constants (same as test-m6-linux.sh)
CREATE_DOMAIN_HEX="67686f73742d676174652f626f742d73657373696f6e2f7631""00""504f5354""00""2f76312f626f742f73657373696f6e73""00"

cleanup() {
    for pid in $PID_A $PID_B; do
        [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && { kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
    done
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

hmac_sha256() {
    local key_hex="$1" domain_hex="$2" body="$3"
    python3 - "$key_hex" "$domain_hex" "$body" <<'PYEOF'
import hmac as _hmac, hashlib, sys
key_hex, domain_hex, body_str = sys.argv[1], sys.argv[2], sys.argv[3]
key = bytes.fromhex(key_hex)
msg = bytes.fromhex(domain_hex) + body_str.encode('utf-8')
print(_hmac.new(key, msg, hashlib.sha256).hexdigest(), end='')
PYEOF
}

pass() { echo "  [PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "  [FAIL] $1 — $2"; FAIL=$((FAIL+1)); }

wait_healthy() {
    local url="$1" label="$2"
    for i in $(seq 1 25); do
        curl -sf "$url/health" >/dev/null 2>&1 && { echo "  $label healthy after ${i}00 ms."; return 0; }
        sleep 0.2
    done
    echo "  ERROR: $label did not start in 5 s"
    exit 1
}

echo ""
echo "=== Ghost Gate M6+ Dual-Network Separation Test ==="
echo ""

[ -f "$BRIDGE_BIN" ] || { echo "Bridge binary not found: $BRIDGE_BIN"; exit 1; }

# ── Start bridge A (Esmeralda, network 0x26, key A) ───────────────────────────
echo "Starting Bridge A (Esmeralda, 0x26) on $URL_A ..."
GG_BRIDGE_BIND="127.0.0.1:$PORT_A" \
GG_BRIDGE_ORIGINS="$URL_A" \
GG_BRIDGE_GATES="$GATE_ID=:${RESOURCE_ADDR}:10:0:tTARI" \
GG_OOTLE_NETWORK="0x26" \
GG_BOT_KEY="$KEY_A" \
GG_BOT_AUTH_DB_DIR="$TEST_DIR/auth-a" \
GG_BOT_GATE_ID="$GATE_ID" \
GG_BOT_POLICY_HASH="$POLICY_HASH" \
GG_BOT_NETWORK="0x26" \
GG_BOT_RESOURCE="$RESOURCE_ADDR" \
GG_BOT_THRESHOLD="10" \
GG_BOT_CHAT_ID="$CHAT_ID" \
"$BRIDGE_BIN" >"$TEST_DIR/bridge-a.log" 2>&1 &
PID_A=$!
wait_healthy "$URL_A" "Bridge A"

# ── Start bridge B (Mainnet, network 0x00, key B) ─────────────────────────────
echo "Starting Bridge B (Mainnet, 0x00) on $URL_B ..."
GG_BRIDGE_BIND="127.0.0.1:$PORT_B" \
GG_BRIDGE_ORIGINS="$URL_B" \
GG_BRIDGE_GATES="$GATE_ID=:${RESOURCE_ADDR}:10:0:tTARI" \
GG_OOTLE_NETWORK="0x00" \
GG_BOT_KEY="$KEY_B" \
GG_BOT_AUTH_DB_DIR="$TEST_DIR/auth-b" \
GG_BOT_GATE_ID="$GATE_ID" \
GG_BOT_POLICY_HASH="$POLICY_HASH" \
GG_BOT_NETWORK="0x00" \
GG_BOT_RESOURCE="$RESOURCE_ADDR" \
GG_BOT_THRESHOLD="10" \
GG_BOT_CHAT_ID="$CHAT_ID" \
"$BRIDGE_BIN" >"$TEST_DIR/bridge-b.log" 2>&1 &
PID_B=$!
wait_healthy "$URL_B" "Bridge B"

echo ""
echo "Running tests..."
echo ""

NOW_UNIX=$(date +%s)

# ── T1: Esmeralda key accepted by bridge A ────────────────────────────────────
BODY_1="{\"update_id\":2001,\"telegram_user_id\":55,\"telegram_chat_id\":$CHAT_ID,\"gate_id\":\"$GATE_ID\",\"policy_hash\":\"$POLICY_HASH\",\"sent_unix\":$NOW_UNIX}"
SIG_A=$(hmac_sha256 "$KEY_A" "$CREATE_DOMAIN_HEX" "$BODY_1")
RESP_A=$(curl -s -X POST "$URL_A/v1/bot/sessions" \
    -H "Content-Type: application/json" \
    -H "Authorization: GG-Bot-HMAC $SIG_A" \
    --data-raw "$BODY_1" --max-time 5 2>/dev/null)
SID_A=$(echo "$RESP_A" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('session_id',''))" 2>/dev/null || true)
[ -n "$SID_A" ] && pass "T1: Esmeralda key accepted by Bridge A (session $SID_A)" \
                 || fail "T1: Esmeralda key accepted by Bridge A" "resp: $RESP_A"

# ── T2: Esmeralda key rejected by bridge B ────────────────────────────────────
BODY_2="{\"update_id\":2002,\"telegram_user_id\":55,\"telegram_chat_id\":$CHAT_ID,\"gate_id\":\"$GATE_ID\",\"policy_hash\":\"$POLICY_HASH\",\"sent_unix\":$NOW_UNIX}"
SIG_A2=$(hmac_sha256 "$KEY_A" "$CREATE_DOMAIN_HEX" "$BODY_2")
S2=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$URL_B/v1/bot/sessions" \
    -H "Content-Type: application/json" \
    -H "Authorization: GG-Bot-HMAC $SIG_A2" \
    --data-raw "$BODY_2" --max-time 5 2>/dev/null || echo "000")
[ "$S2" -ge 400 ] && pass "T2: Esmeralda key rejected by Bridge B (HTTP $S2)" \
                   || fail "T2: Esmeralda key rejected by Bridge B" "expected 4xx, got $S2"

# ── T3: Mainnet key accepted by bridge B ─────────────────────────────────────
BODY_3="{\"update_id\":2003,\"telegram_user_id\":55,\"telegram_chat_id\":$CHAT_ID,\"gate_id\":\"$GATE_ID\",\"policy_hash\":\"$POLICY_HASH\",\"sent_unix\":$NOW_UNIX}"
SIG_B=$(hmac_sha256 "$KEY_B" "$CREATE_DOMAIN_HEX" "$BODY_3")
RESP_B=$(curl -s -X POST "$URL_B/v1/bot/sessions" \
    -H "Content-Type: application/json" \
    -H "Authorization: GG-Bot-HMAC $SIG_B" \
    --data-raw "$BODY_3" --max-time 5 2>/dev/null)
SID_B=$(echo "$RESP_B" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('session_id',''))" 2>/dev/null || true)
[ -n "$SID_B" ] && pass "T3: Mainnet key accepted by Bridge B (session $SID_B)" \
                 || fail "T3: Mainnet key accepted by Bridge B" "resp: $RESP_B"

# ── T4: Mainnet key rejected by bridge A ─────────────────────────────────────
BODY_4="{\"update_id\":2004,\"telegram_user_id\":55,\"telegram_chat_id\":$CHAT_ID,\"gate_id\":\"$GATE_ID\",\"policy_hash\":\"$POLICY_HASH\",\"sent_unix\":$NOW_UNIX}"
SIG_B2=$(hmac_sha256 "$KEY_B" "$CREATE_DOMAIN_HEX" "$BODY_4")
S4=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$URL_A/v1/bot/sessions" \
    -H "Content-Type: application/json" \
    -H "Authorization: GG-Bot-HMAC $SIG_B2" \
    --data-raw "$BODY_4" --max-time 5 2>/dev/null || echo "000")
[ "$S4" -ge 400 ] && pass "T4: Mainnet key rejected by Bridge A (HTTP $S4)" \
                   || fail "T4: Mainnet key rejected by Bridge A" "expected 4xx, got $S4"

# ── T5: Esmeralda session not reachable via bridge B challenge endpoint ───────
if [ -n "$SID_A" ]; then
    SC=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$URL_B/v1/bot/sessions/$SID_A/challenge" \
        -H "Content-Type: application/json" \
        --data-raw '{"substate_id":"substate_010101010101010101010101010101010101010101010101010101010101"}' \
        --max-time 5 2>/dev/null || echo "000")
    [ "$SC" -ge 400 ] && pass "T5: Esmeralda session_id not found on Bridge B (HTTP $SC)" \
                       || fail "T5: session isolation" "expected 4xx, got $SC"
else
    echo "  [SKIP] T5: no session from T1"
fi

# ── T6: Each bridge has a separate SQLite authorization file ──────────────────
DB_A="$TEST_DIR/auth-a/authorization.sqlite"
DB_B="$TEST_DIR/auth-b/authorization.sqlite"
if [ -f "$DB_A" ] && [ -f "$DB_B" ]; then
    if [ "$DB_A" != "$DB_B" ]; then
        pass "T6: separate authorization.sqlite files for each network"
    else
        fail "T6: separate DB files" "both bridges share the same DB path"
    fi
else
    fail "T6: separate authorization.sqlite files" "missing: $([ -f "$DB_A" ] || echo "DB_A ") $([ -f "$DB_B" ] || echo "DB_B")"
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
echo ""
[ "$FAIL" -eq 0 ] || { echo "Bridge A log:"; tail -10 "$TEST_DIR/bridge-a.log" || true; echo "Bridge B log:"; tail -10 "$TEST_DIR/bridge-b.log" || true; exit 1; }
exit 0
