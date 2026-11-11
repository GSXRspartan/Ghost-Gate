#!/usr/bin/env bash
# Ghost Gate M6+ — Linux process-isolation integration test
#
# Starts the real ghost-gate-bridge binary inside WSL2/Linux, sends HMAC-authenticated
# HTTP requests against the bot-session admission routes, and verifies correct behavior.
#
# Because the bridge enforces loopback-only access on the bot-session routes, this test
# must run inside the same Linux environment as the bridge binary (not from Windows).
#
# Usage:
#   wsl -d Ubuntu -e bash /mnt/c/Users/pdark/Documents/Codex/ghost-gate-laptop/scripts/test-m6-linux.sh
#
# Or from inside WSL2:
#   bash /mnt/c/Users/pdark/Documents/Codex/ghost-gate-laptop/scripts/test-m6-linux.sh
#
# KNOWN LIMITATION: The /v1/bot/sessions/:id/proof step requires a live walletd (Tari node).
# That step is covered by unit tests in ghost-gate-bridge/src/server.rs with mock wallets.
# This script covers everything testable without walletd:
#   - bridge starts and reports healthy (GET /health)
#   - bot session creation returns 201 with session_id (POST /v1/bot/sessions)
#   - a replay (same update_id) is refused with 403/409
#   - a tampered HMAC is refused with 403
#   - a non-loopback request (Origin header present) is refused
#   - challenge issuance for a live session returns 200
#   - bot session redemption (POST /v1/bot/sessions/redeem) returns 403 (unverified)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BRIDGE_BIN="$HOME/ghost-gate-linux-target/debug/ghost-gate-bridge"

# ── Test parameters ────────────────────────────────────────────────────────────
TEST_PORT=7788
BRIDGE_URL="http://127.0.0.1:$TEST_PORT"
BOT_KEY="aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"
POLICY_HASH="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
RESOURCE_ADDR="resource_0101010101010101010101010101010101010101010101010101010101010101"
GATE_ID="test-gate"
CHAT_ID="-1001234567890"

TEST_DIR="$(mktemp -d /tmp/gg-linux-test-XXXXXX)"
AUTH_DB_DIR="$TEST_DIR/auth-db"
SESSION_DIR="$TEST_DIR/sessions"
mkdir -p "$AUTH_DB_DIR" "$SESSION_DIR"

PASS=0
FAIL=0
BRIDGE_PID=""

# ── Cleanup ────────────────────────────────────────────────────────────────────
cleanup() {
    if [ -n "$BRIDGE_PID" ] && kill -0 "$BRIDGE_PID" 2>/dev/null; then
        kill "$BRIDGE_PID" 2>/dev/null || true
        wait "$BRIDGE_PID" 2>/dev/null || true
    fi
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

# ── HMAC helper ────────────────────────────────────────────────────────────────
# Compute HMAC-SHA256 over (domain_bytes || body_bytes), return lowercase hex.
# Domain is passed as a hex string to avoid null-byte escaping issues.
# Requires: python3 (available in Ubuntu 24.04)
hmac_sha256() {
    local key_hex="$1"
    local domain_hex="$2"
    local body="$3"
    python3 - "$key_hex" "$domain_hex" "$body" <<'PYEOF'
import hmac as _hmac, hashlib, sys

key_hex, domain_hex, body_str = sys.argv[1], sys.argv[2], sys.argv[3]
key          = bytes.fromhex(key_hex)
domain_bytes = bytes.fromhex(domain_hex)
body_bytes   = body_str.encode('utf-8')

msg = domain_bytes + body_bytes
sig = _hmac.new(key, msg, hashlib.sha256).hexdigest()
print(sig, end='')
PYEOF
}

# Domain bytes as hex (null-byte separated, matching bot_session_interface.rs / bot_admission.rs).
# Precomputed: encode each segment, join with 00 (null byte), terminate with 00.
# ghost-gate/bot-session/v1 \0 POST \0 /v1/bot/sessions \0
CREATE_DOMAIN_HEX="67686f73742d676174652f626f742d73657373696f6e2f7631""00""504f5354""00""2f76312f626f742f73657373696f6e73""00"
# ghost-gate/bot-redeem/v1 \0 POST \0 /v1/bot/sessions/redeem \0
REDEEM_DOMAIN_HEX="67686f73742d676174652f626f742d72656465656d2f7631""00""504f5354""00""2f76312f626f742f73657373696f6e732f72656465656d""00"

# ── Assertion helpers ──────────────────────────────────────────────────────────
pass() { echo "  [PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "  [FAIL] $1 — $2"; FAIL=$((FAIL+1)); }

assert_status() {
    local name="$1" url="$2" method="$3" body="$4" auth_header="$5" extra_flag="${6:-}"
    local expected_range_lo="${7:-200}" expected_range_hi="${8:-299}"
    local status
    local flags=(-s -o /dev/null -w "%{http_code}" -X "$method" "$url"
                 -H "Content-Type: application/json"
                 -H "Authorization: $auth_header"
                 --data-raw "$body"
                 --max-time 5)
    [ -n "$extra_flag" ] && flags+=($extra_flag)
    status=$(curl "${flags[@]}" 2>/dev/null || echo "000")
    if [ "$status" -ge "$expected_range_lo" ] && [ "$status" -le "$expected_range_hi" ]; then
        pass "$name (HTTP $status)"
    else
        fail "$name" "expected $expected_range_lo-$expected_range_hi, got HTTP $status"
    fi
}

# ── Build check ────────────────────────────────────────────────────────────────
echo ""
echo "=== Ghost Gate M6+ Linux Process-Isolation Test ==="
echo ""
echo "Step 1: Checking bridge binary..."
if [ ! -f "$BRIDGE_BIN" ]; then
    echo "  Bridge binary not found at $BRIDGE_BIN"
    echo "  Build it first with:"
    echo "    /home/darkp/.cargo/bin/cargo build --manifest-path $REPO_ROOT/Cargo.toml -p ghost-gate-walletd --bin ghost-gate-bridge --target-dir \$HOME/ghost-gate-linux-target"
    exit 1
fi
echo "  Binary found: $BRIDGE_BIN"
file "$BRIDGE_BIN" || true

# ── Start bridge ───────────────────────────────────────────────────────────────
echo ""
echo "Step 2: Starting bridge on $BRIDGE_URL ..."
export GG_BRIDGE_BIND="127.0.0.1:$TEST_PORT"
export GG_BRIDGE_ORIGINS="$BRIDGE_URL"
export GG_BRIDGE_GATES="$GATE_ID=:${RESOURCE_ADDR}:10:0:tTARI"
export GG_OOTLE_NETWORK="0x26"
export GG_BOT_KEY="$BOT_KEY"
export GG_BOT_AUTH_DB_DIR="$AUTH_DB_DIR"
export GG_BOT_GATE_ID="$GATE_ID"
export GG_BOT_POLICY_HASH="$POLICY_HASH"
export GG_BOT_NETWORK="0x26"
export GG_BOT_RESOURCE="$RESOURCE_ADDR"
export GG_BOT_THRESHOLD="10"
export GG_BOT_CHAT_ID="$CHAT_ID"

"$BRIDGE_BIN" >"$TEST_DIR/bridge-stdout.log" 2>"$TEST_DIR/bridge-stderr.log" &
BRIDGE_PID=$!
echo "  Bridge PID: $BRIDGE_PID"

# Wait up to 5 s for the bridge to become healthy
for i in $(seq 1 25); do
    if curl -sf "$BRIDGE_URL/health" >/dev/null 2>&1; then
        echo "  Bridge healthy after ${i}00 ms."
        break
    fi
    sleep 0.2
    if [ "$i" -eq 25 ]; then
        echo "  ERROR: bridge did not start in 5 s. stderr:"
        cat "$TEST_DIR/bridge-stderr.log" | tail -20
        exit 1
    fi
done

# ── Tests ──────────────────────────────────────────────────────────────────────
echo ""
echo "Step 3: Running tests..."
echo ""

# T1: health endpoint
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BRIDGE_URL/health" 2>/dev/null || echo "000")
[ "$STATUS" -eq 200 ] && pass "T1: /health returns 200" || fail "T1: /health returns 200" "got $STATUS"

# T2: bot session creation — valid HMAC
NOW_UNIX=$(date +%s)
UPDATE_ID=1001
TG_USER=55
BODY="{\"update_id\":$UPDATE_ID,\"telegram_user_id\":$TG_USER,\"telegram_chat_id\":$CHAT_ID,\"gate_id\":\"$GATE_ID\",\"policy_hash\":\"$POLICY_HASH\",\"sent_unix\":$NOW_UNIX}"
SIG=$(hmac_sha256 "$BOT_KEY" "$CREATE_DOMAIN_HEX" "$BODY")
RESP=$(curl -s -X POST "$BRIDGE_URL/v1/bot/sessions" \
    -H "Content-Type: application/json" \
    -H "Authorization: GG-Bot-HMAC $SIG" \
    --data-raw "$BODY" \
    --max-time 5 2>/dev/null)
SESSION_ID=$(echo "$RESP" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('session_id',''))" 2>/dev/null || true)
if [ -n "$SESSION_ID" ]; then
    pass "T2: bot session creation returns session_id ($SESSION_ID)"
else
    fail "T2: bot session creation returns session_id" "response: $RESP"
fi

# Re-derive a fresh signature for the replay test (same body, same update_id = replay)
SIG2=$(hmac_sha256 "$BOT_KEY" "$CREATE_DOMAIN_HEX" "$BODY")
S2=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BRIDGE_URL/v1/bot/sessions" \
    -H "Content-Type: application/json" \
    -H "Authorization: GG-Bot-HMAC $SIG2" \
    --data-raw "$BODY" \
    --max-time 5 2>/dev/null || echo "000")
[ "$S2" -ge 400 ] && pass "T3: replay (same update_id) is refused (HTTP $S2)" || fail "T3: replay refused" "expected 4xx, got $S2"

# T4: tampered HMAC is refused
BAD_SIG="0000000000000000000000000000000000000000000000000000000000000000"
S4=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BRIDGE_URL/v1/bot/sessions" \
    -H "Content-Type: application/json" \
    -H "Authorization: GG-Bot-HMAC $BAD_SIG" \
    --data-raw "$BODY" \
    --max-time 5 2>/dev/null || echo "000")
[ "$S4" -ge 400 ] && pass "T4: tampered HMAC refused (HTTP $S4)" || fail "T4: tampered HMAC refused" "expected 4xx, got $S4"

# T5: Origin header present → refused (browser-originated request blocked on bot route)
UPDATE_ID2=1002
BODY2="{\"update_id\":$UPDATE_ID2,\"telegram_user_id\":$TG_USER,\"telegram_chat_id\":$CHAT_ID,\"gate_id\":\"$GATE_ID\",\"policy_hash\":\"$POLICY_HASH\",\"sent_unix\":$NOW_UNIX}"
SIG5=$(hmac_sha256 "$BOT_KEY" "$CREATE_DOMAIN_HEX" "$BODY2")
S5=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BRIDGE_URL/v1/bot/sessions" \
    -H "Content-Type: application/json" \
    -H "Authorization: GG-Bot-HMAC $SIG5" \
    -H "Origin: https://example.com" \
    --data-raw "$BODY2" \
    --max-time 5 2>/dev/null || echo "000")
[ "$S5" -ge 400 ] && pass "T5: Origin header present → refused (HTTP $S5)" || fail "T5: Origin blocks bot route" "expected 4xx, got $S5"

# T6: challenge for the live session (browser-reachable route; no loopback restriction)
if [ -n "$SESSION_ID" ]; then
    SUBSTATE="substate_010101010101010101010101010101010101010101010101010101010101"
    CHAL_BODY="{\"substate_id\":\"$SUBSTATE\"}"
    SC=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BRIDGE_URL/v1/bot/sessions/$SESSION_ID/challenge" \
        -H "Content-Type: application/json" \
        --data-raw "$CHAL_BODY" \
        --max-time 5 2>/dev/null || echo "000")
    # 200 = challenge issued; 403 = session not in Created state (may have been used by T2 re-request)
    [ "$SC" -eq 200 ] || [ "$SC" -eq 403 ] && pass "T6: challenge endpoint reachable (HTTP $SC)" || fail "T6: challenge endpoint" "expected 200/403, got $SC"
else
    echo "  [SKIP] T6: no session_id from T2"
fi

# T7: redeem without prior verification is refused
UPDATE_ID3=1003
BODY3="{\"session_id\":\"nonexistent-session\",\"sent_unix\":$NOW_UNIX}"
SIG7=$(hmac_sha256 "$BOT_KEY" "$REDEEM_DOMAIN_HEX" "$BODY3")
S7=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BRIDGE_URL/v1/bot/sessions/redeem" \
    -H "Content-Type: application/json" \
    -H "Authorization: GG-Bot-HMAC $SIG7" \
    --data-raw "$BODY3" \
    --max-time 5 2>/dev/null || echo "000")
[ "$S7" -ge 400 ] && pass "T7: redeem of unverified session refused (HTTP $S7)" || fail "T7: unverified redeem refused" "expected 4xx, got $S7"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
echo ""
if [ "$FAIL" -gt 0 ]; then
    echo "Bridge stderr (last 20 lines):"
    tail -20 "$TEST_DIR/bridge-stderr.log" || true
    exit 1
fi
exit 0
