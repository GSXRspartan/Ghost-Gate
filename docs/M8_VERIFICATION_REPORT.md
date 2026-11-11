# Ghost Gate M8 — End-to-End Admission Verification Report

**Date:** 2026-11-11  
**Branch:** main  
**Milestone:** M8 — Process-level E2E admission test

---

## Summary

All four M8 end-to-end process-level tests pass. Three real compiled binaries
(`ghost-gate-bridge`, `gg-test-signer`, `ghost-gate-telegram`) ran as separate Linux
processes against a local HTTP fixture server. No production credentials, real Telegram
API, or mainnet transactions were used.

```
=== Results: 4 pass, 0 fail ===
M8 E2E: ALL PASS
```

---

## Test configuration

| Parameter | Value |
|-----------|-------|
| Network | Esmeralda testnet (0x26) |
| Gate ID | Crypt |
| Resource | `resource_0101...0101` (32×0x01) |
| Threshold | 10,000,000 µTARI |
| UTXO | `utxo_0101...0101_2c71...` (fixture) |
| Bot key | 32-byte test-only HMAC key |
| Policy hash | 32-byte test-only placeholder |
| Telegram API | Local HTTP fixture (port 7810) |
| Bridge | `127.0.0.1:7788` |
| Bot claim | `127.0.0.1:7808` |

---

## Test results

### T1 — Happy path (valid keypair → approveChatJoinRequest)

**Procedure:**
1. `gg-test-signer gen-keypair` generates a fresh Ristretto keypair.
2. Bridge configured with `GG_FIXTURE_UTXO` associating that public key with a UTXO
   meeting the threshold.
3. `/join` command injected for user 55.
4. Bot creates a session on the bridge (HMAC-authenticated), sends verify URL.
5. Test script calls `POST /v1/bot/sessions/{id}/challenge` and gets back the
   signing challenge.
6. `gg-test-signer sign` produces a valid Schnorr signature.
7. `POST /v1/bot/sessions/{id}/proof` returns `{"verified": true}`.
8. Bot's `/claim` endpoint called; bot calls bridge `POST /v1/bot/sessions/redeem`
   (HMAC-authenticated) and then calls `approveChatJoinRequest` on the fixture.

**Result:** PASS — `approveChatJoinRequest` called once for user 55.

---

### T2 — Wrong key (attacker's signature rejected)

**Procedure:**
1. A second Ristretto keypair (attacker) is generated.
2. The UTXO is configured to only accept the legitimate key (from T1 keypair).
3. `/join` injected for user 56; session created normally.
4. Attacker signs the challenge with their own secret key.
5. `POST /v1/bot/sessions/{id}/proof` with attacker's signature.

**Result:** PASS — Bridge returns HTTP 403; `approveChatJoinRequest` never called.

---

### T3 — Replay attack (redeemed session refused)

**Procedure:**
1. T1's session is now in state `Redeemed`.
2. Test attempts a fresh challenge on the same session ID.
3. `POST /v1/bot/sessions/{session_id_T1}/challenge` with a new UTXO argument.

**Result:** PASS — Bridge returns HTTP 403; `Created`-state check rejects `Redeemed`
sessions uniformly (same refusal for wrong-state, non-existent session, or expired).

---

### T4 — Restart safety (session survives bot process termination)

**Procedure:**
1. `/join` injected for user 57; session created.
2. Challenge obtained and valid proof submitted (`verified: true`).
3. Bot process killed (`SIGTERM`) before claim.
4. Bot restarted from scratch with the same `GG_BOT_SESSION_STORE_DIR`.
5. `/claim` called on restarted bot.
6. Bot reads session from durable store, calls bridge `redeem`, calls
   `approveChatJoinRequest`.

**Result:** PASS — `approveChatJoinRequest` called once for user 57 after restart.

---

## Binaries tested

| Binary | Size | Built |
|--------|------|-------|
| `ghost-gate-bridge` | 508 MB (debug) | 2026-11-11 01:26 |
| `gg-test-signer` | 55 MB (debug) | 2026-11-11 01:29 |
| `ghost-gate-telegram` | 54 MB (debug) | 2026-11-11 01:34 |

Target directory: `/home/pdark/gg-ootle-target/debug` (WSL2 `Ubuntu-22.04-orig`)

---

## Changes required to reach this milestone

| File | Change |
|------|--------|
| `crates/ghost-gate-walletd/src/bin/gg-test-signer.rs` | Fixed `rand::thread_rng()` → `rand::rng()` (rand 0.10 API change) |
| `scripts/test-m8-e2e.sh` | Fixed `BIN_DIR` detection; fixed `POLICY_HASH` to exactly 64 hex chars; fixed `wait_for_session` diagnostic echo to stderr |
| `scripts/fixture-telegram-server.py` | New: minimal Telegram Bot API fixture server |
| `scripts/build-m8.sh` | New: helper build script |

---

## Go / No-go verdicts

### Esmeralda testnet live admission

**Verdict: READY TO ENABLE (pending operator checklist)**

The process-level integration tests confirm:
- HMAC session lifecycle works between bot and bridge processes
- Ownership proof verification works with the FixtureChainReader (Ristretto Schnorr,
  domain-separated challenge, correct threshold check)
- Replay and wrong-key proofs are rejected with the same opaque 403
- Session durability across bot restarts works

Remaining operator steps before enabling live Esmeralda admissions:
1. Configure `GG_FIXTURE_UTXO` / `GG_TG_FIXTURE=1` to point at a real Esmeralda indexer
2. Set real `GG_BOT_KEY`, `GG_BOT_POLICY_HASH` (from policy document), `GG_BOT_CHAT_ID`
3. Run one manual end-to-end test with a real tTARI wallet
4. Confirm `approveChatJoinRequest` is called in the real Telegram group

### Mainnet admission

**Verdict: NOT READY**

Mainnet requires:
- A real mainnet indexer endpoint (no mainnet UTXO index available yet)
- Mainnet resource address and policy hash confirmed by the Tari network
- Separate network validation (the `warning: the wallet is on network 0` guard must
  agree with the mainnet network byte)
- Independent security review of the admission path under live traffic

Do not set `GG_BOT_NETWORK` to any mainnet value until these are resolved.

---

## Security constraints in force

The following constraints remain in force from prior milestones and are not relaxed
by this report:

- No production deployments, live Telegram group mutations, or mainnet transactions
  without explicit approval.
- No automatic kicking, bans, or destructive migrations of existing Telegram members.
- No copy of Esmeralda resource addresses into mainnet configuration.
- Fixture mode (`GG_TG_FIXTURE=1`) is impossible to enable accidentally in production:
  the binary checks `GG_TG_BOT_TOKEN` must start with `fixture_` and exits otherwise.
- Test binaries in this report are debug builds; production deployment requires
  release builds with stripped debug info.
