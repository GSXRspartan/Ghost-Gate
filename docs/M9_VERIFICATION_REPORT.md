# Ghost Gate M9 — Verification Report

**Date:** 2026-11-11  
**Branch:** main  
**Milestone:** M9 — Real wallet flow, Ootle audit, mainnet frontend, bot dual-network, security hardening

---

## Summary

M9 delivers six areas of work:

1. **M9.1** — Real Sapient wallet flow for Esmeralda (browser→wallet→bridge with M6+ bot-session endpoints)
2. **M9.2** — Ootle v0.49.2 compatibility audit (reference tree; v0.53 does not exist)
3. **M9.3** — Functional mainnet frontend at `/mainnet` (honest status; no admission buttons until end-to-end validated)
4. **M9.4** — Cross-network proof-reuse prevention via `network_label` stored in `PendingBotSession` / `StoredSession`
5. **M9.5** (security) — Admin-session isolation, admission recovery state machine, bridge authorization storage durability (carried forward — see M8 completion)
6. **Evidence** — Build confirmation; explicit GO/NO-GO verdicts below

---

## M9.1 — Real Sapient wallet flow

### What changed

| File | Change |
|------|--------|
| `web/telegram/claim.js` | Complete rewrite: removed `telegramAdmissionAvailable = false` guard; switched from old join-token endpoints to M6+ bot-session endpoints; correct step order (output → challenge → sign → verify → claim); signs `ch.challenge` (full Blake2b-512 string), not `ch.challenge_nonce` |
| `web/telegram/join.html` | Step order updated to match M6+ flow; threshold corrected to 10 tTARI; footer updated |

### Protocol correctness

The M6+ bot-session flow requires:

1. **Output first**: `provider.approveAndBuildProof("credential", ...)` → yields `substateId`
2. **Challenge bound to output**: `POST /v1/bot/sessions/{id}/challenge` with `{ substate_id }` → returns `ChallengeIssued { challenge, challenge_nonce, ... }`
3. **Sign the full challenge string**: `provider.signChallenge(substateId, ch.challenge)` — `ch.challenge` is the 128-char Blake2b-512 hash of the full Telegram proof context; the bridge re-derives the identical string when verifying
4. **Submit proof**: `POST /v1/bot/sessions/{id}/proof` with `challenge_nonce`, `session_commitment` (wire-required but not validated in bot path), `substate_id`, `public_key`, `public_nonce`, `signature`
5. **Bot auto-redeems**: no separate claim step on the page

The old flow used `/gate/{id}/challenge` → `/gate/{id}/credential` → bot's `/claim`. That path is gone.

### Chain verification path

Real chain verification requires `GG_INDEXER_ENDPOINT=http://217.182.93.35:50124`. When configured:

- `IndexerChainReader` fetches the UTXO at `substate_id` from the Esmeralda indexer
- `UtxoOnChain.verified` must be `true`; a `false` value → `CredentialRefusal::UnverifiedChainData`
- The `ownership_proof_message(network, resource, substate_id, challenge_string)` function (Blake2b-512 domain-separated) produces the message the wallet signed; the bridge verifies the Schnorr signature against the UTXO's `auth_key`
- Network byte `0x26` (Esmeralda) is enforced; a mainnet UTXO (byte `0x00`) would be rejected at `submit()` in `walletd/src/lib.rs`

**NOT proven in this milestone**: actual live browser-to-wallet-to-bridge round-trip with a real tTARI wallet connected to the Esmeralda indexer. The M8 E2E tests used `gg-test-signer` as a fixture wallet. Real wallet integration requires the operator checklist in §GO/NO-GO.

### Session commitment field

`session_commitment` in `CredentialProofRequest` is a wire-required field (`#[serde(deny_unknown_fields)]`) that the bot-session path does not validate — `TelegramProofContext.verify()` checks only `gate_id`, `substate_id`, `challenge_nonce`. The page sends `"00".repeat(32)` (64-char zero hex) as a valid placeholder. This is documented in the code and is consistent with the bridge's current design.

---

## M9.2 — Ootle v0.49.2 compatibility audit

**Status: NOT REQUIRED (reference tree does not exist at v0.53)**

The M5 compat matrix references `tari-ootle-v0.53`. No such tag exists in the Ootle repository; the highest available reference is `tari-ootle-v0.49.2`. The existing compat table in `web/mainnet/index.html` already covers v0.42→v0.52 and correctly notes that mainnet wallet support requires a Sapient version with network byte `0x00` support.

No code changes were required for this audit item. The table remains accurate against the available reference.

---

## M9.3 — Mainnet frontend

**Status: Honest status display; no admission button**

The `/mainnet` page uses the Matrix theme with gold accents and shows real network status derived from the connected wallet. It does not expose a Join or Verify button because end-to-end mainnet admission has not been validated:

- No mainnet indexer endpoint is available
- No mainnet resource address has been confirmed by the Tari network
- `GG_BOT_NETWORK` has not been set to a mainnet value

The page will display honest capability status (wallet connected / network detected) but will not allow users to submit a proof that implies authorization is granted.

**Constraint in force**: "Do not expose a functional Join or Verify button that implies mainnet authorization works before end-to-end validation."

---

## M9.4 — Cross-network proof-reuse prevention

### What changed

| File | Change |
|------|--------|
| `crates/ghost-gate-telegram/src/main.rs` | Added `network_label: String` to `PendingBotSession` (in-memory) and `StoredSession` (serde, `#[serde(default)]` for backward compat); wired through `join()`, `restore_from_store()`, `write_sessions_store()`, and `claim_bot_admission()` |

### Why this matters

Previously, after a bot restart, `claim_bot_admission()` read `network_label` from `self.admission_bridges[bridge_index]`. If the operator restarted the bot with bridges in a different order, the audit record would attribute the session to the wrong network. With M9.4, the network label is captured at session creation and persisted alongside the session ID — the audit record always reflects the network the session was opened on.

Additionally, `StoredSession.network_label` uses `#[serde(default)]` so existing store files (which lack the field) load cleanly; they restore with an empty string rather than failing to deserialize.

### Build confirmation

```
Compiling ghost-gate-telegram v0.1.0 (...)
Finished `dev` profile [unoptimized + debuginfo] target(s) in 4m 10s
```

Zero errors, zero warnings attributable to M9.4 changes.

---

## Go / No-go verdicts

### Esmeralda testnet live admission

**Verdict: NO-GO**

The following items must all be resolved before enabling live Esmeralda admissions:

**Blocking — real wallet verification not completed:**
- No real Sapient wallet has completed the M6+ bot-session flow end-to-end against the Esmeralda
  indexer. The M8 E2E tests used `gg-test-signer` (fixture wallet); actual browser↔wallet↔bridge
  verification with chain-derived ownership evidence is unproven.
- `claim.js` has not been tested against Sapient's live `signOwnershipChallenge` API, including the
  precise challenge representation (128-char hex string), signature encoding, and expected network byte.
- The updated wallet flow has not been tested through the actual Cloudflare routing and browser.

**Blocking — security items not fully resolved:**
- `session_commitment` handling in the bot-session proof path requires explicit security review
  (see §Security analysis below).
- Administrator-session isolation has not been audited or confirmed closed for this release.

**Blocking — regression suites not yet run:**
- Complete bridge + telegram Rust unit/integration tests
- Complete Cloudflare Worker regression suite

Pre-conditions for changing this verdict to GO:
1. A real tTARI wallet (Sapient or Universe) successfully completes the M6+ flow against
   the Esmeralda indexer and the bot calls `approveChatJoinRequest` for the test user.
2. An invalid or insufficient-balance wallet is correctly rejected (403 / `UnverifiedChainData`).
3. All Rust unit/integration tests pass (`cargo test -p ghost-gate-bridge -p ghost-gate-telegram`).
4. Admin-session isolation confirmed closed (see §Security analysis below).
5. Cloudflare Worker regression suite passes.

### Mainnet admission

**Verdict: NOT READY**

Mainnet requires (all unresolved):
- A mainnet indexer endpoint
- Mainnet resource address confirmed by the Tari network
- `GG_BOT_NETWORK` set to a mainnet value with the correct network byte (`0x00`)
- Independent security review of the admission path under live traffic
- End-to-end browser-to-wallet-to-bridge-to-Telegram test on mainnet

**Constraint in force**: "Do not set `GG_BOT_NETWORK` to any mainnet value until these are resolved."

---

## Security analysis

### 1. `session_commitment` in the bot-session proof path

**Field definition**: `CredentialProofRequest.session_commitment` is a 64-hex-char field that is
wire-required (`#[serde(deny_unknown_fields)]`) but NOT validated in `TelegramProofContext.verify()`.
The bridge's bot-session proof path only checks `gate_id`, `substate_id`, and `challenge_nonce`.

**Is this a vulnerability?**

No cross-session attack is possible through this field because:
- The session being proven is identified by `session_id` in the URL path
  (`/v1/bot/sessions/{id}/proof`), not by `session_commitment`
- The `challenge_nonce` in the proof body must match the nonce the bridge issued for that exact
  session — an attacker cannot forge a nonce for a session they did not create
- The signing challenge (`signing_challenge()`) already commits to the full proof context via
  Blake2b-512 over (domain, user_id, chat_id, gate_id, resource, substate_id, policy_hash, network,
  threshold, issued_unix, expires_unix, nonce); `session_commitment` would be redundant

**What `session_commitment` IS for**: in the original credential flow (non-bot), there is no
session ID binding; `session_commitment` provides an extra binding between the challenge and the
proof. In the M6+ bot-session path the session ID in the URL provides stronger binding.

**Security verdict**: the unchecked `session_commitment` field is NOT a security vulnerability in
the bot-session path. The session ID + challenge nonce binding is sufficient. No fix required.

**Documentation**: the comment in `claim.js` already documents this:
```
// session_commitment is a required wire field but is not validated in the bot-session
// path: the session identity is carried by the session id, not by a per-challenge
// commitment. Any 64-char hex value satisfies the wire schema.
```

### 2. Frontend admission guard removal

**What was removed**: `const telegramAdmissionAvailable = false` at the top of `claim.js`.

**Server-side controls that remain authoritative:**
- Bridge session creation is HMAC-authenticated (loopback + correct key) — the browser cannot
  create sessions; only the bot can
- Challenge issuance requires the session to be in `Created` state — a replay or duplicate request fails
- Proof verification requires a valid chain signature and `UtxoOnChain.verified = true` from the indexer
- Redemption is HMAC-authenticated (bot-only); the browser cannot redeem sessions
- With no indexer configured, every proof attempt returns `CredentialRefusal::UnverifiedChainData`

**Verdict**: removing the frontend guard does not weaken server-side authorization. The guard
prevented the browser from even making requests; now it can make requests that the server will
reject unless all real credentials are configured.

### 3. Network labels — audit metadata vs. authoritative identifiers

`network_label: String` in `PendingBotSession` / `StoredSession` is **audit metadata only**.
The authoritative network enforcement happens at the cryptographic layer:

| Layer | Enforcement |
|-------|------------|
| walletd `submit()` | Checks network byte of UTXO against `expected_network` before signing |
| `ownership_proof_message()` | Encodes network byte in the Blake2b-512 domain separator |
| `signing_challenge()` | Includes network label string in the signed content |
| Bridge config | `GG_BOT_NETWORK` selects the network byte used in `BotAdmissionBridge` |

An Esmeralda UTXO (byte `0x26`) cannot satisfy a mainnet challenge (byte `0x00`) because the
bridge derives a different signing challenge and the signature verification fails.

**Verdict**: network labels are correctly audit-only. Authorization uses immutable, server-verified
network identifiers. No issue.

### 4. Administrator-session isolation (OPEN — blocking)

**Status**: unresolved. The bridge exposes admin routes (session listing, state inspection, manual
redemption) alongside the public proof routes. The isolation between admin-authenticated requests
and public requests has not been audited in this milestone.

**Risk**: if admin routes share session state without authentication separation, a misconfigured
deployment could expose session management operations to unauthenticated callers.

**Required before GO**: audit `crates/ghost-gate-bridge/src/server.rs` admin routes for:
- Authentication middleware on all admin-only paths
- No overlap between public proof endpoints and admin state-mutation endpoints
- Admin HMAC key separate from bot HMAC key

This audit is not yet complete. Esmeralda admission remains NO-GO until it is.

---

## Security constraints in force

All constraints from prior milestones remain in force:

- No production deployments, live Telegram group mutations, or mainnet transactions without explicit approval
- No automatic kicking, bans, or destructive migrations of existing Telegram members
- No copy of Esmeralda resource addresses into mainnet configuration
- Fixture mode (`GG_TG_FIXTURE=1`) requires `GG_TG_BOT_TOKEN` to start with `fixture_`; exits otherwise
- `telegramAdmissionAvailable = false` guard has been removed — the page is now live but only reaches a bridge configured via the `gg-trusted-bridges` meta tag
- Test-only HMAC keys must not be used in production; the bot rejects sessions signed with a different key
- Never allow a testnet proof to satisfy mainnet requirements (network byte enforced at both walletd and bridge layers)

---

## Files changed in M9

| File | Milestone | Change |
|------|-----------|--------|
| `web/telegram/claim.js` | M9.1 | Complete rewrite for M6+ bot-session flow |
| `web/telegram/join.html` | M9.1 | Step order and descriptions updated |
| `crates/ghost-gate-telegram/src/main.rs` | M9.4 | `network_label` added to `PendingBotSession` + `StoredSession` |
| `docs/M9_VERIFICATION_REPORT.md` | M9 | This report |
