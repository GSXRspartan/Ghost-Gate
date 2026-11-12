# M12 — Connect the Verified Sapient Proof to Real Authorization

Status: **IMPLEMENTED, process-level verified.** The M11 credential-only Sapient verification
(PROOF VERIFIED — SESSION NOT ISSUED) is now wired into the existing M6–M8 durable Telegram
authorization system. A real browser session-backed proof is the remaining step and requires the
operator's wallet.

## 1. The M11 positive wallet proof — audit record

The operator connected a real Sapient wallet on Esmeralda through the local Lab and received
**PROOF VERIFIED — SESSION NOT ISSUED**. The exact code path that ran, in order:

1. **Challenge issuance** — `POST /gate/esme/challenge` → `server.rs::issue_challenge` →
   `gate_registry::issue_challenge` → `ChallengeBook::insert_bound`. The challenge bound: gate
   (credential-only sentinel `component_0000…0000`), resource `resource_0101…0101` (native tTARI,
   independently verified against upstream), network 38 (Esmeralda), fresh 32-byte nonce,
   session commitment, threshold 100000000, relying site `http://127.0.0.1:7799`,
   expiration (epoch + wall clock).
2. **Ownership signature** — the page passed `challenge_nonce` to `tari_signOwnershipChallenge`;
   the wallet signed `ownership_proof_message` (Blake2b-512, domain
   `com.tari.paylink.ownership_proof.v1.v1`, network byte, resource string, substate string,
   challenge string) with the output's spend key.
3. **Chain read** — `POST /gate/esme/credential` → `CredentialVerifier::verify` →
   `JsonChainReader::utxo` → live indexer `GET /substates/{id}` → **M10 CBOR decoder**
   (`read_utxo_cbor`, positional-array schema, validated against two real indexer blobs).
4. **Verifier checks, completed in order** (`credential.rs`):
   a. challenge live, session-bound, minted by this bridge (`policy::validate_prove_request`);
   b. substate fetched from the indexer, never from the page;
   c. output is a UTXO of the gate's resource and still UP (unspent);
   d. `minimum_value_promise` read from chain ≥ threshold (100000000 ≥ 100000000);
   e. spend authorisation is a key path and the Schnorr signature verifies against the
      on-chain `auth.Key` — never the page-supplied public key;
   f. frozen refusal (M10) would have fired here; the output was not frozen.
5. **Receipt** — `CredentialReceipt { gate_id, attested_minimum: 100000000,
   required_minimum: 100000000, substate_id, mode: "credential" }`; challenge retired.

No session was issued because the local bridge is not registry-backed — the honest
credential-only outcome, and the M11 milestone evidence.

## 2. What M12 changed (no cryptography rewritten)

Every existing component is reused: `TelegramProofContext`, `AuthorizationCoordinator`,
`bot_session_interface`, the HMAC bot transport, `AuthorizationState`, and the durable SQLite
store. Three gaps were closed and one identity was made configurable:

### 2.1 The claim POST — the missing link
`claim.js` verified the proof and then *assumed* "the bot polls the bridge and auto-redeems."
No such loop exists: the only redemption trigger is the bot's `/claim` endpoint receiving
`{bot_session_id}`. A verified session would have sat `Verified` forever. claim.js now POSTs
the claim (step 5) and reports the bot's refusal honestly if the admission cannot complete.

### 2.2 The resume path — no new shield
The M12 test uses the operator's **existing qualifying UTXO**. claim.js now resumes from the
remembered output (`gg-last-output`, written by the Lab and by the join flow's own shield):
no shield transaction, no fee, no spend. The challenge is bound to the existing output; the
bridge re-checks existence, unspent status, floor, frozen state and ownership against chain
state, so a stale or spent id fails exactly as a fresh one would. `ChallengeIssued` now
carries `resource` so the resume path (which never ran a shield in that page session) can
still name the resource when signing.

### 2.3 The verify URL — the right page
The bot's Esmeralda verify URL pointed at `/lab`, which cannot read `bot_session` (its
credential route is session-free by design). It now points at `/telegram/join`, the M6+
bot-session page.

### 2.4 The relying site — operator-configured
The `vip.example` placeholder in `parse_gate` was replaced by `GG_BRIDGE_RELYING_SITE`
(required when env gates are configured, validated against the permitted origins, ≤ 64 bytes,
stamped into every minted challenge). Regression tests pin both gate kinds and the oversize
refusal. `GG_BRIDGE_RELYING_SITE` is now also required by the M8/M12 e2e bridge env.

### 2.5 Frozen fixtures
`GG_FIXTURE_UTXO` entries accept an optional 4th field `frozen`, so the e2e suite can exercise
the M10 frozen refusal at process level.

## 3. Test evidence

**Unit (cargo test -p ghost-gate-bridge --lib): 211 passed** — including the new
`a_credential_only_lab_signature_cannot_be_replayed_into_a_telegram_session`: a signature
framed over the raw nonce (what the M11 Lab flow signs) is refused by the Telegram path even
with the correct key, because the Telegram challenge is a different, domain-separated string
(`ghost-gate/telegram-ownership/v1` over user/chat/gate/resource/substate/policy/network/
threshold/timestamps/nonce). The session stays `Created`; nothing becomes redeemable.

**Telegram crate: 40 passed.** **Node (cloudflare): 86 passed + 1 skipped.**

**Process-level e2e (`scripts/test-m12-e2e.sh`): 7/7** — real compiled bridge + bot +
`gg-test-signer` against the HTTP Telegram fixture:

| # | Case | Result |
|---|------|--------|
| T5 | session creation with a chat differing from policy → refused (403) | PASS |
| T6 | happy path: proof verified → claim granted → `approveChatJoinRequest` called | PASS |
| T9 | duplicate claim on a redeemed session → refused | PASS |
| T7 | output below threshold → `BelowThreshold` refusal naming the floor | PASS |
| T8 | frozen output → `Frozen` refusal (M10, process level) | PASS |
| T11 | lab-framed signature replay → `signature does not verify` | PASS |

M8 baseline (`scripts/test-m8-e2e.sh`) re-run after the changes: **4/4** (happy path, wrong
key, replayed challenge, restart safety).

Expired-challenge refusal is pinned by unit tests (`TelegramProofContext::signing_challenge`
validates the window; the coordinator refuses on read); the e2e does not sleep 180 seconds to
re-prove it.

## 4. Local Esmeralda admission test mode (running now)

- Bridge: `127.0.0.1:7799`, **live indexer** (`ootle-indexer-a.tari.com`, v0.53.2), credential
  gate `esme` over native tTARI, threshold 100000000, relying site `http://127.0.0.1:7799`,
  bot admission configured (`GG_BOT_*`, chat `-1001234567890`).
- Bot: HTTP fixture mode — simulated Telegram API at `127.0.0.1:7812`, claim listener on
  `127.0.0.1:7808` (matches the join page's `gg-trusted-claims` meta), admission bridge → 7799.
- The Lab's credential-only route continues to work and continues to issue **no** session.
- Nothing touches the real Telegram API; no group membership is changed; no production
  deployment.

## 5. What the browser interaction will do (the remaining step)

1. A fresh `/join` is injected into the fixture Telegram API; the bot mints a session bound to
   the Telegram user + chat (server-side), DMs the verify URL (valid 180 s).
2. The operator opens the URL. The join page (served by the bridge, same origin as the Lab)
   probes Sapient; the **resume path** picks up the M11 output from `localStorage` — no new
   shield, no spend.
3. `POST /v1/bot/sessions/{id}/challenge` → the **Telegram-bound challenge**
   (`ghost-gate/telegram-ownership/v1` over user/chat/gate/resource/output/policy/network/
   threshold/timestamps/nonce). The M11 signature cannot be replayed here — different message,
   and the M11 nonce was never bound to this session.
4. The wallet signs; the page submits the proof; the bridge verifies against the **live
   indexer** (same five checks as M11, plus the stored Telegram identity binding).
5. The page POSTs the claim; the bot redeems (HMAC, single-use, identity from the bridge —
   never from the page) and calls `approveChatJoinRequest` **on the fixture Telegram API**.
6. The fixture records the approval. Real Telegram membership is untouched.

## 6. Remaining security blockers before a controlled live Telegram admission

1. **Session-backed proof with the real wallet** (the step above) has not been performed yet —
   this is the operator's next browser interaction.
2. **Policy hash provenance**: the local test mode pins `GG_BOT_POLICY_HASH` on both sides by
   hand. In production the hash must come from the published registry snapshot on both the
   bridge and the bot, so a hand-set value cannot silently diverge.
3. **Legacy join-token path**: the bot still holds the older `/claim {token, proof_id}` route
   alongside the session flow; the module doc itself records that the accepted-proof receipt is
   not yet bound to the bot-minted join token. Before live admission, decide: disable or bind.
4. **Long-poll production run**: the VPS production bot must be restarted on the new binary
   with `GG_BOT_ESMERALDA_*` configured — operator-approved deployment only.
5. **Mainnet parity**: the mainnet admission bridge (`GG_BOT_MAINNET_*`) is configured but its
   verify page (`/mainnet`) has no bot-session flow yet; mainnet admission stays off until that
   exists (independent-network separation is preserved by the per-network keys and sessions).

## 7. Operator participation — exact steps

1. Say the word; a fresh `/join` is injected and a fresh verify URL is returned (the session
   lives 180 s, so links are minted on demand).
2. Open the URL in the browser where Sapient lives (Chrome, same profile as the M11 test).
3. Approve **only the signature prompt** — the resume path shields nothing. The expected
   wallet prompt is the ownership-signature request showing the challenge string.
4. The page reports each step (output → challenge → sign → verify → claim) and finishes with
   "Verified and admitted — the bot has approved your join request. Check Telegram."
5. The fixture's `/fixture/results` shows the recorded `approveChatJoinRequest`.
