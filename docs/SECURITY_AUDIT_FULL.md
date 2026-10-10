# Ghost Gate full adversarial security audit — October 2026

Scope: the whole system, attacked rather than read. An attacker is modelled as controlling their own
wallet and transaction arguments, their own browser and provider responses, arbitrary public HTTP
requests, malicious asset metadata, request timing, and previously-valid credentials. They do **not**
control the pinned cohort tree, this repository, or the operator's machine beyond what any web page
can reach.

This document is the audit narrative. Per-finding classification with reproduction procedures lives
in `SECURITY_FINDINGS.md`; remediations in `SECURITY_FIXES.md`; the go/no-go decision table in
`SECURITY_RELEASE_GATE.md`. Every claim of "proven" below names the test that proves it.

Companion baselines, preserved:

- `gate3-green` (1a0b2824) — the frozen Gate 3 checkpoint, untouched.
- `audit-baseline` (a9bb600) — pre-audit state: workspace 198 passed, engine `access_rules` 48,
  web provider tests 20, patch verification green.
- The audit is developed on branch `security-audit`.

## 1. Method

Three layers, in increasing trust cost:

1. **Real-engine adversarial tests** (`crates/ghost-gate-tests/tests/adversarial.rs`): the real
   template compiled to real WASM, executed by the real engine with real Ristretto/Schnorr crypto.
   The attacker builds actual forged statements — mutated MVPs, garbage and foreign balance proofs,
   other resources' commitments, invented commitments, duplicate spends — and submits them through
   `prove_access` exactly as a hostile dApp would.
2. **Bridge attack tests** (`ghost-gate-bridge` unit suite): forged HTTP requests against the
   transport policy — rebound hostnames, cross-origin pages, unknown request fields, replayed
   challenges, saturated books.
3. **Source review of everything reachable**, with live-binary verification for transport findings
   (each Host-header and 429 behaviour was exercised against the built binary).

Mocks are used only for parser/API-shape tests (the JS provider suite). No consensus property rests
on a mock.

## 2. The headline question: can a caller forge a `StealthTransferStatement`?

**Verdict: the attack does not work. The consensus boundary is sound, and it is enforced by the
engine, not by wallet software.**

The concern inherited from the previous session was real to raise and wrong in conclusion. The
template's own `find_qualifying_output` checks only the statement's *shape* (inputs present and
key-path, no revealed amounts, exactly one output, a balance proof *present*, output key-spendable,
claimed MVP ≥ threshold). A reader who stops there — as the previous session did — sees no
cryptography and concludes the gate attests whatever the caller claims. But `prove_access` does not
stop there: it then hands the statement to `ResourceManager::stealth_transfer`, which executes the
statement through the engine's native validation in the same transaction:

- **Range proof over claimed MVPs** (`validate_stealth_outputs_statement` → `validate_bullet_proof`):
  the aggregated bulletproof is verified against the `minimum_value_promise` values *read back out of
  the statement*. Mutating the MVP after signing breaks it.
- **Balance proof over the public excess** (`validate_transfer`): `Σinputs − Σoutputs` is signed
  over a message that covers both statements, so a proof made for different values refuses.
- **Input liveness scoped to the gate's resource**: every input is resolved as
  `UtxoAddress::new(GATE_RESOURCE, commitment)`. An output of any other resource does not exist at
  that address.
- **Input authorisation before execution** (`verify_input_authorizations`): the transaction must
  carry the one-time stealth key of each input.
- **Atomicity**: a rejected statement aborts the transaction; nothing is downed, no counter moves,
  no nonce burns.

The eleven reproduction attempts, all through the real engine:

| # | Attack | Result |
|---|---|---|
| 1 | 1-unit holder mutates MVP 0 → 10 000 (the zero-token headline) | **refused** — bulletproof mismatch |
| 2 | MVP lowered then raised in one statement | **refused** — same |
| 3 | `balance_proof: Some(garbage 64 bytes)` | **refused** — balance proof invalid |
| 4 | Balance proof from an honest statement, attached to a mutated one | **refused** — proof/message mismatch |
| 5 | Real output of resource B presented to a gate over resource A, honest proofs, MVP at threshold | **refused** — input resolution (`utxo_A_… not found`) |
| 6 | Invented commitment that exists nowhere | **refused** — input resolution |
| 7 | Someone else's commitment, attacker's signer | **refused** — authorisation |
| 8 | Same commitment twice with a re-signed balance proof | **refused** — `Duplicate input commitment` |
| 9 | Honest path, same engine, same run | **accepted** — control |
| 10 | Challenge answerability after every forgery | **held** — counter 0, nonce unburnt |
| 11 | Attacker's input after a refused forgery | **intact** — spendable again |

Suite: `adversarial.rs`, 11 tests, ~141 s. The engine-level suite (`gate_engine.rs`) already covered
tampered promises, invalid balance proofs, double-spends, replay, and every challenge-binding field;
the adversarial suite adds the zero-token headline, cross-resource substitution, invented
commitments, wrong-signer claims, and the state-preservation assertions.

**Corrected consequence for the product.** The previous session's reasoning had disabled "Mode A"
(consensus proof) in the browser adapters as *unsound*. That reasoning was wrong: forging through a
browser wallet fails at the engine exactly as it fails here. Mode A remains unimplemented for
browsers for a different and narrower reason — a dApp cannot *assemble* a valid statement (it has no
access to input masks or wallet-decrypted values, and wallet-built statements are never exposed to
pages), which is a capability gap with a specified upstream fix
(`PROVIDER_COMPATIBILITY.md` §5), not a soundness gap.

## 3. The bridge and browser surface

Attacks modelled: cross-site requests from any page, DNS rebinding, request forgery with malformed
bodies, replay, concurrent submission, memory exhaustion via unauthenticated routes.

Fixed (details in `SECURITY_FIXES.md`):

- **DNS rebinding → confused deputy (HIGH, fixed).** A rebound hostname made attacker requests
  *same-origin*, so they carried no `Origin` header and passed the allowlist as if they were the
  operator's own curl — letting a hostile page drive the victim's local walletd and spend the
  victim's qualifying output. The bridge now answers only for loopback `Host` spellings; a rebound
  name is 403 on every route, `/health` included. Verified against the built binary.
- **Unbounded challenge book (MEDIUM, fixed).** Minting is unauthenticated apart from transport
  policy; each challenge is held until answered. Capped at 256 live, expired entries pruned on
  insert, saturation answered 429 with the remedy named. (And the plumbing bug that would have
  surfaced this as a generic 500 — `issue_challenge` collapsing all errors into an `Option` — fixed
  so a real limit cannot hide.)
- **Unbounded job list (LOW, fixed).** Same shape, capped at 1 000 with oldest-first eviction.

Reviewed, no finding:

- **CORS**: no `Access-Control-Allow-*` header is ever emitted; the page is same-origin by design.
  Cross-site `fetch` reads are blocked by the browser's own policy; cross-site form-style POSTs
  carry `Origin` and are refused by the allowlist.
- **CSRF**: every state-changing route requires either a body the attacker cannot produce (the
  challenge nonce + session commitment pair, minted per challenge) or an allowed origin; a hostile
  page cannot read the challenge response it forced, and cannot complete a proof without it.
- **XSS**: the two `innerHTML` uses are static templates; all data is set via `textContent`. JSON
  responses are `application/json`; assets carry `X-Content-Type-Options: nosniff`.
- **Request smuggling**: hand-rolled parser accepts exactly one request per connection, reads at
  most `MAX_BODY` (8 KiB) plus header slack, requires `\r\n` framing, and closes after one response
  (`Connection: close`).
- **Oversized/malformed bodies**: bounded reads, `deny_unknown_fields` on every request type, and
  a `400` with the parser's own words for anything else.
- **Challenge entropy**: `random_nonce()` fills from the OS CSPRNG; nonces are public by design
  (single-use tokens, not secrets); uniqueness asserted by a test.
- **Concurrent submission**: one connection at a time behind a mutex; the second submission of a
  consumed challenge sees `AlreadyAnswered` (tested).

## 4. Wallet integration

Audited: the walletd channel (`ghost-gate-walletd`), the three provider adapters, the credential
mode, and the bridge's wallet-facing policy.

Structural properties, each backed by a test:

- **No caller-supplied destinations, amounts, resources or UTXOs reach a wallet.** The bridge asks
  the wallet for `(gate.resource, gate.threshold)` and nothing else (tested); request bodies are
  three fields with `deny_unknown_fields` (tested); the adapters build every parameter from the
  gate registry (tested).
- **Key isolation.** The Rust side never touches key material: `WalletDaemonChannel` holds a client
  and an endpoint; signing happens inside walletd via lock-derived stealth signers (the daemon's own
  rule, quoted in the channel's docs). The browser adapters prompt in the wallet's own UI and the
  page never sees a key, a mask, or a decrypted value.
- **Mode gating is capability-driven and refuses to blur.** No wallet adapter offers both modes
  (tested as the matrix invariant); the walletd adapter's `signChallenge` refuses outright; a
  browser wallet that reports `minimumValuePromise` still gets exactly the credential mode.
- **Malformed provider responses fail closed** (JS suite): a missing `substateId` is an error, a
  `4001` is a declined request, a `4200` capability read is "unavailable", never a silent fallback.
- **No seed/key/balance surface exists.** `GET /wallet/status` returns reachability, default-account
  presence and network byte — nothing else. There is no route that could return a balance or
  inventory; asserted by a route sweep test.

Residual (documented, not fixed — wallet-side by design): the approval screens a wallet shows for
`shield` are the wallet's own responsibility; Ghost Gate's UI quotes the disclosure but the prompt
itself is upstream. A malicious wallet is out of scope everywhere in this design (the threat model
says so explicitly).

## 5. The credential mode

What it proves: that a specific on-chain output exists, is unspent *at verification time*, publicly
commits to at least the threshold, and is controlled by whoever produced a valid ownership signature
over **this bridge's** challenge. What it does not prove: a whole balance, future unspentness, or
anything about who will hold the output a minute later.

Fixed in this audit:

- **Indexer trust (MEDIUM, fixed).** The verifier ignored the indexer's merkle-`verified` flag, so a
  compromised indexer could fabricate a floor/key for a nonexistent output or serve a stale record
  for a spent one. The flag is now carried through and unverified answers are refused (fail-closed).
  Cost, documented: credential proofs are unavailable where proofs are disabled or in the post-epoch
  window; the consensus mode does not touch the indexer at all.

Verified against the listed checklist (each with a test): output existence and unspentness (the
indexer answers a spent UTXO with an error → refusal), MVP read from chain not from the page,
signature verified against the **on-chain** `auth.Key` (a lying `publicKey` field cannot move the
verdict — tested in both directions), byte-exact message framing with the doubled domain suffix
(tested against a hand-hashed stream), wrong-resource refusal before any chain read, wrong-network
refusal via the signed network byte, session binding and expiry via the shared challenge book,
duplicate submission (the challenge is consumed on acceptance), concurrent redemption (serialized
loop), and credential reuse after spending (the unspent check refuses).

Residual, stated rather than softened: the output identifier is public in the receipt and the floor
is public for as long as the output exists; re-using one output across sessions links them. A
committed receipt describes the state at one moment; the site's own session policy governs what
happens after. Deep reorgs between lookup and decision are inherent to L2 finality and are handled
by the site's expiry policy, not by the verifier.

## 6. Upstream Ootle backports

- **GHSA-pp4v-v773-9qxg (empty-proof possession bypass)**: backport active and verified —
  `verify_patches.sh` green (12 files, 0 mismatches), and the backport's own regression
  (`an_empty_proof_cannot_satisfy_a_resource_rule`) passes inside the engine suite's 48.
- **GHSA-rr6w-w4r5-9fcx (published 2026-10-08, after our v0.42 pin; `<= 0.43.0` vulnerable, no
  patched release at audit time)**: unauthenticated dust deposits grow any builtin account's inline
  vault map until its WASM encode OOMs, permanently freezing the account's funds. **Applies to our
  pinned cohort** (`or_insert_with` present, no vault-removal path). Classification: upstream
  availability vulnerability — it bricks accounts network-wide and is **not** a Ghost Gate bypass:
  our proof soundness, replay protection and privacy boundaries are unaffected. Impact on us: the
  walletd proof path pays fees from the user's default account, so a bricked account cannot run
  proofs — the same availability loss every account on the network already faces. Not remediated
  here (a cohort re-pin would discard the pinned, byte-verified v0.42.0 + patch provenance and
  cannot be done safely inside this audit); recorded in the release gate with the recommendation to
  re-pin when upstream ships a fix, re-verify the two patches against the new tree, and re-run the
  full engine suite.

## 7. Game and Telegram boundaries (pre-approval requirements)

Both are being built **only** on the verified boundaries:

- **Game unlocks are server-side decisions.** The page never decides an unlock from local state: it
  renders the bridge's verdict (`/proof/:id/status`, `credential` verdicts), and every unlock it
  shows names the artifact that earned it. Editing browser JS or local storage can only defraud the
  cheater's own screen; it cannot mint a server-side receipt, because receipts exist only after the
  bridge's own verification (consensus mode: engine-committed result; credential mode: on-chain
  checks + signature). Preview mode mints **nothing**: it renders labelled sample states and never
  touches the challenge, proof, or credential routes.
- **No client-side downgrade.** The UI cannot trade a consensus unlock for a credential unlock or
  vice versa; the mode is chosen by capabilities and recorded in the receipt.
- **Telegram**: grants are issued only by the backend, only after a *fresh* bridge-verified proof,
  bound to one Telegram account, with a fixed expiry, and revocable by re-verification failure.
  The bot never asks for seeds, keys, or exact balances; it consumes the same public receipts the
  game consumes. The full design is in the Telegram section of the implementation docs.

## 7b. Live-integration recheck (this phase) — boundaries after the new components

The Haunted Vault game, the Telegram bot and the join page were added after the audit's first pass.
The four fixed vulnerability classes were replayed against the new code, and the shared-localnet
compatibility question was settled from source:

- **Two reintroductions found and fixed** (commit `d2b0455`): the bot's claim endpoint had no Host
  validation and enforced no media type — a `text/plain` CORS-safelisted POST would have skipped
  the preflight that its CORS otherwise gates (CSRF shape); and the bot's pending-token set was
  unbounded (the F-03 class). Both now mirror the bridge's discipline: loopback Host spellings
  only, `application/json` required, tokens capped at 512 — each verified live against the running
  binary and pinned by regression tests.
- **No reintroduction** elsewhere: issuer-origin binding covers the telegram flow (the join page
  mints and answers its challenge from one origin); credential claims need no reconciliation (the
  bridge records the receipt synchronously); the game's poll loops are bounded; preview mode
  touches no proof route (asserted by a web test).
- **The 11 malicious-statement tests re-pinned.** Each refusal reason is now asserted to be exactly
  one of the two intended engine invariants (authorisation failure or input-resolution failure),
  with an XOR so an incidental rejection cannot satisfy the test silently. Verified concretely:
  the wrong-signer case refuses with `RequiredSignatureMissingForStealthUtxo` — the engine's
  key-path scope check, which is the intended boundary, not a side effect.
- **Shared-localnet compatibility, settled from source**: the atomic-swap session's ootle tree is
  the SAME commit as our pin (`a43773e6`), and its `engine`, `runtime`, `consensus`, `state_store`
  and `epoch` crates are byte-identical to ours modulo line endings. The only content differences
  are the three files of our GHSA-pp4v-v773-9qxg backport, which exist only in our tree. Consequences:
  (a) their validators CAN execute Ghost Gate proofs — engine-side MVP verification is native to
  v0.42; (b) our MVP-patched walletd runs standalone against their validators/indexer with an
  independent wallet DB; (c) the GHSA empty-proof gap EXISTS on their network and is a shared-network
  residual — it cannot be remediated without modifying their tree (prohibited), and no Ghost Gate
  proof path depends on Proof-possession rules (the gate's access rules are `allow_all`; its
  threshold is enforced by the engine's stealth validation), so it is not a Ghost Gate bypass.

## 8. What was actually tested (counts at audit close)

| Suite | Count | What it covers |
|---|---|---|
| `ghost-gate-tests` adversarial | 11 | real-engine forgeries, state preservation, honest control |
| `ghost-gate-tests` gate_engine | 30 | engine-level tamper/replay/binding (pre-existing) |
| `ghost-gate-tests` cross_resource | 16 | generalized assets, symbol fakes, class refusals |
| `ghost-gate-tests` mvp_and_shape | 18 | shape rules, MVP binding vs the engine's own validator |
| `ghost-gate-bridge` | 88 | transport policy, rebinding, caps, credential verifier |
| engine `access_rules` | 48 | incl. the GHSA backport regression |
| workspace total | **209+** | everything above plus core/verifier/wallet/walletd |

Second-pass review: a separate adversarial read of the candidate changes was performed after the
first pass; its findings and dispositions are appended to `SECURITY_FINDINGS.md`.
