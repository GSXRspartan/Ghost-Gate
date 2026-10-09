# Threat model

## 0. What each backend actually asserts

Ghost Gate has two backends with different evidence and different claims. Conflating them is the
easiest way to make a false claim about this project, so the boundary is stated first.

### Ootle backend — PROVEN

> A wallet controlled qualifying input(s) for the resource the gate was configured with, and produced a
> consensus-valid private statement attesting at least the configured threshold of that resource for
> this one-time challenge. At the moment a validator committed that transaction.

What it does **not** assert, for any gate, on any resource:

| Not claimed | Why it cannot be |
| --- | --- |
| Total wallet balance | The proof covers the inputs it spent. A qualifying output worth 1,000,000 says nothing about the rest of the wallet. |
| Identity, or that the prover is human | Nothing in a stealth key-path spend identifies a person. |
| Uniqueness / Sybil resistance | One key can mint many sessions across many challenges. |
| Continuous holding | The funds can be spent immediately after the proof commits. A session means "around login time". |
| Ownership of every output in a wallet | Only the inputs named by the statement were under the signer's control. |
| Future balance | A claim about the past, never the present. |
| Immunity to credential sharing after issue | A session is a bearer token. Whoever holds it holds the door open until it expires. |

Two further properties belong to the *mechanism*, not to any user:

- **A proof does not prove the qualifying output belongs to the prover.** A stealth output is spendable
  by whoever holds its spend key, and only the creator learns it. The gate requires the output be
  key-*spendable*; it cannot require it be the caller's. See `docs/PRIVACY_MODEL.md`.
- **The gate does not check the statement's resource, deliberately.** A stealth UTXO's address is
  `(resource, commitment)` and the engine resolves spent inputs under the gate's own resource, so a
  statement naming another resource cannot resolve. The gate leaves that to consensus rather than
  duplicating it.

### Native Minotari XTM backend — DESIGN ONLY

Not implemented, not run, no claims. The design, the source audit, the route comparison and the two
genuine blockers are in `docs/XTM_RESEARCH.md`. In summary: L1 already carries a consensus-enforced
`minimum_value_promise` on a public, hash-committed output, which is the primitive the Ootle path needs
and it exists natively today; but cross-output aggregation is not expressible with consensus-verifiable
L1 primitives, and spend-key challenge signing exists in the library yet is not reachable over the
wallet gRPC. The chosen route is an access-time self-transfer submitted by the bridge, which costs an L1
transaction per access and would therefore be a fallback mode, not the default.

## 1. Malicious prover

Each row: the attack, what it costs, the mitigation, which layer enforces it, and what risk
remains. "Template" means consensus; "Engine" means Ootle's own validation; "Verifier" means the
relying site's code; "Wallet" means walletd.

The layering principle: **the threshold is enforced by consensus.** A relying site that
mis-implements anything can be tricked into a wrong answer; a validator that mis-implements nothing
cannot be. Anything a site decides is a usability matter, not a security matter.

---

## 1. Malicious prover

| | |
|---|---|
| **Attack** | Claim a threshold the prover does not meet. |
| **Consequence** | Unqualified access. |
| **Mitigation** | The promise is a field of the bulletproof statement. A promise above the hidden value cannot verify. |
| **Layer** | Engine — `validate_bullet_proof`. Template refuses `MVP < threshold` first, as a cheap pre-filter. |
| **Residual** | None found. Tested in both directions in `mvp_and_shape.rs`. |

| | |
|---|---|
| **Attack** | Build a valid proof, then raise the public promise. |
| **Consequence** | A 10,000-holder passing as a 50,000-holder. |
| **Mitigation** | The bulletproof attests `value ∈ [MVP, 2^64)`; changing MVP after generation invalidates it. |
| **Layer** | Engine. |
| **Residual** | None. `mutating_mvp_after_proof_breaks_validation`. |

| | |
|---|---|
| **Attack** | Submit a statement spending an output that is already spent. |
| **Consequence** | Double spend; two proofs from one coin. |
| **Mitigation** | Inputs must be live UTXOs; the engine rejects non-existent or spent commitments. |
| **Layer** | Engine — `execute_stealth_transfer`. |
| **Residual** | None. |

| | |
|---|---|
| **Attack** | Spend an input the prover does not own, by guessing or reusing a public spend key. |
| **Consequence** | Spending someone else's Tari. |
| **Mitigation** | The UTXO's committed `spend_key` becomes a badge that must be in the transaction's auth scope, i.e. signed for. |
| **Layer** | Engine — `verify_input_authorizations`. |
| **Residual** | None. Not a Ghost Gate property; it is the stealth primitive's. |

| | |
|---|---|
| **Attack** | Fabricate a statement that passes the template's shape checks but proves nothing. |
| **Consequence** | Access without funds. |
| **Mitigation** | The template's checks are necessary, never sufficient. The engine then verifies the balance proof and the bulletproof regardless. |
| **Layer** | Engine. |
| **Residual** | None. This is why a template check passing is never treated as a verdict. |

| | |
|---|---|
| **Attack** | Grief the gate with a huge number of inputs to make each proof expensive. |
| **Consequence** | Validator load; fee cost borne by the prover. |
| **Mitigation** | `MAX_TRANSFER_INPUTS` bounds the count (Engine/Wallet). Range-proof aggregation is capped at `MAX_LAZY_BP_AGG_FACTORS` and must be a power of two. |
| **Layer** | Engine and wallet. |
| **Residual** | A prover can still spend their own fee. Not a DoS on the gate. |

---

## 2. Challenge and replay

| | |
|---|---|
| **Attack** | Redeem one committed proof for multiple sessions. |
| **Consequence** | A captured proof becomes a reusable credential. |
| **Mitigation** | Two independent gates. The nonce is burnt in the gate's component state on chain, so a replay finds it gone. Off chain, `ChallengeBook::consume` removes it. |
| **Layer** | Template (consensus) and verifier. |
| **Residual** | Two layers means either alone is insufficient. |

| | |
|---|---|
| **Attack** | Predict a challenge nonce. |
| **Consequence** | Pre-emptive proof, defeating access-time binding. |
| **Mitigation** | 32 bytes from the OS RNG. |
| **Layer** | Verifier. |
| **Residual** | A weak RNG would defeat this. Not a protocol property. |

| | |
|---|---|
| **Attack** | Reuse a challenge issued for site A at site B. |
| **Consequence** | A proof for one relying site valid at another. |
| **Mitigation** | The challenge names its `relying_site`, compared against the gate's configured value. |
| **Layer** | Template. |
| **Residual** | Two sites under the same operator share the site identifier by choice. |

| | |
|---|---|
| **Attack** | Lift a proof into a different browser session. |
| **Consequence** | Session hijack via a copied transaction. |
| **Mitigation** | `session_commitment` is checked on chain against the gate's configured value, and again off chain when redeeming. |
| **Layer** | Template and verifier. |
| **Residual** | A malicious wallet controls its own browser and can produce any commitment it likes; the binding stops *lifting*, not a compromised endpoint. |

| | |
|---|---|
| **Attack** | Answer a challenge long after it was issued. |
| **Consequence** | A stale proof presented as fresh. |
| **Mitigation** | `expires_epoch` compared against `Consensus::current_epoch()`. |
| **Layer** | Template (consensus), not the site's clock. |
| **Residual** | Within the TTL the user may hold funds and then spend them. Documented in `docs/PRIVACY_MODEL.md`. |

| | |
|---|---|
| **Attack** | Race two redemptions of the same challenge. |
| **Consequence** | Two sessions from one proof. |
| **Mitigation** | `ChallengeBook::consume` removes the entry before the session is returned, so the second call finds nothing. |
| **Layer** | Verifier. |
| **Residual** | The verifier is single-process. A multi-instance deployment needs shared storage; noted below. |

| | |
|---|---|
| **Attack** | Lower a challenge's threshold and redeem it at a higher gate. |
| **Consequence** | Buying a cheap challenge once and reusing it. |
| **Mitigation** | The challenge's threshold must equal the gate's policy threshold. |
| **Layer** | Template. |
| **Residual** | None. |

---

## 3. Substitution

| | |
|---|---|
| **Attack** | Redeem a challenge at a different gate. |
| **Consequence** | Satisfying a lenient gate to unlock a strict one. |
| **Mitigation** | `challenge.gate` compared against `CallerContext::current_component_address()`. |
| **Layer** | Template. |
| **Residual** | None. Self-address binding, no stored address needed. |

| | |
|---|---|
| **Attack** | Present a proof for a different resource. |
| **Consequence** | Satisfying a 10,000-of-cheap-token gate to unlock a 10,000-TARI gate. |
| **Mitigation** | `challenge.resource` compared against the gate's policy, and the engine resolves the transfer against that resource, so a commitment from another resource is not a UTXO of this one. |
| **Layer** | Template and engine. |
| **Residual** | None. |

| | |
|---|---|
| **Attack** | Claim a different network. |
| **Consequence** | A mainnet proof used for a testnet gate, or the reverse. |
| **Mitigation** | The challenge's network byte is compared against the byte the gate was deployed for, as a constructor argument rather than a compile-time constant. |
| **Layer** | Template — partially. |
| **Residual** | **Real gap.** No template can observe the network (`V042_SOURCE_TRACE.md` finding 31). This catches a prover and gate *disagreeing*; it cannot catch a transaction admitted on the wrong chain. The validator is the layer that actually enforces this, and it is outside Ghost Gate. |

---

| | |
|---|---|
| **Attack** | Redeem a proof at a gate over a different asset, using funds from an asset you hold. |
| **Consequence** | Holding 1 token of a worthless asset satisfies a gate demanding 1,000,000 tTARI. |
| **Mitigation** | None is needed in the gate, and none is attempted there. A stealth UTXO's on-chain address is `(resource, commitment)`, and the engine resolves every spent input under the *gate's* resource address, so a first-asset output submitted to a second-asset gate resolves to a UTXO that does not exist. The gate never inspects the statement's resource, and deliberately so. |
| **Layer** | Ootle engine. |
| **Residual** | None for the threshold itself. A relying site that displays a threshold against the wrong resource would confuse a user without weakening consensus — so a site must read `GhostGate::resource` from chain, and never from a caller-supplied symbol. Covered by `cross_resource.rs::a_statement_spending_another_resource_is_refused_even_when_the_challenge_agrees`. |

---

## 4. Output-shape attacks

| | |
|---|---|
| **Attack** | Two qualifying outputs, so "the proof output" is ambiguous. |
| **Consequence** | A relying site picking the wrong one, or a prover smuggling value past a check. |
| **Mitigation** | Exactly one output required. Ambiguity is refused, not resolved. |
| **Layer** | Template. |
| **Residual** | None. |

| | |
|---|---|
| **Attack** | A revealed output alongside the qualifying one, publishing an exact amount. |
| **Consequence** | The user's balance becomes public while they believe it is not. |
| **Mitigation** | `revealed_output` must be absent, and `revealed_input_amount` must be zero. |
| **Layer** | Template. |
| **Residual** | None. |

| | |
|---|---|
| **Attack** | A qualifying output locked in a condition tree rather than held by a key. |
| **Consequence** | Passing the gate with funds a predicate can move, and a public beacon that persists. |
| **Mitigation** | `spend_key().is_some()` required. Script-only is refused. |
| **Layer** | Template. |
| **Residual** | The template cannot verify the output belongs to *this* prover — see below. |

| | |
|---|---|
| **Attack** | A key-path output whose spend key the prover does not hold. |
| **Consequence** | Passing the gate with funds they immediately cannot access. |
| **Mitigation** | **None available.** A stealth output is spendable by whoever holds its spend key; the engine does not verify the creator keeps it. |
| **Layer** | — |
| **Residual** | **Accepted.** A prover who destroys their own access gains nothing but loses their funds. Not a security issue against the gate. Recorded because it bounds the "self-owned" language: the product says *key-spendable*, not *yours*. |

---

## 5. Malicious relying site

| | |
|---|---|
| **Attack** | Reinterpret a valid proof to grant more than it says. |
| **Consequence** | Access without funds, from the site's own bug. |
| **Mitigation** | The site's `qualify` call is the same function the template runs (`ghost-gate-core`). The site cannot accept what consensus would reject. |
| **Layer** | Shared code. |
| **Residual** | The site could ignore its own result and grant access anyway. That is a broken site, not a broken protocol — Ghost Gate cannot prevent a site from lying about what it did. |

| | |
|---|---|
| **Attack** | Grant access without ever checking a proof. |
| **Consequence** | A gate with no security. |
| **Mitigation** | Out of Ghost Gate's control. |
| **Layer** | — |
| **Residual** | Documented: Ghost Gate is infrastructure a site *may* use correctly. |

| | |
|---|---|
| **Attack** | Record which users passed. |
| **Consequence** | De-anonymisation of gate users by the relying site. |
| **Mitigation** | The protocol stores no user data, and the site has no need to: a session is a bearer token with no identity attached. |
| **Layer** | Design. |
| **Residual** | **The site can correlate issuance, submission and redemption by timestamp** and thereby link a browser to a transaction. Not preventable by any protocol. See `docs/PRIVACY_MODEL.md`. |

---

## 6. Malicious backend / indexer

| | |
|---|---|
| **Attack** | Report a pending transaction as committed. |
| **Consequence** | Access before the funds ever moved. |
| **Mitigation** | The verifier distinguishes `Pending`, `Committed { accept: false }` and `Rejected`, and grants only on `Committed { accept: true }`. The finality evidence is an argument, so a caller cannot accidentally pass "submitted" for "committed". |
| **Layer** | Verifier. |
| **Residual** | A malicious backend can lie to itself. |

| | |
|---|---|
| **Attack** | Forge a receipt. |
| **Consequence** | Access without a transaction. |
| **Mitigation** | A receipt is read from the transaction's own result and matched against a challenge the site issued. A forged one names a nonce the site never issued. |
| **Layer** | Verifier plus consensus state. |
| **Residual** | A compromised validator could lie about finality. Outside scope. |

| | |
|---|---|
| **Attack** | Withhold a committed proof so a user cannot log in. |
| **Consequence** | Denial of service against one user. |
| **Mitigation** | None needed — the user can request a fresh challenge. |
| **Layer** | — |
| **Residual** | A determined backend can deny service indefinitely. Same as any identity provider. |

---

## 7. Frontend and session attacks

| | |
|---|---|
| **Attack** | CSRF against the redeem endpoint. |
| **Consequence** | An attacker redeems a victim's proof into their own session. |
| **Mitigation** | **Not yet implemented.** Required before any deployment: SameSite session cookies, a per-request CSRF token, and strict Origin checking. |
| **Layer** | Verifier (pending). |
| **Residual** | Open. Listed here rather than glossed over. |

| | |
|---|---|
| **Attack** | XSS reading the session or the challenge. |
| **Consequence** | Session theft. |
| **Mitigation** | **Not yet implemented.** Required: no `innerHTML` for untrusted content, a strict CSP, and `HttpOnly`/`Secure`/`SameSite` cookies. |
| **Layer** | Frontend (pending). |
| **Residual** | Open. |

| | |
|---|---|
| **Attack** | Session fixation: plant a session id before the user authenticates. |
| **Consequence** | The attacker's session becomes the user's. |
| **Mitigation** | The session id is server-generated and rotated on proof acceptance, not taken from the client. |
| **Layer** | Verifier (partial — `AccessSession.id` is supplied by the caller). |
| **Residual** | A caller that reuses an id breaks this. Needs a server-side generator. |

| | |
|---|---|
| **Attack** | Challenge fixation: plant a challenge so the user's proof binds to the attacker's challenge. |
| **Consequence** | The attacker's site receives the credential. |
| **Mitigation** | The challenge names its `relying_site`, and the gate is configured for one site, so a foreign challenge is refused on chain. |
| **Layer** | Template. |
| **Residual** | If the victim's Origin is compromised, this is not enough. That is a browser problem. |

| | |
|---|---|
| **Attack** | Origin confusion: redeem a proof at a different origin. |
| **Consequence** | Cross-site credential use. |
| **Mitigation** | The gate's `relying_site` is fixed at construction. |
| **Layer** | Template. |
| **Residual** | Two origins under one site identifier share the gate by configuration. |

---

## 8. Wallet and provider

| | |
|---|---|
| **Attack** | A malicious wallet reports a false balance to the user. |
| **Consequence** | The user approves a proof without knowing what it costs. |
| **Mitigation** | Out of Ghost Gate's control. The UI must show the semantic explanation (`docs/GATE4_RESULTS.md`). |
| **Layer** | Wallet / frontend. |
| **Residual** | A malicious provider can lie about anything. |

| | |
|---|---|
| **Attack** | A wallet exports spend keys to a third party. |
| **Consequence** | Total loss of the stealth property. |
| **Mitigation** | Ghost Gate never requests one. The RPC flow keeps every key inside walletd; `derive_stealth_signers` derives signing keys *from the wallet's own locks*, explicitly "never from the caller". |
| **Layer** | Design. |
| **Residual** | Gate 3 must demonstrate this holds end to end, not just assert it. |

| | |
|---|---|
| **Attack** | A wallet substitutes a different resource or threshold. |
| **Consequence** | A proof that does not mean what the user approved. |
| **Mitigation** | The gate compares the challenge's resource and threshold against its own policy on chain. A substituted statement is refused regardless of what the wallet claimed. |
| **Layer** | Template. |
| **Residual** | None. |

| | |
|---|---|
| **Attack** | A chain observer correlates a prover's proofs by which UTXO each one spent. |
| **Consequence** | Repeated access to a site becomes a linkable pattern, even though each proof is individually unlinkable to a balance. |
| **Mitigation** | *Not* addressed by this design, and stated rather than glossed: a stealth output's **address** is `(resource, commitment)`, so the output spent by a proof is public on chain. The adapter spends the **smallest** qualifying output, which limits how much is consolidated, but that is a heuristic about the shape of the disclosure — it is not a guarantee. A proof that spends a fresh output each time would be stronger and requires wallet-side UTXO management this project does not have. |
| **Layer** | Protocol, not bridge. |
| **Residual** | Present and documented. The privacy claim this project makes is narrower and specific: **the relying site** cannot learn which output was spent, what it was worth, or what else the wallet holds. No UTXO identifier crosses the bridge API in either direction, asserted by a test over all eight routes. |

---

## 8b. What a relying site is required to do

Consensus decides whether a proof *qualifies*. It does not decide whether a proof should open a door.
That second decision is entirely the site's, and a site that skips any of the following converts a
threshold proof into a weaker thing than it looks like.

| Requirement | If skipped |
| --- | --- |
| **Generate cryptographically unpredictable nonces** | A predictable nonce lets an attacker pre-mint a statement for a challenge nobody asked for, and replay the gate's own answer to a victim. |
| **Enforce an expiry, and answer challenges in the same epoch window the gate allows** | A challenge answered weeks later is a claim about the past. `docs/PRIVACY_MODEL.md` explains why the session TTL is deliberately longer than the challenge TTL, and why both are bounded. |
| **Bind the challenge to gate, resource, threshold, network, site and session** | A proof minted for one gate becomes a key to another. The gate checks the first four; the last two are the site's alone. |
| **Verify the committed result, never a submission response** | `transactions.submit` returning 200 means the node accepted the transaction for sequencing. It means nothing about whether a validator executed it, whether the template accepted it, or whether the nonce is burnt. Read the committed receipt and the gate's own state. `ghost-gate-verifier::observe_and_authorize` grants only on `Committed { accept: true }`. |
| **Consume the challenge exactly once, and only on acceptance** | Two sessions from one proof. The gate's burnt-nonce state prevents this at consensus; a site that consumes on *failure* turns a user's mistake into a support ticket instead. |
| **Issue short-lived sessions** | "Proved control at login" quietly becomes "is logged in", which is a different and much stronger claim. |
| **Retain no unnecessary wallet metadata** | A site that stores the user's UTXO identifiers or transaction history has built a profile the product exists to avoid making easy. |
| **Render the resource address, not a symbol** | A site showing `GHOSTTEST` while the gate watches `resource_...` is showing the wrong asset, and no consensus rule will catch it. |
| **Say that the interaction is public** | The transaction, its timing and its committed floor are on chain. A UI that omits this misrepresents the product. |

## 9. Chain-level

| | |
|---|---|
| **Attack** | Reorg after the site granted access. |
| **Consequence** | A session granted on a proof that is no longer canonical. |
| **Mitigation** | The verifier requires `Committed`, and a well-configured site waits for finality depth appropriate to its risk. |
| **Layer** | Verifier + consensus. |
| **Residual** | **Open.** Finality policy is site-specific and not yet implemented. Documented rather than assumed. |

| | |
|---|---|
| **Attack** | A validator accepts a transaction the others reject. |
| **Consequence** | Split view of who qualified. |
| **Mitigation** | Deterministic execution: every validator runs the same template over the same inputs. |
| **Layer** | Consensus. |
| **Residual** | A consensus-level divergence is out of scope. |

| | |
|---|---|
| **Attack** | Testnet/mainnet confusion. |
| **Consequence** | Users proving against the wrong chain. |
| **Mitigation** | See substitution row 3 — weaker than intended. |
| **Layer** | Template, partial. |
| **Residual** | **Real gap.** The gate's network check is a constant comparison. A deployment must additionally verify the gate component address it talks to matches the expected chain. |

---

## 10. Denial of service and cost

| | |
|---|---|
| **Attack** | Flood a gate with proofs to inflate its state. |
| **Consequence** | Growing `burnt_nonces` map; higher per-transaction cost for everyone. |
| **Mitigation** | Input and output counts are bounded by the engine's stealth limits. |
| **Layer** | Engine. |
| **Residual** | **The nonce map grows without bound.** Each proof adds one entry that is never pruned. Acceptable for a contest MVP over a short window; a long-lived gate needs expiry-based pruning, which means storing the expiry alongside the burn epoch. Tracked, not solved. |

| | |
|---|---|
| **Attack** | Fee griefing: manipulate the fee market so proofs become unaffordable. |
| **Consequence** | The gate is unusable in practice. |
| **Mitigation** | None available at the protocol level. |
| **Layer** | — |
| **Residual** | Accepted. Anyone can also simply not use the gate. |

---

## Open items, stated plainly

1. **CSRF, XSS, session-rotation protections** are required before deployment and not yet written.
2. **Finality depth policy** for the relying site is unspecified.
3. **Nonce map pruning** is not implemented.
4. **Network binding** is a constant comparison, weaker than the design intended.
5. **`binding_hash` is FNV-1a**, not SHA-256. It binds public fields and is not a security
   boundary — the single-use guarantee is the on-chain burn — but it should be replaced before
   anyone treats a challenge commitment as tamper-evident. The type is named so nobody mistakes it
   for a cryptographic hash.
6. **Gate 3 is green, but the live wallet path is unrun.** `@ghost_gate` passes on localnet
   (2 scenarios, 48 steps). The bridge's `WalletChannel` implementation
   (`crates/ghost-gate-walletd`) compiles and is unit-tested, but **no proof has been completed
   against a live `walletd`**, because this environment has none to point at. Gate 4's manual
   six-case flow is therefore still unperformed. See `docs/GATE4_RESULTS.md`.
7. **Wallet-selected inputs are refused, not implemented.** `InputChoice::WalletSelected` returns
   `WalletSelectionUnsupported` before any wallet call, because the engine resolves a spent input
   under the gate's resource and refuses a transaction that does not declare every substate it
   spends — so a freely-chosen input cannot be built into a valid transaction. The adapter instead
   qualifies the gate resource's own unspent outputs locally, which keeps every identifier inside
   the local bridge. The missing capability is a wallet-side RPC that reports the inputs it *would*
   select without building a statement; that is a wallet change, not a protocol change. No engine
   check is weakened to close this gap.
8. **Output-reuse correlation is a residual risk, not a solved one.** See §8: the output a proof
   spends is public on chain, and the "smallest qualifying output" strategy is a heuristic.