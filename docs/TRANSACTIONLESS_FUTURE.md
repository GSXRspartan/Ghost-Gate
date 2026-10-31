# Transactionless Ghost Gate — future research

## The question

Can the property Ghost Gate provides be obtained **without a transaction**?

```text
Prove in zero knowledge that:

  I know/control the current unspent outputs C1...Cn

  AND

  each is a member of the current live state

  AND

  their hidden values sum to >= X

  AND

  the proof is bound to a challenge

WITHOUT

  creating a transaction
  moving the outputs
  publishing an MVP-bearing output
  paying a transaction fee
  writing anything to the ledger
```

## Why V1 uses a transaction anyway

The transaction is a shortcut, not a necessity. Ootle's existing machinery already gives, in one
atomic step:

```text
live UTXO existence      (the UTXO substate is a committed substate)
unspentness               (absent from the transaction's input set)
ownership authorisation   (key-path badge in the auth scope)
value conservation        (balance proof)
range proof enforcement   (bulletproof over [MVP, 2^64))
```

Writing a bespoke zero-knowledge membership argument against the current state root would re-derive
all five. That is a large amount of new cryptography, a new soundness argument, and a new failure
surface, in exchange for saving a fee and avoiding a public transaction.

For a contest MVP, spending a fee is the right trade. Recorded here so the shortcut is not mistaken
for the architecture.

## What a transactionless design would need

### 1. A state root a light client can hold

The prover must convince a verifier that C1...Cn are in the *current* state, not in some historical
state, and not in a state the prover made up.

Relevant Ootle concepts:

| Concept | Where | Assessment |
|---|---|---|
| Substate tree / state tree | `crates/state_tree` | Exists. The engine commits to state transitions; the question is whether a proof about membership in that tree is cheap. |
| State versions | `SubstateVersion`, `StateVersion` | Exist. A proof would need to bind to a specific version, or accept "recent enough". |
| Merkle structures | `crates/state_tree`, `MerkleTree` in `tari_engine_types::stealth` | Exist for spend conditions. Whether a general inclusion proof over UTXO commitments is exposed is **not established**. |
| Authenticated inclusion proofs | `MerkleProof` in `tari_template_lib_types::stealth` | Exist, but scoped to **spend conditions**, not to the state tree. |
| Nullifiers | — | **Not found** in the v0.42.0 tree. A double-spend-proof design would need them. |
| Accumulators | — | **Not found.** |

### 2. Proving membership in a UTXO set without revealing which UTXOs

The naive approach — include C1...Cn and their inclusion proofs — publishes the commitments, which
is exactly what the transaction already publishes anyway. So this part is not the hard part: the
transaction is already revealing about *which* UTXOs it spends.

The hard part is the rest.

### 3. Proving aggregate hidden value >= X

Two components:

- **Individual ranges.** Each commitment must be shown to hide a value in `[0, 2^64)` with an
  aggregate lower bound. Bulletproofs over multiple commitments give exactly this today, which is
  why the transaction works.
- **Sum >= X.** The aggregate is the sum of values that are each hidden. Bulletproofs prove
  non-negativity of a hidden sum, not that a hidden sum exceeds a public constant. Proving
  `Σv_i >= X` for hidden `v_i` needs a different construction.

The `minimum_value_promise` is what makes this trivial **in the transaction case**: the promise is a
*public* lower bound on one output, so the range proof is over `[MVP, 2^64)` and the comparison is
free. Without an output, there is no public promise to compare against.

A transactionless proof would need to show "these hidden values sum to at least X" with no public
per-output bound. Achievable with a suitable ZK argument; not achievable by reusing the existing
bulletproof API unchanged.

### 4. Non-membership, to prevent proving against a spent output

The transaction gets unspentness from the engine refusing an input it has already consumed. A
transactionless proof has no such luxury: a prover could present a valid inclusion proof for an output
that was spent an hour ago.

This is the requirement with no existing answer in the v0.42.0 tree. It needs either:

- **Nullifiers**: a spent-output set committed as an accumulator, with a proof of non-membership.
  Not present in the codebase.
- **A recency window**: accept proofs against recent state versions and accept the resulting race.
  Weaker, and needs a documented staleness bound.
- **A challenge-response scheme where the gate records what it saw**: back to state.

Any of these is new protocol design, not new code.

### 5. Preventing reuse of one proof for many sessions

The transactionless proof would be replayable by construction: nothing is consumed. Binding to a
challenge nonce does not help unless the nonce is consumed somewhere durable — which means either an
on-chain burn (a transaction again) or an off-chain record (which the relying site controls and which
is exactly the centralisation the design is trying to avoid).

A transactionless Ghost Gate is therefore a **one-time-per-session** primitive at best, and a
**replayable credential** at worst, unless challenge state moves somewhere durable.

### 6. Consensus enforcement

V1's decisive property is that the threshold is checked by validators. A transactionless proof is
verified by the relying site. That inverts the entire architecture: the site becomes the authority,
and it must run a verifier it trusts.

A site running its own verifier is fine — self-hosting is a design goal. A site running someone
else's verifier is a centralisation the architecture was meant to avoid.

## Classification

| Requirement | Status |
|---|---|
| State root / substate tree exists | **feasible with existing APIs** — `crates/state_tree` |
| Binding to a specific state version | **feasible with existing APIs** |
| Inclusion proofs over UTXO commitments | **UNKNOWN** — `MerkleProof` exists but is scoped to spend conditions |
| Prove individual hidden ranges | **feasible with existing APIs** — bulletproofs, as today |
| Prove `Σv_i >= X` with no public per-output bound | **significant ZK research** |
| Non-membership / spent-output prevention | **significant ZK research** — nullifiers or accumulators, neither present |
| Durable single-use without a transaction | **currently impractical** — needs a state anchor, which means a transaction or a trusted third party |
| Consensus enforcement | **currently impractical** — moves enforcement off validators and onto the relying site |

## Honest summary

Two of the seven requirements are available today. Three need ZK constructions that do not exist in
this codebase. One is architecturally circular: preventing replay without a transaction requires
somewhere to record the burn.

The transactionless design is a research project, not a V2. If someone builds it, the interesting
version is the one that keeps consensus enforcement — perhaps by proving a batch of access proofs
inside one transaction, amortising the fee across many users while keeping the fee-intent and
single-use properties V1 already has.

That batching idea is more tractable than transactionless, and worth more: a gate that accepts N
challenges and proves all of them in one transaction cuts the per-user fee by N and keeps every
security property intact.

## What would have to be built for the batching variant

Nothing new cryptographically. Only:

- a gate method taking a vector of `(challenge, statement)` pairs;
- a cap on the batch size, bounded by the fee-intent stealth transfer cap (which already exists at
  `crates/engine/src/runtime/impl.rs:4200`);
- the relying site batching its users' proofs.

This is the highest-value direction after Gate 3, and it is noted here so it is not lost.