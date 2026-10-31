# Gate 1 — MVP self-transfer

The question: does the underlying primitive actually work? Before any Ghost Gate logic, can a
hidden value be committed with a public lower bound that provably covers it, and does that bound
hold up when the value or the bound is attacked?

**Verdict: GREEN.** Twelve tests, all passing.

This gate deliberately contains no Ghost Gate code. It tests the Ootle primitive that the product
depends on, using the engine's own validator rather than a reimplementation.

## What MVP is

`UnspentOutput.minimum_value_promise` is a public `u64` on every stealth output
(`crates/template_lib_types/src/stealth/unspent_output.rs:45`). It is not metadata checked
afterwards — it is a field of each bulletproof statement
(`crates/engine_types/src/crypto/range_proof.rs:32`):

```rust
Ok(Statement {
    commitment,
    minimum_value_promise: stmt.minimum_value_promise,   // bound into the proof
})
```

So the bulletproof attests the value lies in `[MVP, 2^64)`. Set the promise to 10,000 and the
prover has committed, in zero knowledge, to holding at least 10,000 — without revealing whether it
is 10,000 or 10,000,000.

This confirms hypothesis **H1** from the v0.41 research.

## The four required cases

### 1. Hidden value above the threshold → VALID

`hidden_value_above_threshold_validates`

A self-transfer of a hidden 20,000 with `MVP = 10,000`. The engine's own
`validate_stealth_outputs_statement` accepts it, and the gate rules accept it.

### 2. Hidden value below the threshold → construction or proof FAILS

Two independent refusals, because there are two places the claim can break.

`mvp_above_value_is_refused_at_construction`

The output constructor rejects a promise larger than the value before any proof is generated. The
cohort does this in both output builders (`crates/ootle_wasm/core/src/stealth/outputs.rs:150`,
`crates/ootle_sdk_core/src/stealth/outputs.rs:120`); the test drives the same rule through
`tari_ootle_wallet_crypto`.

`engine_range_proof_accepts_value_at_or_above_mvp`

Invokes the engine's validator directly, rather than trusting Ghost Gate's reading of the spec.

### 3. MVP mutation after proof creation → verification FAILS

`mutating_mvp_after_proof_breaks_validation`

Build a valid proof, then change the public promise on both sides of the true value:

```rust
statement.outputs_statement.outputs[0].output.minimum_value_promise = THRESHOLD - 1;  // fails
statement.outputs_statement.outputs[0].output.minimum_value_promise = THRESHOLD + 1;  // fails
```

Lowering must fail, because the bulletproof attests the value is at least 10,000 and lowering the
public claim would let a 9,999-holder pass as a 10,000-holder. Raising must fail, because the proof
cannot be stretched after the fact.

This is the security property the entire product rests on. The cohort pins the same behaviour in
`crates/wallet/crypto/src/stealth.rs:414` (`it_is_invalid_if_minimum_value_changed`); Ghost Gate
reproduces it independently.

### 4. Fragmented inputs → VALID

`fragmented_inputs_qualify_once`

Four inputs — 3,100 / 2,900 / 4,800 / 1,500, totalling 12,300 — consolidated into one output with
`MVP = 10,000`. Qualifies as a single proof with `input_count: 4`.

Fragmentation is the ordinary case, not an edge case: a wallet's UTXO set is whatever previous
transactions left behind. The product claim is about a wallet's *aggregate* qualifying funds, not
about a single large coin.

## Two tests about what the promise does not leak

`attested_minimum_is_a_lower_bound_not_the_amount`

Two proofs: one hiding 10,000, one hiding 9,000,000 — a 900× difference. Both produce receipts with
identical `attested_minimum`. Nothing in the receipt distinguishes them.

`receipt_carries_only_public_lower_bound_and_nonce`

The receipt is three fields: the public bound, the input count, the burnt nonce. It round-trips
through CBOR unchanged. No value, no address, no identity — so it is safe to hand to an indexer.

## Commands and results

```
$ cargo test -p ghost-gate-core -p ghost-gate-wallet -p ghost-gate-verifier
running 13 tests   (ghost-gate-core)      13 passed; 0 failed
running 10 tests   (ghost-gate-wallet)    10 passed; 0 failed
running 9 tests    (ghost-gate-verifier)  9 passed; 0 failed
```

`ghost-gate-tests --test mvp_and_shape` runs under WSL (see `docs/GATE0_RESULTS.md`) because it
depends on `tari_engine_types`, which pulls the engine.

## Why the wallet has to be involved

The tests above build statements directly with `tari_ootle_wallet_crypto`. A real prover cannot do
that: building a statement requires the input masks, which live in the wallet. That is not an
implementation inconvenience, it is the privacy boundary.

The load-bearing consequence, verified in `docs/V042_SOURCE_TRACE.md` finding 5: the stock wallet
**cannot** produce an MVP-bearing output. `StealthOutputsApi::create_output_witness` hardcodes
`minimum_value_promise: 0` and takes no such argument, so every statement the ordinary wallet path
builds promises zero.

Option 1 — reuse a wallet output and mutate the promise — is impossible, per case 3 above.

Option 2 — set the promise on the witness before the statement is built — is what
`ghost-gate-wallet::qualifying_output_witness` does, and it is sound: the promise is public, the
value is already committed inside the mask, and the bulletproof is generated *over* the promise. A
promise above the value cannot verify. No secret is involved.

This is the one place Ghost Gate writes against the wallet's crypto layer rather than a high-level
SDK call, and it is documented at the top of `crates/ghost-gate-wallet/src/lib.rs`.

## What Gate 1 does and does not establish

Established: the primitive works, the promise is genuinely bound to the hidden value, and mutation
breaks it in both directions.

Not established: that an ordinary wallet can produce such an output through its own APIs. That is
Gate 3, and it is the gate that decides whether this product exists.