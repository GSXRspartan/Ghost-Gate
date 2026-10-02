# Gate 3 — ordinary wallet E2E

**The gate that decides whether this product exists.**

## The statement under test

```text
NORMAL WALLET
      │
      ▼
ordinary existing key-path stealth tTARI
      │
      ▼
normal wallet input selection
      │
      ▼
qualifying self-owned MVP output
      │
      ▼
Ghost Gate component call
      │
      ▼
wallet performs authorization/signing
      │
      ▼
consensus threshold enforcement
      │
      ▼
COMMITTED → access proof
```

## Verdict: NOT GREEN

Not attempted in this run. **Nothing in this repository demonstrates that an ordinary wallet can
produce an MVP-bearing output, because stock walletd cannot.**

This document records the finding rather than leaving the gate silently empty, because the finding
is the most important thing discovered about this product.

## Why it is blocked: a stock-walletd gap

The qualifying output must carry `minimum_value_promise >= threshold`. Stock walletd cannot produce
one.

**VERIFIED** — `crates/wallet/sdk/src/apis/stealth_outputs.rs:929-963`:

```rust
pub fn create_output_witness(&self, destination: &RistrettoOotleAddress, amount: u64, ...) -> ... {
    ...
    let witness = OutputWitness {
        amount,
        mask: mask.key,
        sender_public_nonce: public_nonce,
        minimum_value_promise: 0,          // <- literal zero, no argument to change it
        encrypted_data,
        resource_view_key,
    };
```

Every statement the wallet builds through this path promises zero. The same holds for the
confidential path (`applications/tari_walletd/src/handlers/confidential.rs:158,200,313`) and for the
engine's own `mint_stealth` (`crates/engine/src/runtime/impl.rs:3755`).

The RPC request type confirms there is no field to set it either.
`TransferOutput` (`crates/wallet/sdk/src/apis/stealth_transfer/params.rs:115`) carries `address`,
`revealed_amount`, `blinded_amount`, `memo`, `pay_to` — **no MVP**.

### The two ways out, and why one is impossible

**Mutate a wallet-built output's promise afterwards.** Impossible. The promise is a field of the
bulletproof statement (`crates/engine_types/src/crypto/range_proof.rs:32`), so changing it after the
proof exists invalidates the proof. Verified in Gate 1
(`mutating_mvp_after_proof_breaks_validation`) and by the cohort itself
(`crates/wallet/crypto/src/stealth.rs:414`).

**Set the promise on the witness before the statement is built.** Sound, and what
`ghost-gate-wallet::qualifying_output_witness` does. It requires the prover's Pedersen masks, which
live inside the wallet.

## What is genuinely proven about the integration path

Not the end-to-end flow, but the parts that decide whether it can work. Each verified against v0.42.0
source; full citations in `docs/V042_SOURCE_TRACE.md`.

**A statement can be built and the inputs left locked.**
`accounts.create_stealth_transfer_statement`
(`applications/tari_walletd/src/handlers/accounts.rs:1631`) returns `statements`, `lock_id`,
`signing_keys` and `utxo_signers`, and explicitly "Return without unlocking the outputs".

**The caller can append its own instruction.**
`transactions.submit_instruction`
(`applications/tari_walletd/src/handlers/transaction.rs:70`) takes `CallInstructionRequest`
containing caller-supplied instructions, so a `CallMethod` to the gate component can be appended
after the statement is built. The wallet then builds, pays the fee from a named account component,
and signs.

**The wallet derives the signing keys itself, not from the caller.**
`derive_stealth_signers` (`transaction.rs:251`):

> "Derived from the wallet's own record of what each lock locked, never from the caller. ...
> re-deriving here means the locked outputs are the only thing that decides."

A caller cannot name the keys the wallet signs with. This is the property that makes the preferred
flow acceptable, and it is the reason the unacceptable fallback — exporting the account key so
Ghost Gate signs for the user — is not needed.

**Ordinary key-path inputs survive being spent from inside a custom template.**
`verify_input_authorizations` (`crates/engine/src/runtime/impl.rs:817`) reads the UTXO's committed
`spend_key`, turns it into a badge, and checks it against `base_call_scope()` — the transaction's
outermost scope, not the template's local scope (`crates/engine/src/runtime/working_state.rs:1689`).

This was hypothesis **H2**, and it is the finding that makes the whole architecture viable. Confirmed
by the cohort's own `programmatic_transfer` test
(`crates/engine/tests/stealth.rs:237-275`), where a template performs a key-path stealth transfer
authorised by the transaction seal.

**Input selection is ordinary.**
`UtxoInputSelection` (`crates/wallet/sdk/src/apis/stealth_transfer/api.rs:168-329`) supports
`ConfidentialOnly`, `PreferRevealed` and `PreferConfidential`; the RPC adds `InputSelection::Specific`
for naming exact UTXOs, which additionally requires scoped `StealthUtxos::Read` authority. Fragmented
inputs are the normal case and need no special handling.

**Finality is observable as three distinct states.**
`transactions.wait_result` returns `TransactionFinalizedResult::{Pending, Finalized, Rejected}`, and
`Rejected` is documented as "rejected by mempool validation at submission and was never sequenced".
`ghost-gate-verifier::observe_and_authorize` grants only on `Committed { accept: true }`.

So every link in the chain works **except** the one that sets the promise. That is a narrow, specific
gap — and it is upstream, in walletd, not in Ghost Gate.

## Why this gate is not marked yellow

Yellow would imply a partially working path with a workaround. There is no workaround that keeps the
wallet in charge:

- Assembling the statement outside the wallet requires the input masks — the keys.
- Assembling it inside walletd requires changing walletd.
- Changing walletd means either an upstream patch or a local fork.

Ghost Gate's design deliberately does **not** choose the third option. A fork that exports nothing
and keeps every key inside the wallet process is architecturally sound, but it is a different product
from "works with the wallet Tari ships", and calling that green would be exactly the kind of overclaim
this project is meant to avoid.

## Smallest viable fix

Three lines of upstream walletd, in this shape:

1. Add `minimum_value_promise: u64` to `TransferOutput`
   (`crates/wallet/sdk/src/apis/stealth_transfer/params.rs:115`).
2. Thread it through `StealthOutputToCreate`
   (`crates/wallet/sdk/src/apis/stealth_transfer/types.rs:81`) into `create_output_witness`, replacing
   the literal `0` at `stealth_outputs.rs:961`.
3. Validate `mvp <= amount` in `create_output_witness` — the same rule the WASM and SDK output
   builders already enforce (`crates/ootle_wasm/core/src/stealth/outputs.rs:150`,
   `crates/ootle_sdk_core/src/stealth/outputs.rs:120`), so the wallet fails early with a clear message
   rather than producing a statement that will not verify.

Then the flow becomes:

```text
1. POST accounts.create_stealth_transfer_statement
     input_selection: Specific([...]) or Selection(ConfidentialOnly)
     outputs: [{ address: self, blinded_amount: threshold + fee, minimum_value_promise: threshold }]
   -> statements[0], lock_id

2. build transaction:
     fee intent  : pay_fee from a revealed bucket
     main intent : CallMethod(gate, "prove_access", args![challenge, statements[0]])
     inputs      : write(gate), read(resource), write(each input UTXO)

3. POST transactions.submit
     transaction, seal_signer = account owner key, lock_ids = [lock_id]
   -> wallet derives stealth signers from the lock, signs, seals, submits

4. observe transactions.wait_result -> Committed { accept: true }
   -> read the GG event for the burnt nonce -> issue session
```

No key ever leaves walletd. The caller supplies bytes; the wallet supplies authority.

## What would be needed to close this gate

1. Run a validator node and a walletd against localnet.
2. Create an account, fund it with stealth tTARI through the ordinary faucet path, and confirm the
   outputs are key-path and spendable.
3. Execute the four-step flow above.
4. Assert `COMMITTED`, then `transactions.wait_result` returns `accept: true`, and that the gate
   component's `proofs_accepted` incremented and the nonce is burnt.

Step 2 depends on the v0.42 testnet faucet being empty after the reset and on the current burn/claim
flow for acquiring test tTARI. Neither was exercised in this run.

## The honest summary

The architecture is sound and every component of it is verified against v0.42.0 source, including the
load-bearing one — that ordinary key-path wallet funds are authorised correctly even when spent from
inside a custom template.

What is missing is a walletd that can express the product. That is a real blocker with a small,
well-understood upstream fix, and it is the single highest-value next task.