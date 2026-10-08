# Native Minotari XTM: can Ghost Gate prove a threshold without an Ootle burn?

**This is a research document. Nothing here is a product claim, and no part of it is merged into the
Ootle proof path.** The Ootle backend is stable and independently proven; this is a separate question
about a separate chain.

## The question

> Prove control of at least X native Minotari L1 XTM, without burning or bridging that XTM onto Ootle,
> and without revealing the exact amount.

## What the source actually provides

Read from the vendored `tari_* 6.0.1-pre.2` / `tari_crypto 0.23.4` crates and
`minotari_app_grpc-6.0.1-pre.2/proto/wallet.proto` in the cargo registry. Every claim below is quoted
from a path and line, and **NOT FOUND** is recorded as such rather than filled in.

Three of the findings changed the shape of the answer, and one of them is a genuine surprise in the
project's favour.

### The surprise: L1 already has a minimum value promise

`TransactionOutput` carries a public `minimum_value_promise`, and it is part of the output hash, so it
is consensus data:

```rust
// tari_transaction_components/src/transaction_components/transaction_output.rs:96-98
/// The minimum value of the commitment that is proven by the range proof
#[serde(default)]
pub minimum_value_promise: MicroMinotari,
```

Consensus verifies it, through the bulletproof over `[minimum_value_promise, 2^64)`:

```rust
// transaction_output.rs:555-597, batch_verify_range_proofs
statements.push(RistrettoAggregatedPublicStatement {
    statements: vec![Statement {
        commitment: ...,
        minimum_value_promise: output.minimum_value_promise.into(),
    }],
});
```

And it is on the base node's wire format (`transaction.proto:117`, field 11), so an external verifier
can read a public output's commitment, range proof and promised minimum **straight off a base node,
with no chain modification at all**.

This is the whole reason the native-XTM idea is not fantasy: the primitive Ghost Gate's Ootle path
depends on already exists on L1, natively, today.

### Spend-key challenge signing: exists in the library, not over gRPC

Four domain-separated signing methods exist on `TransactionKeyManagerInterface`:

```rust
// tari_transaction_key_manager/src/key_manager/interface.rs:236-259
fn sign_message_with_spend_key(&self, message: &[u8], sender_offset_key: Option<&CompressedPublicKey>)
    -> Result<WalletMessageSchnorrSignature, KeyManagerError>;
fn sign_script_message(&self, private_key_id: &TariKeyId, challenge: &[u8]) -> ...;
fn sign_script_message_with_spend_key(&self, message: &[u8], ...) -> ...;
fn sign_with_nonce_and_challenge(&self, private_key_id: &TariKeyId, nonce: &TariKeyId,
                                 challenge: &[u8; 64]) -> ...;
```

`sign_message_with_spend_key` is genuinely domain-separated:
`SignatureWithDomain::<WalletMessageSigningDomain>` with the label
`"com.tari.base_layer.wallet.message_signing"` (`tari_hashing/src/domains.rs:68-72`).

That would be enough to prove "I control this output's spend key" without any transaction at all.

**But it is not reachable from an external process.** The wallet's only spend-adjacent signing RPC is:

```proto
// minotari_app_grpc/proto/wallet.proto:1497-1500
// - This signs with the wallet's node identity private key.
// - The signature can be verified using the wallet's public key.
rpc SignMessage (SignMessageRequest) returns (SignMessageResponse);
```

**UNRESOLVED, and deliberately left unresolved:** the gRPC service implementation crate
(`tari_wallet_grpc`) is not vendored on this machine, so the claim above rests on the proto's own doc
comment. It was not confirmed in code. If that RPC can be made to use the spend key, this changes
materially, and it is worth chasing upstream before anyone commits to a conclusion.

### Fees do not leak the amount

`WeightParams::calculate` (`weight.rs:75-94`) and `calculate_body` (`:96-112`) take kernel/input
**counts** and feature/script byte sizes. There is no `value` argument anywhere. Upstream Tari
historically weighted fees by value, and had it done so here the exact transaction value would have
leaked through `fee / fee_per_gram`. On the code read, it does not. Worth re-checking on any upgrade.

### The blocker: no cross-output aggregation

`sum_commitments` exists (`aggregate_body_internal_validator.rs:320-331`) and is used for balance
checking, but **no aggregate commitment is ever published as a proof-bearing object.** The key manager
only ever builds one-commitment proofs:

```rust
// tari_transaction_key_manager/src/key_manager/manager.rs:975
.construct_extended_proof(vec![extended_witness], None)   // a ONE-element vector
```

and `RANGE_PROOF_AGGREGATION_FACTOR` is `1` (`tari_common_types/src/types/mod.rs:79`). Despite the
name, `batch_verify_range_proofs` batch-*verifies* independent proofs; it does not aggregate them.

So "prove I control ≥ X across several native UTXOs" in one statement is **not** expressible with
consensus-verifiable L1 primitives. It would need a genuinely new proof protocol.

### Two more gaps

| Gap | Evidence |
| --- | --- |
| No UTXO-listing RPC | `GetUnspentAmounts` returns amounts only (`wallet.proto:992`). `OutputManagerHandle::get_unspent_outputs` (`handle.rs:857`) is library-level only. A base node's `FetchMatchingUtxos` (`base_node.proto:83`) returns full outputs, but needs output hashes the caller already has. |
| No HTLC predicate in TariScript | `grep -ri "htlc\|hashlock"` over `tari_script` returns zero hits; the full `Opcode` enum (`op_codes.rs:142-298`) has no such opcode. What exists is the *claim* side of someone else's HTLC: `create_claim_sha_atomic_swap_transaction` (`service.rs:3054`), `create_htlc_refund_transaction` (`:3136`). |

## Route comparison

| | A: Ghost Credential | B: Aggregate over existing UTXOs | C: Dry-run spend proof | D: HTLC / submarine |
| --- | --- | --- | --- | --- |
| Funds move? | **Yes, within the wallet** | No | Yes, if broadcast | Yes, temporarily locked |
| Setup transaction required? | **Yes**, one | No | No | **Yes**, plus a refund |
| Proving transaction required? | **Yes** | No | No | No |
| L1 fee per access? | **Yes** | No | No | Two fees |
| Exact amount disclosed? | No | — | No | No |
| UTXO identifiers disclosed? | No, if the wallet keeps them | — | **Yes** | Yes |
| Relying site sees a broadcastable transaction? | **No, if the bridge submits it** | — | **YES — this is the danger** | No |
| Proves current ownership? | Yes, by spending | — | Yes | Only via the claim |
| Proves current unspent state? | Yes, by definition | Requires base-node lookup per output | Yes | Only while locked |
| Replay protection? | Gate-side nonce burn | Would need new construction | Challenge binding only | Challenge bound into the lock |
| Implementation complexity | Moderate | **Very high** | Low | High |
| Amount of novel cryptography | **None** | **Substantial** | None | None |
| Verifiable from public chain data? | **Yes** — commitment + range proof + MVP | No | No | Yes |
| Suitability for public launch? | **Viable as a fallback mode** | Not without external review | **No** | No |

## Route C's danger, stated plainly

The instruction to investigate C came with the right warning, and the source confirms it. Building and
validating a spend produces a *real, fully signed transaction*. `TransactionBuilder::build()`
(`builder.rs:1215`) returns it; `TransactionInternalValidator::validate`
(`transaction_internal_validator.rs:52-67`) checks it — including the note, on its own doc comment,
that it "does NOT check that inputs come from the UTXO set", which is exactly why it is safe to run.

**Handing that transaction to a relying site hands the site the ability to broadcast it.** That is a
spend the user did not authorise, of funds the site now knows are worth at least X. Route C is
therefore not a proof *format*. It is a wallet-internal validation mechanism, and the only safe way to
expose it is to never let the signed bytes leave the wallet — which makes it Route A with extra steps.

Note the related subtlety from `docs/GATE3_RESULTS.md`: a qualified statement is only spendable from a
transaction that **declares** the outputs it spends, so "which UTXO am I spending" is inherent to
spending on Ootle. The XTM analogue is that any L1 spend names its inputs by hash. Neither is a
disclosure the site needs to see, because in both designs the *wallet* builds and submits the
transaction and the site only ever receives a transaction id and a committed outcome.

## The chosen route

**Route A, with the bridge submitting.** One L1 self-transfer at access time, carrying an output with
`minimum_value_promise >= X`, submitted by the local bridge and never handed to the relying site.

Why this one:

1. **It needs no new cryptography.** It uses `create_pay_to_self_transaction`
   (`handle.rs:1233-1262`), which already takes an explicit `minimum_value_promise`, and the existing
   consensus range-proof check. Nothing has to be designed, reviewed or trusted that does not already
   run on every Minotari block.
2. **The evidence is independently checkable.** A third party can read the output's commitment, range
   proof and promised minimum off a base node and confirm the floor. The claim does not rest on the
   prover's word, which is the property the Ootle path has and the one worth preserving.
3. **It proves current control**, not historical control. Spending the output is what proves the
   prover could. An unspent output with a high promise proves only that someone once could.
4. **The funds never leave the wallet.** The output goes back to the same owner. Nothing is bridged,
   nothing is burnt onto Ootle, and no fee is paid to another chain.

What it costs, honestly: **an L1 transaction and an L1 fee on every access**, which Route A as
originally framed (a one-time setup credential) does not. That is a real product difference from the
Ootle path and is why this is a *fallback backend*, not the default.

## What is proven, prototyped, designed and blocked

| State | Item |
| --- | --- |
| **PROVEN** | L1 carries a consensus-enforced `minimum_value_promise` on a public, hash-committed output, readable from a base node. Source-quoted above. |
| **PROVEN** | The Ootle backend proves ≥ X of a supported stealth fungible resource without revealing the amount. 30/30 + 15/15 + 22-step localnet. |
| **PROVEN** | Fees in this version are value-independent, so a fee cannot leak the amount. |
| **PROTOTYPE** | Nothing yet. See below. |
| **DESIGN ONLY** | The full XTM backend: access-time self-transfer, gate-side nonce binding, session issuance on the L1 path, and the bridge's `WalletChannel` implementation against Minotari's gRPC. |
| **DESIGN ONLY** | Whether `SignMessage` can be made to use the spend key. Unresolved and explicitly not guessed. |
| **BLOCKED** | **Route B.** Cross-output aggregation is not expressible with consensus-verifiable L1 primitives today (`construct_extended_proof(vec![one_witness])`, `RANGE_PROOF_AGGREGATION_FACTOR = 1`). It would require a new proof protocol, which this project will not invent. |
| **BLOCKED** | **Route D.** No HTLC or hashlock predicate exists in TariScript. The opcodes to hand-build one do exist (`HashSha256` `op_codes.rs:244`, `CheckSigVerify` `:257`, `CheckHeightVerify` `:147`), but nothing in the codebase writes one and there is no evidence such a script passes consensus. Writing one would be unaudited new protocol work in consensus-critical code. |

## Why no prototype was built

A prototype would need a live Minotari node and a wallet with funds, neither of which is available in
this environment, and the shape it would take is not yet decided by anything that has been verified:
the ownership half of Route A depends on the unresolved `SignMessage` question. Building a harness
around an unresolved primitive and calling it progress would be exactly the kind of rounding-up this
project has avoided so far.

The next concrete step is small and specific: **read `tari_wallet_grpc`'s `SignMessage` handler**, which
was not vendored here. If it uses the node identity key, Route A is confirmed viable as a
transaction-per-access backend and the design can be written down properly. If a spend-key variant is
addable, a *zero-transaction* native-XTM proof becomes possible and is a much better product than
anything else on this page.

## What is NOT claimed for native XTM, at all

- That it works. It does not; it has not been run.
- That no Ootle burn is needed *in practice*. Route A burns no Ootle value, but it does require an L1
  transaction per access, and the base-layer burn flow the Ootle path already uses remains the cheaper
  option for a user who has L1 XTM to burn.
- Any privacy property beyond "the output's committed minimum is public and its value is not". The
  metadata an L1 transaction reveals — that a transaction of some size happened, its fee, its
  confirmation time — is public, and no design on this page hides it.

The product statement stays what the evidence supports:

> Ghost Gate proves that a wallet controlled a qualifying input worth at least X of a supported Ootle
> stealth fungible resource at the moment a validator committed a transaction, and published no amount
> to do so. A native Minotari XTM backend exists as a documented design; it is not yet implemented and
> makes no claims.