# Native Minotari XTM: can Ghost Gate prove a threshold without an Ootle burn?

**This is a research document. Nothing here is a product claim, and no part of it is merged into the
Ootle proof path.** The Ootle backend is stable and independently proven; this is a separate question
about a separate chain.

## 2026-10-23 browser-wallet capability update

The requested Tari Universe source is now published as
[`chironbuilds/tari-wallet`](https://github.com/chironbuilds/tari-wallet). Its own README explicitly
identifies it as a **Tari Ootle L2** wallet, rather than a Minotari L1 wallet. Its injected
`window.tari` contract reports Ootle accounts and Ootle networks (`esmeralda`/`igor`) and exposes
Ootle transaction, shielding and ownership-proof operations. It does not expose a Minotari L1
address, L1 output commitment, L1 output-spend-key signature, output-inclusion proof, or a
current-UTXO-state proof.

That rules out a tempting but invalid substitution: an Ootle `window.tari` connection or signature
cannot establish ownership of native XTM. In particular, the Esmeralda name returned by the L2
provider is not an independently verified Minotari L1 network assertion.

The official `tari-project/tari` repository continues to expose Minotari through a console wallet
and base-node gRPC interfaces. It has no browser provider contract equivalent to `window.tari` that
lets an external site obtain the complete challenge-bound, output-owned, inclusion-checked and
currently-unspent evidence this gate needs. The existing in-process `ghost-gate-minotari` prototype
can construct a pay-to-self proof transaction, but that is deliberately not a public browser-wallet
flow and is incompatible with a no-transaction access policy.

Accordingly, Ghost Gate's `ProofMode::Xtm` remains a saved, reviewable **draft**. The browser UI
now recognizes an L1 gate before wallet probing and refuses to request a Tari Universe/Sapient
connection, issue a challenge, or present an authorization path. This is a production safety guard,
not an L1 verification feature.

No code from the Tari Universe/Sapient application is copied for this integration. The browser
provider contract is referenced through Tari's published integration documentation.

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
// tari_transaction_key_manager-6.0.1-pre.2/src/legacy_key_manager/wrapper.rs:226,431,440,449
fn sign_message_with_spend_key(&self, message: &[u8], sender_offset_pub_key: Option<&CompressedPublicKey>)
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

**RESOLVED, from source, on 2026-10-08.** The gRPC service implementation is inside
`minotari_console_wallet`, which *is* vendored in the cargo registry. The handler is:

```rust
// minotari_console_wallet-6.0.1-pre.2/src/grpc/wallet_grpc_server.rs:3043
async fn sign_message(&self, request: Request<SignMessageRequest>) -> Result<Response<SignMessageResponse>, Status> {
    let message = request.into_inner();
    let secret = self.wallet.node_identity.secret_key().clone();
    let signature = SignatureWithDomain::<WalletMessageSigningDomain>::sign(&secret, message_str.as_bytes(), &mut rand::rng())
        .map_err(|e| Status::internal(format!("Failed to sign message: {e}")))?;
    ...
}
```

The handler signs with `node_identity.secret_key()` and with nothing else. There is no request field,
flag, key-index or variant that selects a spend key. The proto's doc comment was accurate.

Two consequences, and they settle the XTM question:

1. **A zero-transaction native-XTM proof is not reachable through the wallet's gRPC surface.** A
   relying site cannot ask a Minotari wallet to sign a challenge with an output's spend key, so it
   cannot obtain "I control this ≥ X output" without a transaction.
2. **The primitive is nevertheless present inside the wallet.**
   `Wallet::sign_message(&mut self, secret: &PrivateKey, message: &str)` at
   `minotari_wallet-6.0.1-pre.2/src/wallet.rs:466` takes the secret key as a parameter and performs
   the same domain-separated signature. So a *future* wallet build that exposed a spend-key variant
   would be a small change, and the domain separation is already right. This is a wallet-surface
   question, not a cryptography question.

For contrast, the same crate already calls the spend-key version internally, for its own purposes:

```rust
// minotari_console_wallet-6.0.1-pre.2/src/automation/commands.rs:2913
let signature = key_manager_service.sign_message_with_spend_key(&commitment_bytes, sender_offset)?;
```

so the call exists and is exercised — it is simply not exposed over gRPC.

### Fees do not leak the amount

`WeightParams::calculate` (`weight.rs:75-94`) and `calculate_body` (`:96-112`) take kernel/input
**counts** and feature/script byte sizes. There is no `value` argument anywhere. Upstream Tari
historically weighted fees by value, and had it done so here the exact transaction value would have
leaked through `fee / fee_per_gram`. On the code read, it does not. Worth re-checking on any upgrade.

### The blocker: no cross-output aggregation

The **crypto** library can aggregate. `ExtendedRangeProofService::construct_extended_proof` takes a
`Vec<ExtendedWitness>` and its own doc comment says the proof "may be aggregated":

```rust
// tari_crypto-0.23.4/src/extended_range_proof.rs:48-60
/// Constructs a new extended range proof, which may be aggregated, for the given set(s) of secret key(s) value(s)
/// and minimum value promise(s).
fn construct_extended_proof(
    &self,
    extended_witnesses: Vec<ExtendedWitness<Self::K>>,
    seed_nonce: Option<Self::K>,
) -> Result<Self::Proof, RangeProofError>;
```

The **key manager** cannot reach it. Every range-proof path the wallet has goes through one signature,
which takes a single commitment mask and a single value:

```rust
// tari_transaction_key_manager-6.0.1-pre.2/src/legacy_key_manager/inner.rs:447
pub fn construct_range_proof(
    &self,
    commitment_mask_key_id: &TariKeyId,   // one mask
    value: u64,                            // one value
    min_value: u64,                        // one promise
) -> Result<RangeProof, KeyManagerError>
```

and `construct_extended_proof` is not called anywhere in the vendored key-manager crate. So a prover
cannot aggregate several of its own outputs into one L1-consensus-verifiable statement through the
wallet, and "prove I control ≥ X across several native UTXOs" is **not** expressible today. It would
need a new key-manager entry point and new consensus acceptance, which is new protocol work.

Two supporting details, both verified:

- `RANGE_PROOF_AGGREGATION_FACTOR: usize = 1` (`tari_common_types-6.0.1-pre.2/src/types/mod.rs:79`).
- `sum_commitments` exists for balance checking
  (`aggregate_body_internal_validator.rs`), but no aggregate commitment is ever published as a
  proof-bearing object.

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

Route A was chosen before the `SignMessage` question was resolved, and it survives the answer. The
answer removed the only route that would have beaten it — see the "one change that would make a
transaction-free proof possible" section above — rather than invalidating it.

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
| **BLOCKED** | **A zero-transaction native-XTM proof.** The wallet gRPC signs challenges with the node identity key and offers no spend-key variant (`wallet_grpc_server.rs:3054`, resolved from source above). This closes the most attractive option: an external prover cannot obtain "I control this ≥ X output" without a transaction. |
| **BLOCKED** | **Route B.** Cross-output aggregation is unreachable from the wallet: every L1 range-proof path goes through `construct_range_proof(mask_id, value, min_value)` — one commitment — and `construct_extended_proof` is never called by the key manager (`RANGE_PROOF_AGGREGATION_FACTOR = 1`). Reaching it needs a new key-manager entry point *and* new consensus acceptance, which is new protocol work this project will not invent. |
| **BLOCKED** | **Route D.** No HTLC or hashlock predicate exists in TariScript. The opcodes to hand-build one do exist (`HashSha256` `op_codes.rs:244`, `CheckSigVerify` `:257`, `CheckHeightVerify` `:147`), but nothing in the codebase writes one and there is no evidence such a script passes consensus. Writing one would be unaudited new protocol work in consensus-critical code. |

## Why no prototype was built

The question this document set out to answer — can a native-XTM threshold proof avoid a transaction —
is now answered, and the answer is no on the current wallet surface. The only remaining route is A, and
A's cost is structural rather than incidental: it is one L1 transaction and one L1 fee per access, by
construction, because the transaction is what proves current control.

So the prototype that would have been built is a prototype of Route A, which requires a live Minotari
node and a funded wallet. Neither exists in this environment: the localnet harness here is Ootle (an L2
that consumes Minotari), and it starts no Minotari base node. Building one, funding it, and waiting for
confirmations is a multi-day environment task, not a code task.

That is a **BLOCKED-on-environment** state rather than an idea that was rejected, and it is recorded
that way rather than as progress. Writing a harness that constructs the transaction but cannot submit
it would demonstrate the builder, not the proof.

What *is* verified about Route A, from source:

```rust
// minotari_wallet-6.0.1-pre.2/src/output_manager_service/handle.rs:1233
pub async fn create_pay_to_self_transaction(
    &mut self, amount: MicroMinotari, utxo_selection: UtxoSelectionCriteria,
    output_features: OutputFeatures, fee_per_gram: MicroMinotari,
    lock_height: Option<u64>, payment_id: MemoField,
    minimum_value_promise: MicroMinotari,          // <- the field the gate needs
) -> Result<(MicroMinotari, Transaction, TxId), OutputManagerError>
```

The threshold-bearing output is constructible by the wallet today, with an explicit promise, and the
resulting transaction carries a consensus-verifiable `minimum_value_promise`. The design is not blocked
on primitives; it is blocked on having somewhere to run it.

## The one change that would make a transaction-free proof possible

Expose a spend-key variant of `SignMessage` over the wallet gRPC — the call already exists inside the
wallet (`commands.rs:2913` calls `sign_message_with_spend_key` for its own automation), the domain
separation is already correct, and the verifier would be a signature check against the output's public
spend key. With that one RPC, Route A collapses to zero transactions per access and the native-XTM
backend becomes strictly better than the Ootle path. It is a small, well-scoped change to a wallet
surface — and it is upstream work, not something this project should fork to obtain.

## What is NOT claimed for native XTM, at all

- That it works. It does not; it has not been run.
- That no Ootle burn is needed *in practice*. Route A burns no Ootle value, but it does require an L1
  transaction per access, and the base-layer burn flow the Ootle path already uses remains the cheaper
  option for a user who has L1 XTM to burn.
- That a transaction-free native-XTM proof is impossible in principle. It is impossible **on the current
  wallet gRPC surface**, which is a wallet limitation rather than a protocol one, and the change that
  would lift it is identified above.
- Any privacy property beyond "the output's committed minimum is public and its value is not". The
  metadata an L1 transaction reveals — that a transaction of some size happened, its fee, its
  confirmation time — is public, and no design on this page hides it.

The product statement stays what the evidence supports:

> Ghost Gate proves that a wallet controlled a qualifying input worth at least X of a supported Ootle
> stealth fungible resource at the moment a validator committed a transaction, and published no amount
> to do so. A native Minotari XTM backend exists as a documented design; it is not yet implemented and
> makes no claims.
