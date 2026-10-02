# Tari Ootle v0.42.0 source trace

Every assumption Ghost Gate makes, checked against the source rather than against documentation or
memory. Each finding is labelled:

- **VERIFIED** — read in the source at the stated path and symbol, and confirmed by a test or by
  direct execution.
- **STRONG INFERENCE** — the source constrains it and nothing contradicts it, but no test in the
  cohort exercises the exact case.
- **UNKNOWN** — could not be established from the source.

Reference: `tari-ootle-v0.42.0-reference`, tag `v0.42.0`, commit
`a43773e600b9503ed3fadcd3f0048f86131e3644`, working tree clean.

---

## 1. `StealthTransferStatement`

**VERIFIED** — `crates/template_lib_types/src/stealth/statement.rs:190`

```rust
pub struct StealthTransferStatement {
    #[n(0)] pub inputs_statement: StealthInputsStatement,
    #[n(1)] pub outputs_statement: StealthOutputsStatement,
    #[n(2)] pub balance_proof: Option<BalanceProofSignature>,
    #[n(3)] pub covenant_claims: Vec<CovenantBalanceClaim>,
}
```

Four fields. `balance_proof` is `None` only for a revealed-only transfer. Ghost Gate requires it to
be `Some`, because a proof with no balance proof has no value-conservation argument.

Accessors exist for the parts a template inspects: `stealth_inputs()`, `stealth_outputs()`,
`revealed_input_amount()`, `revealed_output_amount()`, `revealed_receiver()`.

Used by Ghost Gate: `ghost-gate-core::find_qualifying_output`.

## 2. `minimum_value_promise`

**VERIFIED** — `crates/template_lib_types/src/stealth/unspent_output.rs:45`

```rust
pub struct UnspentOutput {
    #[n(0)] pub commitment: PedersenCommitmentBytes,
    #[n(1)] pub sender_public_nonce: RistrettoPublicKeyBytes,
    #[n(2)] pub encrypted_data: EncryptedData,
    #[n(3)] pub minimum_value_promise: u64,
    #[n(4)] pub viewable_balance_proof: Option<ViewableBalanceProof>,
}
```

A plain public `u64` on the output, part of the statement the template receives. A template can
therefore read the threshold a prover committed to without any host call.

Also mirrored on the persisted form: `crates/engine_types/src/crypto/output.rs:32`
(`OutputBody.minimum_value_promise`), and on the WASM-side output spec at
`crates/ootle_wasm/core/src/stealth/types.rs:41`.

## 3. MVP binding to the hidden value

**VERIFIED** — `crates/engine_types/src/crypto/range_proof.rs:18-35`

```rust
pub fn validate_bullet_proof<'a, I: IntoIterator<Item = &'a UnspentOutput>>(
    range_proof: &RangeProofBytes,
    outputs: I,
) -> Result<(), ResourceError> {
    let mut statements = outputs.into_iter().map(|stmt| {
        ...
        Ok(Statement {
            commitment,
            minimum_value_promise: stmt.minimum_value_promise,   // <- bound into the proof
        })
    })
```

The MVP is a field of each bulletproof *statement*, not metadata checked afterwards. The proof
therefore attests that the value lies in `[MVP, 2^64)`. This is the whole mechanism Ghost Gate
rests on.

**This is finding H1, confirmed.** The cohort's own test pins it:

`crates/wallet/crypto/src/stealth.rs:414-421`

```rust
#[test]
fn it_is_invalid_if_minimum_value_changed() {
    let mut proof = create_valid_proof(100, 100);
    proof.outputs[0].output.minimum_value_promise = 99;
    validate_stealth_outputs_statement(&proof, None).unwrap_err();
    proof.outputs[0].output.minimum_value_promise = 1000;
    validate_stealth_outputs_statement(&proof, None).unwrap_err();
}
```

Ghost Gate reproduces this independently in `crates/ghost-gate-tests/tests/mvp_and_shape.rs`
(`mutating_mvp_after_proof_breaks_validation`), calling the engine's validator directly.

## 4. MVP above value is refused at construction

**VERIFIED** — `crates/ootle_wasm/core/src/stealth/outputs.rs:150` and
`crates/ootle_sdk_core/src/stealth/outputs.rs:120`

```rust
if params.minimum_value_promise > params.amount {
    return Err("minimum_value_promise ({}) must be <= amount ({})");
}
```

Checked before the proof is built, in both the WASM output constructor and the SDK one. A prover
cannot construct an output promising more than it hides. Pinned by the cohort's own test
`create_witness_rejects_minimum_value_promise_above_amount`
(`crates/ootle_wasm/core/src/stealth/outputs.rs:474`).

Ghost Gate refuses the same case a second time, before calling into the crypto layer, so the failure
names the wallet's own rule rather than a generic crypto error.

## 5. MVP is not settable through the ordinary wallet path

**VERIFIED** — `crates/wallet/sdk/src/apis/stealth_outputs.rs:929-963`

`StealthOutputsApi::create_output_witness` builds `OutputWitness { .., minimum_value_promise: 0, .. }`.
The value is a literal zero, and the function takes no MVP argument. Every statement the wallet
builds through this path therefore promises zero.

Also zero, unconditionally, in three other places:

- `crates/wallet/sdk/src/apis/confidential_transfer.rs` region — the confidential output witness
  (`applications/tari_walletd/src/handlers/confidential.rs:158,200,313`)
- `crates/ootle_sdk_core/src/stealth/assemble.rs:622,1051,1166,1263,1467`
- `crates/engine/src/runtime/impl.rs:3755` — the engine's own `mint_stealth` output

**Consequence for Ghost Gate.** The stock wallet cannot produce an MVP-bearing output. Two options
existed:

1. Reuse a wallet output and mutate the promise afterwards. **Impossible** — finding 3 shows the
   mutation invalidates the range proof.
2. Set the promise on the witness *before* the statement is built. This is what
   `ghost-gate-wallet::qualifying_output_witness` does.

Option 2 is sound because the promise is public, and soundness comes from the proof being generated
*over* it: the value is already committed inside the mask, `encrypted_data` is already encrypted to
the owner's view key, and the bulletproof is generated against the promise. A promise larger than
the value is unforgeable, because the proof would not verify. No secret is involved.

This is the one place Ghost Gate writes code against the wallet's crypto layer rather than calling
a high-level SDK API, and it is documented at the top of `crates/ghost-gate-wallet/src/lib.rs`.

## 6. Range proof aggregation

**VERIFIED** — `crates/engine_types/src/crypto/range_proof.rs:37-67`

- Zero outputs requires an empty proof; a non-empty proof is rejected.
- Statement count must be a power of two, padded with zero-commitment, MVP-zero statements.
- Count above `MAX_LAZY_BP_AGG_FACTORS` is rejected.

So the number of outputs in a statement is itself bounded, and padding statements carry MVP zero —
a padded statement can never satisfy a threshold check. Relevant because Ghost Gate requires exactly
one output anyway.

## 7. `ResourceManager::stealth_transfer`

**VERIFIED** — `crates/template_lib/src/resource/manager.rs:558`

```rust
pub fn stealth_transfer(&self, transfer: StealthTransferStatement) -> Option<Bucket> {
    self.stealth_transfer_internal(transfer, None)
}
```

Returns `None` when the statement has no revealed output. Ghost Gate relies on that: it requires
`revealed_output` to be absent and asserts the call returns `None`, so a proof cannot smuggle a
cleartext bucket into the gate's workspace.

Variant `stealth_transfer_with_opt_input_bucket` (line 567) additionally takes an input bucket for
revealed input amounts. Ghost Gate does not use it: it requires the revealed input amount to be
zero.

## 8. Stealth transfer validation in the engine

**VERIFIED** — `crates/engine/src/runtime/impl.rs:4186`

`Runtime::stealth_transfer` is the single path both a `StealthTransfer` instruction and a template's
`ResourceManager::stealth_transfer` reach. In order:

1. `tracker.account_fee_inte_gate_stealth_transfer()` — the fee-intent cap (line 4200).
2. Read the resource substate, charge native execution points for the statement (4206-4217).
3. `self.verify_input_authorizations(resource_address, &statement)` (4227).
4. `state.execute_stealth_transfer(...)` — validation and spend (4229-4238).

Because there is one entry point, a template cannot bypass any of it. Ghost Gate's template calls
`ResourceManager::stealth_transfer` and inherits all four steps.

Comment at 4219-4226 states the invariant explicitly: authorisation happens before the spend, so a
rejection leaves inputs unspent.

## 9. Key-path authorisation

**VERIFIED** — `crates/engine/src/runtime/impl.rs:817-893`

```rust
SpendWitness::KeyPath => {
    let Some(pk) = input_auths[index].spend_key() else { ... InvalidSpend ... };
    let badge = NonFungibleAddress::from_public_key(*pk);
    let in_scope = self.tracker.read_with(|state|
        state.base_call_scope().auth_scope().contains_badge(&badge));
    if !in_scope {
        return Err(RequiredSignatureMissingForStealthUtxo { commitment, public_key: *pk });
    }
}
```

The UTXO's committed `spend_key` becomes a badge, and the transaction's auth scope must contain it.

**This is finding H2, confirmed.** Two properties matter for Ghost Gate:

- The check reads the UTXO's *own* committed spend key, so a normal wallet output works with no
  Ghost Gate involvement in authorisation.
- It consults `base_call_scope()`, which is `initial_call_scope`
  (`crates/engine/src/runtime/working_state.rs:1689`). **The badge requirement is evaluated against
  the transaction's outermost scope, not the template's local scope.** A key-path input therefore
  survives being spent from inside a custom template call — which is what H2 doubted and what the
  whole design needs.

Confirmed by the cohort's own `programmatic_transfer` test
(`crates/engine/tests/stealth.rs:237-275`): a transaction calls a template method with a statement
whose inputs are key-path, and the template performs the transfer inside. The signature that
authorises it is the transaction seal, added with `.add_signer(...)`.

## 10. `SpendWitness` selection

**VERIFIED** — `crates/template_lib_types/src/stealth/spend_witness.rs:20`

```rust
pub enum SpendWitness {
    KeyPath,
    ScriptPath { leaf: SpendCondition, proof: MerkleProof, data: Bytes },
}
```

Per input, chosen by the spender. The committed `SpendAuthorization` gates which are admissible;
the engine never assumes which the spender picks.

`is_key_path()` (line 64) is a `const fn`. Ghost Gate uses it to require key path for every input,
which is what makes the product claim ("ordinary wallet funds") true rather than approximate.

## 11. `SpendAuthorization`

**VERIFIED** — `crates/template_lib_types/src/stealth/unspent_output.rs:64`

```rust
pub enum SpendAuthorization {
    Key(RistrettoPublicKeyBytes),
    Script(Hash32),
    KeyAndScript { spend_key: RistrettoPublicKeyBytes, condition_root: Hash32 },
}
```

No `{no key, no conditions}` variant, so a decoded output is always spendable by construction.

Ghost Gate requires `spend_key().is_some()` — rejecting `Script`-only. A script-only output would
satisfy a threshold while parking the funds behind a predicate, which is not "you control enough
right now", and it would leave a public beacon attached to the funds.

## 12. Template-visible statement types

**VERIFIED** — `crates/template_lib/src/prelude.rs:64-84` re-exports
`StealthTransferStatement`, `StealthInputsStatement`, `StealthOutputsStatement`, `SpendAuthorization`,
`SpendWitness`, `SpendCondition`, `MerkleProof`, `CurrentInputView`, `StealthInputView`,
`StealthOutputView`.

A template receives the statement as a decoded argument with no host call, so every structural rule
Ghost Gate enforces is computable on chain.

## 13. `Consensus::current_epoch`

**VERIFIED** — `crates/template_lib/src/consensus.rs`

`Consensus::current_epoch() -> u64`, an engine op (`EngineOp::ConsensusInvoke`,
`ConsensusAction::GetCurrentEpoch`). Also `current_epoch_hash() -> Hash32`.

Ghost Gate compares this against `challenge.expires_epoch`. Expiry is therefore enforced by
consensus, not by the relying site's clock.

## 14. `CallerContext::current_component_address`

**VERIFIED** — `crates/template_lib/src/caller_context.rs`

The address of the component being called. Ghost Gate compares it against `challenge.gate`, so a
challenge minted for gate A cannot be redeemed at gate B. Self-address binding without any stored
address.

## 15. Challenge issuance by the template

**STRONG INFERENCE** — no cohort mechanism issues challenges.

Challenges in the reference are either off-chain (backend-held) or on-chain (a `burn` claim with a
prover-supplied statement). A template that wants single-use semantics stores state; the cohort has
`BTreeMap`-shaped component state and `HashSet`-shaped state
(`crates/engine/tests/templates/signature/src/lib.rs:18` uses `HashSet<PublicKey>`), so a
`BTreeMap<Hash32, u64>` of burnt nonces is idiomatic and decodable.

Ghost Gate does exactly this: `burnt_nonces: BTreeMap<Hash32, u64>` mapping nonce to the epoch it was
burnt at. Replay is refused when the nonce is present.

**Not established:** the storage cost of a growing map, and whether unbounded growth is acceptable.
Noted in `docs/THREAT_MODEL.md`.

## 16. Events and receipts

**VERIFIED** — `crates/template_lib/src/events.rs`

`emit_event(topic, payload)` with `EngineOp::EmitEvent`. Events are recorded in the transaction
result.

Ghost Gate emits topic `GG` with a CBOR-encoded `ProofReceipt`: the attested minimum, the input
count, and the burnt nonce. No value, no address, no identity. Safe to hand to an indexer.

## 17. Component state

**VERIFIED** — `crates/engine/tests/no_std.rs` reads a single-field struct through
`IndexedValue::get_value("$.0")`, confirming minicbor encodes `#[n(i)]` structs as arrays indexed by
field number. Ghost Gate's gate state therefore decodes positionally, and any field added later
must keep its index.

## 18. Test harness: compiling the template

**VERIFIED** — `crates/template_test_tooling/src/compile.rs:18`

`compile_template` runs `cargo build --target wasm32-unknown-unknown --release
--config profile.release.strip="symbols"`, in the template's own directory, with
`CARGO_TARGET_DIR` set to a per-feature-key subdirectory.

Consequences for Ghost Gate:

- `wasm32-unknown-unknown` must be installed (it is).
- The template must be `crate-type = ["cdylib"]`.
- Templates must ship stripped: `WasmModule::validate_code` rejects custom sections other than
  `tari_tdef`.
- The template directory must be its own workspace (it has `[workspace]` in its `Cargo.toml`),
  because it is built for a different target.

## 19. `TemplateTest` API

**VERIFIED** — `crates/template_test_tooling/src/template_test.rs`

| Method | Line | Use in Ghost Gate |
|---|---|---|
| `new(base_path, template_paths)` | 170 | construct the harness with the template |
| `bootstrap_state` | 302 | called automatically; seeds TARI resources and builtin faucets |
| `get_template_address(name)` | 557 | resolve the compiled template |
| `get_previous_output_address(SubstateType)` | 481 | find the gate component / resource just created |
| `call_function` / `call_method` | 596 / 631 | convenience single-instruction helpers |
| `execute_expect_success` / `execute_expect_failure` | 979 / 991 | run a full transaction |
| `secret_key` / `to_public_key_bytes` | 669 / 686 | the default signing key |
| `enable_auto_add_proofs_from_signers` | 382 | on by default; adds proofs from signers |
| `read_only_state_store` | 430 | inspect committed state |
| `extract_component_value<T>(addr, path)` | 444 | read a field out of the gate's state |
| `create_empty_account` / `create_funded_account` | 695 / 710 | an account component with an owner key |

`enable_fees` (368) is off by default, so tests do not need a funded fee account.

## 20. Builtin templates and the reference tree

**VERIFIED** — `crates/template_builtin/build.rs`

`crates/template_builtin/.gitignore` contains `compiled/`, and `templates.rs` does
`include_bytes!("../compiled/account.wasm")`. The compiled builtins are therefore absent from a
fresh clone, and the build script produces them by compiling five templates into its own crate tree.

`tari_template_test_tooling` depends on `tari_template_builtin` with `features = ["templates", "state"]`,
so any engine-backed test triggers those writes.

Consequence: building against the reference checkout in place would modify it. Ghost Gate builds
against a verified copy (`scripts/prepare_reference.sh`), leaving the reference pristine. This was
hit as a real failure first, not anticipated:

```
error: failed to run custom build command for `tari_template_builtin`
  Error: Copy file to dest / The system cannot find the path specified. (os error 3)
```

## 21. The engine does not build on Windows

**VERIFIED** — `wasmer-compiler-cranelift-7.4.0/src/lib.rs:21-24`

```rust
#[cfg(target_os = "windows")]
compile_error!("The Cranelift compiler backend is not supported on Windows. Use the V8 backend instead.");
```

`tari_engine` depends on `wasmer = { features = ["cranelift"] }`, and the accepted module set and
memory tunables are consensus-critical and pinned (`~7.4.0`, with a comment that a bump must be a
deliberate reviewed change). There is no supported way to swap the backend.

Consequence: engine-backed tests run in WSL on Linux. `scripts/wsl_run.sh` syncs the tree to a
native-Linux path and runs cargo there. Pure-Rust suites that do not pull the engine run on Windows
and are useful for a fast inner loop.

## 22. Wallet input selection

**VERIFIED** — `crates/wallet/sdk/src/apis/stealth_transfer/api.rs`

| Path | Line | Behaviour |
|---|---|---|
| `lock_inputs_for_transfer` | 123 | locks inputs, holding back `FEE_INTENT_INPUT_RESERVE` |
| `UtxoInputSelection::ConfidentialOnly` | 169 | `lock_outputs_for_at_least_amount` |
| `UtxoInputSelection::PreferRevealed` | 224 | spends the account's revealed balance first |
| `UtxoInputSelection::PreferConfidential` | 289 | `lock_outputs_until_partial_amount` |
| `InputSelection::Specific` (RPC) | — | `lock_specific_outputs`, exact named UTXOs, caller-supplied order |

`MAX_TRANSFER_INPUTS` bounds the count. Fragmented inputs are therefore ordinary: selection is
wallet-side and the statement is the same shape whatever the input count. Ghost Gate's
`fragmented_inputs_qualify_once` test covers four inputs.

**Relevant security note** in the RPC handler (`applications/tari_walletd/src/handlers/accounts.rs:1691-1699`):
naming exact UTXOs requires scoped `StealthUtxos::Read` authority in addition to the transfer scope.

## 23. Statement creation RPC

**VERIFIED** — `applications/tari_walletd/src/handlers/accounts.rs:1631`
`handle_create_stealth_transfer_statement`, registered at `server.rs:201` as
`accounts.create_stealth_transfer_statement`.

Request: `AccountsCreateStealthTransferStatementRequest { requests: Vec<TransferStatementRequest> }`,
each with `sender_account`, `resource_address`, `input_selection`, `outputs`. At most 16 requests.

Response: `AccountsCreateStealthTransferStatementResponse { statements, lock_id, signing_keys, utxo_signers }`.

Note: `TransferOutput` (`crates/wallet/sdk/src/apis/stealth_transfer/params.rs:115`) carries
`address`, `revealed_amount`, `blinded_amount`, `memo`, `pay_to` — **no MVP field**, consistent with
finding 5.

The response also says explicitly: "Return without unlocking the outputs".

## 24. Signing and submission

**VERIFIED** — `applications/tari_walletd/src/handlers/transaction.rs`

`submit_inner` (line 145):

```rust
let stealth_signers = derive_stealth_signers(sdk, &req.lock_ids)?;   // line 200
...
for key in req.other_signers { transaction = local_signer.sign(key, transaction)?; }
for key in &stealth_signers { transaction = local_signer.sign_with_stealth_key(key, transaction)?; }
let transaction = sdk.signer_api().sign(req.seal_signer, transaction)?;   // line 214
```

`derive_stealth_signers` (line 251) derives the per-UTXO stealth spend keys **from the locks**, not
from the caller:

> "Derived from the wallet's own record of what each lock locked, never from the caller. ...
> re-deriving here means the locked outputs are the only thing that decides."

That is the load-bearing property for Gate 3: a caller cannot name the keys the wallet signs with.
Only `LockedForSpend` outputs contribute; a view-only output is a hard error.

`sign_with_stealth_key` lives at `crates/wallet/sdk/src/apis/signer.rs:72`.

## 25. Custom instruction submission

**VERIFIED** — `applications/tari_walletd/src/handlers/transaction.rs:70`
`handle_submit_instruction`, registered as `transactions.submit_instruction`.

Takes `CallInstructionRequest { instructions, fee_account, max_fee, min_epoch, max_epoch, inputs,
override_inputs }`. The wallet builds the transaction from caller-supplied instructions, pays the
fee from a named account component, and signs with the fee account's owner key.

**This is the RPC a Ghost Gate flow needs**: `create_stealth_transfer_statement` produces the
statement and the lock, the caller appends a `CallMethod` to the gate component, and
`submit_instruction` has the wallet authorise and sign it. The caller never holds a key.

## 26. Finality observation

**VERIFIED** — `clients/wallet_daemon_client/src/types.rs`, RPC `transactions.wait_result`
(`server.rs:165`, handler `transaction.rs:640`), and `TransactionFinalizedResult`
(`crates/wallet/sdk/src/network.rs:138`):

```rust
pub enum TransactionFinalizedResult {
    Pending,
    Finalized { final_decision: Decision, execution_result: Option<Box<ExecuteResult>>, ... },
    Rejected { details: String, rejected_time: PrimitiveDateTime },
}
```

Three distinct states, and `Rejected` is explicitly documented as "rejected by mempool validation at
submission and was never sequenced". Ghost Gate's verifier treats `Pending` and `Rejected` as
granting nothing, and requires `Committed { accept: true }`.

**This is finding 25, confirmed.**

## 27. JS wallet client coverage

**VERIFIED** — `clients/javascript/wallet_daemon_client/src/index.ts`

The client wraps `accounts.stealth_transfer` (line 430) and
`accounts.create_stealth_transfer_statement` (line 436) alongside the other routes.

`bindings/src/wallet-types.ts` exports the generated types, and
`bindings/src/types/StealthTransferStatement.ts` exists. The release note that the JS client now
covers every walletd JSON-RPC route is consistent with what is in the tree.

**This is finding H5, confirmed for the routes Ghost Gate needs.** No custom client or
regeneration was required.

## 28. Transaction input read/write intent

**VERIFIED** — `crates/wallet/sdk/src/apis/stealth_transfer/api.rs:491`

```rust
// A transfer reads the resource without altering it.
substate_inputs.push(InputDeclaration::read(params.resource_address));
```

A Ghost Gate call additionally needs write access to the gate component (to record the burnt nonce),
so `submit_instruction`'s `inputs` must include `InputDeclaration::write(gate_component)`.

## 29. Test tooling helpers for stealth

**VERIFIED** — `crates/template_test_tooling/src/support/stealth.rs`

| Symbol | Line | Note |
|---|---|---|
| `generate_mint_statement` | 66 | builds a mint statement with output specs |
| `generate_transfer_data` | 195 | the general-purpose helper: inputs, outputs, revealed amounts |
| `generate_transfer_data_to` | 221 | names a specific revealed receiver |
| `spend_first_input_twice` | 143 | hand-assembles a double spend the engine must reject |
| `StealthSecretTransferData::input_spec_for` | 178 | builds an `InputSpec` from a generated output |
| `OutputAuthSpec` / `InputAuthSpec` | `spec.rs:9` / `spec.rs:92` | key-path vs conditions vs both |

Every one of these hardcodes `minimum_value_promise: 0` (lines 124, 130, 189, 194). None can build
an MVP-bearing output, so Ghost Gate's engine tests construct their own witnesses with
`tari_ootle_wallet_crypto` and hand them to the engine — which is also a stronger test, since it
does not rely on the harness's opinion of a valid statement.

`spend_first_input_twice` is worth noting: it exists because the *builder* refuses to construct a
double spend, and the engine still has to reject one. The same shape applies to Ghost Gate's
adversarial cases — several are assembled by hand precisely because a well-behaved builder will not
produce them.

## 30. Key derivation for the qualifying output

**VERIFIED** — `crates/wallet/crypto/src/api.rs:96`

```rust
pub fn derive_stealth_owner_public_key(&self, network: Network, public_key: &RistrettoPublicKey,
                                       nonce_secret: &RistrettoSecretKey) -> RistrettoPublicKey {
    kdfs::owner_stealth_dh_stealth_address(network, public_key, nonce_secret)
}
```

Network-domain-separated. Ghost Gate threads a `Network` through statement assembly so the derived
spend key differs per chain.

`encrypt_value_and_mask` is at line 125; `owner_stealth_secret` (the matching private half) at 105.

## 31. Network is not observable from a template

**UNKNOWN** — no host op reports the network to a template.

`Consensus` exposes only `current_epoch` and `current_epoch_hash`. `CallerContext` exposes caller
component address, signer proof and the like. There is no `get_network`.

Consequence: `ghost_gate_core::NETWORK_BYTE` is a constant (0) that the challenge must match, which
catches a *prover and gate disagreeing about the network*, but cannot detect a transaction admitted
on the wrong chain. That check belongs to the validator admitting the transaction at all, which is
outside Ghost Gate's reach.

**This is a real gap in the network-binding claim and is documented as such** in
`docs/PRIVACY_MODEL.md` and `docs/THREAT_MODEL.md`. The V1 statement is "this challenge and this gate
agree on the network byte", not "this transaction was validated on network X".

## 32. Live public testnet version

**UNKNOWN.**

`Live testnet version: not established.` No network call was made during the source trace, and the
v0.42.0 release notes state the public faucet is empty after the testnet reset. See
`docs/GATE0_RESULTS.md`.

## 33. Template-side statement construction is not exposed

**VERIFIED** — a template cannot mint a stealth output with a chosen MVP.

`ResourceBuilder::stealth()...initial_supply()` routes through `mint_stealth`, whose output witness
carries `minimum_value_promise: 0` (`crates/engine/src/runtime/impl.rs:3755`). The only way a
promise above zero exists is a prover-supplied statement, which is why the prover's wallet is
involved and why `ghost-gate-wallet` exists.

## 34. Fee-intent cap on stealth transfers

**VERIFIED** — `crates/engine/src/runtime/impl.rs:4200`, and the cohort's tests at
`crates/engine/tests/stealth.rs:159-214`.

`account_fee_inte_gate_stealth_transfer()` caps the number of stealth transfers performed in the fee
intent, which runs on free compute credit. The cap counts transfers *performed*, so routing one
through a template does not evade it (`fee_intent_counts_a_stealth_transfer_performed_from_wasm`).

Ghost Gate performs exactly one stealth transfer per proof, so a proof fits inside the cap. The fee
must be paid by a separate statement or a bucket, since the proof's own statement reveals nothing.

## 35. Balance proof

**VERIFIED** — `crates/wallet/crypto/src/stealth.rs:141` `create_transfer_statement`,
and `crates/wallet/crypto/src/balance_proof.rs`.

The balance proof signs the aggregate mask difference, bound to the input set, the output set and
the covenant claims. It is what makes "no coins created or destroyed" provable without revealing
values, and it is why the engine treats a missing balance proof as disqualifying.

`create_transfer_statement` also refuses to build a statement that spends the same commitment twice
(lines 184-188), with a comment explaining that the balance proof signs the mask difference alone so
a silently deduplicated statement would fail at the validator.

## 36. Covenant balance claims

**VERIFIED** — `crates/wallet/crypto/src/stealth.rs:236` `generate_covenant_claims`; keyed by
`partition_input_index`, one per distinct `condition_root` among script-path inputs.

Key-path inputs never join a covenant partition (`crates/engine/src/runtime/impl.rs:840-853`), so a
Ghost Gate proof made entirely of key-path inputs carries an empty `covenant_claims` list. Ghost
Gate's wallet assembler relies on this, and asserts it in a test.

---

## Findings the earlier v0.41 research proposed

| Hypothesis | Verdict | Finding |
|---|---|---|
| H1 — MVP binds the hidden amount; mutating it fails verification | **VERIFIED** | 3 |
| H2 — ordinary key-path inputs survive component usage | **VERIFIED** | 9 — the auth-scope check reads `base_call_scope()`, the transaction's outermost scope |
| H3 — script-path is not our target | **VERIFIED, and confirmed as the wrong path** | 9, 10 — the real check is on the UTXO's committed spend key against the transaction scope; `SpendWitness::KeyPath` is what ordinary wallet funds use |
| H4 — a custom template can consume a stealth statement and inspect outputs | **VERIFIED** | 1, 7, 12, plus the cohort's `programmatic_transfer` and `claim_funds` tests |
| H5 — v0.42 JS client covers every walletd route | **VERIFIED for the routes needed** | 27 |

## Assumptions that turned out to be wrong

Recorded because they changed the design:

1. **"The wallet can be asked for an MVP-bearing output."** It cannot (finding 5). Ghost Gate
   assembles the statement itself, inside the wallet, using the official crypto layer.
2. **"A template can observe the network."** It cannot (finding 31). Network binding is a weaker
   claim than intended.
3. **"The engine's test helpers can build MVP outputs."** They cannot (finding 29).
4. **"Engine-backed tests can run on the development machine."** They cannot (finding 21). WSL.
5. **"Building against the reference checkout is read-only."** It is not (finding 20).