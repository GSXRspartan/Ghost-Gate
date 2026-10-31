# GGBP-1 Wallet-Core Review Request

**Status: feature-disabled synthetic adapter. It did not open a wallet, read a wallet database,
contact a node, create a transaction, or expose an RPC/WASM/mobile API.**

## What this patch demonstrates

`crates/ghost-gate-minotari/src/ggbp1_wallet_adapter.rs` is a minimal, testable model of the
required *wallet-internal* operation. It owns synthetic output witnesses and can only:

1. accept only a runtime-authenticated synthetic request whose strict canonical HTTPS origin,
   network, genesis, generator, subject, threshold, and expiry are checked;
2. atomically select and lease at most 16 eligible synthetic `PushPubKey` outputs, excluding
   pending, encumbered, spent, invalid, immature, locked, unsupported-covenant, missing-script,
   and commitment-opening-inconsistent fixtures;
3. show a `Ggbp1WalletApprovalPrompt` containing canonical origin, network/genesis,
   gate/configuration, subject identity, threshold, expiry, selected public output references,
   and an exact request fingerprint;
4. generate an opaque foreground approval bound to that exact lease—there is no caller-provided
   approval trait, callback, signing handle, or Boolean; and
5. revalidate state/openings before proof creation and return only the pre-existing bounded
   canonical GGBP-1 response.

The adapter cannot return values, masks, script/spending keys, seeds, view keys, generic
signatures, a reusable approval capability, or a transaction. It makes no claim about an actual
Minotari output. Its passing tests use only in-memory synthetic fixtures and the independent
Tari-primitive verifier.

## Pinned implementation findings

The review target is the exact dependency cohort in `Cargo.lock`:

| Crate | Version | Relevant pinned implementation |
| --- | --- | --- |
| `minotari_wallet` | `6.0.1-pre.2` | `src/output_manager_service/handle.rs`, `storage/models.rs`, `commitment_mask.rs` |
| `tari_transaction_components` | `6.0.1-pre.2` | `src/key_manager/interface.rs`, `key_manager/manager.rs` |
| `tari_transaction_key_manager` | `6.0.1-pre.2` | `src/legacy_key_manager/inner.rs` |
| `tari_crypto` | `0.23.4` | Extended Pedersen and Bulletproofs+ primitives used by the synthetic verifier |
| `hmac` | `0.12.1` | Synthetic runtime-only opaque request/approval capability tags; not a relying-party protocol |

The existing output manager already has the wallet-local information an internal operation needs:
`OutputManagerHandle::get_unspent_outputs` returns `DbWalletOutput`; that record carries the
commitment, hash, status, mined height, and its `WalletOutput`. The latter keeps the value,
commitment-mask key ID, script, and script-key ID in the wallet process. The existing
`check_output_mask` verifies a stored commitment against the mask key ID and stored value.

The existing key-manager operation is insufficient as a public GGBP-1 API. Its
`construct_range_proof(mask_key_id, value, min_value)` operates on *one* opening. Its
`sign_script_message(key_id, challenge)` is generic transaction/script-adjacent signing. Neither
accepts a canonical GGBP-1 request, checks output eligibility, binds output references and
network, aggregates openings, requires wallet approval, or returns a complete GGBP-1 response.
Calling either directly from a dApp would be unsafe and is expressly not proposed.

## Smallest upstream API proposal

Add one non-exporting operation owned jointly by the output-manager and key-manager internals;
do not add a raw-signing method or key/mask getter. Names below are intentionally illustrative.

```rust
// Wallet-core/private module; not gRPC, FFI, WASM, or a public dApp trait.
fn authenticate_ggbp1_request(
    envelope: BoundedCanonicalRequestEnvelope,
    relying_party: OperatorPinnedHttpsIdentity,
) -> Result<AuthenticatedGgbp1Request, Ggbp1Error>;

fn prepare_ggbp1_proof(
    request: AuthenticatedGgbp1Request,
    current_tip: TrustedTip,
) -> Result<Ggbp1ApprovalPreview, Ggbp1Error>;

fn approve_and_create_ggbp1_proof(
    prepared: PreparedGgbp1Proof,
) -> Result<CanonicalGgbp1Response, Ggbp1Error>;
```

`prepare` must fail closed unless all conditions hold: request encoding/version/size is valid;
network and genesis match the configured wallet; threshold is nonzero and bounded; the subject is
wallet-controlled; each selected output is exactly the supported standard script form; output
status is unspent and unencumbered; maturity and confirmation policy are met; the output's stored
mask verifies against its stored value and commitment; and the aggregate fits the specified
scalar/value bounds. Selection must be deterministic and limited to the GGBP-1 response maximum.

`prepare` must atomically compare-and-reserve selected records in a separate durable proof-lease
registry. It must not hold an output-manager database transaction or wallet lock across the human
approval interaction. The normal transaction path must consult that registry before encumbering
or spending; expiry, cancellation, restart recovery, and a failed proof must release or safely
revalidate the lease without changing transaction encumbrance state.

`approve_and_create` must be foreground-only and owned entirely by the wallet runtime; it takes
no caller-supplied approval object. The UI must show the entire preview, including the canonical
origin, network/genesis, gate/configuration, authenticated subject, threshold, expiry,
output-reference disclosure, request fingerprint, and the fact that it sends no transaction.
After approval it must recheck the lease/output state and commitment-opening consistency, then
construct the dedicated-domain authority and subject signatures internally, sum the real
commitment openings, construct the reviewed aggregate minimum proof, serialize the bounded
canonical response, and release the reservation. It returns neither handles nor secret material.

The current wallet source can supply selection data and key IDs internally. The smallest missing
contract is therefore this high-level, all-or-nothing operation plus its aggregate-opening and
dedicated-authority-signature implementations. It must not be composed from public
`construct_range_proof` or `sign_script_message` calls.

## Review questions for Tari wallet maintainers

1. Is the proposed eligibility predicate complete for `DbWalletOutput` status, encumbrance,
   maturity, output version/range-proof type, and wallet recovery states?
2. Where should the durable proof-lease registry live so that output-manager transaction
   selection atomically respects it without treating a proof as a transaction encumbrance?
3. What exact relation between a standard `PushPubKey` output's script key and its spending
   authority should the new GGBP-1-only signer attest, and what domain/transcript is acceptable?
4. Can the lower-level Bulletproofs+ service accept one aggregate mask derived inside the key
   manager without returning individual mask scalars, and what overflow/scalar constraints must
   be enforced?
5. What authenticated current-UTXO evidence can a wallet provide to an independent verifier, and
   what reorganization/freshness contract is acceptable?

## Web Universe / chironbuilds boundary

Web Universe can adopt this only if the operation remains inside its Rust/WASM wallet core and its
same-origin UI owns `ForegroundWalletApproval`. A browser page may pass a bounded canonical
challenge and receive a canonical response after explicit approval; it must never receive an
approval capability, key ID, mask, value, script private key, seed, view key, generic signing
function, or cross-origin callback authority. The existing audited public Web Universe surface
does not yet provide this native-L1 operation, so no integration is enabled by this patch.

## Suggested review request

> Please review a feature-disabled, Rust-only wallet-core GGBP-1 prototype. It needs one
> user-approved operation that selects eligible standard UTXOs and internally creates the
> canonical aggregate balance proof. We explicitly do **not** request raw signing, key/mask
> export, transaction construction, RPC/FFI/WASM exposure, or production authorization. Review
> the eligibility/locking contract, exact output-authority relation, aggregate-opening primitive,
> generator/transcript compatibility, and independent current-UTXO evidence before any platform
> integration.

## Verification and current verdict

`cargo test -p ghost-gate-ggbp1-spike` passes 17 isolated tests, including forged request/approval
refusal, wrong origin/subject refusal, atomic competing reservations, spend conflict, cancellation,
lease expiry, synthetic restart recovery, post-approval state/opening revalidation, restricted
fixture filtering, canonical response decoding, and independent proof verification. `cargo check -p ghost-gate-minotari --features
experimental-ggbp1 --lib` compiles the feature surface. Existing unrelated warnings remain
outside this patch.

| Claim | Result |
| --- | --- |
| Mathematically plausible | Yes, subject to cryptographic review of the protocol statement. |
| Synthetic Rust proof verified | Yes; isolated Tari primitives and independent verifier pass. |
| Real Tari output verified | No. |
| Live Esmeralda tXTM proof verified | No. |
| Production security reviewed | No. |

One genuine Esmeralda tXTM proof still requires: a reviewed upstream wallet-core operation,
authenticated current-chain evidence from a synced Esmeralda source, a real output selected by
that wallet (without export), explicit foreground approval, cross-implementation test vectors,
and independent security review. None is enabled or attempted here.
