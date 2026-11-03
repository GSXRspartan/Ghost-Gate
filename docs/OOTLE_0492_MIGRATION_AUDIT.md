# Ootle 0.49.2 migration — Stage 1 impact audit

Audit date: 2026-11-02 (America/Los_Angeles). Canonical repository: `ghost-gate-public`, HEAD `f960d1575c7175f98625d2ae0015a300980b0b68`.

This is a source audit, not a successful migration or a live compatibility certification. Only this document was added to Ghost Gate. No implementation changes, builds, tests, commits, signed dry runs, transactions, wallet resets, service changes, deployments, or live-site updates were performed. The requested external upstream checkout was created separately.

## Findings that determine the migration

1. **The main workspace is a locally patched v0.42.0 cohort, not v0.47.0.** Its wallet MVP extension is still absent from stock v0.49.2. Merely changing version numbers will not compile or preserve the local walletd proof flow.
2. **Both active indexer readers are incompatible with the new value representation.** The v0.42 typed reader expects `response.substate`; the v0.47 JSON reader expects an object at `/state/up/substate/Utxo`. In v0.49.2, `state.up.substate` is base64-encoded CBOR. `ghost-gate-cbor` is a standalone generic decoder with no consumer in the active readers.
3. **No Ghost Gate template accepts a Tari authorization `Proof`, and no current Ghost Gate call uses account `*_with_auth`, `withdraw_approved`, or `create_ownership_proof`.** `prove_access` accepts `Challenge` and `StealthTransferStatement`. Do not add proof windows just because application types contain the word “proof.”
4. **Ghost Gate nevertheless relies on transaction signer authorization for spending inputs.** The upstream key-path verifier explicitly checks the transaction's base auth scope. This is distinct from lending a signer badge through nested component calls. Port signatures and test that path; do not replace it with resource-proof windows.
5. **No resource auth hook or component migration is configured by the three checked-in templates.** Fresh components can keep the locked upgrade default. The hook rule becomes relevant if an operator selects an externally created resource that has a hook.
6. **Existing non-genesis L2 state cannot be reused.** Templates must be rebuilt and republished; custom resources, accounts/components, UTXOs, and gate state must be recreated as applicable. Native TARI's constant address is unchanged; this does not preserve its balances or outputs. Browser credential gates need fresh outputs and policy/generation review, but do not inherently need a GhostGate on-chain component.
7. **The v0.47 sidecar is an isolated historical verifier, not an attached production verifier in this checkout.** Its types, checkpoint fixtures, release-derived root, epoch, and source pins cannot authenticate the reset chain. There is no call from the main bridge to its HTTP endpoint. Production-grade consensus evidence needs a reviewed v0.49.2 verifier and integration; an indexer's `verified: true` is not that evidence.
8. **Live readiness is unverified.** Public indexer health probes returned HTTP 403; the provider contract endpoint failed certificate validation. The VPS's deployed binaries, private registry, Worker catalog, and installed browser-wallet builds were not inspected. These are explicit release gates, not assumed compatible.

No new assertion of private, shielded, or confidential movement is made here. Names such as `StealthTransferStatement`, `ResourceType::Stealth`, and provider `shield` identify APIs. Post-migration movement claims require new committed receipts and balance/output evidence.

## 1. Exact dependency and version matrix

### Source provenance and upstream target

External reference: sibling checkout `../tari-ootle-v0.49.2-reference`. Remote: [official tari-project/tari-ootle](https://github.com/tari-project/tari-ootle). Detached HEAD is exactly tag **v0.49.2**, commit **aa7b0c81719e5c3cfaf9bf3b5fb87bd83180cb90**. Its worktree is clean. No upstream source was vendored into Ghost Gate, and the reference was not built or patched.

| Inspected ref | Exact commit | Purpose |
| --- | --- | --- |
| v0.47.0 | `9dabb2a76a9ad5c6e99dfa180ab7bbbcb1a05a47` | Historical handover/verifier baseline |
| v0.48.0 | `6a25dbc524581bfaa0a3c6ef120f8d59cc827572` | First reset, signatures, REST and SDK changes |
| v0.49.0 | `681287c8d62ae1b06acd56bdb403c60fec9b6f47` | Second reset and authorization changes |
| v0.49.1 | `b94de26c3ec463b17926a92f2189507a195ac00c` | Decoder/build fixes |
| v0.49.2 | `aa7b0c81719e5c3cfaf9bf3b5fb87bd83180cb90` | Required deployment target |
| origin/development at audit | `0c870120fee1cf729a381c86f85a12aa6c8922c3` | Current development changelog; byte-identical to v0.49.2 CHANGELOG.md |

Each requested tag's changelog was read from Git. Development's changelog was compared to the target. The reference uses a partial clone; missing historical blobs were fetched from the same official remote. No release-signature authentication ceremony was performed; exact source identity is recorded, but a future trust-anchor enrollment still needs its provenance review.

Primary upstream sources:

- [0.47 changelog](https://github.com/tari-project/tari-ootle/blob/v0.47.0/CHANGELOG.md), [0.48 changelog](https://github.com/tari-project/tari-ootle/blob/v0.48.0/CHANGELOG.md), [0.49.0 changelog](https://github.com/tari-project/tari-ootle/blob/v0.49.0/CHANGELOG.md), [0.49.1 changelog](https://github.com/tari-project/tari-ootle/blob/v0.49.1/CHANGELOG.md), [0.49.2 changelog](https://github.com/tari-project/tari-ootle/blob/v0.49.2/CHANGELOG.md).
- [Development changelog at audited commit](https://github.com/tari-project/tari-ootle/blob/0c870120fee1cf729a381c86f85a12aa6c8922c3/CHANGELOG.md).
- [0.49.2 transaction builder](https://github.com/tari-project/tari-ootle/blob/v0.49.2/crates/transaction/src/builder/mod.rs), [transaction fields](https://github.com/tari-project/tari-ootle/blob/v0.49.2/crates/transaction/src/v1/unsigned.rs), [signature implementation](https://github.com/tari-project/tari-ootle/blob/v0.49.2/crates/transaction/src/v1/signature.rs).
- [Indexer REST types](https://github.com/tari-project/tari-ootle/blob/v0.49.2/clients/tari_indexer_client/src/types.rs), [walletd RPC types](https://github.com/tari-project/tari-ootle/blob/v0.49.2/clients/wallet_daemon_client/src/types.rs).
- [Authorization guide](https://github.com/tari-project/tari-ootle/blob/v0.49.2/docs/developer-docs/src/content/docs/guides/authorization-and-access.mdx), [runtime input authorization](https://github.com/tari-project/tari-ootle/blob/v0.49.2/crates/engine/src/runtime/impl.rs), [account template](https://github.com/tari-project/tari-ootle/blob/v0.49.2/crates/template_builtin/templates/account/src/lib.rs).

### Ghost Gate build graphs

`Cargo.toml` declares 12 native members, application version 0.1.0, edition 2024, Rust 1.97.1. Each of the three template manifests has its own `[workspace]`, package version 0.1.0, edition 2024, Rust 1.97.1, and `cdylib`. The sidecar is a fifth independent Cargo build graph. There are **five lockfiles** to review: root, three templates, and sidecar. Upstream v0.49.2 also pins Rust 1.97.1, so no toolchain bump is demonstrated by this migration.

The main manifest's documented upstream baseline is v0.42.0, commit `a43773e600b9503ed3fadcd3f0048f86131e3644`. All listed path dependencies resolve through `../_ootle-v042-ghost-gate`, which resolved during the audit to a mutable local Ootle 0.42.0 worktree. The target's workspace version is 0.42.0 and its `TransferOutput` contains the MVP patch. It has no `.git`, so its full provenance cannot be independently established with `git rev-parse`; manifest comments and the lockfile are not a content attestation for that mutable copy.

The exact root dependency pins and target crate versions are in Appendix A. **Ootle release versions are not uniform crate versions:** target template library is 0.37.0, library types 0.36.0, transaction/engine 0.49.2, wallet SDK/client/storage 0.51.0, wallet crypto/indexer client 0.50.0. Do not set every dependency to 0.49.2.

| Area | Current dependency/code path | Migration consequence |
| --- | --- | --- |
| `templates/ghost_gate` | lib 0.33.0, ABI 0.20.1, path `ghost-gate-core`; `new`, `prove_access`, `set_open` | Rebuild with lib 0.37.0 and matching ABI/types/core; republish for Mode A |
| `templates/ghost_gate_faucet` | lib 0.33.0; `new`, `new_resource`, `mint` | Rebuild test fixture; recreate test resources, only publish if custom-resource/localnet scenario is used |
| `templates/ghost_gate_other_classes` | lib 0.33.0; public-fungible/confidential/NFT constructors | Rebuild negative-test fixture; no evidence it is a hosted production dependency |
| `ghost-gate-core` | types 0.33.0; minicbor 2.3; shape qualification, policy hashes and chain generation | Align typed wire objects; preserve policy compatibility and reset guard semantics |
| `ghost-gate-wallet` | crypto 0.44.0, transaction 0.42.0; `qualifying_output_witness`, `assemble_proof_statement` | Update view-key-based derivation and target types |
| `ghost-gate-walletd` | client/SDK 0.44.0; `stealth_utxos_list`, `accounts_create_stealth_transfer_statement`, `submit_transaction`, `wait_transaction_result` | Port MVP extension, signer types, receipt handling and readers |
| `ghost-gate-bridge` | core/registry/verifier; crypto 0.44.0, types 0.33.0; `credential.rs`, `server.rs`, reset/replay paths | Rebind state generation; retain independent off-chain ownership signature verification; wire new chain evidence where required |
| `ghost-gate-verifier` | core/types and Tari crypto; `observe_and_authorize`; hosted contract | Its standalone hosted verifier intentionally returns UNKNOWN without a chain implementation; not an alternative to upgrading the reader |
| Registry | `ghost-gate-registry`, core, serde, blake3 1.8.7 | Off-chain JSON registry; regenerate published bindings as needed and advance durable generation; no on-chain “registry template” found |
| Admin plane | core/registry, p256 0.13.2, Tari crypto 0.23.4 | Own WebAuthn and wallet challenge implementation; unrelated to walletd WebAuthn setup token |
| Telegram | reqwest 0.12, serde/tokio; bridge API client | No direct Ootle SDK dependency; admission must refuse pre-reset authorizations |
| Sapient / Web Tari Universe | `web/js/ghost/provider.js`, `capabilities.js`; dynamic `window.tari`; remote connector script | No wallet version pinned in this repository; capability and live contract tests required |
| Cloudflare | ES modules, no runtime Ootle package; Wrangler `^4.0.0`, lock 4.152.0; compatibility date 2026-10-23 | Catalog/backend generation/replay changes, not a demonstrated Worker SDK upgrade |
| v0.47 sidecar | `tools/ghost-gate-v047-verifier`, independent workspace, `.tari-v047-reference` paths | Referenced checkout absent here; recreate externally for implementation or replace cohort; don't vendor it |
| Minotari/GGBP-1 | Native L1 dependencies predominantly `6.0.1-pre.2`, Tari crypto 0.23.4 | Ootle reset alone does not reset L1. Isolate dependency alignment from any L1 protocol migration |

All three template locks resolve lib/types 0.33.0, ABI 0.20.1, macros 0.23.0, BOR 0.16.2, serde helper 0.6.0. The sidecar lock resolves engine/common/transaction/consensus/state-tree/storage 0.47.0, indexer client 0.48.0, light client 0.1.0, lib/types 0.35.0, ABI 0.21.0, byte type 0.17.0, BOR 0.16.5, serde helper 0.6.1, network 0.2.0, Tari crypto 0.24.1. Its manifest does not add numeric constraints to the local upstream paths.

The root explicitly uses `tari_crypto = "0.23.4"`, `tari_utilities = "0.10"`, `tari_shutdown = "6.0.1-pre.2"`, minicbor `2.3`. Upstream's target lock has crypto 0.24.1, utilities 0.10.0, shutdown 6.3.0-pre.2, minicbor 2.3.0, light client 0.3.0 and state tree 0.49.2. Keep the Minotari 6.0.1 graph separate where necessary; cross-crate key types cannot be assumed interchangeable between crypto versions. Target's lock also includes sidechain 8.0.0 and 9.0.0 transitively; the new Ootle header API is the 9.0.0 cohort.

## 2. Upstream breaking changes and 3. impact classification

Definitions: **BLOCKING** means the existing affected route cannot be treated as working on the target. **REQUIRES CHANGE** means a concrete code/config/build/operational action is identified. **LIKELY UNAFFECTED** means no affected direct usage was found; this is not a test pass. **NEEDS LIVE VERIFICATION** means deployment state or a third-party capability cannot be settled from this checkout. These labels concern individual changes, not permission to deploy.

### v0.47 baseline gaps, relevant because the main workspace starts at v0.42

| Change | Classification | Ghost Gate evidence/action |
| --- | --- | --- |
| Validator-set handover and changed committee/proof formats; synchronized node/indexer upgrade | BLOCKING for independently verified current-chain evidence | Existing sidecar pins v0.47 and epoch 12634; port to the target light client and re-bootstrap |
| REST `substate` becomes `state`; down proofs can accompany HTTP 200 | REQUIRES CHANGE, partially handled already | `esmeralda.rs` handles old v0.47 objects; target CBOR and exact down/proof semantics still need implementation |
| Default wallet indexer verification | NEEDS LIVE VERIFICATION | v0.48 reverses this default; explicitly select target trust policy |
| Removed GraphQL config/server | LIKELY UNAFFECTED | No Ghost Gate GraphQL client/config usage found; audit any separately managed indexer config |
| Removed `tari_debug`/`engine_debug!`; lib 0.35 | LIKELY UNAFFECTED at source, rebuild required | No such import/macro found in the three templates; old WASM is not a reusable target artifact |
| Confidential outputs require positive minimum promise | LIKELY UNAFFECTED to the supported key-path output route | Negative resource-class fixture must continue rejecting unsupported classes; don't conflate confidential vault outputs with supported statement outputs |
| walletd wait limit/pending error and restricted signing key classes | REQUIRES CHANGE/verification of handling | `ghost-gate-walletd/src/lib.rs` maps wait errors to timeout; verify reconciliation of Pending/1003, never resubmit blindly |

### v0.48.0 (first reset)

| Upstream change | Classification | Exact impact and required action |
| --- | --- | --- |
| Reset every validator, indexer and wallet DB; genesis state roots change; protocol history becomes V0 | BLOCKING | Old L2 state/evidence cannot authenticate the new chain. Reinitialize participating upstream services and wallet stores under a controlled reset; advance Ghost Gate chain generation |
| sr25519 transaction signatures and explicit main signer | BLOCKING for old transaction producers | Upgrade transaction, wallet crypto/SDK/client and engine together. `TransactionSubmitRequest` still carries a key ID and lock IDs; walletd signs. Preserve that custody boundary |
| libp2p sr25519 key type 5, new PeerIds | REQUIRES CHANGE for owned upstream services; otherwise LIKELY UNAFFECTED | Reset/reconfigure node peers if operated. Ghost Gate HTTP services have no libp2p identity |
| Required fields; `MainSigner` JSON accepts None/SealSigner/Authorizer only | BLOCKING for legacy serialized transactions | Use target serializer; no `is_seal_signer_authorized` or boolean main signer. `blobs`, `nonce`, `StealthInput.witness`, `FunctionDef.is_migration` are required. Target builder defaults to SealSigner and still takes `(network, max_epoch)`; an extra custom main-signer field is not automatically required in Ghost Gate code |
| `FinalizeResult` CBOR fields from result onward shift down one index | REQUIRES CHANGE | Decode receipts/execution results with target types. Revalidate `wait`, `attested_minimum_from` / `input_count_from`, deployer diff extraction and old fixtures |
| `XTR` alias removed; use `TARI`/`TARI_TOKEN` | LIKELY UNAFFECTED | No executable `XTR` usage found, only a test comment. Native constant used by Ghost Gate remains valid. Upstream still has some named `XTR_FAUCET_*` constants; do not mechanically rename those |
| RPC `transactions.get_all` -> `transactions.list`; `PayRef` -> `DestinationTag`; `value_summary` -> `value_summaries` | LIKELY UNAFFECTED directly | None of these old names is called by Ghost Gate source. Upgrade client types; provider internals remain a live compatibility risk |
| `webauthn.auth_start` drops username; `OutputStatus::Burnt` added | LIKELY UNAFFECTED directly; NEEDS LIVE VERIFICATION for wallet login | Ghost Gate's wallet adapter does not call WebAuthn RPC. Its Unspent selection and burnt/frozen exclusions must retain equivalent behavior with target output types |
| Spend keys derive from view-key DH `c = H(v·R)` | BLOCKING for old assembler/fixtures | `ghost-gate-wallet/src/lib.rs:166` calls the three-argument derivation. Target `crypto/src/api.rs:96` requires account public key, **view public key**, nonce secret, plus network. Update recipient secret derivation in tests too |
| Allowed-host enforcement on validator and walletd | NEEDS LIVE VERIFICATION | Local IP endpoints are appropriate. Only explicitly forwarded walletd/validator hostnames require their allowed-host config. Ghost Gate's separate `GG_BRIDGE_PERMITTED_HOSTS` is not walletd's setting |
| Indexer wallet trust default becomes `trust` | REQUIRES CHANGE if verification is required | Set upstream `indexer_trust = "verify"` explicitly and enroll a reviewed reset-chain anchor. This does not automatically upgrade Ghost Gate's separate HTTP reader or its trust tier |
| REST substate/receipt/event/resource/dry-run/UTXO values become base64 CBOR | BLOCKING | Both current readers fail the target representation. Wire bounded decoding and target `SubstateValue` mapping; preserve proof/value binding and fail-closed behavior |
| Remove GET `/utxos`; POST `/utxos/fetch` is UTXO-ID paginated | LIKELY UNAFFECTED directly; REQUIRES CHANGE in migrated dependencies | Ghost Gate readers use `/substates/{id}` and walletd uses `stealth.utxos.list`, not removed GET. Target SDK/provider scanners must handle `cursor`/`next_cursor`; don't confuse these APIs |
| Resource/input parsing suffixes validated from the right | LIKELY UNAFFECTED | Ghost Gate's checked-in address literals have no malformed `:version:junk` suffix. Retain malformed-address negative tests |
| Prune receipts/events after 1000 epochs and spent-output tombstones after 504; pruned event cursor -> 410 | NEEDS LIVE VERIFICATION and test change | Missing/pruned records must not become “unspent” or accepted. Set retention for an owned evidence-serving indexer if needed; keep old audit evidence outside its pruning store |
| New fee schedule: 250 micro-TARI per created substate, loading/pledging charges, fee scale (10000 bps at release) | REQUIRES CHANGE | Re-estimate proof, mint, publish and creation fees. Existing `GG_MAX_FEE` (default 100,000) and deployer's 5,000,000 ceiling are caps, not evidence of sufficiency |
| Opaque nonempty template metadata hash; binary hash commits value hash; existing-state creation -> Conflict | REQUIRES CHANGE | Rebuild/re-publish; use target publishing metadata/hash implementation. `metadata: None` at the walletd request layer is not by itself proof of an invalid hash; target handler computes it. Do not manually recreate old hash logic |
| Validator/indexer tracing logging config; removed scan interval flags; strict epoch-oracle keys | NEEDS LIVE VERIFICATION | No tracked upstream service config here. Inspect operator configs before startup; Ghost Gate systemd logging remains separate |
| Swarm instance `extra_args` -> `settings` | NEEDS LIVE VERIFICATION for external localnet harness | `scripts/ootle_e2e.sh` runs a scenario in the patched external cohort; that scenario/config is not completely versioned in this repo |
| `tari_sidechain` 9 header requires transaction Merkle root | REQUIRES CHANGE for consensus verification; LIKELY UNAFFECTED for standalone L1 holdings route | Target light-client/sidechain types must agree. No evidence Ghost Gate's L1 threshold reader decodes Ootle headers directly; do not reset/upgrade L1 wallets just because L2 reset |

### v0.49.0–v0.49.2 (second reset and authorization)

| Upstream change | Classification | Exact Ghost Gate impact |
| --- | --- | --- |
| Second complete reset for new component headers; fleet upgrades together without activation epoch | BLOCKING | Use v0.49.2-compatible services and fresh state. A v0.48 reset is not sufficient. Never restore v0.47/v0.48 DBs into this chain |
| Proof authority requires explicit caller-side windows | LIKELY UNAFFECTED directly | No Tari `Proof` parameters, `proof.authorize`, vault proof windows, or account `*_with_auth` usage in current templates/transaction calls |
| `AuthorizeProof` / `DropProofAuthorization`, manifest `authorize!` / `drop_authorize!` | REQUIRES CHANGE to SDK/wire cohort; LIKELY UNAFFECTED to current instruction sequence | No custom instruction enum decoder in browser code. Target libraries must understand variants; only emit windows when a new/actual proof-based authorization requires them |
| Windows lend one hop; proof arguments alone lend no authority | LIKELY UNAFFECTED to current call graph | GhostGate calls native `ResourceManager::stealth_transfer`, not another account with a shown Proof. Add targeted non-transitivity coverage if future code lends proofs |
| Signer/public-key badges remain scoped to stamped frames | REQUIRES CHANGE to signature cohort; NEEDS LIVE VERIFICATION of complete Mode A transaction | Current template has no nested signer-gated component call. Target `verify_input_authorizations` uses `base_call_scope().auth_scope().contains_badge` for KeyPath spends, preserving a direct transaction-authorizer path. Test missing/wrong spend signer and fee account separately |
| Removed signer/owner proof getters | LIKELY UNAFFECTED | No calls to removed getters in Ghost Gate templates or runtime code. Old skill examples and historical patch tests are not a target API specification |
| Account `withdraw_approved(spender_badge, resource, amount)`; remove `create_ownership_proof` | LIKELY UNAFFECTED | Neither is called here. Target `spender_badge` is `NonFungibleAddress`, checked with `assert_badge_in_scope`. Browser `tari_signOwnershipChallenge` is a different off-chain API and is not removed by this change |
| Built-in faucet `take_with_proof` removed | LIKELY UNAFFECTED directly | No caller found. GhostGateFaucet is a separate fixture with its own constructors/mint methods |
| Template lib 0.37, locked upgrade default, `upgrade_rule` component header | REQUIRES CHANGE for ABI/decoders/build; LIKELY UNAFFECTED to need for mutable code | Fresh deployment is sufficient. The changelog calls it `UpgradeRule::Locked`; exact template builder API at the target uses **`UpdateRule::Locked`** and `.with_upgrade_rule(UpdateRule)`. Do not implement the changelog's type spelling from memory |
| Component migration confinement, no signer badges; migration only rewrites own state | LIKELY UNAFFECTED | No migration entrypoints or upgrade operations exist. Off-chain registry generation migration is unrelated |
| Resource auth-hook component must be declared input; SDK auto-fill does not yet add it | LIKELY UNAFFECTED for repo-created resources; NEEDS LIVE VERIFICATION for selected external assets | No hook configured in the three templates. Inspect actual resource definition before enabling a gate. If a hook exists, add its component explicitly and test omission -> `AuthHookComponentNotDeclared` |
| Authorization metered per rule node/proof; templates/governance count for input load/fanout | REQUIRES CHANGE to fee evidence | Old dry-run/receipt fees cannot establish target caps. Do not waive fee tests because GhostGate's access rules are allow-all |
| First walletd passkey requires setup token, `reset-passkeys` added | NEEDS LIVE VERIFICATION for operator wallet setup; LIKELY UNAFFECTED to Ghost Gate admin | Preserve walletd API-token authentication; bootstrap through target wallet UI when needed. Never treat Ghost Gate's separate admin bootstrap token as walletd's token |
| v0.49.1 FFI value decoders, optional hex/duration binary-serde fixes; networking/build repairs | LIKELY UNAFFECTED directly, use final target | Ghost Gate has no C/Go FFI caller. Provider transitive dependencies still need matching schemas |
| v0.49.2 release build feature repair | REQUIRES CHANGE to binary target selection | Use 0.49.2; do not claim 0.49.0/0.49.1 binary availability from their release announcements. No extra application protocol change is documented for .2 |

Other changelog consensus/network/storage fixes are consumed through the coherent target node/engine/client upgrade; no separate application rewrite is inferred merely because a bugfix exists.

## 4. Exact files requiring modification or review

### Required implementation/build changes

| Files | Required work |
| --- | --- |
| `Cargo.toml`, `Cargo.lock` | Select coherent v0.49.2 source/package cohort; account for wallet MVP extension and crypto version split with L1 |
| `templates/ghost_gate/Cargo.toml`, `Cargo.lock`; same pair under `ghost_gate_faucet` and `ghost_gate_other_classes` | Upgrade template lib/types/ABI/macros as a coherent graph; rebuild all three WASMs |
| `crates/ghost-gate-wallet/src/lib.rs` | Pass view public key to target owner-key derivation; align crypto types; rebuild signatures/witness fixtures |
| `crates/ghost-gate-walletd/src/lib.rs` | Integrate target client plus reviewed MVP port; typed result/receipt handling; burnt/unspent filtering; main signer serialization and pending reconciliation |
| `crates/ghost-gate-walletd/src/indexer.rs` | Replace old `response.substate` access with target state/encoded-value decode; set proof request fields deliberately |
| `crates/ghost-gate-walletd/src/esmeralda.rs` | Replace v0.42/v0.47 object pointers with explicit target CBOR parsing or retire this adapter in favor of target typed reader; update tests/endpoints |
| `crates/ghost-gate-walletd/src/bin/ghost-gate-bridge.rs` | Replace the `minor >= 47` => legacy JSON-reader selection; do not label 0.49 credential mode enabled before compatible decode/evidence support |
| `crates/ghost-gate-walletd/src/bin/deploy_vault.rs` | Update types/publishing results and MVP output construction; preserve fee bounds; replace localnet-only assumptions before any Esmeralda use |
| `crates/ghost-gate-tests/tests/gate_engine.rs`, `adversarial.rs`, `cross_resource.rs`, `mvp_and_shape.rs` | Port signing/witness/key derivation and target engine fixtures; re-prove authorization, output binding and resource rejection |
| `crates/ghost-gate-walletd/tests/credential_real_chain.rs` | Remove old live-output dependency from current-chain assertions; use freshly recorded target fixtures/outputs |
| `docs/wallet-mvp.patch`, `scripts/wallet_mvp_patch.sh`, `scripts/wallet_mvp_patch.ps1` | Replace or version the v0.42 patch with a narrowly reviewed target patch; preserve original evidence as historical |
| `scripts/prepare_reference.sh`, `prepare_builtin_templates.sh`, `verify_patches.sh`, `check_gate3_integration.sh` | Change source SHA/tag/cohort assumptions and target regression checks; keep upstream reference immutable |
| `scripts/patch_test.sh`, `patch_sdk_test.sh`, `patch_walletd.sh`, `patch_build_localnet.sh`, `ootle_e2e.sh` | Select target scratch source, tests, and binary names; port external scenario rather than implicitly running v0.42 |
| `scripts/package-staging-source.ps1` | Stop packaging `_ootle-v042-ghost-gate`; record exact target source + patch provenance. Keep upstream a sibling artifact, never vendor into public repo |
| `scripts/check_layout.sh`, `check_ootle_bins.sh`, `check_targets.sh`, `wsl_bg.sh` | Update old tree/binary assumptions if retained as active migration tooling |
| `scripts/cdp-resume-check.mjs` | Review its recorded UTXO as a mock-only fixture; use a fresh generation-specific input if adapting this harness into a live test |
| `deploy/setup-vps.sh`, `.gitignore`, missing service env templates | Fix clean-clone provisioning: script expects three `deploy/ghost-gate-*.env.template` files absent from tracked tree; `.gitignore` currently excludes `deploy/*.env.*`. Add safe placeholder templates/exception in implementation, never real credentials |

`ghost-gate-cbor` is optional infrastructure for the new reader, not a second consensus decoder to invent. If used, add the dependency in `crates/ghost-gate-walletd/Cargo.toml` and typed mapping/real target fixtures in `crates/ghost-gate-cbor/src/lib.rs` and `src/tests.rs`. Alternatively use target `Encoded<SubstateValue>` decoding with explicit bounds; the generic crate need not be modified just to “use” it.

For independent consensus verification, migrate or replace **all** of `tools/ghost-gate-v047-verifier/Cargo.toml`, `Cargo.lock`, `src/lib.rs`, `src/bin/ghost-gate-v047-sidecar.rs`, `tests/esmeralda_release_handover.rs`, `README.md`, and its `evidence/` current-fixture selection. Preserve original captures as historical evidence. Integrate the verifier through the chain-reader/evidence boundary and bridge `credential.rs`/`server.rs`/`access.rs`; renaming the executable alone is insufficient. Root `ghost-gate-core` evidence types, registry trust derivation, and transport authentication must continue refusing unverified promotion.

### Review/test before deciding on source edits

- `templates/*/src/lib.rs`: recompilation is mandatory, but no Proof-window, hook, or upgrade-rule source edit is established by current usage. Apply only target compiler/API changes actually needed. Separate finding: `GhostGate::set_open` is exposed under `AccessRules::allow_all()` despite an operator-action comment. This is pre-existing, not caused by 0.49; review before treating an on-chain close as an access-control guarantee.
- `crates/ghost-gate-core/src/lib.rs`, `src/policy.rs`; `ghost-gate-registry/src/lib.rs`; bridge `reset_guard.rs`, `replay_store.rs`, `session.rs`, `gate_registry.rs`: preserve/retest generation and hash semantics. Do not rewrite them merely because the network resets.
- `crates/ghost-gate-bridge/src/credential.rs`, `ghost-gate-admin/src/auth.rs`, `examples/wallet_sign.rs`: distinguish application Schnorr challenge signatures from new sr25519 transaction signatures. Change framing/algorithm only against a verified provider contract, never by global replacement.
- `web/js/ghost/provider.js`, `capabilities.js`, `ghost-gate.js`, `test.js`; `web/lab/lab.js`, `wallet-connection-state.js`, `technical-state.js`; `web/hosted.js`; `web/telegram/claim.js`, `join-endpoints.js`: fresh provider/result fixtures, reset/resume behavior and current capability tests. No demonstrated requirement to replace the UI architecture.
- `cloudflare/src/worker.js`, `contracts.js`, `backend-state.js`, `replay-coordinator.js`: test generation/policy/halt rejection; change code only if target payload contract changes. Render new catalogs through `scripts/render-worker-catalog.ps1` and assets through `prepare-staging-web.ps1`.
- `deploy/*.service`, `cloudflared-config.yml.template`, `healthcheck.sh`, `backup.sh`: confirm binary/config/state locations and restore exclusions. No protocol-driven requirement to expose walletd or admin publicly.
- `docs/walletd-cli-dup-short.patch`, `docs/ghsa-empty-proof.patch`: retire/reassess old patch applicability rather than blindly reapply. Target `tracker_auth.rs` already excludes empty proofs. Preserve a regression assertion if patch tooling changes.
- `README.md`, `docs/CLEAN_ROOM.md`, `V042_SOURCE_TRACE.md`, `V047_CONSENSUS_VERIFICATION.md`, `PROVIDER_COMPATIBILITY.md`, `MANUAL_TEST.md`, `VPS_PROVISIONING_RUNBOOK.md`, `NEXT_IMPLEMENTATION_HANDOFF.md`, `ESMERALDA_RELEASE_BOOTSTRAP_POLICY.md`, `ESMERALDA_ANCHOR_INVENTORY.md`, `deploy/README.md`, `deploy/PRIVATE_ADMIN.md`, `cloudflare/README.md`: distinguish the new supported cohort from historical evidence and repair stale setup instructions.

## 5. Template republish and deployment inventory

| Artifact | What exists in source | Reset action |
| --- | --- | --- |
| GhostGate template | `templates/ghost_gate`, WASM artifact `ghost_gate_template.wasm` | Rebuild/re-publish if using consensus Mode A; read new published address and binary/metadata hashes from target receipt |
| GhostGate components | `new(allocation, resource, threshold, relying_site, session_commitment, network)` | Fresh allocation and creation per intended gate; record binding/threshold/session/network and new nonce state |
| GhostGateFaucet template/resource/component/vault | `templates/ghost_gate_faucet`, `ghost_gate_faucet.wasm`; constructors and mint | Test-only by source designation. Recreate only for required localnet/custom-resource tests; do not deploy an allow-all mint fixture as a production asset |
| GhostGateOtherClasses template/resources/vaults | `templates/ghost_gate_other_classes`, `ghost_gate_other_classes.wasm` | Rebuild for public-fungible/confidential/NFT rejection tests; publish only if those tests run on a network |
| Native TARI and built-in account/faucet templates | Upstream genesis/builtin artifacts | Supplied by reset chain; Ghost Gate does not republish native TARI. Create/fund fresh user/admin fee accounts as needed |
| Credential-mode Crypt/other registry gates | Off-chain policy records, component address may be absent | Rebind/review policies and advance generation; obtain fresh qualifying outputs. No automatic need to deploy GhostGate or its test faucet |

**Existing deployer:** `crates/ghost-gate-walletd/src/bin/deploy_vault.rs` publishes faucet + gate, creates a resource/faucet, funds the wallet, allocates gates `crypt`, `vault`, `abyss` with raw thresholds 100000 / 500000 / 2000000. It hard-codes network `0x10` (LocalNet), `vip.example`, `haunted-vault`, a 5,000,000 fee cap, and epoch ceiling 1,000,000. It is not an Esmeralda migration command. Its comment suggests content reuse but the publish function actually submits publication and extracts a newly upped template; verify target duplicate/Conflict handling rather than assuming idempotence.

**Scripts:** no standalone tracked shell/PowerShell script directly publishes on-chain templates. `prepare_builtin_templates.sh` builds upstream builtin artifacts; `check_gate3_integration.sh` checks copied external fixtures; `ootle_e2e.sh` invokes the external integration-tests cucumber harness, which can perform deployments. `admin_live_demo.sh` creates off-chain admin policy examples with dummy addresses, not on-chain components. `package-staging-source.ps1` packages source; `prepare-staging-web.ps1` and `render-worker-catalog.ps1` prepare web/catalog artifacts. `deploy/setup-vps.sh` installs services/config; it is not a template publisher. None was executed.

Prefer the target wallet Web UI for operator template publication; do not add a new publisher during migration. Any retained existing CLI deployer must first be made target-compatible and have its network/config assumptions reviewed.

## 6. Invalidated addresses, policy hashes, and persistent state

The complete tracked concrete address inventory is in Appendix B. It separates native/genesis constants, historical localnet outputs, a recorded browser-resume fixture, and dummy fixtures. The repository does **not** contain a complete live deployment manifest. Runtime `bindings.json`, environment gate lists, wallets and the live Worker catalog are intentionally outside tracked source; their exact deployed addresses/hashes cannot be inferred here.

| State/address category | Required disposition |
| --- | --- |
| Custom published template, faucet, resource, vault and GhostGate component addresses from either old reset generation | Rebuild/recreate and use receipt-derived addresses. Even if deterministic bytes recur, require new-generation evidence |
| User/fee accounts and their vaults | Recreate/recover using target wallet flow and resync fresh chain; old addresses alone are not evidence accounts exist |
| All old L2 UTXOs, commitments, balances, mint/transfer receipts, proof transaction IDs, pending transactions and scan cursors | Invalid as live reset-chain evidence. Archive; do not resume or resubmit old signed payloads |
| Native TARI `resource_0101010101010101010101010101010101010101010101010101010101010101` | Same constant in target `template_lib_types/src/constants.rs`; revalidate resource state, do not generate an arbitrary replacement address |
| Built-in faucet `component_0102030000000000000000000000000000000000000000000000000000000000` | Genesis constant; fresh state still must be verified. Existing ignored live test is version-specific |
| Network byte 38 / 0x26 | Esmeralda remains Esmeralda; not a reset discriminator |
| Policy version/hash, genesis identity, chain generation | Review actual chain identity and re-publish changed policy fields; advance chain generation beyond persisted floor. Do not fake a new genesis hash when upstream L1 identity is unchanged |
| Sessions, challenges, pending jobs, Telegram claims/admissions, browser resume storage, Worker authorizations | Old generation must fail; retain replay/tombstone/audit history so reset cannot resurrect authorizations |
| v0.47 validator-set roots/committees/checkpoints | Historical only; re-bootstrap independently against target generation and verify handovers |

`crates/ghost-gate-core/src/policy.rs` deliberately excludes `chain_generation` from the policy digest. Therefore **a reset does not necessarily change the policy hash** if all hashed policy fields remain identical. The generation guard is a separate mandatory binding. Do not manufacture a hash change by relabeling the resource or discard an old digest's historical meaning. If resource/component/domain/genesis/threshold or other hashed fields change, publish a new immutable policy version and render its canonical hash into the catalog.

The concrete policy hash `13af3169aefb313f355368c5b9131d512d86048ab700d850024c79ddb680b74f` is documented as the Crypt v3 policy in `docs/ARCHITECTURE.md:38–44` and repeated in tracked frontend tests (`cloudflare/test/lab-technical.test.js:12`, `telegram-join-config.test.js:10,49`). That documented binding is `https://ghostgate.boo`, network 38, raw threshold 100000000 (100 tTARI), credential mode. It is an operator-trusted testnet binding; its actual deployed version/hash after reset remains unverified. Synthetic repeated hashes in tests are fixtures. Sidecar bootstrap pins include source commit, signer fingerprint, policy version `ghost-gate/esmeralda-release-bootstrap/v1`, preset SHA-256 `e9b9badfb8061e982524c4176ae2336d44229c34b6d074ef128cd670e49d9df3`, epoch 12634 and four validator keys in `tools/ghost-gate-v047-verifier/src/lib.rs:38–67`. The root `dc39359775aa329670eb8cbfce7e1c77f7e5280d1ae334bc62bb46485c6c8956` and next root `23b6a682150e19910b13f626f89a6352212554a50625a3eaa85b88b74fa2fc7f` in old evidence must not be adopted for the reset chain.

## 7. Wallet, indexer and reset requirements

### Local walletd / Mode A

The required MVP port remains a real blocker: target `crates/wallet/sdk/src/apis/stealth_transfer/params.rs:150` defines `TransferOutput` without `minimum_value_promise`. Ghost Gate sets that field in both its daemon adapter and deployer. The existing patch threads it through output construction and rejects a promise above the blinded value before locking. Port those semantics and focused tests to a separate writable target source copy; do not apply the entire historical patch blindly to the immutable reference. Account-level statement creation and explicit input selection still exist upstream, so a fresh full wallet implementation is not indicated.

The bridge's default `GG_MAX_EPOCH` is 100 (`src/bin/ghost-gate-bridge.rs:393`); review a bounded current-epoch configuration rather than assuming the default will remain usable as the new network advances. This is an existing operational assumption, not a new upstream API requirement.

Upgrade the daemon and matching client/SDK together. Keep keys, masks and signing inside the wallet boundary. Reset/recover the target wallet after backups and operator review, then fund it from the new testnet. A backup is for recovery/audit, not for restoring old chain tables. Review API token/cookie authentication and first-passkey setup. `bootstrap_local_auth` currently requests Admin with `AuthCredentials::None` only when no token was supplied; test target auth mode behavior rather than weakening authentication to make that path work.

### Reader and verifier

At target, `GetSubstateResponse` has `version`, `state`, `verified`, optional `proof`. `state.up.substate` is `Encoded<SubstateValue>`; decode it with the target BOR/engine types, validate it is the requested UTXO, and derive floor/key from that decoded output. `GetSubstateRequest` adds `include_proof`. A proven Down response is conditional on the requested version and proof mode; otherwise unknown/down can be 404. Treat Down, missing output, absent key, unverified response, malformed/trailing CBOR, wrong resource, wrong value/proof and stale proof as refusal/unknown, never acceptance.

The current generic decoder bounds depth/size/width and retains bytes; it does **not** validate a UTXO schema, bind a value to a committee proof, or establish current unspent status. Its synthetic tests do not demonstrate decoding of real v0.49.2 captures. The old sidecar's `ConsensusProofRequest.value: SubstateValue` is also a v0.47 typed JSON boundary that must be deliberately migrated.

Select fresh anchors through the existing reviewed trust process. Do not anchor on the first public indexer answer, silently re-anchor on failure, or map indexer `verified` directly to `ConsensusVerified`. Current bridge configuration explicitly permits only an operator-trusted testnet tier when `GG_OPERATOR_TRUSTED_INDEXER` policy allows it. Production policy remains unavailable until independently verified evidence is integrated.

Upstream default Esmeralda endpoints are now `https://esme-indexer-a.ootle.tari.com/` and `https://esme-indexer-b.ootle.tari.com/` (`applications/tari_walletd/src/config.rs:477–478`). Historical tests still reference `https://ootle-indexer-a.tari.com`. On this audit's bounded public requests, **all three `/health` requests returned 403**; no version, sync readiness or active-chain epoch was established. Do not infer the cause or that the hosts are down. Verify from the deployment environment before setting `GG_INDEXER_ENDPOINT`.

No direct GET `/utxos` caller was found; `/wallet/utxos` appears only in a bridge refusal test. Target `/utxos/fetch` uses POST, `cursor: Option<UtxoId>` and `next_cursor`; its terminal cursor semantics must be tested in any new scanner/provider integration. Owned indexer retention must support the intended evidence freshness/history policy.

## 8. Sapient and Web Tari Universe risks

Ghost Gate uses the shared `window.tari` provider through `web/js/ghost/provider.js`. Browser Mode B requests `kind: "shield"` with `resourceAddress`, `amount`, `minimumValuePromise`; polls/approves/submits through the request API, then calls `tari_signOwnershipChallenge`. Capabilities must include the required spend/MVP/ownership support. Daemon-backed browser accounts can lack these capabilities; do not enable them by wallet name. Universe additionally requires its embedded iframe provider.

Transaction sr25519 migration does **not** prove a change to the application's ownership-challenge format. Current credential verification expects the domain `com.tari.paylink.ownership_proof.v1.v1` and Tari Schnorr nonce/scalar framing checked against the independently read output key. Keep it separate from transaction signing; require fresh provider-generated positive/negative vectors before changing it. Likewise, Ootle's removed account `create_ownership_proof` is not browser `tari_signOwnershipChallenge`.

The public pages load `https://universe.tari.mw/tari-connector.js` without a repository package/version pin. No installed Sapient/Universe build is pinned here. Historical `docs/PROVIDER_COMPATIBILITY.md` is useful architecture evidence, not a 0.49.2 certification. Browser Mode A remains unsupported by the recorded provider contract unless a wallet exposes a validated wallet-built Ghost Gate statement operation; do not make it available merely because the transaction SDK upgraded.

Bounded current-source checks: the [Web Tari Universe repository manifest](https://github.com/chironbuilds/tari-l1-wallet-ui/blob/master/package.json) returned package 0.1.0 with ranges `@chironbuilder/ootle-sdk ^0.1.29`, `@tari-project/ootle ^0.10.0`, indexer and secret-key-wallet `^0.10.0`, ts-bindings `^1.60.0`, wasm `^0.47.0`, wasm-bor `^0.48.0-rc.0`. These are manifest ranges from a moving branch, **not resolved versions or the deployed build**; they do not establish 0.49 authorization compatibility. The attempted Sapient `main/package.json` URL returned 404, so its current dependency/build version remains unverified. The live type-contract URL failed certificate validation; no TLS bypass was used and no site outage is asserted.

Acceptance gates: get actual wallet build/dependency versions; confirm target sr25519/MainSigner/required fields and view-key derivation; prove target CBOR decode and fresh scan completion; obtain one approved fresh output + committed result + ownership signature; reject old-generation output, wrong key, wrong network, spent/burnt/frozen output and forged floor. Exercise cancellation/pending/resume without duplicate broadcast. Record actual fees and output/balance changes before asserting movement properties. Native L1 XTM/GGBP-1 limitations remain separate and are not solved by this L2 migration.

## 9. VPS changes

Tracked systemd units describe bridge `127.0.0.1:7799`, private admin `localhost:7811`, and Telegram claim service `127.0.0.1:7808`, with binaries in `/opt/ghost-gate/bin` and per-service env files in `/opt/ghost-gate/etc`. Registry and replay data are separate under `/opt/ghost-gate/data`. The older `deploy/README.md` says there is no admin on the VPS, but `deploy/PRIVATE_ADMIN.md`, setup script and admin unit describe one: **this source inconsistency is not evidence of which service is currently running**.

Required implementation-stage operations, not performed here:

1. Inventory actual binary hashes/versions, systemd units, source archive manifest, endpoint/trust settings and state schema; record only non-secret configuration.
2. Build reviewed target bridge/Telegram/admin binaries from a reproducible archive. Correct `package-staging-source.ps1`'s v0.42 sibling tree assumption. Restore safe env-template files missing from the public checkout before relying on fresh provisioning.
3. Preserve registry, immutable policy versions, audit log, generation ledger, reset/halt revision and replay data. Latch/retain a maintenance halt; advance generation through the admin flow. Inspect old pending jobs before restart, so target startup cannot resume stale chain payloads.
4. Change `GG_INDEXER_ENDPOINT` and reader selection; validate target schema/health. If an independent verifier is deployed, update its binary, authenticated loopback transport, anchor config and readiness check together. No sidecar unit is tracked in this repository.
5. Keep admin SSH-forwarded and walletd private. The documented hosted credential route does not require VPS wallet custody. Only reset/upgrade walletd or upstream nodes if the operator actually runs them; no such upstream service units are tracked here.
6. Reconcile Telegram gate bindings and outstanding admissions via existing policy. Old sessions/claims must stop authorizing after generation change. Do not send messages, change membership, or revoke users during this audit.

The target network reset requires fresh **Ootle** DBs. It does not authorize deleting Ghost Gate replay/registry/audit data, Cloudflare Durable Objects, Telegram state, or L1 wallets.

## 10. Cloudflare changes

Worker entrypoint is `cloudflare/src/worker.js`; it proxies to the Rust backend and uses `ReplayCoordinator` through `REPLAY_COORDINATOR`. It does not directly parse Ootle CBOR or sign transactions. Existing `backend-state.js` checks policy hash, generation, halt revision, session TTL and authenticated backend state. Target compatibility belongs in the backend plus fresh catalog bindings unless evidence shows a changed app-level contract.

- Re-render `GG_GATE_CATALOG` from current **published** `bindings.json`, using the correct origin map and immutable version/hash. A constant TARI resource address does not excuse a stale generation.
- Preserve Worker script/namespace identity, Durable Object class and `v1` migration/history; do not create a fresh replay database to conceal stale state. Confirm old backend-state bindings/authorizations fail after generation/halt revision changes.
- Keep request/response HMAC and coordinator tokens separate; network reset is not itself evidence these secrets need rotation. No secrets were read.
- Rebuild generated staging assets only when the approved catalog/origin configuration requires it. Public page/provider caches must not revive old pending outputs.
- Keep tunnel path allowlists and 404 fallback. No change to public hostname, DNS, walletd exposure or admin routing is required by 0.49.2 itself.
- Config files are `cloudflare/wrangler.toml`, `wrangler.staging.toml.template`, `wrangler.ghostgate.toml.template`. Actual configured Worker/catalog/deployment IDs were not read; no Cloudflare API mutation occurred.

No Wrangler upgrade is established as necessary. Tests and a later reviewed staging deployment must verify backend mismatch, outage, reset halt and replay rejection. Updating the live site is outside this stage.

## 11. GitHub / CI and reproducibility

`git ls-files .github` returns no tracked workflow. There is no checked-in CI job that automatically proves this migration. Repository source pins and lockfiles alone cannot reproduce the patched external source copy or absent `.tari-v047-reference`.

Implementation should supply reproducible external-source setup at exact target SHA, a reviewed patch manifest/hash, and target lockfiles. Use a writable build copy outside the repository if upstream build scripts write builtin artifacts. Do not point builds at the immutable audit checkout. A GitHub workflow, if added, should run focused offline/unit/engine tests with no deployment or wallet secrets, and archive only public evidence. Explicitly separate ignored real-chain tests from CI.

`scripts/verify.sh` covers only selected suites; it is not full coverage of newer registry/admin/bridge/CBOR/Worker functionality. `scripts/check_gate3_integration.sh` verifies copies in an external integration tree; port those fixtures and provenance checks. Update `scripts/gg_test.sh` comments if its cohort description changes; upstream and Ghost Gate currently agree on Rust 1.97.1. Keep expensive WSL/engine builds to one focused run per scoped change, not repeated blanket sweeps.

Pre-existing public packaging issue: `.gitignore` excludes the service env templates that `deploy/setup-vps.sh` expects. Fix with placeholder-only templates and a narrow ignore exception. Do not add machine-local `.cargo`, old wallet DBs or current deployment secrets to make CI pass.

## 12. Staged implementation plan

Each stage should be a small reviewable patch with focused validation. This document is not authorization to execute them.

1. **Cohort/reproducibility:** decide one coherent target dependency source, preserve external reference, create a separate target build copy if necessary, port the wallet MVP extension minimally, retire already-upstream security/backport patches, update manifest/lock/source setup. Keep L1 types isolated. Exit: reproducible target build graph and patch provenance.
2. **Read-only target reader:** implement typed bounded CBOR decode, explicit UP/DOWN and proof request behavior, version selection, real captured fixtures, stale/pruned handling. Exit: positive decode and negative evidence cases pass without weakening trust tiers. This can progress independently of wallet signing.
3. **Consensus evidence:** port isolated verifier to target light client/proof formats; establish a reviewed reset-generation bootstrap; attach evidence to bridge if Production is required. Exit: valid handover/inclusion succeeds; forged roots/values, stale/down/old-generation evidence fail. No trust-on-first-use fallback.
4. **Wallet + templates:** update view-key derivation, signatures and statement/witness construction; compile all three templates; run focused engine tests. Review `set_open` authority separately. Exit: supported proof path and all shape/resource/signature refusals demonstrated on target engine.
5. **Local target network:** fresh upstream stores and configured verification; operator-controlled funding/publishing/creation using target wallet tools. Capture hashes/addresses/receipts/fees; prove wallet MVP locks/recovery and rejected transaction reconciliation. Exit: a complete target Mode A scenario, if Mode A is in scope for release.
6. **Browser compatibility:** record actual Sapient/Universe build/cohort, test credential Mode B with newly created outputs, inspect ownership signature vectors, exercise pending/cancel/resume and negative cases. Exit: separate per-wallet result, not a blanket “browser compatible.” Mode B can be staged without deploying the GhostGate test faucet.
7. **Staging registry/VPS/Worker preparation:** inventory live non-secret state, preserve halt/replay/audit, advance generation, publish any changed bindings, render catalog, prepare reviewed binaries and assets. Exit: local/staging tests show old sessions/claims fail and current published bindings agree end to end.
8. **Separately authorized release:** coordinated services/cutover, bounded user-approved live verification, release evidence and rollback target. Exit: exact deployed hashes/build versions, active anchors, gate inventory, receipts and monitoring recorded. No live cutover is part of Stage 1.

Unresolved external gates are explicit: deployed wallet/provider versions, actual indexer health/proof availability, independently approved anchor material, complete live binding/address inventory, and live fee/receipt evidence. These do not prevent starting source implementation; they prevent claiming the new deployment works.

## 13. Rollback plan

Before a future cutover, retain source/binary hashes, Worker deployment ID, non-secret manifests and protected state backups. A failure leaves issuance halted. Roll back compatible application code/config only if it still enforces the **current** generation floor, policy, halt and replay checks. Otherwise run a maintenance/disabled route while repairing forward.

Do not reconnect old v0.42/v0.47/v0.48 binaries or databases to the reset testnet. There is no rollback that restores deleted network balances/components. Old data can be inspected only as an isolated historical environment. Do not lower chain generation, restore a lower generation ledger, delete replay state, clear a reset halt automatically, resurrect old policy sessions or restore old anchors to regain availability. If a former policy is desired, republish/review it within a forward generation and current-chain state.

Retain Cloudflare replay namespace/history on Worker rollback. If an older Worker cannot interpret the current generation binding, disable proof/session routes rather than serving stale authorizations. Keep Telegram admission halted until backend policy verification is restored; reconcile memberships separately under operator control.

## 14. Test plan and audit validation

No builds or test suites were run in Stage 1. Validation here consisted of source/lockfile inspection, complete tracked-address and API-name searches, exact Git ref checks, changelog comparison and bounded public read attempts. Failed public reads are recorded above, not counted as passing checks.

| Targeted test group | Required evidence / named existing locations |
| --- | --- |
| Cohort/compiler | Root + three template + verifier graphs use intended target crates; Rust 1.97.1; no accidental v0.42/v0.47 engine mixing; valid public clean clone/build setup |
| Transaction serialization | Target MainSigner explicit on wire; nonce/blobs/witness/is_migration present; sr25519 authorization/seal round trip; reject old fields/invalid signatures; compare target golden vectors |
| Wallet MVP extension | Promise <= value accepted, above value refused before lock, altered promise fails range proof, exact selected input/lock ownership preserved, cancellation/timeout reconciled; external patched SDK/walletd tests |
| Core/engine Mode A | `gate_engine.rs`, `adversarial.rs`, `cross_resource.rs`, `mvp_and_shape.rs`: valid direct KeyPath; wrong/missing signer, forged statement, missing input, wrong resource/network/challenge/session, expired/reused nonce, zero promise/input, extra output, revealed leg and unsupported class all fail as intended |
| Changed auth model | Prove current no-`Proof` route works without synthetic windows. Focused upstream/fixture tests for one-hop window semantics only where actually used; test hook omission explicitly if selected asset has a hook; confirm fresh component's upgrade default is locked |
| Recipient derivation | New view-key DH, owner public/secret agreement, resource tag and encrypted payload recovery; update `ghost-gate-wallet` unit tests and SDK-created input fixtures in `gate_engine.rs` |
| CBOR / reader | Real target UTXO/resource/receipt/result fixtures; correct floor/auth key; malformed base64/CBOR, bounds, trailing bytes, unknown shape, wrong type/resource, missing auth, down/404/pruned/error all fail closed. `ghost-gate-cbor/src/tests.rs`, walletd readers and `credential_real_chain.rs` |
| Consensus verifier | Target committee and handover, valid committed value, mutated value, wrong proof/root/network/version, future/stale epoch, no anchor, reset-generation evidence, malformed transport; migrate `esmeralda_release_handover.rs` and sidecar unit tests |
| Wallet RPC/reconciliation | Status/network/account auth, Unspent/burnt/frozen filtering; submit/wait/receipt decode; five-minute pending and interrupted submission do not trigger duplicate spend; old generation pending jobs remain unusable |
| Registry/admin/bridge | `ghost-gate-admin/tests/admin_plane.rs` plus core/registry/bridge unit tests: hash v1/v2 consistency, generation monotonicity, rollback rejection, halt persistence, published-only bindings, no trust promotion, old sessions/replays rejected; admin WebAuthn unaffected by walletd token |
| Browser providers | `web/js/ghost/test.js`, lab/browser checks and manual per-wallet run: current capabilities, proper frame/origin/network, MVP output + ownership challenge vectors, wrong key, cancellation, pending, reconnect and pre-reset resume refusal |
| Worker/Telegram | Existing `cloudflare/test/*.test.js`, bridge/Telegram tests: HMAC/policy/generation mismatch, reset halt, backend outage, replay/race, stale session/claim, exact tunnel origin/path allowlists. Replace stale fixture assumptions only where test intent requires current-chain data |
| Fees / live state | New receipt/diff and wallet balance/output deltas for publish/create/proof; fee cap behavior on both success/rejection; fresh TARI and selected resource metadata, hook status, component header and hashes |

Run one focused check per implementation patch and report skipped live/expensive tests explicitly. Do not rerun legacy suites against old cohorts and call that target verification. Wallet signing, signed dry runs, publishing, funding and live admission changes belong to separately authorized later work.

## Stage 1 verdict

**READY FOR IMPLEMENTATION** means the source-impact audit identifies concrete changes and a bounded implementation sequence. It does **not** mean ready to deploy: old transaction/reader cohorts, absent stock wallet MVP support, stale chain evidence and unverified browser/live configuration are blocking runtime compatibility. Complete the stated external gates before release.

The appendices below are the exact dependency/address inventories used by this audit.


## Appendix A. Exact root Ootle pins

All current paths below have prefix `../_ootle-v042-ghost-gate/`. Target versions were read from the corresponding manifest in the exact v0.49.2 checkout, not inferred from the release number.

| Dependency | Declared version | Root lock version | Upstream-relative source | Target version |
| --- | --- | --- | --- | --- |
| `tari_template_lib` | `0.33.0` | 0.33.0 | `crates/template_lib` | 0.37.0 |
| `tari_template_lib_types` | `0.33.0` | 0.33.0 | `crates/template_lib_types` | 0.36.0 |
| `tari_template_abi` | `0.20.1` | 0.20.1 | `crates/template_abi` | 0.22.0 |
| `tari_template_test_tooling` | `0.42.0` | 0.42.0 | `crates/template_test_tooling` | 0.49.2 (workspace) |
| `tari_engine` | `0.42.0` | 0.42.0 | `crates/engine` | 0.49.2 (workspace) |
| `tari_engine_types` | `0.42.0` | 0.42.0 | `crates/engine_types` | 0.49.2 (workspace) |
| `tari_ootle_transaction` | `0.42.0` | 0.42.0 | `crates/transaction` | 0.49.2 (workspace) |
| `tari_ootle_wallet_crypto` | `0.44` | 0.44.0 | `crates/wallet/crypto` | 0.50.0 |
| `tari_ootle_wallet_sdk` | `0.44.0` | 0.44.0 | `crates/wallet/sdk` | 0.51.0 |
| `tari_ootle_wallet_storage_sqlite` | `0.44.0` | 0.44.0 | `crates/wallet/storage_sqlite` | 0.51.0 |
| `tari_ootle_walletd_client` | `0.44.0` | 0.44.0 | `clients/wallet_daemon_client` | 0.51.0 |
| `tari_ootle_common_types` | `0.42.0` | 0.42.0 | `crates/common_types` | 0.49.2 (workspace) |
| `tari_ootle_address` | `0.12` | 0.12.0 | `crates/ootle_address` | 0.15.0 |
| `tari_indexer_client` | `0.43` | 0.43.0 | `clients/tari_indexer_client` | 0.50.0 |
| `tari_consensus_types` | `0.42.0` | 0.42.0 | `crates/consensus_types` | 0.49.2 (workspace) |
| `tari_bor` | `0.16.2` | 0.16.2 | `crates/tari_bor` | 0.16.6 |
| `ootle_byte_type` | `0.14` | 0.14.0 | `crates/ootle_byte_type` | 0.18.0 |
| `ootle-network` | `0.2` | 0.2.0 | `crates/ootle_network` | 0.2.0 |
| `ootle_serde` | `0.6` | 0.6.0 | `crates/ootle_serde` | 0.6.2 |
| `tari_ootle_wallet_sdk_services` | `0.34.2` | 0.34.2 | `crates/wallet/sdk_services` | 0.34.2 |

## Appendix B. Complete tracked concrete address inventory

Scope: tracked text at the audited Ghost Gate HEAD, matching literal `component_`, `resource_`, `template_`, `vault_`, or `utxo_` addresses with at least 40 hexadecimal characters. Generated addresses, repeated-byte Rust constructors, environment-injected values and ignored live state are not deployment addresses that can be recovered by this scan. No concrete prefixed template/vault literal was found, and no published GhostGate template hash was identified in the tracked deployment evidence. Obtain actual target publication addresses from receipts.

### `component_0102030000000000000000000000000000000000000000000000000000000000`

Built-in faucet constant in an ignored live test: retain only with target genesis/state verification; update v0.47 test assumptions.

Locations: `crates/ghost-gate-walletd/src/esmeralda.rs:172`.

### `component_0dc41b5cc74b36d696c7b140323a40a2f98b71df5d60e5a6bf4c1a07ffffffff`

Synthetic wallet SDK engine-test account: recreate/revalidate with target test harness, not a known Esmeralda deployment.

Locations: `crates/ghost-gate-tests/tests/gate_engine.rs:1293`.

### `component_510245845d18b031fce6f5a1ec9f22329cba92c4a978106d0f48dce152e7e588`

Historical localnet evidence: preserve documentation; create fresh resources/components/outputs for new tests, never treat as current Esmeralda state.

Locations: `docs/GATE3_RESULTS.md:33`.

### `component_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`

Dummy/synthetic fixture: not a live deployment address to regenerate.

Locations: `scripts/admin_live_demo.sh:89`.

### `component_f222f57006413994f7161a77f999105a2f9edd1446700c4c80b796a1c79ffa01`

Historical localnet evidence: preserve documentation; create fresh resources/components/outputs for new tests, never treat as current Esmeralda state.

Locations: `docs/GATE3_RESULTS.md:38`.

### `resource_0101010101010101010101010101010101010101010101010101010101010101`

Native TARI constant: retain address; verify fresh generation/resource state. Old balances are not retained.

Locations: `cloudflare/test/contracts.test.js:421`, `crates/ghost-gate-admin/tests/admin_plane.rs:839`, `crates/ghost-gate-registry/src/lib.rs:1409`, `crates/ghost-gate-walletd/tests/credential_real_chain.rs:33`, `docs/REAL_10_TTARI_GATE_VERDICT.md:16`, `scripts/cdp-resume-check.mjs:41`, `scripts/dev.ps1:57`.

### `resource_5161236c4a402a14303a92562737748f0cd122fa42e3831aec7f32c6fca44fc7`

Historical localnet evidence: preserve documentation; create fresh resources/components/outputs for new tests, never treat as current Esmeralda state.

Locations: `docs/GATE3_RESULTS.md:32`.

### `resource_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`

Dummy/synthetic fixture: not a live deployment address to regenerate.

Locations: `scripts/admin_live_demo.sh:89`, `scripts/admin_live_demo.sh:180`.

### `utxo_0101010101010101010101010101010101010101010101010101010101010101_5ad3313f43e35ac5d89c7e5819ad12852aacc6534a21ddbf6b237b7fc5be8c6f`

Recorded browser-resume UTXO in a simulated-provider UI harness. It is not live 0.49.2 evidence; keep mock tests explicit, and obtain a fresh output for a real wallet acceptance test.

Locations: `scripts/cdp-resume-check.mjs:40`.

### `utxo_0101010101010101010101010101010101010101010101010101010101010101_a66c77cfed68833788b9d91dbece3e506cdbc590953d5c8f75ada7043f54b407`

Historical Swap Alice **localnet** output at indexer 127.0.0.1:12007, not an Esmeralda deployment. An Esmeralda reset alone does not alter that separate localnet. Recreate it for target localnet integration tests; preserve the old value only in an isolated legacy fixture.

Locations: `crates/ghost-gate-walletd/src/esmeralda.rs:187`, `crates/ghost-gate-walletd/tests/credential_real_chain.rs:30`.

### `utxo_0101010101010101010101010101010101010101010101010101010101010101_abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd`

Dummy/synthetic fixture: not a live deployment address to regenerate.

Locations: `cloudflare/test/lab-technical.test.js:60`, `cloudflare/test/lab-technical.test.js:72`, `cloudflare/test/lab-technical.test.js:94`.

### `utxo_5161236c4a402a14303a92562737748f0cd122fa42e3831aec7f32c6fca44fc7_2c713522a4aaf79f2b219d869b5033d3d71d63c0537e5e0bbed2d717d8b2a67e`

Historical localnet evidence: preserve documentation; create fresh resources/components/outputs for new tests, never treat as current Esmeralda state.

Locations: `docs/GATE3_RESULTS.md:36`.

## Final audit status

Only `docs/OOTLE_0492_MIGRATION_AUDIT.md` was added in the canonical repository. The external reference remains detached at v0.49.2. Runtime compatibility and deployment remain subject to the implementation and verification gates above.

STAGE 1 VERDICT:
READY FOR IMPLEMENTATION
