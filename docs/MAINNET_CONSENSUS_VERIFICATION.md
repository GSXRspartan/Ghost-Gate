# Mainnet consensus verification research

Status: **research complete; production authorization remains NO-GO**.

This document records why the existing L2 ownership verifier cannot yet be made safe for real mainnet Telegram admissions, what Tari's light-client APIs can and cannot authenticate, and the exact remaining work.

## Verified mainnet identity

| Fact | Value | Source |
|---|---|---|
| Native L2 TARI resource | `resource_0101010101010101010101010101010101010101010101010101010101010101` | `STEALTH_TARI_RESOURCE_ADDRESS` in `template_lib_types/src/constants.rs`; official tokenomics page |
| Divisibility | 6 (`1 TARI = 1_000_000 µT`) | official tokenomics page |
| Network byte | `0x00` (`Network::MainNet`) | `ootle_network::Network::as_byte`; live indexer `/info` |
| Mainnet address prefix | `otl_` | exchange integration guide |
| Public indexer A | `https://indexer-a.ootle.tari.com/` | exchange integration guide; live probe |
| Public indexer B | `https://indexer-b.ootle.tari.com/` | exchange integration guide; live probe |

The resource and divisibility are now pinned in `crates/ghost-gate-core/src/lib.rs` as `network::MAINNET_TARI_RESOURCE` and `network::MAINNET_TARI_DIVISIBILITY`, with a test that parses the address and checks the `0x01` key bytes.

An indexer's self-report is **not** a chain identity. The `/info`, `/health`, `/identity`, `/network`, `/network/economics`, `/network/stats`, and `/epoch-manager/stats` responses are local to the node answering; two nodes are expected to disagree on many of them.

## Live indexer compatibility (read-only, 2026-11-23)

Both public indexers returned:

```json
{"current_epoch":39254,"db_ok":true,"epoch_manager_ok":true,"network_ok":true,"status":"ok","version":"0.55.0"}
```

`/info` reported:

- `version: "0.55.0"`
- `network: "mainnet"`
- `network_byte: 0`
- `verify_substate_proofs: true`
- `substate_cache_max_serve_lag_secs: 300`
- `current_epoch: 39254`

`/committees?epoch=39254&shard=1` on both hosts returned the same committee keyed by validator-set hash
`ca427fa5e20c3cb4776c03e48901c6aa11e2c477fbab2372b4e15ca6bcee3739`, with a base64 CBOR
`ValidatorSetCommitteeProof`. `/epoch-checkpoints/latest` returned a quorum-signed end-of-epoch
checkpoint naming `next_epoch_validator_set_hash`
`ca427fa5e20c3cb4776c03e48901c6aa11e2c477fbab2372b4e15ca6bcee3739`.

`GET /substates/{id}?include_proof=true` returns:

```json
{"version":17,
 "state":{"up":{"substate":"<base64 CBOR SubstateValue>"}},
 "verified":true,
 "proof":{"anchor":{"epoch":39255,"shard_group":{"start":1,"end_inclusive":256},
                     "height":3,"block_id":"...","state_merkle_root":"..."},
          "commit_proof":"<base64 CBOR SidechainBlockCommitProof>",
          "value_proof":"<base64 CBOR SubstateValueProof>",
          "value_hash_epoch":39254,
          "down_proof":null}}
```

The `verified` flag is only the indexer's assertion. The proof fields are authenticatable. A spent
version returns `state: {"down":{}}` with a `down_proof`. `POST /utxos/fetch` and the live-only
`POST /substates/versions` are required for efficient output lookup; they were not called.

The live `/openapi.json` is OpenAPI 3.1.0, `info.version = 0.55.0`, and includes `POST /substates/versions`,
which is absent from the local v0.49.2 route table. This confirms material version skew.

Upstream release evidence: v0.55.0 was released 2026-11-20 at commit
`b7c964c45d0251c89270739ec1ceaffbfb983e59`; it introduced transaction schema V2, a new required
`WalletNetworkInterface::get_substate_versions` method, FFI ABI `ootle-sdk-ffi-c/20`, and
`POST /substates/versions`.

## Tari light-client capability audit

Audited local references:

- `C:\Users\pdark\Documents\Codex\_ootle-v0492-ghost-gate`
- `C:\Users\pdark\Documents\Codex\tari-ootle-v0.49.2-reference`

Their `crates/wallet/light_client` and `crates/storage` trees are byte-identical (per-file SHA-256).

Relevant APIs:

- `TrustedValidatorSet::anchor_pinned(network, walk_shard, epoch, validator_set_hash, committee)` — `validator_set.rs:53-66`
- `TrustedValidatorSet::advance(&EpochCheckpointEntry)` — `validator_set.rs:123-155`
- `VerifiedCommittee::verify` / `verify_commit_proof` / `verify_checkpoint` — `committee.rs:35-73,128-180`
- `CommittedBlockProof::validate(network, quorum_threshold, committee) -> VerifiedBlockTip` — `committed_block_proof.rs:91-124`
- `TrustedStateRoot::check_contains` — `substate_value_proof.rs:230-239`
- `verify_substate_value_proof_against_root` — `substate_value_proof.rs:289-334`
- `verify_substate_down_proof_against_roots` — `substate_value_proof.rs:350-431`
- `proofs.rs`: `verify_substate`, `verify_absent`, `verify_receipt`, `verify_result`, `verify_down_proof`, `check_result_matches_receipt` — `proofs.rs:34-262`
- `IndexerTrust::Verify` — `wallet/sdk/src/sdk.rs:59-76`
- `SubstatesApi::verify_down`, `verify_read`, `check_fresh` — `wallet/sdk/src/apis/substate.rs:437-501,558-621`
- `ValidatorSetApi::sync`, `walk`, `verified_shard_state_versions` — `wallet/sdk/src/apis/validator_set.rs:221-369,524-558`

Capability mapping:

| Required evidence | Supported? | Mechanism |
|---|---|---|
| Finalized consensus commitment | Yes, with trusted committee | `CommittedBlockProof::validate` gives `VerifiedBlockTip` with state root |
| Output existence and value binding | Yes | `verify_substate_value_proof_against_root` hashes full `SubstateValue`; `minimum_value_promise` and `is_frozen` are inside that hash |
| Current unspent state | Yes, conditionally | prior `ProvenUp` plus later `down_proof` verified against two ordered quorum-signed roots |
| Correct native TARI resource | Yes, when verifying value hash | resource address is part of the committed substate/UTXO value |
| Non-frozen output | Yes, when verifying value hash | `is_frozen` is part of the committed UTXO value |
| Authenticated validator-set chain | Yes, only if pinned out-of-band | `anchor_pinned` plus contiguous `advance` over signed checkpoints |
| Current freshness against wall clock | **No** | indexer can withhold newer checkpoints; `substate.rs:555-557` documents this |
| Base-layer epoch hash anchoring | **No** | `VerifiedBlockTip.epoch_hash` exists but is not used by the light client or wallet SDK |

`anchor_on_first_use` and `anchor_on_current_epoch` are TOFU/indexer-influenced and are not acceptable as production roots.

The APIs can authenticate the *content* of indexer responses without trusting the indexer, provided a validator-set hash is pinned out-of-band for a known `(Network, Epoch)` and every handover is walked with contiguous signed checkpoints. They do **not** by themselves prove that the authenticated state is current.

## Security advisories and version compatibility

| Advisory | Issue | Fixed in / notes |
|---|---|---|
| `GHSA-wxp4-rq8h-jcvf` | epoch-boundary HotStuff strand / handover DoS | v0.43.0 |
| `GHSA-m493-gggq-hvvw` | foreign proposal verified against wrong shard committee | v0.43.0 |
| `GHSA-734p-gq7p-3pwq` | `AllAccept` finalized without input shard group | v0.44.0 |
| `GHSA-2xjh-wg9w-g5hc` | substate exclusion proof not bound to shard | v0.46.0 |
| `GHSA-h2q8-m8f7-xvv7` | anchor age not bound; stale quorum root proves output down | v0.46.x / v0.49.2 source has freshness checks |
| `GHSA-4x6r-vhmx-g34f` | `IndexerTrust::Verify` bypass via unrequested/omitted substates | v0.48.0 |
| `GHSA-mxc7-fprj-8xq2` | foreign-proposal notification suppression | v0.48.0 |
| `GHSA-52vp-j7ph-m3g3` | forged UTXO Spent update hides unspent output | v0.48.0 (`retain_proven_spends`, `verify_down`) |
| `GHSA-28cx-xpx5-3xq2` | omitted confidential output poisons scan state | v0.48.0 |
| `GHSA-ch7v-fvrr-5338` | float values break verified reads via indexer JSON | v0.48.0 moved verified reads to base64 CBOR |

Version verdict:

- **v0.42.0** (current project pin): no light client, no `IndexerTrust`, no `verify_down`; affected by multiple advisories. Unsafe for mainnet.
- **v0.47.0**: first light-client release, but named affected version of `GHSA-ch7v` and still vulnerable to the forged-Spent, verify-bypass, and omitted-output advisories. Cannot verify current mainnet state; local docs already leave production authorization fail-closed.
- **v0.49.2**: contains the advisory fixes and is the best available audit baseline, but is many breaking releases behind live mainnet `0.55.0`.
- **v0.55.0 cohort required** for live mainnet: transaction schema V2, new `get_substate_versions`, new FFI ABI, new indexer endpoint, and matching proof encodings.

## Why a production evidence adapter was not implemented

Upstream does expose the cryptographic primitives required for content-authenticated evidence, but a real adapter needs all of:

1. A v0.55.0 matching client cohort. The current workspace is pinned to v0.42.0; switching cohorts requires rebuilding wallet/engine/SDK types together and is a separate breaking migration.
2. An independently authenticated mainnet validator-set hash for a known epoch, obtained out-of-band (not from the indexer's `/identity`, `/validators`, or `anchor_on_current_epoch`).
3. A contiguous quorum-signed checkpoint walk from that pinned anchor to the current epoch, with handover verification.
4. A freshness/liveness source outside the indexer. Tari's light client cannot detect checkpoint withholding. A base-layer epoch-hash cross-check and/or quorum of independent indexers/validator RPC is required.
5. `POST /utxos/fetch` / `POST /substates/versions` proof-bearing reads, and down-proof verification for current unspent state.
6. Revalidation of the authenticated output at redemption time so stale evidence cannot be redeemed later.

Implementing these against v0.42/v0.49.2 would produce an adapter that cannot talk to the live indexers or cannot prove freshness. Doing so would be speculative and would not satisfy the production tier. No authorization path was weakened.

## Required next engineering work

1. Import and pin the v0.55.0 Tari Ootle cohort locally, keeping v0.42 isolated for the legacy Esmeralda bridge.
2. Build a `mainnet-evidence` adapter using `IndexerTrust::Verify`, `TrustedValidatorSet::anchor_pinned`, `CommittedBlockProof::validate`, `verify_substate_value_proof_against_root`, and `verify_substate_down_proof_against_roots`.
3. Obtain an out-of-band mainnet validator-set anchor for a specific epoch, plus a documented chain of signed checkpoints to current.
4. Add an independent liveness/freshness check (base-layer epoch hash and/or two independent indexer/validator sources) with a bounded proof age compatible with the indexer's 300 s serve lag.
5. Add revalidation at Telegram redemption.
6. Only then consider a production evidence kind that can satisfy the `Production` trust tier.

## Existing Ghost Gate v0.47 work

`tools/ghost-gate-v047-verifier` already demonstrates pinned-anchor checkpoint verification on Esmeralda epochs 12633/12634, but its own documents state:

- the handover proves state only relative to a conditional root;
- there is no contiguous chain to present-day state;
- production authorization remains fail-closed.

That work is reusable as an architectural reference, not as a mainnet trust anchor.

## Decision

## M13 update — isolated v0.55.0 evidence verifier

`tools/m13-mainnet-verifier` is a standalone crate using the signed v0.55.0 source at commit
`b7c964c45d0251c89270739ec1ceaffbfb983e59`. It does not join the Ghost Gate workspace.

The mainnet validator set ships in the release configuration
`applications/tari_ootle_app_utilities/src/mainnet_epoch_oracle.json`: 7 validators, shard group
`1–256`, `registration_epoch 38362`. Recomputing the validator-set tree with upstream code yields
`a434332a6f312f9d278fa614ed4f32cbe22cf6c08b17b58941bce832d3788e6a`, which both public indexers
serve as the epoch-38362 committee hash. This is the first defensible out-of-band anchor found.

Result:

- walked 901 signed handovers from epoch 38362 to epoch 39263;
- verified a real public substate inclusion proof at epoch 39263;
- persisted and reloaded the trusted set;
- rejected wrong anchor, wrong network, foreign-epoch committee, missing handover, withheld
  checkpoints, unsupported version, wrong substate id, and up-as-down proof;
- cross-checked two indexers for epoch and handover hashes (liveness check only, not consensus).

Remaining before Ghost Gate integration: connect this verifier to `CredentialVerifier`/production
evidence kind; add current-unspent down-proof verification for tTARI outputs; add base-layer epoch
cross-check and stronger liveness; real Sapient session-bound proof; and all live admission approvals.

**Status: verifier prototype GO; Ghost Gate mainnet connection NO-GO.**
