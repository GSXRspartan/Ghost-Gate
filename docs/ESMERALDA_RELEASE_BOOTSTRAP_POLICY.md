# Esmeralda v0.47 release-bootstrap policy

**Policy version:** `ghost-gate/esmeralda-release-bootstrap/v1`
**Status:** draft review record; not an installed anchor and not production approval.

This policy describes the narrow, conditional trust boundary used to reproduce the v0.47
light-client verification tests. It deliberately does not turn a public indexer response, a
GitHub badge, or a wallet connection into authority to issue Ghost Gate access.

## Reviewed release material

- Release tag: `v0.47.0`
- Tag target commit: `9dabb2a76a9ad5c6e99dfa180ab7bbbcb1a05a47`
- Reviewed signing-key fingerprint:
  `337B91EFC5F1027D8AEDF63D1885B149504C0A64`
- Release preset:
  `applications/tari_ootle_app_utilities/config_presets/f_epoch_oracle.toml`
- SHA-256 of that exact preset:
  `e9b9badfb8061e982524c4176ae2336d44229c34b6d074ef128cd670e49d9df3`

The tag signature cryptographically binds the tag object to that OpenPGP key. It does **not**
independently establish that the key holder had authority to define Esmeralda's historical or live
validator membership. Installing an anchor from this policy requires an accountable operator's
explicit approval of that signer-authority assumption.

## Release-defined topology and canonical calculation

The reviewed preset selects `Hybrid`, configures L1 only for epoch timing, and embeds the
configured topology. `configured/config.rs` activates each validator at
`registration_epoch + 1`; all four registrations at 8367 therefore activate at 8368. The
configured epoch manager assigns every active validator vote power one
(`epoch_manager_service.rs:192-214`).

| Validator public key | Vote power | Shard group |
| --- | ---: | --- |
| `10780fe1b4d31f8350e4b881dccd8f8210ce056050ac6dd8cca88ca16710b044` | 1 | `1..=256` |
| `568adadd2744c7bb3ae4c58e26e83a49a5b5af3380edfcd6b5d7af315580552f` | 1 | `1..=256` |
| `c480fe3a76f03dcdce8d7c85ac7d0001ec97b667260172709b23818c8707e503` | 1 | `1..=256` |
| `d6da35adba3642e7d1343985d5e4f123f5230a74c5480bf2857aabe50bcd6362` | 1 | `1..=256` |

Canonical member ordering is ascending public key order, as enforced by
`hash_validator_set_committee`. `ProtocolVersion::at` selects Esmeralda V0 from epoch 0, V1 at
11925, and V2 at 12220; the committee leaf commits to that version. `ValidatorSetHash::calculate`
then commits network byte 38, epoch, 256 preshards, and the committee-tree root.

| Epoch | Version | Derived validator-set root |
| ---: | --- | --- |
| 12634 | V2 | `dc39359775aa329670eb8cbfce7e1c77f7e5280d1ae334bc62bb46485c6c8956` |
| 12635 | V2 | `23b6a682150e19910b13f626f89a6352212554a50625a3eaa85b88b74fa2fc7f` |

The 8368-to-11670 indexer-history gap is irrelevant to this **mathematical calculation** only
when the operator expressly trusts the signed release topology to be active at the selected
anchor epoch. It does not prove uninterrupted historical membership.

## Retained transport and cryptographic result

The following unmodified public-indexer responses were retrieved read-only on 2026-10-23 and are
retained under `tools/ghost-gate-v047-verifier/evidence/`:

| Epoch response | Request | SHA-256 |
| ---: | --- | --- |
| 12633 | `/epoch-checkpoints?from_epoch=12633&limit=1&shard=1&include_committees=true` | `edb21015983b49990d392617995b74f302aaf445bf07e5ff3084af02bea180ab` |
| 12634 | `/epoch-checkpoints?from_epoch=12634&limit=1&shard=1&include_committees=true` | `7aee0c580912b116cfd20895b08125946cc404e5f6ddcd3da7c0349fcab9866d` |

Base URL: `https://ootle-indexer-a.tari.com/`. It is untrusted transport, not a root of trust.
The genuine 12633 response supplies the epoch-12634 committee proof; the verifier checks it
against the derived epoch-12634 root with `TrustedValidatorSet::anchor_pinned`. It then verifies
the epoch-12634 checkpoint's quorum signatures and next committee through `advance`, reaching the
independently derived epoch-12635 root. This passed in
`esmeralda_release_handover.rs`.

For four unit-vote validators, the v0.47 quorum rule is not hardcoded: `Committee::quorum_threshold`
computes total power minus `floor((total power - 1) / 3)`, giving 3 of 4 here. The official
light-client implementation enforces the actual committee vote power and signatures.

## Freshness is not established

The successful one-epoch handover does not establish present-day state. Under v0.47,
`BaseLayerOracle` obtains the L1 consensus constants at the observed tip and maps height through
`constants.height_to_epoch`; an epoch boundary is at `epoch * epoch_length`. There is no fixed,
release-preset height-to-epoch formula that Ghost Gate can safely use alone. `HybridEpochOracle`
forwards only these L1 epoch ticks to the configured oracle.

Ghost Gate has neither an independently authenticated L1 tip/constant set nor a contiguous
quorum-signed checkpoint chain from the reviewed anchor to a defined current freshness horizon.
Two public indexers agreeing would not repair either absence. Therefore the sidecar's
`maxProofAgeEpochs` check remains only a relative check against its latest **authenticated**
handover; without continuously advanced trusted state, it cannot authorize a current balance.

To authorize a 10-tTARI proof, all of the following must be available: approved policy/anchor,
contiguous signed handovers to a current trusted epoch, an authenticated account or vault state
proof no older than the approved epoch window, server-side ownership and threshold verification,
and the existing nonce/replay/session checks. Missing any item returns no access session.

## Required human action before any installation

An accountable operator must record the signer-authority decision, this policy version and digest,
the reviewed evidence digests, an expiry/review date, and the exact approved epoch/root in a
gitignored local review record. Only then may a separately reviewed local anchor JSON include the
matching `releaseBootstrap` fields. This document itself is not such approval.
