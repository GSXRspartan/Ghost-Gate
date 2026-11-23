# M13 mainnet verified-evidence prototype

Standalone verifier for Tari Ootle mainnet evidence. It is **not** connected to Ghost Gate and cannot grant access.

## Source

- Tari Ootle v0.55.0, signed tag commit `b7c964c45d0251c89270739ec1ceaffbfb983e59`.
- Local source checkout: `C:\Users\pdark\Documents\Codex\tari-ootle-v0.55.0-source`.
- This crate is standalone (`[workspace]` in its own Cargo.toml) and does not change the Ghost Gate workspace dependency graph.

## Bootstrap anchor

The mainnet validator set ships in the v0.55.0 release configuration
(`applications/tari_ootle_app_utilities/src/mainnet_epoch_oracle.json`):

- 7 validators
- shard group `1–256`
- `registration_epoch: 38362`
- base time `2026-08-24T13:05:12Z`

`anchor.rs` recomputes the validator-set hash with upstream `tari_state_tree` / `tari_ootle_common_types` code:

```text
network=mainnet byte=0x00
registration_epoch=38362
validators=7
protocol_version=V1
state_tree_hash=a434332a6f312f9d278fa614ed4f32cbe22cf6c08b17b58941bce832d3788e6a
```

Both public mainnet indexers independently serve epoch-38362 committee hash `a434332a…e6a`, confirming the recomputed release-derived anchor.

## Run

```powershell
$env:CARGO_TARGET_DIR='D:\pb-target\m13'
cargo run --manifest-path 'tools\m13-mainnet-verifier\Cargo.toml' --bin anchor -j 1
cargo run --manifest-path 'tools\m13-mainnet-verifier\Cargo.toml' --bin verify -j 1
```

The verifier:

1. Fetches health and committee evidence from both public indexers.
2. Refuses unsupported response versions.
3. Rejects a committee hash that differs from the release-derived anchor.
4. Walks every signed end-of-epoch checkpoint from epoch 38362 to current.
5. Persists the latest trusted validator set and checks restart equality.
6. Verifies a real public substate inclusion proof.
7. Rejects wrong anchor, wrong network, foreign-epoch committee, missing handover, withheld checkpoints, unsupported version, wrong substate id, and up-as-down proof.

## Freshness

- Maximum trusted-epoch lag: 2 epochs relative to indexer health.
- Two indexers are cross-checked for current epoch and validator-set handover hashes. Agreement is a liveness cross-check, **not** independent cryptographic consensus.
- Persisted trusted state is monotonic: a lower epoch must not replace a higher one.

## Current result

```text
cross-indexer: health epoch and checkpoint chain agree (not a consensus proof)
self-tests: wrong anchor, wrong network, missing handover, version, freshness all fail closed
negative tests: foreign-epoch committee and withheld checkpoints fail closed
anchor epoch=38362 hash=a434332a6f312f9d278fa614ed4f32cbe22cf6c08b17b58941bce832d3788e6a
walked checkpoints=901 latest trusted epoch=Epoch(39263)
persistence: trusted epoch Epoch(39263) survived save/load
substate: verified up at epoch Epoch(39263) height NodeHeight(24)
negative tests: wrong substate id and up-as-down both fail closed
RESULT: authenticated checkpoint chain and public substate proof verified
```
