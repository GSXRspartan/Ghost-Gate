# Esmeralda independent-anchor inventory

Status at `5840b01` plus this review: **no independently authenticated Esmeralda anchor is
available locally.** This is an inventory, not an approval record.

## Checked implementation

| Item | Evidence | Result |
| --- | --- | --- |
| Ghost Gate checkout | `<local Ghost Gate checkout>` | Present; legacy bridge workspace remains the v0.42 cohort. |
| v0.47 reference | `.tari-v047-reference`, tag `v0.47.0`, commit `9dabb2a76a9ad5c6e99dfa180ab7bbbcb1a05a47` | Present and read-only. |
| Pinned verifier | `tools/ghost-gate-v047-verifier` | Isolated v0.47 Cargo project using `anchor_pinned`, `advance`, and verified committee/substate proofs. It is not linked into the v0.42 bridge type graph. |
| Sidecar | `ghost-gate-v047-sidecar` | Loopback-only and token-gated. Without `GG_V047_ANCHOR_CONFIG`, `/health` reports unready and proof requests fail closed. |
| Sapient credential path | `crates/ghost-gate-bridge/src/credential.rs` | Verifies a nonce-bound ownership signature and a threshold against its configured chain reader, but it is not yet supplied a v0.47 light-client verdict. |
| Local Esmeralda L1/base node | process and command inventory | No `minotari_node`, `tari_indexer`, `tari_validator_node`, or v0.47 walletd process was running. No supported binary was found on `PATH`. |
| Wallet profiles | deliberately not opened | A wallet profile is neither an L1 full node nor an anchor source. None was read or modified. |

## Canonical v0.47 parameters traced from source

`applications/tari_ootle_app_utilities/config_presets/f_epoch_oracle.toml` configures Esmeralda
as a **Hybrid** epoch oracle. Its configured part lists four validators for shard group `1..=256`
at registration epoch `8367`; their configured activation is epoch `8368`. Its base-layer part
uses `https://grpc.esmeralda.tari.com` and start height `669506`.

The Hybrid implementation in `crates/epoch_oracles/src/hybrid/oracle.rs` uses the base-layer
oracle for epoch-boundary hashes and timing, then feeds those ticks into the configured oracle.
It does not turn the static configured validator list into authenticated historical L1 membership.
Using that public gRPC endpoint would not make this laptop an independent L1 observer.

The v0.47 Esmeralda consensus constants specify 780 base-layer confirmations, committee size 40,
and `NumPreshards::current()` (the reviewed Esmeralda epoch uses 256 preshards). The observed
four-validator topology therefore maps to one committee covering `1..=256`, with unit vote power.
`Shard::first()` is **1**. Shard 0 is global/reserved and is now rejected by Ghost Gate's anchor
configuration.

No non-default Esmeralda `indexer.sidechain_id` is set in the reviewed preset. That means the
effective sidechain selector must be read from the authenticated v0.47 configuration/L1 scan when
an independent node is available; Ghost Gate must not copy one from an indexer response.

## Final trust conclusion

The signed v0.47 release can derive a conditional candidate root at epoch 12634, but it does not
authenticate the historical 8368-to-11670 membership discrepancy. The public indexer may carry
committees, checkpoints and substate proofs as untrusted transport only. It is not an anchor.

An independently synchronized L1 node is **not** the immediate solution: in this Hybrid design it
can authenticate epoch timing and boundary hashes, while the configured oracle supplies validator
topology and reconstructs already-active validators from its current configuration. It cannot, by
itself, turn that configuration into authenticated Esmeralda membership history.

Independent authentication still requires a maintainer-authenticated immutable anchor statement
binding a concrete Esmeralda epoch to network byte 38, protocol version/preshard count, complete
validator public keys, vote powers, shard assignments, and the validator-set root. The narrower
alternative is an explicitly operator-approved conditional release policy; its genuine one-epoch
handover result is recorded in `ESMERALDA_RELEASE_BOOTSTRAP_POLICY.md`. Neither route currently
has a freshness-qualified current-state chain, so Ghost Gate must not create a production
`GG_V047_ANCHOR_CONFIG` or issue a production gate session.
