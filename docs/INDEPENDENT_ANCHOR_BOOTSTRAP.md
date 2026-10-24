# Independent Esmeralda anchor bootstrap

This run did not install or start a base node, indexer, walletd, or validator. The machine has no
already-synchronized independent L1 source, so starting an ordinary indexer against the public
Esmeralda gRPC endpoint would be a trust downgrade, not a bootstrap.

## Required prerequisites

1. A verified, version-pinned Minotari Esmeralda base-node binary and its release digest/signature.
2. A fully synchronized local base-node database, independently validated by that node's normal
   chain validation. A remote `grpc.esmeralda.tari.com` endpoint is not equivalent.
3. The exact Tari Ootle `v0.47.0` indexer binary, built from commit
   `9dabb2a76a9ad5c6e99dfa180ab7bbbcb1a05a47` or an authenticated release artifact that identifies
   that build.
4. A fresh, dedicated data root such as
   `C:\Users\pdark\Documents\Codex\ghost-gate-laptop\.local\esmeralda-anchor`. It must not be a
   walletd base path or any existing indexer's database.
5. An authenticated record of the Esmeralda L1 network identity, the selected Ootle sidechain,
   and validator-node change history through the proposed anchor epoch.

## Source-derived isolated indexer shape

The v0.47 indexer accepts `--network`, `--base-path`, `--config`, and repeated `-p key=value`
overrides. `CommonCliArgs::get_base_path` appends the network name, so the example root below
becomes `<root>\esmeralda`; the indexer stores its default database below
`data\indexer\global_storage.sqlite` there.

Do not run this until the local base node in prerequisite 2 is healthy and its release provenance
is recorded. With explicit executable paths, the command shape is:

```powershell
$anchorRoot = 'C:\Users\pdark\Documents\Codex\ghost-gate-laptop\.local\esmeralda-anchor'
$indexer = '<verified v0.47 tari_indexer executable>'
$localBaseNodeGrpc = 'http://127.0.0.1:<local-base-node-grpc-port>'

& $indexer --network esmeralda --base-path $anchorRoot `
  -p epoch_oracle.oracle=BaseLayer `
  -p epoch_oracle.base_layer.base_node_grpc_url=$localBaseNodeGrpc
```

The effective `indexer.sidechain_id` must remain the reviewed Esmeralda default unless the
authenticated L1 record proves a different value. Do not set it from an indexer API response.
The BaseLayer oracle path in `applications/tari_indexer/src/bootstrap.rs` verifies the base-node
network and enables validator-node-change synchronization. That is the minimum implementation
path that can calculate a validator-set root from local L1-derived events.

## Approval procedure after synchronization

1. Export/reproduce the active validator identities, activation epochs, shard keys, claim keys and
   vote weights from the local L1-derived epoch manager at one concrete anchor epoch.
2. Recompute its validator-set Merkle root using the exact v0.47 `ValidatorSetTree` and protocol
   version for that epoch. Record the derivation input and a digest of the L1 evidence.
3. Independently compare the derived root with the authenticated record. A public indexer may be
   used only to obtain the committee proof that `anchor_pinned` checks against this already chosen
   root.
4. Have an accountable operator create a gitignored `GG_V047_ANCHOR_CONFIG` with `reviewStatus`
   `approved`, `network` 38, and `walkShard` **1**. No automatic re-anchor is permitted.
5. Replay contiguous signed handovers with `advance()` and retain the resulting verified-set
   history. Missing handovers, malformed committee proofs, an unexpected network, or any L1
   disagreement leave the service unready.

No command in this document is a wallet command or submits a transaction.
