# Tari Ootle v0.47 consensus verification boundary

Ghost Gate's legacy local bridge is pinned to the Tari Ootle v0.42 cohort. The Esmeralda walletd
used on this laptop is v0.47.0, so the two must not be linked into one Rust type graph. The
`tools/ghost-gate-v047-verifier` Cargo workspace is the isolated v0.47 verification boundary.

## Exact upstream source

- Tari Ootle tag: `v0.47.0`
- Commit: `9dabb2a76a9ad5c6e99dfa180ab7bbbcb1a05a47`
- Reused public APIs: `tari_ootle_light_client::TrustedValidatorSet::anchor_pinned`,
  `TrustedValidatorSet::advance`, `TrustedValidatorSetHash::verify_committee`, and
  `VerifiedCommittee::verify_substate`.

The adapter deliberately does **not** use `anchor_on_first_use`. The upstream wallet provider's
normal first-use behavior accepts the set named by an indexer's latest checkpoint, and after a
long failure can re-anchor. That is reasonable wallet UX but not Ghost Gate's hosted trust model.

## Trust and verification sequence

1. An operator obtains a network/epoch/walk-shard/validator-set-hash tuple through an authenticated
   channel independent of the indexer and configures it as the only bootstrap anchor.
2. An untrusted indexer may supply a committee. `anchor_pinned` proves the committee belongs to
   that exact pinned set, has the configured network and epoch, and covers the walked shard.
3. Each checkpoint is accepted only through `advance`. The upstream code verifies its network,
   epoch and shard group, validates the prior committee's quorum certificate, and proves the next
   committee against the next validator-set hash committed by that checkpoint.
4. For a substate proof, the adapter selects the validator-set hash retained for the proof epoch,
   proves the supplied committee against it, then calls `verify_substate`. The upstream verifier
   verifies the commit proof's quorum, block root, network, shard group, inclusion leaf, substate
   version, value, and value-hash epoch.
5. Ghost Gate must apply a separate freshness policy before authorization. Inclusion at a past
   block is not current-holdings proof; missing checkpoints, an unwalked epoch, malformed proof,
   another network, another shard, or an unavailable anchor all remain `UNKNOWN`, never `VERIFIED`.

The initial adapter contains no HTTP client, automatic re-anchor, or indexer `verified` flag path.
Those are intentionally excluded so an integration has to make its trust-anchor and freshness
policy explicit rather than inheriting an indexer's claim by accident.

## Credential and hosted boundary

Consensus proof acceptance alone says only that a particular substate existed at a committed block.
The hosted credential verifier must additionally validate the visitor's challenge-bound ownership
signature, native tTARI resource, raw threshold, gate/policy binding, unspent/current policy, and
replay/session state. Browser-provided account names, addresses, balances, and `verified` booleans
are not consensus evidence.

Until an authenticated v0.47 sidecar is configured with the above pinned anchor and its verified
result is connected to the credential verifier, `ghost-gate-hosted-verifier` remains deliberately
`UNKNOWN` for every proof. The Worker therefore cannot issue a session.

## Local verification

The reference checkout is intentionally ignored and must be fetched explicitly:

```powershell
git clone --depth 1 --branch v0.47.0 https://github.com/tari-project/tari-dan.git .tari-v047-reference
cargo test --manifest-path tools/ghost-gate-v047-verifier/Cargo.toml
```

This only compiles deterministic verification fixtures. It does not connect to walletd, inspect a
wallet profile, submit a transaction, or contact a chain endpoint.
