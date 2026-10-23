# Esmeralda trust-anchor review package

**Status: UNTRUSTED — Ghost Gate must return `UNKNOWN`.**

No independently authenticated Esmeralda validator-set anchor has been provisioned on this laptop.
The v0.47 wallet provider's `anchor_on_first_use` behavior and an indexer's `verified` response
are explicitly not acceptable for this hosted verifier.

## Required reviewed configuration

The loopback sidecar accepts a JSON document only when all of these fields are present and
`reviewStatus` is exactly `approved`:

```json
{
  "network": 38,
  "anchorEpoch": 0,
  "walkShard": 0,
  "validatorSetHash": "<official Tari JSON encoding>",
  "walkedCommittee": { "<official Tari ValidatorSetCommittee encoding>": "..." },
  "provenance": "<authenticated source, retrieval method, and evidence digest>",
  "reviewedAt": "<RFC3339 UTC timestamp>",
  "reviewedBy": "<named accountable reviewer or release verification identity>",
  "upstreamCommit": "9dabb2a76a9ad5c6e99dfa180ab7bbbcb1a05a47",
  "reviewStatus": "approved",
  "maxProofAgeEpochs": 1
}
```

The validator hash must originate from an authenticated release/bootstrap process or independently
verified L1-backed evidence. A value copied from an indexer, walletd RPC, a second indexer, or a
first-use checkpoint alone is insufficient. The committee may be transported by an indexer only
because the v0.47 verifier proves it against the approved hash.

## Reviewer checklist

1. Confirm the Tari source release tag and commit above using an authenticated release process.
2. Confirm network byte `38` is Esmeralda, and record how the epoch, walk shard, validator-set
   hash and committee proof were obtained.
3. Retain the signed/source evidence and a digest beside the approval record.
4. Validate the committee through `PinnedConsensusVerifier::pinned`; it must cover the selected
   walk shard and match the approved network/epoch/hash.
5. Configure the sidecar from a gitignored local file using `GG_V047_ANCHOR_CONFIG` and check
   `GET /health` returns `ready:true` on loopback.
6. Never replace the anchor automatically. Later epochs advance only through signed checkpoint
   handovers verified from this root. A failed handover, stale proof, unavailable evidence or
   configuration parse failure remains `UNKNOWN`.

This package intentionally contains no candidate hash and no approval. Filling its placeholders
requires an operator with independent provenance evidence.

## 2026-10-23 source and public-endpoint review

This review made read-only requests only. It did not configure the sidecar, walletd, a browser
wallet, or a hosted authorizer.

### Observed transport data (not a trust root)

`https://ootle-indexer-a.tari.com/` responded as follows:

* `/health` reported `version: "0.47.0"` and `current_epoch: 12635`.
* `/info` and `/network` reported `network: "esmeralda"` and `network_byte: 38`.
* `/validators` reported four active validators covering shard group `1..=256`, each with vote
  power one and `start_epoch: 11670`.
* `/epoch-checkpoints/latest?shard=1&include_committees=true` returned an end-of-epoch-12634
  checkpoint naming next-epoch validator-set hash
  `23b6a682150e19910b13f626f89a6352212554a50625a3eaa85b88b74fa2fc7f`.
* `/committees?epoch=12634&shard=1` returned validator-set hash
  `dc39359775aa329670eb8cbfce7e1c77f7e5280d1ae334bc62bb46485c6c8956`; the corresponding
  epoch-12635 route returned the hash named by the checkpoint above.

Those values are useful inputs to a verifier only *after* an anchor exists. The v0.47 client
source explicitly says that checkpoint convenience fields are untrusted until their committee
verifies, and that a committee proof is only as good as the validator-set hash it is checked
against. Therefore none of these values, nor agreement with another indexer or Veil, is copied
into an anchor configuration.

`https://explorer.tari.mw/` served the Veil explorer UI, while `/api` returned 404. It was not
used as a consensus source or a second trust root.

### Source evidence and remaining gap

The exact local Tari source is tag `v0.47.0` at
`9dabb2a76a9ad5c6e99dfa180ab7bbbcb1a05a47`. Its
`applications/tari_ootle_app_utilities/config_presets/f_epoch_oracle.toml` selects Esmeralda's
hybrid oracle, names `https://grpc.esmeralda.tari.com`, has start height `669506`, and lists the
same four validator public keys for shard group `1..=256` with registration epoch `8367`.
The protocol-version schedule changes at epochs 11925 and 12220, so a validator-set hash is
epoch-bound even when the members do not change.

This is promising bootstrap material but not an approved Ghost Gate anchor yet:

1. The `v0.47.0` annotated tag contains a PGP signature, but this laptop's `git tag -v v0.47.0`
   could not start GPG (`couldn't create signal pipe, Win32 error 5`). No trusted maintainer key
   fingerprint was available to complete signature verification.
2. The source preset's registration epoch (`8367`) and the public indexer's reported active start
   epoch (`11670`) differ. That may be expected oracle bookkeeping, but this review has no
   independently authenticated evidence binding the source preset to the later validator-set
   hashes, weights, and assignment.
3. The official `TrustedValidatorSet::anchor_pinned` implementation correctly verifies a
   transport-supplied committee against a pinned hash, but it deliberately cannot authenticate
   the first hash. `anchor_on_first_use` has not been used.

**Decision: remain `UNTRUSTED` and return `UNKNOWN`.** The sidecar must not receive an
`approved` anchor configuration based on these endpoint responses or this unverified local clone.

### Exact next action

Obtain an independently authenticated Tari Project release-verification artifact: the maintainer
PGP fingerprint (or another durable signed release channel) for `v0.47.0`, plus a signed Esmeralda
bootstrap statement that binds the network byte, validator public keys, vote powers, shard
assignment, activation history, and either a validator-set hash/committee or an L1-verifiable
derivation. After that artifact is verified, add a small deterministic bootstrap-derivation test,
enter only its resulting hash and transport-fetched committee in the gitignored reviewed anchor
file, and prove one live request through the sidecar. Until then, no live authorization can be
called consensus-verified.
