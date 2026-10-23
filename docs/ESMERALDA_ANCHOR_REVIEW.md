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
