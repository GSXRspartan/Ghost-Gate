# Esmeralda anchor bootstrap: final determination

## Do not synchronize a full L1 node for this purpose

The reviewed v0.47 Esmeralda configuration is Hybrid, not a base-layer topology oracle. The exact
source behavior is decisive:

- `hybrid/oracle.rs:54-76` receives base-layer events but forwards only `EpochChanged` and the
  first `DoneForNow` to the configured ticker; all other base-layer events are ignored.
- `configured/oracle.rs:212-260` emits registrations and `ActiveValidatorNodeSetChanged` from
  `queued_validators`, which originated in configured topology.
- `configured/oracle.rs:127-142` states that validators activated before local shard-key recording
  are pinned to whatever the current configuration derives, because that is the best available
  record for that process.
- Esmeralda's `f_epoch_oracle.toml:70-124` sets `oracle = "Hybrid"`, supplies the L1 endpoint and
  start height, and separately embeds the four validators, shard group `1..=256`, and registration
  epoch 8367 in `config_json`.

Therefore, a freshly synchronized independent L1 node would establish epoch timing/boundaries but
would not independently authenticate the configured validator topology needed to derive Ghost
Gate's epoch-12634 root. It is not a justified immediate operational step. No base node, indexer,
walletd, or validator should be installed or synchronized for this bootstrap question.

## Minimum defensible conditional deployment policy

An operator may choose a **conditional** release-derived root only when all of these are recorded
in a local, gitignored review record:

1. The exact v0.47.0 source tag and commit are verified against a release-signing fingerprint that
   the accountable operator explicitly accepts as policy. GitHub's Verified badge is not enough.
2. The operator records that this authenticates release provenance, not historical Esmeralda
   membership. The policy must use that wording in operator-facing status and deployment review.
3. The release topology is recomputed with v0.47 canonical hashing for one exact epoch, protocol
   version, 256 preshards, shard group `1..=256`, and unit weights; the derived root is recorded.
4. `anchor_pinned(network=38, walk_shard=1, epoch, root, committee)` verifies the transported
   committee proof. Transport never selects or replaces the root.
5. There is no automatic re-anchor. A replacement needs a new review record and explicit operator
   approval. A missing checkpoint, invalid handover, stale proof, or unavailable sidecar denies
   access.

This policy permits an operator-trusted deployment boundary; it does **not** create independent
authentication. Ghost Gate's current production path remains disabled because no such operator
approval record has been installed.

## Exact maintainer-authenticated alternative

The preferred external artifact is a Tari maintainer-signed, immutable anchor statement for one
Esmeralda epoch. It must include or commit by digest to:

- network byte 38 and epoch;
- protocol version and preshard count;
- every validator public key, vote power, and shard assignment in the set;
- the canonical validator-set root; and
- enough committee-proof material to verify the walked shard-1 committee against that root.

The statement's signature must be independently verified against a maintainer key the operator
has explicitly approved; a hosted web response or indexer field is insufficient. A signed release
manifest carrying the same data is acceptable. This artifact is the route to independent anchor
authentication. The alternative is the explicitly conditional operator policy now recorded in
`ESMERALDA_RELEASE_BOOTSTRAP_POLICY.md`; it does not provide independent authentication.

## Evidence retention and replay after approval

Retain the unmodified signed anchor statement, its signature/certificate chain, the exact release
source digest, and raw indexer transport responses. The reproducible public transport fixtures are
versioned under `tools/ghost-gate-v047-verifier/evidence/`; any operator approval record stays
local and gitignored. For each handover retain the complete `EpochCheckpointEntry` bytes and its
next-epoch committee proof.

Install only the reviewed local anchor JSON into `GG_V047_ANCHOR_CONFIG`, then replay contiguous
raw entries through `PinnedConsensusVerifier::advance()` in epoch order. Persist each resulting
trusted validator-set hash with the evidence digest. Do not use decoded JSON convenience `members`
as authoritative; the committee proof and checkpoint signatures are what `advance()` validates.
