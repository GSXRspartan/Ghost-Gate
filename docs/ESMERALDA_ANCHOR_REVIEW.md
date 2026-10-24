# Esmeralda trust-anchor review package

**Status: UNTRUSTED BY DEFAULT — Ghost Gate must return `UNKNOWN` until an operator installs a
reviewed anchor configuration.**

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
  "walkShard": 1,
  "validatorSetHash": "<official Tari JSON encoding>",
  "walkedCommittee": { "<official Tari ValidatorSetCommittee encoding>": "..." },
  "provenance": "<authenticated source, retrieval method, and evidence digest>",
  "reviewedAt": "<RFC3339 UTC timestamp>",
  "reviewedBy": "<named accountable reviewer or release verification identity>",
  "upstreamCommit": "9dabb2a76a9ad5c6e99dfa180ab7bbbcb1a05a47",
  "releaseBootstrap": {
    "releaseTag": "v0.47.0",
    "signerFingerprint": "337B91EFC5F1027D8AEDF63D1885B149504C0A64",
    "policyVersion": "ghost-gate/esmeralda-release-bootstrap/v1",
    "epochOraclePresetSha256": "e9b9badfb8061e982524c4176ae2336d44229c34b6d074ef128cd670e49d9df3"
  },
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
2. Confirm network byte `38` is Esmeralda, and record how the epoch, walk shard (exactly `1`;
   shard `0` is Tari's reserved global shard), validator-set
   hash and committee proof were obtained.
3. Retain the signed/source evidence and a digest beside the approval record.
4. Validate the committee through `PinnedConsensusVerifier::pinned`; it must cover the selected
   walk shard and match the approved network/epoch/hash.
5. Configure the sidecar from a gitignored local file using `GG_V047_ANCHOR_CONFIG` and check
   `GET /health` returns `ready:true` on loopback.
6. Never replace the anchor automatically. Later epochs advance only through signed checkpoint
   handovers verified from this root. A failed handover, stale proof, unavailable evidence or
   configuration parse failure remains `UNKNOWN`.

`releaseBootstrap` is optional. When present, the sidecar accepts only the exact reviewed
v0.47.0 release tag, signer fingerprint, policy version, epoch-oracle-preset SHA-256, Esmeralda
network byte, epoch 12634, and deterministically derived validator-set hash. It is not enabled by
default and does not make a transport response an anchor.

This package intentionally contains no production approval or active configuration. Filling its
placeholders requires an operator with independent provenance evidence.

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

### Signed source, source epoch, and indexer epoch

The exact local Tari source is tag `v0.47.0` at
`9dabb2a76a9ad5c6e99dfa180ab7bbbcb1a05a47`. Its
`applications/tari_ootle_app_utilities/config_presets/f_epoch_oracle.toml` selects Esmeralda's
hybrid oracle, names `https://grpc.esmeralda.tari.com`, has start height `669506`, and lists the
same four validator public keys for shard group `1..=256` with registration epoch `8367`.
The protocol-version schedule changes at epochs 11925 and 12220, so a validator-set hash is
epoch-bound even when the members do not change.

The annotated tag object for `v0.47.0` signs commit
`9dabb2a76a9ad5c6e99dfa180ab7bbbcb1a05a47`. Its OpenPGP issuer fingerprint is
`337B91EFC5F1027D8AEDF63D1885B149504C0A64` (long key ID `1885B149504C0A64`). An isolated,
temporary native GPG home imported the matching public key from GitHub's public
`sdbondi.gpg` endpoint and verified a `Good signature` over that exact tag and object. The key
labels itself `Stanley Bondi <sdbondi@users.noreply.github.com>`.

The earlier Windows error was a Git-for-Windows/MSYS path conversion problem: a native
`C:\\...` homedir supplied to GPG was not the homedir that GPG opened. Supplying its MSYS path
to an isolated keyring fixed verification. WSL cannot independently repeat the check on this
laptop because its configured Ubuntu ext4 VHDX is missing under `D:`; it was not repaired or
recreated. Public OpenPGP directory/keyserver lookups did not independently corroborate this
key's owner identity. Thus GitHub's Verified badge and hosted public key establish neither an
independent Esmeralda network root nor a Web-of-Trust identity certification.

The source's `registration_epoch = 8367` is a configured-oracle registration value. The v0.47
`Validator::activation_epoch` rule activates it at `8368`. The indexer endpoint exposes its stored
`ValidatorNode.start_epoch`, and returns the same four complete public keys only from epoch
`11670`, with vote power one and shard group `1..=256`. It returns no members at epochs 8367,
8368, or 11669. This is a real historical mismatch, not decimal/hex formatting: the signed source
does not itself explain the indexer's earlier history. The canonical v0.47 epoch-manager currently
assigns every active validator vote power one; its Esmeralda protocol rules change at 11925 and
12220, so the validator-set root is epoch-bound.

The configured hybrid oracle does not close that gap. Its base-layer client provides epoch ticks;
the configured oracle supplies topology. No authenticated L1 membership record was located in the
reviewed release that can independently derive the source-to-11670 transition.

### Narrow signed-release bootstrap result

For the later epoch 12634, the four signed-release full public keys, vote powers, shard group and
official v0.47 hash rules deterministically derive
`dc39359775aa329670eb8cbfce7e1c77f7e5280d1ae334bc62bb46485c6c8956`. A captured indexer
committee proof for that epoch matches this root and passes `PinnedConsensusVerifier::pinned`.
The proof is evidence checked *against* the derived root; its transport response was never used to
choose the root. The focused verifier suite covers this derivation, rejects a changed epoch, and
requires the exact release tag/fingerprint when `releaseBootstrap` is selected.

This establishes a bounded bootstrap only under one explicit deployment assumption: the operator
must deliberately pin the fingerprint above as an accepted Tari release-signing key. It does not
infer that policy merely from GitHub, nor does it authenticate the 8368-to-11670 history. The
historical discrepancy does not change the deterministic calculation at 12634, but it means that
calculation is a *conditional candidate root*, not independently established membership history.
No sidecar configuration has been written and no live authorization path has been enabled.

### Checkpoint transport and handover validation

The loopback sidecar now reads one framed HTTP/1.1 request with a 64 KiB total limit, an 8 KiB
header limit, and a 57,340-byte body limit. It requires a single valid `Content-Length` for
`POST /v1/verify`, rejects `Transfer-Encoding`, duplicate framing/authentication headers,
non-UTF-8 or malformed headers, excess bytes, truncated bodies and oversized requests. It uses a
five-second read/write deadline and permits at most eight in-flight loopback connections. This
keeps the approximately 29 KiB captured checkpoint class within bounded memory. It also permits
only one handover per verification request; increasing that policy requires a separately reviewed
transport budget, not an implicit increase in work or memory.

The canonical v0.47 `TrustedValidatorSet::advance` path was adversarially tested with official
signed fixtures. Relative to a pinned starting set, it accepts a valid handover and rejects a
wrong starting root, a corrupted authenticated next-committee proof, insufficient checkpoint
signers, a corrupted checkpoint signature, wrong epoch, altered next-set hash, truncated
checkpoint and incorrect network. The indexer's duplicate JSON `members` field is deliberately
not authoritative: changing only that convenience field leaves the proof-authenticated committee
unchanged, which is the intended safe behavior.

The complete genuine shard-1 12633 and 12634 responses are retained under
`tools/ghost-gate-v047-verifier/evidence/`, with SHA-256 digests in
`ESMERALDA_RELEASE_BOOTSTRAP_POLICY.md`. The focused v0.47 regression uses the 12633 next-epoch
committee as the epoch-12634 `anchor_pinned` proof, then verifies the genuine 12634 checkpoint
with `advance`, reaching the independently derived 12635 root. This is a live-evidence success
relative to the conditional release-derived root; it does not establish signer's authority or
current proof freshness.

### Exact remaining requirement

**BLOCKED for live consensus authorization.** The smallest missing independently authenticated
artifact is a Tari maintainer-authenticated immutable statement (for example, a maintainer-signed
release manifest) binding Esmeralda network byte 38, epoch 12634, the four validator keys,
unit weights, shard group `1..=256`, and the derived validator-set root. It need not reconstruct
all 8368-to-11670 history, but it must bind the candidate root at the anchor epoch.

After that artifact is reviewed and the release-signing-key pin is approved as deployment policy,
place the reviewed, gitignored anchor JSON in a local path and set `GG_V047_ANCHOR_CONFIG` only
for the loopback sidecar process. Then replay the retained raw 12634 checkpoint plus its next
committee through `PinnedConsensusVerifier::advance`; it must reach 12635 with the canonical next
set hash before access issuance is enabled. Until then Ghost Gate must return `UNKNOWN` and the
hosted 10-tTARI access flow must not issue a session.
