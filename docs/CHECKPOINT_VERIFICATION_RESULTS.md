# Checkpoint verification results

## Implemented cryptographic boundary

`tools/ghost-gate-v047-verifier` uses the v0.47 light client in its own Cargo project, preserving
the v0.42 bridge's dependency isolation. It calls `TrustedValidatorSet::anchor_pinned`; it does
not expose `anchor_on_first_use` or automatic re-anchoring.

The adapter retains every verified validator-set hash. `advance()` accepts only the next epoch's
checkpoint when the current walked committee verifies its network, epoch, shard group and quorum
signatures, then verifies the committed next committee against the committed next-set hash.
Inclusion verification chooses the retained set for the evidence epoch, verifies the committee,
then verifies the commit proof and substate proof. A freshness window is applied separately.

The loopback sidecar remains bounded to one handover, 64 KiB total request framing, 57,340-byte
body, five-second I/O deadlines and eight in-flight requests. Its caller token and anchor JSON
remain local process configuration and are not logged.

## Test evidence

The focused v0.47 verifier suite validates official deterministic fixtures for:

- successful pinned committee and substate verification;
- wrong network, value and committee rejection;
- valid signed handover;
- changed authenticated committee data, missing signer, bad signature, wrong epoch, altered hash,
  truncated checkpoint and wrong network rejection;
- untrusted/draft anchor refusal;
- release-topology candidate-root checks at epoch 12634; and
- global shard 0 rejection (Esmeralda's walked shard is 1).

These tests establish implementation behavior relative to a supplied anchor. They do **not**
authenticate a live Esmeralda root.

## Genuine evidence result

On 2026-10-23, bounded read-only requests to the official public indexer returned retained,
genuine shard-1 responses for epochs 12633 and 12634, including each next-epoch committee proof.
The focused `esmeralda_release_handover` regression derives the epoch-12634 root from the reviewed
release topology, authenticates the 12634 committee using the preceding response, and runs the
official `TrustedValidatorSet::advance` on the genuine 12634 checkpoint. It reached the
independently derived epoch-12635 root successfully.

The raw transport hashes, endpoints, protocol-version calculation and trust assumptions are in
`ESMERALDA_RELEASE_BOOTSTRAP_POLICY.md`. This is a cryptographic live-evidence PASS **relative to
the conditional release-derived candidate root**. It is not independent authentication of the
signer's authority, and it does not establish current-state freshness.

Result: **CHECKPOINT_VALID_RELATIVE_TO_CONDITIONAL_ROOT / production authorization remains
fail-closed.**
