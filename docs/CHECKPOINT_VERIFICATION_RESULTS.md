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

No genuine current checkpoint or L1-derived anchor was verified in this run. The earlier raw
12634-to-12635 handover is not retained in the repository, and previous public-endpoint retrieval
was refused. Therefore there is no claim that a genuine 12634-to-12635 handover passed during
this run.

The conditional epoch-12634 release-derived root remains
`dc39359775aa329670eb8cbfce7e1c77f7e5280d1ae334bc62bb46485c6c8956`. It is useful only after an
operator explicitly accepts the reviewed release-signing policy; it is not a substitute for the
independent L1 bootstrap described in `INDEPENDENT_ANCHOR_BOOTSTRAP.md`.

Result: **ANCHOR_UNTRUSTED / no live checkpoint authorization.**
