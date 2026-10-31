# Real 10-tTARI gate verdict

## Verdict: BLOCKED — production authorization remains fail-closed

Ghost Gate has no independently authenticated Esmeralda validator-set root on this laptop. Under
v0.47's Hybrid oracle, synchronizing L1 would establish epoch timing but not independently prove
the configured validator topology. The retained genuine 12634-to-12635 checkpoint now verifies
cryptographically relative to a conditional release-derived root, but the release-signing key's
authority has not been approved as an operator policy and the one-epoch chain does not establish
current-state freshness. The standalone v0.47 sidecar is therefore not ready and is not wired as
a source of production authorization for the v0.42 bridge. No real Sapient proof, access session,
protected-site access, Telegram production admission, wallet operation or transaction was
attempted in this run.

The known Esmeralda credential gate policy remains native tTARI resource
`resource_0101010101010101010101010101010101010101010101010101010101010101`, divisibility 6,
and threshold `10_000_000` raw units (10 tTARI). A browser-supplied balance, account name,
address, or `verified` field is never sufficient.

## Conditions for an eventual authorization

All of the following must succeed in one non-test production path:

1. A reviewed maintainer-authenticated anchor, or explicitly operator-approved conditional
   release-derived anchor under `ESMERALDA_RELEASE_BOOTSTRAP_POLICY.md`, is installed for
   Esmeralda network byte 38, walked shard 1.
2. The sidecar verifies a contiguous signed checkpoint chain and the finalized substate evidence
   against that anchor, including proof epoch freshness.
3. The credential verifier confirms the native resource, 10,000,000 raw minimum, unspent/current
   state and output authorization key from verified state, not an indexer assertion.
4. Sapient proves ownership of that output with the Ghost Gate server challenge nonce and the
   server-bound relying-site/session context.
5. The durable replay store atomically reserves/consumes the challenge and the access registry
   issues exactly one short-lived session scoped to the configured gate and policy.

Any unavailable anchor, invalid handover, missing finality, stale evidence, ownership mismatch,
threshold shortfall, storage error or replay must deny access. Telegram's isolated test mode remains
test-only and cannot satisfy these production conditions.

## Exact next step

Choose and record one trust decision: either obtain a Tari maintainer-authenticated immutable
anchor statement, or explicitly approve the reviewed conditional release-bootstrap policy. Then
retain and verify a contiguous signed checkpoint chain to a defined current freshness horizon and
obtain an authenticated fresh 10-tTARI state/ownership proof. Only after those artifacts pass
review should the sidecar verdict be integrated into live credential-session issuance.
