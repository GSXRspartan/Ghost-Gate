# Real 10-tTARI gate verdict

## Verdict: BLOCKED — production authorization remains fail-closed

Ghost Gate has no independently authenticated Esmeralda validator-set root on this laptop. Under
v0.47's Hybrid oracle, synchronizing L1 would establish epoch timing but not independently prove
the configured validator topology. The standalone v0.47 sidecar therefore cannot be made ready
legitimately, and it is not wired as a source of production authorization for the v0.42
bridge. No real Sapient proof, access session, protected-site access, Telegram production
admission, wallet operation or transaction was attempted in this run.

The known Esmeralda credential gate policy remains native tTARI resource
`resource_0101010101010101010101010101010101010101010101010101010101010101`, divisibility 6,
and threshold `10_000_000` raw units (10 tTARI). A browser-supplied balance, account name,
address, or `verified` field is never sufficient.

## Conditions for an eventual authorization

All of the following must succeed in one non-test production path:

1. A reviewed maintainer-authenticated anchor, or explicitly operator-trusted conditional
   release-derived anchor, is installed for Esmeralda network byte 38, walked shard 1.
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

Obtain a Tari maintainer-authenticated immutable statement binding one concrete Esmeralda epoch to
the complete validator topology and canonical validator-set root. Verify its signature under an
operator-approved maintainer key, then replay the retained raw signed checkpoint handovers through
the sidecar. Only after those artifacts pass review should the sidecar verdict be integrated into
the live credential-session issuance path.
