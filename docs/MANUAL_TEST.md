# Manual human test — Ghost Gate

**Status: NOT PERFORMED.** Every case below needs a reachable `walletd`, and the bridge's wallet channel
is not wired (see `docs/GATE4_RESULTS.md`). This list is kept so the flow is defined before it is
attempted, and so nobody later reports it as done on the strength of the code existing.

## Preconditions

```bash
# 1. The cohort, with the Gate 3 patches and the Gate 4 vendored templates.
export CARGO_TARGET_DIR_UNUSED=1   # not needed; scripts/ootle_e2e.sh passes --config itself

# 2. A localnet: base node, validator, indexer, miner. The cohort's integration_tests harness starts
#    these in process and is the easiest way to get a full stack.
scripts/ootle_e2e.sh -- --tags "@ghost_gate"

# 3. walletd, on 127.0.0.1:5100 by default.

# 4. The bridge, with at least one gate and at least one permitted origin. Both are refused at startup
#    if missing, because a bridge with no origin allowlist is the thing this design exists to prevent.
GG_BRIDGE_GATES='g1=component_<hex>:resource_<hex>:<raw threshold>:<divisibility>:<symbol>' \
GG_BRIDGE_ORIGINS='http://127.0.0.1:7799' \
GG_BRIDGE_BIND='127.0.0.1:7799' \
cargo run -p ghost-gate-bridge

# 5. Open http://127.0.0.1:7799 in the same browser.
```

## The cases

| # | Setup | Expected | Where the evidence goes |
| --- | --- | --- | --- |
| 1 | Wallet holds ≥ threshold of the gate's resource | 👻 **ACCESS GRANTED**, "Minimum threshold proven. Actual balance not disclosed. Challenge consumed." | `GET /proof/:id/status` returning `state: accepted`, plus the `GhostGate.GG` receipt event |
| 2 | Wallet holds < threshold of the gate's resource | **ACCESS DENIED**, "The required threshold was not proven. Your exact balance remains private." | `state: refused` with the gate's own reason |
| 3 | Second (created) resource, wallet holds ≥ threshold | 👻 **ACCESS GRANTED** | same as 1; the receipt names the same floor |
| 4 | Wallet holds the wrong resource only | **ACCESS DENIED** | `state: refused`; consensus refused the cross-resource spend |
| 5 | Replay: reuse the challenge that case 1 consumed | **ACCESS DENIED**, "Challenge already used. Request a fresh challenge." | `409` from `POST /gate/:id/prove` |
| 6 | Wait out the challenge TTL, then answer | **ACCESS DENIED**, "Challenge expired." | `409` with `challenge has expired` |

## What to capture for each

- The browser's Network tab: the request and response bodies. They should contain no balance, no key,
  no mask and no UTXO identifier — and if one does, that is a bug, not an observation to note quietly.
- `GET /wallet/status`, which reports reachability and cohort and nothing else.
- The gate's own on-chain readback: `GhostGate::resource`, `GhostGate::threshold`,
  `GhostGate::proofs_accepted`, `GhostGate::is_nonce_used`.
- For an accepted proof, the `GhostGate.GG` event payload decoded into `ProofReceipt`.

## Cases that must also pass and are easy to forget

- A page on an origin **not** in `GG_BRIDGE_ORIGINS` gets `403` on every route, including `/health`.
- `GET /wallet/balance`, `GET /wallet/utxos` and `GET /gate/:id/keys` return `404`.
- A prove request carrying an extra `amount` or `utxos` field is refused and never reaches the wallet.

## The question this test is really asking

Not "does it work" — that is the engine suite and the localnet. The question is whether a person can
look at this and correctly believe three things: their balance was not disclosed, their funds did not
move to anyone, and the interaction is public on chain. If any of those three is not visible without
reading source, the UI is wrong however well the tests pass.