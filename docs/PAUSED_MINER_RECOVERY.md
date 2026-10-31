# Paused-Miner Recovery Procedure — DRAFT (Write-Only)

> **STATUS: DRAFT — DO NOT EXECUTE.**
> This document was written 2026-10-19 to satisfy the P1 task. It is a *prepared* procedure only.
> Execution requires explicit operator approval and physical presence at the shared localnet host.
> Nothing in this file has been run, and no automated tooling is wired to it.

## 1. Context

The shared localnet (purrivacy-localnet-v042) was deliberately paused on **2026-10-17** by the
operator. The pause marker records:

> *"2026-10-17 deliberate stop: L2 consensus drains epoch-transition queue; oracle must not
> outrun committed (ootle v0.42.0 EndEpoch-only blocks carry no mempool txs)"*

**Why the pause was taken (inferred from the marker text):**
In Ootle v0.42.0, `EndEpoch`-only blocks carry **no mempool transactions**. This means a block can
finalize while the epoch-transition queue is still draining. If the Ghost Gate oracle (verifier)
reads committed state *before* the queue fully drains, it may attest against a state view that is
already stale relative to the next epoch boundary. The miner was paused to freeze the tip while
the queue drained, so the oracle could be synchronized and validated against a stable epoch.

**Why it matters for Ghost Gate:**
Our real-proof path (P2) relies on the indexer reporting `current_epoch` and `block_height` that
match the actual committed consensus tip. If mining restarts before we validate the drain
behavior, the epoch will advance under us and the 10-tTARI proof may verify against a stale
epoch.

## 2. Safety Rules (unchanged)

- The pause marker **must not be removed** by any automated tooling.
- Mining must **not be restarted** without the operator physically initiating it.
- The chain **must not be reset**; no transaction may be broadcast as a "test" during this
  procedure.
- Shared wallet state (walletd at `:12010`) **must not be modified**.

## 3. Preconditions for Recovery

Before lifting the pause, the following must be verified **read-only**:

| Check | Target | Expected |
|---|---|---|
| Indexer healthy | `http://127.0.0.1:12007/health` | `status: "ok"`, `db_ok: true` |
| Consensus tip | `current_epoch` | Stable at `3672` (or current at pause time) |
| Epoch transition queue | `/api/v1/epoch/queue` (or equivalent) | Empty / drained |
| L1 Minotari node | port `12001` | Running, block tip frozen |
| Validator | port `12005` | Running, no consensus errors in last N min |
| Wallet daemon | port `12010` | Running, reachable |
| Ghost Gate walletd | port `18130` | Running, no pending transactions |
| Pause marker | host filesystem | Present, timestamp readable |

## 4. Recovery Steps (Operator-Only)

1. **Operator physically verifies** all preconditions in §3 pass.
2. **Operator records the exact tip hash** and `block_height` at the moment of pause-lift.
3. **Operator removes the pause marker** (manual filesystem action, no automation).
4. **Operator restarts the miner** using the localnet launcher (manual, one-by-one, not scripted).
5. **Observe:** the miner should produce exactly **one block** to confirm it is healthy. If it
   produces more than 3 consecutive blocks immediately, abort and re-pause (this indicates the
   queue was not drained).
6. **Verify no epoch skip:** `current_epoch` must increment by at most 1 per epoch boundary. If
   it jumps by >1, abort and re-pause.
7. **Wait for full drain:** wait for the L2 consensus to finalize the next epoch boundary. Check
   that `EndEpoch` block contains **no mempool transactions** (the v0.42.0 behavior).
8. **Only then** allow the oracle to resume reading committed state.

## 5. Abort Criteria

If any of the following occurs, re-pause the miner immediately and re-add the marker with an
updated timestamp:

- Miner produces > 3 blocks within the first minute of resume.
- Epoch skips by more than 1.
- Indexer reports a `db_ok: false` or a mismatch between `current_epoch` and the actual tip.
- Validator logs show a consensus warning or a fork.
- Walletd (either `:12010` or `:18130`) reports an unexpected balance change not caused by our
  own signed transactions.

## 6. Out of Scope

- Actual restart of mining (operator task).
- Broadcasting the 10-tTARI shield transaction (P2 — must wait until this procedure completes).
- Cloudflare deployment (P3 — requires separate operator approval).
- Telegram bot integration against a real Telegram group (P3 — requires separate approval).
