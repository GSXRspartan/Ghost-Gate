# Tari Ootle Spooky Secrets contest submission

> **Historical draft.** It predates the Crypt v3 release state and must not be used as the current
> contest description. See the top-level `README.md` and `docs/DEMO.md`.

## One-sentence claim

**Ghost Gate: a user proved they controlled sufficient private Tari without revealing the amount,
on a live Ootle network, through a component that any ordinary wallet can call.**

That sentence is the whole submission. Everything below exists only to support it, and every claim
is backed by a test or a result file. Nothing here says "balance proof" and nothing here says
"anonymous" — both would be false, and the privacy model is written precisely enough to know why.

## What was built

Ghost Gate is a privacy gate for Ootle resources. A site embeds it, sets a threshold in the admin
dashboard (say, exactly 10 tTARI), and visitors prove they control at least that amount **without
disclosing the amount, the balance, or the wallet that holds it**. The gate runs on-chain —
a `GhostGate` component deployed to the Ootle network — so the threshold is enforced by consensus,
not by the site's backend. The backend exists to hand out challenges and issue access sessions; it
cannot change the threshold, forge a proof, or see how much anyone has.

The three pieces:

```
                     +----------------------------------------------+
                     |              GHOST GATE ADMIN                |
                     |   http://127.0.0.1:7811/admin                |
                     |  passkey / wallet-key login, exact tTARI     |
                     |  threshold, per-gate registry, audit log     |
                     +--------------------+-------------------------+
                                          |
                                          v
        +-------------+      +------------+-----------------+     +-------------------+
        |  BROWSER    |      |      GHOST GATE BRIDGE       |     |  OOTLE VALIDATORS |
        |  visitor    |----->|  http://127.0.0.1:7799       |---->|  (consensus)      |
        |  wallet via |      |  challenge -> prove ->       |     |  GhostGate comp-  |
        |  extension  |      |  access check                |     |  onent enforces   |
        +-------------+      +------------------------------+     +-------------------+
             ^                                      |
             |                                      v
             +--------------------------------- access session
                     (token only proves "enough", never the amount)
```

The browser asks the bridge for a challenge. The bridge gives it a nonce, the gate's threshold and
the gate's binding — but **not** the visitor's balance. The visitor's wallet builds a statement
against that nonce, covering exactly the threshold and no more, and submits it. Validators commit
the result. If the promise is met, the bridge issues an access session token. The token is a proof
of sufficiency, not a proof of value: it can be checked by any process holding the registry, but it
carries no amount.

## What is proven, with where it is proven

Every row below points at a file in this repository. `PROVEN` means a test in this repository
demonstrates it — it never means "simulated".

| Claim | Where it is proven |
|---|---|
| Threshold enforced under Ootle consensus | `docs/GATE1_RESULTS.md`, `docs/GATE3_RESULTS.md` |
| The promise is covered by the range proof, so the amount is not revealed | `docs/PRIVACY_MODEL.md`, `docs/GATE1_RESULTS.md` |
| Ordinary wallet funds flow through the component | `crates/ghost-gate-engine/tests/`, `a_wallet_built_statement_satisfies_the_gate` |
| Live network submission, validators committed, replay refused | `docs/GATE3_RESULTS.md` (GREEN, re-measured 2026-10-07) |
| Any stealth fungible resource, any divisibility | `crates/ghost-gate-engine/tests/cross_resource.rs` |
| Unsupported resource classes refused by name | same file |
| GHSA-pp4v-v773-9qxg reconciled and backported | `docs/GATE3_RESULTS.md`, 48/48 tests |
| Privacy Lab runs fully offline, no localnet needed | `crates/ghost-gate-bridge/assets/lab/`, `http://127.0.0.1:7799/lab` |
| Real browser E2E: 74/74 checks pass on a live admin plane | `scripts/browser_game_check.sh`, admin `tests/admin_plane.rs` |

## Privacy model — what is hidden and what is not

`docs/PRIVACY_MODEL.md` is the authoritative list of what is hidden, what is visible, and what is
explicitly **not** claimed. The short version:

**Hidden from the site and from observers:**
- The exact amount of the wallet's balance.
- Whether the balance is 10 tTARI or 10,000 tTARI (both prove "at least 10").
- The wallet's identity beyond the fact that it participated.

**Visible (and stated honestly):**
- The threshold itself — it is part of the gate's public policy.
- The timing of proofs, and how many proofs a gate accepted.
- Session correlation: two proofs from the same browser within a session can be linked.
- The refresh beacon keeps history alive for the configured window; a refresh does not erase the
  past, it stops future beaconing.

**Explicitly NOT claimed:** total balance proof, network anonymity, cross-network binding stronger
than the challenge/gate byte agreement, or invisibility from the operator's own bridge.

## Why it matters

Most "prove you have X" systems require you to reveal X, or to reveal your balance, or to use a
custodian. Ghost Gate requires none of those: the amount stays inside the range proof, the wallet
is never named, and the gate runs on-chain where neither the site nor the operator can weaken it.
The visitor proves they are *enough* — never *how much*. That is the property the Spooky Secrets
contest is about, and it is the property the lab makes visible.

## Repo layout

```
crates/
  ghost-gate-core/       policy model, network bytes, canonical hashing
  ghost-gate-engine/     gate statement engine + adversarial test suite
  ghost-gate-verifier/   offline proof verification library
  ghost-gate-walletd/    patched walletd (MVP binding) + bridge binary
  ghost-gate-registry/   authoritative gate/policy/session registry
  ghost-gate-admin/      admin control plane (7811)
  ghost-gate-bridge/     HTTP bridge + Privacy Lab (7799)
templates/ghost_gate/    the on-chain component, wasm32-unknown-unknown
docs/                    privacy model, threat model, gate results, this file
scripts/                 startup, demo, browser harness, localnet watcher
```

## How to run the demo

`docs/DEMO_SCRIPT.md` walks through it. The Privacy Lab needs only:

```bash
./scripts/start_vault.sh
```

Then open `http://127.0.0.1:7799/lab` in a browser. No localnet, no wallet, no network — the lab
demonstrates the decision flow, the timing-privacy property, and the refresh beacon using the real
policy registry, the real bridge code and the real challenge/nonce logic. A full consensus demo
(add `--with-localnet`) needs the Ootle localnet running.

## Honest limitations

- The consensus demo requires a localnet instance; the lab does not.
- The bridge is a self-hosted backend, not a managed service. `docs/THREAT_MODEL.md` covers what
  the operator can and cannot see.
- Cross-network binding is weaker than a validator commitment (see `docs/PRIVACY_MODEL.md`,
  "Cross-network binding is weaker than intended" — the gate stores a network byte and compares
  challenge to gate; it does not assert the transaction was validated on network X).
- The wallet extension used in the full E2E is the MVP-patched walletd shipped in
  `crates/ghost-gate-walletd/`. Any ordinary stealth-fungible wallet that implements the statement
  flow works; wallets that do not implement it will fail at the challenge step, not silently pass.

## Verification commands

```bash
# One-shot: build + all tests + browser check (uses /home/pdark/gg-ootle-target)
./scripts/run_all_tests.sh

# Core suites only
cargo test -p ghost-gate-core -p ghost-gate-engine -p ghost-gate-registry \
           -p ghost-gate-admin -p ghost-gate-bridge -p ghost-gate-verifier -p ghost-gate-walletd

# Privacy Lab (offline, no localnet)
./scripts/start_vault.sh
open http://127.0.0.1:7799/lab

# Full consensus demo (needs localnet up)
./scripts/first_real_proof.sh
```

## Licensing

MIT (`LICENSE`). Official Tari Ootle is BSD-3-Clause and is consumed unmodified as a dependency;
`docs/CLEAN_ROOM.md` states the clean-room posture.
