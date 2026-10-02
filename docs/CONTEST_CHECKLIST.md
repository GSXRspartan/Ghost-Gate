# Contest checklist

Requirements for the October 2026 Tari Ootle **Spooky Secrets** privacy build contest. Tracked as
a checklist so nothing is claimed as done before it is.

## Repository and licensing

| Item | Status |
|---|---|
| Public source repository | **NOT DONE** — this repo is local only. Needs a public URL. |
| OSI-approved license | **DONE** — MIT, `LICENSE`. Note: official Tari Ootle is BSD-3-Clause and is an unmodified dependency. |
| README with honest status | **DONE** — `README.md`, with a PROVEN / NOT PROVEN table. |
| Clean-room statement | **DONE** — `docs/CLEAN_ROOM.md`. |
| Privacy claim written precisely | **DONE** — `docs/PRIVACY_MODEL.md`. |
| Threat model | **DONE** — `docs/THREAT_MODEL.md`, including open items. |

## Technical submission

| Item | Status |
|---|---|
| Ghost Gate template compiling for `wasm32-unknown-unknown` | **DONE** — `templates/ghost_gate`. |
| Threshold enforced under consensus | **DONE** — `GhostGate::prove_access`, tested. |
| MVP binding demonstrated | **DONE** — `docs/GATE1_RESULTS.md`. |
| Adversarial test suite | **DONE** — unit, crypto and template tiers. |
| Ordinary wallet E2E | **NOT DONE** — `docs/GATE3_RESULTS.md`. This is the gate that decides product viability. |
| Runnable demo | **NOT STARTED** — blocked behind Gate 3, correctly. |
| Self-hostable backend | **PARTIAL** — `ghost-gate-verifier` library exists; no HTTP service. |

## Submission content still to write

| Item | Status |
|---|---|
| Contest submission description | **NOT WRITTEN.** Draft should lead with: *"a user proved they controlled sufficient private Tari without revealing the amount"*, and must not say "balance proof" or "anonymous". |
| Demo script | **NOT WRITTEN.** Depends on a running demo. |
| Architecture diagram for the submission post | **NOT DRAWN.** The ASCII diagram in `README.md` will do as a starting point. |
| Screenshot or recording | **NOT TAKEN.** Depends on a running demo. |

## Payments and announcements

| Item | Status |
|---|---|
| Tari payment address for prize payout | **NOT PROVIDED** — deliberately absent from the source. Add only when supplied. |
| Bluesky or Reddit announcement | **NOT POSTED.** Do not fabricate links. |
| Single official contest submission post | **NOT POSTED.** One canonical post; announcements should link to it rather than duplicate it. |

## Before submitting, verify

1. `cargo test` passes on a clean checkout.
2. `docs/GATE3_RESULTS.md` says GREEN, or the submission says plainly that it does not.
3. No claim in the README or submission exceeds `docs/PRIVACY_MODEL.md`.
4. No secrets, wallet databases or build outputs are committed (`git status --short` clean).
5. Every "not done" above is either done or stated as a limitation in the submission itself.