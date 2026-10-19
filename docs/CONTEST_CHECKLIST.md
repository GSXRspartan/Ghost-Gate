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
| Ordinary wallet E2E | **DONE** — `docs/GATE3_RESULTS.md` says GREEN; two scenarios committed by validators and replay refused. Re-measured 2026-10-07 at `5d92ae9`. |
| Runnable demo | **PARTIAL** — the Privacy Lab (`http://127.0.0.1:7799/lab`) runs fully offline with no localnet and demonstrates the real decision flow, timing privacy and the refresh beacon. A full consensus demo still needs the localnet running. |
| Self-hostable backend | **DONE** — `ghost-gate-bridge` is a real HTTP service (port 7799: challenge, prove, access, Privacy Lab; port 7811: admin plane). Registry-backed, fail-closed, tested. |

## Submission content still to write

| Item | Status |
|---|---|
| Contest submission description | **DRAFTED** — `docs/CONTEST_SUBMISSION.md`. Leads with the required sentence; no "balance proof" or "anonymous". |
| Demo script | **DRAFTED** — `docs/DEMO_SCRIPT.md`, for the Privacy Lab demo (runs offline, no localnet). |
| Architecture diagram for the submission post | **DONE** — the ASCII diagram in `README.md` is the starting point; `docs/CONTEST_SUBMISSION.md` includes a refined version. |
| Screenshot or recording | **DONE** — `docs/screenshots/privacy-lab-simple.png` and `privacy-lab-technical.png` (the Lab's two views, committed at `0e92d96`). |

## Payments and announcements

| Item | Status |
|---|---|
| Tari payment address for prize payout | **NOT PROVIDED** — deliberately absent from the source. Add only when supplied. |
| Bluesky or Reddit announcement | **NOT POSTED.** Do not fabricate links. |
| Single official contest submission post | **NOT POSTED.** One canonical post; announcements should link to it rather than duplicate it. |

## Before submitting, verify

1. `cargo test` passes on a clean checkout. — **DONE 2026-10-18** at `801d9bc`: full workspace, 340 tests, 0 failures. Warnings are unused-import/variable cosmetics only.
2. `docs/GATE3_RESULTS.md` says GREEN, or the submission says plainly that it does not. — **DONE**: GREEN verdict at line 149.
3. No claim in the README or submission exceeds `docs/PRIVACY_MODEL.md`. — **DONE 2026-10-18**: grep for "anonymous"/"untraceable" returns nothing; "balance proof" appears only in engine-feature tables and the submission's explicit NOT-claimed list.
4. No secrets, wallet databases or build outputs are committed (`git status --short` clean). — **DONE 2026-10-18**: clean.
5. Every "not done" above is either done or stated as a limitation in the submission itself. — Remaining NOT DONEs (public repo URL, payment address, announcements) are all operator actions; the submission text states no false claims about them.