# Security fixes — what changed, and how each is verified

Each entry links to its finding in `SECURITY_FINDINGS.md`, states the remediation in implementation
terms, and names the verification. Every fix is a separate logical commit; this file is the index.

| # | Finding | Severity | Commit | Verification |
|---|---|---|---|---|
| F-01 | Forged statement consensus bypass | **REFUTED** (was CRITICAL) | `00b4ae3` | 11 real-engine forgeries refused; honest control accepted |
| F-02 | DNS rebinding → confused-deputy spend | HIGH | `b94f7d0` | host-allowlist tests + live binary check |
| F-03 | Unbounded challenge book (DoS) | MEDIUM | `b94f7d0` | cap test at 256, 429 with remedy, 429 rendering |
| F-04 | Credential verifier trusted unverified indexer data | MEDIUM | `b94f7d0` | `verified` flag fail-closed test |
| F-05 | Docs overclaimed browser Mode A unsoundness | INFORMATIONAL | `b94f7d0` (docs) | corrected prose, cites the adversarial suite |
| F-06 | Unbounded job list | LOW | `b94f7d0` | `MAX_JOBS` eviction |
| F-07 | Upstream GHSA-rr6w-w4r5-9fcx on pinned cohort | LOW (project) | n/a — documented | release-gate entry with re-pin procedure |
| F-09 | Session commitment was bearer knowledge | MEDIUM | `31f2fb9` | hijack reproduction refuses post-fix |

## F-02 — the Host allowlist

`parse_request` now extracts `Host`; `Bridge::handle` refuses any present-but-unrecognised host
before the origin check, on every route. Permitted set: `127.0.0.1`, `localhost`, `::1`, `[::1]`
(case-insensitive, port ignored — the listener already fixed the port). An absent Host still passes,
documented as the operator/CLI case; a browser always sends Host, and a rebound name is not in the
set.

Design note kept from the audit: the check deliberately comes **before** the origin check so a
rebinding page cannot even learn which origin policy it faces.

## F-03 — the challenge cap

`ChallengeBook::insert` prunes expired entries then enforces `MAX_LIVE_CHALLENGES = 256`; saturation
returns `BookError::TooManyChallenges`, which the registry propagates (no longer collapsed into an
`Option`) and the route answers **429** with "wait for one to be answered or expire". `render()`
learned the 429 reason phrase. The cap bounds concurrent state, not rate — an attacker can keep
exactly 255 live forever, which is bounded and intentional.

## F-04 — indexer evidence must be verified

`UtxoOnChain` carries the indexer's `verified` flag; `IndexerChainReader` passes it through
untouched; `CredentialVerifier` refuses `verified == false` with a dedicated refusal naming the
reason. Fail-closed by design; the documented cost (credential proofs unavailable where substate
proofs are disabled or just after an epoch boundary) is accepted for an authorisation path.

## F-09 — session binding against the issuer

`IssuedChallenge` records `issued_to_origin: Option<String>`; `validate_prove_request` (used by both
the consensus and credential routes) compares the caller's Origin with the issuer's and refuses a
mismatch as `SessionMismatch`. A `None` issuer (operator challenge) may only be answered by a
`None`-origin caller. The test harness deliberately permits two origins so the multi-site hijack is
the case under test.

## What was deliberately **not** changed

- **The Gate 3 template and `ghost-gate-core` rules.** The adversarial suite proved them sound; the
  only edits near consensus in this audit are tests. `gate3-green` (1a0b2824) remains untouched.
- **The cohort tree.** Two upstream patches (wallet MVP, GHSA backport) stay byte-verified; no
  re-pin, no upgrade. The one applicable upstream advisory is documented, not patched.
- **Wallet authorisation flows.** Nothing was loosened to improve usability; the two changes near
  the wallet (F-02, F-09) both *restrict* who can drive it.

## Regression posture

- Every reproduction test written for a confirmed finding **failed before its fix and passes after**
  (F-02's rebinding sweep, F-03's cap loop, F-04's unverified refusal, F-09's hijack).
- The F-01 suite's eleven forgeries are permanent negative regressions: if any ever turns green, the
  engine's validation has regressed and the consensus mode must be re-disabled.
- Counts at audit close: bridge 89, workspace 209, engine `access_rules` 48, web 20 — all green.
