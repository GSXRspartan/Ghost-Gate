# Security release gate — what may ship, and what may not

The purpose of this gate is to make the go/no-go decisions explicit, so "the happy path works" can
never be confused with "the component is secure". Properties are labelled by how they are
established: **PROVEN** (a permanent test that fails on regression), **REVIEWED** (source + second
pass, no test), or **KNOWN GAP** (documented, not fixed).

## Decision table

| Capability | Status | Basis | Public-demo safe? |
|---|---|---|---|
| Consensus proof (Mode A) via local walletd | **GO** | PROVEN — adversarial suite (11 forgeries refused) + engine suite + localnet scenario; soundness enforced by the engine, not wallet software | Yes |
| Credential proof (Mode B) via browser wallets | **GO, with conditions** | PROVEN — verifier tests (framing, key binding, unspent, unverified-data refusal, session binding) | Yes, where the indexer serves merkle-verified substates |
| Credential proof where substate proofs are disabled | **NO-GO** | F-04 fail-closed; the route answers with the reason | n/a |
| Bridge transport (loopback, origins, hosts, caps) | **GO** | PROVEN — rebinding, cap, hijack, replay, oversize, smuggling checks | Yes |
| Haunted Vault game **preview mode** | **GO** | Renders labelled sample state; never calls the challenge/proof/credential routes; mints nothing | Yes |
| Haunted Vault game **real unlocks** | **GO on testnets** | Bridge verdicts only; receipt-backed; no client-side grant path | Yes (testnet) |
| Game unlocks on mainnet | **NO-GO (yet)** | Requires an operator risk sign-off and mainnet cohort re-verification incl. F-07 | No |
| Telegram membership grants | **GO on testnets** | Backend-issued, fresh-proof-bound, expiring, revocable; consumes the same verified receipts | Yes (testnet) |
| Telegram on a public community | **NO-GO (yet)** | Same mainnet re-verification + operational hardening (bot token custody, rate limits) | No |
| Native L1 XTM proofs | **NO-GO** | BLOCKED upstream (no L1 dApp surface in Universe; Minotari wallet gRPC signs with the node-identity key only); experimental label everywhere | No |
| Sapient/Universe live wallet flows | **NOT CLAIMED** | No browser/extension in the build environment; the manual checklist exists and is unrun | n/a |

## Security properties proven by tests

1. **Threshold soundness is consensus-enforced** — an attacker with zero qualifying tokens cannot
   satisfy a nonzero threshold by any of the eleven modelled forgeries
   (`adversarial.rs`; engine's bulletproof + balance proof + resource-scoped input resolution).
2. **Failed forgeries are side-effect-free** — no counter increment, no nonce burn, no input
   destruction, challenge remains answerable (`adversarial.rs`).
3. **Replay protection** — a burnt nonce refuses reuse (`gate_engine.rs`); a consumed challenge
   refuses a second redemption (bridge).
4. **Cross-asset substitution** — a gate over resource A cannot be satisfied by holdings of resource
   B, NFTs, or public fungibles (`adversarial.rs`, `cross_resource.rs`).
5. **Challenge binding** — gate, resource, threshold, network, site, session, and (now) issuing
   origin are each individually refused on mismatch (`gate_engine.rs`, bridge).
6. **No UTXO identifier can cross the bridge API in either direction** — route sweep test.
7. **Transport policy** — rebound hosts refused on every route; origin allowlist exact-match;
   challenge cap 256 with 429; job cap 1 000; request framing and body bounds enforced.
8. **Credential verification** — byte-exact message framing, verification against the on-chain
   `auth.Key` (self-reported keys cannot move the verdict), unspent-at-verify-time, merkle-verified
   indexer evidence required, wrong network/resource refused, session+issuer binding.
9. **Wallet key isolation** — the Rust side never holds key material; signers are lock-derived
   inside walletd; browser prompts happen in the wallet's own UI.
10. **GHSA-pp4v-v773-9qxg backport active** — patch verification green; the backport's own
    regression passes inside the engine suite.

## Security properties independently reviewed

- The second-pass review (recorded in `SECURITY_FINDINGS.md` §Second-pass) challenged proof
  authenticity, resource ownership, threshold correctness, wallet authorisation, challenge
  uniqueness, session issuance, browser isolation, indexer trust, finality, and privileged backend
  operations. One new finding (F-09) emerged and was fixed; the rest are recorded as cleared with
  the check that cleared them.
- **Not yet externally reviewed.** An independent security-specialised read of the candidate
  changes is desirable before any public deployment; the audit documents are written to make that
  review cheap (each claim names its test).

## Known limitations (documented, not fixed)

- **F-07**: upstream GHSA-rr6w-w4r5-9fcx (account bricking via dust deposits) applies to the pinned
  cohort. Availability loss only; no Ghost Gate rule bypass. Remediation is a cohort re-pin when
  upstream ships a fix — a deliberate, byte-verified procedure (see below).
- **Credential mode finality**: a receipt describes the output state at one moment; sites govern
  session length with their own expiry. Deep reorgs between lookup and decision are inherent to L2.
- **Cross-session linkability in credential mode**: re-using one output links the sessions that used
  it (documented in `PROVIDER_COMPATIBILITY.md` §3; fresh output per proof is the unlinkable path).
- **Live browser wallet flows are unrun** — no browser/extension in the build environment. The
  manual checklist (`MANUAL_TEST.md`) defines exactly what to run and observe before any claim.
- **Session binding for operator callers**: a `None`-origin challenge may be answered by any
  `None`-origin caller on the same machine (curl/tests). This is the documented operator case.

## Unresolved vulnerabilities

- **None open at audit close.** All confirmed findings are fixed with failing-then-passing
  regressions; one was refuted; one upstream advisory is documented as unfixable within this
  project's provenance constraints.

## Features safe for local demonstration

- All of the GO rows above, on **testnets**, with the demo/preview mode clearly labelled.
- The Haunted Vault game including preview mode, real unlock flow through the bridge on localnet.

## Features requiring further work before public deployment

1. **Mainnet cohort re-verification** (incl. adopting F-07's upstream fix): re-pin, re-verify both
   patches, re-run the full engine + adversarial suites, then re-run this gate.
2. **Live wallet passes**: execute `MANUAL_TEST.md` on a real browser with Sapient and Tari
   Universe, and record results here.
3. **External review**: an independent security read of the candidate changes.
4. **Telegram operational hardening** before a public community: bot-token custody, rate limits,
   and an abuse playbook.
5. **CSRF/XSS/session hardening sweep** for any publicly reachable deployment (the current surface
   is loopback-only by design; a public listener would need this sweep first — the origin/host
   policy is not a public-internet design).

## Procedure for the F-07 cohort re-pin (when upstream ships a fix)

1. Fetch the upstream fix release; create a new `tari-ootle-v<ver>-ghost-gate` copy (never build in
   place).
2. Re-apply `docs/wallet-mvp.patch` and the GHSA backport; run `scripts/verify_patches.sh` against
   the new tree.
3. Re-run: workspace suite, engine `access_rules`, the adversarial suite, and the localnet
   `@ghost_gate` scenario.
4. Re-check the advisory list for anything newer; update this gate's decision table.
5. Only then flip mainnet rows to GO.
