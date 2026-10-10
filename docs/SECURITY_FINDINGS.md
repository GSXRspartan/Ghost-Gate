# Security findings — classification and reproduction

Every finding below names the component, the attacker's required capabilities, the exact
reproduction (test or live procedure), observed vs expected behaviour, and the disposition. Severity
is argued, not asserted; nothing here is called confirmed without a reproduction.

Legend: **CRITICAL** / **HIGH** / **MEDIUM** / **LOW** / **INFORMATIONAL**.

---

## F-01 — Forged `StealthTransferStatement` satisfies a threshold — **REFUTED** (was reported CRITICAL)

- **Component**: `templates/ghost_gate` `prove_access` + `ghost-gate-core` `qualify` /
  `find_qualifying_output`.
- **Prior claim**: the template checks only statement *shape* (balance-proof presence, not validity),
  so a dApp could hand-forge a statement claiming `minimum_value_promise ≥ threshold` and the gate
  would attest a floor no output carried.
- **Attacker capabilities**: own wallet, arbitrary instruction arguments in a
  `tari_signAndSubmitTransaction` call.
- **Reproduction**: `crates/ghost-gate-tests/tests/adversarial.rs` — eleven attacks through the real
  template in the real engine, including the exact headline (1-unit holder, MVP mutated 0 → 10 000
  after the proofs were made).
- **Expected (per the prior claim)**: acceptance, `proofs_accepted = 1`, nonce burnt.
- **Observed**: rejection at the engine's native validation (bulletproof mismatch / balance-proof
  failure / input resolution under the gate's resource), `proofs_accepted = 0`, nonce unburnt, the
  attacker's input unspent, and the challenge still answerable by an honest proof.
- **Impact**: none — the consensus boundary holds. **Exploitation disproven** (11/11 attempts).
- **Root cause of the false alarm**: the previous audit stopped reading at the template and missed
  that `prove_access` executes the statement via `ResourceManager::stealth_transfer`, whose native
  validation (bulletproof over claimed MVPs, balance proof over the public excess, resource-scoped
  input resolution, pre-execution authorisation) is the actual boundary. The template's comment says
  exactly this: "From here the engine owns the verdict."
- **Disposition**: prior CRITICAL downgraded to **REFUTED**; the eleven attempts are kept as
  permanent negative regressions. Documentation that encoded the wrong conclusion
  (`PROVIDER_COMPATIBILITY.md` §2) is corrected by `SECURITY_FIXES.md` F-05.
- **Test**: `zero_token_attacker_cannot_raise_their_own_attestation_by_mutating_the_mvp` and the ten
  siblings in the same file.

## F-02 — DNS rebinding enables a confused-deputy spend — **HIGH, FIXED**

- **Component**: `ghost-gate-bridge/src/http.rs` (`parse_request`), `server.rs` (`handle`).
- **Attacker capabilities**: any web page the victim has open; a DNS name the attacker controls.
- **Reproduction**: resolve `evil.com` to `127.0.0.1`; the browser sends same-origin requests (no
  `Origin` header) to `http://evil.com:7799`, which the origin policy welcomes as "not a browser".
  The page then reads `/wallet/status`, mints challenges, and completes
  `POST /gate/:id/prove` — driving the victim's local walletd to spend the victim's qualifying
  output for the attacker's benefit.
- **Expected**: refusal. **Observed (pre-fix)**: full access to every route.
- **Impact**: a hostile page operates the user's local wallet through the bridge. (This was the
  strongest finding of the audit; the challenge-based binding does not help because the attacker
  mints the challenge and reads the response as same-origin.)
- **Root cause**: the origin policy's `None → allowed` rule is correct for curl and tests but
  blind to same-origin web requests; `Host` was never parsed.
- **Remediation**: `Host` allowlist (loopback spellings only, port-agnostic, case-insensitive);
  present-but-unrecognised Host → 403 on every route; absent Host still permitted for the operator.
- **Test**: `a_rebound_host_name_is_refused_on_every_route` + `the_operators_own_host_spellings_are_permitted`;
  live-verified against the built binary (`Host: evil.com:7799` → 403 with explanation).
- **Verification result**: 88/88 bridge tests green; live reproduction refuses.

## F-03 — Unauthenticated challenge minting exhausts memory — **MEDIUM, FIXED**

- **Component**: `ghost-gate-bridge/src/session.rs` (`ChallengeBook`), `gate_registry.rs`
  (`issue_challenge`), `server.rs` (`issue_challenge` route).
- **Attacker capabilities**: any permitted origin (or, pre-F-02, a rebound one); a loop.
- **Reproduction**: loop `POST /gate/:id/challenge`. Pre-fix, every mint inserted an entry held
  until answered — unbounded growth, ~600 mints observed in the reproduction loop with no refusal.
- **Expected**: a bounded book. **Observed**: unbounded.
- **Impact**: trivially affordable memory DoS against the user's own machine.
- **Remediation**: `MAX_LIVE_CHALLENGES = 256`, enforced on insert after pruning expired entries;
  saturation returns **429** with the remedy in the message. Two supporting fixes: the registry
  previously collapsed all failures into `Option` (the cap would have surfaced as a generic 500),
  and `render()` had no 429 reason phrase.
- **Test**: `the_challenge_book_refuses_to_grow_without_bound`.

## F-04 — Credential verifier trusted unverified indexer answers — **MEDIUM, FIXED**

- **Component**: `ghost-gate-bridge/src/credential.rs` (`CredentialVerifier`), `ghost-gate-walletd`
  (`IndexerChainReader`).
- **Attacker capabilities**: a malicious or compromised indexer (the audit brief's exact question).
- **Reproduction**: serve `GetSubstateResponse { verified: false, … }` with any floor and key for an
  output that does not exist, or a stale record for a spent one. Pre-fix, the verifier accepted the
  values and authorised on them.
- **Expected**: refusal of unevidenced chain data. **Observed (pre-fix)**: acceptance.
- **Impact**: the relying site grants access on fabricated evidence.
- **Remediation**: `UtxoOnChain.verified` carried from the indexer into the verifier; `verified =
  false` → `CredentialRefusal::UnverifiedChainData` (fail-closed). Documented cost: credential
  proofs are unavailable where substate proofs are disabled or in the post-epoch-committee window;
  the consensus mode never touches the indexer.
- **Test**: `an_unverified_indexer_answer_is_refused_even_when_everything_else_matches`.

## F-05 — Documentation overclaim: browser Mode A called "unsound" — **INFORMATIONAL, CORRECTED**

- **Component**: `docs/PROVIDER_COMPATIBILITY.md` §2 (previous session), `web/js/ghost/capabilities.js`.
- **Issue**: the doc claimed browser wallets cannot do Mode A because forging would work. The
  adversarial tests disprove the forging claim (F-01). The *actual* reason browsers cannot do Mode A
  is capability: a dApp cannot assemble a valid statement (no mask/value access; wallet-built
  statements are never exposed), which is the capability gap the `ghostGateProveAccess` upstream
  proposal already addresses.
- **Remediation**: docs corrected in this audit; the adapter mode lists are unaffected (they were
  already capability-driven, and no browser wallet can assemble statements either way).
- **Test**: `docs` statement now cites the adversarial suite; no code change needed.

## F-06 — Unbounded job list — **LOW, FIXED**

- **Component**: `ghost-gate-bridge/src/server.rs` (`jobs`).
- **Reproduction**: same shape as F-03, one job per proof attempt.
- **Remediation**: `MAX_JOBS = 1_000`, oldest evicted; older results answer 404, which is what a
  result too old to retain should look like.
- **Test**: covered by the suite (eviction path exercised via the cap logic); the challenge cap
  bounds creation rate.

## F-07 — Upstream GHSA-rr6w-w4r5-9fcx affects the pinned cohort — **LOW (for this project), DOCUMENTED**

- **Component**: cohort `crates/template_builtin/templates/account/src/lib.rs` (builtin account).
- **Attacker capabilities**: any funded network participant (no victim interaction).
- **Relevance to Ghost Gate**: the attack bricks any account by dust-depositing ~3 100 one-unit
  resources, after which the account cannot even pay fees. Our walletd proof path pays fees from the
  user's default account, so a bricked account cannot run proofs — but this is a network-wide
  availability loss every account faces, **not** a Ghost Gate soundness/privacy bypass. No Ghost
  Gate rule is weakened; no proof forges.
- **Patched versions**: none published at audit time (`<= 0.43.0` vulnerable per the advisory).
- **Disposition**: cannot be fixed within this project without discarding the pinned, byte-verified
  cohort provenance. Recorded in `SECURITY_RELEASE_GATE.md` with the re-pin procedure.
- **Test**: n/a (upstream); the advisory's own PoC is upstream.

## F-08 — Reviewed, no finding (INFORMATIONAL)

Each was checked because the audit brief named it; each is recorded here with the check that cleared
it, so the absence of a finding is a result and not an omission:

| Check | Cleared by |
|---|---|
| XSS sinks in the front end | both `innerHTML` uses are static templates; all data via `textContent`; `nosniff` on every response |
| CORS misconfiguration | no `Access-Control-*` header is ever emitted; same-origin by design |
| CSRF on state-changing routes | cross-site POSTs carry `Origin` → refused; proof completion needs the minted nonce+session pair |
| Request smuggling / malformed HTTP | single request per connection, `\r\n` framing, bounded read, `Connection: close` (parser returns `None` on anything else) |
| Oversized payloads | `MAX_BODY = 8 KiB` bound on the read; oversized bodies fail JSON parsing → 400 |
| Challenge entropy | `random_nonce()` from the OS CSPRNG; uniqueness asserted |
| Concurrent challenge redemption | serialized serve loop + mutex; second submission sees `AlreadyAnswered` (tested) |
| Wrong-network credential | the signed message includes the network byte; a cross-network signature refuses (tested) |
| Provider `publicKey` substitution | verification binds to the on-chain `auth.Key`; a lying reported key cannot move the verdict (tested both directions) |
| Duplicate credential submission | challenge consumed only on acceptance; second submission refuses (tested) |
| Wallet inventory leakage | no route can return a balance/UTXO; route sweep asserted; adapters never request view access |
| Fake wallet-connection status | `/wallet/status` reports only what the adapter answered; not writable by pages |
| Replay of prior wallet approvals | every proof builds a fresh statement/transaction through the wallet's own lock; the gate's burnt-nonce rule refuses reuse (engine-tested) |
| Key-path / script-path confusion | template refuses script-path inputs/outputs (engine-tested); the engine authorises every input before execution |
| Malformed statements at decode | `deny_unknown_fields` + the engine's decode refusal (engine-tested) |
| Counter/nonce changes on failed transactions | asserted `(0, false)` after every forgery in the adversarial suite |
| Funds lost on rejection paths | the attacker's input remains spendable after a refused forgery (adversarial suite) |
| Zero/maximum value edges | SDK refuses MVP > value at construction (existing test); u64 saturation in the counter is `saturating_add` (template) |

## Second-pass review (§11)

A separate adversarial pass over the candidate changes ran after the first pass, from a hostile
user's perspective, challenging the assumptions behind proof authenticity, resource ownership,
threshold correctness, wallet authorisation, challenge uniqueness, session issuance, browser
isolation, indexer trust, finality, and privileged backend operations. Findings raised and their
dispositions:

- **"The walletd proof spends the victim's whole holding — can the bridge be talked into
  over-spending?"** Checked: the bridge asks the wallet for `input_revealed = gate.threshold`
  against the wallet's own listed outputs; the daemon refuses a promise above the output's value;
  the output returns to the prover's own account. No over-spend parameter exists on the surface.
  No finding.
- **"Can a second challenge be answered by the first proof's receipt?"** Checked: receipts bind the
  nonce, which is burnt on acceptance; a replay refuses at the gate (engine-tested). No finding.
- **"Can the Host allowlist be bypassed with an IP-literal Host?"** Checked: the permitted set is
  the loopback literals themselves; any other literal (e.g. the machine's LAN IP) refuses. No
  finding. (A page on the victim's own LAN IP origin would need to *reach* that IP — the listener
  binds loopback only.)
- **"Does `prune_expired` on insert let an attacker keep exactly 255 live challenges forever?"**
  Yes — that is the cap working as designed: bounded state, not bounded rate. Documented as
  intended behaviour; the 429 names the remedy.
- **"Is the credential mode's fail-closed `verified` check a hidden availability regression for the
  game?"** Checked: the game's demo mode and consensus mode do not depend on it; the credential mode
  is explicitly optional (no `GG_INDEXER_ENDPOINT` → route answers 503 with the reason). No finding.
- **"Can preview mode in the game be mistaken for a real unlock?"** Design requirement, addressed
  during game construction (labels, no challenge/proof route calls, no receipts minted) — tracked in
  the release gate.

One genuinely new MEDIUM finding emerged from the second pass and is fixed in the same commit that
records it — see **F-09** below.

## F-09 — Session commitments are not bound to the *challenger* — **MEDIUM, FIXED**

- **Component**: `ghost-gate-bridge/src/server.rs` (`issue_challenge`, `prove`, `credential`).
- **Attacker capabilities**: two permitted origins (or two tabs) controlled by the same person —
  more precisely, any party able to read a challenge response.
- **Reproduction**: origin A mints challenge N with session S. Origin B mints nothing, but submits
  `{gate_id, challenge_nonce: N, session_commitment: S}` to `prove`. The gate's session check
  compares the *challenge's* stored session against the *submitted* value — both are S, so it
  passes. The session field, presented to users as "bound to that browser session", is in fact
  bearer knowledge: whoever can read one challenge response can answer from anywhere.
- **Expected**: a proof must be provable only by the party the challenge was issued to.
- **Observed**: any reader of the response can complete the proof.
- **Impact**: limited on its own (whoever completes the proof *spends their own* qualifying output
  to mint the attestation — the attacker cannot steal funds), but the attestation is then a valid
  session credential for a party the challenge was never issued to; combined with a shared link or
  a referer leak it mints real, server-side sessions for the wrong party.
- **Remediation**: the session commitment is generated per challenge **and checked against the
  transport peer** — the bridge records the binding it observed when the challenge was issued, and
  a proof whose Origin differs from the issuing Origin is refused with `SessionMismatch`. Callers
  with no Origin (operator curl) keep the old behaviour, explicitly documented as operator-only.
- **Test**: `a_proof_from_a_different_origin_than_the_challenge_is_refused`; the CLI path asserted
  unchanged.
- **Note**: this is a *modelling* fix that tightens an assumption the design doc already claimed
  ("bound to that browser session"); the gate's on-chain rules were never affected.
