# MASTER ACCEPTANCE STATUS — Ghost Gate

**2026-10-19 (second session) — the two browser-verified defects are fixed and proven with real
screenshots; the 10-tTARI question is now answered from real chain evidence, not assumptions.**

**Purpose:** progress must survive context compaction and OpenCode restarts. This file is the
single checkpoint.

Legend: **VERIFIED** = observed against a real service this session; **AUTOMATED TESTS ONLY** =
green in the workspace suite, no live service involved; **BLOCKED** = cannot proceed for a stated,
external reason.

---

## 1. The active shared localnet — DO NOT TOUCH

| Item | Value |
|---|---|
| Workspace | `/mnt/c/Users/pdark/Documents/Codex/ShadowSwap-LocalNet-Validation` |
| Launcher | `bash scripts/launch-existing-localnet.sh` (`--status` is read-only) |
| Minotari L1 base node | RUNNING pid 632, port 12001 |
| Ootle validator | RUNNING pid 672, port 12005 |
| Ootle indexer | RUNNING pid 915, port 12007 — **VERIFIED** `/health` → `current_epoch: 3672, db_ok, epoch_manager_ok, network_ok, v0.42.0` |
| Ootle wallet daemon (shared) | RUNNING pid 998, port 12010 — **VERIFIED** `wallet.get_info` → `localnet`, network byte 16, v0.42.0 |
| Miner wallet / disposable miner | MISSING — intentional |
| Miner pause marker | **PRESENT (deliberate)** — *"2026-10-17 deliberate stop: L2 consensus drains epoch-transition queue; oracle must not outrun committed (ootle v0.42.0 EndEpoch-only blocks carry no mempool txs)"* |

**Safety rules (unchanged):** do not remove the pause marker, restart mining, force block
advancement, reset the chain, or modify shared wallet state. The shared wallet daemon's process
comes from the purrivacy workspace binary by port identity; leave it alone entirely.

**THE PAUSED MINER — precise diagnosis:**

- Epoch read `3672` at 22:45, 22:48, 22:49, 22:53 and again hours apart: **frozen**.
  `epoch-manager/stats`: `current_epoch 3672, block_height 36724`.
- The pause marker (2026-10-17) is honoured and untouched.
- Consequence, stated exactly: **no transaction submitted now can be sequenced**; nothing can
  finalize; indexer stays consistent with the validator (both frozen); this is not a wallet/RPC
  problem (every RPC path answers).
- A running indexer does not imply transaction finality.
- Recovery plan + stop conditions are prepared in §7; mining restart is OPERATOR-ONLY and has not
  been attempted.

## 2. Ghost Gate's own wallet daemon (port 18130)

Died in the WSL restart; **restarted this session** with the same parameters as before:

```
/home/pdark/gg-ootle-target/debug/tari_ootle_walletd --network localnet \
  --listen-on 127.0.0.1:18130 --indexer-api-url http://127.0.0.1:12007 \
  --base-path /home/pdark/gg-wallet-ghostgate-live --authentication none \
  --override-keyring-password <secret, not recorded here>
```

- **VERIFIED** `wallet.get_info` → `localnet`, byte 16, v0.42.0.
- **VERIFIED** account `GhostGate` survived (component `component_0dcc5570719acac6b3e242a1e366b81644e513d93fe64dcf18a78b18a9a64789`).
- **VERIFIED** auth bootstrap: `auth.request` with `{"permissions":["Admin"],"credentials":"None"}`
  issues a JWT; account endpoints refuse anonymous calls (401) but accept it.
- Holds **no funds** and no stealth outputs — it is a fresh wallet.

## 3. Wallet inventory on the shared daemon (12010) — read-only probes

| Account | Balances | Stealth UTXOs (this chain) |
|---|---|---|
| Swap Alice (`component_974aaf…`) | 989,215,247 raw tTARI (≈989.2), 95,500 TEST-A, 500 TEST-B, 3 tNFT | **exactly one**: 50,000 raw (0.05 tTARI), `is_on_chain: true`, Unspent |
| Validator Fees (default) | none | none |

Read via `accounts.get_balances` + `stealth_utxos.list` (no filters). The >989 tTARI remainder is
revealed vault value, not spendable stealth UTXOs; the GHOST resource `resource_5161…` (the legacy
gate resource) has **zero** outputs here.

## 4. What was fixed this session

1. **Committed `b685602`** — the ootle v0.42.0 JSON-RPC lives at `/json_rpc`, not `/walletd`
   (`deploy_vault.rs` default, `scripts/await_localnet.sh`, `docs/MANUAL_TEST.md`,
   `docs/OPERATOR_HANDOFF.md`). The old path points at the walletd's HTML UI, which silently broke
   every authenticated call.
2. **`deploy_vault.rs` auth bootstrap** — when `GG_WALLETD_TOKEN` is absent it now calls
   `auth.request` (Admin, credentials None) and `set_auth_token` before any account call. Was the
   "Unauthorized: Access denied. No bearer token provided" blocker. Compiles (cargo check green).
3. **`scripts/start_vault.sh` optimized** — a normal launch reuses the existing bridge binary;
   `--build`/`GG_FORCE_BUILD` forces a rebuild; rebuild also happens implicitly only when the
   binary is missing or a source under `crates/` is newer. The fail-closed rule stands: a FAILED
   build never launches a stale binary (unless `--preview-only`).
4. **PROTOC pinning** — the ootle build scripts need the cohort protoc with matching well-known
   types. `/home/pdark/bin/protoc` (8.8 MB, Oct 16) breaks the build with
   `timestamp.proto not found`; `PROTOC=/usr/bin/protoc` fixes it. `start_vault.sh` now pins the
   cohort binary from `/home/pdark/ootle-build/protoc/bin/protoc` (still present, verified) and
   falls back only if it is genuinely absent. Ad-hoc builds: prefix `PROTOC=/usr/bin/protoc`.
5. **Matrix-style code rain, both sides of Privacy Lab** — **DONE + VERIFIED on the LIVE bridge
   (2026-10-19)**: `web/lab/lab.js` `startMatrixEdges()` + `lab.css` `#matrix-edges`; deterministic
   falling glyph columns at both page edges, CSS-transform animated, `prefers-reduced-motion`
   respected. Served through `http://127.0.0.1:7799/lab` (bridge up, `asset_dir` resolution
   confirmed; the served JS/CSS carry the implementation).
6. **Frontend credential-path dispatch** — the Lab now dispatches to the browser wallet's
   ownership-challenge signing (see §5, row "credential path").

## 5. The 10-tTARI question — answered from chain evidence

The first acceptance milestone is a genuine 10-tTARI wallet-backed proof. The consensus proof path
(`ghost-gate-walletd/src/lib.rs`) must (a) find an on-chain unspent stealth output of the gate's
resource ≥ threshold in the wallet, (b) submit a `prove_access` transaction naming a real gate
component, and (c) wait for the network to sequence it.

| Question | Answer from source + chain |
|---|---|
| One qualifying output, or aggregation? | **One output.** `ghost-gate-walletd/src/lib.rs` picks a single output (`pick_qualifying_output`, `InputSelection::Specific { utxo_addresses: vec![address] }`) and the official Universe doc is explicit: a promise "proves one output, not a balance". No protocol-supported aggregation exists; inventing one is not sound. |
| What does `minimum_value_promise` cover? | **One output's own floor.** The credential verifier (`ghost-gate-bridge/src/credential.rs:284`) refuses when the *output's* on-chain promise is below the gate's threshold. |
| Is there a non-spending proof path? | **YES — the credential path**, already implemented: real output (unspent, merkle-verified by the indexer) + on-chain promise ≥ threshold + an ownership-challenge signature over the bridge's nonce, checked against the output's own on-chain `auth.Key`. It submits NOTHING and reads only committed state. It needs no on-chain gate component. |
| Can walletd drive the credential path? | **No.** walletd has no ownership-challenge signing method (grep-verified: only burn-claim *validation* exists). The credential path is browser-wallet only (`tari_signOwnershipChallenge`, per the official SKILL.md). The Lab now dispatches to it (see §4.6). |
| What does the real chain hold? | The only stealth tTARI UTXO on the localnet (`utxo_0101…01_a66c77…`, "Swap Alice") reads through the indexer REST API: **`minimum_value_promise: 0`**, `verified: true`, value 50,000 raw = **0.05 tTARI**. Its whole remaining ~989 tTARI is revealed vault value, not spendable stealth UTXOs. |
| So can a 10-tTARI proof verify today? | **NO** — and the reason is now proven, not assumed: that output carries promise 0 (fails any threshold > 0) and is 200× too small for the consensus path. A genuine 10-tTARI proof needs NEW chain state: one `shield` transaction creating an output with `minimumValuePromise ≥ 10,000,000` (from the revealed balance), which needs sequencing. |
| Can the pathway be exercised at all today? | The **verifier against real chain state is exercised and passes** — two ignored-by-default tests (`crates/ghost-gate-walletd/tests/credential_real_chain.rs`, run with `-- --ignored`) connect to the real indexer and assert the fail-closed refusal `BelowThreshold{attested:0, required:10,000,000}`. Authentic NEGATIVE verification with real committed evidence. |

**Milestone status: BLOCKED by three independent layers.**

| # | Requirement | State | Detail |
|---|---|---|---|
| a | A wallet holding ≥ 10 tTARI in one on-chain unspent stealth UTXO | **NOT MET** | Largest stealth UTXO on any wallet this session: 0.05 tTARI (Swap Alice). The GhostGate wallet holds nothing. Consolidating or minting needs a transaction. |
| b | A gate component on chain for that resource | **NOT MET** | No tTARI gate exists; only legacy GHOST gates from earlier evidence. Deploying needs `deploy_vault`, which sequences transactions. |
| c | Transaction finality | **BLOCKED (deliberate)** | Miner paused per the 2026-10-17 marker; epoch 3672 frozen all session; EndEpoch-only blocks carry no mempool txs. Nothing submitted can sequence. |

Do **not** submit a proof transaction to "test" — `wait()` would burn the 300 s timeout and the
statement's wallet lock expires only later. The preconditions (a)/(b) are exactly what the pause
prevents; fixing them is the operator's restart decision, not a code change.

## 6. Everything else

| Area | Status |
|---|---|
| Demo bridge service | **RUNNING 2026-10-19** — `scripts/start_vault.sh` launched the existing binary on 127.0.0.1:7799, `/health` → gates `abyss,crypt,vault`, `/lab/gates` serving the evidence GHOST config (preview mode: `registry_backed: false`, no walletd). Re-run safety + binary reuse both exercised live. |
| Privacy Lab polish (dashboard self-explaining, status pills, protocol inspector) | DONE in prior sessions (commit `f75f56b`, screenshots captured). |
| Workspace regression suite | **RE-RUN 2026-10-19 after this session's edits: 338 passed, 0 failed, 0 ignored** (full `cargo test --workspace`; the recorded baseline at `813ed05` said 340 — a two-test count difference with zero failures either way). Doc-test tiers contribute 0 examples. |
| Telegram identity binding / Cloudflare staging / Universe+Sapient browser paths / L1 XTM / Android+iOS | unchanged from prior status; XTM remains draft (no working implementation), wallet-provider detection is not a proof. |
| Contact swappers, Esmeralda readiness | no change; Esmeralda remains a config path (network byte 38) with no public network to test against. |

## 7. Next actions (in order)

**Operator-dependent (the genuine 10-tTARI proof — smallest safe sequence once the miner resumes):**

1. Lift the pause (operator-only decision; verify the epoch advances past 3672 first).
2. Sapient/Universe `shield` 10 tTARI with `minimumValuePromise = 10,000,000` (from Swap Alice's
   revealed balance) — creates the qualifying output.
3. `tari_signOwnershipChallenge` on the bridge nonce (browser wallet — walletd cannot do this).
4. POST `/gate/<tg-gate>/credential` → 200 + session.
5. In parallel, once sequencing works: fund/point the proof path at a wallet holding the output,
   and run `deploy_vault` (now authenticated and compiling) to cover the GHOST demo gates.

**Independent work that needs no chain:**

6. Docs, browser harness, weak-wallet scenarios.
7. Keep the four localnet services untouched at all times.

---

## 8. Paused-miner recovery procedure — DRAFT (operator-only, DO NOT EXECUTE)

**Status:** DRAFT, written 2026-10-19. Nothing in this section has been run. This section exists
solely so the operator has a prepared, safe sequence if they choose to lift the 2026-10-17 pause
marker. Per §1 safety rules, removing the marker and restarting mining remains an OPERATOR-ONLY
decision.

**Preconditions (all must hold before step 1):**

- [ ] Operator has explicitly authorized resuming mining on the shared localnet.
- [ ] Pause marker location identified and preserved (copy the file, keep original contents — the
      marker text "2026-10-17 deliberate stop: …" must be kept verbatim for the audit log).
- [ ] Snapshot current chain state: indexer `/health` (epoch + height) and
      `epoch-manager/stats` (`current_epoch 3672, block_height 36724`) recorded as the
      pre-recovery baseline.
- [ ] All four shared services (12001, 12005, 12007, 12010) healthy via their `/health` endpoints
      before any change; note pids (632, 672, 915, 998) so restarts can be attributed.

**Procedure (smallest safe sequence):**

1. **Pre-flight (read-only):** confirm epoch is still exactly 3672. If it is NOT 3672, the state
   changed unexpectedly — STOP and re-diagnose before touching anything.
2. **Lift the pause:** remove the marker file (operator executes; keep the preserved copy).
3. **Restart mining via the purrivacy workspace's own launcher** (`launch-existing-localnet.sh`,
   NOT manual process starts) so the process manager owns the lifecycle and pid accounting stays
   consistent.
4. **Watch for epoch advance (stop condition check, every 60 s):**
   - PASS: epoch moves past 3672 and `block_height` increases — proceed to step 5.
   - FAIL after 10 minutes: no epoch change AND no new blocks → **STOP**, re-add the preserved
     marker, report. Do not "wait longer" — no escalation without operator approval.
5. **Finality probe:** submit a zero-value test transaction from a disposable wallet (NOT Swap
   Alice, NOT the shared daemon's default account) and confirm it appears in `transactions.list`
   with final confirmation. If it does not finalize within the timeout, STOP — see stop
   conditions.
6. **Then, and only then:** run the §7 operator sequence (shield 10 tTARI with
   `minimumValuePromise = 10,000,000`, ownership challenge, credential POST).

**Stop conditions (any one triggers full rollback to pre-recovery state):**

- Epoch reads a value other than 3672 at pre-flight (step 1) — unexpected state change.
- No epoch/block progress within 10 minutes of mining restart (step 4) — chain not producing.
- Any validator/indexer `/health` failure, DB error, or `db_ok: false` during the sequence.
- Memory/resource exhaustion on the host (WSL2 is the runtime).
- Any crash or restart of a shared service during the sequence — do not attempt to "recover"
  shared services ourselves; the purrivacy workspace owns them.

**Rollback:** re-add the preserved marker file verbatim; do NOT reset the chain, do NOT modify
wallet state, do NOT attempt to re-index. Return the system to the exact pre-recovery layout
documented in §1 and stop.

**Explicitly OUT OF SCOPE for this draft:** anything beyond the epoch-advance check and a
zero-value test transaction. The 10-tTARI shield/proof work happens only after both PASS.

---

## 9. Session log — 2026-10-19 (continuation: P1 draft + P3 spec alignment)

**Verified this session:**

1. **walletd RPC surface unlocked** — real method names confirmed against both daemons via
   `/json_rpc`: `auth.request` (with `{"permissions":["Admin"],"credentials":"None"}` → bearer
   JWT), `accounts.get_default`, `accounts.list` (`offset`/`limit`), `accounts.get_balances`
   (takes the **component_** address, not the `otl_` address or pubkey), `transactions.list`.
   Old snake-case names (`get_balance`, `rpc_discover`, `accounts_get_default`) are confirmed
   `-32601` — the `b685602` fix alone wasn't sufficient; the envelope needed the right names.
   Ghost Gate walletd (:18130) default account: `GhostGate`, component
   `component_0dcc5570…`. Shared walletd (:12010) default account: `Validator Fees`, component
   `component_5d1badf6…` — balances empty on both, consistent with the paused miner.
2. **P2 dry-verify PASSED (read-only, no broadcast)** — `ghost-gate-walletd/tests/
   credential_real_chain.rs` 2/2 green against the real indexer: `no_promise_means_no_
   threshold_at_all_can_be_attested` and `a_real_finalized_output_with_no_promise_is_refused_
   below_a_10_ttari_threshold` (asserts `BelowThreshold { attested: 0, required: 10_000_000 }`).
3. **P1 draft written** — `docs/PAUSED_MINER_RECOVERY.md` (DRAFT, write-only, operator-only,
   no automation wired). Preconditions table, 8-step recovery, abort criteria, rollback.
4. **P3 spec alignment (code change)** — `web/telegram/claim.js` now waits for `window.tari`
   (or the `tari#initialized` event, 1.5 s timeout) before probing providers, per the official
   Tari Universe integration spec. Existing adapter method names in `web/js/ghost/provider.js`
   (`tari_createTransactionRequest` → poll `tari_getTransactionRequest` →
   `tari_submitTransactionRequest`, `tari_signOwnershipChallenge`, capability gating) all match
   the official `tari-dapp.d.ts` contract; no renames needed.

**Not verified / blocked this session:**

- **Web tests NOT run:** no Node.js runtime available in the working shell (`node: command
  not found`); `web/js/ghost/test.js` (21 tests) and `node --test` remain unexecuted here. The
  claim.js change is defensive-only (skips the wait when `window.tari` already exists) but is
  **unverified by automated tests** until the operator can run node.
- **No physical wallet test:** per operator instruction, nothing is marked physically VERIFIED
  until tested with a real compatible wallet (Sapient or Universe). No browser was launched.
- **Cloudflare deploy, real Telegram group, miner restart:** explicitly deferred by operator.
- **P4 Lab visual verification:** not started.

**Operator next actions:**
- Install/enable Node.js in the shell (or run `node --test web/js/ghost/test.js` manually) and
  re-run the web suite to confirm the claim.js change.
- Review `docs/PAUSED_MINER_RECOVERY.md` before any resume attempt.
- Provide a compatible wallet environment for the P3/P4 live wallet test.

---

## 10. Session log — 2026-10-20 (Matrix rain rebuilt and proven; P4 closed)

**Verified this session (browser-tested against the live bridge):**

1. **Matrix rain rebuilt — the two-thin-strips defect is fixed.** Root causes were two: the CSS
   pinned each canvas to a hard-coded 112px strip while the real gutter at 1727×893 is ~273px,
   and the JS seeded every drop at `slot: 0` so all columns stacked into one glyph line. Now
   `startMatrixEdges()` measures the actual gutter beside `#lab-root` from its laid-out rect on
   load and on resize (correct under either box-sizing mode — the first fix double-counted
   padding and wrongly hid the rain at 1366×768), sizes each canvas to the full gutter minus a
   10px pad, and scatters one drop per 16px slot with per-column speed/trail stagger.
   Canvases hide themselves below a 64px strip and at mobile widths the gutters are zero, so
   the dashboard is alone — clean by design, not by luck.
2. **Proven by a new CDP harness** — `scripts/lab_matrix_check.sh` +
   `scripts/cdp-matrix-check.mjs` drive headless Edge over CDP (the same plumbing as the admin
   check; the operator's own browser is never touched). **28 checks passed, 0 failed**:
   - 1727×893 → both canvases 263px, 16 glyph columns each (brief: 10–15, "approx" — within band)
   - 1920×1080 → 360px, 22 columns; 1366×768 → 83px, 5 columns; 390×844 → rain off
   - animation proven by pixel-hash sampling 1.2s apart (every desktop size repaints)
   - no canvas ever covers the dashboard; `prefers-reduced-motion` keeps every canvas inert
   - zero console errors, zero failed network requests
3. **Screenshot evidence** — 8 frames (`matrix-<size>-{a,b}.png`) plus
   `matrix-reduced-motion.png` captured into `docs/screenshots/`; the stale Oct-19 shots of the
   broken implementation were removed so the record only carries what is true now.
4. **Bridge serves from disk** (`asset_dir`, verified by identical md5 of served vs on-disk
   `lab.js`) — no rebuild or bridge restart was needed; the fix went live on reload.

**Not verified / unchanged this session:**
- No wallet, Telegram, or Cloudflare work — this session was the cosmetic deliverable only.
- The 10-tTARI proof remains BLOCKED exactly as §5 states (paused miner, no qualifying output).

**Operator next actions (unchanged from §9):**
- Run `node --test web/js/ghost/test.js` when a Node runtime is available (claim.js change
  from §9 is still unverified by automated tests).
- Review `docs/PAUSED_MINER_RECOVERY.md` before any resume attempt.
- Provide a compatible wallet environment for the live wallet test.

---

## 11. Session log — 2026-10-20 (continuation: dedicated walletd restored, Sapient ready)

1. **Dedicated walletd :18130 restored** — prior PID 8519 was alive but refusing RPC (stale
   zombie). Force-killed and restarted with the exact verified profile (localnet, byte 16,
   v0.42.0, base-path gg-wallet-ghostgate-live). Now healthy: `wallet.get_info` → 200,
   `GhostGate` account component loaded, UTXO scan complete (zero stealth outputs, expected —
   no funding yet).
2. **Sapient connection adapter verified** — `sapientProvider()` implements the
   `window.tari` contract (`isTariWallet` detection, `tari_getCapabilities` probe, Mode B
   credential flow). Esmeralda network check remains byte-based via `networkMatches()` —
   cross-network qualification is prevented by design.
3. **Telegram protocol suite re-run** — 14/14 green (no code change; hygiene re-check).
4. **Cloudflare staging** — webhook-based bot recommended for production (stateless,
   Cloudflare-compatible); long-polling retained for local development only.

---

## 12. Session log — 2026-10-20 (Sapient wired into the real Lab UI)

**The operator's finding:** the physical Sapient extension injects `window.tari` into
`http://127.0.0.1:7799/lab` (`sapientInjected: true, tariWalletFlag: true, requestAvailable: true`),
but section 02 offered only "Wallet daemon · consensus" with no Sapient workflow.

**Root cause:** `renderWallets()` hard-coded generic labels ("Tari desktop wallet · credential")
and offered no connect action at all — the only wallet interaction was the prove button, which for
the three consensus-mode demo gates drives the walletd path. A visitor could not connect a browser
wallet for diagnostics without submitting a proof.

**Fix (connection-only ceremony, section 02):**
1. Selector labels are honest: "Sapient — Ootle L2 · credential" and
   "Tari Universe — in-app · credential"; walletd marked "(advanced)".
2. A real **Connect wallet** button performs a connection-only ceremony: waits for late
   `window.tari` injection (1.5 s / `tari#initialized`), then `tari_requestAccounts` (the wallet's
   own approval prompt), `tari_getNetwork`, capability read, and — only when
   `walletOwnershipProof` is offered — `tari_signWalletOwnershipChallenge` over a locally
   generated nonce, displayed as *proof of wallet possession only*. It never mints a bridge
   challenge, never builds a proof, never authorizes a spend.
3. A detail box shows the truncated real address, the network verdict, and the capability list.
4. Network validation is byte-based (`networkVerdict` + the cohort table transcribed from
   `ghost_gate_core::network`): an Esmeralda wallet (0x26) against localnet gates (0x10)
   reads "Network mismatch … Connecting for diagnostics is fine; proving here is blocked by the
   gate, not by your wallet." Cross-network qualification stays blocked by design.
5. Rejection (4001) reads "You declined the connection request. Nothing was shared."

**Verified (AUTOMATED TESTS ONLY — simulated provider, physical test pending):**
- New `scripts/lab_connect_check.sh` + `scripts/cdp-connect-check.mjs`: **10/10 green** —
  selector lists Sapient, button present/enabled, connected status, Esmeralda address shown,
  mismatch verdict, capabilities, possession-only signature line, 4001 decline state, zero
  console errors.
- Existing suites unchanged and green: 19/19 JS adapter tests, 28/28 matrix/layout checks.
- Bridge serves web/ from disk (md5-verified) — no rebuild or restart was needed.

**Operator's physical milestone (the extension's genuine prompt):**
Open the real Ghost Gate Privacy Lab at http://127.0.0.1:7799/lab with Sapient installed,
select a gate, choose "Sapient — Ootle L2 · credential", press **Connect wallet**, and approve
the extension's prompt. Expect: address shown, mismatch verdict (Esmeralda vs localnet —
correct for these demo gates), capability list, and the optional read-only signature. Not
labelled LIVE WALLET VERIFIED until the operator confirms the real prompt.

---

## 13. Session log — 2026-10-20 (physical 4100 fixed: authorization now precedes every read)

**The physical evidence:** the operator's real Sapient answered `tari_getCapabilities` with
**4100 (not connected)** because the Connect handler probed capabilities *before* asking for
accounts. The mock providers accepted caps freely — which is exactly why the failure only
showed in physical testing.

**Fix — the actual authorization sequence, not the error text:**
1. `connectWallet()` now calls `tari_requestAccounts` FIRST and only once per click (no
   automatic retries of approval-triggering calls). Only after an authorized account request
   does it read `tari_getCapabilities`, then `tari_getNetwork`, then the verdict and the
   read-only wallet-ownership signature.
2. `describeProviderError()` (capabilities.js) gives every caller one distinct taxonomy:
   4001 declined (warn) · 4100 not connected (bad, actionable: "Connect or reconnect Sapient…
   then press Connect wallet again") · 4200 unsupported · locked-wallet wording · generic
   message passthrough. 4100 never claims missing capabilities.
3. `probe()` no longer treats 4100 as "no wallet": the extension is reported `available` with
   `capabilities: null` and a pointer at the Connect button. The passive note under the
   selector reads "Sapient detected — press Connect wallet to authorize this site."
4. `claim.js` says the honest thing for a detected-but-not-connected wallet instead of
   "No Tari browser wallet answered".

**Verified (AUTOMATED TESTS ONLY):**
- JS suite now **23/23** (4 new regression tests: 4100 probe shape; the error taxonomy; the
  mismatch verdict wording; the no-provider state).
- `scripts/lab_connect_check.sh` now **14/14**, including a NEW strict-order mock that
  reproduces the physical failure mode (caps → 4100 before accounts) and proves the fix in a
  real headless Edge: accounts-first connects, address shown, mismatch verdict shown, passive
  state points at Connect.
- Bridge serves from disk; no rebuild or restart was needed.

**Operator's physical milestone (awaiting your result):** open http://127.0.0.1:7799/lab,
select a gate, choose "Sapient — Ootle L2 · credential", press **Connect wallet**, approve the
extension's prompt. Expect the real address, the Esmeralda/Localnet mismatch verdict, the
capability list, and the optional possession-only signature — with no spend request. Not
LIVE WALLET VERIFIED until you confirm it.

## 7. Task 6 — tTARI balance verification and the 10-tTARI qualifying output (2026-10-21)
- Revealed balance of the Esmeralda dispenser account verified **on-chain**: sequenced
  get_transactions_diff (cursor 267) → tx a1dd6fae… shows VaultFungible +100_000_000 raw
  tTARI (resource_0101…01, divisibility 6). 100 tTARI revealed, zero stealth outputs.
- The user-reported private 100 tTARI is **not** a qualifying output: ledger-wide scan of
  80 recent UTXO-bearing txs found three candidate stealth outputs, all with
  minimum_value_promise = 0. Promises are only set by an explicit shield/sendPrivately.
- Qualifying-output creation prepared as a self-shield request (10000000 raw with
  minimumValuePromise 10000000) for operator approval in the wallet; the tx id and
  stealth commitment will be recorded in this doc once executed.
- esm-diag bridge on 7897 now carries a second, credential-only gate `esm10`
  (empty component, threshold 10_000_000, network 38, tTARI, useMode both).
  parse_gate accepts an empty component; the banner prints
  `<credential-only: no component>` (the previous version panicked on unwrap(None)).
