# Operator handoff — live integration phase status

*Written at the end of the live-integration session. Update the timestamps after each operator step.*

## 1. Git state

- Branch **`main`**, HEAD **`04e504c`** (fix: the walletd debug-binary clap bug, captured as a third verified patch) — actually `f364d13` after the flags doc; latest commits:
  - `04e504c` fix(cohort): walletd debug panic → `docs/walletd-cli-dup-short.patch` (3rd patch, provenance-covered)
  - `f364d13` docs: await_localnet.sh verified flags
  - `82b8ac7` feat: `deploy_vault` (one command → playable vault)
  - `91f9ed5` feat: `GG_WALLETD_TOKEN` auth support
  - `d2b0455` fix(telegram): claim-endpoint Host + media-type, token cap
- Tags: `gate3-green` (1a0b2824, untouched), `audit-baseline` (a9bb600).
- The working tree is clean. Nothing has been pushed.

## 2. Processes running right now (in WSL)

**Localnet binaries: ALL LINKED.** The atomic-swap session's release build finished —
`tari_indexer` (80M), `tari_ootle_walletd` (63M), `tari_validator_node` (74M), `minotari_node`
(85M), `minotari_console_wallet` (57M), `minotari_miner` (18M) all exist in the two release target
dirs, and no cargo build remains. The swarm daemon is running but has NOT started its instances —
no instance ports are listening yet, and starting them looks like a web-UI action (or the other
session's next step). Per the operator's rule the swarm is not to be modified, reset or stopped by
this session; the one missing step may be exactly the operator clicking *Start* in
<http://127.0.0.1:8080>.

| PID | What | Port | Notes |
|---|---|---|---|
| 83448 | **ghost-gate-bridge** (our binary) | **7799** | started by `start_vault.sh`; 3 game gates registered; NO wallet/indexer yet — proofs fail closed with an honest message |
| 89094 | tari_swarm_daemon (atomic-swap session) | **8080** | their localnet swarm — **do not stop/modify** |
| 89123/89141/123057/123058/… | their cargo release builds | — | building Minotari L1 + validator + indexer + walletd (hours) |
| 161694 | await_localnet.sh monitor | — | logging to `/home/pdark/gg-logs/await-localnet.log`; prints wiring when the network lands |

Our built binaries (all in `/home/pdark/gg-ootle-target/debug/`): `ghost-gate-bridge`, `ghost-gate-telegram`, `deploy_vault`, `tari_ootle_walletd` (post-CLI-fix, works), `tari_swarm_daemon`. Template WASM built: faucet 310,808 B, gate 310,210 B.

## 3. URLs to open on the gaming PC (Windows Chrome)

- **Game**: <http://127.0.0.1:7799/game> — works NOW in preview mode.
- Demo/API walkthrough: <http://127.0.0.1:7799/>
- Health: <http://127.0.0.1:7799/health> · Wallet status: <http://127.0.0.1:7799/wallet/status>
- Telegram join page (needs a live join link): <http://127.0.0.1:7799/telegram/join>
- Shared localnet's swarm UI: <http://127.0.0.1:8080>

## 4. Startup / shutdown

```bash
# START (build + bridge + optional bot)
scripts/start_vault.sh                          # bridge only (preview + real paths when wired)
GG_TG_BOT_TOKEN=<token> GG_TG_CHAT_ID=<id> scripts/start_vault.sh --with-telegram

# STOP
kill $(ss -ltnp | awk '/:7799 /{sub(".*pid=","");sub(",.*","");print}')   # bridge
kill $(ss -ltnp | awk '/:7810 /{sub(".*pid=","");sub(",.*","");print}')   # telegram bot (if running)

# BUILD the game's template WASM (already done; re-run after template edits)
scripts/build_templates.sh
```

The pinned toolchain/protoc/native-deps exports are inside the scripts — no manual environment setup.

## 5. walletd status and network

- **Not yet running.** Ghost Gate's own MVP-patched walletd is BUILT and starts cleanly
  (`--version` → `tari_ootle_walletd 0.42.0`; the clap `-l` collision that panicked the debug build
  is fixed and captured as the third patch). It has nothing to connect to yet: it needs the shared
  localnet's indexer URL.
- Planned invocation (in `await_localnet.sh`'s output once ports exist):
  `tari_ootle_walletd --network localnet --listen-on 127.0.0.1:18130 --indexer-api-url http://127.0.0.1:<indexer> --base-path /home/pdark/gg-wallet-ghostgate [--authentication none for the fixture run]`
- The atomic-swap session's own walletd (their swarm instance) is **unpatched** — it cannot build
  MVP-bearing statements; Ghost Gate's consensus path uses OUR walletd.

## 6. Browser / wallet integration results

| Integration | Status |
|---|---|
| Local walletd (consensus mode) | **IMPLEMENTED + ENGINE-VERIFIED** (localnet scenario 2/48 green; adapter 4 tests; NOT yet driven live against the standing network) |
| Sapient (credential mode) | **IMPLEMENTED, NOT LIVE-TESTED** — capability-driven adapter against the pinned contract; requires the extension in Windows Chrome |
| Tari Universe Web (credential mode) | **IMPLEMENTED, NOT LIVE-TESTED** — must be opened from its app catalogue (iframe-only provider) |
| Fake/mocked provider responses | Tested (21 web tests incl. 4001/4200/no-substateId paths) — mocks never substitute for a live wallet claim |
| Native L1 XTM | **BLOCKED** upstream (no L1 dApp surface; node-identity-only gRPC signing) — experimental label everywhere |

## 7. Manual tests actually completed (by me, in this environment)

- Bridge HTTP surface live-verified: all game/assets routes + content types; unknown-field refusal; origin refusal; **rebinding-host 403**; **text/plain claim 415**; credential route honest failures; challenge stays live after failures.
- Telegram fixture lifecycle live-verified: grant → replay-refused → `[fixture]` messages recorded.
- All automated suites green (counts in §11).
- **Everything requiring a browser, a wallet, or Telegram was NOT performed by me** — see §8.

## 8. Tests that require YOUR interaction (in order)

1. **Preview walk-through now** (no wallet needed): open <http://127.0.0.1:7799/game> → "Preview
   without a wallet" → all three chambers, three puzzles, three whispers, animations; check the
   PREVIEW banner; DevTools Network tab must show no `/gate/*/challenge|prove|credential` calls
   during preview; reload re-seals everything.
2. **When the shared localnet is up** (monitor says so): start our walletd per §5 →
   `deploy_vault` (prints the bridge config line) → restart the bridge with it → play The Crypt
   for real (click Break the Seal; approve in the wallet UI if configured to require it).
3. **Sapient**: install in Windows Chrome from the release page, fund a local account from the
   faucet/demo wallet, then the game's credential path; then `docs/MANUAL_TEST.md`'s six cases.
4. **Tari Universe Web**: open the game URL from *inside* Universe's app catalogue; same flow.
5. **Telegram**: create the bot via @BotFather → `GG_TG_BOT_TOKEN=… GG_TG_CHAT_ID=…
   scripts/start_vault.sh --with-telegram` → `/join` from your account → approve twice →
   invite lands; wait out the TTL to watch revocation + re-verification.
6. **iOS**: requires Xcode/an iPhone — documented as operator-required; not claimed complete.

## 9. Telegram bot readiness

- Bot logic, grant lifecycle, revocation, replay idempotence: **implemented + unit + live-fixture verified** (10 tests).
- Join page served by the bridge (same origin as the credential flow it runs).
- Awaiting: a real bot token + chat id, then `--with-telegram`. The bot never asks for seeds/keys/balances; the join message states that in its own words.
- Privacy tradeoff (documented): Telegram learns which account joins; Ghost Gate never reveals a balance — the gate learns a public floor only.

## 10. Known security / functionality issues

- **Unresolved vulnerabilities: none open.** All confirmed findings are fixed with regressions (see `docs/SECURITY_FINDINGS.md`).
- Shared-network residual: the atomic-swap validators lack our GHSA-pp4v-v773-9qxg backport (their tree, cannot patch). No Ghost Gate proof path depends on Proof-possession rules; documented in `docs/SECURITY_AUDIT_FULL.md` §7b.
- Upstream GHSA-rr6w-w4r5-9fcx (account bricking via dust deposits) affects the pinned cohort — availability DoS only; release-gate re-pin procedure documented.
- Template `set_open` is allow-all (availability griefing; template frozen) — F-13.
- The gate components on the shared localnet will be owned by OUR wallet's account; `set_open` griefing by anyone on the localnet is possible but recoverable (re-deploy).

## 11. Test counts (current)

| Suite | Count |
|---|---|
| Workspace (Rust) | **219** — bridge 91, core 20, telegram 10, adversarial 11, cross_resource 16, gate_engine 30, mvp_and_shape 18, verifier 17, wallet 14, walletd 4 (+doc-tests 0) |
| Web (node --test) | **21** |
| Engine `access_rules` (GHSA backport included) | **48** |
| `verify_patches.sh` | ALL CHECKS PASSED (13 files, 3 patches) |
| `check_gate3_integration.sh` | ALL CHECKS PASSED |
| Localnet `@ghost_gate` scenario | 2 scenarios / 48 steps (recorded evidence + final confirmation run) |

## 12. Contest packaging status

- `docs/CONTEST_README.md` — submission-ready honest feature map (working/blocked with evidence).
- `docs/DEMO_GUIDE.md` — 10-shot screenshot set + 4-minute video storyboard + presentation notes.
- `docs/PROVIDER_COMPATIBILITY.md` — the universal-wallet matrix + upstream proposals.
- One-command startup: `scripts/start_vault.sh` (+ `--with-telegram`); `deploy_vault` makes a fresh network playable.
- **Not done**: screenshots not captured (needs the browser), video not recorded, nothing published/submitted — **operator approval required before any public action**.

## 13. Exact next operator steps (the short path to playing)

1. (Now) Open <http://127.0.0.1:7799/game> and run the preview walk-through (§8.1).
2. (When the monitor log announces the localnet) Start our walletd (§5), then:
   `GG_WALLETD_ENDPOINT=http://127.0.0.1:18130/walletd GG_WALLETD_TOKEN=<key> deploy_vault` (it prints the bridge line),
   restart the bridge with that line + `GG_INDEXER_ENDPOINT=<their indexer>`,
   then play The Crypt for real and attempt the full manual six-case flow (`docs/MANUAL_TEST.md`).
3. (Any time) Install Sapient → the credential-mode cases; create the Telegram bot → `--with-telegram`.
4. Before any public contest submission: say the word — nothing has been published, pushed, or broadcast.
