# Ghost Gate — Gaming PC migration handoff

This document is for a fresh OpenCode session continuing on a faster gaming PC. It is a snapshot of the repository as inspected on 2026-11-23. It contains no credentials, wallet secrets, HMAC values, API keys, or production configuration.

## 1. Git state

- Repository path used for this handoff: `C:\Users\pdark\Documents\Codex\ghost-gate-laptop`
- Branch: `main`
- HEAD: `b1ea62a926344271d4f3a728fb319342e67040e2` (`b1ea62a`)
- Latest commits:
  - `b1ea62a` `feat(m15): bind verified mainnet evidence to gate policy`
  - `fe10a64` `feat(m14): verify real mainnet TARI output state`
  - `c82fbeb` `feat(m13): add isolated mainnet verified-evidence prototype`
  - `e71f7fd` `docs(mainnet): record consensus verification blocker and pin TARI resource`
  - `230613f` `feat(mainnet): harden Telegram admission and deployment rollback`
  - `cd57436` `feat(ggbp1): add non-authorizing GGBP-1 v3 test gate and lab flow`
  - `5c56e39` `feat(m12): wire verified Sapient credential into Telegram session-backed admission`
- No Git remotes are configured.
- No Git submodules are configured.
- Known worktree: `/tmp/gg-baseline` at `1a0b282`, detached and prunable.

Untracked/preserved files at handoff time (do not delete or discard):

- `docs/OCTOBER_CONTEST_FINAL_CHECKLIST.md`
- `docs/WEB_UNIVERSE_DAPP_FAILURE_INVESTIGATION.md`
- `scripts/deploy-staging-worker.ps1`
- `scripts/start-telegram-live.ps1`
- `scripts/start-m16-real-wallet-test.ps1` — M16 fixture helper (has a known launch bug; see §4)
- `tools/m16-fixture-bridge/` — standalone M16 fixture bridge crate
- `docs/HANDOFF_GAMING_PC.md` and `docs/NEXT_PROMPT_GAMING_PC.md` — these handoff documents

No tracked production files are modified at this snapshot. Do not commit unless explicitly instructed.

## 2. Repository architecture and layout

Top-level:

- `crates/` — Rust workspace:
  - `ghost-gate-core` — policy, challenges, thresholds, XTM types; no crypto deps.
  - `ghost-gate-bridge` — HTTP bridge, challenge book, replay, access plane, credential verifier, bot-session routes, GGBP-1 test routes.
  - `ghost-gate-registry` — authoritative policy/session store and sanitized public-policy snapshot.
  - `ghost-gate-admin` — private administrator control plane.
  - `ghost-gate-telegram` — Telegram bot/session redemption service.
  - `ghost-gate-walletd` — walletd channel and main bridge/telegram binaries.
  - `ghost-gate-verifier`, `ghost-gate-wallet`, `ghost-gate-cbor`, `ghost-gate-minotari`, `ghost-gate-tests`, `ghost-gate-ggbp1`, `ghost-gate-ggbp1-spike`.
- `web/` — static frontends: Privacy Lab, mainnet preview, Telegram join/claim pages.
- `cloudflare/` — Worker, Durable Object replay coordinator, wrangler templates, browser tests.
- `deploy/` — VPS/systemd/tunnel/backup/restore scripts.
- `templates/ghost_gate` — on-chain template; separate wasm workspace.
- `tools/` — isolated verifier prototypes:
  - `ghost-gate-v047-verifier` — v0.47 checkpoint verifier.
  - `m13-mainnet-verifier` — v0.55.0 mainnet evidence verifier + M15 adapter.
  - `m16-fixture-bridge` — standalone M16 real-indexer bridge for the Sapient session test.
- `docs/` — extensive milestone, security, and operational docs.
- `scripts/` — build/test/dev/deployment helpers.

Workspace pins to patched Tari Ootle v0.42.0 sibling source at `../_ootle-v042-ghost-gate`. `templates/ghost_gate` is excluded from the native workspace.

## 3. Milestones completed (M11–M15)

### M11 — real Sapient ownership proof (credential-only)
- A real Sapient wallet signed an Esmeralda ownership proof through the local Lab.
- The verifier checked threshold, unspent state, on-chain auth key, frozen flag, and network/resource binding.
- Outcome was `PROOF VERIFIED — SESSION NOT ISSUED` because the bridge was not registry-backed.
- Exact output was not always recorded; a known 10 tTARI output from the physical test is `5ad3313f…b7fc5be8c6f` with promise `10_000_000`, which does **not** meet the 100 tTARI Crypt gate.

### M12 — session-backed Telegram architecture
- Implemented `TelegramProofContext`, HMAC bot sessions, durable SQLite authorization, simulated Telegram API, and `/claim {bot_session_id}`.
- Process-level M8/M12 negative tests pass; no real session-bound Sapient proof was completed.
- Legacy unbound claim remained compiled but fail-closed in production until M15.

### M13 — mainnet signed checkpoint verifier
- Isolated v0.55.0 verifier in `tools/m13-mainnet-verifier`.
- Release-derived anchor at epoch `38362`, 7 validators, hash `a434332a6f312f9d278fa614ed4f32cbe22cf6c08b17b58941bce832d3788e6a`.
- Verified ~912 signed handovers to current mainnet epoch and a real public substate inclusion proof.
- Never authorizes.

### M14 — real mainnet TARI output evidence
- Extended M13 to verify a real current-Up native TARI stealth output:
  - promise `11_000_000 µTARI` (11 TARI), unfrozen, key-path, fresh authenticated anchor.
- Refuses a known spent output because indexers supplied only exclusion-only Down evidence, no authenticated down proof.

### M15 — verified-evidence adapter and Telegram hardening
- Added `tools/m13-mainnet-verifier/src/bin/adapter.rs`:
  - non-authorizing;
  - binds resource, output, promise, frozen, epoch, commitment, network, gate, policy hash, challenge, relying origin, Telegram scope;
  - refuses the 11 TARI output against a 100 TARI gate;
  - refuses Esmeralda policy hash on mainnet;
  - always sets `authorized:false` and `session:null`.
- Hard-disabled legacy unbound `/claim {token, proof_id}` at the HTTP boundary.
- Published sanitized `public-policy.json` from admin so the public bridge no longer needs admin credentials/sessions; deployment permission changes were prepared but not applied.
- Added explicit mainnet policy audit: no authoritative mainnet Crypt registry binding exists in the repo; `13af3169…680b74f` is Esmeralda staging, not mainnet.

## 4. Actual M16 progress

M16 objective: first REAL Sapient session-bound ownership proof on Esmeralda with a simulated Telegram approval.

Current state:

- No real Sapient session-bound proof has been completed in M16.
- No wallet approval has been requested.
- No services are currently running after the PC restart.
- Built test artifacts:
  - `D:\pb-target\debug\m16-fixture-bridge.exe`
  - `D:\pb-target\debug\ghost-gate-telegram.exe`
- Added `tools/m16-fixture-bridge` — standalone bridge using `ghost-gate-bridge` plus a real Esmeralda indexer chain reader; avoids the Minotari/RandomX dependency graph.
- Added `scripts/start-m16-real-wallet-test.ps1` to start fixture services and generate fresh sessions on demand.
- Known blocker in helper: `Start-Process -ArgumentList @()` fails under Windows PowerShell 5.1 with an empty argument list. Fix by omitting `-ArgumentList` when the collection is empty or passing `@('')`. Do this before running `-StartServices`.
- No real browser session has been tested for the GGBP-1 cross-layer flow (see §6).

Do not claim M16 end-to-end success until the user personally approves the wallet signature and the bridge verifies the real response.

## 5. M13/M14 isolated v0.55.0 verifier

Location: `tools/m13-mainnet-verifier`

- Standalone `[workspace]` crate; does not alter the main workspace dependency graph.
- Path dependencies point to `C:\Users\pdark\Documents\Codex\tari-ootle-v0.55.0-source` (outside the repo). This path must be recreated after migration.
- Binaries:
  - `anchor` — recomputes the release-derived validator-set hash.
  - `verify` — walks checkpoints and verifies a public substate.
  - `output` — verifies a real TARI output and emits evidence JSON.
  - `adapter` — non-authorizing policy binder.
- Example policy: `tools/m13-mainnet-verifier/mainnet-policy.example.json` (illustrative only).
- Build/test commands:
  ```powershell
  $env:CARGO_TARGET_DIR='D:\pb-target\m13'
  cargo run --manifest-path 'tools\m13-mainnet-verifier\Cargo.toml' --bin anchor -j 1
  cargo run --manifest-path 'tools\m13-mainnet-verifier\Cargo.toml' --bin verify -j 1
  cargo run --manifest-path 'tools\m13-mainnet-verifier\Cargo.toml' --bin output -j 1
  cargo test --manifest-path 'tools\m13-mainnet-verifier\Cargo.toml' --bin adapter -j 1
  ```

## 6. GGBP-1 L1 tXTM in Tari Universe embedded dApp

Source and deployed build were inspected read-only:

- Current upstream repo: `chironbuilds/tari-l1-wallet-ui`, branch `master`.
- `src/components/DappFrame.tsx` handles:
  - `tari_getBalanceProofSubject`
  - `tari_requestBalanceProof`
  - capability reporting via `ggbp1Capability(s.network, canSpend)`
  - per-origin subject key, genesis hash, origin hash, 223-byte challenge validation
  - preview of disclosed outputs, linkability notice, foreground-tab check, rate limits, output leases.
- `src/lib/ggbp1.ts` reports `{protocolVersion:3, network:'esmeralda', maxOutputs:16, maxProofBytes:8192}` only for Esmeralda and spend-capable wallets.
- `tari_getNetwork` returns the **Ootle L2** network from `ootleNetworkFor(s.network)`; GGBP1 subject returns the **L1** network and genesis hash.
- Deployed bundle `https://universe.tari.mw/assets/App-DZdsNCHq.js` contains matching GGBP-1 strings, so the deployed build includes the implementation.
- Not verified in a real embedded browser session:
  - actual `ggbp1BalanceProof` value from the user's wallet;
  - cross-screen navigation between L1 wallet screen and Ootle Apps;
  - whether the iframe connection resets;
  - real challenge signing and GGBP1R response.
- Keep this separate from M16 Sapient L2 session-bound testing.

## 7. Telegram H-01/H-02/H-03 status

- H-01 legacy `/claim {token, proof_id}`: **hard-disabled** at HTTP boundary in M15. Tests updated and passing.
- H-02 durable/restart-safe state: partial.
  - Sessions and pending approvals are durable; SQLite single-use redemption and replay protection pass.
  - Still open: in-memory grants, update offset persistence, `chat_member` reconciliation, and full membership recovery.
- H-03 admin data isolation: code-level fix in M15.
  - Admin publishes `public-policy.json`; bridge `AccessPlane` prefers it.
  - A compatibility fallback to `registry.json` remains with a loud warning.
  - `registry.json` save path sets `0600` on Unix; deployment scripts were updated but not applied.
  - Rotate admin sessions and remove the fallback only after reviewing the migration.
- No live Telegram group or bot process was touched.

## 8. Crypt policy, network separation, blockers

- Esmeralda Crypt gate:
  - network `0x26`
  - native TARI resource `resource_0101…0101`
  - threshold `100_000_000` raw = 100 tTARI
  - divisibility 6
  - staging policy hash `13af3169…680b74f`
  - relying origin is configured server-side (local dev uses `http://127.0.0.1:7799`; hosted uses `https://ghostgate.boo`).
- Mainnet:
  - network `0x00`
  - resource same native TARI address
  - no authoritative mainnet registry binding or policy hash in the repository.
- Blocker: mainnet and Esmeralda policy identities must never be confused. Adapter refuses Esmeralda hash on mainnet and vice versa.
- Production blockers:
  - no real Sapient session-bound proof yet;
  - no authoritative mainnet gate policy;
  - no authenticated down/liveness strategy for public indexers;
  - no base-layer epoch cross-check;
  - H-02 incomplete;
  - production trust-tier boundary remains unchanged.

## 9. Tests passing and tests needed

Passing in this session/previous verified state:

- Bridge: **213 passed**
- Telegram: **41 passed**
- Admin: **33 integration + 4 lib + 1 main passed**
- Registry: **26 passed**
- Browser provider suite: **31 passed**
- Worker suite: **86 passed, 1 intentionally skipped**
- GGBP-1 crate: **31 passed**
- M15 adapter unit test: **1 passed**
- M13 verifier and M14 output verifier runs passed against live mainnet indexers.

Still needed:

- Fix M16 helper `Start-Process -ArgumentList @()` bug.
- Real Sapient session-bound proof on Esmeralda, then optional non-spending mainnet ownership proof.
- Real embedded Universe GGBP-1 browser test with user approval.
- Authenticated Down/spent-output evidence strategy.
- Independent liveness/base-layer epoch anchor.
- H-02 completion and production deployment review.

Run focused tests with:
```powershell
$env:CARGO_TARGET_DIR='D:\pb-target'
cargo test -p ghost-gate-bridge --lib -j 1
cargo test -p ghost-gate-telegram --bin ghost-gate-telegram -j 1
cargo test -p ghost-gate-registry -p ghost-gate-admin -j 1
npm test --prefix cloudflare
node --test web/js/ghost/test.js
```

## 10. Local services, ports, env vars

Ports seen in this project:

- `7799` — bridge/Lab (M12 fixture bridge and old demo bridge; know which binary you started)
- `7808` / `7809` — Telegram claim service variants
- `7789` — M12 fixture bridge in `test-m12-e2e.sh`
- `7811` — fixture Telegram server (also admin port in production templates; local-only conflict)
- `7899` — older live-test helper bridge
- `7443` — local HTTPS GGBP-1 proxy (stopped after restart)
- `18300`, `18142`, `5110` — indexer/walletd-related defaults in docs

Important env var names (values intentionally omitted):

- Bridge: `GG_BRIDGE_BIND`, `GG_BRIDGE_ORIGINS`, `GG_BRIDGE_RELYING_SITE`, `GG_BRIDGE_GATES`, `GG_INDEXER_ENDPOINT`, `GG_OOTLE_NETWORK`, `GG_GATE_THRESHOLD`, `GG_BOT_KEY`, `GG_BOT_AUTH_DB_DIR`, `GG_BOT_GATE_ID`, `GG_BOT_POLICY_HASH`, `GG_BOT_NETWORK`, `GG_BOT_RESOURCE`, `GG_BOT_THRESHOLD`, `GG_BOT_CHAT_ID`, `GG_BOT_SESSION_TTL_SECS`.
- Bot: `GG_TG_FIXTURE`, `GG_TG_API_URL`, `GG_TG_BOT_TOKEN`, `GG_TG_CHAT_ID`, `GG_TG_FIXTURE_TEST_CHAT_ID`, `GG_BOT_ESMERALDA_KEY`, `GG_BOT_ESMERALDA_BRIDGE`, `GG_BOT_ESMERALDA_GATE_ID`, `GG_BOT_ESMERALDA_POLICY_HASH`, `GG_BOT_SESSION_STORE_DIR`, `GG_JOIN_BASE_URL`, `GG_TG_CLAIM_PORT`, `GG_TG_GATE`.
- Mainnet guard: `GG_MAINNET_ADMISSIONS_ENABLED` must remain unset.

## 11. Exact build/restart commands for gaming PC

Initial setup (PowerShell from workspace root):

```powershell
$env:CARGO_TARGET_DIR='D:\pb-target'
rustc --version
cargo --version
node --version
python --version
```

Required sibling source (from repo parent):

```powershell
git clone https://github.com/tari-project/tari-ootle.git ..\_ootle-v042-ghost-gate
git -C ..\_ootle-v042-ghost-gate checkout a43773e600b9503ed3fadcd3f0048f86131e3644
git -C ..\_ootle-v042-ghost-gate apply "$PWD\docs\wallet-mvp.patch"
```

Focused bridge/telegram binaries:

```powershell
$env:CARGO_PROFILE_DEV_DEBUG='0'
cargo build -p ghost-gate-telegram --bin ghost-gate-telegram -j 1
cargo build --manifest-path 'tools\m16-fixture-bridge\Cargo.toml' -j 1
```

Full walletd binaries may hit RandomX MSVC CRT link issues in debug on a fresh Windows build. Use release mode if needed:
```powershell
$env:CARGO_TARGET_DIR='D:\pb-target\release'
cargo build --release -p ghost-gate-walletd --bin ghost-gate-bridge --bin gg-test-signer -j 1
```

M16 fixture helper:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\start-m16-real-wallet-test.ps1 -StartServices
powershell -ExecutionPolicy Bypass -File scripts\start-m16-real-wallet-test.ps1 -Status
powershell -ExecutionPolicy Bypass -File scripts\start-m16-real-wallet-test.ps1
```

OpenCode restart: close the old session, `cd` to the migrated repository, run `opencode`, then paste `docs/NEXT_PROMPT_GAMING_PC.md`.

## 12. Paths that need updating after migration

- Repo root path.
- `$env:CARGO_TARGET_DIR` (`D:\pb-target`, `D:\pb-target\m13`, `D:\pb-target\release`).
- `.cargo/config.toml` WSL target `/home/pdark/gg-ootle-target` if using WSL builds.
- Sibling cohort path `../_ootle-v042-ghost-gate`.
- `tools/m13-mainnet-verifier/Cargo.toml` v0.55 source path.
- `tools/ghost-gate-v047-verifier/Cargo.toml` `.tari-v047-reference` path.
- `tools/m16-fixture-bridge/src/main.rs` fallback temp auth DB path.
- `scripts/start-m16-real-wallet-test.ps1` absolute binary paths, Python path, state directory, fixture paths.
- Local HTTPS cert/key directory under Temp/opencode if GGBP-1 Lab is resumed.
- SSH key path for any operator runbook; do not copy the key.

## 13. External dependencies and files outside the repo

Required/recreate:

- Tari Ootle v0.42 cohort clone + `docs/wallet-mvp.patch`.
- Tari Ootle v0.55.0 source clone for M13/M14/M15 verifier.
- `.tari-v047-reference` is inside the repo but may not be committed; verify after import.
- Node modules under `cloudflare/node_modules` (`npm install` there if missing).
- Browser profile with Sapient extension and existing output history/localStorage; do not copy secrets.
- Local HTTPS cert/key files under Temp/opencode if GGBP-1 embedded testing resumes.
- WSL staging from `docs/GATE3_RESULTS.md` only if running full engine integration suites: protoc, libudev headers, Swagger UI cache.

Do not copy:

- `~/.ssh/ghostgate_vps` or any credential files.
- Any wallet seed, key, HMAC, bot token, API key, or production env file.

## 14. Safety status

- No deployment, no push, no live Telegram changes, no mainnet admissions, no wallet approval, no spending, no certificate-store changes.
- Fail-closed controls remain intact: production evidence tier unchanged, legacy claim disabled, admin state isolated in code, non-authorizing test gates only.
