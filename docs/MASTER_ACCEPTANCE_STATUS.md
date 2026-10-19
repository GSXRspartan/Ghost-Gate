# MASTER ACCEPTANCE STATUS — Ghost Gate

**Purpose:** progress must survive context compaction and OpenCode restarts. This file is the
single checkpoint. Updated 2026-10-19 (session: post-WSL-restart resume).

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

**Chain state this session:** epoch read `3672` repeatedly across 15+ minutes (22:45–22:53 UTC)
with no movement → **no blocks are being produced**. This is the deliberate pause in effect, not a
failure. A running indexer does not imply transaction finality.

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
5. **Build dir** `/home/pdark/gg-ootle-target` reused throughout; no `cargo clean` anywhere.

## 5. The first acceptance milestone — a genuine 10-tTARI wallet-backed proof

**Status: BLOCKED by three independent layers.** The consensus proof path
(`ghost-gate-walletd/src/lib.rs`) must (a) find an on-chain unspent stealth output of the gate's
resource ≥ threshold in the wallet, (b) submit a `prove_access` transaction naming a real gate
component, and (c) wait for the network to sequence it.

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
| Matrix-style code rain, both sides of Privacy Lab | **DONE** — `web/lab/lab.js` `startMatrixEdges()` + `lab.css` `#matrix-edges`: deterministic falling glyph columns at both page edges, CSS-transform animated, `prefers-reduced-motion` respected. |
| Privacy Lab polish (dashboard self-explaining, status pills, protocol inspector) | DONE in prior sessions (commit `f75f56b`, screenshots captured). |
| Workspace regression suite | **RE-RUN 2026-10-19 after this session's edits: 338 passed, 0 failed, 0 ignored** (full `cargo test --workspace`; the recorded baseline at `813ed05` said 340 — a two-test count difference with zero failures either way). Doc-test tiers contribute 0 examples. |
| Telegram identity binding / Cloudflare staging / Universe+Sapient browser paths / L1 XTM / Android+iOS | unchanged from prior status; XTM remains draft (no working implementation), wallet-provider detection is not a proof. |
| Contact swappers, Esmeralda readiness | no change; Esmeralda remains a config path (network byte 38) with no public network to test against. |

## 7. Next actions (in order)

1. Finish the `deploy_vault` build; rebuild nothing else.
2. Re-run the workspace suite after this session's edits; record the count.
3. Commit: deploy_vault auth bootstrap + start_vault.sh optimization + this file.
4. Keep the four localnet services untouched. When the operator lifts the pause: verify the epoch
   advances, fund the GhostGate wallet (or point the bridge at Swap Alice's walletd), deploy the
   vault, then the genuine proof is the first acceptance run.
5. Independent work that needs no chain: docs, browser harness, weak-wallet scenarios.
