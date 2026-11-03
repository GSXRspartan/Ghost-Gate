# Esmeralda 0.49.2 bootstrap execution plan

Stage 3A, 2026-11-02. Planning only: no build, reset, signing, transaction, publication, service change, deployment, or commit was performed. Stage 2 changes remain in the worktree. Read with `OOTLE_0492_MIGRATION_AUDIT.md` and `OOTLE_0492_IMPLEMENTATION.md`.

## Execution decision and evidence

**BLOCKED for blockchain execution.** The plan is complete enough to prepare Stage 3B, but required Rust engine/adversarial/cross-resource and service tests have not passed; deployed inventory, current chain identity/readiness, and actual browser wallet compatibility remain unverified. No guessed genesis hash, deployed address, or fee is an execution input.

Authority is official `tari-project/tari-ootle` tag `v0.49.2`, commit `aa7b0c81719e5c3cfaf9bf3b5fb87bd83180cb90`, in the sibling checkout `../tari-ootle-v0.49.2-reference`. Build source is the separate sibling `_ootle-v0492-ghost-gate` plus `docs/wallet-mvp-0492.patch`. Preserve the reference unchanged.

Source-confirmed facts:

- `crates/ootle_network/src/lib.rs` assigns Esmeralda **0x26 = 38**. Network 38 alone does not distinguish resets.
- Official wallet defaults are `https://esme-indexer-a.ootle.tari.com/` and `https://esme-indexer-b.ootle.tari.com/` (`applications/tari_walletd/src/config.rs`, test `esmeralda_defaults_to_both_tari_indexers`). These are configured endpoints, not demonstrated healthy endpoints. This stage's web reads of both `/health` URLs were inaccessible; Stage 1 previously received 403. Neither establishes a network outage or readiness.
- Exact-tag `applications/tari_ootle_app_utilities/config_presets/f_epoch_oracle.toml` selects Hybrid for Esmeralda, base node `https://grpc.esmeralda.tari.com`, birthday height 669506, configured epoch time 1200 and base time `2026-02-23T13:08:42+0000`. These values are not a current genesis hash or authenticated checkpoint.
- Crypt credential mode needs native TARI outputs and off-chain registry/service state. It needs **no GhostGate on-chain component**, custom faucet, admin badge, or on-chain registry.
- `MARK` in `crates/ghost-gate-core/src/lib.rs` is **`GG`**. Mode A's typed receipt is the `receipt` payload of that event. The Stage 2 document's `ghost_gate.proof` wording is inaccurate; the runtime uses `MARK`. Credential mode does not emit this template event.

Official source references: [network](https://github.com/tari-project/tari-ootle/blob/v0.49.2/crates/ootle_network/src/lib.rs), [wallet config](https://github.com/tari-project/tari-ootle/blob/v0.49.2/applications/tari_walletd/src/config.rs), [epoch preset](https://github.com/tari-project/tari-ootle/blob/v0.49.2/applications/tari_ootle_app_utilities/config_presets/f_epoch_oracle.toml), [indexer status handlers](https://github.com/tari-project/tari-ootle/blob/v0.49.2/applications/tari_indexer/src/rest_api/handlers/misc.rs). Findings above were read from the local exact-tag reference; web retrieval did not independently confirm live state.

## Phase 0 — prepare a reproducible release and execution manifest

Run on Linux with enough disk, using the exact sibling source layout. Do not repeat the known Windows Cranelift/PDB failures. Record toolchain, source commit, worktree diff digest, patch digest, all lockfile digests, test results, and artifact digests. No deployment credentials belong in CI.

```text
git -C ../tari-ootle-v0.49.2-reference rev-parse HEAD
git -C ../tari-ootle-v0.49.2-reference status --short
git -C ../tari-ootle-v0.49.2-reference apply --recount --check -p1 ../ghost-gate-public/docs/wallet-mvp-0492.patch
cargo check --workspace --locked
cargo test --workspace --locked
cargo test --manifest-path ../_ootle-v0492-ghost-gate/Cargo.toml -p tari_ootle_wallet_sdk minimum_value_promise
node --test web/js/ghost/test.js
npm --prefix cloudflare test
```

The upstream test filter is a starting point: verify it executes the intended patch tests, rather than accepting zero matched tests. Test changed receipt and CBOR paths with current captures. Run the skipped Worker/Rust integration scenario with its documented local verifier setup. Do not run ignored live tests against their old addresses. Build patched walletd as well as the SDK; SDK compilation alone does not prove the daemon patch.

Prepare an untracked, access-controlled execution manifest with: environment ID, generation, genesis provenance, network/sidechain, endpoint versions/status, app ID and exact-case gate ID, owner credential ID, existing policy version/hash/hash-format, fee account public address, artifact hashes, transaction intent IDs, transaction IDs and outcomes, created addresses and publication receipts. Leave unresolved fields explicitly unset. The repository has no complete live deployment manifest; it cannot supply private VPS paths or current registry values.

Stop before mutations if any mandatory tests fail, a source/patch differs, identity is unresolved, or a wallet/provider cannot prove the needed capabilities.

## Phase 1 — preserve state and establish a reset boundary

During separately authorized execution, hold issuance/admission in maintenance and take consistent protected backups before changing state. Resolve actual base paths, process owners and configured files first. Prefer a new generation-specific Ootle data directory over deleting old directories. Never recursively remove a broad user, repo, or service directory.

| State | Required handling |
|---|---|
| Ootle walletd `<base_path>/data/wallet.sqlite`, WAL/SHM companions | Archive consistently after stopping owned daemon; start fresh target database. Do not restore old transactions, outputs, scan positions, locks or account-state cache into the new network. Preserve key recovery material separately before retirement. |
| Wallet seed/keychain/encrypted identity backups | Preserve securely. Recommended bootstrap uses a separate newly generated testnet wallet/profile, making old pending transactions and derivation state unambiguous. Existing identity may instead be recovered into a fresh target wallet with the supported recovery flow if continuity is required; rederive/rescan using target view-key rules and recreate account state. No old balance survives. Do not extract/copy SQL key rows or reset browser wallets wholesale. |
| Owned indexer data directory | Fresh generation-specific store. Exact-tag default relative directory is `data/indexer`; paths include `state.db`, `global_storage.sqlite`, companions, and cached consensus state. Archive old directory as historical. Review explicit consensus overrides rather than copying `consensus_constants.toml` blindly. |
| Remote public indexers | Operator-managed. Ghost Gate cannot wipe them; require readiness and current generation evidence. No local indexer is mandatory for the remote-reader route. |
| Owned validator state, if any | Follow target full reset procedure separately. No tracked Ghost Gate validator service establishes ownership or its path. |
| Ghost Gate `registry.json`, `bindings.json`, `sessions.json`, `audit.ndjson`, `generations.ndjson` | Preserve complete history and monotonic floor. Advance generation through admin migration; invalidate old sessions, do not delete replay/generation history to regain availability. Regenerate published bindings from registry. |
| Bridge replay records, reset/halt revision, pending jobs | Preserve tombstones and halt. Retire old-generation work; never resume old signed payloads. |
| Worker Durable Objects/replay namespace and backend-state bindings | Preserve namespace/history. Later update binding generation/hash coherently; old authorizations must fail. No namespace reset. |
| Telegram claims, binding and admission state | Preserve audit/replay records; old claims/sessions cannot authorize after reset. Membership reconciliation is a separate operator action. |
| Admin credentials/passkeys and audit identity | Preserve. Ghost Gate admin WebAuthn is distinct from walletd WebAuthn. |
| Browser pending/resume records | Invalidate this app's old-generation jobs; preserve wallet seeds and unrelated origins. |
| Native Minotari L1 wallets/base-node state | Preserve. L2 reset does not authorize any L1 wipe. Crypt does not need `minotari-base-node`. Keep L1 gates disabled unless separately building/testing that feature with its native dependencies. |

VPS source suggests `/opt/ghost-gate/data/registry`, `/opt/ghost-gate/data/replays`, private configs under `/opt/ghost-gate/etc`, bridge 7799/admin 7811/Telegram 7808. Verify actual deployment before use. `deploy/backup.sh` is insufficient as an execution guarantee: it suppresses tar failures and prunes archives. Stage 3B needs a checked, complete backup/restore verification procedure; do not run this script blindly.

## Phase 2 — establish indexer and ledger readiness

The following commands are read-only and intended for the future deployment environment. Repeat for endpoint B by changing only the base URL:

```powershell
curl.exe --fail --max-time 20 https://esme-indexer-a.ootle.tari.com/health
curl.exe --fail --max-time 20 https://esme-indexer-a.ootle.tari.com/ready
curl.exe --fail --max-time 20 https://esme-indexer-a.ootle.tari.com/info
curl.exe --fail --max-time 20 https://esme-indexer-a.ootle.tari.com/identity
curl.exe --fail --max-time 20 https://esme-indexer-a.ootle.tari.com/epoch-manager/stats
curl.exe --fail --max-time 20 https://esme-indexer-a.ootle.tari.com/network
curl.exe --fail --max-time 20 https://esme-indexer-a.ootle.tari.com/network/stats
```

Require TLS success; correct release compatibility, `network_byte=38`, Esmeralda, expected sidechain ID, ready state, completed scan and a progressing current epoch. Compare both endpoints at compatible epochs; record lag and retention. `/info` exposes version, network, byte, sidechain ID, epoch, proof-verification setting and retention. `/identity` identifies a node, not the chain genesis. Never treat HTTP 200 health alone as readiness.

Obtain the registry's `GG_GENESIS_HASH` from documented authoritative ledger identity and verify its provenance against the current operator chain configuration. The checked-in sources do not establish the actual deployment's genesis value. Do not use the tag commit, birthday height, a random hash, an epoch hash, or old sidecar root as a substitute. L1 genesis may remain unchanged across an L2 reset: preserve a verified unchanged genesis and separately advance chain generation. Record current L2 bootstrap/checkpoint evidence where available, without claiming independent consensus verification.

Read/decode native TARI resource state using target types: address `resource_0101010101010101010101010101010101010101010101010101010101010101`, resource class Stealth, divisibility 6, no unexpected hook. Confirm builtin account/faucet availability if used. Decode a fresh known UTXO and negative Down/absent cases. Require the bridge's current reader and usable verification/trust result; never force the 0.47 JSON reader for 0.49.

Set `GG_INDEXER_ENDPOINT` to the verified endpoint and unset `GG_INDEXER_JSON`. Explicitly review wallet `indexer_trust`: target default is trust. Operator-trusted-testnet can use that declared limitation; choosing `verify` requires approved fresh anchors and successful verification. Neither setting upgrades Ghost Gate to consensus-verified. `GG_OPERATOR_TRUSTED_INDEXER` must reflect the intended testnet policy. Stop on unverified/malformed/stale reader results instead of relaxing validation.

## Phase 3 — fresh wallet and funding

Choose a private generation-specific base path and start the reviewed patched walletd using its exact binary's `--help`/configuration, Esmeralda defaults, explicit indexer URLs, local listen addresses and allowed hosts. Do not copy localnet 18130 or obsolete endpoint assumptions. Record actual UI/RPC URLs rather than assuming 5100/5110.

For WebAuthn mode with no enrolled passkey, target walletd writes a one-use token to `<base_path>/setup_token`; its TTL is one hour. Enroll the first passkey through the wallet's registration UI with that token. Restart generates a new token when needed; enrolled wallets remove stale setup-token files. Keep token out of logs/reports/tracked files. Do not turn authentication off to make Ghost Gate's `AuthCredentials::None` fallback succeed. Give the adapter an operator-issued token if required. Allowed-host configuration must contain only intended hosts; test unknown Host rejection and keep walletd private.

Create/recover target wallet identity and create the required fee/test accounts through the official wallet UI. Request native testnet TARI through its supported faucet workflow and wait for committed funding and scan completion. Fee funding is separate from the 100 tTARI qualifying output: exact-threshold testing requires fee headroom elsewhere. Never mint a custom resource labelled tTARI as a replacement for native TARI.

The MVP patch must be present in the actual walletd that builds statements. Validate a requested floor <= blinded amount and rejection above it before locks; verify generated committed output's floor, owner key, decryptability, fee and balance deltas. Browser providers use their own wallet implementations: the local patch does not patch Sapient/Universe. Each must independently demonstrate nonzero MVP and ownership signing support.

## Phase 4 — template inventory and optional on-chain branches

Build all three artifacts, even when only Crypt credential mode is activated. Commands below run from the repository root; default artifact paths assume no `CARGO_TARGET_DIR` override (record actual resolved directory otherwise):

```text
cargo build --locked --release --target wasm32-unknown-unknown --manifest-path templates/ghost_gate/Cargo.toml
cargo build --locked --release --target wasm32-unknown-unknown --manifest-path templates/ghost_gate_faucet/Cargo.toml
cargo build --locked --release --target wasm32-unknown-unknown --manifest-path templates/ghost_gate_other_classes/Cargo.toml
```

| Publication order if full inventory is required | Artifact under that template's `target/wasm32-unknown-unknown/release/` | Dependencies |
|---|---|---|
| P1 GhostGate | `ghost_gate_template.wasm` | Funded fee account, current network/epoch; no prior custom template/resource |
| P2 GhostGateFaucet | `ghost_gate_faucet.wasm` | Same; independent of P1 |
| P3 GhostGateOtherClasses | `ghost_gate_other_classes.wasm` | Same; independent of P1/P2 |

This is a deterministic operational order, not a protocol dependency. The Crypt-only branch skips all three publications; full template validation publishes them in P1/P2/P3 order. Faucet/OtherClasses are allow-all test fixtures, never native TARI issuers or production security components.

Use the official target wallet Web UI: select the reviewed fee account, upload the exact WASM, estimate fee with the current schedule, review cap/metadata, publish once, wait for final acceptance. Record transaction ID before proceeding, publication address, metadata hash, binary hash and committed created substate. Confirm indexer availability and binary identity before calls. The file SHA-256 used for build provenance is not necessarily the protocol template address/hash. Do not invent metadata/hash serialization. Every transaction uses current required fields, network 38, explicit main signer, sr25519 signing, current inputs and bounded current max epoch. Old 100 or 1,000,000 epoch defaults and 100,000/5,000,000 fee caps are not validated estimates.

The Tari skill directs publication through the wallet UI; no new custom publisher is proposed. Existing `deploy_vault.rs` must not be run here: it hard-codes localnet 0x10, `vip.example`, `haunted-vault`, wrong demo thresholds and a fresh resource. Its idempotency comment does not implement a reliable resume journal.

Dependency graph:

```text
tests + provenance -> verified chain/indexer -> fresh wallet/account -> native fee funding
  -> Crypt browser output creation -> independent current-output read
  -> generation migration + reviewed Crypt publication -> acceptance -> controlled activation

optional full fixture branch after fee funding:
  P1, P2, P3 publications
  P2 -> new_resource -> resource address -> wallet FromBucket statement -> faucet.mint
  P1 + existing supported resource -> allocation + GhostGate.new -> Mode A proof
  P3 -> public_fungible / confidential / non_fungible -> rejection tests
```

Exact constructor order/arguments from source:

- `GhostGateFaucet::new_resource(symbol: String, divisibility: u8, initial_supply: Amount)` creates resource, faucet component and supply vault. Then build the wallet statement against its actual resource address and call `mint(mint: StealthTransferStatement)`. Do not use `new(..., mint)` for wallet bootstrap before the resource address is known.
- `GhostGate::new(allocation: ComponentAddressAllocation, resource: ResourceAddress, threshold: u64, relying_site: MaxBytes<64>, session_commitment: MaxBytes<64>, network: u8)` requires allocation in the same transaction and explicit resource input (constructor reads its metadata). Use a separately recorded Mode A test site/session binding; do not substitute it for dynamic credential sessions. Locked update rule is required.
- `GhostGateOtherClasses::public_fungible(symbol, divisibility, supply: Amount)`, `confidential(symbol, divisibility, supply: Amount)`, and `non_fungible(symbol, count: u64)` each create a distinct resource/component/vault. Use distinct test symbols and minimal supply. Attempts to create GhostGate over these unsupported classes should reject.
- Admin and policy registry are off-chain services. There is no admin/registry template to publish or chain component to instantiate.

No Tari Proof arguments, account `*_with_auth`, signer getter, or auth hooks are used by this inventory. Do not add authorization windows. If a selected external resource unexpectedly has a hook, stop and review its explicit component input and authorization requirements first.

## Phase 5 — Crypt policy and generation

Read actual application ID, owner credential, exact-case gate ID, topology, grants, enabled/test-lane flags, immutable policy versions and durable generation floor from protected registry export. Do not guess IDs from display name `Crypt` or silently create another tenant. Keep the current owner/admin credentials where valid.

Required Crypt values:

| Field | Required value |
|---|---|
| Relying site / challenge domain | `https://ghostgate.boo` exactly |
| Network | 38, confirmed from target source and future live `/info` |
| Resource | native `resource_0101010101010101010101010101010101010101010101010101010101010101` |
| Threshold / divisibility | 100000000 / 6 = **100 tTARI**, not 10 |
| Proof mode / component | `credential` / absent |
| Session TTL | 604800 seconds; set explicit gate override and review application default |
| Trust ceiling | `operator-trusted-testnet`; no consensus/production promotion |
| Use mode / production | `both` / `false` |

Under fresh owner step-up and CSRF/session checks, use existing `POST /admin/api/app/migrate-generation` with body `{"applicationId":"<existing-id>","newGeneration":<strictly-greater-than-current-and-floor>}`. This is an off-chain mutation for Stage 3B; not performed here. It advances the durable floor and retires sessions. An already-applied generation is reconciled by reading state, not repeating with an arbitrary higher number. Keep halt until backend/registry/catalog are coherent. Do not recreate the application just to reset its generation to 1.

Publish/review the desired immutable policy through the existing authenticated admin flow, then export `bindings.json`. Hash with repository `hash_policy_versioned` and the actual published snapshot, not hand-concatenated UI labels. New publications use v2 and BLAKE3 hex. Verify catalog/backend/Telegram all agree on app/gate, version/hash, generation, TTL and trust.

Exact v2 canonical order (`crates/ghost-gate-core/src/policy.rs::canonical_form_v2`), pipe-separated:

```text
v2 | application_id | gate_id | policy_version |
owner_credential | topology_code | network | genesis_hash | production | app_default_session_ttl |
resource_address | threshold_raw | divisibility | symbol | name |
Debug(proof_mode) | challenge_domain | effective_gate_ttl | enabled | test_lane |
comma_join(grants) | component_address_or_empty | use_mode
```

Topology Independent=0/Hierarchical=1. Proof mode uses Rust Debug spelling (Credential), not its lowercase display spelling. Grant order and exact string bytes matter. Trust tier is derived/enforced separately, not an additional serialized hash field. Chain generation is deliberately excluded, as are unrelated app revision/display metadata.

Therefore a reset alone can leave a hash unchanged if the same frozen version and every hashed field remain unchanged. New publication version, changed owner/genesis/resource/component/domain/TTL/settings changes it. Crypt has no component and native resource bytes remain fixed, so template republishing alone does not change its policy hash. The old documented v3 digest `13af3169aefb313f355368c5b9131d512d86048ab700d850024c79ddb680b74f` is historical, not an approved new value. Recompute from actual hash format/version and reviewed snapshot; do not fabricate a replacement hash now.

Prepare catalog locally with the existing renderer after publication:

```powershell
.\scripts\render-worker-catalog.ps1 -BindingsPath <protected-current-bindings.json> -OriginsPath <origin-map.json> -OutputPath <candidate-GG_GATE_CATALOG.json>
```

Origin map entry is `"<actual-app-id>/<actual-gate-id>":"https://ghostgate.boo"`. The renderer enforces the exact frozen challenge domain and credential mode. Later VPS/Worker activation must preserve replay namespace, private admin access, tunnel allowlists and HMAC authentication. This document grants no activation authority.

## Phase 6 — transaction inventory, failure boundaries and retry rules

For every row: record intent, unsigned review, fee estimate/cap, network/epoch and resulting ID before another mutation. Success requires finalized accepted execution, expected substate/event contents and independent target indexer read. RPC success, fee payment alone, or a returned transaction ID is insufficient.

| Mutation | Prerequisite | Required committed evidence | Repeat / recovery |
|---|---|---|---|
| Create account | Target wallet custody/auth and chain ready | Intended account component, owner and vault state | Reconcile known address/ID first; new key/allocation may create unwanted account |
| Fund from builtin faucet | Target builtin confirmed, intended destination | Native TARI credit/output and fee deltas | Not idempotent; retry only after final rejection/confirmed absence, within faucet limits |
| Publish P1/P2/P3 (each separate) | Funded fee account, reviewed artifact and metadata | Published-template substate, address/binary/metadata identity | Same content may conflict or cost fees; query before reuse; no blind rebroadcast or changed nonce after timeout |
| Create test resource/faucet | P2 indexed, chosen supply/divisibility | New resource plus faucet/vault, exact class/supply | New transaction normally creates duplicates; journal created IDs, never restart whole deployer |
| Mint test outputs | Resource exists, wallet FromBucket statement for it | Outputs with intended keys/floors and resource plus supply/fee deltas | Repetition mints extra supply; reconcile result/outputs/locks first |
| Create unsupported-class fixtures (three calls) | P3 indexed and minimal amounts | Correct distinct class/resource/component/vault | Each retry can duplicate fixture; reuse confirmed result |
| Create Mode A gate | P1, supported resource, allocation/site/session/network | Correct component policy and Locked header | Duplicate creates unwanted gate; retain original accepted address; rejected unsupported-class creation must create no application component |
| Browser shield/self-transfer | Compatible wallet, funds and fee headroom | Final transaction plus current owned UTXO with qualifying MVP | Spends/create outputs; inspect Pending/transaction status and wallet locks before retry; never replay an old-generation payload |
| Mode A prove_access (optional) | Fresh bound challenge, explicit inputs, valid statement | Final accepted result, `GG` event typed receipt, nonce state and output/fee changes | Single-use nonce; success not repeatable. Fresh challenge only after reconciliation |

Fee-side effects may survive a rejected main execution; inspect actual outcome and fee receipts. For Unknown/Pending/timeouts, query the original ID and wallet locks; wait within a bounded operational policy and escalate unresolved results. Never treat an indexer 404 alone as proof of non-submission. Rebuild/sign only when original final rejection or safe expiration/non-commit is established, with fresh inputs and bounded epoch. New output addresses are read from accepted results, never predictions copied from old artifacts.

There is no chain rollback for an accepted publication/mint/create. Mark erroneous artifacts unused, keep them out of the registry, and create a reviewed replacement if authorized. A service rollback must retain the new generation floor/halt/replay data. Old Ootle databases/binaries cannot restore the reset chain. If a compatible rollback cannot enforce current bindings, remain in maintenance.

## Reset-invalidated inventory

The complete tracked literal inventory remains Stage 1 Appendix B; the following is the execution disposition, including nonliteral/live state:

| Category and source | Action |
|---|---|
| Actual templates, components, custom resources, vaults, accounts in private env/bindings/receipt logs | Export inventory before reset; replace/revalidate every item using new receipts. No concrete published template address is present in tracked deployment evidence. |
| All old L2 transaction IDs, UTXOs, balances, scan cursors, pending locks/payloads | Historical only; record new IDs/results. Deterministic address recurrence does not prove state continuity. |
| `docs/GATE3_RESULTS.md` component `510245…e7e588`, component `f222f5…ffa01`, resource `516123…44fc7`, its UTXO `2c7135…b2a67e` | Historical localnet evidence; preserve document. Regenerate for target test runs, never use for Esmeralda. Full literals in audit Appendix B. |
| `credential_real_chain.rs` and `esmeralda.rs` output suffix `a66c77…54b407` | Old localnet fixture; replace with explicit fresh-run manifest for target live tests. Separate localnet is not erased by an Esmeralda reset. |
| `scripts/cdp-resume-check.mjs` suffix `5ad331…be8c6f` | Mock browser evidence only. Parameterize fresh live acceptance inputs; do not mistake a simulated provider pass for wallet compatibility. |
| Native resource `01` repeated 32 bytes; builtin faucet `component_0102030000000000000000000000000000000000000000000000000000000000` | Constants may remain; verify current resource/faucet state. No custom replacement of native TARI. |
| `component_0dc41b…ffffffff`, repeated `aa` addresses and `abcdef` outputs | Synthetic engine/unit fixtures, not deployment values; keep isolated and revalidate target test semantics. |
| Crypt digest above in `docs/ARCHITECTURE.md`, Worker `lab-technical` and `telegram-join-config` tests | Preserve historical docs; replace active catalog only with recomputed published value. Tests may retain clearly labelled fixtures; no live assertions from them. |
| `scripts/dev.ps1` | Hard-coded wallet version 0.47.0, `esm10`/10000000 default and hex network string `26`; must be parameterized/reviewed before Crypt bootstrap. `GG_OOTLE_NETWORK` expects hex in that launcher; don't pass decimal text 38 blindly. |
| v0.47 sidecar epoch 12634, preset digest `e9b9badf…d3df3`, roots `dc393597…956` and `23b6a682…7f`, old committees/anchors | Historical only; not current consensus evidence. No need to activate sidecar for operator-trusted Crypt. Full values/provenance in Stage 1 audit. |
| Genesis / generation | Verify real genesis; advance operator counter above durable floor. No hard-coded new generation or invented genesis. |
| Registry, Worker catalog, backend-state, sessions/Telegram/browser resume | Regenerate derived bindings; invalidate previous authorizations while retaining audit/replay/generation records. |

## Phase 7 — real-chain acceptance and post-bootstrap checklist

Use isolated test participants and record per-wallet build/version, source cohort, public output ID, transaction ID, current generation, policy version/hash, fee deltas and redacted result. Run every applicable row independently for Sapient and Web Tari Universe. A missing capability is unsupported/blocked, never an implicit pass. Universe must run within its actual embedded provider; a plain tab is not that test.

| Case | Procedure and required result |
|---|---|
| Below threshold | Fresh native output/funds <100000000 with no alternative qualifying output; request Crypt proof. Refuse with no usable session. Test at 99999999 if supported. |
| Qualifying success | Fresh owned native output with chain-decoded MVP >=100000000; complete current ownership challenge. One session with expected app/gate/site/generation/hash/trust and <=604800-second lifetime. |
| Exactly threshold | Output value/floor exactly 100000000, separate fee headroom. Accept; if provider cannot isolate fee funding, record explicit test limitation, not success. |
| Stale challenge | Let captured challenge exceed actual expiresAt, then submit. Refuse and mint no session. Also test pre-reset generation challenge. |
| Replay/race | Submit identical signed response twice/concurrently and retry after restart. At most one usable authorization; no extra session or Telegram admission. |
| Wrong site | Use another HTTPS origin or alter relyingSite after signature. Refuse before issuance. |
| Wrong gate | Apply Crypt response to another actual/synthetic gate ID or changed policy hash/version. Refuse. |
| Wrong resource | Owned, sufficient output of a different real resource (optional fixture branch); submit against native Crypt. Refuse despite sufficient floor. Do not test only a nonexistent address. |
| Wrong session | Sign challenge for browser session A, submit using B's job/session binding. Refuse; B cannot poll/claim A's proof. |
| Wrong key/spent/unverified | Wrong wallet signature, consumed output, malformed CBOR or unavailable/unverified reader all refuse/UNKNOWN, never grant. |
| Sapient | Record actual installed build; capability probe, connect/cancel, current transaction fields/network/sr25519, scan, shield/MVP and ownership signature, pending/reconnect and old-resume refusal. |
| Web Tari Universe | Same cases inside embedded wallet with exact HTTPS origin; confirm connector version and actual provider. Keep UI embedding limited to intended public pages. |
| Session lifecycle | Check secure cookie behavior without recording cookie, TTL <=7 days, correct binding and trust, generation advance invalidation, backend outage/halt refusal. |
| Telegram use=both | New claim/link tied to published Crypt policy; server re-verifies against bridge. Wrong/expired/replayed claim refuses. No client receipt alone grants admission. Membership actions require separately approved test chat. |
| Protocol Inspector | Shows correct resource, raw threshold/divisibility, public output/transaction reference, policy hash/version/generation, actual provider and explicit operator-trusted tier. A failure stays failed; no fabricated `GG` event for credential mode or claim of independent consensus/private movement. |

Before releasing maintenance: all tests have recorded outcomes; fresh bindings match backend/Worker/Telegram; old sessions and pending jobs refuse across restart; recovery copies are readable; no exposed wallet/admin endpoint; no secret in artifacts; fees and current epoch caps validated; rollback preserves floors/replays; unresolved wallet failures remain disabled. Preserve actual committed receipt and balance/output evidence before any privacy assertion.

## Stage 3B reproducibility work (not implemented)

1. Add a read-only preflight/evidence collector: exact source and patch hashes, toolchain/binaries, endpoint `/info`/readiness, resource CBOR, configured genesis provenance, generation floor, artifact digests. Reject missing inputs and redact credentials.
2. Add a generation-scoped execution manifest and reconciliation helper: per-intent transaction ID, phase, accepted/rejected/pending outcome, expected addresses/hashes. Read status before retries. Keep official wallet UI publication; do not add a publisher.
3. Update `prepare_reference.sh`, `prepare_builtin_templates.sh`, `verify_patches.sh`, `wallet_mvp_patch.{sh,ps1}`, `patch_sdk_test.sh`, `patch_test.sh`, `patch_walletd.sh`, `patch_build_localnet.sh`, `ootle_e2e.sh`, `check_gate3_integration.sh` and `package-staging-source.ps1` to exact 0.49.2 sibling source/provenance or mark historical-only. Audit `check_layout.sh`, `check_ootle_bins.sh`, `check_targets.sh`, `wsl_bg.sh` likewise.
4. Guard/parameterize `deploy_vault.rs` before any Esmeralda use: no default network/site/threshold, two-step wallet resource/mint flow, explicit manifest, correct receipt extraction, reconciliation and duplicate protection. It is not required for Crypt. Preserve Locked components.
5. Parameterize `scripts/dev.ps1` and live test fixtures. Add Linux verification workflow or documented runner covering the unfinished Rust suites and the actual patched daemon; no chain credentials in CI.
6. Prepare safe placeholder service env templates missing from `deploy/setup-vps.sh` inputs, with narrow `.gitignore` exception. Prepare backup/restore verification and candidate service manifests locally. No VPS mutation in this stage.
7. Reuse `render-worker-catalog.ps1` and `prepare-staging-web.ps1` with reviewed published snapshot; add non-mutating consistency checks. Preserve Worker replay namespaces. No Cloudflare mutation in this stage.
8. Add a redacted real-chain acceptance harness referencing fresh manifest outputs; leave signatures and submission to explicitly approved wallet actions. Separate mock CDP tests from real provider tests.

## Secrets and evidence boundaries

Never write seed phrases, mnemonic/passphrases, private spend/view/signing keys, masks/decryption secrets, setup tokens, wallet DB/keychain exports, cookies/session or CSRF tokens, JWT/API tokens, backend HMAC/coordinator keys, Telegram bot tokens or claim links, Cloudflare API/account credentials, SSH private keys/passwords, VPS credentials, or full private environment exports to tracked files. Avoid shell history, command-line token arguments, screenshots, CI logs and unredacted receipts containing private session material. Use protected runtime configuration/secret stores. Public addresses and transaction hashes may be recorded after review, but output ownership/linkage remains sensitive; collect only necessary evidence.

Blocking inputs to resolve in Stage 3B: green mandatory Rust tests; exact deployed registry/owner/version/generation inventory; reachable current endpoint readiness and authoritative genesis/sidechain evidence; patched walletd runtime test; actual Sapient/Universe positive vectors; reproducible safe command wrappers for any optional fixture branch. No live mutation is authorized by this planning document.

STAGE 3A VERDICT:
BLOCKED
