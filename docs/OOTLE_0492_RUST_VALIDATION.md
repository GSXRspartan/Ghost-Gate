# Ootle 0.49.2 Rust validation

Date: 2026-11-02
Repository: canonical Ghost Gate checkout
HEAD before validation: `f960d1575c7175f98625d2ae0015a300980b0b68`

## Scope and safety

This stage was local validation only. No template was published, no transaction was submitted, no
chain address was regenerated, and no Cloudflare, VPS, production configuration, or live service was
changed. No source fix was made. The only tracked-worktree addition made by this stage is this report.
Cargo and rustfmt created or reused untracked build artifacts only.

The Tari/Ootle validation instructions were read before performing the checks. The migration audit,
implementation report, and bootstrap plan were also read before validation.

## Worktree state

The worktree was already dirty when this stage began. The pre-validation status was:

```text
 M Cargo.lock
 M Cargo.toml
 M crates/ghost-gate-bridge/Cargo.toml
 M crates/ghost-gate-core/Cargo.toml
 M crates/ghost-gate-ggbp1-spike/Cargo.toml
 M crates/ghost-gate-minotari/Cargo.toml
 M crates/ghost-gate-minotari/src/lib.rs
 M crates/ghost-gate-minotari/src/wallet_service.rs
 M crates/ghost-gate-tests/Cargo.toml
 M crates/ghost-gate-wallet/src/lib.rs
 M crates/ghost-gate-walletd/Cargo.toml
 M crates/ghost-gate-walletd/src/bin/ghost-gate-bridge.rs
 M crates/ghost-gate-walletd/src/esmeralda.rs
 M crates/ghost-gate-walletd/src/indexer.rs
 M crates/ghost-gate-walletd/src/lib.rs
 M templates/ghost_gate/Cargo.lock
 M templates/ghost_gate/Cargo.toml
 M templates/ghost_gate/src/lib.rs
 M templates/ghost_gate_faucet/Cargo.lock
 M templates/ghost_gate_faucet/Cargo.toml
 M templates/ghost_gate_faucet/src/lib.rs
 M templates/ghost_gate_other_classes/Cargo.lock
 M templates/ghost_gate_other_classes/Cargo.toml
 M templates/ghost_gate_other_classes/src/lib.rs
?? docs/ESMERALDA_0492_BOOTSTRAP_PLAN.md
?? docs/OOTLE_0492_IMPLEMENTATION.md
?? docs/OOTLE_0492_MIGRATION_AUDIT.md
?? docs/wallet-mvp-0492.patch
```

Those paths are the existing Stage 2/3A migration artifacts. Validation did not overwrite or revert
them. `git diff --check` passed; Git emitted line-ending notices for the four modified lockfiles but
reported no whitespace error. The HEAD remained unchanged.

Toolchain observed on the Windows host:

```text
rustc 1.97.1 (8bab26f4f 2026-07-14)
cargo 1.97.1 (27f3f646c 2026-07-13)
rustfmt 1.9.0-stable (8bab26f4f6 2026-07-14)
rustfmt 1.10.0-nightly (ad3d0bc141 2026-07-31)
host: x86_64-pc-windows-msvc
```

`wasm32-unknown-unknown` is installed.

## Commands and results

### Required commands

| Command | Result | Classification |
|---|---|---|
| `cargo fmt --all -- --check` | **FAIL**. Stable rustfmt traversed both Ghost Gate and the sibling patched Ootle path workspace. It ignored the sibling Ootle tree's nightly-only rustfmt settings and emitted more than 300,000 tokens of diffs before the already-deterministic check was stopped. Exit 1. | Environment/tooling scope failure plus source-format failure; see below. |
| `cargo check --workspace` | **PASS**, 28m22s. All workspace crates compiled. | Pass. |
| `cargo test --workspace` | **FAIL before tests** at upstream `wasmer-compiler-cranelift 7.5.0`: `The Cranelift compiler backend is not supported on Windows. Use the V8 backend instead.` The command was allowed to reach and report the genuine blocker; remaining parallel compilation jobs were then stopped because the workspace run could no longer execute an engine test. | **ENVIRONMENT FAILURE**. |
| `cargo test --workspace --exclude ghost-gate-tests` | **PASS**, 26m53s build plus test execution. 397 passed, 0 failed, 5 ignored. | Pass for every Windows-compatible workspace package. |

The first `cargo test --workspace` attempt was interrupted externally while compiling. It was restarted
with the exact same command and reused the completed artifacts. The restarted command is the one that
reached and recorded the Cranelift error above.

### Formatting diagnosis

The repository has no `rust-toolchain` file and no repository-local `rustfmt.toml`. The external Ootle
workspace does have a nightly-oriented formatter policy. Two diagnostic checks were run without
changing files:

```powershell
cargo +nightly fmt --all -- --check
rustfmt +nightly --edition 2024 --check `
  crates/ghost-gate-minotari/src/lib.rs `
  crates/ghost-gate-minotari/src/wallet_service.rs `
  crates/ghost-gate-wallet/src/lib.rs `
  crates/ghost-gate-walletd/src/bin/ghost-gate-bridge.rs `
  crates/ghost-gate-walletd/src/esmeralda.rs `
  crates/ghost-gate-walletd/src/indexer.rs `
  crates/ghost-gate-walletd/src/lib.rs `
  templates/ghost_gate/src/lib.rs `
  templates/ghost_gate_faucet/src/lib.rs `
  templates/ghost_gate_other_classes/src/lib.rs
```

Both failed. Nightly avoids the stable-only warning mismatch but still finds real formatting deltas in
the patched wallet SDK and Ghost Gate. The focused check confirms that migration-touched files such as
`ghost-gate-wallet/src/lib.rs`, walletd sources, and all three templates are among the files with
formatting deltas. The root command also finds many unrelated, pre-existing formatting deltas (for
example in `ghost-gate-admin`) because it formats the full workspace.

This is a **SOURCE FAILURE for formatting compliance**, not a compile or behavioral migration defect.
It was not auto-fixed because doing so would reformat a broad set of pre-existing files and the
external patched Ootle tree, contrary to this stage's instruction to fix only migration source defects
and preserve existing work.

### Template and migration-specific checks

All three current template workspaces compiled for WASM:

```powershell
cd templates/ghost_gate
cargo check --target wasm32-unknown-unknown

cd ../ghost_gate_faucet
cargo check --target wasm32-unknown-unknown

cd ../ghost_gate_other_classes
cargo check --target wasm32-unknown-unknown
```

Result: **PASS / PASS / PASS**. These checks used `tari_template_lib 0.37.0` and the Ootle 0.49.2
cohort selected by the manifests. They did not publish the resulting templates.

The wallet minimum-value-promise patch was tested directly:

```powershell
cargo test --manifest-path ../_ootle-v0492-ghost-gate/Cargo.toml `
  -p tari_ootle_wallet_sdk minimum_value_promise
```

Result: **PASS**, 3 passed, 0 failed, 54 filtered out:

- promise above blinded amount is rejected;
- promise at or below blinded amount is accepted;
- an omitted promise defaults to zero.

### Windows-compatible test inventory

`cargo test --workspace --exclude ghost-gate-tests` executed all non-engine workspace test targets.
The substantive counts were:

| Crate/target | Passed | Failed | Ignored |
|---|---:|---:|---:|
| `ghost-gate-admin` unit + `admin_plane` | 37 | 0 | 0 |
| `ghost-gate-bridge` | 174 | 0 | 0 |
| `ghost-gate-cbor` | 12 | 0 | 0 |
| `ghost-gate-core` | 49 | 0 | 0 |
| `ghost-gate-ggbp1-spike` | 20 | 0 | 0 |
| `ghost-gate-minotari` | 15 | 0 | 0 |
| `ghost-gate-registry` | 25 | 0 | 0 |
| `ghost-gate-telegram` | 25 | 0 | 0 |
| `ghost-gate-verifier` | 22 | 0 | 0 |
| `ghost-gate-wallet` | 14 | 0 | 0 |
| `ghost-gate-walletd` offline unit tests | 4 | 0 | 3 |
| `credential_real_chain` | 0 | 0 | 2 |
| **Total** | **397** | **0** | **5** |

Doc tests also passed (the crates currently contain no runnable doc tests).

The passing tests cover the local registry/admin plane, policy hashes, generation/reset guards,
challenge freshness, nonce burning and replay refusal, site/gate/resource/session binding,
cross-origin refusal, fail-closed indexer behavior, CBOR limits and strict types, wallet statement
shape and minimum-value-promise handling, typed receipt behavior, server-side Telegram re-verification,
and cross-resource rejection at the non-engine layers.

Compiler warnings were present (unused imports/variables, one dead timeout constant, and one
unnecessary `mut`). They are warnings rather than test failures and were not changed in this stage.

## Ignored and skipped tests

The five ignored tests are intentional live-service tests and are **EXPECTED LIVE-CHAIN SKIPS** for
this local/offline stage:

- `ghost-gate-walletd::esmeralda::tests::a_v042_utxo_substate_parses_through_the_substate_shape` —
  requires the shared localnet indexer;
- `ghost-gate-walletd::esmeralda::tests::a_v047_component_substate_parses_through_the_state_shape` —
  requires the public historical Esmeralda indexer;
- `ghost-gate-walletd::esmeralda::tests::esmeralda_indexer_is_v047` — requires that same historical
  public endpoint;
- `credential_real_chain::a_real_finalized_output_with_no_promise_is_refused_below_a_10_ttari_threshold` —
  requires the shared localnet indexer at `127.0.0.1:12007`;
- `credential_real_chain::no_promise_means_no_threshold_at_all_can_be_attested` — requires the same
  localnet indexer.

They were not unignored, weakened, or contacted. No production or public network service was used.

The following engine-backed integration targets did **not execute** because Windows cannot compile
Ootle's selected Wasmer Cranelift backend:

- `crates/ghost-gate-tests/tests/gate_engine.rs`;
- `crates/ghost-gate-tests/tests/adversarial.rs`;
- `crates/ghost-gate-tests/tests/cross_resource.rs`;
- `crates/ghost-gate-tests/tests/mvp_and_shape.rs`.

This is not an expected live-chain skip: these are required local engine tests and remain an
**ENVIRONMENT FAILURE**.

## Linux engine-test environment

WSL enumeration initially failed inside the sandbox with `E_ACCESSDENIED`. An approved read outside
the sandbox showed three registered WSL 2 distributions: `Ubuntu-22.04`, `Ubuntu`, and
`Ubuntu-22.04-orig`. The repository helper was inspected but not used because it only syncs the old
`ghost-gate` and old cohort layout, not this `ghost-gate-public` plus Ootle 0.49.2 layout.

Direct probes then failed before a Linux process could start:

```powershell
wsl.exe -d Ubuntu-22.04 -- bash -lc "cargo --version && rustc --version && df -h /root"
wsl.exe -d Ubuntu -- bash -lc "cargo --version && rustc --version && df -h /root"
```

Both distributions are registered against missing VHDX paths and return
`WSL/Service/CreateInstance/MountDisk/ERROR_PATH_NOT_FOUND`. The first expected
`D:\wsl\Ubuntu-2204\ext4.vhdx`; the second expected
`D:\from laptop\WSL\Ubuntu\ext4.vhdx`. No WSL state was modified.

## GitHub Actions Linux validation

Linux validation will now run through the `Ootle 0.49.2 Linux validation` GitHub Actions workflow in
`.github/workflows/ootle-0492-validation.yml`. The workflow is intentionally offline: it needs no
wallet seed, chain endpoint, Cloudflare/VPS credential, Telegram secret, or production service.

The blocking `Linux engine and migration tests` job checks out the exact Ghost Gate commit selected
by the event, checks out Ootle tag `v0.49.2`, verifies its pinned commit
`aa7b0c81719e5c3cfaf9bf3b5fb87bd83180cb90`, applies `docs/wallet-mvp-0492.patch`, and recreates the
sibling patched-cohort path used by the manifests. On Ubuntu 24.04 with Rust 1.97.1 it runs:

```text
cargo check --workspace --locked
cargo test --workspace --exclude ghost-gate-tests --locked
cargo test -p ghost-gate-tests --locked
cargo check --target wasm32-unknown-unknown --locked  # in each of the three template workspaces
cargo test --manifest-path ../_ootle-v0492-ghost-gate/Cargo.toml \
  -p tari_ootle_wallet_sdk minimum_value_promise --locked
```

The `ghost-gate-tests` command executes all four previously blocked engine targets: `gate_engine`,
`adversarial`, `cross_resource`, and `mvp_and_shape`. The workflow uses Ootle's own 0.49.2 Ubuntu
dependency installer rather than maintaining a guessed package list in Ghost Gate.

Formatting remains a separate `Ghost Gate formatting diagnostic (non-blocking)` job. It runs the
documented nightly formatter only over the migration-touched Ghost Gate Rust files, does not traverse
or gate on the external patched Ootle workspace, and does not suppress the existing Ghost Gate
formatting differences. Its failure is visible but cannot obscure the independent Linux engine-test
result. Formatting remains a release/bootstrap blocker until its canonical policy and source scope
are resolved and the focused diagnostic is green.

This local commit only defines the workflow. No GitHub Actions result exists until an operator pushes
the branch or manually dispatches the workflow, so this report's validation verdict remains blocked
until the required job completes successfully and the separate formatting blocker is resolved.

## Ootle 0.49.2 migration assertions

Static searches were run across all Rust sources under `crates/` and `templates/` for:

```text
AuthorizeProof
DropProofAuthorization
*_with_auth
create_ownership_proof
owner/signature proof getter variants
auth_hook / AuthHook
```

There were no matches. Therefore:

- Ghost Gate passes a `StealthTransferStatement`, not a Tari `Proof` argument;
- it does not call account `*_with_auth` methods;
- no `AuthorizeProof`/`DropProofAuthorization` window is required by the current flow;
- it does not depend on removed signer/owner proof getters or signer/public-key badge lending;
- it defines no resource auth hook, so there is no auth-hook component input to declare.

The current transaction path compiled and was inspected:

- `TransactionBuilder::new(network, max_epoch)` supplies the current validity field;
- `.with_nonce(...)` supplies the required nonce;
- `.with_main_signer(MainSigner::SealSigner)` declares the explicit main signer before the sr25519
  signing message is built;
- the wallet daemon seals with the account owner key and derives UTXO signers from the wallet lock;
- the gate component and spent UTXO are explicit transaction inputs;
- `other_signers` and pre-supplied `signatures` remain empty;
- there is no auth-hook input because there is no auth hook.

All fresh template constructors compile with `.with_upgrade_rule(UpdateRule::Locked)`. No migration
convenience upgrade authority was introduced.

The current indexer reader compiles against `tari_indexer_client 0.50.0`. It calls typed
`get_substate`, obtains the response's encoded substate, decodes the base64-CBOR
`Encoded<SubstateValue>`, requires `SubstateValue::Utxo`, and carries the indexer's `verified` bit
through to fail-closed credential verification. The 12 strict `ghost-gate-cbor` tests passed. Receipt
handling compiles against typed consensus events and reads the `GG_PROOF_ACCEPTED` payload rather
than removed finalize return values.

The wallet adapter compiles against wallet SDK/client `0.51.0`, wallet crypto `0.50.0`, indexer client
`0.50.0`, Ootle engine/transaction/consensus `0.49.2`, and Minotari `6.3.0-pre.2`. Its offline tests
passed. WebAuthn setup-token issuance and allowed-host enforcement are daemon/operator startup
behaviors and cannot be proven by these offline client tests; they remain bootstrap readiness checks,
not local source failures.

## Failure classification

### SOURCE FAILURE

1. Formatting compliance is red. Both the required stable root check and the diagnostic nightly/
   focused checks report formatting differences, including in migration-touched Ghost Gate files.
   No behavioral or compile failure was found in those files.

### ENVIRONMENT FAILURE

1. `ghost-gate-tests` cannot compile on Windows because upstream `wasmer-compiler-cranelift 7.5.0`
   intentionally rejects Windows.
2. The registered WSL distributions cannot start because their configured VHDX files are missing, so
   the four required Linux engine suites could not be executed locally.

### EXPECTED LIVE-CHAIN SKIP

The five ignored tests listed above intentionally require a public/historical indexer or the shared
localnet indexer. They are not evidence of a source failure and were not contacted in this stage.

## Source fixes and files changed by this stage

No Rust, manifest, test, template, script, configuration, lockfile, or external Ootle source was
changed. No test was weakened or marked ignored. This report is the only file created by Stage 3A.1.

## Bootstrap safety

The Windows-compatible source surface is green and the Ootle 0.49.2 APIs compile. Nevertheless, the
repository is **not yet cleared for Stage 3 live bootstrap** because the required engine-backed
adversarial/cross-resource/template execution tests have not run and the required formatting gate is
red.

Minimum concrete actions required to reach PASS:

1. Push the workflow commit to `upgrade/ootle-0.49.2` and require the blocking
   `Linux engine and migration tests` job to pass for the exact commit. All four engine integration
   targets must pass; a restored WSL or equivalent Linux runner remains an acceptable local fallback.
2. Define/pin the canonical rustfmt toolchain and scope so the Ghost Gate formatting gate is
   reproducible without treating the external patched Ootle checkout as vendored Ghost Gate source.
   Format the migration-touched files (and any in-scope pre-existing files) without semantic changes,
   then make the agreed `cargo fmt --all -- --check` equivalent green.
3. Rerun `cargo check --workspace`, the Windows-compatible workspace tests, all three WASM checks,
   and the focused wallet SDK minimum-value-promise tests after those two actions. Do not bootstrap
   until the rerun is green.

RUST VALIDATION VERDICT: BLOCKED
