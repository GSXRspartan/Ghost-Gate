# Gate 0 — v0.42 baseline

The question: are we building against the cohort we think we are, with a toolchain that works, and
can we run the engine at all?

**Verdict: SOURCE BASELINE VERIFIED · LIVE TESTNET VERSION UNKNOWN · engine runs only under WSL.**

## Reference verification

```
$ git -C ..\tari-ootle-v0.42.0-reference rev-parse HEAD
a43773e600b9503ed3fadcd3f0048f86131e3644

$ git -C ..\tari-ootle-v0.42.0-reference describe --tags --exact-match
v0.42.0

$ git -C ..\tari-ootle-v0.42.0-reference status --short
(empty)
```

Tag and commit agree, working tree clean. The reference is never written to.

## Dependency cohort

Every Ootle crate is pinned by path to a verified copy of that commit, and additionally carries the
version the cohort declares, so the pin is readable without consulting the reference.

| Crate | v0.42.0 declares | Registry equivalent |
|---|---|---|
| `tari_template_lib` | 0.33.0 | 0.33.0 (confirmed published) |
| `tari_template_lib_types` | 0.33.0 | 0.33.0 |
| `tari_template_abi` | 0.20.1 | 0.20.1 |
| `tari_template_macros` | 0.23 | 0.23 |
| `tari_template_test_tooling` | 0.42.0 | 0.42.0 |
| `tari_engine` | 0.42.0 | 0.42.0 |
| `tari_engine_types` | 0.42.0 | 0.42.0 |
| `tari_ootle_transaction` | 0.42.0 | 0.42.0 |
| `tari_ootle_wallet_crypto` | 0.44 | 0.44 |
| `tari_ootle_wallet_sdk` | 0.44.0 | 0.44.0 |
| `tari_ootle_walletd_client` | 0.44.0 | 0.44.0 |
| `tari_ootle_wallet_storage_sqlite` | 0.44.0 | 0.44.0 |
| `tari_ootle_common_types` | 0.42.0 | 0.42.0 |
| `tari_ootle_address` | 0.12 | 0.12 |
| `tari_indexer_client` | 0.43 | 0.43 |
| `tari_consensus_types` | 0.42.0 | 0.42.0 |
| `tari_bor` | 0.16.2 | 0.16.2 |
| `ootle_byte_type` | 0.14 | 0.14 |
| `ootle-network` | 0.2 | 0.2 |
| `ootle_serde` | 0.6 | 0.6 |
| `tari_crypto` | 0.23.4 | 0.23.4 |
| `minicbor` | 2.3 | 2.3 |
| `wasmer` | ~7.4.0 (pinned, consensus-critical) | same |

**No v0.41 dependency anywhere.** The `wasmer` pin matters: the Ootle workspace comments that the
accepted module set and memory tunables are consensus-critical, so a minor bump must be a reviewed
change. Ghost Gate inherits `~7.4.0` through the engine and does not relax it.

`tari_template_lib` was additionally checked against crates.io: `0.33.0` is the highest published
version, confirming this is the current cohort and not a stale pin.

## Toolchain

```
rustc 1.97.1 (8bab26f4f 2026-07-14)
cargo 1.97.1 (c980f4866 2026-06-30)
```

Matches `rust-toolchain.toml` in the reference exactly (`channel = "1.97.1"`). No override, no
nightly.

Targets needed:

- `x86_64-pc-windows-msvc` — for the non-engine suites
- `wasm32-unknown-unknown` — for compiling the template
- `x86_64-unknown-linux-gnu` (WSL) — for the engine

## Two build obstacles, both real

### 1. Building the reference would modify it

`crates/template_builtin/build.rs` compiles five builtin WASM templates and writes them into its own
crate tree (`crates/template_builtin/compiled/*.wasm`, plus a `target/` per template). Those paths are
gitignored, so they are absent from a fresh clone. `tari_template_test_tooling` depends on
`tari_template_builtin` with `features = ["templates", "state"]`, so any engine-backed test triggers
those writes.

Hit as a failure, not anticipated:

```
error: failed to run custom build command for `tari_template_builtin v0.42.0`
  Error: Copy file to dest
  Caused by: The system cannot find the path specified. (os error 3)
```

**Resolution.** `scripts/prepare_reference.sh` verifies the reference SHA, copies the working tree to
`../_ootle-v042-build`, re-checks the copy's workspace version, and points the workspace's path
dependencies there. The reference stays pristine; `git status --short` on it remains empty.

The copy lives outside this repository and is never committed.

### 2. The engine cannot build on Windows

`wasmer-compiler-cranelift` 7.4.0, `src/lib.rs:21`:

```rust
#[cfg(target_os = "windows")]
compile_error!("The Cranelift compiler backend is not supported on Windows. Use the V8 backend instead.");
```

`tari_engine` requires `wasmer = { features = ["cranelift"] }`. Since the backend is consensus-pinned,
substituting V8 is not an option: different accepted modules and different metering.

```
$ cargo test -p ghost-gate-tests
error: The Cranelift compiler backend is not supported on Windows.
error: could not compile `wasmer-compiler-cranelift` due to 1 previous error
```

**Resolution.** Engine-backed suites run under WSL (Ubuntu 22.04, 3 cores, ~3 GiB RAM).
`scripts/wsl_run.sh` rsyncs the tree to `/root/gg` on the WSL ext4 volume — cargo's many small file
operations on the `/mnt/c` drvfs mount are far slower — and runs cargo there with
`CARGO_TARGET_DIR=/root/gg-target`. The Windows checkout remains the source of truth; nothing is
written back.

Suites that do not pull in the engine run on Windows and stay in the fast inner loop.

## Build profile

`Cargo.toml` mirrors the Ootle workspace's `opt-level = 2` override for wasmer and the cranelift
crates. The Ootle comment records why: unoptimized Cranelift makes template tests spend their time
in codegen rather than in template logic (their `tari_engine` suite, ~150s → ~5s).

## Live public testnet version

**UNKNOWN.**

No network call was made. The v0.42.0 release notes state the public testnet faucet is empty after
the reset, and acquiring test tTARI now involves a burn/claim flow that has not been exercised here.

```
SOURCE BASELINE: VERIFIED
LIVE TESTNET VERSION: UNKNOWN
```

Stating the first without the second is deliberate. Nothing in this repository should be read as
claiming a transaction was accepted by a public validator.

## What Gate 0 does and does not establish

Established:

- the reference is at the expected commit and tag, unmodified;
- every dependency is in the v0.42.0 cohort, with no downgrade;
- the toolchain matches the cohort's pin;
- the template builds for `wasm32-unknown-unknown`;
- the engine's test harness compiles and runs (under WSL).

Not established:

- that a live public validator accepts Ghost Gate transactions;
- that the live network cohort matches v0.42.0;
- anything about walletd running against a real node.