# Ghost Gate compatibility with live Ootle 0.49.1

Date: 2026-11-03

## Decision

**Classification A: the validated Ghost Gate v0.49.2 client/source is fully compatible with the
live v0.49.1 Esmeralda network for every Ghost Gate code path reviewed.** The server's `0.49.1`
version string is not, by itself, an incompatibility. No Rust dependency downgrade or protocol
change is required.

Ghost Gate deliberately remains built from the patched exact v0.49.2 source cohort. This retains
the already validated code and wallet minimum-value-promise patch. Downgrading the path cohort to
v0.49.1 would change package identities and force a second engine validation without changing any
relevant implementation or wire type.

## Exact upstream comparison

The comparison used the signed upstream tags in the external reference checkout:

- `v0.49.1`: `b94de26c3ec463b17926a92f2189507a195ac00c`
- `v0.49.2`: `aa7b0c81719e5c3cfaf9bf3b5fb87bd83180cb90`

`v0.49.2` is one commit after `v0.49.1`: `chore: release v0.49.2 (#3259)`. The complete
`git diff --name-status v0.49.1..v0.49.2` is:

```text
M CHANGELOG.md
M Cargo.lock
M Cargo.toml
M crates/logging/Cargo.toml
```

The content changes are limited to:

1. workspace package version `0.49.1` to `0.49.2`;
2. the corresponding workspace-package version entries in `Cargo.lock`; and
3. `tari_logging` feature `metrics = ["dep:prometheus-client"]` to
   `metrics = ["prometheus-client"]`, with an upstream comment explaining that this restores
   release-binary feature resolution for `cargo-auditable`.

The v0.49.2 changelog says it ships validator, indexer, wallet daemon, and swarm binaries that
v0.49.0/v0.49.1 failed to build. There is no relevant runtime implementation change between the
two tags.

## Ghost Gate API-by-API result

An exact tree diff over the directories containing the following APIs returned no source change:

| Ghost Gate dependency or behavior | Upstream source checked | v0.49.1 vs v0.49.2 |
|---|---|---|
| `tari_template_lib` 0.37 and proof models | `crates/template_lib`, `crates/template_lib_types` | Identical |
| Wallet crypto and `derive_stealth_owner_secret` | `crates/wallet/crypto`, `crates/wallet/sdk` | Identical; account and view secrets remain separate inputs |
| `WalletSdkConfig` and SDK services | `crates/wallet/sdk`, `crates/wallet/sdk_services` | Identical |
| Minimum-value-promise behavior | wallet SDK stealth-transfer code | Identical upstream; the same Ghost Gate patch applies to both trees |
| Indexer REST client and base64-CBOR values | `clients/tari_indexer_client`, `applications/tari_indexer` | Identical |
| Transaction model, required fields, sr25519, `MainSigner` | `crates/transaction`, transaction validation | Identical |
| Proof authorization windows and frame-scoped badges | `crates/engine`, engine proof-window tests | Identical |
| Account authorization calls | engine/template APIs | Identical |
| Walletd JSON-RPC and WebAuthn behavior | `applications/tari_walletd`, `clients/wallet_daemon_client` | Identical |
| Resource proof and stealth structures | engine/template/wallet type trees | Identical |
| Template build and test tooling | `crates/template_build`, `crates/template_test_tooling` | Identical implementation |

The full relevant-directory command also returned success (no differences) for walletd, indexer,
both Rust REST clients, engine, transaction, template libraries, engine types, CBOR, and wallet.
The only non-changelog source change is the release-build-only logging feature declaration above.

## Current Ghost Gate cohort retained

The live branch keeps the validated dependency matrix:

| Area | Retained version/source |
|---|---|
| Template library | `tari_template_lib 0.37.0` |
| Engine / transaction / consensus types | path cohort `0.49.2` |
| Wallet SDK / walletd client | `0.51.0` |
| Indexer client | `0.50.0` |
| Wallet crypto | `0.50.0` |
| Template types | `0.36.0` |
| Tari crypto | `0.24.1` |
| Minotari support | `6.3.0-pre.2`, isolated behind its existing feature |

The source path remains `../_ootle-v0492-ghost-gate`, an exact v0.49.2 checkout plus
`docs/wallet-mvp-0492.patch`. This is a tested client/source cohort connecting to a compatible
v0.49.1 server cohort; it is not a claim that the server runs v0.49.2.

## Security and migration implications

All v0.49 authorization behavior introduced in v0.49.0 is already present in v0.49.1. Therefore
the live branch retains the current transaction model, `MainSigner::SealSigner`, sr25519
assumptions, separated stealth account/view derivation, current wallet config, CBOR indexer
decoding, and frame-scoped authorization semantics. Ghost Gate still passes no Tari `Proof`
arguments, uses no account `*_with_auth` call, signer/owner proof getter, or resource auth hook, so
it must not add an artificial `AuthorizeProof`/`DropProofAuthorization` window.

The compatibility finding is scoped to the reviewed Ghost Gate surfaces and the exact tags above.
It does not waive network-byte checks, verified-state checks, registry policy binding, chain
generation migration, wallet provenance, or real browser-provider testing.

## Required retarget changes

No Rust, Cargo, template, deployment-manifest, transaction, or GitHub Actions change is required.
The minimum retarget is:

- accept exact live server version `0.49.1` while recording tested client/source version `0.49.2`;
- keep Esmeralda byte 38, two-indexer agreement, readiness, and proof-bearing native/faucet state
  as hard network gates;
- report a missing API `sidechain_id`/genesis field as a diagnostic rather than making that
  optional field a network-monitor blocker; and
- retarget the operator readiness and browser-wallet instructions to the live v0.49.1 network.
