# Clean room

Ghost Gate is a new implementation. This document records what that means concretely, and what
the project is allowed to depend on.

## Policy

No application code from any previous project was searched for, inspected, imported, copied, ported,
rewritten or adapted. Specifically excluded as sources:

- any atomic swap project;
- any Purrivacy application;
- any mobile swap application;
- any liquidity protocol work;
- Private Ballot;
- VeilStrike;
- any stablecoin experiment;
- any earlier contest entry;
- Sapient application source;
- any extracted, application-specific Tari helper library;
- any other contestant's application.

Parent Codex directories were not searched for reusable code. The work stayed inside
`ghost-gate-workspace/`, which contains only this repository and the read-only Ootle reference.

If behaviour was needed from another application, the equivalent behaviour was traced into official
Tari Ootle source and the official primitive used directly, rather than adapting that application.

## What was read

Read-only, as the specification for the protocol:

- `tari-ootle-v0.42.0-reference/` — the official Tari Ootle clone at tag `v0.42.0`, commit
  `a43773e600b9503ed3fadcd3f0048f86131e3644`.

That directory was never modified. A build copy is made for compiling, because
`crates/template_builtin/build.rs` writes compiled WASM into its own crate tree; see
`scripts/prepare_reference.sh`.

## Official dependencies

Everything Ghost Gate depends on is an official Tari project crate or a general-purpose library.
All Ootle crates are pinned by path to the verified v0.42.0 cohort and additionally carry the
version the cohort declares, so the pin is visible without consulting the reference.

### On-chain

| Crate | Version in v0.42.0 | Used for |
|---|---|---|
| `tari_template_lib` | 0.33.0 | Template author-facing API: `Component`, `ResourceManager`, `Consensus`, `CallerContext`, `emit_event` |
| `tari_template_lib_types` | 0.33.0 | `StealthTransferStatement`, `SpendAuthorization`, `SpendWitness`, `Amount`, `MaxBytes`, `Hash32` |
| `tari_template_macros` | 0.23 | The `#[template]` attribute macro |

### Statement assembly (runs inside the wallet)

| Crate | Version in v0.42.0 | Used for |
|---|---|---|
| `tari_ootle_wallet_crypto` | 0.44 | `create_transfer_statement`, `StealthOutputWitness`, `StealthInputWitness`, `MaskAndValue`, encryption, key derivation |
| `ootle-network` | 0.2 | `Network`, used to domain-separate derived stealth keys |

### Engine-backed tests

| Crate | Version in v0.42.0 | Used for |
|---|---|---|
| `tari_template_test_tooling` | 0.42.0 | `TemplateTest`: compiles the template to WASM, bootstraps state, executes transactions |
| `tari_engine_types` | 0.42.0 | `validate_stealth_outputs_statement` — the engine's own range-proof check, invoked directly in tests |

### Third-party

`minicbor` 2.3 (CBOR, matching the cohort's), `tari_crypto` 0.23.4 (Ristretto), `rand` 0.10.1,
`sha2` 0.10.8, `thiserror` 2.0.17, `hex` 0.4, `time` 0.3.47.

## What was written

Every line of Ghost Gate's own logic:

- `crates/ghost-gate-core` — the qualification rules, the challenge type, the receipt type and the
  refusal reasons.
- `templates/ghost_gate` — the template that enforces those rules on chain.
- `crates/ghost-gate-wallet` — wallet-side statement assembly, including the minimum value promise.
- `crates/ghost-gate-verifier` — self-hostable relying-side logic: challenge issuance, single-use
  consumption, finality gating, session issuing.
- `crates/ghost-gate-tests` — the test suites.

## Boundary note on the template

The template is where the product's security claim lives, and it is written against the documented
public API of `tari_template_lib`. Reading official source to learn what an API guarantees is
dependency research, not application-code reuse — the same as reading documentation. No template
logic was copied; `crates/engine/tests/templates/` in the reference was read only to learn which
APIs exist and what invariants they carry, and every Ghost Gate rule was written from the protocol
requirements in `README.md` and the task specification.

## Reproducibility

The reference SHA, the build-copy procedure and the exact toolchain are recorded in
`docs/GATE0_RESULTS.md`. `scripts/prepare_reference.sh` refuses to proceed against a cohort other
than the pinned commit.