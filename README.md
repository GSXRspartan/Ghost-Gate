# Ghost Gate

**Your balance stays in the shadows.**

> Prove you control enough without revealing exactly how much.

Ghost Gate is a private threshold access system for [Tari Ootle](https://github.com/tari-project/tari-ootle).
It lets a user prove control of at least a configured amount of private Tari at access time, without
revealing the exact amount.

```text
GHOST GATE

VIP Vault

Requirement:
≥ 10,000 tTARI

[ PROVE ACCESS ]

Result:
QUALIFIED ✓

Exact balance:
NOT DISCLOSED
```

The threshold is enforced **inside an Ootle template**, under consensus. A relying site cannot
reinterpret the cryptography: if a proof is accepted, every validator that executed the transaction
ran the same rule.

## What a proof actually asserts

At the moment the proof transaction committed, its signer controlled at least the gate threshold of
the gate's resource, and proved it without publishing an amount.

It is **not** a proof of total wallet balance, identity, uniqueness, or holdings at any later time.
`docs/PRIVACY_MODEL.md` states the boundary precisely, including what leaks.

## Status

Newly written, pinned to Tari Ootle **v0.42.0** (commit `a43773e6…`). Everything was written during
the October 2026 Spooky Secrets build contest; nothing predates the theme announcement.

| Area | State | Where |
|---|---|---|
| MVP binding: the promise is covered by the range proof | PROVEN | `docs/GATE1_RESULTS.md` |
| Statement-shape rules (no revealed amounts, one output, key-spendable, balance proof) | PROVEN | `docs/GATE2_RESULTS.md` |
| Challenge binding, single-use, replay refusal | PROVEN (off-chain) | `ghost-gate-verifier` tests |
| Template enforcement under the engine | IN PROGRESS | `docs/GATE2_RESULTS.md` |
| Ordinary wallet funds through the component | NOT PROVEN | `docs/GATE3_RESULTS.md` |
| Live network submission | NOT ATTEMPTED | `docs/GATE0_RESULTS.md` |

`PROVEN` means a test in this repository demonstrates it. It never means simulated.

## Architecture

```text
ordinary key-path stealth tTARI
            │
            ▼
wallet selects sufficient private inputs
            │
            ▼
one fresh self-owned stealth output, MVP ≥ threshold
            │
            ▼
GhostGate::prove_access(challenge, statement)
            │
            ├─ challenge matches gate, resource, threshold, network, site, session
            ├─ challenge not expired, not already burnt
            ├─ inputs live, key-path authorised, nothing revealed
            ├─ exactly one output, key-spendable
            └─ MVP ≥ threshold
            │
            ▼
ResourceManager::stealth_transfer(statement)
            │
            ▼
Ootle engine: key-path authorisation · liveness · balance proof · bulletproof
            │
            ▼
COMMITTED → nonce burnt → relying site issues session
```

The V1 proof is transaction-backed. That is a pragmatic shortcut, not a theoretical requirement: the
transaction supplies liveness, unspentness, ownership authorisation, value conservation and
range-proof enforcement for free. See `docs/TRANSACTIONLESS_FUTURE.md` for what a transactionless
version would need, and why two of its seven requirements are unavailable today.

## Privacy

Hidden: the exact value behind the qualifying output, the exact wallet balance, and the ownership
information the stealth primitive hides.

Observable: that a Ghost Gate transaction happened, which gate, the public lower bound it committed
to, and its timing. **The transaction itself is public metadata.**

Not claimed: anonymity of gate usage, permanent eligibility, holdings after the access event, total
balance, identity, uniqueness, Sybil resistance, or network anonymity.

## Quick start

Requires Rust **1.97.1** (the toolchain v0.42.0 pins) and a checkout of `tari-ootle` at tag `v0.42.0`.

```powershell
# 1. Verify the reference cohort
git -C ..\tari-ootle-v0.42.0-reference rev-parse HEAD
#    expect a43773e600b9503ed3fadcd3f0048f86131e3644

# 2. Create the writable build copy (the script header explains why a copy rather than in place)
bash scripts/prepare_reference.sh

# 3. Suites that do not need the engine — fast, runs on Windows
$env:CARGO_TARGET_DIR = "..\_cargo-target"
cargo test -p ghost-gate-core -p ghost-gate-wallet -p ghost-gate-verifier

# 4. Engine-backed suites — WSL, because wasmer's Cranelift backend cannot build on Windows
bash scripts/wsl_run.sh test -p ghost-gate-tests
```

`docs/GATE0_RESULTS.md` records the exact toolchain, the dependency cohort, and the two build
obstacles that were hit rather than anticipated.

## Layout

```text
ghost-gate/
├── templates/ghost_gate/                    the on-chain template
├── crates/
│   ├── ghost-gate-core/                     qualification rules shared by template and verifier
│   ├── ghost-gate-wallet/                   wallet-side statement assembly
│   ├── ghost-gate-verifier/                 self-hostable relying-side logic
│   └── ghost-gate-tests/                    engine-backed and unit suites
├── docs/                                    source trace, gates, privacy, threat model
└── scripts/                                 reference preparation, WSL runner
```

`ghost-gate-core` is the point of the layout. The template and the relying site both compile the
same `qualify` function, so a site cannot disagree with consensus about what a valid proof is.

## Clean room

Ghost Gate is a new implementation. No application code from any previous project was consulted,
copied or ported. It depends only on official `tari-project/tari-ootle` crates, official Tari
cryptography, and general-purpose libraries. See `docs/CLEAN_ROOM.md`.

## License

MIT — see `LICENSE`. Official Tari Ootle is BSD-3-Clause and is used unmodified.