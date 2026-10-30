# GHOST GATE — PRIVACY LAB

> **Historical development record.** This document describes a prior local/demo state and is not
> the Crypt v3 release contract. See the top-level `README.md` and `docs/DEMO.md`.

**Prove enough. Reveal less.**

Ghost Gate is a privacy-verification platform: you prove that you hold **at least** a configured
minimum of a token, and nobody — not the verifier, not the operator, not this website — ever learns
your exact balance. There is no burn, no wrap, no custodian, and no database of visitors.

```
Site / Telegram  ──►  Gate policy (administrator)  ──►  Challenge  ──►  Wallet builds a
                      threshold, versioned,          single-use     range proof [min, 2^64)
                      published, tamper-evident                      │
                                                                     ▼
                                       Verifier: floor ≥ threshold, then a server-issued
                                       session whose expiry is the administrator's choice
```

---

## Run it

```bash
# 1. an administrator's gate registry (fresh directory, one-time bootstrap token)
GG_ADMIN_DATA=~/ghost-gate-admin \
GG_ADMIN_HOSTNAME=localhost \
GG_GENESIS_HASH=<your chain's genesis hash> \
  ghost-gate-admin
#    → open http://localhost:7811/admin, paste the token from stdout, register a passkey

# 2. the bridge, reading that registry as its only gate authority
GG_BRIDGE_BIND=127.0.0.1:7799 \
GG_BRIDGE_ORIGINS=http://127.0.0.1:7799 \
GG_BINDINGS_PATH=~/ghost-gate-admin \
GG_BRIDGE_NETWORK=localnet \
  ghost-gate-bridge

# 3. the Lab
open http://127.0.0.1:7799/lab
```

`GG_ADMIN_HOSTNAME=localhost` is not decoration: WebAuthn requires a registrable domain as the
relying party, so a passkey cannot be created on an IP address. The dashboard detects an IP, says
so plainly, and disables the passkey buttons rather than showing a browser `SecurityError`.

## What is here

| Route | What it is |
| --- | --- |
| `/lab` | the Privacy Lab: gate picker, wallet picker, SIMPLE and TECHNICAL views, the privacy X-ray |
| `/lab/gates` | the authoritative gate list — public policy metadata only |
| `/lab/trace?attempt=…` | one attempt's sanitized event stream (the attempt id is the only key) |
| `/lab/simulate` | the labelled OFFLINE SIMULATION — issues nothing |
| `/admin` | the administrator dashboard: applications, gates, thresholds, tiers, sessions, audit |
| `/telegram/join` | the Telegram membership verification flow |
| `/access/check` | the integration point: token + application + gate → the server's decision |

## The two views

**SIMPLE** walks nine real steps — select a gate, select a wallet, request a challenge, request
authorization, submit, wait for consensus, verify against the published policy, grant or reject,
explain the session — with a plain-English "why this step exists" under the ones that matter.

**TECHNICAL** is a protocol inspector fed by the bridge: sequence numbers, relative timestamps,
source labels, severity, expandable JSON, search, severity filter, pause/resume, sanitized
copy/export. It shows what *happened*. It does not animate.

Both views are driven by the same events, so they cannot disagree.

## The privacy X-ray

Two panels per proof mode — **what the verifier learns** and **what stays private** — with an honest
note that the modes are *not* equally private:

* **Consensus (Ootle stealth fungible)**: the verifier learns a floor; the amount above it is never
  revealed; the transaction itself is public on chain.
* **Credential (browser wallet)**: a receipt names an output, so that output's public value is
  visible on chain — still no balance.
* **Native L1 XTM**: experimental. Shown, refused, never advertised as functional.

## Diagnostics are a security boundary

The inspector can only show what a **closed, server-side allowlist** constructs. There is no
pass-through, no generic map, and no exception text (a panic message can carry a path, a SQL
fragment or a secret). Every free-form string is minimised at the boundary: a label filter, then a
shape-based scrub that drops anything resembling a credential *whole* — a JWT, a long key run, an
`sk-`/`ghp_`/`Bearer` token.

Canary secrets are a test, not a promise: `a_canary_secret_never_reaches_a_trace` and
`a_value_with_the_shape_of_a_credential_is_dropped_entirely` in `crates/ghost-gate-bridge/src/trace.rs`.

The simulation is honest about being a simulation: it walks the same event constructors, stamps
every event `simulated: true`, contacts no wallet and no network, and has **no code path that can
mint a session at all** — a server test asserts the grant map is untouched.

## Who decides what

* The **administrator** publishes a versioned policy. The Lab reads it; it cannot change it.
* The **bridge** decides access, server-side, from the registry — never from the page.
* The **wallet** builds the statement. Its key, seed and balance never leave it.
* The **network** is the final authority for a consensus proof.
* The **page** shows what happened. It decides nothing.

A visitor cannot change a threshold, cannot manufacture a session, cannot read another visitor's
trace, and cannot turn the simulation into access.

## For judges without a testnet wallet

Press **Run the offline simulation**. It produces the full event sequence with its shape, severity,
provenance and verdict — and grants nothing. The badge and every event say so.

## Tests

```bash
cargo test --workspace        # 338 tests, including 127 bridge and 24 admin integration
scripts/admin_live_demo.sh    # the control plane end to end on one machine
scripts/browser_admin_check.sh # the admin dashboard in headless Edge, with a virtual passkey
```

## Repository map

| Path | What lives there |
| --- | --- |
| `crates/ghost-gate-core` | the no_std/WASM policy model: thresholds, tiers, versions, digests |
| `crates/ghost-gate-registry` | the authoritative store: applications, versions, sessions, audit, bindings |
| `crates/ghost-gate-admin` | the administrator dashboard, its auth, and its API |
| `crates/ghost-gate-bridge` | the serving/verification process: challenges, proofs, sessions, diagnostics |
| `crates/ghost-gate-telegram` | the membership bot: account binding, invites, revocation |
| `crates/ghost-gate-verifier` | the standalone Ootle verifier |
| `crates/ghost-gate-walletd` | the patched wallet adapter and the bridge binary |
| `web/lab` | the Privacy Lab page |
| `docs/GAME_PROVENANCE.md` | what the removed games were and where the third-party import is archived |

## Licence

This work is original. The one third-party codebase this repository ever imported (an MIT dungeon
crawler) was removed from the contest application; its full import, with its upstream MIT notice,
is preserved on the branch `archive-games-before-privacy-lab` for inspection. See
`docs/GAME_PROVENANCE.md`.
