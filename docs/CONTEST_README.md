# Ghost Gate — The Haunted Vault (contest README)

**The pitch:** a token-gated haunted experience where the *only* thing that opens a door is a
genuine private proof the network verifies — never a password, never a balance reveal, never
client-side trust-me. The same verified backend powers a Telegram bot that grants expiring,
re-verifiable community membership.

This document is the honest feature map: what works, what is demonstrated where, and what is
blocked and why. Security state lives in `docs/SECURITY_RELEASE_GATE.md`; the full audit in
`docs/SECURITY_AUDIT_FULL.md`.

---

## Quick start (demo machine)

```bash
scripts/start_vault.sh                    # builds and starts the bridge with the three gates
# then open http://127.0.0.1:7799/game
```

The game boots in **preview mode** on a machine with no wallet/chain: clearly labelled, mints
nothing, and every door can be walked through to see the puzzles, lore, relics and the
door-opening sequence. Preview never calls the challenge/proof/credential routes — asserted by a
web test.

Real proofs additionally need a standing localnet (next section).

## What works (and where the evidence is)

| Feature | Status | Evidence |
|---|---|---|
| Consensus-proof mode (Mode A) through walletd | **WORKING** | `@ghost_gate` localnet scenario: 2 scenarios / 48 steps green (docs/GATE3_RESULTS.md); the engine enforces the threshold — see the audit |
| Credential-proof mode (Mode B) through browser wallets | **IMPLEMENTED, unrun live** | 20 credential-verifier tests (byte-exact framing, on-chain key binding, unspent + merkle-verified checks); needs a browser + wallet to execute end to end |
| The Haunted Vault game | **WORKING (preview + real-proof wiring)** | served at `/game`; thresholds from the bridge's `/gate/:id`; two verified proof paths wired (consensus via walletd, credential via browser wallets); puzzles/relics/lore/secrets/animations complete |
| Telegram token-gating POC | **IMPLEMENTED, unrun live** | 8 lifecycle tests (single-use tokens, TTLs, wrong-gate refusal, revocation, replay idempotence); the join flow is served by the bridge and runs the credential mode |
| Soundness of the consensus rule | **PROVEN** | 11 real-engine forgery attempts refused (`crates/ghost-gate-tests/tests/adversarial.rs`) |
| Bridge transport security | **PROVEN** | Host allowlist (DNS rebinding), origin + issuer binding, challenge/job caps, deny-unknown-fields, bounded parsing — 91 bridge tests |
| GHSA backports on the pinned cohort | **ACTIVE** | `scripts/verify_patches.sh` green; the backport's regression passes in the engine's 48 |
| Demo page (developer API walkthrough) | **WORKING** | `/` — wallet selection by capability, both flows |

## What is blocked, and precisely why

| Feature | Blocker | Unblocks when |
|---|---|---|
| Live browser-wallet runs (Sapient / Tari Universe) | No browser or extension in the build environment | Run `MANUAL_TEST.md` on the demo machine with the extension installed |
| Live Telegram run | Needs a real bot token (`@BotFather`) and a community chat | Set `GG_TG_BOT_TOKEN` / `GG_TG_CHAT_ID` and run `start_vault.sh --with-telegram` |
| Native L1 (XTM) proofs | Two upstream gaps: no L1 dApp surface in Tari Universe Web (source-verified); Minotari wallet gRPC signs with the node-identity key only (`docs/XTM_RESEARCH.md`) | Upstream exposes an L1 signing surface or a spend-key `SignMessage` variant |
| Credential proofs against an uncontrolled indexer | The indexer's `verified` flag is its own software's bit; a compromised indexer could forge values (audit F-04 scope note) | Upstream exposes proof bytes for client-side merkle verification |
| Mainnet anything | The cohort is pinned at v0.42.0 testnets; upstream GHSA-rr6w-w4r5-9fcx (account bricking) is unfixed upstream | The release gate's re-pin procedure, after a fixed upstream release |

## Standing localnet (for real proofs on the demo machine)

The Gate 3 harness (`scripts/ootle_e2e.sh`) starts a full network **in-process and tears it
down**; it is the evidence source, not a standing backend. For standing real proofs:

1. Start a persistent localnet stack (base node, validators, indexer, miner) from the cohort, then
   `walletd` pointed at it. The cohort's own tooling is the reference; this repo does not ship its
   own node.
2. Deploy three Ghost Gate components over one stealth resource at the three thresholds
   (`100000`, `500000`, `2000000` — example values, configurable, not protocol limits) and register
   them with the bridge:

   ```bash
   GG_BRIDGE_GATES='crypt=<gate1>:<resource>:100000:6:GHOST,vault=<gate2>:<resource>:500000:6:GHOST,abyss=<gate3>:<resource>:2000000:6:GHOST' \
   GG_WALLETD_ENDPOINT='http://127.0.0.1:<walletd port>/walletd' \
   scripts/start_vault.sh
   ```

   Each gate's address and the resource address come from your deployment output; the game reads
   the terms from the bridge, never from the page.
3. Fund the demo wallet with the resource; break the seals in the game.

For the Telegram bot the same gates serve; `GG_TG_GATE` picks which one gates the community.

## Architecture (who trusts whom)

```text
Browser (game / demo / telegram join page)
   │  same-origin, loopback, Host+Origin allowlist, issuer-bound challenges
   ▼
ghost-gate-bridge  (the verifier: consensus-mode driver + credential verifier + policy)
   │                                   │
   │ walletd JSON-RPC                  │ indexer REST (merkle-verified answers only)
   ▼                                   ▼
walletd (holds keys; signs)        chain state (public facts)
   ▼
Ootle (consensus: engine-validated stealth transfer — the threshold's real boundary)
```

- The **engine** enforces the threshold: bulletproof over claimed MVPs, balance proof over the
  public excess, input resolution scoped to the gate's resource, authorisation before spend.
- The **bridge** never holds keys and never learns a balance; its API cannot carry a UTXO
  identifier in either direction (tested).
- The **bot** trusts only the bridge's receipts, binds each proof to one Telegram account, and
  revokes on expiry.
- **Nothing** asks for a seed, a private key, or an exact balance — anywhere in the stack.

## Security summary (one paragraph)

An adversarial audit (branch `security-audit`) reproduced the previously-reported forged-statement
attack against the real engine and **refuted it** — the engine's native stealth-transfer
validation enforces the threshold, and eleven attempts to forge, mutate, substitute or replay
statements all fail with no state changes. It then found and fixed four real issues of its own
(DNS-rebinding confused deputy, unbounded challenge memory, a dead reconciliation path that left
consensus proofs unfinished over HTTP, and a session commitment that was bearer knowledge), plus a
credential-verifier trust gap now gated on merkle-verified indexer answers. Full trail:
`docs/SECURITY_AUDIT_FULL.md`, `SECURITY_FINDINGS.md`, `SECURITY_FIXES.md`, `SECURITY_RELEASE_GATE.md`.

## Test map (what a reviewer should run)

```bash
bash scripts/web_tests.sh                                            # provider adapters + game invariants
cargo  --config 'build.target-dir="/home/pdark/gg-ootle-target"' \
       test --workspace                                              # bridge, core, engine-backed suites
cd ../_ootle-v042-ghost-gate && cargo test -p tari_engine --test access_rules   # GHSA backport
bash scripts/verify_patches.sh                                       # cohort patch provenance
scripts/ootle_e2e.sh -- --tags "@ghost_gate"                          # the localnet scenario
```

Counts at the time of writing: workspace 210+, engine access_rules 48, web 21, telegram 8, bridge
91 — all green. The `gate3-green` checkpoint tag (1a0b2824) is untouched.
