# Manual human test — Ghost Gate

**Status: NOT PERFORMED.** The wallet channel is implemented (`crates/ghost-gate-walletd`) and the
bridge connects to it, but no case below has been run: this environment has no standalone `walletd` to
point `GG_WALLETD_ENDPOINT` at, because the cohort's harness starts its wallet in-process instead. The
blocker is an environment, not missing code. This list is kept so the flow is defined before it is
attempted, and so nobody later reports it as done on the strength of the code existing.

## Preconditions

```bash
# 1. A localnet: base node, validator, indexer, miner. The cohort's integration_tests harness starts
#    these in process and is the easiest way to get a full stack.
scripts/ootle_e2e.sh -- --tags "@ghost_gate"

# 2. A standalone walletd for the same network. This is the piece the harness does not give you: it
#    starts its wallet inside the test process rather than listening on a port.

# 3. The bridge. Gate policy now comes from the ADMINISTRATOR DASHBOARD, not from an environment
#    variable: create the application and its gates at http://localhost:7811/admin, publish them, and
#    point the bridge at the same data directory. See docs/ADMIN_DASHBOARD.md. The bind address and the
#    origin list are still refused at startup if wrong, because a bridge with no origin allowlist is
#    the thing this design exists to prevent. (GG_BRIDGE_GATES remains supported for a single-gate
#    bring-up, but it is no longer the authority: with GG_BINDINGS_PATH set, the registry wins.)
GG_BINDINGS_PATH='~/ghost-gate-admin' \
GG_BRIDGE_NETWORK='localnet' \
GG_BRIDGE_ORIGINS='http://127.0.0.1:7799' \
GG_BRIDGE_BIND='127.0.0.1:7799' \
GG_WALLETD_ENDPOINT='http://127.0.0.1:5100/json_rpc' \
GG_MAX_FEE=100000 GG_MAX_EPOCH=100 \
cargo run -p ghost-gate-walletd --bin ghost-gate-bridge

# 4. Open http://127.0.0.1:7799 in the same browser, and manage policy at
#    http://localhost:7811/admin (a hostname, not an IP: passkeys require a domain).
```

The startup banner is the first thing to check. It must show a wallet line, not the "no wallet daemon is
connected" note:

```text
  wallet daemon: http://127.0.0.1:5100/json_rpc (network byte 16)
  wallet status: reachable=true default_account=true network=16 (localnet)
```

If `network=` disagrees with the byte in the gate spec, proofs will be refused until they agree, and
that is deliberate — a proof submitted to the wrong chain would be a valid transaction in the wrong
place.

The resource and threshold come from the gate's own on-chain state. Take them from the `@ghost_gate`
scenario's output rather than inventing them: the dashboard needs a resource **address**, and a
symbol in that field is refused at startup by design.

## Wallet choice, and which flow a case uses

The page offers three wallets, each probed from its own capabilities:

| Wallet | Where it works | Proof mode | Notes |
| --- | --- | --- | --- |
| **Sapient** (extension) | any tab, once installed | **credential** | local (seed) accounts only; a daemon-relayed account shows as unsupported |
| **Tari Universe** | only inside its app-catalogue iframe | **credential** | a plain tab is unreachable *by design*; the picker says so |
| **Local walletd** | this bridge + a running daemon | **consensus** | the developer backend; no daemon credentials are ever asked of a browser-provider user |

Per-wallet setup for the cases below:

- **Sapient**: install the extension, create or import a wallet, fund the account with at least the
  gate threshold of the gate's resource (the credential flow additionally needs XTR for the fee).
  Case 2's second form (wrong resource) needs a holding of some *other* stealth resource.
- **Tari Universe**: open the dApp from the app catalogue (never a plain tab), connect, fund as above.
- **Local walletd**: run the bridge with `GG_WALLETD_ENDPOINT` set, as in the Preconditions.

The cases are the same for all three; only the flow differs (credential mode shows a two-step
approval: the proof output first, then the challenge signature).

## The cases

| # | Setup | Expected | Where the evidence goes |
| --- | --- | --- | --- |
| 1 | Wallet holds ≥ threshold of the gate's resource | 👻 **ACCESS GRANTED**, "Minimum threshold proven. Actual balance not disclosed. Challenge consumed." | `GET /proof/:id/status` returning `state: accepted`, plus the `GhostGate.GG` receipt event |
| 2 | Wallet holds < threshold of the gate's resource | **ACCESS DENIED**, "The required threshold was not proven. Your exact balance remains private." | `state: refused` with the gate's own reason |
| 3 | Second (created) resource, wallet holds ≥ threshold | 👻 **ACCESS GRANTED** | same as 1; the receipt names the same floor |
| 4 | Wallet holds the wrong resource only | **ACCESS DENIED** | `state: refused`; consensus refused the cross-resource spend |
| 5 | Replay: reuse the challenge that case 1 consumed | **ACCESS DENIED**, "Challenge already used. Request a fresh challenge." | `409` from `POST /gate/:id/prove` |
| 6 | Wait out the challenge TTL, then answer | **ACCESS DENIED**, "Challenge expired." | `409` with `challenge has expired` |

## Credential-mode specifics to watch (Sapient / Universe)

- The wallet's own approval screen must show the **public and permanent** disclosure for the
  minimum-value-promise output. If it does not, that is a wallet bug; note it, do not work around it.
- The page must never request view access. If a view-access prompt appears, the flow is wrong.
- The bridge's verdict must name the on-chain floor (`attested_minimum` read from the substate), not
  the amount the page asked for.
- A rejected request in the wallet (code 4001) must land as "REQUEST DECLINED" with nothing
  submitted — not as an error and not as a denial of the gate.
- Re-running the flow with the same output must be refused as an answered challenge; re-running with
  a fresh output must work. That is the single-use property, per mode, on a real wallet.

## What to capture for each

- The browser's Network tab: the request and response bodies. They should contain no balance, no key,
  no mask and no UTXO identifier — and if one does, that is a bug, not an observation to note quietly.
- `GET /wallet/status`, which reports reachability and cohort and nothing else.
- The gate's own on-chain readback: `GhostGate::resource`, `GhostGate::threshold`,
  `GhostGate::proofs_accepted`, `GhostGate::is_nonce_used`.
- For an accepted proof, the `GhostGate.GG` event payload decoded into `ProofReceipt`.

## Cases that must also pass and are easy to forget

- A page on an origin **not** in `GG_BRIDGE_ORIGINS` gets `403` on every route, including `/health`.
- `GET /wallet/balance`, `GET /wallet/utxos` and `GET /gate/:id/keys` return `404`.
- A prove request carrying an extra `amount` or `utxos` field is refused and never reaches the wallet.
- A prove request carrying `utxo_address` is refused **by name**:
  `unknown field \`utxo_address\`, expected one of \`gate_id\`, \`challenge_nonce\`, \`session_commitment\``.

## Case 2 has a second form worth running

Case 2 assumes the wallet holds *less* than the threshold, so the adapter finds no qualifying output and
returns `GG: no unspent output of <resource> holds at least <n>` before any statement is built. Run the
variant where the wallet holds a qualifying output **of a different resource**: the adapter will find
nothing for the *gate's* resource and refuse the same way. Neither path may reach consensus, and
neither may name a UTXO in its error.

## The Privacy Lab manual pass

1. **Open the Lab** — `http://127.0.0.1:7799/lab` (hard-refresh: Ctrl+Shift+R).
2. **Status strip (above the fold)** — six honest pills. BRIDGE must read `healthy`; NETWORK shows
   the cohort (wallet-reported, else the registry byte); WALLETD reads `not reachable` when no
   daemon is up — say it plainly, never "connecting"; INDEXER reads `not configured` or
   `configured` (configuration, NOT a sync claim); MODES lists what can run with `XTM blocked`;
   GATES counts the published gates.
3. **Proof target card** — the gate picker lists gates sorted by threshold ascending. The card's
   dominant number is `≥ <human> <symbol>`; raw units and divisibility sit beside it; the resource
   truncates with a hover title and a COPY button that really copies; mode and session state are
   badges. For an activatable gate the availability badge must be invisible.
4. **Choose how you will prove** — with no walletd the note must be a short, warn-colored pill:
   "Wallet daemon not reachable. Start walletd or choose another supported proof method."
5. **Run the offline simulation** — the outcome says SIMULATED GRANT and grants nothing; switching
   to TECHNICAL shows the inspector with the simulation banner and 11 events, each with a truthful
   source label. PAUSE/COPY/EXPORT work; the filter narrows rows; PAUSE stops auto-scroll.
6. **Inspector empty state** — before any attempt, the terminal shows the prompt plus the four
   event categories (bridge/wallet/consensus/verifier) ghosted as LABELS — never fabricated logs.
7. **Telegram section** — with no Telegram-scoped gate, the card is dimmed with a "NOT
   CONFIGURED" chip and the button is disabled and relabelled. Scoping a gate to Telegram in the
   dashboard and refreshing must re-enable it with the gate's name in the note.
8. **Negative path** — press Prove access with no walletd: the bridge refuses; the outcome is a
   clean denial with the bridge's own reason. Nothing may pretend a proof happened.
9. **Responsive** — 390×844: no horizontal overflow, no sideways scroll, the two columns stack
   with the proof target first. prefers-reduced-motion must suppress the edge animation entirely
   (DevTools rendering emulation, then check `#matrix-edges` is empty or static).

## The question this test is really asking

Not "does it work" — that is the engine suite and the localnet. The question is whether a person can
look at this and correctly believe three things: their balance was not disclosed, their funds did not
move to anyone, and the interaction is public on chain. If any of those three is not visible without
reading source, the UI is wrong however well the tests pass.