# Gate 4 — real wallet UX

## Verdict: PARTIAL — the wallet channel is implemented, but no proof has been completed against a live walletd

Gate 4 asks whether a user can understand what they are approving. It is deliberately sequenced last
because it cannot be answered honestly until Gate 3 is green: without a wallet that can build a Ghost
Gate transaction, there is nothing for a user to approve.

| Piece | State |
| --- | --- |
| The local bridge's security policy (gate registry, one-use challenges, request validation, origin allowlist) | **PROVEN**, 64 tests |
| The bridge's HTTP surface, including the routes that do *not* exist | **PROVEN**, tested |
| No UTXO identifier can cross the API in either direction | **PROVEN**, a test sweeps all eight routes |
| The demo page, and the privacy boundary expressed as an API surface | **PROVEN** by construction; not run against a wallet |
| The `WalletChannel` implementation against `walletd` (`crates/ghost-gate-walletd`) | **IMPLEMENTED**, compiles clean, 4 tests; drives the same JSON-RPC surface the localnet scenario drove |
| A completed proof, end to end, against a live `walletd` | **NOT PERFORMED** — this environment has no walletd to run one against |
| The manual human test (six cases) | **NOT PERFORMED**, for the same reason |
| What a user sees on the *wallet's* approval screen | **NOT ASSESSED** — unchanged from the original analysis below |

The honest one-line summary: the adapter exists, refuses the one input strategy that cannot work, and
keeps every wallet identifier inside the local process — but nothing has yet proved it against a live
daemon, so the manual flow is still **blocked on a walletd to run against**, not on missing code.

## The requirement

A user must be able to tell, from the approval screen, that:

```text
GHOST GATE

Private Access Proof

Requirement:
≥ 10,000 tTARI

Sent to another person:
0 tTARI

Your qualifying funds:
Remain under your control

Network fee:
<actual fee>

Exact balance revealed:
No

Public Gate interaction:
Yes

[ APPROVE PROOF ]
```

The line that matters most is the last one. A wallet that renders only "Spend 30,000 TARI" for a
transaction that moves nothing to anyone would be actively misleading, even though the transaction is
benign.

## What stock walletd displays — verified from source

Not verified. The request types in `clients/wallet_daemon_client/src/types.rs` and the manifest
generator (`crates/transaction_manifest/src/generator.rs`) describe amounts; whether walletd renders
them with application-level semantics is not established by anything read in this run, and no
walletd UI was run.

Recorded as unknown rather than guessed.

## Why the generic display is likely to be wrong

From `docs/V042_SOURCE_TRACE.md` findings 23 and 25, the flow is:

1. `accounts.create_stealth_transfer_statement` — the caller names blinded amounts.
2. `transactions.submit_instruction` — the caller supplies instructions; walletd builds, prices and
   signs.

The wallet sees a set of stealth inputs, one stealth output with a public promise, and a
`CallMethod` to a component it does not recognise. It has no field in the request for "this is a
threshold proof; render it as such".

The realistic generic rendering would be something like:

```text
Spending 30,000 tTARI
```

which is **wrong in substance** even though it is right in arithmetic: the 30,000 does not leave the
user, and "spending" invites the belief that it does.

## What would be needed

Three options, in increasing order of honesty:

**A dedicated walletd approval screen** for `CallMethod` to a known gate template. Requires walletd
to know about Ghost Gate, which couples it to one application. Rejected.

**An application-provided manifest or transaction-request description.** walletd already has a
`transactions.create` / `approve` / `reject` flow
(`applications/tari_walletd/src/server.rs:175-180`). If a transaction request could carry a
human-readable description supplied by the relying site, walletd could render that instead of
inferring semantics. Needs verification that the request type has, or can have, such a field.

**A separate approval surface in Ghost Gate's own frontend**, with walletd as a signing service
behind it. Honest about who is asking for what, but it means the approval screen is not the wallet's,
and users must be told that clearly.

## The design constraint either way

Whatever is rendered must include, without being asked:

- the gate threshold in the gate's resource;
- that the qualifying funds stay under the user's control;
- that the transaction is public;
- that the exact balance is not revealed;
- the actual fee.

A UI that omits "Public Gate interaction: Yes" to make the flow feel smoother is misrepresenting the
product. `docs/PRIVACY_MODEL.md` says the transaction is observable; the approval screen has to say
so.

## The bridge, and what is and is not proven

`crates/ghost-gate-bridge` is the local half between a relying site and `walletd`.

```text
Browser / relying site
        |
        |  public gate metadata, public challenge
        v
Local Ghost Gate bridge      127.0.0.1 only, explicit origin allowlist
        |
        |  authenticated local wallet control
        v
walletd
        |
        v
Ootle
```

### Endpoints

```text
GET  /health                 service, version, the gate ids served, live challenge count
GET  /wallet/status          whether a wallet is reachable, and on which cohort
GET  /gate/:id               public metadata: gate address, RESOURCE ADDRESS, threshold, divisibility
POST /gate/:id/challenge     mint a fresh single-use challenge, with a session commitment
POST /gate/:id/prove         ask for a proof; returns a job id
GET  /proof/:id/status       accepted / refused / still working
GET  /, /app.css, /app.js    the demo page, same origin as the API
```

There is deliberately **no** route for balances, UTXOs, inventory, keys, statements, or anything that
spends. `http.rs` has a test that walks a list of such paths and asserts each one is
`Route::NotFound`, because "we do not expose it" is a claim about a surface and the surface is what
should be asserted.

### The privacy boundary, as code

Three things make it structural rather than a promise:

1. **`ProveRequest` has three fields**: `gate_id`, `challenge_nonce`, `session_commitment`. There is no
   field for an amount, a destination, a resource or a UTXO, so there is nothing to validate away. A
   test asserts the serialised form is exactly those three keys.
2. **`PublicProof` has eight fields**, none of which can hold a key, a mask, a balance, a decrypted
   value or a UTXO identifier. A test asserts the exact serialised JSON.
3. **The resource and threshold the wallet is asked for come from the registry**, not the request. A
   test asserts the fake wallet was asked for `(gate.resource, gate.threshold)` and that the selection
   sent was `InputChoice::Named(vec![])` — an empty named set, which is how a request body expresses
   "no input specified". A second test asserts the server *never* constructs
   `InputChoice::WalletSelected` and never names a non-empty input, so nothing from the caller can
   become a UTXO.

Two further properties are asserted rather than described:

- **No route can return a UTXO identifier.** One test walks all eight routes — including a refused
  request, a pending proof and an *accepted* proof — and requires that no response body contains a
  `utxo_` prefix. A regression fails there rather than in review.
- **A request naming a UTXO is rejected by name.** `ProveRequest` is `deny_unknown_fields`, so
  `{"utxo_address": "utxo_deadbeef"}` comes back as `unknown field \`utxo_address\`, expected one of
  \`gate_id\`, \`challenge_nonce\`, \`session_commitment\``.

Five server tests each attempt to add an `amount`, `utxos`, `destination`, `resource` or `threshold` to
a prove request; all five are refused and the wallet is asserted **not** to have been called.

### The live channel

`crates/ghost-gate-walletd` implements `WalletChannel` against a running `walletd`. It is a separate
crate because it needs the walletd client, the wallet SDK and the transaction builder: keeping those
out of `ghost-gate-bridge` is what lets the bridge's 64 policy tests compile without the SDK in the
graph. The bridge process moved into that crate as its binary, because a binary needs both sides and
the dependency runs bridge → walletd; the binary is still called `ghost-gate-bridge`, so nothing that
invokes it changes.

The adapter drives the same JSON-RPC surface the localnet scenario drove rather than a
re-description of it:

```text
stealth_utxos_list                    -> candidates: the gate resource's own unspent outputs
accounts_create_stealth_transfer_statement
                                      -> a statement spending exactly one of them, with the gate's
                                         threshold as the output's minimum_value_promise
submit_transaction (under the lock)   -> the wallet derives the stealth signers itself
wait_transaction_result               -> consensus's verdict
```

One detail makes this cheap: the `StealthTransferStatement` the client returns is the *same*
`tari_template_lib_types` type the trait already used, so there is no conversion layer on the
boundary. And the attested minimum and input count are decoded from the committed `ProofReceipt`,
which `ghost-gate-core` declares and derives bor's `Decode` for — nameable even though the template
itself is WASM, and a compile error rather than a silent zero if the template's return type changes.

Startup is honest about what is connected: with `GG_WALLETD_ENDPOINT` unset the process serves its
public routes and prints that proofs cannot be completed; with it set but nothing listening, it prints
the connection error and a warning, and every wallet route reports the failure per request.

**What is still not proven.** No proof has been completed against a live walletd. This environment runs
the cohort's cucumber harness, which starts its own wallet in-process, so the adapter is exercised by
that scenario's RPC shape and by four unit tests — not by a completed manual run. The manual flow

```text
start Ootle -> start walletd -> start bridge -> open browser -> connect -> load gate
-> request challenge -> approve -> submit -> observe -> ACCESS GRANTED -> replay -> refused
```

has therefore not been observed end to end. Claiming otherwise would be the single most dishonest
thing this document could do.

### Why wallet-chosen inputs are refused rather than wired up

`InputChoice::WalletSelected` is what a finished product would use: the wallet picks, the site learns
nothing. It cannot be implemented today, and the reason is the engine rather than this bridge:

1. **A spent input is resolved under the gate's resource.** The gate qualifies a proof by finding the
   statement's commitment among that resource's outputs. If the wallet spends an input of a different
   resource, the engine finds nothing and consensus refuses.
2. **A transaction must declare every substate it spends.** The same transaction that carries the
   statement has to declare the UTXO the wallet chose.

Together these mean a wallet that chooses freely cannot produce a transaction that *names* its choice,
because the choice is never communicated to the builder. Every such proof would be refused at
consensus, after burning the inputs and the challenge. So the adapter returns
`WalletError::WalletSelectionUnsupported` **before any wallet call** — asserted through the real
adapter against an unreachable wallet, which distinguishes "refused the selection" from "could not
reach the wallet". No engine check is weakened to make the path work.

What the adapter does instead is the two-stage shape, locally:

1. the wallet selects qualifying outputs internally, via `stealth_utxos_list` on the **gate's**
   resource address;
2. the exact selected output's versioned requirement goes to the **trusted local** builder, which
   declares it as a transaction input;
3. the wallet signs and submits under its own lock;
4. the relying site receives only `attested_minimum`, `input_count` and a transaction id.

Steps 1–4 are what the code does today, except that the selection is made by the adapter rather than by
a separate wallet-side planning call. The missing capability is narrow and worth naming precisely: a
wallet-side RPC that returns the inputs it *would* choose for a statement, without building one, so the
choosing and the declaring are done by the wallet rather than by the bridge re-deriving it.
`stealth_utxos_list` is the closest thing present, and it hands the decision to the caller. Adding it
means a wallet-side selection endpoint, not a protocol change.

This is a **local bridge** property, not a privacy claim about the chain: which output was spent is
visible on chain to anyone who reads it, and picking the smallest qualifying output is a heuristic
about what that reveals, not a guarantee. See `docs/THREAT_MODEL.md`.

### Why the demo page is served by the bridge

The page is served from `/` on the bridge itself. If it were served from anywhere else the browser
would need CORS to reach the API, and a CORS-enabled wallet bridge is a wallet bridge every page in the
browser can reach. Same origin is the mitigation; the origin allowlist is the second one.

## The demo page

`web/` is plain HTML, CSS and JavaScript with no build step and no framework. It renders the gate's
resource **address** alongside the symbol, formats the threshold from the raw integer and the
divisibility the gate reported, and moves through preparing → wallet approval → submitting → waiting →
granted/denied. The create-gate form shows the specification and states plainly that publishing it is a
chain transaction the bridge did not submit — it has no connection that could authorise one.

It is not a claim that a human has been through the flow. It is the surface a human would use, once
the wallet channel exists.

## The manual human test

`docs/MANUAL_TEST.md` lists the six cases that must pass. **None of them has been performed.** The
blocker is no longer missing code — it is that this environment has no standalone `walletd` to point
`GG_WALLETD_ENDPOINT` at; the cohort's harness starts its wallet in-process instead. The list is kept,
and the honest status is that it is unrun.

## Open

Not started. Gate 3 first — there is nothing to approve yet.