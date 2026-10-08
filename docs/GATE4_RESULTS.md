# Gate 4 — real wallet UX

## Verdict: PARTIAL — the bridge and the page exist and the policy is proven; the live wallet channel is not wired

Gate 4 asks whether a user can understand what they are approving. It is deliberately sequenced last
because it cannot be answered honestly until Gate 3 is green: without a wallet that can build a Ghost
Gate transaction, there is nothing for a user to approve.

| Piece | State |
| --- | --- |
| The local bridge's security policy (gate registry, one-use challenges, request validation, origin allowlist) | **PROVEN**, unit- and integration-tested |
| The bridge's HTTP surface, including the routes that do *not* exist | **PROVEN**, tested |
| The demo page, and the privacy boundary expressed as an API surface | **PROVEN** by construction; not run against a wallet |
| The bridge's `WalletChannel` implementation against a live `walletd` | **NOT WIRED** — see below |
| What a user sees on the *wallet's* approval screen | **NOT ASSESSED** — unchanged from the original analysis below |

The honest one-line summary: everything that decides whether a website can spend from someone's wallet
is built and tested; the part that talks to a wallet is not connected, and the manual end-to-end flow a
developer would want is therefore **blocked on that one piece**.

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
   test asserts the fake wallet was asked for `(gate.resource, gate.threshold)` and that
   `InputChoice::WalletSelected` was used, so input selection stays with the wallet and the site is not
   told what it chose.

Four server tests each attempt to add an `amount`, `utxos`, `destination` or `resource` to a prove
request; all four are refused and the wallet is asserted **not** to have been called.

### What is not wired, and why it is stated plainly

`wallet::WalletChannel` is a trait. `server.rs` is written against it and is fully exercised by
`tests/server.rs` through a fake. The production implementation, which would speak real `walletd`
JSON-RPC, is **not implemented**:

- `main.rs` wires a `NoWallet` channel that returns `WalletError::Unreachable`. The process starts,
  serves `/health`, `/gate/:id` and `/gate/:id/challenge`, and prints a note to stderr saying so.
- The fake in the tests is a stand-in for an *external service*, which is a legitimate thing to fake —
  the bridge's policy is what is under test, not consensus. The consensus claim belongs to the
  `@ghost_gate` localnet scenario and to `gate_engine.rs`.

So the manual flow

```text
start Ootle -> start walletd -> start bridge -> open browser -> connect -> load gate
-> request challenge -> approve -> submit -> observe -> ACCESS GRANTED -> replay -> refused
```

runs **as far as "challenge issued" and then stops**, because there is no wallet to answer it. Claiming
that flow as working would be the single most dishonest thing this document could do.

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

`docs/MANUAL_TEST.md` lists the six cases that must pass. **None of them has been performed**, because
every one of them needs a reachable wallet. The list is kept, and the honest status is that it is
unrun.

## Open

Not started. Gate 3 first — there is nothing to approve yet.