# Gate 4 — real wallet UX

## Verdict: NOT ASSESSED

Gate 4 asks whether a user can understand what they are approving. It is deliberately sequenced last
because it cannot be answered honestly until Gate 3 is green: without a wallet that can build a Ghost
Gate transaction, there is nothing for a user to approve.

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

## Open

Not started. Gate 3 first — there is nothing to approve yet.