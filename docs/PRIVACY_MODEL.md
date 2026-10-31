# Privacy model

What Ghost Gate hides, what it publishes, and what it is not. Read this before describing the
product to anyone, including users.

## The claim, precisely

> At the moment the proof transaction committed, the transaction's signer controlled at least the
> gate threshold of the gate's resource, and proved it without revealing the exact amount.

Every word of that sentence is load-bearing. In particular it says **at least X**, **at access
time**, and **without the exact amount**. It does not say "worth X", "worth more than X", or
"continues to be worth X".

## What stays hidden

**The exact value behind the qualifying output.** The bulletproof proves `value ∈ [MVP, 2^64)`
without revealing which value in that range it is. A holder of 10,000 and a holder of 10,000,000
produce identical public data. This is the product.

**The exact wallet balance.** Ghost Gate never sees it. The prover assembles their own statement
from their own UTXOs; the gate sees one output's public promise and the count of inputs consumed.

**Direct ownership information.** The qualifying output's ownership is a one-time stealth key
derived from the owner's account key and a sender nonce. The encrypted value and mask are readable
only by the owner's view key.

## What becomes public

This is the part that is easy to gloss over and must not be.

**That a Ghost Gate transaction occurred.** Publicly visible, permanently. The transaction's shape
and the fact that it called a gate component are on chain.

**Which gate.** The `GhostGate` component address, its threshold and its resource are public state.

**The public lower bound.** `minimum_value_promise` is public by construction — the bulletproof
commits to it. The gate's threshold is effectively revealed by any successful proof, and it is
stored in the component state regardless.

**Timing.** When the proof was submitted, and when it committed.

**Ordinary transaction metadata.** Inputs consumed (as opaque commitments), the output created, the
fee paid. Stealth outputs hide values and ownership, not the existence of a transaction.

**Possible input/output relationships.** Whether a given input was consumed by a gate proof, and
which output replaced it.

**Activity statistics.** Over time, an observer sees how many proofs a gate accepted, and at what
public bounds.

## Correlation is unavoidable, and a relying site knows it best

A relying site that issued a challenge at 14:02:03 sees the gate transaction commit at 14:02:20 and
the browser redeem at 14:02:21. It can correlate all three trivially, because it issued the first
and observes the third.

The same observer can correlate two proofs from the same browser by session, and can correlate
challenge issuance with transaction submission because it holds both records.

**Do not describe Ghost Gate activity as anonymous.** It is value-private, not unlinkable.

## Population leakage

Successive proofs from the same wallet are visible as separate transactions with separate public
promises. If the promises are tracked across transactions, they accumulate lower-bound information:
each proof is a fresh, dated statement about that wallet's holdings at that moment. Nothing in the
protocol prevents a prover from always promising the same bound, and nothing prevents an observer
from noticing that they do.

Conversely, if a prover always promises exactly the threshold, observers learn only that they met
the bar — which is the intended outcome.

## Cross-gate leakage

A wallet that proves against several gates produces several transactions. Whether they can be
linked depends on the gates:

- **Same gate, repeated use:** outputs from an earlier proof become inputs to a later one. Linkable
  by a party that observes both the specific UTXO commitments and the fact of reuse.
- **Different gates:** no on-chain link exists between the qualifying outputs as such, because the
  outputs are fresh and independently encrypted. But the *wallet* is the same actor, and if the
  relying sites share information, or if a single site observes both, the link is immediate.
- **Same site, two browsers:** the site can link them if it correlates sessions. The session
  commitment binds a proof to the session that requested it, so a proof cannot be *redeemed* in
  another session — it does not prevent the site from noticing two of its own challenges were
  answered.

## What Ghost Gate explicitly does not claim

- **Invisible gate usage.** False. The transaction is public.
- **Permanent eligibility.** False. The claim is about access time. A user who qualifies once and
  spends the funds has not qualified for anything afterwards.
- **Current holdings.** False. By the time a session is used, the funds may be gone.
- **Total wallet balance proof.** False, and cannot be. A prover could hold 10,000 in one wallet and
  nothing elsewhere, or 10,000 spread across a dozen fragmented UTXOs; both satisfy the gate. The
  gate proves a lower bound on the value *moved in this transaction*, which is the natural reading of
  "you control enough", but it is not a balance attestation.
- **Proof of identity.** False. No key, address or credential is bound to a person.
- **Proof of unique humanity.** False. One person with ten wallets passes ten times.
- **Sybil resistance.** False, and it is not a design goal. Ghost Gate is a wealth threshold, not a
  personhood proof.
- **One wallet, one person.** False, as above.
- **Inability to move or reuse the funds later.** False. The proof output is the prover's to spend.
- **Network anonymity.** False. Nothing here touches network-level privacy.

## The honesty constraint that shaped the design

`ghost-gate-core::find_qualifying_output` requires exactly one stealth output, and refuses anything
ambiguous rather than picking. A statement with two qualifying outputs has two answers to "which one
was the proof", and no consensus rule to choose between them. Guessing there would be a
correctness bug that reads as a privacy property.

The same reasoning drives the refusal to accept a revealed output, and the requirement that the
qualifying output be key-spendable rather than locked in a condition tree.

## Privacy refresh

After a gate proof commits, the qualifying output still carries a public promise of at least the
threshold. That beacon rides along on the user's current coin.

`ghost-gate-wallet::refresh_output_witness` builds an ordinary self-transfer output with
`MVP = 0`, consolidating the funds and dropping the public bound.

What this achieves: the persistent disclosure attached to the *current* output goes away.

What it does not achieve: **history is unchanged.** The gate transaction, its promise and its timing
remain on chain forever. A refresh does not make past gate use disappear; it stops the beacon from
propagating forward.

## Session freshness: two different clocks

| | Challenge TTL | Session TTL | Example |
|---|---|---|---|
| Bounds | how long the user has to produce a proof | how long the site trusts the result | 3 min / 1 h |
| Enforced by | consensus (`Consensus::current_epoch`) | the relying site | |
| Claim | control existed *around login time* | | |

With a 3-minute challenge TTL and a 1-hour session TTL, the honest claim is:

> the user proved control of sufficient funds around login time.

It is **not**:

> the user continuously owned sufficient funds for one hour.

Anyone who spent the funds thirty seconds after proving still has a valid session. That is a
deliberate, documented property of the design, not an oversight: shortening the session TTL to match
the challenge TTL would mean re-proving on every page load, which no site wants and no user would
accept.

## Cross-network binding is weaker than intended

The gate stores the network byte it was deployed for (`GhostGate::new`'s `network` argument) and
compares the challenge's network byte against it. A template has no host call that reports the network
(`docs/V042_SOURCE_TRACE.md` finding 31), so this catches a *prover and gate disagreeing* about the
network and nothing more.

Detecting a transaction admitted on the wrong chain belongs to the validator, outside Ghost Gate's
reach. The statement is "this challenge and this gate agree on the network byte", not "this transaction
was validated on network X". Recorded as a residual risk in `docs/THREAT_MODEL.md`.

**What changed from a single constant, and why it matters.** An earlier revision compared against a
compile-time `NETWORK_BYTE`. That constant was wrong: it was `0`, which in Ootle's `Network` enum is
`MainNet`, while its own doc comment claimed it named the Esmeralda testnet (`0x26`). Nothing caught it
because both sides of every comparison used the same wrong value, so every test passed. The same
template WASM is published on every cohort, so a single baked-in byte cannot be correct for more than
one of them. Each deployment now names its own cohort at construction, and
`ghost_gate_core::network` names each byte explicitly so a reader can check it against the enum.

The weakness described above is unchanged and is not fixed by this: it was never the constant that
limited the check, it was the absence of an observable network.