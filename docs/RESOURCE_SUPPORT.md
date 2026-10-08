# Which resources a Ghost Gate can watch

**Ghost Gate works with any Ootle stealth fungible resource, identified by its resource address.
tTARI is one instance of that class, not a protocol special case.**

## The rule

A gate is configured with four things:

| Field | Meaning | Consensus role |
| --- | --- | --- |
| `resource` | Any **stealth fungible** resource address | The security identity of the asset. Bound into the challenge, compared against the gate's policy, and the address the engine resolves spent outputs under. |
| `threshold` | A raw `u64` in the resource's own smallest unit | Compared as an integer: `attested_minimum >= threshold`. |
| `network` | The Ootle cohort byte the gate is deployed on | Compared against the challenge's network byte. |
| `relying_site`, `session_commitment` | Opaque, bounded byte strings | Only ever compared, never interpreted. |

The threshold never passes through a floating point number, a decimal string, or a display format.
Divisibility is read from chain and stored so a UI can render the threshold the way a person would
write it; no rule reads it, and the gate's own accessor set keeps it visibly separate from `threshold`.

## What is supported, and why only that

Ghost Gate's guarantee is produced by a **bulletproof over `[minimum_value_promise, 2^64)`**. Only a
stealth resource has such a proof to produce. So the supported class is exactly:

```text
ResourceType::Stealth  ->  supported
ResourceType::Fungible  ->  refused at construction ("public fungible")
ResourceType::Confidential -> refused at construction ("confidential fungible")
ResourceType::NonFungible  -> refused at construction ("non-fungible")
```

The refusal happens in `GhostGate::new`, which reads the resource's own `ResourceInfo` from chain and
refuses by name. That is a deliberate choice over accepting the address and failing later: a gate that
accepted an NFT resource would deploy successfully, sit there accepting nobody, and tell its operator
nothing.

Each refusal names its class rather than just saying "unsupported", because "Ghost Gate only works with
stealth tokens" is something a user needs to hear at gate-creation time, not discover when their proof
keeps failing.

### Not claimed for the unsupported classes

- **Public fungible.** A threshold could be proven by an ordinary balance check, and the balance is
  already visible on chain. That is not this product, and no claim is made that it uses the same privacy
  proof. It does not.
- **Confidential fungible.** Values live in vaults and are revealed per output through
  `ConfidentialWithdrawProof`. There is no per-output `minimum_value_promise` to pin a floor to, so
  there is no bulletproof of the form the gate verifies. A confidential gate would need a different proof
  construction; none is implemented and none is claimed.
- **Non-fungible.** There is no amount to threshold. "Prove you own this NFT" is a different product
  with a different privacy model, not a special case of this one.

## Identity is the address, never the name

A resource's symbol and name are chosen by whoever creates it. `GHOSTTEST`, `tTARI` and
`definitely-not-tari` are all strings, all attacker-chosen, and none of them is checked by any rule.

What a gate binds to, what a challenge commits to, and what the engine resolves spent outputs under is
the **resource address**. The tests assert this directly:

- `a_gate_reports_its_own_resource_and_divisibility` -- the gate returns the address it was given and
  the divisibility it read off chain, and the rendered display never moves the raw integer;
- `two_gates_over_two_assets_report_different_resources` -- two gates over two assets report different
  resources, so a site reading the wrong gate cannot mistake one asset for another;
- `a_statement_spending_another_resource_is_refused_even_when_the_challenge_agrees` -- naming the wrong
  asset is refused by consensus, not by a name comparison.

## Why a cross-resource statement is impossible, not merely discouraged

A stealth UTXO's on-chain address is the pair `(resource, commitment)`. The engine resolves every spent
input under **the gate's own resource address**:

```rust
// crates/engine/src/runtime/working_state.rs, WorkingState::validate_and_spend_stealth_utxos
let address = UtxoAddress::new(resource_address, input.commitment.into());
```

So a first-asset output submitted to a second-asset gate resolves to a UTXO address that does not
exist, and the spend fails. Two consequences worth stating because they are easy to get wrong:

1. **The gate does not have to check the statement's resource.** It never looks at it. `qualify()`
   inspects only the promise on the qualifying output, so a statement promising the threshold in the
   wrong asset clears every one of the gate's own rules. The engine is what refuses it.
2. **A commitment is not resource-bound, but a UTXO is.** Two outputs minted with the same mask and the
   same value commit to the same Pedersen value under *either* resource, and a stealth spend key is
   derived from `(account key, nonce)` — neither of which mentions the resource. They are genuinely
   interchangeable at the crypto level and only distinguishable by which resource's address they are
   filed under. Test fixtures must therefore mint each asset with a *different* mask
   (`cross_resource.rs` does), or they will accidentally build two identical outputs and a cross-resource
   case will pass for the wrong reason.

## What each layer proves

The two layers are separate measurements and neither substitutes for the other.

| Layer | What it establishes | Where |
| --- | --- | --- |
| Consensus, in one process | Any stealth fungible resource, any divisibility: acceptance, the threshold boundary, cross-resource refusal, unsupported-class refusal, gate/site/session/threshold/network binding, replay. | `crates/ghost-gate-tests/tests/cross_resource.rs` (15 tests, under the real `tari_engine`) |
| Transport, over a real network | A validator executed and committed a proof for native stealth tTARI, and a validator executed and committed a proof for a resource created on chain. Receipts, counts and burnt nonces read back from committed state; replay refused. | `integration_tests/tests/features/ghost_gate.feature`, scenarios 1 and 2 |

### Case A on native tTARI is deliberately absent from the engine suite

Under the engine harness, the builtin XTR faucet pays a component into an aggregate stealth *vault
container*, not into individual stealth outputs. Measured directly during Phase 1: the faucet call
created **0 UTXOs** and left a container holding `1_000_000_000` units. A wallet therefore cannot come
to own a native tTARI UTXO under that harness at all.

A wallet comes to hold native tTARI the only way it can in reality — through a real transfer that
creates a UTXO — which is exactly what the localnet scenario does, and it has since the Gate 3
checkpoint. The two created resources in `cross_resource.rs` stand in for the *mechanism* being
resource-agnostic; the localnet covers the native asset over the real stack. This split is recorded
rather than papered over.

## Unsupported: proving a *total balance*

Ghost Gate proves that a witness controlled a qualifying input worth at least X at the moment a
validator committed a transaction. It does **not** prove:

- the prover's total balance, or that they hold nothing else;
- their identity, or that they are human;
- Sybil resistance — one person with many wallets can mint many sessions;
- continuous holding — the funds can be spent immediately afterwards;
- that they own *every* output in a wallet;
- their balance at any later time.

See `docs/PRIVACY_MODEL.md` and `docs/THREAT_MODEL.md`.

## Configuring a gate over a resource nobody has named

A site may gate an asset whose symbol it cannot resolve. The address is enough: `GhostGate::resource`
and `GhostGate::divisibility` are readable on chain, and `ghost_gate_verifier::display::Symbol::Unknown`
renders the bare number. An unlabelled asset is a normal case, not an error.