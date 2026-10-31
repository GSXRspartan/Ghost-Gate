# Gate 3 ? ordinary wallet E2E

**The gate that decides whether this product exists.**

## Generalisation re-measurement, 2026-10-07

The `@ghost_gate` scenario was re-run after the Gate 4 generalisation commit (`b69e34a`), on the same
cohort, with the same harness, and now covers **two scenarios**:

```text
scripts/ootle_e2e.sh -- --tags "@ghost_gate"

[Summary]
1 feature
2 scenarios (2 passed)
48 steps (48 passed)
```

**Final confirmation run.** The same command was re-run after the Gate 4 wallet work, from the tree at
`5d92ae9`, and returned the identical verdict above: `2 scenarios (2 passed)`, `48 steps (48 passed)`,
ending in `Done.` The generalisation claim is therefore not resting on a single run — the second resource
scenario (`GHOSTTEST`, divisibility 2, threshold 10000) passed again on a fresh build.

| Scenario | What it proves |
| --- | --- |
| A wallet proves control of native tTARI to a gate, and cannot prove it twice | the control case: the cohort's own native stealth resource, gate read back on chain, receipt, replay refused |
| A wallet proves control of a resource created on chain to a gate over that resource | the generalisation claim: a resource **created in the scenario**, with a caller-chosen symbol and divisibility, backing a gate exactly as native tTARI does |

### The second resource, as the network reported it

```text
created stealth resource resource_5161236c4a402a14303a92562737748f0cd122fa42e3831aec7f32c6fca44fc7
    (GHOSTTEST, divisibility 2) held by component_510245845d18b031fce6f5a1ec9f22329cba92c4a978106d0f48dce152e7e588

account ACCOUNT funded with 400000 of GHOSTTEST into
    utxo_5161236c4a402a14303a92562737748f0cd122fa42e3831aec7f32c6fca44fc7_2c713522a4aaf79f2b219d869b5033d3d71d63c0537e5e0bbed2d717d8b2a67e:0

ghost gate deployed at component_f222f57006413994f7161a77f999105a2f9edd1446700c4c80b796a1c79ffa01
    over GHOSTTEST (resource_5161236c…44fc7), threshold 10000
```

The validator's block transaction executor, for the committed proof:

```text
Transaction 29262bbfdd28c25a6804b3fc69664452dae6477f73ae4220c0c27de4d0907e83 executed in 10.82ms.
  Accept(2 up, 1 down)
the committed proof emitted 3 event(s): ["std.vault.pay_fee", "GhostGate.GG", "std.component.updated"]
receipt read back from the committed event:
  ProofReceipt { attested_minimum: 10000, input_count: 1, challenge_nonce: Hash32([67, 67, …]) }
```

`Accept`, not a submission response: a validator executed that transaction and included it. Two up and
one down — the gate's component state and the qualifying output in, the spent UTXO out.

**The receipt is the whole privacy claim, and it is unchanged by the resource being user-created.** The
raw threshold was `10000`, which on a divisibility-2 asset is *fifty whole GHOSTTEST*. The amount
actually proven over was `400000` raw units — *four hundred whole GHOSTTEST*. The receipt reports
`attested_minimum: 10000` and `input_count: 1`; the real amount appears nowhere in it. A user-created
asset discloses no more than native tTARI does, which is the thing a "created on chain" claim could
easily have got wrong.

Gate state, read by calling its accessors on chain:

```text
the ghost gate GATE2 reports GHOSTTEST as its resource
the ghost gate GATE2 reports divisibility 2
the ghost gate GATE2 reports 1 proofs accepted
the ghost gate GATE2 reports the nonce of challenge CHALLENGE2 as burnt
```

The first two are new steps added for this phase. They matter because they show the gate returns the
**resource address** it was configured with and the **divisibility it read off chain**, rather than a
name or a caller-supplied figure — and that a divisibility of 2, unlike tTARI's 6, changes nothing about
the threshold comparison.

And the replay, from a fresh statement, sharing nothing but the nonce:

```text
Transaction 87f113c4bd81f782737c26548385e95804c8fd84b19e8212b72dec08ef22eb09 executed in 13.34ms.
  AcceptFee(2 up, 1 down), Reject Execution failure (TemplateError): At instruction #1:
  Template error: GG: challenge nonce has already been used
```

### Two bugs this found, both mine and both real

1. **`DanglingResources: 1 dangling address allocations remain after transaction execution`** on the
   resource-creation step. The faucet's `new_resource` derives its own address with `.create()` and
   takes no allocation argument, so the `allocate_component_address` the step issued was never
   consumed. Only `GhostGate::new` takes an allocation, because *its* address has to be predictable to
   the relying site.
2. **`no resource was recorded under GHOSTTEST`** on the funding step. The resource and the faucet
   component were recorded under each other's names, so the asset lookup found a component where it
   expected a resource.

Neither was caught by a type checker, and neither would have been caught by the engine suite. They are
recorded because they are the cost of adding a scenario to a harness whose steps are string-matched
against a feature file, and because the first run's failure mode (`DanglingResources`, after the resource
had already been created) would have been easy to misread as a consensus problem.

## The frozen milestone

```text
commit  1a0b2824f443aaa91457be494d2006a5687b2a69
tag     gate3-green  (annotated)
```

This is the Gate 3 milestone, frozen. Everything below is evidence measured at or before that commit.
Later work in this repository -- generalising Ghost Gate to arbitrary stealth fungible resources, the
local wallet bridge, the interactive frontend and the native-XTM research -- starts from this tag and
must leave it intact: it is the reference point for "what was proven before the product shape changed".

Re-verified at the tag on 2026-10-07:

```text
scripts/gg_test.sh test -p ghost-gate-tests --test gate_engine -- --test-threads=2
test result: ok. 30 passed; 0 failed

scripts/verify_patches.sh            ALL CHECKS PASSED
scripts/check_gate3_integration.sh   ALL CHECKS PASSED
```

## The statement under test

```text
NORMAL WALLET
      ?
      ?
ordinary existing key-path stealth tTARI
      ?
      ?
normal wallet input selection
      ?
      ?
qualifying self-owned MVP output
      ?
      ?
Ghost Gate component call
      ?
      ?
wallet performs authorization/signing
      ?
      ?
consensus threshold enforcement
      ?
      ?
COMMITTED ? access proof
```

## Verdict: GREEN -- both halves, measured separately

The gap that used to make this gate unreachable ? stock walletd cannot express a minimum value
promise ? is closed by a local patch, and all three of its verifications now pass: 17 SDK tests, 5
walletd handler tests, and -- as of 2026-10-04 -- the 30-test engine suite, whose last two cases are a
statement a real wallet built being spent into a gate call and accepted by consensus.

What that does **not** cover is the transport: no RPC, no mempool, no block, no network. That is the
second claim, and it has now been measured too, on the cohort's own end-to-end harness: **22 steps, 22
passed**, with a wallet-built statement carried over JSON-RPC, committed by a validator, read back as
public chain evidence, and refused on replay. The two results are reported separately because they are
separate proofs, and both are needed.

| Step | Status |
| --- | --- |
| Gap identified and scoped against v0.42.0 source | done |
| Minimal walletd patch written | done ? `docs/wallet-mvp.patch` |
| Patch applies to pristine `a43773e6` and round-trips byte-identically | done |
| Wallet SDK MVP tests | **17 passed, 0 failed** |
| walletd handler tests, real wallet, real RPC path | **5 passed, 0 failed** |
| walletd lib + tests type-check | clean |
| Engine suite re-run against the patched cohort | **30 passed, 0 failed** (2026-10-04, gaming PC) |
| Wallet-built statement accepted by a gate call | **passing** (same run; was "written, never compiled") |
| Live localnet: validator + walletd, four-step flow, `COMMITTED` | **22 steps, 22 passed** (2026-10-07) |
| `@transfer` baseline re-run on the backported cohort | 2 of 3 scenarios green; one pre-existing burn-claim epoch flake, see below |
| Public chain evidence read back (receipt, count, burnt nonce) | **read back** |
| Replay of the same challenge over RPC | **refused by consensus** |
| GHSA-pp4v-v773-9qxg (empty proof as resource possession) | reconciled, backported, regression green |

The 30/30 is the **consensus** half and nothing more: the statement is built by a real wallet and
executed by the real engine in one process. It says nothing about RPC, mempool admission or block
production. The 22/22 is the **transport** half, and it says nothing the consensus half does not: it runs
the same code over a network rather than in one process. Both are needed, and neither substitutes for the
other.

The engine suite was re-run after the security backport, unchanged at 30 passed, 0 failed.

## What was wrong, and what the patch does about it

The qualifying output must carry `minimum_value_promise >= threshold`. Stock walletd cannot produce
one.

**VERIFIED** ? `crates/wallet/sdk/src/apis/stealth_outputs.rs:929-963`:

```rust
pub fn create_output_witness(&self, destination: &RistrettoOotleAddress, amount: u64, ...) -> ... {
    ...
    let witness = OutputWitness {
        amount,
        mask: mask.key,
        sender_public_nonce: public_nonce,
        minimum_value_promise: 0,          // <- literal zero, no argument to change it
        encrypted_data,
        resource_view_key,
    };
```

The RPC request type had nowhere to put the value either: `TransferOutput`
(`crates/wallet/sdk/src/apis/stealth_transfer/params.rs:115`) carried `address`, `revealed_amount`,
`blinded_amount`, `memo`, `pay_to` ? **no MVP**.

Mutating a wallet-built output's promise afterwards is not an alternative. The promise is a field of
the bulletproof statement (`crates/engine_types/src/crypto/range_proof.rs:32`), so changing it after
the proof exists invalidates the proof. Verified in Gate 1
(`mutating_mvp_after_proof_breaks_validation`) and by the cohort itself
(`crates/wallet/crypto/src/stealth.rs:414`).

So the promise has to be set on the witness before the statement is built, which means inside the
wallet. That is the whole patch:

```text
TransferOutput.minimum_value_promise        serde default, so old callers get 0
  ? StealthOutputToCreate.minimum_value_promise
  ? create_output_witness(..., minimum_value_promise)
  ? OutputWitness.minimum_value_promise
```

An unsatisfiable promise ? larger than the hidden value, which would make the bulletproof attest
`value ? [mvp, 2^64)` with no value satisfying it ? is rejected in `StealthTransferParams::validate`
and again in `create_output_witness`, before any input is locked, so the caller learns why instead of
discovering it from a validator rejection later.

### The patch

`docs/wallet-mvp.patch` ? 8 files, 965 lines, generated by `scripts/wallet_mvp_patch.ps1` (Windows)
and `scripts/wallet_mvp_patch.sh` (WSL).

```text
modified crates/wallet/sdk/src/apis/stealth_transfer/params.rs
modified crates/wallet/sdk/src/apis/stealth_transfer/types.rs
modified crates/wallet/sdk/src/apis/stealth_transfer/api.rs
modified crates/wallet/sdk/src/apis/stealth_outputs.rs
new      crates/wallet/sdk/src/apis/stealth_transfer/minimum_value_promise_tests.rs
modified applications/tari_walletd/src/handlers/accounts.rs
new      applications/tari_walletd/src/handlers/accounts/create_stealth_transfer_statement_handler_tests/mvp_integration_tests.rs
modified utilities/traffic-sim/src/sim.rs
```

`scripts/wallet_mvp_patch.ps1` fails if the patched tree diverges from the reference anywhere outside
that list, so the artifact cannot silently absorb unrelated drift.

**Verified:** `git apply -p1` against a fresh clone of the reference at `a43773e6` applies with no
warnings, and all 8 resulting files are byte-identical to the working tree the patch was generated
from. (The reference's Windows checkout is CRLF via `core.autocrlf=true`; the patch is LF, matching
the repository's blobs. It therefore verifies against the index, not the CRLF working tree.)

## What the 17 SDK tests establish

```text
cargo test -p tari_ootle_wallet_sdk --lib minimum_value_promise -- --nocapture
test result: ok. 17 passed; 0 failed; 46 filtered out
```

- an omitted promise defaults to `0`; an explicit `0` is accepted
- a promise below the value, and one equal to it, are accepted
- a promise above the value is refused, and the error names `minimum_value_promise`
- the request survives serde with the promise encoded as a string
- the promise reaches the built statement, and the engine's range-proof validator accepts it
- mutating the promise after proof generation invalidates verification in both directions
- fragmented inputs carry the promise unchanged
- per-output promises are independent, and bounded by each output's own value
- the statement carries no secret material

These are unit and integration tests inside the patched SDK. They say the wallet can be *asked* for
the right output. They do not say a validator will accept the resulting transaction.

## What the walletd handler tests established

These pass: `applications/tari_walletd/src/handlers/accounts/create_stealth_transfer_statement_handler_tests/mvp_integration_tests.rs`.

They reuse the existing `StatementTest` harness, so they drive the real handler against a real
wallet ? real SQLite store, real key manager, real cipher seed, real account with an owner key ?
with only the indexer network interface offline. Five cases:

- the caller's promise reaches the statement the handler returns, across three fragmented key-path
  inputs, and `tari_engine_types::stealth::validate_transfer` accepts that statement
- a caller that omits the promise still gets `0`
- an unsatisfiable promise is refused, and the input is left `Unspent` with no lock taken
- the response carries one `utxo_signers` entry per spent output plus the wallet's `signing_keys`,
  each naming only public data, and every input is `LockedForSpend` under the returned lock
- the statement has the shape a gate needs: one output, no revealed amounts, a balance proof, every
  input on the key path, the output key-spendable, and the promise at or above the threshold

That last group is the one that matters most: it is the difference between "the field round-trips"
and "a caller can actually assemble a gate transaction with this wallet's help".

## The flow to run once the tests are green

```text
1. POST accounts.create_stealth_transfer_statement            (walletd, default 127.0.0.1:5100)
     input_selection: Specific([...]) or Selection(ConfidentialOnly)
     outputs: [{ address: self, blinded_amount: threshold + fee, minimum_value_promise: threshold }]
   -> statements[0], lock_id

2. build transaction:
     fee intent  : pay_fee from a revealed bucket
     main intent : CallMethod(gate, "prove_access", args![challenge, statements[0]])
     inputs      : write(gate), read(resource), write(each input UTXO)

3. POST transactions.submit
     transaction, seal_signer = account owner key, lock_ids = [lock_id]
   -> wallet derives stealth signers from the lock, signs, seals, submits

4. observe transactions.wait_result -> Committed { accept: true }
   -> read the GG event for the burnt nonce -> issue session
```

No key ever leaves walletd. The caller supplies bytes; the wallet supplies authority.

## Why the rest of the chain is believed to work

Each verified against v0.42.0 source; full citations in `docs/V042_SOURCE_TRACE.md`.

**A statement can be built and the inputs left locked.**
`accounts.create_stealth_transfer_statement`
(`applications/tari_walletd/src/handlers/accounts.rs:1631`) returns `statements`, `lock_id`,
`signing_keys` and `utxo_signers`, and explicitly "Return without unlocking the outputs".

**The wallet derives the signing keys itself, not from the caller.**
`derive_stealth_signers` (`transaction.rs:251`):

> "Derived from the wallet's own record of what each lock locked, never from the caller. ...
> re-deriving here means the locked outputs are the only thing that decides."

A caller cannot name the keys the wallet signs with. This is why the unacceptable fallback ?
exporting the account key so Ghost Gate signs for the user ? is not needed. Note that step 3 uses
`transactions.submit` with `lock_ids`, not `transactions.submit_instruction`: only `submit` accepts
the lock, and only `submit` is what triggers this derivation.

**Ordinary key-path inputs survive being spent from inside a custom template.**
`verify_input_authorizations` (`crates/engine/src/runtime/impl.rs:817`) reads the UTXO's committed
`spend_key`, turns it into a badge, and checks it against `base_call_scope()` ? the transaction's
outermost scope, not the template's local scope (`crates/engine/src/runtime/working_state.rs:1689`).

This was hypothesis **H2**, and it is the finding that makes the whole architecture viable. Confirmed
by the cohort's own `programmatic_transfer` test
(`crates/engine/tests/stealth.rs:237-275`), where a template performs a key-path stealth transfer
authorised by the transaction seal.

**Input selection is ordinary.**
`UtxoInputSelection` (`crates/wallet/sdk/src/apis/stealth_transfer/api.rs:168-329`) supports
`ConfidentialOnly`, `PreferRevealed` and `PreferConfidential`; the RPC adds `InputSelection::Specific`
for naming exact UTXOs, which additionally requires scoped `StealthUtxos::Read` authority. Fragmented
inputs are the normal case and need no special handling.

**Finality is observable as three distinct states.**
`transactions.wait_result` returns `TransactionFinalizedResult::{Pending, Finalized, Rejected}`, and
`Rejected` is documented as "rejected by mempool validation at submission and was never sequenced".
`ghost-gate-verifier::observe_and_authorize` grants only on `Committed { accept: true }`.
## Run of 2026-10-04: the wallet/consensus seam, measured

This is the first time the two halves of Gate 3 have been in the same process, let alone the same
build. Everything below was produced on the gaming PC; nothing is carried over from the laptop except
the cohort and the patch.

**Machine.** 16 GB host, of which WSL gets ~9.7 GiB with 8 GiB of swap and 8 visible CPUs. Source on
`D:` (internal SATA HDD) at `/mnt/d/Codex/ghost-gate-workspace`; the Linux filesystem had 920 GB free, so
the Cargo target directory lives there (`~/gg-ootle-target`, 11 GB after both suites) and no
build artifact was written to the nearly-full `C:`.

**Toolchain.** `rustc 1.97.1 (8bab26f4f 2026-07-14)`, which is what the cohort's own
`rust-toolchain.toml` pins (`channel = "1.97.1"`, matching `rust-version` in this workspace's
`Cargo.toml`). This has to be applied explicitly: rustup only applies a directory's
`rust-toolchain.toml` to processes started inside that directory, and the build starts in
`ghost-gate/`, not in the cohort tree. The machine's default toolchain is `stable` = 1.99.0, and the
build deliberately does not use it.

**Cargo jobs.** 3 (`CARGO_BUILD_JOBS=3`), one heavy build at a time. Peak observed usage was ~3.6 GiB
resident, so the memory ceiling that killed the laptop's builds was never approached.

**Cohort.** `a43773e600b9503ed3fadcd3f0048f86131e3644` (tag v0.42.0), patched tree selected:
`diff -rq reference patched` reports exactly the 8 source files `docs/wallet-mvp.patch` touches, plus the
new `mvp_integration_tests.rs`. After building, the patched tree additionally contains five
build-script outputs (`crates/template_builtin/compiled/*.wasm`) that the pristine reference does not;
they are generated by `crates/template_builtin/build.rs` and are not part of the patch.

**Command.**

```text
scripts/gg_test.sh test -p ghost-gate-tests --test gate_engine -- --test-threads=2

running 30 tests
test result: ok. 30 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 145.46s
```

**The original 28 are unchanged.** Sorting the `#[test]` function names at Gate 2 (`3781941`) and now and
diffing gives exactly two additions and no modifications:

```text
> a_wallet_built_statement_satisfies_the_gate
> a_wallet_statement_below_the_threshold_is_refused
```

**The two new cases.**

| Test | What it establishes |
| --- | --- |
| `a_wallet_built_statement_satisfies_the_gate` | A statement built by `StealthOutputsApi::generate_transfer_statement` from a promise-bearing `StealthOutputToCreate` -- the same call and field the patched `accounts.create_stealth_transfer_statement` handler makes -- carries `minimum_value_promise == threshold`, passes `tari_engine_types::stealth::validate_transfer`, is accepted by `GhostGate::prove_access` under the engine, produces exactly one new UTXO, and increments `proofs_accepted` to 1. |
| `a_wallet_statement_below_the_threshold_is_refused` | The same call with `minimum_value_promise == threshold - 1`. The wallet neither rounds up nor refuses, the statement is still valid to the engine's own validator, and the transaction is refused by the template with `proofs_accepted` still 0. This is what rules out a template that ignores the promise. |

The wallet in those tests is a real one: a SQLite store in a temp directory, a real key manager with a
real cipher seed, an account with an owner key read back out of the wallet's own keyring. Only the
indexer network interface is inert, because the statement path resolves inputs from the wallet rather
than from the network.

### What had to be fixed to get there

The seam had never been through rustc, so it had ten defects. Eight were mechanical, two were design.

Mechanical:

1. **The cohort switch had missed the template workspaces.** `templates/ghost_gate/Cargo.toml` and
   `templates/ghost_gate_faucet/Cargo.toml` each declare their own `[workspace]` (they build for wasm32),
   and both still pinned `../_ootle-v042-build`. One of their lockfiles therefore held two different
   copies of the same cohort crate and cargo refused: `package collision in the lockfile: packages
   ootle_serde v0.6.0 (...) and ootle_serde v0.6.0 (...) are different`. Both now pin the patched tree,
   which is what the root workspace's COHORT SWITCH comment says they do.
2. **`KeyManagerApi::get_private_key` does not exist**; it is `get_key`, and the secret accessor is
   `secret()`, not `secret_key()`.
3. **`SafePassword::from(Vec<u8>)` is not implemented**; `SafePassword::from_str("...")` is.
4. **`RistrettoOotleAddress::new` takes `RistrettoPublicKey`, not its byte form.**
5. **`IndexerRestApiNetworkInterface` is behind the `indexer_client` feature** of
   `tari_ootle_wallet_sdk_services`, which the dev-dependency did not enable.
6. **`StealthUnspentOutput` exposes `commitment()` as a method**, with the nonce and ciphertext under
   `.output`. This was in `fund()`, i.e. in code the Gate 2 suite already used -- it was added in
   `c25bb22` and, like the rest of that section, never compiled.
7. **`UnsealedTransaction::seal` takes `&RistrettoSecretKey`.**
8. **`CARGO_TARGET_DIR` is exported by cargo to build scripts.** Keeping the target directory on the
   Linux filesystem through that variable breaks the cohort's own
   `crates/template_builtin/build.rs`, which shells out to a nested `cargo build` per builtin template
   and then reads the `.wasm` from that template's own `target/` directory:
   `Error: Copy file to dest / No such file or directory`. Verified directly: a build script sees
   `CARGO_TARGET_DIR` when the variable is in the environment, and does not when the same directory comes
   from `build.target-dir` in config or from `cargo --config build.target-dir=...`. The target directory
   is therefore set in `.cargo/config.toml` (git-ignored, machine-local, absolute path), and
   `scripts/ootle_e2e.sh` passes `--config build.target-dir=...` for the same reason.

Design:

9. **The funding had to be built by the wallet too.** `fund()` mints faucet outputs with all-zero
   `encrypted_data`, which no wallet can decrypt. `generate_transfer_statement` recovers each input's
   mask and value by decrypting the output with the wallet's own view-only key
   (`resolve_output_masks_for_spending`), so a wallet cannot spend a UTXO whose encryption it did not
   perform. That is a property of every wallet, not a fixture limitation, and the real flow has the same
   shape: funds arrive as an ordinary transfer, and only then can a statement be built. So
   `GhostGateFaucet` gained a second entry point, `mint`, and funding a wallet is now two transactions:
   `fund` creates the resource and mints the tranche the test controls, and once the resource address
   exists the wallet builds its own output for it and `mint` turns that into a UTXO. The first step is
   necessary because a stealth output's tag is derived by its *sender* from the resource address, which
   does not exist until the faucet that creates it has executed.
10. **The input spend key is the wallet's own derivation.** For a wallet-created output the sender's
    secret nonce is unknowable to the test, so `derive_input_spend_key(owner_secret, index)` -- which
    recomputes a nonce the fixture chose -- cannot be used. The test now calls
    `StealthCryptoApi::derive_stealth_owner_secret(network, account_secret, output_public_nonce)`, which
    is exactly what `KeyManagerApi::generate_stealth_owner_key` does inside the SDK: the same key pair,
    derived from the on-chain nonce instead of from the sender's secret.

Nothing was weakened to make this pass. The positive case spends a wallet-built statement; the negative
case is the same statement one unit of promise lower and is refused.

## The transport half: real localnet -- GREEN

**A wallet-built, promise-bearing statement was carried over real JSON-RPC, spent into a real
`GhostGate::prove_access` call, accepted and committed by a real validator, read back as public chain
evidence, and then refused when the same challenge was replayed.**

```text
scripts/ootle_e2e.sh -- --tags "@ghost_gate"

[Summary]
1 feature
1 scenario (1 passed)
22 steps (22 passed)
```

The scenario, in the order it runs:

| Step | What it proves |
| --- | --- |
| a network with a registered validator, indexer, miner and wallet daemon | the stack is real, in process, over RPC |
| publish the `ghost_gate` template through walletd | the Ghost Gate template compiles to wasm and is published on chain |
| deploy a gate over tTARI with a 10000 threshold | a gate component exists with a real policy |
| a stealth transfer of 300000 to the account | the prover holds **stealth** tTARI, discovered by the wallet |
| `accounts.create_stealth_transfer_statement` with `minimum_value_promise: 10000` | the patched RPC carries the promise; the wallet builds the whole statement |
| `prove_access` submitted with the wallet's lock id | key-path signing derived by the wallet from its own lock; no key leaves the daemon |
| the receipt, the count, the burnt nonce, read back | the public evidence a site consumes exists in committed state |
| a second fresh statement, then the same challenge again | replay protection, over the wire |

### The evidence, exactly as the network reported it

The validator's block transaction executor, from the scenario's own log:

```text
Transaction 33a724aee380f9dd53bc87988ae04adc7a0f1470ffac5c73ca2d992cfb3b8f4a executed in 11.01ms.
  Accept(2 up, 1 down)
```

`Accept`, not a submission response: a validator executed that transaction against committed state and
included it. Two up-substates and one down -- the gate's component state (nonce burnt, count incremented)
and the qualifying output in, the spent UTXO out. The wallet added **1 stealth signer** from its own lock,
and the whole proof cost **11298** microtari in fees.

The events that transaction committed:

```text
the committed proof emitted 3 event(s): ["std.vault.pay_fee", "GhostGate.GG", "std.component.updated"]
```

`GhostGate.GG` is the template's receipt event. Note the topic is **`<module>.<MARK>`**, not `GG`: the
engine namespaces a custom event topic with the emitting module (`Runtime::emit_event` does
`format!("{module}.{topic}")`). A site filtering on a bare `"GG"` would see nothing, which is worth
knowing before anyone writes that filter.

The receipt, decoded from the committed event rather than assembled by the test:

```text
receipt read back from the committed event:
  ProofReceipt { attested_minimum: 10000, input_count: 1, challenge_nonce: Hash32([67, 67, ...]) }
```

`ProofReceipt` has exactly three fields -- a public floor, a count of live inputs, and the burnt nonce --
so decoding into it and checking those three is also a check that the event published **no amount, no
address and no identity**. The floor is 10000, which is the gate's threshold; the real value was 300000 and
appears nowhere.

Then the gate's own state, read by calling its accessors on chain (what `ghost-gate-verifier` would do):

```text
the ghost gate GATE reports 1 proofs accepted
the ghost gate GATE reports the nonce of challenge CHALLENGE as burnt
```

And the replay, built from a *fresh* statement so the only thing the two transactions share is the nonce:

```text
Transaction 2c8e62d37d2d9f336d87b82e67d3b59e52a39671efb6499cc7feeb7b8b8ac296 executed in 13.65ms.
  AcceptFee(2 up, 1 down), Reject Execution failure (TemplateError): At instruction #1:
  Template error: GG: challenge nonce has already been used
```

`AcceptFee(..., Reject)` is the shape to expect: the fee intent settles and the main intent is refused, so
the network pays for nothing and commits no proof. The reason is the gate's own rule, in the gate's own
words, which is what makes the refusal legible to a site without re-implementing anything.



**The cohort's own end-to-end harness runs on this machine. The baseline is green; the Ghost Gate
scenario is the open item.**

### Baseline: `@transfer` passes

```text
scripts/ootle_e2e.sh -- --tags "@transfer"

[Summary]
1 feature
3 scenarios (3 passed)
48 steps (48 passed)
```

All three scenarios, including `Stealth transfer to account that does not previously exist`. That is a
base node, a validator, an indexer, a miner, a wallet daemon and a Minotari console wallet, started in
process and driven over real RPC, mining blocks, claiming a base-layer burn and moving stealth tTARI.
Everything the localnet half of this gate needs is therefore working here.

**Re-run after the security backport, and what it showed.** The same command on the final cohort (patched
MVP + GHSA backport + the Gate 3 additions) came back **3 scenarios (2 passed, 1 failed), 39 steps (38
passed, 1 failed)**:

| Scenario | Result |
| --- | --- |
| Transfer tokens to account that does not previously exist | **failed** at `I claim burn BURN_PROOF ...` |
| Transfer tokens to existing account | passed, including its own burn claim |
| Stealth transfer to account that does not previously exist | passed, including a real stealth transfer |

The failure is `NotYetValid: block header not found for hash ... in an epoch before Epoch(3)` -- the same
burn-claim epoch race this project hit four times while building the Ghost Gate scenario, and the reason
`ghost_gate.feature` waits for `VN is past the epoch burn proof ... was mined in` before claiming. It is a
timing sensitivity in the cohort's own scenario, not a regression: the identical claim step *passed* in
scenario 2 of the same run, the stealth-transfer scenario passed outright, the same scenario passed 3/3 on
the pre-backport cohort on 2026-10-04, and nothing in the backport is on the claim's path
(`RuleRequirement::Resource` evaluation and two zero-amount guards). Recorded here rather than smoothed
over: the honest summary is "the baseline was green before the backport, and green again after it apart
from one known flake, which the Ghost Gate scenario works around explicitly".

(The arguments go after a `--`: `cargo` parses `--tags` itself and refuses the command otherwise, which
is why the script's own usage line was wrong until this run.)

### What it cost to get here


**This is a separate claim from the 30/30 above, and it is not green yet.**

The harness is the cohort's own `integration_tests` (a base node, validator, indexer, miner and wallet
daemon in one process, driven over real RPC by Cucumber), which is the right tool: it is what the cohort
tests its own wallet flows with. Three environment facts had to be established before it would build at
all on this machine:

| Obstacle | Resolution |
| --- | --- |
| `rustup` default is 1.99.0, the cohort pins 1.97.1 | `RUSTUP_TOOLCHAIN=1.97.1` in `scripts/ootle_e2e.sh` |
| `utoipa-swagger-ui` downloads a Swagger UI archive from github.com in its build script | `scripts/stage_swagger_ui.sh` fetched `swagger-ui-v5.17.14.zip` (4,388,280 bytes, zip header and `dist/` entries verified) to `~/gg-cache/`; the script honours `SWAGGER_UI_DOWNLOAD_URL=file:...` |
| `hidapi` (via the Minotari base-layer wallet) needs libudev's *dev* files, which this image lacks, and `sudo` needs a password | `scripts/stage_native_deps.sh` unpacks `libudev-dev` from the Ubuntu 22.04 archive into `~/gg-local` and the script exports `PKG_CONFIG_PATH` and `CPATH`. Nothing outside `$HOME` is touched. |
| base-layer protos use proto3 optional fields, which the distro's protoc 3.12.4 rejects | `PROTOC=~/ootle-build/protoc/bin/protoc` (21.12, already staged on this machine) |
| the target directory must stay off the D: drive, but `CARGO_TARGET_DIR` breaks the cohort's own build script | `--config build.target-dir=...`, as above |

### What was added to the cohort tree, and why it is safe

The harness lives inside the cohort (`integration_tests/`), so exercising the Ghost Gate template on a real
localnet means adding files to the cohort tree. `scripts/check_gate3_integration.sh` enumerates every
difference between the pristine reference and the patched cohort and fails on anything unaccounted for:

```text
wallet MVP patch (docs/wallet-mvp.patch): 9 entries
Gate 3 integration additions:             8 entries
cohort build-script output:              17 entries
no unexplained divergence
ALL CHECKS PASSED
```

The Gate 3 additions are:

| Path | What it is |
| --- | --- |
| `integration_tests/src/templates/ghost_gate/` | The template, copied from `templates/ghost_gate`, with its path dependencies rewritten to the cohort's own crates. |
| `integration_tests/src/ghost_gate_core/` | `crates/ghost-gate-core` copied in, because a path into the Ghost Gate workspace would put two spellings of the same cohort crate in one lockfile (see below). |
| `integration_tests/tests/steps/ghost_gate.rs` | Four steps: deploy the gate and issue a challenge, ask the wallet for a statement with a promise, submit the proof, replay it. |
| `integration_tests/tests/features/ghost_gate.feature` | One scenario. |
| `integration_tests/tests/steps/mod.rs`, `integration_tests/src/lib.rs`, `integration_tests/Cargo.toml`, `Cargo.lock` | Registration and the two new `TariWorld` fields the steps need. |

Both copies are byte-identical to the Ghost Gate repository's originals, which the same script checks with
`cmp`. The copies exist for one reason worth recording: `ghost-gate/Cargo.toml` pins the cohort as
`../_ootle-v042-ghost-gate`, a symlink, while the cohort's own crates refer to each other by their real
paths. Cargo does not canonicalise those, so a single dependency graph containing both spellings of
`ootle_serde v0.6.0` is refused outright:

```text
error: package collision in the lockfile: packages ootle_serde v0.6.0 (.../_ootle-v042-ghost-gate/...)
and ootle_serde v0.6.0 (.../tari-ootle-v0.42.0-ghost-gate/...) are different, but only one can be written
to lockfile unambiguously
```

The same collision is what made the engine suite fail before any of this was written: the two template
workspaces had been left pointing at the pristine tree by the cohort switch (fix 1 above).

### The Ghost Gate scenario: what it took to get it running

Five failures on the way to the first committed proof, each one a fact about the stack rather than about
the gate, plus two scenario bugs of my own. They are recorded in the order they happened, because the next
person to run this hits the same walls in the same order.

| Attempt | What failed | Fix |
| --- | --- | --- |
| 1 | The template would not compile: `failed to load manifest for dependency 'ghost-gate-core'` -- the vendored copy sat one directory too high (`../ghost_gate_core` instead of `../../ghost_gate_core`) | Fixed the path. The template then compiled to wasm from inside the cohort. |
| 2 | `Dry-run transaction rejected: InsufficientFunds ... Required: 1009897246, Available: 999647246` -- publishing a template costs about 1010 TARI in *estimated fees* (a size premium), and 10 TARI of burn was not enough headroom | Burn 50 TARI instead. |
| 3 | `NotYetValid: Burn claim proof names base layer state this epoch does not have: block header not found for hash ... in an epoch before Epoch(3)` -- the claim names a base-layer header the validator had not ingested yet | Wait for the scan, exactly as `wallet_daemon.feature` does, and mine into the next epoch so the validator's *consensus* epoch passes the burn's. |
| 4 | `InsufficientFunds: Required: 999947246, Available: 999647246` on template publication -- a gap of exactly 300000, the amount of the stealth transfer that preceded it | The harness sizes publication's `max_fee` at `min(estimate * 1.1, total balance)` while fees come out of *revealed* funds, so moving value into a stealth output first makes `max_fee` exceed what the fee source can pay. Publish and deploy **before** the funds move. |
| 5 | `Substates not found: utxo_<resource>_<commitment> not found` when submitting the proof -- the statement spends a UTXO the validator had not committed yet | `miner MINER mines to the next epoch`, which takes the chain past the funding transaction and waits for the tip. A UTXO only exists on chain once the transaction carrying it is in a block; a relying site has to wait for the funding transaction to finalise before a proof can be accepted. |

### The one that was not a scenario bug: an input has to be a *declared* input

Worth recording on its own, because the error message misleads. The proof was refused twice with

```text
Substates not found: At instruction #1: utxo_01010101..._f4c9ba83... not found
```

which reads like "that UTXO is not on chain". It is not. The validator's own log says what it really is:

```text
Runtime error: Substate 'utxo_01010101..._f4c9ba83...' not found **or is not a transaction input**
  at crates/engine/src/wasm/process.rs:470
```

The engine resolves every substate a transaction's arguments reference
(`WorkingState::check_all_substates_in_scope`) and refuses one the transaction did not declare as an
input. The statement named a UTXO that was committed -- it was in the validator's RocksDB, the indexer's
state and the wallet's own store, all three verified by grepping the scenario's temp directory -- but the
*transaction* declared only the gate component, so from the engine's point of view the spend referenced a
substate outside the transaction's scope.

**What this does and does not say about input selection.** The scenario names the exact UTXO the proof
spends (`InputSelection::Specific`), and that is *test scaffolding*, not a product design. It is
deterministic infrastructure: the scenario knows which transaction created which output, because it ran
that transaction, and a regression test that lets a wallet pick would be testing the wallet's input
selection heuristics rather than the gate. The same reasoning applies to `.add_input(built.input)`: a
deterministic fixture, not a claim about who chooses what in production.

For the real architecture the constraint is the opposite one. `accounts.create_stealth_transfer_statement`
takes `InputSelection::Selection(...)` as well as `Specific { utxo_addresses }`, and the handler resolves
`Selection` itself from the wallet's own store. So input selection *can* stay wallet-local, and it should:
the wallet or a trusted local bridge chooses or approves the qualifying output, and the browser or relying
site receives the minimum it needs to submit and observe the proof -- the challenge, the transaction, the
committed result and the receipt event. A site has no business learning the user's UTXO identifiers or
wallet inventory, and nothing in the protocol requires it to.

Where the current API *does* constrain us, and it is worth writing down rather than glossing: to submit a
transaction that spends a specific UTXO, the caller has to declare that UTXO as an input, because the
engine refuses a statement referencing a substate the transaction did not declare. That is an engine rule,
not a wallet choice, and it is why `utxo_signers` and the locked inputs come back with the statement: the
caller is consenting to spend specific outputs. The least-privacy-leaking shape is therefore the one where
the *wallet* holds that consent: the site supplies the challenge and receives the receipt, while the
selection and the declaration stay behind the wallet's RPC boundary. Nothing about the threshold itself
depends on any of this -- it is enforced on the bulletproof.

Two things follow. The first is the fix: the proof transaction declares the UTXO as a write input
(`.add_input(built.input)`), which is what `InputDeclaration: From<SubstateRequirement>` exists for, and
what walletd does for the transfers it builds itself. The second is a property of the flow worth stating
plainly: **a qualifying statement is only spendable from a transaction that declares the outputs it
spends.** A relying site's backend has to know the UTXO it is asking to spend, which is exactly why the
wallet's statement RPC returns `utxo_signers` alongside the statement -- the outputs being spent are part
of what the caller is consenting to.

Pinning the input also removed a real ambiguity. With `ConfidentialOnly` the wallet picks the inputs, and
a wallet's idea of what it holds can include outputs a validator does not have; with
`InputSelection::Specific` the scenario names the exact output the funding transaction created, read from
that transaction's own committed diff through the harness's output records. The wallet still does
everything that matters -- it decrypts the input, builds the bulletproof over
`[minimum_value_promise, 2^64)`, signs the key path from its own lock, and never exports a key -- and the
site names what it wants spent, which is what a site does.

Two of the attempts in between were pure scenario bugs rather than stack behaviour, recorded because they
cost the same 40-minute link each: a step whose text did not match its definition (`validator node VN is past
...` against `{word} is past ...`), and a statement that asked a single 300000 stealth input to create a
100000 output (`Input: 300000, Output: 100000` -- a stealth output cannot be split, so the wallet selects
its input whole).
What the attempts established beyond the fixes themselves: the network starts, the account is created and
funded over RPC, a base-layer burn is claimed into it, a **stealth transfer of tTARI into the same account
succeeds and the wallet's balance reflects the stealth output** -- so the prover really does hold stealth
funds, discovered by the wallet, over the real RPC surface. That is the precondition the gate needs.

Useful discovery for the transport work: **tTARI on Ootle is itself a stealth resource.** The harness's
existing steps `I do a stealth transfer ... via the wallet daemon ...` operate on `TARI_TOKEN` through
`accounts.stealth_transfer`. A gate can therefore watch the resource the test account already holds,
without a purpose-built stealth faucet: what is missing is a step that calls the patched
`accounts.create_stealth_transfer_statement` with a promise and then submits a transaction whose main
intent is `CallMethod(gate, "prove_access", args![challenge, statement])` with the returned `lock_id`,
plus a `ghost_gate.feature` beside the existing ones.

## What remains for Gate 3 to be GREEN

Nothing in the two claims above. What remains is *not* Gate 3:

1. `ghost-gate-verifier::observe_and_authorize` consuming what the scenario now proves exists. The
   evidence -- `proofs_accepted`, the burnt nonce, the `GhostGate.GG` receipt -- is read and asserted in
   the scenario; wiring the verifier to it in a running relying-site process is the next unit of work.
2. A relying site's four-step flow as a *product*: challenge issuance, session grant, expiry policy.
3. The known limits of what this gate means, unchanged by any of the above: it proves control of a
   qualifying amount at access time, not total balance, not identity, not Sybil resistance, and not
   anything about holdings after access.

## Reproducing this

```text
# Phase 1, the consensus seam (30/30)
scripts/gg_test.sh test -p ghost-gate-tests --test gate_engine -- --test-threads=2

# Phase 2, the transport
scripts/stage_swagger_ui.sh                     # one-off: the indexer's swagger-ui build input
scripts/ootle_e2e.sh -- --tags "@transfer"      # the cohort's own baseline: 3 scenarios, 48 steps
scripts/ootle_e2e.sh -- --tags "@ghost_gate"    # the Ghost Gate scenario: 22 steps, 22 passed

# the backport's own regression tests, inside the cohort
cd _ootle-v042-ghost-gate
cargo --config 'build.target-dir="~/gg-ootle-target"' test -p tari_engine --test access_rules
cd -

# integrity: both patches apply to the pinned commit, and the cohort tree carries nothing else
scripts/verify_patches.sh            # each patch applies; the patched cohort matches the patched export
scripts/check_gate3_integration.sh   # every difference from the pristine reference is accounted for
```

Three things about the environment, all learned the hard way and all still true:

- **The cucumber test binary takes 20-40 minutes to link.** Any change under `integration_tests/` --
  a feature file included -- invalidates it, so scenario tweaks are batched. Passing
  `--config 'profile.test.package.integration_tests.debug=0'` keeps it around 20 minutes and much
  lighter, at the cost of no debug info in that one crate's test binary.
- **The machine is shared, and the host restarts without warning.** Another user's cargo build was
  running for much of this session, and three WSL VM restarts killed in-flight links outright. Logs for
  every run are under `~/gg-logs/`.
- **D: is CRLF.** The reference working tree does not match its own blobs by line endings, so
  `git apply --check` against it needs `--ignore-whitespace`, and any content comparison against an LF
  export has to normalise CR. `scripts/verify_patches.sh` does both and reports the caveats rather than
  papering over them.

## The honest summary

Both halves of Gate 3 are now measured, and they are separate measurements.

**Consensus, in one process.** 30/30 in `gate_engine`, of which 28 are the unchanged Gate 2 suite and two
are the seam: a statement built by an ordinary wallet's SQLite store, key manager and cipher seed, carrying
a `minimum_value_promise` the caller chose, is accepted by `GhostGate::prove_access` under the engine and
increments `proofs_accepted`; the same call one unit of promise short is refused. The cohort is
`a43773e6` plus `docs/wallet-mvp.patch`, so the wallet and the engine are one compilation of the same
crates.

**Transport, over a real network.** 22 steps in the cohort's own `integration_tests`, against a base node,
validator, indexer, miner and wallet daemon: the wallet builds the promised statement over JSON-RPC, the
proof transaction is declared with the UTXO it spends, the wallet signs the key path from its own lock
without any key leaving the daemon, a validator executes and commits it (`Accept(2 up, 1 down)`), the
public evidence -- the `GhostGate.GG` receipt decoding to a floor of 10000 over one input and the burnt
nonce, `proofs_accepted() == 1`, `is_nonce_used(nonce) == true` -- is read back from committed state, and
the same challenge replayed from a fresh statement is refused with `GG: challenge nonce has already been
used`.

**Security.** The pinned cohort predates GHSA-pp4v-v773-9qxg, in which a zero-amount or empty proof
satisfied `rule!(resource(X))`. The exploit was reproduced on this cohort -- an empty vault passed a
resource rule and took 10 tokens -- and closed by a minimal backport whose upstream regression tests pass
(48/48). Ghost Gate's threshold path never traverses that construct: the threshold is a bulletproof over
`[minimum_value_promise, 2^64)` plus key-path input authorisation, not a possession rule, and the gate
refuses non-key-path inputs before the engine could evaluate an `AccessRule` leaf. The seam is 30/30 both
before and after the backport, which is the evidence for that claim.

What is still not true, and was never claimed: that this proves total balance, identity, Sybil
resistance, or anything about holdings after access. It proves that at the moment a validator committed
that transaction, its signer controlled enough private tTARI to cover the gate's threshold -- and published
no amount to do it.
