# GGBP-1 Cryptographic Feasibility Spike

**Status: synthetic Rust construction verified; not a real Tari output, live Esmeralda proof, or production authorization feature.**

## Scope and versions

The isolated [`ghost-gate-ggbp1-spike`](../crates/ghost-gate-ggbp1-spike) harness compiles the same disabled-by-default
[`experimental-ggbp1`](../crates/ghost-gate-minotari/Cargo.toml) module using only:

| Dependency | Version |
| --- | --- |
| `tari_crypto` | `0.23.4` |
| `tari_bulletproofs_plus` | `0.5.3` (resolved by `tari_crypto`) |
| `tari_script` | `6.0.1-pre.2` |

It opens no wallet, creates no `TransactionOutput`, signs no transaction, contacts no base node, and uses only fixed synthetic keys, masks, values, and output identifiers in memory.

## Source basis

This spike is pinned to the local crate sources resolved by `Cargo.lock`, rather than substituting a generic curve or signature implementation:

- `tari_crypto-0.23.4/src/ristretto/pedersen/extended_commitment_factory.rs` supplies the default Tari commitment generators and `commit_value`/`open_value` operations.
- `tari_crypto-0.23.4/src/ristretto/bulletproofs_plus.rs` supplies `BulletproofsPlusService`, extended witnesses, and public statements; `tari_crypto-0.23.4/src/extended_range_proof.rs` supplies proof construction and batch verification.
- `tari_script-6.0.1-pre.2/src/lib.rs` supplies the standard `push_pubkey_script` construction and Tari's native `CheckSigHashDomain`, against which the new GGBP-1 domain is negatively tested.
- `tari_common_types-6.0.1-pre.2/src/types/mod.rs` fixes the surrounding Tari defaults at 64 range-proof bits and aggregation factor 1.

## Construction that was verified

For each fixture, the prover uses Tari's `ExtendedPedersenCommitmentFactory::default()` to form
`C_i = r_i.G + v_i.H`, and attaches the exact standard `tari_script::push_pubkey_script` form to a public script key. The proof-side private witness holds `r_i`, `v_i`, and the matching synthetic script private key. None is placed in the proof object.

Version 2's signed transcript contains the complete canonical challenge (experimental version,
network, genesis, origin, gate, subject, threshold, nonce, expiry, and ordered output hashes),
then every indexed synthetic output record: output hash, commitment, exact `PushPubKey` script
bytes, and script public key. Each script key signs that full table with its own index. The subject
also signs the full table in its separate subject-binding domain. Thus replacing a commitment
while preserving the aggregate commitment, changing a supported script identity, reordering, or
duplicating a record invalidates the corresponding authority transcript. The signature uses the
new Tari hash domain `com.ghost-gate.ggbp1.balance_proof/v1`, not the native script
`CheckSigHashDomain`. The verifier independently reconstructs the transcript and requires that
the advertised public key occurs in the exact supported `PushPubKey` script before verifying it.

For multiple outputs the prover performs checked `u64` addition of values, adds their masks in the Ristretto scalar field, and adds their public commitments. It then proves a minimum value against **one aggregate commitment**:

```text
C_sum = sum(C_i) = (sum(r_i)).G + (sum(v_i)).H
```

`BulletproofsPlusService::construct_extended_proof` is called with a single aggregate witness and the requested minimum. The independent verifier recomputes `C_sum` only from the received public commitments, compares it to the proof's aggregate commitment, then calls `verify_batch` with a one-statement `RistrettoAggregatedPublicStatement` using the exact challenge threshold.

This is deliberately not a claim that Tari currently supports a wallet-created proof aggregated from arbitrary existing outputs. It is a lower-level proof that the required algebra and Bulletproofs+ statement can be expressed when one party already holds every opening.

## Verified test cases

The initial isolated crypto harness passed six tests covering:

- a value below the threshold refusing to produce a proof, with equal and above-threshold single outputs verifying;
- two `45 + 55` synthetic outputs verifying against threshold `100`;
- challenge-threshold substitution failing first at the bound authority signatures, and still failing the Bulletproofs+ verification when synthetic authority signatures are regenerated for the altered threshold;
- invalid opening mask, invalid authority signature, changed commitment, non-standard script,
  reordered/duplicate output identifiers, malformed proof bytes, and `u64` aggregate overflow
  rejecting;
- the audit's aggregate-preserving `C1' = 2C1`, `C2' = C2 - C1` substitution now rejecting at the
  independently reconstructed authority transcript, while the aggregate Bulletproofs+ check is
  retained;
- a GGBP-1 signature failing verification when reinterpreted under Tari's `CheckSigHashDomain`.

The same harness now has three additional Phase 2 tests for an isolated server/challenge/ChainView
lifecycle, concurrent redemption refusal, response-size refusal, maturity and reorganization
refusal, forged aggregate-proof refusal, gate-binding refusal, and recheck revocation. See
[GGBP1_PHASE2_EXPERIMENT.md](GGBP1_PHASE2_EXPERIMENT.md).

The fixtures are reproducible: their private keys, masks, challenge fields, and signature RNG seeds are fixed in the test module. They are not published as Esmeralda vectors and have no chain meaning.

## Security limits

The synthetic standard-script check establishes control of the key named by the fixture's `PushPubKey` script. It does **not** establish that a real output is confirmed, unspent, mature, has a valid metadata signature, has compatible features/proof version, or can be spent under every possible Tari script. Those are distinct chain-view and wallet obligations.

The test also does not establish that a wallet can derive the correct output key, obtain all masks, or make the aggregate witness without export. It intentionally does not call a generic wallet/script signing method. A real implementation needs a new wallet-internal operation that accepts only the canonical request, recognizes supported output/script forms, obtains openings internally, displays approval, and returns only public proof material.

## Verdict matrix

| Claim | Result |
| --- | --- |
| Mathematically plausible | Yes, for same-generator commitments with checked `u64` totals. |
| Synthetic Rust proof verified | Yes, using pinned Tari lower-level primitives. |
| Real Tari output verified | No. No `TransactionOutput` or authenticated chain observation was used. |
| Live Esmeralda proof verified | No. No network or wallet interaction occurred. |
| Production security reviewed | No. Wallet API, output coverage, chain view, encoding, privacy, and independent cryptographic review remain required. |

## Smallest safe upstream change

Add a Rust-only, experimental wallet API for one explicitly supported standard output form. It must construct the canonical request internally, verify network/genesis and local output eligibility, retain script keys/masks/values, require foreground user approval, produce the dedicated-domain authority signatures and aggregate minimum proof, and return bounded public material only. Exposing `sign_script_message`, raw Schnorr signing, masks, or decrypted output data to callers is not an acceptable substitute.
