# GGBP-1: Ghost Gate Balance Proof v1

**Status: feasibility record and interface draft — not implemented, not live, and not an authorization mechanism.** This document records a deliberately fail-closed outcome from a source-level review of the Minotari `6.0.1-pre.2` / `tari_crypto 0.23.4` stack pinned by this repository. It does not change the existing draft-only native-XTM gate status.

## Verdict

The underlying Pedersen arithmetic is sound in principle: if `C_i = r_i.G + v_i.H` are commitments made with the same Minotari generators, then `C_sum = sum(C_i) = r_sum.G + v_sum.H`, where `r_sum = sum(r_i)` and `v_sum = sum(v_i)`. A party holding all valid openings can therefore form an opening for the aggregate.

That observation is **not a deployable GGBP-1 proof**. The exact pinned wallet interface has a single-mask, single-`u64` `construct_range_proof` entry point and no safe aggregate-proof or output-authority API. No wallet surface supplies the needed aggregate opening while retaining the keys inside the wallet.

The lower-level primitive is nevertheless sufficient for a tightly bounded synthetic construction: the experimental spike sums the openings privately, constructs **one** extended Bulletproofs+ witness for `C_sum`, and independently verifies it against the recomputed public commitment. See [GGBP1_CRYPTOGRAPHIC_SPIKE.md](GGBP1_CRYPTOGRAPHIC_SPIKE.md). This is not an aggregate proof over individual output statements and does not make the construction wallet-reachable.

Consequently, normal builds still include **no GGBP-1 prover or accepting verifier**. The synthetic module is disabled by default and has no chain, wallet, bridge, HTTP, Telegram, or authorization connection.

The Phase 2 feature-gated experiment adds a separate in-memory verifier lifecycle and a read-only,
locally-trusted base-node adapter. Its result type is explicitly non-authorizing and it is not
connected to normal builds. See [GGBP1_PHASE2_EXPERIMENT.md](GGBP1_PHASE2_EXPERIMENT.md).

## Source findings

The project pins `tari_transaction_key_manager 6.0.1-pre.2` and `tari_crypto 0.23.4`; detailed source quotations and paths are retained in [XTM_RESEARCH.md](XTM_RESEARCH.md).

| Requirement | Exact finding | Effect |
| --- | --- | --- |
| Commitment aggregation | Same-generator Pedersen commitments are linearly composable. | Mathematically possible, provided every input is an authenticated Minotari output. |
| Aggregate witness | `r_sum` and `v_sum` require every selected output's opening. | Must remain wallet-internal; Ghost Gate must never receive it. |
| Minimum statement | Standard output range proofs bind a public `minimum_value_promise`; outputs are verified over `[minimum, 2^64)`. | A verifier may read an existing output's promise, but cannot repurpose it as a proof of a sum. |
| Wallet proof creation | `construct_range_proof(mask_key_id, value, min_value)` accepts one mask and one `u64` value. | Cannot make an aggregate proof through the shipped wallet/key-manager surface. |
| Authority signing | Internal `sign_message_with_spend_key` and script-signing methods exist; wallet gRPC `SignMessage` signs the node identity, not an output spend key. | An external caller cannot obtain output-specific authority safely today. |
| Extended proofs | `ExtendedRangeProofService` can aggregate witnesses internally. | Insufficient without an explicit, reviewed aggregate-sum statement, encoding, and wallet API. |

## Required statement, if upstream adds it

An eventual proof request must be canonical bytes, not JSON selected by a website:

```text
GGBP1/challenge/v1 || network || genesis_hash || origin || gate_id || subject_id ||
threshold_micro_xtm_le || nonce_32 || issued_at || expires_at || canonical_tip_anchor ||
max_outputs || selected_output_hashes
```

The wallet may select output hashes after user approval, but the returned proof must bind the same ordered, duplicate-free list. The verifier must bind the request and response to network **and** genesis hash; gate, subject, origin, nonce, expiry, and exact integer threshold; authenticated output hashes, commitments, scripts, features, maturity, and chain state; and a dedicated `BalanceProofDomain` distinct from transaction, script, identity, and generic message-signing domains.

`u64` arithmetic is not enough by implication: selection must use checked addition, reject an overflow before proving, and define a representable total range. A valid protocol must either prove the total is within the chosen range or impose and verify a safe maximum total. It must also define compatible output versions/features, script forms, consensus epoch, and range-proof version; unknown forms fail closed.

## Required authority operation

The wallet needs a purpose-built operation conceptually equivalent to:

```text
create_balance_proof(canonical_challenge, selected_output_hashes) -> GGBP1Proof
```

It must look up each output internally, refuse unsupported scripts/features, derive the corresponding authority internally, and sign only the canonical `BalanceProofDomain` message. It must not accept an arbitrary message, transaction challenge, caller-provided script, private-key identifier, mask, or nonce. It must use an approved Schnorr nonce construction and return only signature and public proof material.

Generic `sign_script_message`, a generic raw Schnorr helper, or node-identity `SignMessage` cannot be substituted: none establishes that the authenticated UTXO is spendable by the signer for every supported Minotari script type.

## What a future verifier must check

An accepting implementation is blocked until the upstream proof format exists. Its contract is nevertheless constrained now:

1. Decode a strictly bounded, versioned binary request and response; reject unknown fields, duplicate hashes, invalid lengths, excess outputs, and non-canonical encodings.
2. Consume a server-generated nonce exactly once. Enforce a short expiry and exact gate, subject, origin, network, and genesis bindings.
3. Obtain each output solely from a verified chain view. Never accept a client-provided commitment, script, amount, spent flag, confirmation height, or tip as authoritative.
4. Authenticate every standard-script spending condition and verify its per-output `BalanceProofDomain` signature. Reject unsupported script/features rather than guessing.
5. Check unspent state, maturity, confirmations, canonical tip freshness, network/genesis, and a reorganization policy immediately before issuing any test result. Recheck/revoke if configured.
6. Construct the aggregate commitment from authenticated chain commitments only, then verify the future, independently specified aggregate minimum proof against the server's exact threshold.

No branch may fall back to an Ootle proof, a browser `window.tari` provider, a wallet address signature, or a client-reported balance. GGBP-1 remains non-authorizing until this is implemented, reviewed, and tested independently.

## Capability states

| State | Meaning |
| --- | --- |
| `UnavailableUpstreamProofApi` | Wallet cannot create the dedicated authority + aggregate proof. Current state. |
| `UnsupportedOutput` | Script, feature, proof version, maturity, or protocol version is not explicitly supported. |
| `MissingVerifiedChainEvidence` | Full output or synchronized canonical-chain evidence is unavailable. |
| `StaleOrReorganized` | Tip freshness or canonicality policy fails. |
| `RejectedProof` | A future parser, signature, or proof verifier rejected the response. |

These are failure states, never authorization results.
