# GGBP-1 Security Model

**Status: design review record. GGBP-1 is not implemented and no real wallet was accessed.**

## Assets and trust boundaries

The wallet retains its seed, spend keys, view keys, decrypted output data, commitment masks, values, and nonce material. Ghost Gate may receive only an approved, challenge-bound proof and a bounded set of output references. A base-node/chain-view service is evidence, not a source of wallet secrets. A browser origin is an untrusted requester until authenticated by the wallet confirmation screen.

Neither a balance, a commitment, a public range proof, a wallet address, nor an identity-key signature alone establishes the required statement: current authority over specific, unspent outputs whose aggregate satisfies a requested threshold.

## Threat controls required before acceptance

| Threat | Required control |
| --- | --- |
| View-key holder or one-sided sender claims control | Verify a dedicated output-authority signature against the chain-authenticated spending condition; never use scan/decryption capability as authority. |
| Signature becomes a spend signature | Separate `BalanceProofDomain`, a non-transaction canonical message, independent nonce handling, and no generic signing endpoint. |
| Malicious site obtains arbitrary signatures | Wallet constructs all message bytes itself and displays origin, network, gate, threshold, output-count/disclosure, and expiry. |
| Client invents commitment/script/spent state | Chain view returns full authoritative outputs; client fields are identifiers only. |
| Output counted after spend or reorg | Query current unspent state and canonical, synchronized tip; enforce confirmation, maturity, freshness, and recheck/revocation policy. |
| Sum proof is forged or threshold changed | Authenticate selected commitments, use checked arithmetic, and verify a reviewed aggregate proof against the exact canonical challenge threshold. |
| Cross-gate/account/network replay | Bind gate, subject, origin, network, genesis, nonce, expiry, output list, and tip anchor; consume nonce atomically. |
| Resource exhaustion | Strict byte, output-count, age, proof-size, parser, and verifier-work limits before cryptographic work. |

## Disclosure model

Even a sound threshold proof can disclose: selected output hashes, number of outputs, proof version, network, time window, gate/subject linkage, and potentially an on-chain correlation set. The minimum promise itself does not reveal a value above its floor, but output selection can be identifying. The wallet must show an output-disclosure warning and permit cancellation. Ghost Gate must store the minimum necessary proof/receipt material with a documented retention limit.

The design must never call native L1 information “stealth”, “private”, or “confidential” as a product claim merely because amounts are commitment-backed. Those properties require protocol-specific evidence beyond this unimplemented design.

## Chain-view contract

`ChainView` is a read-only abstraction, not a permission to install or run a node. A production adapter needs evidence for full output commitment, output hash, exact script, output features, maturity, confirmed height, current unspent state, canonical tip, and synchronization state.

`SearchPaymentReferencesViaOutputHash` is insufficient by itself: its response does not include the full script. `FetchMatchingUtxos` can be part of a path only when returned full outputs are tied to requested hashes and the implementation verifies the protocol's network, tip, and sync conditions. Fixtures must be typed separately from live observations; a fixture can never grant authorization.

If observations disagree, lack any required field, report an unsynchronized node, are stale, or cannot establish canonicality, the required result is `MissingVerifiedChainEvidence` or `StaleOrReorganized`.

## Outstanding assumptions needing independent review

1. A concrete aggregate-sum Bulletproof statement and serialization can be designed safely with the Tari primitives without a consensus change.
2. Every output form a wallet elects to support has a well-defined, non-exporting authority witness.
3. The chosen base-node path can prove current unspent status and authenticate full script data under the expected network/topology.
4. The release-specific proof, feature, and script semantics agree across base node, wallet, WASM, Android, iOS, and verifier.
5. The disclosure trade-off is acceptable to users of a given gate.

None is established by the current reference. They are explicit review gates, not implementation notes to defer.
