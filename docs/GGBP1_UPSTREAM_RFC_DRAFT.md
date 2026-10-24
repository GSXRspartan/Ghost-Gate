# Draft RFC: Noncustodial Minotari L1 Balance Proof API

## Abstract

Define a wallet-internal, user-approved API for proving control of a bounded set of current Minotari outputs and a threshold statement over their aggregate committed value. It is not a transaction API, generic signing API, key-export API, or proof that a particular account owns a public balance.

## Required upstream primitives

1. **Canonical `BalanceProofDomain`.** A domain tag distinct from wallet identity signing, transaction kernels, script signatures, and arbitrary message signing.
2. **A wallet-owned output-authority operation.** Given a canonical request and internally selected output hashes, resolve each authenticated, supported output and produce a signature verifiable against its actual spending condition. The caller never supplies scripts, key IDs, nonces, or signing bytes beyond the bounded request.
3. **An aggregate-sum minimum-proof operation.** Given wallet-internal openings for selected commitments, construct a specifically defined proof that the aggregate commitment opens to a nonnegative total at least the canonical threshold. Define range/overflow limits, transcript, proof encoding, generator/version identifiers, verification algorithm, and test vectors.
4. **An authenticated chain-data adapter.** Return full output data and canonical current unspent evidence—not merely a payment reference—along with network/genesis, tip/sync, and freshness data.
5. **A capability query.** Report only supported protocol versions, output/script forms, limits, and network/genesis. Unsupported forms fail closed.

## Non-goals

- exporting seeds, private keys, view keys, masks, amounts, or wallet database records;
- signing arbitrary caller strings, transaction scripts, or Schnorr challenges;
- transfers, locks, burns, claims, or background approvals;
- replacing a base-node's consensus validation or asserting wallet balance to an unauthenticated website.

## Suggested API boundary

```rust
trait BalanceProofProvider {
    fn capabilities(&self, network: Network, genesis: Hash) -> BalanceProofCapabilities;
    fn prepare(&self, request: CanonicalBalanceProofRequest) -> ApprovalPreview;
    fn approve_and_create(&mut self, request: CanonicalBalanceProofRequest,
                          approval: ExplicitUserApproval)
        -> Result<BalanceProofResponse, BalanceProofError>;
}
```

`prepare` may inspect only the wallet's own state and must not contact a callback. `approve_and_create` must be foreground-only, construct all signed bytes internally, use approved nonce generation, bound resource use, and return no private witness. An implementation must document how it gets current unspent evidence and how it revokes/rechecks a proof after a reorganization.

## Acceptance and review criteria

The RFC is incomplete until it includes independent cryptographic review of the aggregate statement, cross-language test vectors, malformed-input and overflow tests, supported script/feature matrix, privacy review, base-node evidence specification, and interoperability tests for Rust, Android JNI, iOS Swift, desktop, CLI, and WASM. The `6.0.1-pre.2` single-output key-manager API is not this API.

## Smallest next upstream change

Start with a Rust-only, non-exporting prototype behind an experimental capability flag: canonical request decoding, explicit user approval, one supported standard output form, and deterministic fixtures. The synthetic lower-level construction in [GGBP1_CRYPTOGRAPHIC_SPIKE.md](GGBP1_CRYPTOGRAPHIC_SPIKE.md) establishes the exact one-aggregate-commitment statement to carry forward, while [GGBP1_PHASE2_EXPERIMENT.md](GGBP1_PHASE2_EXPERIMENT.md) records the bounded wire format, trusted-chain requirement, and required wallet-core boundary. Both require independent review before any gRPC, browser, deep-link, or mobile exposure is considered.
