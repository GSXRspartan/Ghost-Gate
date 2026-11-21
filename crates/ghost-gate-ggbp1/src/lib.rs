//! GGBP-1 v3 Esmeralda tXTM balance proofs, for a deliberately non-authorizing test gate.
//!
//! This crate has three layers:
//!
//! * [`v3`] is the vendored upstream cryptographic package: a canonical 223-byte challenge,
//!   a bounded `GGBP1R` response grammar, and a synthetic-only verifier. It proves arithmetic
//!   and signatures; it does not prove that any output exists on a chain.
//! * [`challenge`] is Ghost Gate's exact challenge codec and binding helpers. The gate id,
//!   configuration version, network and genesis are chosen by Ghost Gate, never by the caller.
//! * [`chain`] is the explicit, node-asserted evidence layer. Its only positive source is an
//!   operator-pinned authenticated base node; the plain base-node gRPC source is diagnostic and
//!   can never produce a positive experimental verdict.
//!
//! [`server::Ggbp1TestServer`] ties those together. Every success value it returns is named
//! `verified_test_only` or `cryptographically_valid_chain_unverified` and is deliberately not
//! convertible into a Ghost Gate session, access grant, or Telegram authorization.

pub mod chain;
pub mod challenge;
pub mod server;
pub mod v3;

pub use chain::{
    Ggbp1ChainChecker, Ggbp1ChainError, Ggbp1ChainPolicy, Ggbp1ChainSnapshot, Ggbp1ChainView,
    Ggbp1ChainViewError, Ggbp1EvidenceSource, Ggbp1ObservedOutput,
};
pub use challenge::{
    CHALLENGE_BYTES, ESMERALDA_GENESIS_HASH, ESMERALDA_NETWORK, MAINNET_NETWORK,
    decode_challenge, encode_challenge, gate_configuration_version, gate_id_bytes,
};
pub use server::{
    Ggbp1ChallengeRequest, Ggbp1ChallengeView, Ggbp1ServerError, Ggbp1TestServer, Ggbp1TestVerdict,
    Ggbp1TestVerdictStatus,
};
pub use v3::{
    GGBP1_EXPERIMENTAL_VERSION, GGBP1_MAX_OUTPUTS, GGBP1_MAX_PROOF_BYTES,
    GGBP1_STANDARD_SCRIPT_BYTES, Ggbp1Challenge, Ggbp1Error, Ggbp1Proof, Ggbp1WireProof,
    SyntheticOutputWitness, SyntheticStandardOutput, SyntheticSubjectWitness,
    expected_commitment_generator_fingerprint, prove_synthetic, verify_synthetic,
};
