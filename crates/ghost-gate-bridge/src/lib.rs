//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! The relying side of Ghost Gate, minus the network.
//!
//! This crate is the part a relying site's backend runs: it knows which gates it operates, mints
//! challenges for them, and decides whether an answer to one of its own challenges is good. It is
//! written to be read, because the interesting part is not what it does but what it refuses to do.
//!
//! # What a proof request is allowed to say
//!
//! A caller supplies a **challenge the bridge itself minted**, for a **gate the bridge itself
//! registered**, plus the session it got that challenge in. It does not supply a resource address, a
//! threshold, a UTXO, a recipient, or an amount it would like spent. None of those can come from a
//! browser: a website that could name the resource could point a wallet at an asset the user holds and
//! the gate does not care about, and a website that could name outputs could spend them.
//!
//! The consequence is worth stating plainly, because it is the design and not an omission: **a website
//! cannot instruct this wallet to spend anything except the qualifying input for the gate it was
//! issued a challenge for.** Input selection happens here or inside the wallet, never in the request.
//!
//! # What leaves this process
//!
//! Only what a site needs to authorise a session: whether a proof was accepted, which gate, which
//! resource, the attested minimum, the challenge and session it is bound to, and the transaction id.
//!
//! Never: private keys, stealth owner secrets, masks, an exact balance, a decrypted UTXO value, the
//! wallet's inventory, or a list of its UTXO identifiers. [`PublicProofResult`] is the entire surface,
//! and it has no field that could hold any of those.
//!
//! # Layout
//!
//! - [`GateRegistry`] — the gates this bridge serves. Registration is an operator action.
//! - [`ChallengeBook`] — fresh, single-use challenges with a bounded lifetime.
//! - [`policy`] — the validation every request passes, and the reason a request is refused.
//! - [`OriginPolicy`] — which browser origins may talk to this process at all.
//! - [`wallet`] — the wallet daemon channel, behind a trait so the policy above is testable without one.
//! - [`credential`] — the credential proof mode (browser wallets): chain-state + signature
//!   verification of a proof-of-funds output, with the properties that distinguish it from the
//!   consensus mode stated rather than blurred.

#![deny(unsafe_code)]

pub mod access;

pub mod credential;
pub mod gate_registry;
pub mod http;
pub mod origin;
pub mod policy;
pub mod replay_store;
pub mod reset_guard;
pub mod server;
pub mod session;
pub mod trace;
pub mod wallet;
pub mod xtm;

pub use credential::{
    ChainReadError, ChainReader, CredentialProofRequest, CredentialReceipt, CredentialRefusal,
    CredentialVerifier,
    NoChainReader, OwnershipProof, UtxoOnChain, ownership_proof_message,
    reported_key_is_the_auth_key,
};
pub use gate_registry::{GateBinding, GateCondition, GateRegistrationError, GateRegistry, ProofKind};
pub use origin::{OriginPolicy, OriginRejection};
pub use policy::{ProofRefusal, ProveRequest, validate_prove_request};
pub use session::{AnyChallenge, ChallengeBook, IssuedChallenge, ProofJob, ProofStatus, PublicProof};
pub use wallet::{
    CommitOutcome, InputChoice, StatementRequest, WalletChannel, WalletError, WalletStatus,
};
pub use xtm::{MinedKernel, XtmChainError, XtmChainReader, XtmChannel, XtmProofArtifact, XtmProofRequest, XtmWalletStatus, XtmTip, verify_xtm_proof};

/// Server version, reported by `GET /health`.
pub const BRIDGE_VERSION: &str = env!("CARGO_PKG_VERSION");
