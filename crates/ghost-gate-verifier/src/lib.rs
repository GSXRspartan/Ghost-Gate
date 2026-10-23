//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! Self-hostable Ghost Gate relying-side logic.
//!
//! A relying site runs this library itself. There is no central Ghost Gate oracle: a site issues
//! its own challenges, watches the chain for its own gate, and mints its own sessions. Nobody is
//! told which users visited.
//!
//! What lives here:
//! - challenge issuance with a cryptographically random nonce and a bounded lifetime;
//! - one-time consumption, so a committed proof yields exactly one session;
//! - finality gating, so a pending or rejected transaction yields nothing;
//! - short-lived sessions whose meaning is "the user proved control around login time", not "the
//!   user holds funds now";
//! - resource *presentation*: rendering a raw amount with the resource's own divisibility.
//!
//! # Presentation lives here, not in the gate
//!
//! Formatting a threshold as `1,000,000 GHOSTTEST` needs the resource's divisibility and its symbol.
//! Neither belongs in a consensus rule, and neither is trustworthy input: a symbol is chosen by whoever
//! created the resource, and a site that let a caller name the token would let a caller name the asset.
//! So [`display`] renders from the *address*, the divisibility the gate read off chain, and a symbol
//! the site resolved itself -- and everything it produces is for a human, never for a comparison.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ghost_gate_core::Challenge;
use sha2::{Digest, Sha256};

pub mod display;
pub mod hosted;

/// How long a prover has to produce a proof after being issued a challenge.
pub const DEFAULT_CHALLENGE_TTL: Duration = Duration::from_secs(180);

/// How long a relying site trusts an access-time proof.
///
/// Deliberately an hour rather than the three minutes of a challenge: the challenge bounds when the
/// user had to act, the session bounds how long the site keeps the door open. A session is a claim
/// about the past ("around login time"), never about the present.
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(3_600);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifierError {
    #[error("GG: unknown challenge")]
    UnknownChallenge,
    #[error("GG: challenge has expired")]
    Expired,
    #[error("GG: challenge has already been redeemed")]
    AlreadyRedeemed,
    #[error("GG: challenge does not match this session")]
    SessionMismatch,
    #[error("GG: transaction is not committed yet")]
    NotFinalized,
    #[error("GG: transaction was rejected: {0}")]
    Rejected(String),
    #[error("GG: transaction did not produce a Ghost Gate proof for this challenge")]
    NoMatchingProof,
}

/// What a relying site knows about a submitted transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionStatus {
    /// Submitted, not yet finalised. Grants nothing.
    Pending,
    /// Committed with a decision. `accept` is what a Ghost Gate proof needs.
    Committed { accept: bool },
    /// Rejected at submission or by consensus. Grants nothing.
    Rejected { reason: String },
}

/// A challenge the site has issued and not yet redeemed.
#[derive(Debug, Clone)]
pub struct IssuedChallenge {
    pub challenge: Challenge,
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
}

/// A short-lived access session.
///
/// The honest description of what it asserts: "the holder proved control of at least the gate
/// threshold at the time this session was issued". It asserts nothing about the holder's balance
/// now, their identity, or whether they are a unique human.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessSession {
    pub id: String,
    pub challenge_nonce: [u8; 32],
    pub gate: String,
    pub threshold: u64,
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
}

/// A relying site's challenge book.
#[derive(Debug, Default)]
pub struct ChallengeBook {
    challenges: HashMap<[u8; 32], IssuedChallenge>,
}

impl ChallengeBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a freshly issued challenge.
    ///
    /// Rejects a duplicate nonce rather than overwriting: a collision must never silently
    /// invalidate a session somebody already holds.
    pub fn insert(&mut self, challenge: Challenge, ttl: Duration) -> Result<(), VerifierError> {
        let now = SystemTime::now();
        let nonce = challenge.nonce.into_array();
        if self.challenges.contains_key(&nonce) {
            return Err(VerifierError::AlreadyRedeemed);
        }
        self.challenges.insert(
            nonce,
            IssuedChallenge {
                challenge,
                issued_at: now,
                expires_at: now + ttl,
            },
        );
        Ok(())
    }

    /// Fetches an issued challenge without consuming it.
    pub fn peek(&self, nonce: &[u8; 32]) -> Result<&IssuedChallenge, VerifierError> {
        self.challenges.get(nonce).ok_or(VerifierError::UnknownChallenge)
    }

    /// Consumes a challenge, returning it if it was live.
    ///
    /// This is the single-use boundary. A second call with the same nonce fails, which is what stops
    /// a copied committed transaction from being replayed into a second session.
    pub fn consume(
        &mut self,
        nonce: &[u8; 32],
        session_commitment: &[u8],
    ) -> Result<IssuedChallenge, VerifierError> {
        let entry = self.challenges.get(nonce).ok_or(VerifierError::UnknownChallenge)?;
        if SystemTime::now() > entry.expires_at {
            return Err(VerifierError::Expired);
        }
        if entry.challenge.session_commitment.as_slice() != session_commitment {
            return Err(VerifierError::SessionMismatch);
        }
        let entry = self
            .challenges
            .remove(nonce)
            .ok_or(VerifierError::AlreadyRedeemed)?;
        Ok(entry)
    }

    /// Number of live, unredeemed challenges.
    pub fn live(&self) -> usize {
        self.challenges.len()
    }

    /// Drops challenges that expired more than `grace` ago.
    ///
    /// A relying site that never calls this grows without bound. Expired entries are worth nothing
    /// and keeping them only widens the window for a nonce collision to matter.
    pub fn prune(&mut self, grace: Duration) {
        let now = SystemTime::now();
        self.challenges
            .retain(|_, entry| now.duration_since(entry.expires_at).map_or(true, |d| d < grace));
    }
}

/// A committed Ghost Gate proof, as observed from the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedProof {
    pub transaction_id: String,
    pub challenge_nonce: [u8; 32],
    pub attested_minimum: u64,
    pub input_count: u32,
}

/// Decides whether an observed transaction grants access, and mints the session if it does.
///
/// Takes the finality evidence as an argument rather than fetching it, so the caller cannot
/// accidentally pass "submitted" for "committed".
pub fn observe_and_authorize(
    book: &mut ChallengeBook,
    status: &TransactionStatus,
    proof: Option<&CommittedProof>,
    session_commitment: &[u8],
    session_ttl: Duration,
    session_id: String,
) -> Result<AccessSession, VerifierError> {
    match status {
        TransactionStatus::Pending => return Err(VerifierError::NotFinalized),
        TransactionStatus::Rejected { reason } => return Err(VerifierError::Rejected(reason.clone())),
        TransactionStatus::Committed { accept: false } => return Err(VerifierError::NoMatchingProof),
        TransactionStatus::Committed { accept: true } => {},
    }

    let proof = proof.ok_or(VerifierError::NoMatchingProof)?;

    let issued = book.consume(&proof.challenge_nonce, session_commitment)?;

    let now = SystemTime::now();
    Ok(AccessSession {
        id: session_id,
        challenge_nonce: proof.challenge_nonce,
        gate: issued.challenge.gate.to_string(),
        threshold: issued.challenge.threshold,
        issued_at: now,
        expires_at: now + session_ttl,
    })
}

/// Whether `session` is still usable at `now`.
pub fn session_is_live(session: &AccessSession, now: SystemTime) -> bool {
    now < session.expires_at
}

/// A random 32-byte nonce from the OS RNG.
pub fn random_nonce() -> [u8; 32] {
    let mut buf = [0u8; 32];
    rand::fill(&mut buf);
    buf
}

/// An opaque session commitment.
///
/// The site sends its own random value to the browser and stores nothing about the user; the
/// commitment binds a proof to the browser session that requested it, so a proof captured from one
/// session cannot be redeemed in another.
pub fn session_commitment(site_nonce: &[u8], browser_nonce: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"tari.ghost_gate.session.v1");
    hasher.update(site_nonce);
    hasher.update(browser_nonce);
    hasher.finalize().to_vec()
}

/// Seconds since the Unix epoch, for tests and for logging.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_gate_core::network;
    use tari_template_lib_types::{ComponentAddress, Hash32, MaxBytes, ObjectKey, ResourceAddress};

    const RESOURCE: ResourceAddress = ResourceAddress::new(ObjectKey::from_array([7u8; ObjectKey::LENGTH]));
    const GATE: ComponentAddress = ComponentAddress::new(ObjectKey::from_array([1u8; ObjectKey::LENGTH]));

    fn challenge(nonce: u8) -> Challenge {
        Challenge {
            gate: GATE,
            resource: RESOURCE,
            threshold: 10_000,
            network: network::LOCALNET,
            nonce: Hash32::from_array([nonce; 32]),
            expires_epoch: 1_000,
            relying_site: MaxBytes::new_checked(b"vip.example".to_vec()).unwrap(),
            session_commitment: MaxBytes::new_checked(b"commit".to_vec()).unwrap(),
        }
    }

    fn proof(nonce: u8) -> CommittedProof {
        CommittedProof {
            transaction_id: "abc".to_string(),
            challenge_nonce: [nonce; 32],
            attested_minimum: 10_000,
            input_count: 1,
        }
    }

    #[test]
    fn an_accepted_committed_proof_yields_one_session() {
        let mut book = ChallengeBook::new();
        book.insert(challenge(1), DEFAULT_CHALLENGE_TTL).unwrap();

        let session = observe_and_authorize(
            &mut book,
            &TransactionStatus::Committed { accept: true },
            Some(&proof(1)),
            b"commit",
            DEFAULT_SESSION_TTL,
            "session-1".to_string(),
        )
        .expect("must authorize");
        assert_eq!(session.threshold, 10_000);
        assert!(session_is_live(&session, SystemTime::now()));
    }

    #[test]
    fn replaying_the_same_proof_yields_no_second_session() {
        let mut book = ChallengeBook::new();
        book.insert(challenge(1), DEFAULT_CHALLENGE_TTL).unwrap();

        observe_and_authorize(
            &mut book,
            &TransactionStatus::Committed { accept: true },
            Some(&proof(1)),
            b"commit",
            DEFAULT_SESSION_TTL,
            "first".to_string(),
        )
        .unwrap();

        let second = observe_and_authorize(
            &mut book,
            &TransactionStatus::Committed { accept: true },
            Some(&proof(1)),
            b"commit",
            DEFAULT_SESSION_TTL,
            "second".to_string(),
        );
        assert_eq!(second.unwrap_err(), VerifierError::UnknownChallenge);
    }

    #[test]
    fn pending_grants_nothing() {
        let mut book = ChallengeBook::new();
        book.insert(challenge(1), DEFAULT_CHALLENGE_TTL).unwrap();
        let err = observe_and_authorize(
            &mut book,
            &TransactionStatus::Pending,
            Some(&proof(1)),
            b"commit",
            DEFAULT_SESSION_TTL,
            "s".to_string(),
        )
        .unwrap_err();
        assert_eq!(err, VerifierError::NotFinalized);
        assert_eq!(book.live(), 1, "the challenge must survive so the prover can retry");
    }

    #[test]
    fn rejected_grants_nothing() {
        let mut book = ChallengeBook::new();
        book.insert(challenge(1), DEFAULT_CHALLENGE_TTL).unwrap();
        let err = observe_and_authorize(
            &mut book,
            &TransactionStatus::Rejected {
                reason: "below threshold".to_string(),
            },
            None,
            b"commit",
            DEFAULT_SESSION_TTL,
            "s".to_string(),
        )
        .unwrap_err();
        assert!(matches!(err, VerifierError::Rejected(_)));
    }

    #[test]
    fn a_committed_transaction_with_no_matching_proof_grants_nothing() {
        let mut book = ChallengeBook::new();
        book.insert(challenge(1), DEFAULT_CHALLENGE_TTL).unwrap();
        let err = observe_and_authorize(
            &mut book,
            &TransactionStatus::Committed { accept: false },
            None,
            b"commit",
            DEFAULT_SESSION_TTL,
            "s".to_string(),
        )
        .unwrap_err();
        assert_eq!(err, VerifierError::NoMatchingProof);
    }

    #[test]
    fn a_proof_for_a_different_session_is_refused() {
        let mut book = ChallengeBook::new();
        book.insert(challenge(1), DEFAULT_CHALLENGE_TTL).unwrap();
        let err = observe_and_authorize(
            &mut book,
            &TransactionStatus::Committed { accept: true },
            Some(&proof(1)),
            b"other-session",
            DEFAULT_SESSION_TTL,
            "s".to_string(),
        )
        .unwrap_err();
        assert_eq!(err, VerifierError::SessionMismatch);
    }

    #[test]
    fn duplicate_nonce_insert_is_refused() {
        let mut book = ChallengeBook::new();
        book.insert(challenge(1), DEFAULT_CHALLENGE_TTL).unwrap();
        assert_eq!(
            book.insert(challenge(1), DEFAULT_CHALLENGE_TTL).unwrap_err(),
            VerifierError::AlreadyRedeemed
        );
    }

    #[test]
    fn random_nonces_differ() {
        assert_ne!(random_nonce(), random_nonce());
    }

    #[test]
    fn session_commitment_depends_on_both_inputs() {
        assert_ne!(session_commitment(b"a", b"b"), session_commitment(b"a", b"c"));
        assert_eq!(session_commitment(b"a", b"b"), session_commitment(b"a", b"b"));
    }
}
