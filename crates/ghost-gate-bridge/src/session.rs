//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! Fresh, single-use challenges and the jobs that answer them.
//!
//! One challenge yields at most one session. That is enforced here as well as on chain, and the two
//! are not redundant: the gate burns the nonce in committed state, so a replay cannot mint a second
//! session even against a bridge that forgot. This side exists so a bridge that *does* forget still
//! cannot, and so an in-flight answer is not mistaken for a second one.
//!
//! Expiry is wall-clock, not epoch. The gate compares epochs itself and is the layer that actually
//! enforces it; the bridge's clock bounds how long *it* will keep trying, and is deliberately the
//! stricter of the two in practice because a site chooses it.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ghost_gate_core::Challenge;
use serde::{Deserialize, Serialize};

/// A random 32-byte nonce from the OS RNG.
pub fn random_nonce() -> [u8; 32] {
    let mut buf = [0u8; 32];
    rand::fill(&mut buf);
    buf
}

/// How long a prover has to answer a challenge the bridge minted.
pub const DEFAULT_CHALLENGE_TTL: Duration = Duration::from_secs(180);

/// A challenge the bridge issued and has not yet consumed.
#[derive(Debug, Clone)]
pub struct IssuedChallenge {
    pub challenge: Challenge,
    /// When this bridge stops considering it answerable. Not the gate's rule; see the module docs.
    pub expires_at: SystemTime,
}

/// Why a challenge was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BookError {
    #[error("GG: unknown challenge")]
    Unknown,
    #[error("GG: challenge has expired")]
    Expired,
    #[error("GG: challenge has already been answered")]
    Consumed,
    #[error("GG: challenge belongs to a different browser session")]
    SessionMismatch,
    #[error("GG: too many live challenges; wait for one to be answered or expire")]
    TooManyChallenges,
}

/// The most live challenges the book will hold at once.
///
/// A challenge is state the process holds for up to the TTL, and minting one is unauthenticated
/// apart from the origin policy. Without a cap, a page that loops the challenge route grows the
/// process's memory without bound -- a denial of service that costs the attacker one request per
/// entry. 256 is far above anything an honest user produces (a handful per session) and far below
/// anything that matters to the allocator.
pub const MAX_LIVE_CHALLENGES: usize = 256;

/// The bridge's live challenges.
#[derive(Debug, Default)]
pub struct ChallengeBook {
    entries: HashMap<[u8; 32], IssuedChallenge>,
    answered: HashMap<[u8; 32], SystemTime>,
}

impl ChallengeBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a freshly issued challenge.
    ///
    /// Refuses a duplicate nonce rather than overwriting: a collision must not silently invalidate a
    /// session somebody already holds.
    pub fn insert(&mut self, challenge: Challenge, ttl: Duration) -> Result<(), BookError> {
        let nonce = challenge.nonce.into_array();
        if self.entries.contains_key(&nonce) {
            return Err(BookError::Consumed);
        }
        // The cap is enforced on insert, after pruning whatever has already expired: a book that
        // hit its cap through normal traffic frees the expired entries first, so the cap bounds
        // *concurrent* challenges, not the rate.
        self.prune_expired();
        if self.entries.len() >= MAX_LIVE_CHALLENGES {
            return Err(BookError::TooManyChallenges);
        }
        self.entries.insert(
            nonce,
            IssuedChallenge {
                challenge,
                expires_at: SystemTime::now() + ttl,
            },
        );
        Ok(())
    }

    /// Drops every entry whose TTL has passed.
    ///
    /// Called on insert rather than on a timer: the book has no background task, and the only
    /// operation that can grow it is the one that should pay for cleaning it.
    fn prune_expired(&mut self) {
        let now = SystemTime::now();
        self.entries.retain(|_, e| e.expires_at > now);
    }

    /// How many challenges are currently held, live or expired-but-not-yet-pruned.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Reads a challenge without consuming it.
    pub fn peek(&self, nonce: &[u8; 32]) -> Result<&IssuedChallenge, BookError> {
        if self.answered.contains_key(nonce) {
            return Err(BookError::Consumed);
        }
        self.entries
            .get(nonce)
            .ok_or(BookError::Unknown)
            .and_then(|e| {
                if SystemTime::now() > e.expires_at {
                    Err(BookError::Expired)
                } else {
                    Ok(e)
                }
            })
    }

    /// Confirms a challenge is live and belongs to `session_commitment`, without consuming it.
    ///
    /// Separate from [`Self::consume`] so that a *refused* proof does not burn the challenge. A user
    /// who was declined because they were one unit short should be able to try again against the same
    /// session; burning the nonce on failure would turn every mistake into a support ticket.
    pub fn check_live(&self, nonce: &[u8; 32], session_commitment: &[u8]) -> Result<(), BookError> {
        let entry = self.peek(nonce)?;
        if entry.challenge.session_commitment.as_slice() != session_commitment {
            return Err(BookError::SessionMismatch);
        }
        Ok(())
    }

    /// Consumes a challenge only after its proof has been *accepted*, and only if it belongs to the
    /// session that answered it.
    ///
    /// The ordering matters: a rejected proof must leave the challenge live, and only a committed
    /// acceptance retires it.
    pub fn consume_on_acceptance(
        &mut self,
        nonce: &[u8; 32],
        session_commitment: &[u8],
    ) -> Result<IssuedChallenge, BookError> {
        self.check_live(nonce, session_commitment)?;
        self.answered.insert(*nonce, SystemTime::now());
        Ok(self.entries.remove(nonce).expect("checked above"))
    }

    /// Number of live, unanswered challenges.
    pub fn live(&self) -> usize {
        self.entries.len()
    }

    /// Number of challenges this bridge has accepted an answer for.
    pub fn answered(&self) -> usize {
        self.answered.len()
    }

    /// Drops challenges that expired more than `grace` ago, and the record of answers older still.
    pub fn prune(&mut self, grace: Duration) {
        let now = SystemTime::now();
        self.entries
            .retain(|_, e| now.duration_since(e.expires_at).map_or(true, |d| d < grace));
        self.answered
            .retain(|_, at| now.duration_since(*at).map_or(true, |d| d < grace));
    }
}

/// Where an answer has got to.
// Deserialization is deliberately absent: a proof status is produced here and read over the wire,
// never parsed back. That constraint is what allows the credential variant to reuse the consensus
// receipt type without widening what can arrive on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProofStatus {
    /// The wallet is building the statement.
    Preparing,
    /// The transaction is submitted and the network has not finished with it.
    Submitted { transaction_id: String },
    /// Committed and accepted.
    Accepted { result: PublicProof },
    /// Committed and refused, or refused before sequencing. Carries the network's own words.
    Refused { reason: String },
    /// The wallet or the network could not be reached.
    Failed { reason: String },
    /// Accepted through the credential mode. A separate variant, not a reshaped `Accepted`, so a
    /// receipt always says which proof machinery produced it: a credential receipt names the
    /// output it stands on, which is the property that makes it Mode B, and nothing may present
    /// it as the consensus mode's receipt.
    CredentialAccepted {
        result: Box<crate::credential::CredentialReceipt>,
    },
}

/// The public result of a proof. This is the whole surface that leaves the bridge.
///
/// No field can hold a key, a mask, a balance, a decrypted value or a UTXO identifier, and none was
/// removed for that reason: the type was designed so that adding one would be a visible change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicProof {
    /// The gate that accepted it.
    pub gate_id: String,
    /// The gate component's address, so a site can read the gate itself.
    pub gate_address: String,
    /// The resource the threshold was denominated in, by address.
    pub resource_address: String,
    /// The raw threshold the gate required.
    pub required_minimum: u64,
    /// The public floor the committed receipt attested. **A lower bound, never the real amount.**
    pub attested_minimum: u64,
    /// How many live inputs the proof consumed. A count, not a list.
    pub input_count: u32,
    /// The challenge nonce this answer burnt.
    pub challenge_nonce: String,
    /// The transaction the network committed.
    pub transaction_id: String,
}

/// A proof the bridge is working on, and the only thing a caller may poll.
#[derive(Debug, Clone)]
pub struct ProofJob {
    pub id: String,
    pub gate_id: String,
    pub challenge_nonce: [u8; 32],
    pub status: ProofStatus,
    pub started_at: SystemTime,
}

/// Seconds since the Unix epoch.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tari_template_lib_types::{ComponentAddress, Hash32, MaxBytes, ObjectKey, ResourceAddress};

    fn challenge(nonce: u8) -> Challenge {
        Challenge {
            gate: ComponentAddress::new(ObjectKey::from_array([1u8; 32])),
            resource: ResourceAddress::new(ObjectKey::from_array([7u8; 32])),
            threshold: 10_000,
            network: ghost_gate_core::network::LOCALNET,
            nonce: Hash32::from_array([nonce; 32]),
            expires_epoch: 1_000,
            relying_site: MaxBytes::new_checked(b"vip.example".to_vec()).unwrap(),
            session_commitment: MaxBytes::new_checked(b"session-1".to_vec()).unwrap(),
        }
    }

    const TTL: Duration = Duration::from_secs(60);

    #[test]
    fn a_challenge_is_live_until_answered() {
        let mut book = ChallengeBook::new();
        book.insert(challenge(1), TTL).unwrap();
        assert_eq!(book.live(), 1);
        assert!(book.check_live(&[1u8; 32], b"session-1").is_ok());
        assert_eq!(book.live(), 1, "checking is not consuming");
    }

    #[test]
    fn an_accepted_answer_retires_the_challenge() {
        let mut book = ChallengeBook::new();
        book.insert(challenge(1), TTL).unwrap();
        book.consume_on_acceptance(&[1u8; 32], b"session-1")
            .unwrap();
        assert_eq!(book.live(), 0);
        assert_eq!(book.answered(), 1);
        assert_eq!(
            book.consume_on_acceptance(&[1u8; 32], b"session-1")
                .unwrap_err(),
            BookError::Consumed,
            "a second answer finds nothing, and is told it was already answered rather than \
             that it does not exist -- the more useful of the two refusals"
        );
    }

    #[test]
    fn an_answer_from_another_session_is_refused_and_leaves_the_challenge_live() {
        let mut book = ChallengeBook::new();
        book.insert(challenge(1), TTL).unwrap();
        assert_eq!(
            book.consume_on_acceptance(&[1u8; 32], b"session-2")
                .unwrap_err(),
            BookError::SessionMismatch
        );
        assert_eq!(
            book.live(),
            1,
            "a lifted answer must not burn the challenge"
        );
    }

    #[test]
    fn an_expired_challenge_is_refused() {
        let mut book = ChallengeBook::new();
        book.insert(challenge(1), Duration::from_millis(1)).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(
            book.check_live(&[1u8; 32], b"session-1").unwrap_err(),
            BookError::Expired
        );
    }

    #[test]
    fn a_duplicate_nonce_is_refused_rather_than_overwriting() {
        let mut book = ChallengeBook::new();
        book.insert(challenge(1), TTL).unwrap();
        assert_eq!(
            book.insert(challenge(1), TTL).unwrap_err(),
            BookError::Consumed
        );
        assert_eq!(book.live(), 1);
    }

    #[test]
    fn the_public_proof_carries_a_floor_and_never_a_balance() {
        // A field-by-field statement of the privacy boundary. If someone adds an `amount` or a `balance`
        // field, this test is the one that should fail.
        let proof = PublicProof {
            gate_id: "g1".into(),
            gate_address: "component_..".into(),
            resource_address: "resource_..".into(),
            required_minimum: 10_000,
            attested_minimum: 10_000,
            input_count: 1,
            challenge_nonce: "ab..".into(),
            transaction_id: "cd..".into(),
        };
        let json = serde_json::to_string(&proof).unwrap();
        assert_eq!(
            json,
            r#"{"gate_id":"g1","gate_address":"component_..","resource_address":"resource_..","required_minimum":10000,"attested_minimum":10000,"input_count":1,"challenge_nonce":"ab..","transaction_id":"cd.."}"#,
            "the serialised public result must be exactly these fields"
        );
    }
}
