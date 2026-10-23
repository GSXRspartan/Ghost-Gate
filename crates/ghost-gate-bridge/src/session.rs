//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! Fresh, single-use challenges and the jobs that answer them.
//!
//! One challenge yields at most one submission and one session. That is enforced here as well as on
//! chain, and the two are not redundant: the gate burns the nonce in committed state, so a replay
//! cannot mint a second session even against a bridge that forgot. This side exists so a bridge
//! that *does* forget still cannot, and so an in-flight answer is not mistaken for a second one.
//!
//! The book is intentionally process-local. A restart or a request sent to a different bridge
//! process finds no issued nonce and is refused; deployments that need availability across those
//! boundaries must put this state machine behind an atomic durable store before load balancing.
//!
//! Expiry is wall-clock, not epoch. The gate compares epochs itself and is the layer that actually
//! enforces it; the bridge's clock bounds how long *it* will keep trying, and is deliberately the
//! stricter of the two in practice because a site chooses it.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ghost_gate_core::xtm::XtmChallenge;
use ghost_gate_core::Challenge;
use serde::{Deserialize, Serialize};
use tari_template_lib_types::Hash32;

/// A random 32-byte nonce from the OS RNG.
pub fn random_nonce() -> [u8; 32] {
    let mut buf = [0u8; 32];
    rand::fill(&mut buf);
    buf
}

/// How long a prover has to answer a challenge the bridge minted.
pub const DEFAULT_CHALLENGE_TTL: Duration = Duration::from_secs(180);

/// Either proof machinery's challenge.
///
/// The two cannot be confused: each variant carries its own fields and its own verification path,
/// and every consumer matches on the variant it can handle. This is the type-level half of the
/// cross-network guarantee — an Ootle proof answers an `Ootle` challenge or nothing, and an XTM
/// proof answers a `MinotariXtm` challenge or nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyChallenge {
    Ootle(Challenge),
    MinotariXtm(XtmChallenge),
}

impl AnyChallenge {
    /// The single-use nonce, whichever machinery the challenge belongs to.
    pub fn nonce(&self) -> Hash32 {
        match self {
            Self::Ootle(c) => c.nonce,
            Self::MinotariXtm(c) => c.nonce,
        }
    }

    pub fn network(&self) -> u8 {
        match self {
            Self::Ootle(c) => c.network,
            Self::MinotariXtm(c) => c.network,
        }
    }

    pub fn threshold(&self) -> u64 {
        match self {
            Self::Ootle(c) => c.threshold,
            Self::MinotariXtm(c) => c.threshold_micro,
        }
    }

    pub fn session_commitment(&self) -> &[u8] {
        match self {
            Self::Ootle(c) => c.session_commitment.as_slice(),
            Self::MinotariXtm(c) => c.session_commitment.as_slice(),
        }
    }

    pub fn relying_site(&self) -> &[u8] {
        match self {
            Self::Ootle(c) => c.relying_site.as_slice(),
            Self::MinotariXtm(c) => c.relying_site.as_slice(),
        }
    }

    /// The Ootle challenge, if this is one.
    pub fn ootle(&self) -> Option<&Challenge> {
        match self {
            Self::Ootle(c) => Some(c),
            Self::MinotariXtm(_) => None,
        }
    }

    /// The Ootle gate component, if this is an Ootle challenge.
    pub fn ootle_gate(&self) -> Option<tari_template_lib_types::ComponentAddress> {
        self.ootle().map(|c| c.gate)
    }

    /// The Ootle resource, if this is an Ootle challenge.
    pub fn ootle_resource(&self) -> Option<tari_template_lib_types::ResourceAddress> {
        self.ootle().map(|c| c.resource)
    }

    /// The L1 XTM challenge, if this is one.
    pub fn minotari_xtm(&self) -> Option<&XtmChallenge> {
        match self {
            Self::Ootle(_) => None,
            Self::MinotariXtm(c) => Some(c),
        }
    }
}

/// A challenge the bridge issued and has not yet consumed.
#[derive(Debug, Clone)]
pub struct IssuedChallenge {
    pub challenge: AnyChallenge,
    /// When this bridge stops considering it answerable. Not the gate's rule; see the module docs.
    pub expires_at: SystemTime,
    /// The browser origin the challenge was minted for, as this bridge observed it.
    ///
    /// The session commitment alone is bearer knowledge: it travels inside the challenge response,
    /// so whoever can read one response can replay the pair from anywhere. The issuing origin is
    /// the part of the binding the reader cannot forge, and recording it is what turns "bound to a
    /// browser session" from a claim into a check. `None` marks an operator/CLI challenge, which
    /// may be answered only by another no-origin caller.
    pub issued_to_origin: Option<String>,
    /// The gate's policy hash at the moment this challenge was minted. A challenge is answered
    /// against the policy it was issued under: if an administrator replaces that policy while the
    /// challenge is outstanding, the old threshold is no longer the rule, so the answer is refused
    /// and a fresh challenge must be minted. `None` for a gate that is not registry-backed.
    pub policy_hash: Option<String>,
    /// The explicit replay state. A submitted challenge remains in the book so finality can be
    /// reconciled, but cannot create a second wallet or base-layer submission.
    pub state: ChallengeState,
}

/// The bridge-side lifecycle for a one-shot challenge.
///
/// `Consumed` lives in `ChallengeBook::answered` rather than on an `IssuedChallenge`, because the
/// live entry is removed when access is granted. The resulting state machine is
/// `Issued -> Submitted -> Consumed`, with `Submitted -> Issued` only after an unverified failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeState {
    Issued,
    Submitted,
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
    #[error("GG: a proof for this challenge is already being processed")]
    InProgress,
    #[error("GG: too many live challenges; wait for one to be answered or expire")]
    TooManyChallenges,
    /// The gate's policy was replaced while this challenge was outstanding: the answer proves the
    /// OLD threshold, so it is refused and a fresh challenge must be minted.
    #[error("GG: the gate policy was replaced while this challenge was outstanding")]
    Superseded,
}

/// The most live challenges the book will hold at once.
///
/// A challenge is state the process holds for up to the TTL, and minting one is unauthenticated
/// apart from the origin policy. Without a cap, a page that loops the challenge route grows the
/// process's memory without bound -- a denial of service that costs the attacker one request per
/// entry. 256 is far above anything an honest user produces (a handful per session) and far below
/// anything that matters to the allocator.
pub const MAX_LIVE_CHALLENGES: usize = 256;

/// The most answered nonces retained for replay detection, after eviction.
pub const MAX_ANSWERED: usize = 4_096;

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
    /// Whether this outstanding challenge may still be answered under `hash`, the policy now in
    /// force. `Ok(())` for a gate with no published policy (nothing to supersede) or a matching hash.
    pub fn policy_current(&self, nonce: &[u8; 32], hash: Option<&str>) -> Result<(), BookError> {
        // An absent or already-answered nonce is a different failure (Unknown/Consumed); this call
        // only answers "may THIS live challenge still be answered under the policy in force?".
        if self.answered.contains_key(nonce) {
            return Err(BookError::Consumed);
        }
        let entry = self.entries.get(nonce).ok_or(BookError::Unknown)?;
        if SystemTime::now() > entry.expires_at {
            return Err(BookError::Expired);
        }
        match entry.policy_hash.as_deref() {
            None => Ok(()),
            Some(minted) if hash == Some(minted) => Ok(()),
            Some(_) => Err(BookError::Superseded),
        }
    }

    pub fn insert(
        &mut self,
        challenge: AnyChallenge,
        ttl: Duration,
        issued_to_origin: Option<String>,
    ) -> Result<(), BookError> {
        self.insert_bound(challenge, ttl, issued_to_origin, None)
    }

    pub fn insert_bound(
        &mut self,
        challenge: AnyChallenge,
        ttl: Duration,
        issued_to_origin: Option<String>,
        policy_hash: Option<String>,
    ) -> Result<(), BookError> {
        let nonce = challenge.nonce().into_array();
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
                issued_to_origin,
                policy_hash,
                state: ChallengeState::Issued,
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
        self.check_current(nonce, session_commitment)?;
        if self.entries.get(nonce).expect("checked above").state == ChallengeState::Submitted {
            return Err(BookError::InProgress);
        }
        Ok(())
    }

    /// Confirms a challenge exists and is owned by this browser session, including one that is
    /// already submitted. Policy validation uses this so an idempotent retry is still origin- and
    /// session-bound before the caller learns its existing job id.
    pub fn check_current(&self, nonce: &[u8; 32], session_commitment: &[u8]) -> Result<(), BookError> {
        let entry = self.peek(nonce)?;
        if entry.challenge.session_commitment() != session_commitment {
            return Err(BookError::SessionMismatch);
        }
        Ok(())
    }

    /// Atomically reserves an issued challenge for one proof submission.
    ///
    /// The caller must subsequently either consume it after a verified acceptance or release it
    /// after an unverified failure. A second caller gets `InProgress`, rather than starting a
    /// competing transaction for the same nonce.
    pub fn reserve_for_submission(
        &mut self,
        nonce: &[u8; 32],
        session_commitment: &[u8],
    ) -> Result<(), BookError> {
        self.check_current(nonce, session_commitment)?;
        let entry = self.entries.get_mut(nonce).expect("checked above");
        if entry.state == ChallengeState::Submitted {
            return Err(BookError::InProgress);
        }
        entry.state = ChallengeState::Submitted;
        Ok(())
    }

    /// Makes a failed, unverified submission retryable again. This is deliberately narrower than
    /// deletion: it preserves the original nonce, policy binding, browser-origin binding and TTL.
    pub fn release_submission(
        &mut self,
        nonce: &[u8; 32],
        session_commitment: &[u8],
    ) -> Result<(), BookError> {
        self.check_current(nonce, session_commitment)?;
        let entry = self.entries.get_mut(nonce).expect("checked above");
        if entry.state != ChallengeState::Submitted {
            return Err(BookError::InProgress);
        }
        entry.state = ChallengeState::Issued;
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
        self.check_current(nonce, session_commitment)?;
        self.answered.insert(*nonce, SystemTime::now());
        // The answered set exists so a replayed challenge answers `AlreadyAnswered` rather than
        // `Unknown`. It is also state a loop of *successful* proofs grows, so it is capped like the
        // live set: the oldest receipts drop once the cap is hit, and a nonce old enough to have
        // fallen out of the cap is also old enough that its live entry is long gone -- so the
        // replay it would have caught now answers `Unknown`, which is still a refusal.
        if self.answered.len() > MAX_ANSWERED {
            let overflow = self.answered.len() - MAX_ANSWERED;
            // Sorted copy of the timestamps rather than a heap: the cap is hit rarely and the map
            // is bounded, so an O(n log n) sweep on the way past is the simpler honest code.
            let mut oldest: Vec<([u8; 32], SystemTime)> =
                self.answered.iter().map(|(k, t)| (*k, *t)).collect();
            oldest.sort_by_key(|(_, t)| *t);
            for (k, _) in oldest.into_iter().take(overflow) {
                self.answered.remove(&k);
            }
        }
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

impl ProofStatus {
    /// The challenge nonce an ACCEPTED consensus proof burnt, for grant lookup. Credential
    /// acceptances carry their nonce on the job, not in the receipt.
    pub fn accepted_nonce(&self) -> Option<&str> {
        match self {
            ProofStatus::Accepted { result } => Some(result.challenge_nonce.as_str()),
            _ => None,
        }
    }
}

/// The public result of a proof. This is the whole surface that leaves the bridge.
///
/// No field can hold a key, a mask, a balance, a decrypted value or a UTXO identifier, and none was
/// removed for that reason: the type was designed so that adding one would be a visible change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicProof {
    /// The gate that accepted it.
    pub gate_id: String,
    /// The gate component's address, so a site can read the gate itself. Empty on an L1 proof.
    pub gate_address: String,
    /// The resource the threshold was denominated in, by address. Empty on an L1 proof.
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
    /// Which proof machinery produced this. Present so a relying site can display it and a client
    /// can tell an L1 proof from an Ootle one by type; nothing branches on it for access decisions
    /// — the gate that accepted it already did that.
    pub proof_kind: ProofKindName,
}

/// The proof machinery's name on the wire. A string alias, not a free-form string.
pub type ProofKindName = crate::gate_registry::ProofKind;

/// A proof the bridge is working on, and the only thing a caller may poll.
#[derive(Debug, Clone)]
pub struct ProofJob {
    pub id: String,
    pub gate_id: String,
    pub challenge_nonce: [u8; 32],
    pub status: ProofStatus,
    pub started_at: SystemTime,
    /// The L1 artifact this job is proving with, when the gate is a native XTM gate. Not serialised:
    /// it never leaves the process. The reconciliation reads the kernel signature and output hash
    /// from here rather than from anywhere a caller could influence.
    pub xtm_artifact: Option<crate::xtm::XtmProofArtifact>,
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

    pub fn challenge(nonce: u8) -> AnyChallenge {
        AnyChallenge::Ootle(Challenge {
            gate: ComponentAddress::new(ObjectKey::from_array([1u8; 32])),
            resource: ResourceAddress::new(ObjectKey::from_array([7u8; 32])),
            threshold: 10_000,
            network: ghost_gate_core::network::LOCALNET,
            nonce: Hash32::from_array([nonce; 32]),
            expires_epoch: 1_000,
            relying_site: MaxBytes::new_checked(b"vip.example".to_vec()).unwrap(),
            session_commitment: MaxBytes::new_checked(b"session-1".to_vec()).unwrap(),
        })
    }

    const TTL: Duration = Duration::from_secs(60);

    #[test]
    fn a_challenge_is_live_until_answered() {
        let mut book = ChallengeBook::new();
        book.insert(challenge(1), TTL, None).unwrap();
        assert_eq!(book.live(), 1);
        assert!(book.check_live(&[1u8; 32], b"session-1").is_ok());
        assert_eq!(book.live(), 1, "checking is not consuming");
    }

    #[test]
    fn an_accepted_answer_retires_the_challenge() {
        let mut book = ChallengeBook::new();
        book.insert(challenge(1), TTL, None).unwrap();
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
    fn only_one_submission_can_reserve_a_challenge() {
        let mut book = ChallengeBook::new();
        book.insert(challenge(1), TTL, None).unwrap();

        book.reserve_for_submission(&[1u8; 32], b"session-1").unwrap();
        assert_eq!(
            book.reserve_for_submission(&[1u8; 32], b"session-1").unwrap_err(),
            BookError::InProgress,
            "the check and reservation are one state transition"
        );
        assert_eq!(
            book.check_live(&[1u8; 32], b"session-1").unwrap_err(),
            BookError::InProgress,
        );
    }

    #[test]
    fn an_unverified_failure_releases_the_original_challenge_for_retry() {
        let mut book = ChallengeBook::new();
        book.insert(challenge(1), TTL, None).unwrap();
        book.reserve_for_submission(&[1u8; 32], b"session-1").unwrap();
        book.release_submission(&[1u8; 32], b"session-1").unwrap();
        assert!(book.check_live(&[1u8; 32], b"session-1").is_ok());
    }

    #[test]
    fn an_answer_from_another_session_is_refused_and_leaves_the_challenge_live() {
        let mut book = ChallengeBook::new();
        book.insert(challenge(1), TTL, None).unwrap();
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
        book.insert(challenge(1), Duration::from_millis(1), None).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(
            book.check_live(&[1u8; 32], b"session-1").unwrap_err(),
            BookError::Expired
        );
    }

    #[test]
    fn a_duplicate_nonce_is_refused_rather_than_overwriting() {
        let mut book = ChallengeBook::new();
        book.insert(challenge(1), TTL, None).unwrap();
        assert_eq!(
            book.insert(challenge(1), TTL, None).unwrap_err(),
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
            proof_kind: crate::gate_registry::ProofKind::Ootle,
        };
        let json = serde_json::to_string(&proof).unwrap();
        assert_eq!(
            json,
            r#"{"gate_id":"g1","gate_address":"component_..","resource_address":"resource_..","required_minimum":10000,"attested_minimum":10000,"input_count":1,"challenge_nonce":"ab..","transaction_id":"cd..","proof_kind":"ootle"}"#,
            "the serialised public result must be exactly these fields"
        );
    }
}

#[cfg(test)]
mod policy_binding_tests {
    use super::*;
    use tari_template_lib_types::{Hash32 as TemplateHash32, MaxBytes};

    /// A well-formed Ootle challenge; the nonce is what identifies it in the book.
    fn challenge(nonce: u8) -> AnyChallenge {
        AnyChallenge::Ootle(Challenge {
            gate: tari_template_lib_types::ComponentAddress::try_from([1u8; 32]).unwrap(),
            resource: tari_template_lib_types::ResourceAddress::try_from([2u8; 32]).unwrap(),
            threshold: 10,
            network: ghost_gate_core::network::LOCALNET,
            nonce: TemplateHash32::from_array([nonce; 32]),
            expires_epoch: 1_000,
            relying_site: MaxBytes::new_checked(b"site".to_vec()).unwrap(),
            session_commitment: MaxBytes::new_checked(b"aa".to_vec()).unwrap(),
        })
    }

    #[test]
    fn a_replaced_policy_supersedes_an_outstanding_challenge() {
        let mut book = ChallengeBook::new();
        book.insert_bound(challenge(7), Duration::from_secs(60), Some("http://site".into()), Some("hash-v1".into())).unwrap();
        let nonce = [7u8; 32];
        // While v1 is the policy in force, the challenge is answerable.
        assert!(book.policy_current(&nonce, Some("hash-v1")).is_ok());
        // The administrator replaces the policy: the outstanding answer proves the OLD threshold,
        // so it must not be answerable any more.
        assert_eq!(book.policy_current(&nonce, Some("hash-v2")), Err(BookError::Superseded));
        // Nor if the version was withdrawn entirely.
        assert_eq!(book.policy_current(&nonce, None), Err(BookError::Superseded));
        // The refusal reaches the browser as a reason, not a panic.
        assert_eq!(crate::policy::ProofRefusal::from(BookError::Superseded), crate::policy::ProofRefusal::PolicyReplaced);
    }

    #[test]
    fn a_gate_with_no_policy_binding_is_unaffected() {
        let mut book = ChallengeBook::new();
        book.insert(challenge(7), Duration::from_secs(60), Some("http://site".into())).unwrap();
        assert!(book.policy_current(&[7u8; 32], Some("anything")).is_ok());
        assert_eq!(book.policy_current(&[9u8; 32], Some("anything")), Err(BookError::Unknown));
    }
}
