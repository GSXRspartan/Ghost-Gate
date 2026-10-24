//! Feature-disabled GGBP-1 experimental verifier and chain-view contract.
//!
//! This module deliberately grants no Ghost Gate session and exposes no HTTP endpoint. It is a
//! bounded, in-memory research server used to prove the order of operations a future reviewed
//! integration must preserve: server-issued challenge, public cryptographic verification, trusted
//! chain observation, atomic single redemption, and later revocation.

use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use rand::{CryptoRng, Rng, RngExt};
use tari_crypto::ristretto::{RistrettoPublicKey, pedersen::PedersenCommitment};
use tari_script::TariScript;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::ggbp1::{
    GGBP1_MAX_PROOF_BYTES, Ggbp1Challenge, Ggbp1Error, Ggbp1WireProof, SyntheticOutputWitness,
    SyntheticStandardOutput, SyntheticSubjectWitness, prove_synthetic, verify_synthetic,
};

/// The only two evidence modes this experiment models. A public endpoint is intentionally not an
/// eligible verifier source: the gRPC protocol supplies data, not a portable authenticated proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ggbp1EvidenceSource {
    SyntheticFixture,
    LocallyControlledBaseNode,
}

/// A point-in-time assertion about the base chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ggbp1ChainSnapshot {
    pub source: Ggbp1EvidenceSource,
    pub network: u8,
    pub genesis_hash: [u8; 32],
    pub tip_height: u64,
    pub tip_hash: [u8; 32],
    pub tip_timestamp_unix_seconds: u64,
    pub is_synced: bool,
}

/// Full output evidence needed by this experimental statement. It intentionally contains no
/// opening, private key, encrypted output data, wallet data, or balance.
#[derive(Clone, Debug)]
pub struct Ggbp1ObservedOutput {
    pub output_hash: [u8; 32],
    pub commitment: PedersenCommitment,
    pub script: TariScript,
    pub script_public_key: RistrettoPublicKey,
    pub mined_height: u64,
    pub mined_block_hash: [u8; 32],
    pub confirmations: u64,
    pub maturity_height: u64,
    pub output_version: u32,
    pub output_type: u32,
    pub range_proof_type: u32,
    pub is_unspent: bool,
    pub is_in_best_chain: bool,
}

#[derive(Debug, Error)]
#[error("chain-view failure: {0}")]
pub struct Ggbp1ChainViewError(pub String);

/// Read-only view required by the experimental verifier. Implementations must reject missing or
/// contradictory data rather than filling it from a client response.
#[async_trait]
pub trait Ggbp1ChainView: Send + Sync {
    async fn snapshot(&self) -> Result<Ggbp1ChainSnapshot, Ggbp1ChainViewError>;
    async fn output(
        &self,
        expected: &SyntheticStandardOutput,
    ) -> Result<Option<Ggbp1ObservedOutput>, Ggbp1ChainViewError>;
}

#[derive(Clone, Debug)]
pub struct Ggbp1ChainPolicy {
    pub minimum_confirmations: u64,
    pub maximum_tip_age_seconds: u64,
    pub required_output_version: u32,
    pub required_output_type: u32,
    pub required_range_proof_type: u32,
    /// Tests opt in to fixtures. Any process configured for a node must leave this false.
    pub permit_synthetic_fixtures: bool,
}

impl Ggbp1ChainPolicy {
    pub fn locally_controlled_node() -> Self {
        Self {
            minimum_confirmations: 6,
            maximum_tip_age_seconds: 10 * 60,
            required_output_version: 0,
            required_output_type: 0,
            required_range_proof_type: 0,
            permit_synthetic_fixtures: false,
        }
    }

    pub fn synthetic_test_fixture() -> Self {
        Self {
            minimum_confirmations: 2,
            maximum_tip_age_seconds: 60,
            required_output_version: 0,
            required_output_type: 0,
            required_range_proof_type: 0,
            permit_synthetic_fixtures: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Ggbp1ExperimentalConfig {
    pub network: u8,
    pub genesis_hash: [u8; 32],
    pub origin_hash: [u8; 32],
    pub gate_id: [u8; 16],
    pub gate_configuration_version: u64,
    pub threshold_micro_xtm: u64,
    pub maximum_challenge_ttl_seconds: u64,
    pub chain_policy: Ggbp1ChainPolicy,
}

/// Input already authenticated by an outer, experimental subject-authentication layer. That outer
/// layer may not substitute a client-selected public key for the server's subject record.
#[derive(Clone, Debug)]
pub struct Ggbp1ChallengeRequest {
    pub subject_id: [u8; 16],
    pub subject_authentication_public_key: RistrettoPublicKey,
    pub requested_ttl_seconds: u64,
}

/// A synthetic stand-in for the one wallet-internal API that a future upstream implementation
/// needs. It owns its output witnesses and subject authority, accepts only a fully bound GGBP-1
/// challenge, and returns only canonical public response bytes. It has no arbitrary-signature,
/// secret-export, transaction, or network method.
pub struct SyntheticWalletProver {
    subject: SyntheticSubjectWitness,
    outputs: Vec<SyntheticOutputWitness>,
}

impl SyntheticWalletProver {
    /// Accepts only freshly created synthetic test material; callers cannot attach an existing
    /// wallet, file, seed phrase, or live output to this prototype.
    pub fn new(subject: SyntheticSubjectWitness, outputs: Vec<SyntheticOutputWitness>) -> Self {
        Self { subject, outputs }
    }

    pub fn respond<R: Rng + CryptoRng>(
        &self,
        challenge: &Ggbp1Challenge,
        rng: &mut R,
    ) -> Result<Vec<u8>, Ggbp1Error> {
        let proof = prove_synthetic(challenge, &self.subject, &self.outputs, rng)?;
        Ggbp1WireProof {
            challenge: challenge.clone(),
            proof,
        }
        .to_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ggbp1ExperimentalVerificationStatus {
    VerifiedNotAuthorized,
    Revoked,
}

/// An audit-only result. In particular, `VerifiedNotAuthorized` must never be consumed by
/// production session or Telegram code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ggbp1ExperimentalVerification {
    pub status: Ggbp1ExperimentalVerificationStatus,
    pub challenge_nonce: [u8; 32],
    pub output_hashes: Vec<[u8; 32]>,
    pub verified_tip_hash: [u8; 32],
    pub verified_tip_height: u64,
    pub verified_at_unix_seconds: u64,
}

#[derive(Debug, Error)]
pub enum Ggbp1ServerError {
    #[error("the configured threshold must be nonzero")]
    ZeroThreshold,
    #[error("the subject authentication key is invalid")]
    InvalidSubjectKey,
    #[error("challenge ttl is zero or exceeds the configured maximum")]
    InvalidChallengeTtl,
    #[error("challenge expiry overflows the Unix timestamp range")]
    ExpiryOverflow,
    #[error("proof response exceeds the bounded experimental limit")]
    ResponseTooLarge,
    #[error("the response does not match a currently issued challenge")]
    ChallengeMismatch,
    #[error("the challenge nonce is unknown")]
    ChallengeNotFound,
    #[error("the challenge is expired")]
    ChallengeExpired,
    #[error("another request is already redeeming this challenge")]
    ChallengeInProgress,
    #[error("the challenge has already been redeemed")]
    ChallengeRedeemed,
    #[error("the chain view is not synced")]
    ChainNotSynced,
    #[error("synthetic evidence is not permitted by this verifier configuration")]
    SyntheticEvidenceNotPermitted,
    #[error("the chain network or genesis does not match the server configuration")]
    ChainBindingMismatch,
    #[error("the chain tip is stale or has a future timestamp")]
    StaleTip,
    #[error("the best chain changed while the proof was being checked")]
    ChainChangedDuringVerification,
    #[error("a referenced output was not found in the trusted chain view")]
    OutputNotFound,
    #[error("a referenced output differs from its proof response")]
    OutputMismatch,
    #[error("a referenced output is spent")]
    OutputSpent,
    #[error("a referenced output is not in the best chain")]
    OutputNotInBestChain,
    #[error("a referenced output has contradictory confirmation evidence")]
    ContradictoryConfirmations,
    #[error("a referenced output is immature")]
    OutputImmature,
    #[error("a referenced output does not have enough confirmations")]
    InsufficientConfirmations,
    #[error("a referenced output has an unsupported consensus format")]
    UnsupportedOutputFormat,
    #[error("an output has already been used by another experimental proof")]
    OutputAlreadyRegistered,
    #[error(transparent)]
    Proof(#[from] Ggbp1Error),
    #[error(transparent)]
    Chain(#[from] Ggbp1ChainViewError),
}

#[derive(Clone)]
enum ChallengeLifecycle {
    Active,
    Redeeming,
    Redeemed,
}

#[derive(Clone)]
struct ChallengeEntry {
    challenge: Ggbp1Challenge,
    lifecycle: ChallengeLifecycle,
}

struct GrantRecord {
    challenge: Ggbp1Challenge,
    outputs: Vec<SyntheticStandardOutput>,
    verification: Ggbp1ExperimentalVerification,
}

#[derive(Default)]
struct ExperimentalState {
    challenges: BTreeMap<[u8; 32], ChallengeEntry>,
    output_usage: BTreeMap<[u8; 32], [u8; 32]>,
    grants: BTreeMap<[u8; 32], GrantRecord>,
}

/// An isolated server-side protocol runner. Its only success value explicitly says it is not an
/// authorization artifact.
pub struct Ggbp1ExperimentalServer<C> {
    config: Ggbp1ExperimentalConfig,
    chain: Arc<C>,
    state: Mutex<ExperimentalState>,
}

impl<C: Ggbp1ChainView> Ggbp1ExperimentalServer<C> {
    pub fn new(config: Ggbp1ExperimentalConfig, chain: Arc<C>) -> Result<Self, Ggbp1ServerError> {
        if config.threshold_micro_xtm == 0 {
            return Err(Ggbp1ServerError::ZeroThreshold);
        }
        Ok(Self {
            config,
            chain,
            state: Mutex::new(ExperimentalState::default()),
        })
    }

    /// Creates an unpredictable nonce after checking that the configured chain view is fresh.
    pub async fn issue_challenge<R: Rng + CryptoRng>(
        &self,
        request: Ggbp1ChallengeRequest,
        now_unix_seconds: u64,
        rng: &mut R,
    ) -> Result<Ggbp1Challenge, Ggbp1ServerError> {
        if request.requested_ttl_seconds == 0
            || request.requested_ttl_seconds > self.config.maximum_challenge_ttl_seconds
        {
            return Err(Ggbp1ServerError::InvalidChallengeTtl);
        }
        if request.subject_authentication_public_key == RistrettoPublicKey::default() {
            return Err(Ggbp1ServerError::InvalidSubjectKey);
        }
        self.checked_snapshot(now_unix_seconds).await?;

        let expires_at_unix_seconds = now_unix_seconds
            .checked_add(request.requested_ttl_seconds)
            .ok_or(Ggbp1ServerError::ExpiryOverflow)?;
        let mut nonce = [0u8; 32];
        rng.fill(&mut nonce);
        let challenge = Ggbp1Challenge {
            network: self.config.network,
            genesis_hash: self.config.genesis_hash,
            origin_hash: self.config.origin_hash,
            gate_id: self.config.gate_id,
            gate_configuration_version: self.config.gate_configuration_version,
            subject_id: request.subject_id,
            subject_authentication_public_key: request.subject_authentication_public_key,
            threshold_micro_xtm: self.config.threshold_micro_xtm,
            nonce,
            expires_at_unix_seconds,
            commitment_generator_fingerprint:
                crate::ggbp1::expected_commitment_generator_fingerprint(),
        };
        let mut state = self.state.lock().await;
        if state.challenges.contains_key(&nonce) {
            return Err(Ggbp1ServerError::ChallengeNotFound);
        }
        state.challenges.insert(
            nonce,
            ChallengeEntry {
                challenge: challenge.clone(),
                lifecycle: ChallengeLifecycle::Active,
            },
        );
        Ok(challenge)
    }

    /// Decodes, reserves, checks, and records a response. A successful result is intentionally not
    /// convertible to any production authorization object.
    pub async fn submit_response(
        &self,
        response: &[u8],
        now_unix_seconds: u64,
    ) -> Result<Ggbp1ExperimentalVerification, Ggbp1ServerError> {
        if response.len() > maximum_response_size() {
            return Err(Ggbp1ServerError::ResponseTooLarge);
        }
        let wire = Ggbp1WireProof::from_bytes(response)?;
        let nonce = wire.challenge.nonce;

        {
            let mut state = self.state.lock().await;
            let entry = state
                .challenges
                .get_mut(&nonce)
                .ok_or(Ggbp1ServerError::ChallengeNotFound)?;
            if entry.challenge != wire.challenge {
                return Err(Ggbp1ServerError::ChallengeMismatch);
            }
            if now_unix_seconds >= entry.challenge.expires_at_unix_seconds {
                entry.lifecycle = ChallengeLifecycle::Redeemed;
                return Err(Ggbp1ServerError::ChallengeExpired);
            }
            match entry.lifecycle {
                ChallengeLifecycle::Active => entry.lifecycle = ChallengeLifecycle::Redeeming,
                ChallengeLifecycle::Redeeming => return Err(Ggbp1ServerError::ChallengeInProgress),
                ChallengeLifecycle::Redeemed => return Err(Ggbp1ServerError::ChallengeRedeemed),
            }
        }

        let checked = async {
            verify_synthetic(&wire.challenge, &wire.proof)?;
            self.checked_outputs(&wire.challenge, &wire.proof.outputs, now_unix_seconds)
                .await
        }
        .await;

        let snapshot = match checked {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.restore_active(nonce).await;
                return Err(error);
            }
        };

        let verification = Ggbp1ExperimentalVerification {
            status: Ggbp1ExperimentalVerificationStatus::VerifiedNotAuthorized,
            challenge_nonce: nonce,
            output_hashes: wire
                .proof
                .outputs
                .iter()
                .map(|output| output.output_hash)
                .collect(),
            verified_tip_hash: snapshot.tip_hash,
            verified_tip_height: snapshot.tip_height,
            verified_at_unix_seconds: now_unix_seconds,
        };
        let mut state = self.state.lock().await;
        if wire
            .proof
            .outputs
            .iter()
            .any(|output| state.output_usage.contains_key(&output.output_hash))
        {
            if let Some(entry) = state.challenges.get_mut(&nonce) {
                entry.lifecycle = ChallengeLifecycle::Active;
            }
            return Err(Ggbp1ServerError::OutputAlreadyRegistered);
        }
        for output in &wire.proof.outputs {
            state.output_usage.insert(output.output_hash, nonce);
        }
        state.grants.insert(
            nonce,
            GrantRecord {
                challenge: wire.challenge,
                outputs: wire.proof.outputs,
                verification: verification.clone(),
            },
        );
        let entry = state
            .challenges
            .get_mut(&nonce)
            .expect("challenge is reserved before an experimental grant is recorded");
        entry.lifecycle = ChallengeLifecycle::Redeemed;
        Ok(verification)
    }

    /// Rechecks all still-valid experimental observations. A spent output or a reorganization
    /// changes the in-memory audit status to `Revoked`; it never changes a production grant.
    pub async fn recheck(&self, now_unix_seconds: u64) -> usize {
        let checks = {
            let state = self.state.lock().await;
            state
                .grants
                .iter()
                .filter(|(_, grant)| {
                    grant.verification.status
                        == Ggbp1ExperimentalVerificationStatus::VerifiedNotAuthorized
                })
                .map(|(nonce, grant)| (*nonce, grant.challenge.clone(), grant.outputs.clone()))
                .collect::<Vec<_>>()
        };
        let mut revoked = Vec::new();
        for (nonce, challenge, outputs) in checks {
            if self
                .checked_outputs(&challenge, &outputs, now_unix_seconds)
                .await
                .is_err()
            {
                revoked.push(nonce);
            }
        }
        if revoked.is_empty() {
            return 0;
        }
        let mut state = self.state.lock().await;
        for nonce in &revoked {
            if let Some(grant) = state.grants.get_mut(nonce) {
                grant.verification.status = Ggbp1ExperimentalVerificationStatus::Revoked;
            }
        }
        revoked.len()
    }

    pub async fn verification(&self, nonce: [u8; 32]) -> Option<Ggbp1ExperimentalVerification> {
        self.state
            .lock()
            .await
            .grants
            .get(&nonce)
            .map(|grant| grant.verification.clone())
    }

    async fn restore_active(&self, nonce: [u8; 32]) {
        let mut state = self.state.lock().await;
        if let Some(entry) = state.challenges.get_mut(&nonce) {
            if matches!(entry.lifecycle, ChallengeLifecycle::Redeeming) {
                entry.lifecycle = ChallengeLifecycle::Active;
            }
        }
    }

    async fn checked_snapshot(
        &self,
        now_unix_seconds: u64,
    ) -> Result<Ggbp1ChainSnapshot, Ggbp1ServerError> {
        let snapshot = self.chain.snapshot().await?;
        if !snapshot.is_synced {
            return Err(Ggbp1ServerError::ChainNotSynced);
        }
        if snapshot.source == Ggbp1EvidenceSource::SyntheticFixture
            && !self.config.chain_policy.permit_synthetic_fixtures
        {
            return Err(Ggbp1ServerError::SyntheticEvidenceNotPermitted);
        }
        if snapshot.network != self.config.network
            || snapshot.genesis_hash != self.config.genesis_hash
        {
            return Err(Ggbp1ServerError::ChainBindingMismatch);
        }
        if snapshot.tip_timestamp_unix_seconds > now_unix_seconds
            || now_unix_seconds - snapshot.tip_timestamp_unix_seconds
                > self.config.chain_policy.maximum_tip_age_seconds
        {
            return Err(Ggbp1ServerError::StaleTip);
        }
        Ok(snapshot)
    }

    async fn checked_outputs(
        &self,
        challenge: &Ggbp1Challenge,
        outputs: &[SyntheticStandardOutput],
        now_unix_seconds: u64,
    ) -> Result<Ggbp1ChainSnapshot, Ggbp1ServerError> {
        let snapshot = self.checked_snapshot(now_unix_seconds).await?;
        if snapshot.network != challenge.network || snapshot.genesis_hash != challenge.genesis_hash
        {
            return Err(Ggbp1ServerError::ChainBindingMismatch);
        }
        for expected in outputs {
            let observed = self
                .chain
                .output(expected)
                .await?
                .ok_or(Ggbp1ServerError::OutputNotFound)?;
            self.check_output(&snapshot, expected, &observed)?;
        }
        let end_snapshot = self.checked_snapshot(now_unix_seconds).await?;
        if end_snapshot.tip_hash != snapshot.tip_hash
            || end_snapshot.tip_height != snapshot.tip_height
        {
            return Err(Ggbp1ServerError::ChainChangedDuringVerification);
        }
        Ok(snapshot)
    }

    fn check_output(
        &self,
        snapshot: &Ggbp1ChainSnapshot,
        expected: &SyntheticStandardOutput,
        observed: &Ggbp1ObservedOutput,
    ) -> Result<(), Ggbp1ServerError> {
        if observed.output_hash != expected.output_hash
            || observed.commitment != expected.commitment
            || observed.script != expected.script
            || observed.script_public_key != expected.script_public_key
        {
            return Err(Ggbp1ServerError::OutputMismatch);
        }
        if !observed.is_in_best_chain {
            return Err(Ggbp1ServerError::OutputNotInBestChain);
        }
        if !observed.is_unspent {
            return Err(Ggbp1ServerError::OutputSpent);
        }
        if observed.output_version != self.config.chain_policy.required_output_version
            || observed.output_type != self.config.chain_policy.required_output_type
            || observed.range_proof_type != self.config.chain_policy.required_range_proof_type
        {
            return Err(Ggbp1ServerError::UnsupportedOutputFormat);
        }
        let confirmations = snapshot
            .tip_height
            .checked_sub(observed.mined_height)
            .and_then(|depth| depth.checked_add(1))
            .ok_or(Ggbp1ServerError::ContradictoryConfirmations)?;
        if confirmations != observed.confirmations {
            return Err(Ggbp1ServerError::ContradictoryConfirmations);
        }
        if snapshot.tip_height < observed.maturity_height {
            return Err(Ggbp1ServerError::OutputImmature);
        }
        if confirmations < self.config.chain_policy.minimum_confirmations {
            return Err(Ggbp1ServerError::InsufficientConfirmations);
        }
        Ok(())
    }
}

fn maximum_response_size() -> usize {
    // Match the canonical response's fixed fields and bounded per-output/minimum-proof payload.
    6 + 1
        + 1
        + 32
        + 32
        + 32
        + 16
        + 8
        + 16
        + 32
        + 8
        + 32
        + 8
        + 32
        + 1
        + crate::ggbp1::GGBP1_MAX_OUTPUTS
            * (32 + 32 + crate::ggbp1::GGBP1_STANDARD_SCRIPT_BYTES + 32 + 64)
        + 64
        + 32
        + 2
        + GGBP1_MAX_PROOF_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ggbp1::{SyntheticOutputWitness, SyntheticSubjectWitness};
    use rand::{SeedableRng, rngs::StdRng};

    #[derive(Default)]
    struct FixtureChainView {
        snapshot: Mutex<Option<Ggbp1ChainSnapshot>>,
        outputs: Mutex<BTreeMap<[u8; 32], Ggbp1ObservedOutput>>,
    }

    #[async_trait]
    impl Ggbp1ChainView for FixtureChainView {
        async fn snapshot(&self) -> Result<Ggbp1ChainSnapshot, Ggbp1ChainViewError> {
            self.snapshot
                .lock()
                .await
                .clone()
                .ok_or_else(|| Ggbp1ChainViewError("missing synthetic snapshot".to_string()))
        }

        async fn output(
            &self,
            expected: &SyntheticStandardOutput,
        ) -> Result<Option<Ggbp1ObservedOutput>, Ggbp1ChainViewError> {
            Ok(self
                .outputs
                .lock()
                .await
                .get(&expected.output_hash)
                .cloned())
        }
    }

    fn key(n: u64) -> tari_crypto::ristretto::RistrettoSecretKey {
        tari_crypto::ristretto::RistrettoSecretKey::from(n)
    }

    fn configuration() -> Ggbp1ExperimentalConfig {
        Ggbp1ExperimentalConfig {
            network: 42,
            genesis_hash: [1; 32],
            origin_hash: [2; 32],
            gate_id: [3; 16],
            gate_configuration_version: 7,
            threshold_micro_xtm: 100,
            maximum_challenge_ttl_seconds: 60,
            chain_policy: Ggbp1ChainPolicy::synthetic_test_fixture(),
        }
    }

    fn subject() -> SyntheticSubjectWitness {
        SyntheticSubjectWitness::new(key(31))
    }

    fn witness(id: u8, value: u64, mask: u64, script_key: u64) -> SyntheticOutputWitness {
        SyntheticOutputWitness::new([id; 32], value, key(mask), key(script_key))
    }

    fn observed(output: &SyntheticStandardOutput) -> Ggbp1ObservedOutput {
        Ggbp1ObservedOutput {
            output_hash: output.output_hash,
            commitment: output.commitment.clone(),
            script: output.script.clone(),
            script_public_key: output.script_public_key.clone(),
            mined_height: 190,
            mined_block_hash: [8; 32],
            confirmations: 11,
            maturity_height: 191,
            output_version: 0,
            output_type: 0,
            range_proof_type: 0,
            is_unspent: true,
            is_in_best_chain: true,
        }
    }

    async fn server_and_challenge(
        view: Arc<FixtureChainView>,
        now: u64,
    ) -> (Ggbp1ExperimentalServer<FixtureChainView>, Ggbp1Challenge) {
        *view.snapshot.lock().await = Some(Ggbp1ChainSnapshot {
            source: Ggbp1EvidenceSource::SyntheticFixture,
            network: 42,
            genesis_hash: [1; 32],
            tip_height: 200,
            tip_hash: [9; 32],
            tip_timestamp_unix_seconds: now,
            is_synced: true,
        });
        let server = Ggbp1ExperimentalServer::new(configuration(), view).unwrap();
        let mut rng = StdRng::from_seed([44; 32]);
        let subject = subject();
        let challenge = server
            .issue_challenge(
                Ggbp1ChallengeRequest {
                    subject_id: [4; 16],
                    subject_authentication_public_key: subject.public_key(),
                    requested_ttl_seconds: 30,
                },
                now,
                &mut rng,
            )
            .await
            .unwrap();
        (server, challenge)
    }

    async fn encoded_proof(
        challenge: &Ggbp1Challenge,
        witnesses: &[SyntheticOutputWitness],
    ) -> Vec<u8> {
        let mut rng = StdRng::from_seed([45; 32]);
        SyntheticWalletProver::new(subject(), witnesses.to_vec())
            .respond(challenge, &mut rng)
            .unwrap()
    }

    #[tokio::test]
    async fn synthetic_end_to_end_verifies_then_revokes_a_spent_output() {
        let now = 1_800_000_000;
        let view = Arc::new(FixtureChainView::default());
        let (server, challenge) = server_and_challenge(view.clone(), now).await;
        let witnesses = [witness(1, 45, 11, 21), witness(2, 55, 12, 22)];
        {
            let mut outputs = view.outputs.lock().await;
            for witness in &witnesses {
                outputs.insert(witness.public.output_hash, observed(&witness.public));
            }
        }
        let response = encoded_proof(&challenge, &witnesses).await;
        let verification = server.submit_response(&response, now + 1).await.unwrap();
        assert_eq!(
            verification.status,
            Ggbp1ExperimentalVerificationStatus::VerifiedNotAuthorized
        );
        assert_eq!(
            server
                .submit_response(&response, now + 1)
                .await
                .unwrap_err()
                .to_string(),
            Ggbp1ServerError::ChallengeRedeemed.to_string()
        );

        view.outputs
            .lock()
            .await
            .get_mut(&[1; 32])
            .unwrap()
            .is_unspent = false;
        assert_eq!(server.recheck(now + 2).await, 1);
        assert_eq!(
            server.verification(challenge.nonce).await.unwrap().status,
            Ggbp1ExperimentalVerificationStatus::Revoked
        );
    }

    #[tokio::test]
    async fn malformed_stale_and_concurrent_responses_do_not_grant() {
        let now = 1_800_000_000;
        let view = Arc::new(FixtureChainView::default());
        let (server, challenge) = server_and_challenge(view.clone(), now).await;
        let witnesses = [witness(1, 100, 11, 21)];
        view.outputs
            .lock()
            .await
            .insert([1; 32], observed(&witnesses[0].public));
        let response = encoded_proof(&challenge, &witnesses).await;

        assert!(matches!(
            server
                .submit_response(&vec![0; maximum_response_size() + 1], now + 1)
                .await,
            Err(Ggbp1ServerError::ResponseTooLarge)
        ));
        assert!(matches!(
            server
                .submit_response(&response, challenge.expires_at_unix_seconds)
                .await,
            Err(Ggbp1ServerError::ChallengeExpired)
        ));

        let view = Arc::new(FixtureChainView::default());
        let (server, challenge) = server_and_challenge(view.clone(), now).await;
        view.outputs
            .lock()
            .await
            .insert([1; 32], observed(&witnesses[0].public));
        let response = encoded_proof(&challenge, &witnesses).await;
        let (first, second) = tokio::join!(
            server.submit_response(&response, now + 1),
            server.submit_response(&response, now + 1),
        );
        assert!(first.is_ok() ^ second.is_ok());
        assert!(matches!(
            first.err().or(second.err()),
            Some(Ggbp1ServerError::ChallengeInProgress | Ggbp1ServerError::ChallengeRedeemed)
        ));
    }

    #[tokio::test]
    async fn server_refuses_maturity_reorg_forgery_and_binding_substitution() {
        let now = 1_800_000_000;
        let view = Arc::new(FixtureChainView::default());
        let (server, challenge) = server_and_challenge(view.clone(), now).await;
        let witnesses = [witness(1, 100, 11, 21)];
        let response = encoded_proof(&challenge, &witnesses).await;

        let mut immature = observed(&witnesses[0].public);
        immature.maturity_height = 201;
        view.outputs.lock().await.insert([1; 32], immature);
        assert!(matches!(
            server.submit_response(&response, now + 1).await,
            Err(Ggbp1ServerError::OutputImmature)
        ));

        let mut reorganized = observed(&witnesses[0].public);
        reorganized.is_in_best_chain = false;
        view.outputs.lock().await.insert([1; 32], reorganized);
        assert!(matches!(
            server.submit_response(&response, now + 1).await,
            Err(Ggbp1ServerError::OutputNotInBestChain)
        ));

        view.outputs
            .lock()
            .await
            .insert([1; 32], observed(&witnesses[0].public));
        let mut forged = Ggbp1WireProof::from_bytes(&response).unwrap();
        forged.proof.aggregate_minimum_proof.pop();
        let forged = forged.to_bytes().unwrap();
        assert!(matches!(
            server.submit_response(&forged, now + 1).await,
            Err(Ggbp1ServerError::Proof(Ggbp1Error::InvalidMinimumProof(_)))
        ));

        let mut wrong_gate = Ggbp1WireProof::from_bytes(&response).unwrap();
        wrong_gate.challenge.gate_id = [99; 16];
        let wrong_gate = wrong_gate.to_bytes().unwrap();
        assert!(matches!(
            server.submit_response(&wrong_gate, now + 1).await,
            Err(Ggbp1ServerError::ChallengeMismatch)
        ));
    }
}
