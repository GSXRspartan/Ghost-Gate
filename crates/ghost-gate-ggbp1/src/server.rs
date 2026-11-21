//! A bounded, in-memory GGBP-1 v3 test-gate server.
//!
//! It preserves the order a real integration must keep: a server-issued challenge, a canonical
//! response parse, public cryptographic verification, an explicit chain-evidence step, atomic
//! single use, and output registration. Its success values are named so no caller can mistake
//! them for authorization, and it exposes no method that returns a Ghost Gate session.

use std::{collections::BTreeMap, sync::Arc};

use rand::{Rng, RngExt};
use tari_crypto::ristretto::RistrettoPublicKey;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::chain::{
    Ggbp1ChainChecker, Ggbp1ChainError, Ggbp1ChainPolicy, Ggbp1ChainView, Ggbp1EvidenceSource,
};
use crate::challenge::{CHALLENGE_BYTES, ChallengeError, encode_challenge};
use crate::v3::{
    GGBP1_MAX_PROOF_BYTES, Ggbp1Challenge, Ggbp1Error, Ggbp1WireProof, expected_commitment_generator_fingerprint,
    verify_synthetic,
};

const MAX_CHALLENGES: usize = 64;
const MAX_CONCURRENT_VERIFICATIONS: usize = 2;
const MAX_RESPONSE_BYTES: usize = 6 + 1 + CHALLENGE_BYTES + 1
    + crate::v3::GGBP1_MAX_OUTPUTS
        * (32 + 32 + crate::v3::GGBP1_STANDARD_SCRIPT_BYTES + 32 + 64)
    + 64
    + 32
    + 2
    + GGBP1_MAX_PROOF_BYTES;

/// The subject and gate binding a caller asks the server to put in a challenge.
#[derive(Clone, Debug)]
pub struct Ggbp1ChallengeRequest {
    pub subject_id: [u8; 16],
    pub origin_hash: [u8; 32],
    pub subject_authentication_public_key: RistrettoPublicKey,
    pub gate_id: [u8; 16],
    pub gate_configuration_version: u64,
    pub threshold_micro_xtm: u64,
    pub requested_ttl_seconds: u64,
}

/// A server-issued challenge and its exact wallet-facing encoding.
#[derive(Clone, Debug)]
pub struct Ggbp1ChallengeView {
    pub challenge: Ggbp1Challenge,
    pub bytes: [u8; CHALLENGE_BYTES],
}

/// The only two success labels this server can produce. Neither is an authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ggbp1TestVerdictStatus {
    /// Cryptography, signatures, and chain evidence all passed, under a trusted evidence source.
    VerifiedTestOnly,
    /// Cryptography and signatures passed, but the chain layer was absent or diagnostic.
    CryptographicallyValidChainUnverified,
}

impl Ggbp1TestVerdictStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VerifiedTestOnly => "verified_test_only",
            Self::CryptographicallyValidChainUnverified => "cryptographically_valid_chain_unverified",
        }
    }
}

/// An audit-only result. `authorized` is always false and there is deliberately no session field.
#[derive(Clone, Debug)]
pub struct Ggbp1TestVerdict {
    pub status: Ggbp1TestVerdictStatus,
    pub authorized: bool,
    pub challenge_nonce: [u8; 32],
    pub output_hashes: Vec<[u8; 32]>,
    pub threshold_micro_xtm: u64,
    pub chain_evidence: Option<Ggbp1EvidenceSource>,
    pub verified_tip_hash: Option<[u8; 32]>,
    pub verified_tip_height: Option<u64>,
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
    #[error("too many outstanding GGBP-1 challenges")]
    ChallengeCapacity,
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
    #[error("an output has already been used by another experimental proof")]
    OutputAlreadyRegistered,
    #[error(transparent)]
    ChallengeCodec(#[from] ChallengeError),
    #[error(transparent)]
    Proof(#[from] Ggbp1Error),
    #[error(transparent)]
    Chain(#[from] Ggbp1ChainError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

#[derive(Default)]
struct ServerState {
    challenges: BTreeMap<[u8; 32], ChallengeEntry>,
    output_usage: BTreeMap<[u8; 32], [u8; 32]>,
}

/// The test-gate server. Its only chain view is explicitly diagnostic unless the caller
/// constructs it with an authenticated source.
pub struct Ggbp1TestServer {
    network: u8,
    genesis_hash: [u8; 32],
    policy: Ggbp1ChainPolicy,
    chain: Option<Arc<dyn Ggbp1ChainView>>,
    state: Mutex<ServerState>,
    /// Bounds the number of Bulletproofs+ verifications in flight. A caller can create at most
    /// `MAX_CHALLENGES` outstanding challenges, but without this a burst of valid-looking
    /// responses could still queue expensive proof checks. Two is enough for a single local
    /// browser while keeping CPU use bounded.
    verify_permits: Arc<tokio::sync::Semaphore>,
}

impl Ggbp1TestServer {
    /// A server whose chain view is an operator-pinned authenticated source.
    pub fn new_authenticated(
        network: u8,
        genesis_hash: [u8; 32],
        chain: Arc<dyn Ggbp1ChainView>,
    ) -> Self {
        Self::new(network, genesis_hash, Ggbp1ChainPolicy::esmeralda_authenticated_node(), Some(chain))
    }

    /// A server whose chain view is the plain diagnostic base-node RPC. It can never produce a
    /// positive verdict, even when every chain check passes.
    pub fn new_diagnostic(
        network: u8,
        genesis_hash: [u8; 32],
        chain: Arc<dyn Ggbp1ChainView>,
    ) -> Self {
        Self::new(network, genesis_hash, Ggbp1ChainPolicy::esmeralda_diagnostic(), Some(chain))
    }

    /// A server with no chain view. It verifies cryptography only and labels every success
    /// `cryptographically_valid_chain_unverified`.
    pub fn new_without_chain(network: u8, genesis_hash: [u8; 32]) -> Self {
        Self::new(network, genesis_hash, Ggbp1ChainPolicy::esmeralda_authenticated_node(), None)
    }

    /// Test-only constructor. A shipped bridge must use one of the constructors above.
    pub fn new_for_tests(
        network: u8,
        genesis_hash: [u8; 32],
        policy: Ggbp1ChainPolicy,
        chain: Option<Arc<dyn Ggbp1ChainView>>,
    ) -> Self {
        Self::new(network, genesis_hash, policy, chain)
    }

    fn new(
        network: u8,
        genesis_hash: [u8; 32],
        policy: Ggbp1ChainPolicy,
        chain: Option<Arc<dyn Ggbp1ChainView>>,
    ) -> Self {
        Self {
            network,
            genesis_hash,
            policy,
            chain,
            state: Mutex::new(ServerState::default()),
            verify_permits: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_VERIFICATIONS)),
        }
    }

    pub fn network(&self) -> u8 {
        self.network
    }

    pub fn genesis_hash(&self) -> [u8; 32] {
        self.genesis_hash
    }

    /// Issues an unpredictable single-use challenge. No chain access is required to issue one.
    pub async fn issue_challenge<R: Rng + rand::CryptoRng>(
        &self,
        request: Ggbp1ChallengeRequest,
        now_unix_seconds: u64,
        rng: &mut R,
    ) -> Result<Ggbp1ChallengeView, Ggbp1ServerError> {
        if request.threshold_micro_xtm == 0 {
            return Err(Ggbp1ServerError::ZeroThreshold);
        }
        if request.subject_authentication_public_key == RistrettoPublicKey::default() {
            return Err(Ggbp1ServerError::InvalidSubjectKey);
        }
        if request.requested_ttl_seconds == 0 || request.requested_ttl_seconds > 300 {
            return Err(Ggbp1ServerError::InvalidChallengeTtl);
        }
        let expires_at_unix_seconds = now_unix_seconds
            .checked_add(request.requested_ttl_seconds)
            .ok_or(Ggbp1ServerError::ExpiryOverflow)?;
        let mut nonce = [0u8; 32];
        rng.fill(&mut nonce);
        let challenge = Ggbp1Challenge {
            network: self.network,
            genesis_hash: self.genesis_hash,
            origin_hash: request.origin_hash,
            gate_id: request.gate_id,
            gate_configuration_version: request.gate_configuration_version,
            subject_id: request.subject_id,
            subject_authentication_public_key: request.subject_authentication_public_key,
            threshold_micro_xtm: request.threshold_micro_xtm,
            nonce,
            expires_at_unix_seconds,
            commitment_generator_fingerprint: expected_commitment_generator_fingerprint(),
        };
        let bytes = encode_challenge(&challenge)?;
        let mut state = self.state.lock().await;
        state.challenges.retain(|_, entry| entry.lifecycle != ChallengeLifecycle::Redeemed);
        if state.challenges.len() >= MAX_CHALLENGES {
            return Err(Ggbp1ServerError::ChallengeCapacity);
        }
        if state.challenges.contains_key(&nonce) {
            return Err(Ggbp1ServerError::ChallengeCapacity);
        }
        state.challenges.insert(
            nonce,
            ChallengeEntry {
                challenge: challenge.clone(),
                lifecycle: ChallengeLifecycle::Active,
            },
        );
        Ok(Ggbp1ChallengeView { challenge, bytes })
    }

    /// Parses, reserves, verifies, and records a response. The returned verdict is never an
    /// authorization and is never stored as one.
    pub async fn submit_response(
        &self,
        response: &[u8],
        now_unix_seconds: u64,
    ) -> Result<Ggbp1TestVerdict, Ggbp1ServerError> {
        if response.len() > MAX_RESPONSE_BYTES {
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

        let verify_permit = match self.verify_permits.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => {
                self.restore_active(nonce).await;
                return Err(Ggbp1ServerError::ChallengeInProgress);
            }
        };
        let _verify_permit = verify_permit;

        let checked = async {
            verify_synthetic(&wire.challenge, &wire.proof)?;
            let chain_result = match &self.chain {
                Some(chain) => {
                    let checker = Ggbp1ChainChecker::new(self.network, self.genesis_hash, self.policy.clone());
                    Some(checker.checked_outputs(chain.as_ref(), &wire.proof.outputs, now_unix_seconds).await?)
                }
                None => None,
            };
            Ok::<_, Ggbp1ServerError>(chain_result)
        }
        .await;

        let snapshot = match checked {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.restore_active(nonce).await;
                return Err(error);
            }
        };

        let output_hashes = wire
            .proof
            .outputs
            .iter()
            .map(|output| output.output_hash)
            .collect::<Vec<_>>();
        {
            let mut state = self.state.lock().await;
            if output_hashes
                .iter()
                .any(|output_hash| state.output_usage.contains_key(output_hash))
            {
                drop(state);
                self.restore_active(nonce).await;
                return Err(Ggbp1ServerError::OutputAlreadyRegistered);
            }
            for output_hash in &output_hashes {
                state.output_usage.insert(*output_hash, nonce);
            }
            if let Some(entry) = state.challenges.get_mut(&nonce) {
                entry.lifecycle = ChallengeLifecycle::Redeemed;
            }
        }

        let (status, chain_evidence, verified_tip_hash, verified_tip_height) = match snapshot {
            Some(snapshot) if self.policy.permits_positive_verdict(snapshot.source) => (
                Ggbp1TestVerdictStatus::VerifiedTestOnly,
                Some(snapshot.source),
                Some(snapshot.tip_hash),
                Some(snapshot.tip_height),
            ),
            Some(snapshot) => (
                Ggbp1TestVerdictStatus::CryptographicallyValidChainUnverified,
                Some(snapshot.source),
                Some(snapshot.tip_hash),
                Some(snapshot.tip_height),
            ),
            None => (Ggbp1TestVerdictStatus::CryptographicallyValidChainUnverified, None, None, None),
        };
        Ok(Ggbp1TestVerdict {
            status,
            authorized: false,
            challenge_nonce: nonce,
            output_hashes,
            threshold_micro_xtm: wire.challenge.threshold_micro_xtm,
            chain_evidence,
            verified_tip_hash,
            verified_tip_height,
            verified_at_unix_seconds: now_unix_seconds,
        })
    }

    async fn restore_active(&self, nonce: [u8; 32]) {
        let mut state = self.state.lock().await;
        if let Some(entry) = state.challenges.get_mut(&nonce) {
            if matches!(entry.lifecycle, ChallengeLifecycle::Redeeming) {
                entry.lifecycle = ChallengeLifecycle::Active;
            }
        }
    }
}
