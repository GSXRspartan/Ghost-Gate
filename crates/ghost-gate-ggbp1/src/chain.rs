//! The explicit chain-evidence layer for GGBP-1 v3.
//!
//! A valid `GGBP1R` response proves arithmetic and signatures. It does **not** prove that the
//! outputs it names exist, are confirmed, or are unspent. This module is the only place that
//! turns a response's output table into a chain assertion, and it keeps the provenance of that
//! assertion visible.
//!
//! * `OperatorPinnedAuthenticatedBaseNode` is the only source a positive test verdict may use.
//! * `UntrustedBaseNodeRpc` is diagnostic: plain gRPC has no transferable response
//!   authentication or inclusion proof, so a verdict built on it is labelled unverified.
//! * `SyntheticFixture` exists for this crate's tests and is refused unless a test policy
//!   explicitly permits it.

use async_trait::async_trait;
use tari_crypto::ristretto::{RistrettoPublicKey, pedersen::PedersenCommitment};
use tari_script::TariScript;
use thiserror::Error;

use crate::v3::SyntheticStandardOutput;

/// How a chain view obtained its observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ggbp1EvidenceSource {
    SyntheticFixture,
    /// Plain base-node gRPC. Diagnostic only; never a positive authorization input.
    UntrustedBaseNodeRpc,
    /// Reserved for a connector that authenticates the transport or verifies an operator pin.
    OperatorPinnedAuthenticatedBaseNode,
}

impl Ggbp1EvidenceSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SyntheticFixture => "synthetic_fixture",
            Self::UntrustedBaseNodeRpc => "untrusted_base_node_rpc",
            Self::OperatorPinnedAuthenticatedBaseNode => "operator_pinned_authenticated_base_node",
        }
    }

    /// Whether this source is strong enough to support a positive experimental verdict.
    pub fn is_trusted_for_positive_verdict(self) -> bool {
        matches!(self, Self::OperatorPinnedAuthenticatedBaseNode)
    }
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

/// Full public output evidence needed by the statement. It intentionally contains no opening,
/// private key, encrypted output data, wallet data, or balance.
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
    /// `None` means the chain view did not provide enough data to decide covenant support.
    pub covenant_is_supported: Option<bool>,
    /// The effective maximum of output maturity and script lock height. `None` means the evidence
    /// is incomplete and must fail closed.
    pub effective_lock_height: Option<u64>,
    pub is_unspent: bool,
    pub is_in_best_chain: bool,
}

#[derive(Debug, Error)]
#[error("chain-view failure: {0}")]
pub struct Ggbp1ChainViewError(pub String);

/// Read-only view required by the test gate. Implementations must reject missing or contradictory
/// data rather than filling it from a client response.
#[async_trait]
pub trait Ggbp1ChainView: Send + Sync {
    async fn snapshot(&self) -> Result<Ggbp1ChainSnapshot, Ggbp1ChainViewError>;
    async fn output(
        &self,
        expected: &SyntheticStandardOutput,
    ) -> Result<Option<Ggbp1ObservedOutput>, Ggbp1ChainViewError>;
}

/// Verifier policy for the chain-evidence layer.
#[derive(Clone, Debug)]
pub struct Ggbp1ChainPolicy {
    pub minimum_confirmations: u64,
    pub maximum_tip_age_seconds: u64,
    pub required_output_version: u32,
    pub required_output_type: u32,
    pub required_range_proof_type: u32,
    pub required_evidence_source: Ggbp1EvidenceSource,
    /// Tests opt in to fixtures. Any process configured for a node must leave this false.
    pub permit_synthetic_fixtures: bool,
}

impl Ggbp1ChainPolicy {
    /// The production-shaped policy: five confirmations, standard BulletProofPlus outputs, and
    /// only an operator-pinned authenticated node may produce a positive verdict.
    pub fn esmeralda_authenticated_node() -> Self {
        Self {
            minimum_confirmations: 5,
            maximum_tip_age_seconds: 10 * 60,
            required_output_version: 0,
            required_output_type: 0,
            required_range_proof_type: 0,
            required_evidence_source: Ggbp1EvidenceSource::OperatorPinnedAuthenticatedBaseNode,
            permit_synthetic_fixtures: false,
        }
    }

    /// The same confirmation and format rules, but explicitly diagnostic.
    pub fn esmeralda_diagnostic() -> Self {
        Self {
            required_evidence_source: Ggbp1EvidenceSource::UntrustedBaseNodeRpc,
            ..Self::esmeralda_authenticated_node()
        }
    }

    pub fn synthetic_test_fixture() -> Self {
        Self {
            minimum_confirmations: 2,
            maximum_tip_age_seconds: 60,
            required_output_version: 0,
            required_output_type: 0,
            required_range_proof_type: 0,
            required_evidence_source: Ggbp1EvidenceSource::SyntheticFixture,
            permit_synthetic_fixtures: true,
        }
    }

    /// A positive experimental verdict needs a source this policy accepts as authoritative.
    /// Synthetic fixtures count only when the policy explicitly opted into them for tests.
    pub fn permits_positive_verdict(&self, source: Ggbp1EvidenceSource) -> bool {
        source.is_trusted_for_positive_verdict()
            || (source == Ggbp1EvidenceSource::SyntheticFixture && self.permit_synthetic_fixtures)
    }
}

/// Why the chain layer refused an otherwise well-formed proof.
#[derive(Debug, Error)]
pub enum Ggbp1ChainError {
    #[error("the chain view is not synced")]
    ChainNotSynced,
    #[error("synthetic evidence is not permitted by this verifier configuration")]
    SyntheticEvidenceNotPermitted,
    #[error("the configured chain evidence source is not trusted for a positive verdict")]
    UntrustedChainEvidence,
    #[error("the chain network or genesis does not match the server configuration")]
    ChainBindingMismatch,
    #[error("the chain tip is stale or has a future timestamp")]
    StaleTip,
    #[error("the best chain changed while the proof was being checked")]
    ChainChangedDuringVerification,
    #[error("a referenced output was not found in the chain view")]
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
    #[error("a referenced output has an unsupported covenant")]
    UnsupportedCovenant,
    #[error("the chain view omitted required output lock or covenant evidence")]
    IncompleteOutputEvidence,
    #[error("the chain view supplied an effective lock lower than output maturity")]
    ContradictoryLockHeight,
    #[error(transparent)]
    View(#[from] Ggbp1ChainViewError),
}

/// Runs the before/after-tip and per-output checks against one chain view.
pub struct Ggbp1ChainChecker {
    pub network: u8,
    pub genesis_hash: [u8; 32],
    pub policy: Ggbp1ChainPolicy,
}

impl Ggbp1ChainChecker {
    pub fn new(network: u8, genesis_hash: [u8; 32], policy: Ggbp1ChainPolicy) -> Self {
        Self { network, genesis_hash, policy }
    }

    pub async fn checked_snapshot(
        &self,
        view: &dyn Ggbp1ChainView,
        now_unix_seconds: u64,
    ) -> Result<Ggbp1ChainSnapshot, Ggbp1ChainError> {
        let snapshot = view.snapshot().await?;
        if !snapshot.is_synced {
            return Err(Ggbp1ChainError::ChainNotSynced);
        }
        if snapshot.source == Ggbp1EvidenceSource::SyntheticFixture && !self.policy.permit_synthetic_fixtures {
            return Err(Ggbp1ChainError::SyntheticEvidenceNotPermitted);
        }
        if snapshot.source != self.policy.required_evidence_source {
            return Err(Ggbp1ChainError::UntrustedChainEvidence);
        }
        if snapshot.network != self.network || snapshot.genesis_hash != self.genesis_hash {
            return Err(Ggbp1ChainError::ChainBindingMismatch);
        }
        if snapshot.tip_timestamp_unix_seconds > now_unix_seconds
            || now_unix_seconds.saturating_sub(snapshot.tip_timestamp_unix_seconds)
                > self.policy.maximum_tip_age_seconds
        {
            return Err(Ggbp1ChainError::StaleTip);
        }
        Ok(snapshot)
    }

    pub async fn checked_outputs(
        &self,
        view: &dyn Ggbp1ChainView,
        outputs: &[SyntheticStandardOutput],
        now_unix_seconds: u64,
    ) -> Result<Ggbp1ChainSnapshot, Ggbp1ChainError> {
        let snapshot = self.checked_snapshot(view, now_unix_seconds).await?;
        for expected in outputs {
            let observed = view
                .output(expected)
                .await?
                .ok_or(Ggbp1ChainError::OutputNotFound)?;
            self.check_output(&snapshot, expected, &observed)?;
        }
        let end_snapshot = self.checked_snapshot(view, now_unix_seconds).await?;
        if end_snapshot.tip_hash != snapshot.tip_hash || end_snapshot.tip_height != snapshot.tip_height {
            return Err(Ggbp1ChainError::ChainChangedDuringVerification);
        }
        Ok(snapshot)
    }

    fn check_output(
        &self,
        snapshot: &Ggbp1ChainSnapshot,
        expected: &SyntheticStandardOutput,
        observed: &Ggbp1ObservedOutput,
    ) -> Result<(), Ggbp1ChainError> {
        if observed.output_hash != expected.output_hash
            || observed.commitment != expected.commitment
            || observed.script != expected.script
            || observed.script_public_key != expected.script_public_key
        {
            return Err(Ggbp1ChainError::OutputMismatch);
        }
        if !observed.is_in_best_chain {
            return Err(Ggbp1ChainError::OutputNotInBestChain);
        }
        if !observed.is_unspent {
            return Err(Ggbp1ChainError::OutputSpent);
        }
        if observed.output_version != self.policy.required_output_version
            || observed.output_type != self.policy.required_output_type
            || observed.range_proof_type != self.policy.required_range_proof_type
        {
            return Err(Ggbp1ChainError::UnsupportedOutputFormat);
        }
        match observed.covenant_is_supported {
            Some(true) => {}
            Some(false) => return Err(Ggbp1ChainError::UnsupportedCovenant),
            None => return Err(Ggbp1ChainError::IncompleteOutputEvidence),
        }
        let effective_lock_height = observed
            .effective_lock_height
            .ok_or(Ggbp1ChainError::IncompleteOutputEvidence)?;
        if effective_lock_height < observed.maturity_height {
            return Err(Ggbp1ChainError::ContradictoryLockHeight);
        }
        let confirmations = snapshot
            .tip_height
            .checked_sub(observed.mined_height)
            .and_then(|depth| depth.checked_add(1))
            .ok_or(Ggbp1ChainError::ContradictoryConfirmations)?;
        if confirmations != observed.confirmations {
            return Err(Ggbp1ChainError::ContradictoryConfirmations);
        }
        if snapshot.tip_height < effective_lock_height {
            return Err(Ggbp1ChainError::OutputImmature);
        }
        if confirmations < self.policy.minimum_confirmations {
            return Err(Ggbp1ChainError::InsufficientConfirmations);
        }
        Ok(())
    }
}
