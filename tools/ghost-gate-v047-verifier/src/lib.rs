//! Ghost Gate's pinned-anchor adapter over Tari Ootle v0.47.0 light-client verification.
//!
//! The source tree is intentionally isolated from the v0.42 workspace used by the legacy local
//! bridge. It is built against the exact upstream `v0.47.0` tag (`9dabb2a76a9ad5c6e99dfa180ab7bbbcb1a05a47`).
//!
//! An indexer supplies *untrusted transport data*: committees, checkpoints and substate proofs.
//! It never supplies the initial trust decision. Callers must obtain the initial validator-set
//! hash through an out-of-band, authenticated operational process and pass it to [`Self::pinned`].
//! There is deliberately no `anchor_on_first_use` or automatic re-anchor API here.

use std::collections::BTreeMap;
use std::str::FromStr;

use serde::Deserialize;

use ootle_network::Network;
use tari_engine_types::{
    SubstateVersion,
    substate::{SubstateId, SubstateValue},
};
use tari_indexer_client::types::{EpochCheckpointEntry, SubstateProof, ValidatorSetCommittee};
use tari_ootle_common_types::{
    Epoch,
    NumPreshards,
    ProtocolVersion,
    ShardGroup,
    ValidatorSetHash,
    VotePower,
    hash_validator_set_committee,
    shard::Shard,
};
use tari_ootle_light_client::{LightClientError, TrustedValidatorSet, TrustedValidatorSetHash};
use tari_state_tree::ValidatorSetTree;
use tari_template_lib_types::crypto::RistrettoPublicKeyBytes;

/// The release signer pinned by Ghost Gate's release-bootstrap review. This value identifies
/// source provenance only; the compiled code does not verify OpenPGP signatures at runtime.
pub const ESMERALDA_V047_RELEASE_SIGNER_FINGERPRINT: &str =
    "337B91EFC5F1027D8AEDF63D1885B149504C0A64";

/// The exact signed release commit whose Esmeralda configured-oracle material was reviewed.
pub const ESMERALDA_V047_RELEASE_COMMIT: &str = "9dabb2a76a9ad5c6e99dfa180ab7bbbcb1a05a47";

/// The exact release tag whose signature was checked during the bootstrap review.
pub const ESMERALDA_V047_RELEASE_TAG: &str = "v0.47.0";

/// Policy revision for the reviewed release-derived topology. This is deliberately explicit in
/// local anchor configuration so that an operator must re-review rather than silently inheriting
/// a changed policy.
pub const ESMERALDA_V047_RELEASE_BOOTSTRAP_POLICY_VERSION: &str =
    "ghost-gate/esmeralda-release-bootstrap/v1";

/// SHA-256 of the exact `f_epoch_oracle.toml` file in the reviewed v0.47.0 release checkout.
/// It is a provenance pin, not a runtime substitute for release-signature verification.
pub const ESMERALDA_V047_EPOCH_ORACLE_PRESET_SHA256: &str =
    "e9b9badfb8061e982524c4176ae2336d44229c34b6d074ef128cd670e49d9df3";

/// The first epoch whose release-derived committee was checked against captured public transport
/// evidence. This is intentionally not inferred from the configured-oracle registration epoch.
pub const ESMERALDA_V047_RELEASE_ANCHOR_EPOCH: u64 = 12_634;

const ESMERALDA_RELEASE_VALIDATOR_KEYS: [&str; 4] = [
    "10780fe1b4d31f8350e4b881dccd8f8210ce056050ac6dd8cca88ca16710b044",
    "568adadd2744c7bb3ae4c58e26e83a49a5b5af3380edfcd6b5d7af315580552f",
    "c480fe3a76f03dcdce8d7c85ac7d0001ec97b667260172709b23818c8707e503",
    "d6da35adba3642e7d1343985d5e4f123f5230a74c5480bf2857aabe50bcd6362",
];

/// Derives an Esmeralda validator-set root from the four-validator topology embedded in the
/// authenticated v0.47.0 release. It performs no network access and never changes sidecar
/// readiness: callers must still explicitly choose and review this root before passing it to
/// [`PinnedConsensusVerifier::pinned`].
///
/// The helper deliberately excludes registration history. It is valid only for an epoch where
/// the signed release topology is independently known to be the active topology; a successful
/// committee proof verifies that claim for the requested epoch without trusting the indexer as a
/// root.
pub fn derive_esmeralda_v047_release_validator_set_hash(epoch: Epoch) -> ValidatorSetHash {
    let shard_group = ShardGroup::new(1, 256);
    let members = ESMERALDA_RELEASE_VALIDATOR_KEYS.map(|key| {
        RistrettoPublicKeyBytes::from_hex(key).expect("static release validator key is valid")
    });
    let leaf = hash_validator_set_committee(
        ProtocolVersion::at(Network::Esmeralda, epoch),
        &shard_group,
        members
            .iter()
            .map(|key| (key, VotePower::of(1), &[][..])),
    )
    .expect("static release committee is sorted and valid");
    ValidatorSetTree::build(
        Network::Esmeralda,
        epoch,
        NumPreshards::P256,
        [(shard_group, leaf)],
    )
    .expect("static release validator-set tree is valid")
    .hash()
}

/// Audit metadata extracted only after the official v0.47 verifier has accepted an inclusion
/// proof and its quorum-signed block proof. This is not a browser assertion.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct VerifiedEvidence {
    pub network: u8,
    pub epoch: u64,
    pub shard_group: String,
    pub height: u64,
    pub block_id: String,
    pub state_merkle_root: String,
}

/// The only proof material accepted from a sidecar caller. All values remain untrusted until
/// [`PinnedConsensusVerifier::verify_request`] validates them against its preconfigured anchor.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsensusProofRequest {
    pub substate_id: String,
    pub version: SubstateVersion,
    pub value: SubstateValue,
    pub proof: SubstateProof,
    pub committee: ValidatorSetCommittee,
    #[serde(default)]
    pub handovers: Vec<EpochCheckpointEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChainVerdict { ChainVerified, ChainInvalid, ChainStale, ChainPending, AnchorUntrusted, EvidenceUnavailable }

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsensusProofResult {
    pub verdict: ChainVerdict,
    pub evidence: Option<VerifiedEvidence>,
    pub reason: &'static str,
}

#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    #[error("GG: no independently approved pinned trust anchor is configured")]
    UntrustedAnchor,
    #[error("GG: consensus evidence is stale under the configured epoch policy")]
    StaleEvidence,
    #[error("GG: the proof is for an epoch not reached by the pinned handover chain")]
    EpochNotTrusted,
    #[error("GG: the proof's committee cannot be verified against the trusted validator set: {0}")]
    Verification(#[from] LightClientError),
}

/// A reviewable trust-root envelope. The committee is not trusted by itself: it is verified
/// against the independently reviewed validator-set hash during construction.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PinnedAnchorConfig {
    pub network: u8,
    pub anchor_epoch: u64,
    pub walk_shard: u32,
    pub validator_set_hash: serde_json::Value,
    pub walked_committee: serde_json::Value,
    pub provenance: String,
    pub reviewed_at: String,
    pub reviewed_by: String,
    pub upstream_commit: String,
    pub review_status: String,
    /// Optional provenance pin for the reviewed v0.47 signed-release bootstrap. When present,
    /// the supplied hash must equal the deterministic release-derived root at `anchor_epoch`.
    #[serde(default)]
    pub release_bootstrap: Option<ReleaseBootstrap>,
    #[serde(default = "default_max_proof_age_epochs")]
    pub max_proof_age_epochs: u64,
}

/// Selects the fixed signed-release bootstrap after an operator has made the external OpenPGP
/// trust decision. This is not a runtime signature verifier and is never enabled implicitly.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseBootstrap {
    pub release_tag: String,
    pub signer_fingerprint: String,
    pub policy_version: String,
    pub epoch_oracle_preset_sha256: String,
}

fn default_max_proof_age_epochs() -> u64 { 1 }

impl PinnedAnchorConfig {
    /// Parse an operator-reviewed anchor. No indexer response can cause an untrusted config to
    /// become trusted; `approved` review and the exact v0.47 source revision are mandatory.
    pub fn into_verifier(self) -> Result<(PinnedConsensusVerifier, u64), ConsensusError> {
        if self.review_status != "approved" || self.provenance.trim().is_empty()
            || self.reviewed_at.trim().is_empty() || self.reviewed_by.trim().is_empty()
            || self.upstream_commit != "9dabb2a76a9ad5c6e99dfa180ab7bbbcb1a05a47"
            // Ghost Gate walks Esmeralda's 1..=256 committee through shard 1. In Tari, shard 0
            // is the reserved global shard; accepting it here would turn a configuration typo
            // into a confusing downstream committee failure.
            || self.walk_shard != Shard::first().as_u32()
        { return Err(ConsensusError::UntrustedAnchor); }
        let network = Network::try_from(self.network).map_err(|_| ConsensusError::UntrustedAnchor)?;
        let hash = serde_json::from_value::<ValidatorSetHash>(self.validator_set_hash)
            .map_err(|_| ConsensusError::UntrustedAnchor)?;
        if let Some(bootstrap) = self.release_bootstrap {
            if bootstrap.release_tag != ESMERALDA_V047_RELEASE_TAG
                || bootstrap.signer_fingerprint != ESMERALDA_V047_RELEASE_SIGNER_FINGERPRINT
                || bootstrap.policy_version != ESMERALDA_V047_RELEASE_BOOTSTRAP_POLICY_VERSION
                || !bootstrap.epoch_oracle_preset_sha256.eq_ignore_ascii_case(ESMERALDA_V047_EPOCH_ORACLE_PRESET_SHA256)
                || self.network != Network::Esmeralda.as_byte()
                || self.anchor_epoch != ESMERALDA_V047_RELEASE_ANCHOR_EPOCH
                || hash != derive_esmeralda_v047_release_validator_set_hash(Epoch(self.anchor_epoch))
            {
                return Err(ConsensusError::UntrustedAnchor);
            }
        }
        let committee = serde_json::from_value::<ValidatorSetCommittee>(self.walked_committee)
            .map_err(|_| ConsensusError::UntrustedAnchor)?;
        let verifier = PinnedConsensusVerifier::pinned(network, Shard::first(), Epoch(self.anchor_epoch), &hash, &committee)?;
        Ok((verifier, self.max_proof_age_epochs))
    }
}

/// A validator-set chain rooted in one externally pinned v0.47 validator-set hash.
///
/// The adapter retains every verified set in the chain, so evidence from an earlier verified
/// epoch can be checked without treating an indexer response as a new root of trust.
pub struct PinnedConsensusVerifier {
    latest: TrustedValidatorSet,
    trusted_sets: BTreeMap<Epoch, TrustedValidatorSetHash>,
}

/// The sidecar transport is intentionally sized for one observed Esmeralda checkpoint handover.
/// Longer walks must be explicitly designed with a larger reviewed transport budget rather than
/// making a single proof request unbounded.
const MAX_HANDOVERS_PER_REQUEST: usize = 1;

impl PinnedConsensusVerifier {
    /// Establish the only unauthenticated-to-authenticated boundary in this adapter.
    ///
    /// `validator_set_hash` must come from the deployment's independent trust-anchor process;
    /// `walked_committee` may be supplied by an untrusted indexer because the official verifier
    /// proves that it belongs to that pinned set, matches `network`/`epoch`, and owns `walk_shard`.
    pub fn pinned(
        network: Network,
        walk_shard: Shard,
        epoch: Epoch,
        validator_set_hash: &ValidatorSetHash,
        walked_committee: &ValidatorSetCommittee,
    ) -> Result<Self, ConsensusError> {
        let latest = TrustedValidatorSet::anchor_pinned(
            network,
            walk_shard,
            epoch,
            validator_set_hash,
            walked_committee,
        )?;
        let mut trusted_sets = BTreeMap::new();
        trusted_sets.insert(latest.epoch(), latest.trusted_hash());
        Ok(Self { latest, trusted_sets })
    }

    pub fn network(&self) -> Network {
        self.latest.network()
    }

    pub fn latest_epoch(&self) -> Epoch {
        self.latest.epoch()
    }

    /// The validator-set hash reached through the pinned anchor and verified handovers.
    /// This is useful to bind a product freshness policy to authenticated progression rather than
    /// an indexer's reported latest epoch.
    pub fn latest_validator_set_hash(&self) -> ValidatorSetHash {
        *self.latest.validator_set_hash()
    }

    /// A valid historical inclusion proof is not present-holdings evidence. This check uses the
    /// latest verified handover epoch, never an indexer's unverified reported epoch.
    pub fn verify_substate_fresh(
        &self,
        max_proof_age_epochs: u64,
        substate_id: &SubstateId,
        version: SubstateVersion,
        value: &SubstateValue,
        proof: &SubstateProof,
        committee: &ValidatorSetCommittee,
    ) -> Result<VerifiedEvidence, ConsensusError> {
        if proof.anchor.epoch.as_u64().saturating_add(max_proof_age_epochs) < self.latest.epoch().as_u64() {
            return Err(ConsensusError::StaleEvidence);
        }
        self.verify_substate(substate_id, version, value, proof, committee)
    }

    /// Advance only through supplied signed handovers, then verify one inclusion proof. An
    /// indexer cannot replace the root: non-contiguous, forged, wrong-network, or malformed
    /// handovers cause `CHAIN_INVALID`; absence of a needed handover stays `CHAIN_PENDING`.
    pub fn verify_request(
        &mut self,
        max_proof_age_epochs: u64,
        request: &ConsensusProofRequest,
    ) -> ConsensusProofResult {
        if request.handovers.len() > MAX_HANDOVERS_PER_REQUEST {
            return ConsensusProofResult { verdict: ChainVerdict::EvidenceUnavailable, evidence: None, reason: "handover_limit" };
        }
        for handover in &request.handovers {
            if handover.epoch != self.latest.epoch() {
                return ConsensusProofResult { verdict: ChainVerdict::ChainInvalid, evidence: None, reason: "handover_epoch" };
            }
            if self.advance(handover).is_err() {
                return ConsensusProofResult { verdict: ChainVerdict::ChainInvalid, evidence: None, reason: "handover_invalid" };
            }
        }
        let id = match SubstateId::from_str(&request.substate_id) {
            Ok(id) => id,
            Err(_) => return ConsensusProofResult { verdict: ChainVerdict::ChainInvalid, evidence: None, reason: "substate_id" },
        };
        match self.verify_substate_fresh(max_proof_age_epochs, &id, request.version, &request.value, &request.proof, &request.committee) {
            Ok(evidence) => ConsensusProofResult { verdict: ChainVerdict::ChainVerified, evidence: Some(evidence), reason: "verified" },
            Err(ConsensusError::StaleEvidence) => ConsensusProofResult { verdict: ChainVerdict::ChainStale, evidence: None, reason: "stale" },
            Err(ConsensusError::EpochNotTrusted) => ConsensusProofResult { verdict: ChainVerdict::ChainPending, evidence: None, reason: "handover_needed" },
            Err(_) => ConsensusProofResult { verdict: ChainVerdict::ChainInvalid, evidence: None, reason: "proof_invalid" },
        }
    }

    /// Verify exactly one next-epoch handover. The official implementation checks checkpoint
    /// network, epoch, walked shard group, quorum signatures and the next committee/set proof.
    /// A failure leaves this adapter unchanged.
    pub fn advance(&mut self, checkpoint: &EpochCheckpointEntry) -> Result<(), ConsensusError> {
        let next = self.latest.advance(checkpoint)?;
        self.trusted_sets.insert(next.epoch(), next.trusted_hash());
        self.latest = next;
        Ok(())
    }

    /// Verify live-substate inclusion using the committee proven against the validator set for
    /// the proof's epoch. This refuses a proof for an epoch that the pinned chain has not reached.
    ///
    /// The caller must additionally apply its product freshness policy before authorizing: a
    /// valid historical inclusion proof does not prove present holdings by itself.
    pub fn verify_substate(
        &self,
        substate_id: &SubstateId,
        version: SubstateVersion,
        value: &SubstateValue,
        proof: &SubstateProof,
        committee: &ValidatorSetCommittee,
    ) -> Result<VerifiedEvidence, ConsensusError> {
        let trusted = self.trusted_sets.get(&proof.anchor.epoch).ok_or(ConsensusError::EpochNotTrusted)?;
        let committee = trusted.verify_committee(committee)?;
        let tip = committee.verify_substate(substate_id, version, Some(value), proof)?;
        Ok(VerifiedEvidence {
            network: committee.network().as_byte(),
            epoch: tip.epoch.as_u64(),
            shard_group: tip.shard_group.to_string(),
            height: tip.height.as_u64(),
            block_id: tip.block_id.to_string(),
            state_merkle_root: tip.state_merkle_root.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use ootle_network::Network;
    use tari_engine_types::{SubstateVersion, confidential::ClaimedOutputTombstone, substate::{SubstateId, SubstateValue}};
    use tari_ootle_common_types::{Epoch, shard::Shard};
    use tari_ootle_light_client::test_fixtures::{
        CheckpointSpec,
        NETWORK,
        Signers,
        ValidatorSetFixture,
        checkpoint_entry,
        low,
        substate_proof,
    };
    use tari_template_lib_types::ClaimedOutputTombstoneAddress;

    use super::*;

    fn fixture() -> (PinnedConsensusVerifier, ValidatorSetFixture, SubstateId, SubstateValue) {
        let epoch = Epoch(2);
        let set = ValidatorSetFixture::new(epoch.as_u64());
        let verifier = PinnedConsensusVerifier::pinned(
            NETWORK,
            Shard::first(),
            epoch,
            &set.hash(),
            &set.committee(low()),
        ).unwrap();
        let id = SubstateId::ClaimedOutputTombstone(ClaimedOutputTombstoneAddress::from_bytes(&[7; 32]).unwrap());
        let value = SubstateValue::ClaimedOutputTombstone(ClaimedOutputTombstone { value: 7 });
        (verifier, set, id, value)
    }

    #[test]
    fn pinned_anchor_verifies_authentic_v047_inclusion_evidence() {
        let (verifier, set, id, value) = fixture();
        let proof = substate_proof(&set, &id, SubstateVersion::ZERO, &value);
        let evidence = verifier.verify_substate(&id, SubstateVersion::ZERO, &value, &proof, &set.committee(low())).unwrap();
        assert_eq!(evidence.network, NETWORK.as_byte());
        assert_eq!(evidence.epoch, 2);
    }

    #[test]
    fn committee_from_another_network_cannot_become_an_esmeralda_anchor() {
        let epoch = Epoch(2);
        let set = ValidatorSetFixture::new(epoch.as_u64());
        let rejected = PinnedConsensusVerifier::pinned(
            Network::Esmeralda,
            Shard::first(),
            epoch,
            &set.hash(),
            &set.committee(low()),
        );
        assert!(rejected.is_err());
    }

    #[test]
    fn wrong_value_and_wrong_committee_are_not_evidence() {
        let (verifier, set, id, value) = fixture();
        let proof = substate_proof(&set, &id, SubstateVersion::ZERO, &value);
        let wrong = SubstateValue::ClaimedOutputTombstone(ClaimedOutputTombstone { value: 8 });
        assert!(verifier.verify_substate(&id, SubstateVersion::ZERO, &wrong, &proof, &set.committee(low())).is_err());
    }

    #[test]
    fn fixture_request_returns_chain_verified_only_for_authenticated_evidence() {
        let (mut verifier, set, id, value) = fixture();
        let request = ConsensusProofRequest {
            substate_id: id.to_string(), version: SubstateVersion::ZERO, value,
            proof: substate_proof(&set, &id, SubstateVersion::ZERO, &SubstateValue::ClaimedOutputTombstone(ClaimedOutputTombstone { value: 7 })),
            committee: set.committee(low()), handovers: vec![],
        };
        let result = verifier.verify_request(1, &request);
        assert_eq!(result.verdict, ChainVerdict::ChainVerified);
        assert_eq!(result.evidence.unwrap().network, NETWORK.as_byte());
    }

    #[test]
    fn request_rejects_more_than_one_handover_before_parsing_evidence() {
        let (mut verifier, set, id, value) = fixture();
        let next = ValidatorSetFixture::new(3);
        let checkpoint = checkpoint_entry(CheckpointSpec::handover(&set, &next));
        let request = ConsensusProofRequest {
            substate_id: id.to_string(),
            version: SubstateVersion::ZERO,
            value,
            proof: substate_proof(
                &set,
                &id,
                SubstateVersion::ZERO,
                &SubstateValue::ClaimedOutputTombstone(ClaimedOutputTombstone { value: 7 }),
            ),
            committee: set.committee(low()),
            handovers: vec![checkpoint.clone(), checkpoint],
        };
        let result = verifier.verify_request(1, &request);
        assert_eq!(result.verdict, ChainVerdict::EvidenceUnavailable);
        assert_eq!(result.reason, "handover_limit");
        assert_eq!(verifier.latest_epoch(), set.epoch);
    }

    #[test]
    fn stale_proof_is_rejected_relative_to_an_authenticated_handover() {
        let (mut verifier, current, id, value) = fixture();
        let proof = substate_proof(&current, &id, SubstateVersion::ZERO, &value);
        let next = ValidatorSetFixture::new(3);
        verifier.advance(&checkpoint_entry(CheckpointSpec::handover(&current, &next))).unwrap();

        assert!(matches!(
            verifier.verify_substate_fresh(0, &id, SubstateVersion::ZERO, &value, &proof, &current.committee(low())),
            Err(ConsensusError::StaleEvidence)
        ));
    }

    #[test]
    fn signed_handover_requires_the_pinned_set_and_complete_authentic_evidence() {
        let current = ValidatorSetFixture::new(2);
        let next = ValidatorSetFixture::new(3);
        let checkpoint = checkpoint_entry(CheckpointSpec::handover(&current, &next));
        let mut verifier = PinnedConsensusVerifier::pinned(
            NETWORK,
            Shard::first(),
            current.epoch,
            &current.hash(),
            &current.committee(low()),
        )
        .unwrap();
        verifier.advance(&checkpoint).unwrap();
        assert_eq!(verifier.latest_epoch(), next.epoch);

        // A next-set hash cannot replace the current pinned root.
        assert!(PinnedConsensusVerifier::pinned(
            NETWORK,
            Shard::first(),
            current.epoch,
            &next.hash(),
            &current.committee(low()),
        )
        .is_err());

        let mut changed_validator = checkpoint.clone();
        changed_validator
            .next_epoch_committee
            .as_mut()
            .unwrap()
            .members[0]
            .vote_power = 2;
        // The API's `members` list is convenience data. The official verifier reads the members
        // from the committee proof, so this cosmetic mutation cannot substitute a validator.
        let mut verifier = PinnedConsensusVerifier::pinned(
            NETWORK,
            Shard::first(),
            current.epoch,
            &current.hash(),
            &current.committee(low()),
        )
        .unwrap();
        verifier.advance(&changed_validator).unwrap();
        assert_eq!(verifier.latest_epoch(), next.epoch);

        let mut changed_authenticated_validator = checkpoint.clone();
        changed_authenticated_validator
            .next_epoch_committee
            .as_mut()
            .unwrap()
            .proof[0] ^= 1;
        assert!(PinnedConsensusVerifier::pinned(
            NETWORK,
            Shard::first(),
            current.epoch,
            &current.hash(),
            &current.committee(low()),
        )
        .unwrap()
        .advance(&changed_authenticated_validator)
        .is_err());

        let insufficient_signers = Signers {
            keys: current.low.keys[..2].to_vec(),
        };
        let missing_signer = checkpoint_entry(CheckpointSpec {
            network: current.network,
            epoch: current.epoch,
            shard_group: low(),
            signers: &insufficient_signers,
            next_set: next.hash(),
            carry_preimage: true,
            next_epoch_committee: Some(next.committee(low())),
        });
        assert!(PinnedConsensusVerifier::pinned(
            NETWORK,
            Shard::first(),
            current.epoch,
            &current.hash(),
            &current.committee(low()),
        )
        .unwrap()
        .advance(&missing_signer)
        .is_err());

        let mut bad_signature = checkpoint.clone();
        *bad_signature.checkpoint.last_mut().unwrap() ^= 1;
        assert!(PinnedConsensusVerifier::pinned(
            NETWORK,
            Shard::first(),
            current.epoch,
            &current.hash(),
            &current.committee(low()),
        )
        .unwrap()
        .advance(&bad_signature)
        .is_err());

        let wrong_epoch = checkpoint_entry(CheckpointSpec {
            network: current.network,
            epoch: Epoch(3),
            shard_group: low(),
            signers: &current.low,
            next_set: next.hash(),
            carry_preimage: true,
            next_epoch_committee: Some(next.committee(low())),
        });
        assert!(PinnedConsensusVerifier::pinned(
            NETWORK,
            Shard::first(),
            current.epoch,
            &current.hash(),
            &current.committee(low()),
        )
        .unwrap()
        .advance(&wrong_epoch)
        .is_err());

        let altered_hash = checkpoint_entry(CheckpointSpec {
            network: current.network,
            epoch: current.epoch,
            shard_group: low(),
            signers: &current.low,
            next_set: ValidatorSetFixture::new(4).hash(),
            carry_preimage: true,
            next_epoch_committee: Some(next.committee(low())),
        });
        assert!(PinnedConsensusVerifier::pinned(
            NETWORK,
            Shard::first(),
            current.epoch,
            &current.hash(),
            &current.committee(low()),
        )
        .unwrap()
        .advance(&altered_hash)
        .is_err());

        let mut truncated = checkpoint.clone();
        truncated.checkpoint.truncate(5);
        assert!(PinnedConsensusVerifier::pinned(
            NETWORK,
            Shard::first(),
            current.epoch,
            &current.hash(),
            &current.committee(low()),
        )
        .unwrap()
        .advance(&truncated)
        .is_err());

        let esmeralda_checkpoint = checkpoint_entry(CheckpointSpec {
            network: Network::Esmeralda,
            epoch: current.epoch,
            shard_group: low(),
            signers: &current.low,
            next_set: next.hash(),
            carry_preimage: true,
            next_epoch_committee: Some(next.committee(low())),
        });
        assert!(PinnedConsensusVerifier::pinned(
            NETWORK,
            Shard::first(),
            current.epoch,
            &current.hash(),
            &current.committee(low()),
        )
        .unwrap()
        .advance(&esmeralda_checkpoint)
        .is_err());
    }

    #[test]
    fn draft_or_provenance_free_anchor_config_never_becomes_trusted() {
        let draft: PinnedAnchorConfig = serde_json::from_value(serde_json::json!({
            "network": 38, "anchorEpoch": 2, "walkShard": 0,
            "validatorSetHash": "00", "walkedCommittee": {},
            "provenance": "", "reviewedAt": "", "reviewedBy": "",
            "upstreamCommit": "9dabb2a76a9ad5c6e99dfa180ab7bbbcb1a05a47", "reviewStatus": "draft"
        })).unwrap();
        assert!(matches!(draft.into_verifier(), Err(ConsensusError::UntrustedAnchor)));
    }

    #[test]
    fn signed_release_topology_authenticates_captured_epoch_12634_committee() {
        // This response is transport evidence captured from the public indexer. Its root is
        // calculated below from the signed release topology, never taken from the response.
        let committee: ValidatorSetCommittee = serde_json::from_str(r#"{
          "epoch":12634,
          "shard_group":{"start":1,"end_inclusive":256},
          "validator_set_hash":"dc39359775aa329670eb8cbfce7e1c77f7e5280d1ae334bc62bb46485c6c8956",
          "members":[
            {"public_key":"10780fe1b4d31f8350e4b881dccd8f8210ce056050ac6dd8cca88ca16710b044","vote_power":1},
            {"public_key":"568adadd2744c7bb3ae4c58e26e83a49a5b5af3380edfcd6b5d7af315580552f","vote_power":1},
            {"public_key":"c480fe3a76f03dcdce8d7c85ac7d0001ec97b667260172709b23818c8707e503","vote_power":1},
            {"public_key":"d6da35adba3642e7d1343985d5e4f123f5230a74c5480bf2857aabe50bcd6362","vote_power":1}
          ],
          "proof":"p2duZXR3b3JraWVzbWVyYWxkYWVlcG9jaBkxWm1udW1fcHJlc2hhcmRzZFAyNTZuY29tbWl0dGVlX3Jvb3SYIBgtGBoY9xjDGJoY7Ri/GBgYYhYYzhheGNMYahgwGKgXGNgYlRh7GOUYlBgdGPMY/hjvGM4YIBiuGPoY3Bhxa3NoYXJkX2dyb3VwomVzdGFydAFtZW5kX2luY2x1c2l2ZRkBAGdtZW1iZXJzhKJqcHVibGljX2tleVggEHgP4bTTH4NQ5LiB3M2PghDOBWBQrG3YzKiMoWcQsERqdm90ZV9wb3dlcgGianB1YmxpY19rZXlYIFaK2t0nRMe7OuTFjiboOkmlta8zgO381rXXrzFVgFUvanZvdGVfcG93ZXIBompwdWJsaWNfa2V5WCDEgP46dvA9zc6NfIWsfQAB7Je2ZyYBcnCbI4GMhwflA2p2b3RlX3Bvd2VyAaJqcHVibGljX2tleVgg1to1rbo2QufRNDmF1eTxI/UjCnTFSAvyhXqr5QvNY2Jqdm90ZV9wb3dlcgFlcHJvb2aiZGxlYWaiY2tleaFlYnl0ZXOYIBiLFRifCRhiGCAYtBjPGHEYzRg3GP0YfRjkGFcYjhhGGIEY5hjjGK0YqxjMGC4YuRhHGD8YkxhWGLwYvBgcanZhbHVlX2hhc2iYIAQYuxhTGOkYNRj1GHAYPBjlGNwSGJsYNgkYGREYyxjuGLsYbRjqGJkYLRi4GLAYshAYiwAYfhhzGNJoc2libGluZ3OA"
        }"#).unwrap();
        let epoch = Epoch(12_634);
        let hash = derive_esmeralda_v047_release_validator_set_hash(epoch);
        assert_eq!(hash.to_string(), "dc39359775aa329670eb8cbfce7e1c77f7e5280d1ae334bc62bb46485c6c8956");
        assert_eq!(committee.validator_set_hash, hash);
        PinnedConsensusVerifier::pinned(Network::Esmeralda, Shard::first(), epoch, &hash, &committee).unwrap();
        let reviewed = PinnedAnchorConfig {
            network: Network::Esmeralda.as_byte(),
            anchor_epoch: ESMERALDA_V047_RELEASE_ANCHOR_EPOCH,
            walk_shard: Shard::first().as_u32(),
            validator_set_hash: serde_json::to_value(hash).unwrap(),
            walked_committee: serde_json::to_value(&committee).unwrap(),
            provenance: "release bootstrap test".into(),
            reviewed_at: "2026-10-23T00:00:00Z".into(),
            reviewed_by: "test".into(),
            upstream_commit: ESMERALDA_V047_RELEASE_COMMIT.into(),
            review_status: "approved".into(),
            release_bootstrap: Some(ReleaseBootstrap {
                release_tag: ESMERALDA_V047_RELEASE_TAG.into(),
                signer_fingerprint: ESMERALDA_V047_RELEASE_SIGNER_FINGERPRINT.into(),
                policy_version: ESMERALDA_V047_RELEASE_BOOTSTRAP_POLICY_VERSION.into(),
                epoch_oracle_preset_sha256: ESMERALDA_V047_EPOCH_ORACLE_PRESET_SHA256.into(),
            }),
            max_proof_age_epochs: 1,
        };
        assert!(reviewed.clone().into_verifier().is_ok());
        let mut mismatched = reviewed.clone();
        mismatched.anchor_epoch += 1;
        assert!(matches!(mismatched.into_verifier(), Err(ConsensusError::UntrustedAnchor)));
        let mut wrong_signer = reviewed.clone();
        wrong_signer
            .release_bootstrap
            .as_mut()
            .unwrap()
            .signer_fingerprint = "0000000000000000000000000000000000000000".into();
        assert!(matches!(wrong_signer.into_verifier(), Err(ConsensusError::UntrustedAnchor)));
        let mut wrong_preset = reviewed.clone();
        wrong_preset
            .release_bootstrap
            .as_mut()
            .unwrap()
            .epoch_oracle_preset_sha256 = "00".into();
        assert!(matches!(wrong_preset.into_verifier(), Err(ConsensusError::UntrustedAnchor)));
        let mut wrong_tag = reviewed;
        wrong_tag.release_bootstrap.as_mut().unwrap().release_tag = "v0.47.1".into();
        assert!(matches!(wrong_tag.into_verifier(), Err(ConsensusError::UntrustedAnchor)));
        assert_ne!(hash, derive_esmeralda_v047_release_validator_set_hash(Epoch(12_635)));
    }

    #[test]
    fn esmeralda_anchor_rejects_global_shard_zero() {
        let epoch = Epoch(12_634);
        let set = ValidatorSetFixture::new(epoch.as_u64());
        let config = PinnedAnchorConfig {
            network: NETWORK.as_byte(),
            anchor_epoch: epoch.as_u64(),
            walk_shard: 0,
            validator_set_hash: serde_json::to_value(set.hash()).unwrap(),
            walked_committee: serde_json::to_value(set.committee(low())).unwrap(),
            provenance: "test only".into(),
            reviewed_at: "2026-10-23T00:00:00Z".into(),
            reviewed_by: "test".into(),
            upstream_commit: ESMERALDA_V047_RELEASE_COMMIT.into(),
            review_status: "approved".into(),
            release_bootstrap: None,
            max_proof_age_epochs: 1,
        };
        assert!(matches!(config.into_verifier(), Err(ConsensusError::UntrustedAnchor)));
    }
}
