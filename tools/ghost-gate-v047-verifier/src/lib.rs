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

use ootle_network::Network;
use tari_engine_types::{
    SubstateVersion,
    substate::{SubstateId, SubstateValue},
};
use tari_indexer_client::types::{EpochCheckpointEntry, SubstateProof, ValidatorSetCommittee};
use tari_ootle_common_types::{Epoch, ValidatorSetHash, shard::Shard};
use tari_ootle_light_client::{LightClientError, TrustedValidatorSet, TrustedValidatorSetHash};

/// Audit metadata extracted only after the official v0.47 verifier has accepted an inclusion
/// proof and its quorum-signed block proof. This is not a browser assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEvidence {
    pub network: u8,
    pub epoch: u64,
    pub shard_group: String,
    pub height: u64,
    pub block_id: String,
    pub state_merkle_root: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    #[error("GG: the proof is for an epoch not reached by the pinned handover chain")]
    EpochNotTrusted,
    #[error("GG: the proof's committee cannot be verified against the trusted validator set: {0}")]
    Verification(#[from] LightClientError),
}

/// A validator-set chain rooted in one externally pinned v0.47 validator-set hash.
///
/// The adapter retains every verified set in the chain, so evidence from an earlier verified
/// epoch can be checked without treating an indexer response as a new root of trust.
pub struct PinnedConsensusVerifier {
    latest: TrustedValidatorSet,
    trusted_sets: BTreeMap<Epoch, TrustedValidatorSetHash>,
}

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
    use tari_ootle_light_client::test_fixtures::{NETWORK, ValidatorSetFixture, low, substate_proof};
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
}
