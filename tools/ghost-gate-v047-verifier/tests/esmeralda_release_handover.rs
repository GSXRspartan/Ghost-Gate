//! Genuine, retained public-indexer transport verified relative to the reviewed release candidate.
//!
//! The two JSON files are transport only. The initial root is derived from the signed release
//! topology; neither response selects the root used by `anchor_pinned`.

use ghost_gate_v047_verifier::{
    PinnedConsensusVerifier,
    derive_esmeralda_v047_release_validator_set_hash,
};
use ootle_network::Network;
use tari_indexer_client::types::{EpochCheckpointEntry, ListEpochCheckpointsResponse};
use tari_ootle_common_types::{Epoch, ProtocolVersion, shard::Shard};

fn retained_entry(bytes: &[u8]) -> EpochCheckpointEntry {
    let mut response: ListEpochCheckpointsResponse = serde_json::from_slice(bytes).unwrap();
    assert_eq!(response.checkpoints.len(), 1);
    response.checkpoints.pop().unwrap()
}

#[test]
fn genuine_12634_to_12635_handover_verifies_from_the_release_candidate_root() {
    let predecessor = retained_entry(include_bytes!("../evidence/esmeralda-epoch-12633-shard-1.json"));
    let handover = retained_entry(include_bytes!("../evidence/esmeralda-epoch-12634-shard-1.json"));
    let epoch = Epoch(12_634);
    let next_epoch = Epoch(12_635);
    let root = derive_esmeralda_v047_release_validator_set_hash(epoch);
    let next_root = derive_esmeralda_v047_release_validator_set_hash(next_epoch);

    assert_eq!(Network::Esmeralda.as_byte(), 38);
    assert_eq!(ProtocolVersion::at(Network::Esmeralda, epoch), ProtocolVersion::V2);
    assert_eq!(root.to_string(), "dc39359775aa329670eb8cbfce7e1c77f7e5280d1ae334bc62bb46485c6c8956");
    assert_eq!(next_root.to_string(), "23b6a682150e19910b13f626f89a6352212554a50625a3eaa85b88b74fa2fc7f");

    // The preceding response transports the committee for the candidate anchor epoch. Its proof
    // is checked against `root`; a different root cannot become an anchor.
    assert_eq!(predecessor.epoch, Epoch(12_633));
    let anchor_committee = predecessor.next_epoch_committee.as_ref().unwrap();
    assert_eq!(anchor_committee.epoch, epoch);
    assert_eq!(anchor_committee.validator_set_hash, root);
    assert!(PinnedConsensusVerifier::pinned(
        Network::Esmeralda,
        Shard::first(),
        epoch,
        &next_root,
        anchor_committee,
    )
    .is_err());

    let mut verifier = PinnedConsensusVerifier::pinned(
        Network::Esmeralda,
        Shard::first(),
        epoch,
        &root,
        anchor_committee,
    )
    .unwrap();
    assert_eq!(handover.epoch, epoch);
    assert_eq!(handover.next_epoch_validator_set_hash, Some(next_root));
    verifier.advance(&handover).unwrap();
    assert_eq!(verifier.latest_epoch(), next_epoch);
    assert_eq!(verifier.latest_validator_set_hash(), next_root);
}
