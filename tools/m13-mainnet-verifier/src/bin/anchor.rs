use ootle_network::Network;
use tari_ootle_common_types::{
    Epoch, NumPreshards, ProtocolVersion, ShardGroup, VotePower, hash_validator_set_committee,
};
use tari_state_tree::ValidatorSetTree;
use tari_template_lib_types::crypto::RistrettoPublicKeyBytes;

const MAINNET_REGISTRATION_EPOCH: u64 = 38362;

const MAINNET_RELEASE_VALIDATORS: [&str; 7] = [
    "fa4e3963f426aa881f5956f99b20737326c6621227bb074fe47a5c5d54954403",
    "c445006d2d7555bd65c4d7569f99646efe23d070c63679efd5cb7105cce73048",
    "da4fdeeebc997ca1ab7d3b34a3fec1792f462dfbdbf19e5f3e47feef03df030c",
    "82e0018ee71779d63b068695b9b70d10ac498e7ba2e3a64ebe2c654a88e5192a",
    "dcfec0c59abdd1777e170034f4fb07a724f6300616ffafdad4cf139c36c86865",
    "68f671118bcf2e17aa44381b76a34e55f0d2ac9ef57865497688f0de508ea65d",
    "445e5b791db686ce9202a227e9d54f7864d28d399e998b78bc51b5a26f8f1950",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let network = Network::MainNet;
    let epoch = Epoch(MAINNET_REGISTRATION_EPOCH);
    let shard_group = ShardGroup::new(1u32, 256u32);

    let mut keys = MAINNET_RELEASE_VALIDATORS
        .iter()
        .map(|hex_key| {
            let bytes = hex::decode(hex_key)?;
            let array: [u8; 32] = bytes.try_into().map_err(|_| "validator key is not 32 bytes")?;
            let key = RistrettoPublicKeyBytes::from_bytes(&array)
                .map_err(|_| "validator key is not a canonical Ristretto point")?;
            Ok(key)
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    keys.dedup();

    let version = ProtocolVersion::at(network, epoch);
    let leaf = hash_validator_set_committee(
        version,
        &shard_group,
        keys.iter().map(|key| (key, VotePower::of(1), &[][..])),
    )?;

    let tree = ValidatorSetTree::build(
        network,
        epoch,
        NumPreshards::P256,
        [(shard_group, leaf)],
    )?;

    println!("network=mainnet byte=0x00");
    println!("registration_epoch={MAINNET_REGISTRATION_EPOCH}");
    println!("validators={}", keys.len());
    println!("protocol_version={version:?}");
    println!("state_tree_hash={}", tree.hash());
    Ok(())
}
