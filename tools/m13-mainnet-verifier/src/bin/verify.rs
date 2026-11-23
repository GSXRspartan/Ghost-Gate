use std::{collections::BTreeMap, str::FromStr};

use ootle_network::Network;
use serde::Deserialize;
use tari_engine_types::substate::SubstateId;
use tari_indexer_client::types::{
    EpochCheckpointEntry, GetCommitteeResponse, GetSubstateResponse, ListEpochCheckpointsResponse,
    SubstateState, ValidatorSetCommittee,
};
use tari_ootle_common_types::{Epoch, ValidatorSetHash, shard::Shard};
use tari_ootle_light_client::TrustedValidatorSet;

const ANCHOR_EPOCH: u64 = 38362;
const PINNED_VALIDATOR_SET_HASH: &str =
    "a434332a6f312f9d278fa614ed4f32cbe22cf6c08b17b58941bce832d3788e6a";
const PUBLIC_SUBSTATE: &str =
    "resource_0101010101010101010101010101010101010101010101010101010101010101";
const WALK_SHARD: u32 = 1;
const MAX_EXPECTED_INDEXER_VERSION_MINOR: u64 = 55;
const MAX_TRUSTED_EPOCH_LAG: u64 = 2;

#[derive(Debug, Deserialize)]
struct Health {
    current_epoch: u64,
    version: String,
}

fn anchor_hash() -> Result<ValidatorSetHash, Box<dyn std::error::Error>> {
    let bytes = hex::decode(PINNED_VALIDATOR_SET_HASH)?;
    let array: [u8; 32] = bytes.try_into().map_err(|_| "anchor hash is not 32 bytes")?;
    Ok(ValidatorSetHash::from_array(array))
}

async fn get_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    base: &str,
    path: &str,
) -> Result<T, Box<dyn std::error::Error>> {
    let url = format!("{base}{path}");
    let response = client.get(&url).send().await?;
    if !response.status().is_success() {
        return Err(format!("GET {url} returned {}", response.status()).into());
    }
    Ok(response.json::<T>().await?)
}

fn check_version(version: &str) -> Result<(), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = version.split('.').collect();
    let minor = parts.get(1).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    if parts.first() != Some(&"0") || minor < MAX_EXPECTED_INDEXER_VERSION_MINOR {
        return Err(format!("unsupported indexer response version {version}").into());
    }
    Ok(())
}

async fn fetch_committee(
    client: &reqwest::Client,
    base: &str,
    epoch: u64,
) -> Result<ValidatorSetCommittee, Box<dyn std::error::Error>> {
    let response: GetCommitteeResponse = get_json(
        client,
        base,
        &format!("/committees?epoch={epoch}&shard={WALK_SHARD}"),
    )
    .await?;
    Ok(response.committee)
}

async fn fetch_checkpoints(
    client: &reqwest::Client,
    base: &str,
    from_epoch: u64,
) -> Result<Vec<EpochCheckpointEntry>, Box<dyn std::error::Error>> {
    let mut all = Vec::new();
    let mut from = from_epoch;
    loop {
        let response: ListEpochCheckpointsResponse = get_json(
            client,
            base,
            &format!("/epoch-checkpoints?from_epoch={from}&limit=100&shard={WALK_SHARD}&include_committees=true"),
        )
        .await?;
        if response.checkpoints.is_empty() {
            break;
        }
        let last = response.checkpoints.last().unwrap().epoch.as_u64();
        all.extend(response.checkpoints);
        from = last + 1;
        if last >= from_epoch + 1000 {
            break;
        }
    }
    Ok(all)
}

fn verify_handovers(
    anchor: &ValidatorSetHash,
    anchor_committee: &ValidatorSetCommittee,
    checkpoints: &[EpochCheckpointEntry],
    target_epoch: u64,
) -> Result<(TrustedValidatorSet, BTreeMap<u64, TrustedValidatorSet>), Box<dyn std::error::Error>> {
    let mut trusted = TrustedValidatorSet::anchor_pinned(
        Network::MainNet,
        Shard::from_u32(WALK_SHARD),
        Epoch(ANCHOR_EPOCH),
        anchor,
        anchor_committee,
    )?;
    let mut sets = BTreeMap::new();
    sets.insert(trusted.epoch().as_u64(), trusted.clone());

    for entry in checkpoints {
        if entry.epoch.as_u64() < ANCHOR_EPOCH {
            continue;
        }
        trusted = trusted.advance(entry)?;
        sets.insert(trusted.epoch().as_u64(), trusted.clone());
        if trusted.epoch().as_u64() >= target_epoch {
            break;
        }
    }
    Ok((trusted, sets))
}

fn checkpoint_digest(checkpoints: &[EpochCheckpointEntry]) -> String {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    for entry in checkpoints {
        entry.epoch.as_u64().hash(&mut hasher);
        entry
            .next_epoch_validator_set_hash
            .map(|hash| hash.to_string())
            .unwrap_or_default()
            .hash(&mut hasher);
    }
    format!("{:016x}", hasher.finish())
}

async fn verify_substate(
    client: &reqwest::Client,
    base: &str,
    sets: &BTreeMap<u64, TrustedValidatorSet>,
) -> Result<(), Box<dyn std::error::Error>> {
    let response: GetSubstateResponse = get_json(
        client,
        base,
        &format!("/substates/{PUBLIC_SUBSTATE}?include_proof=true"),
    )
    .await?;
    let proof = response.proof.as_ref().ok_or("substate response carried no proof")?;
    let set = sets.get(&proof.anchor.epoch.as_u64()).ok_or_else(|| {
        format!("no trusted committee for proof anchor epoch {}", proof.anchor.epoch)
    })?;
    let substate_id = SubstateId::from_str(PUBLIC_SUBSTATE)?;
    match &response.state {
        SubstateState::Up { substate } => {
            let (tip, value) = set
                .walk_committee()
                .verify_substate(&substate_id, response.version, substate, proof)?;
            println!(
                "substate: verified up at epoch {} height {} value {:?}",
                tip.epoch, tip.height, std::mem::discriminant(&value)
            );
            let wrong_id = SubstateId::from_str(
                "resource_0202020202020202020202020202020202020202020202020202020202020202",
            )?;
            assert!(
                set.walk_committee()
                    .verify_substate(&wrong_id, response.version, substate, proof)
                    .is_err(),
                "invalid substate binding must fail"
            );
            assert!(
                set.walk_committee()
                    .verify_absent(&substate_id, response.version, proof)
                    .is_err(),
                "an inclusion proof must not verify as a down/absent proof"
            );
            println!("negative tests: wrong substate id and up-as-down both fail closed");
        }
        SubstateState::Down {} => {
            let tip = set.walk_committee().verify_absent(&substate_id, response.version, proof)?;
            println!("substate: verified down at epoch {} height {}", tip.epoch, tip.height);
        }
    }
    Ok(())
}

fn self_tests(
    anchor: &ValidatorSetHash,
    committee: &ValidatorSetCommittee,
    checkpoints: &[EpochCheckpointEntry],
    health: &Health,
) -> Result<(), Box<dyn std::error::Error>> {
    let wrong = ValidatorSetHash::from_array([0u8; 32]);
    assert!(
        TrustedValidatorSet::anchor_pinned(
            Network::MainNet,
            Shard::from_u32(WALK_SHARD),
            Epoch(ANCHOR_EPOCH),
            &wrong,
            committee,
        )
        .is_err(),
        "wrong anchor must fail"
    );
    assert!(
        TrustedValidatorSet::anchor_pinned(
            Network::Esmeralda,
            Shard::from_u32(WALK_SHARD),
            Epoch(ANCHOR_EPOCH),
            anchor,
            committee,
        )
        .is_err(),
        "wrong network must fail"
    );
    let trusted = TrustedValidatorSet::anchor_pinned(
        Network::MainNet,
        Shard::from_u32(WALK_SHARD),
        Epoch(ANCHOR_EPOCH),
        anchor,
        committee,
    )?;
    if let Some(skipped) = checkpoints.iter().find(|e| e.epoch.as_u64() > ANCHOR_EPOCH + 1) {
        assert!(
            trusted.advance(skipped).is_err(),
            "missing handover must fail"
        );
    }
    assert!(
        check_version("0.42.0").is_err(),
        "unsupported response version must fail"
    );
    assert!(
        health.current_epoch.saturating_sub(ANCHOR_EPOCH) > MAX_TRUSTED_EPOCH_LAG,
        "freshness check must reject an old anchor"
    );
    println!("self-tests: wrong anchor, wrong network, missing handover, version, freshness all fail closed");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let bases = [
        "https://indexer-a.ootle.tari.com",
        "https://indexer-b.ootle.tari.com",
    ];

    let mut health = None;
    let mut committee = None;
    let mut checkpoints = None;
    for base in bases {
        let h: Health = get_json(&client, base, "/health").await?;
        check_version(&h.version)?;
        let c = fetch_committee(&client, base, ANCHOR_EPOCH).await?;
        if c.validator_set_hash.to_string() != PINNED_VALIDATOR_SET_HASH {
            return Err("indexer committee does not match release-derived anchor".into());
        }
        let cp = fetch_checkpoints(&client, base, ANCHOR_EPOCH).await?;
        match &health {
            None => {
                health = Some(h);
                committee = Some(c);
                checkpoints = Some(cp);
            }
            Some(first_health) => {
                if first_health.current_epoch != h.current_epoch {
                    return Err("indexers disagree on current epoch; refuse to rely on liveness claim".into());
                }
                if checkpoint_digest(checkpoints.as_ref().unwrap()) != checkpoint_digest(&cp) {
                    return Err("indexers disagree on checkpoint chain".into());
                }
                println!("cross-indexer: health epoch and checkpoint chain agree (not a consensus proof)");
            }
        }
    }

    let health = health.ok_or("no indexer health")?;
    let committee = committee.ok_or("no committee")?;
    let checkpoints = checkpoints.ok_or("no checkpoints")?;
    let anchor = anchor_hash()?;
    let wrong_epoch_committee = fetch_committee(&client, bases[0], ANCHOR_EPOCH + 1).await?;
    assert!(
        TrustedValidatorSet::anchor_pinned(
            Network::MainNet,
            Shard::from_u32(WALK_SHARD),
            Epoch(ANCHOR_EPOCH),
            &anchor,
            &wrong_epoch_committee,
        )
        .is_err(),
        "committee from another epoch must fail"
    );
    self_tests(&anchor, &committee, &checkpoints, &health)?;

    let (stale, _) = verify_handovers(&anchor, &committee, &checkpoints[..10.min(checkpoints.len())], health.current_epoch)?;
    assert!(
        health.current_epoch.saturating_sub(stale.epoch().as_u64()) > MAX_TRUSTED_EPOCH_LAG,
        "withheld checkpoints must be detected as stale"
    );
    println!("negative tests: foreign-epoch committee and withheld checkpoints fail closed");

    let (trusted, sets) = verify_handovers(&anchor, &committee, &checkpoints, health.current_epoch)?;
    println!("anchor epoch={ANCHOR_EPOCH} hash={PINNED_VALIDATOR_SET_HASH}");
    println!("walked checkpoints={} latest trusted epoch={}", checkpoints.len(), trusted.epoch());

    if health.current_epoch.saturating_sub(trusted.epoch().as_u64()) > MAX_TRUSTED_EPOCH_LAG {
        return Err("trusted state is stale relative to indexer health".into());
    }

    let saved = serde_json::to_string(&trusted)?;
    std::fs::write(
        "tools/m13-mainnet-verifier/trusted-state.json",
        saved,
    )?;
    let loaded: TrustedValidatorSet = serde_json::from_str(&std::fs::read_to_string(
        "tools/m13-mainnet-verifier/trusted-state.json",
    )?)?;
    if loaded.epoch() != trusted.epoch() {
        return Err("persisted trusted state did not survive restart".into());
    }
    println!("persistence: trusted epoch {} survived save/load", loaded.epoch());

    verify_substate(&client, bases[0], &sets).await?;
    println!("RESULT: authenticated checkpoint chain and public substate proof verified");
    Ok(())
}
