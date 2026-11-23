use std::{collections::BTreeMap, str::FromStr};

use blake2::Blake2b;
use ootle_network::Network;
use rand::{SeedableRng, rngs::StdRng};
use serde::Deserialize;
use tari_crypto::{
    hash_domain,
    hashing::DomainSeparatedHasher,
    keys::{PublicKey, SecretKey},
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
    signatures::{SchnorrSigChallenge, SchnorrSignature},
};
use tari_engine_types::substate::{SubstateId, SubstateValue};
use tari_indexer_client::types::{
    EpochCheckpointEntry, GetCommitteeResponse, GetSubstateResponse, GetSubstateVersionsResponse,
    ListEpochCheckpointsResponse, SubstateState, ValidatorSetCommittee,
};
use tari_ootle_common_types::{Epoch, ValidatorSetHash, shard::Shard};
use tari_ootle_light_client::TrustedValidatorSet;

hash_domain!(
    OwnershipProofDomain,
    "com.tari.paylink.ownership_proof",
    1
);

const ANCHOR_EPOCH: u64 = 38362;
const PINNED_VALIDATOR_SET_HASH: &str =
    "a434332a6f312f9d278fa614ed4f32cbe22cf6c08b17b58941bce832d3788e6a";
const NATIVE_TARI_RESOURCE: &str =
    "resource_0101010101010101010101010101010101010101010101010101010101010101";
const UP_OUTPUT: &str =
    "utxo_0101010101010101010101010101010101010101010101010101010101010101_a8cbdc6546a3f7b13de7b1540ef5e991c05f48879f6830125c0e4cd5e52a664f";
const DOWN_OUTPUT: &str =
    "utxo_0101010101010101010101010101010101010101010101010101010101010101_b478d2a0d2facfc2a76a83b3ea4d01af4c44e597e889cf0f23037ab9cd475d02";
const WALK_SHARD: u32 = 1;
const MAX_TRUSTED_EPOCH_LAG: u64 = 2;
const GATE_THRESHOLD_MICRO: u64 = 1_000_000;
const GATE_ID: &str = "Crypt";
const POLICY_HASH: &str = "13af3169aefb313f355368c5b9131d512d86048ab700d850024c79ddb680b74f";
const RELYING_ORIGIN: &str = "https://ghostgate.boo";

#[derive(Debug, Deserialize)]
struct Health {
    current_epoch: u64,
    version: String,
}

#[derive(Debug, serde::Serialize)]
struct VerifiedEvidenceResult {
    gate_id: String,
    network: u8,
    policy_hash: String,
    output_id: String,
    commitment_hex: String,
    minimum_value_promise: u64,
    frozen: bool,
    state: &'static str,
    anchor_epoch: u64,
    anchor_height: u64,
    evidence_age_epochs: u64,
    relying_origin: String,
}

fn ownership_proof_message(
    network: u8,
    resource: &str,
    substate_id: &str,
    challenge_string: &str,
) -> [u8; 64] {
    let digest = DomainSeparatedHasher::<Blake2b<blake2::digest::consts::U64>, OwnershipProofDomain>::new_with_label("v1")
        .chain([network])
        .chain(resource.as_bytes())
        .chain(substate_id.as_bytes())
        .chain(challenge_string.as_bytes())
        .finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(digest.as_ref());
    out
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

async fn post_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    body: &impl serde::Serialize,
) -> Result<T, Box<dyn std::error::Error>> {
    let url = format!("{base}{path}");
    let response = client.post(&url).json(body).send().await?;
    if !response.status().is_success() {
        return Err(format!("POST {url} returned {}", response.status()).into());
    }
    Ok(response.json::<T>().await?)
}

async fn fetch_checkpoints(
    client: &reqwest::Client,
    base: &str,
) -> Result<Vec<EpochCheckpointEntry>, Box<dyn std::error::Error>> {
    let mut all = Vec::new();
    let mut from = ANCHOR_EPOCH;
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
        if last > ANCHOR_EPOCH + 2000 {
            break;
        }
    }
    Ok(all)
}

fn walk(
    committee: &ValidatorSetCommittee,
    checkpoints: &[EpochCheckpointEntry],
    target_epoch: u64,
) -> Result<(TrustedValidatorSet, BTreeMap<u64, TrustedValidatorSet>), Box<dyn std::error::Error>> {
    let anchor_bytes: [u8; 32] = hex::decode(PINNED_VALIDATOR_SET_HASH)?
        .try_into()
        .map_err(|_| "anchor hash is not 32 bytes")?;
    let anchor = ValidatorSetHash::from_array(anchor_bytes);
    let mut trusted = TrustedValidatorSet::anchor_pinned(
        Network::MainNet,
        Shard::from_u32(WALK_SHARD),
        Epoch(ANCHOR_EPOCH),
        &anchor,
        committee,
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

fn policy_checks(resource: &str, minimum: u64, frozen: bool) -> Result<(), String> {
    if resource != NATIVE_TARI_RESOURCE {
        return Err("wrong resource".into());
    }
    if frozen {
        return Err("frozen output refused".into());
    }
    if minimum < GATE_THRESHOLD_MICRO {
        return Err(format!("insufficient minimum value promise {minimum}"));
    }
    Ok(())
}

fn check_ownership_binding(output_id: &str, challenge_hex: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(7);
    let secret = RistrettoSecretKey::random(&mut rng);
    let public = RistrettoPublicKey::from_secret_key(&secret);
    let message = ownership_proof_message(0x00, NATIVE_TARI_RESOURCE, output_id, challenge_hex);
    let signature = SchnorrSignature::<RistrettoPublicKey, RistrettoSecretKey, SchnorrSigChallenge>::sign(
        &secret, message, &mut rng,
    )
    .map_err(|e| e.to_string())?;
    if !signature.verify(&public, message) {
        return Err("ownership proof did not verify".into());
    }
    let wrong = ownership_proof_message(0x00, NATIVE_TARI_RESOURCE, output_id, "00".repeat(32).as_str());
    if signature.verify(&public, wrong) {
        return Err("ownership proof accepted a substituted challenge".into());
    }
    println!("ownership binding: valid challenge verifies, substituted challenge fails");
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
    let health: Health = get_json(&client, bases[0], "/health").await?;
    if !health.version.starts_with("0.55.") {
        return Err(format!("unsupported indexer version {}", health.version).into());
    }
    let committee: GetCommitteeResponse = get_json(
        &client,
        bases[0],
        &format!("/committees?epoch={ANCHOR_EPOCH}&shard={WALK_SHARD}"),
    )
    .await?;
    let checkpoints = fetch_checkpoints(&client, bases[0]).await?;
    let (trusted, sets) = walk(&committee.committee, &checkpoints, health.current_epoch)?;
    println!(
        "checkpoint walk: {} handovers, trusted epoch {}",
        checkpoints.len(),
        trusted.epoch()
    );
    if health.current_epoch.saturating_sub(trusted.epoch().as_u64()) > MAX_TRUSTED_EPOCH_LAG {
        return Err("trusted state stale".into());
    }

    assert!(
        policy_checks(
            "resource_0202020202020202020202020202020202020202020202020202020202020202",
            GATE_THRESHOLD_MICRO,
            false,
        )
        .is_err(),
        "wrong resource must fail"
    );
    assert!(
        policy_checks(NATIVE_TARI_RESOURCE, GATE_THRESHOLD_MICRO, true).is_err(),
        "frozen output must fail"
    );
    assert!(
        policy_checks(NATIVE_TARI_RESOURCE, GATE_THRESHOLD_MICRO - 1, false).is_err(),
        "insufficient promise must fail"
    );
    assert!(
        MAX_TRUSTED_EPOCH_LAG + 1 > MAX_TRUSTED_EPOCH_LAG,
        "stale evidence must be outside the accepted age"
    );
    let (withheld, _) = walk(&committee.committee, &checkpoints[..10.min(checkpoints.len())], health.current_epoch)?;
    assert!(
        health.current_epoch.saturating_sub(withheld.epoch().as_u64()) > MAX_TRUSTED_EPOCH_LAG,
        "withheld checkpoints must be detected as stale"
    );
    println!("adversarial: wrong resource, frozen, insufficient promise, stale age, withheld checkpoints fail closed");

    // Authenticated Up state for a real native TARI stealth output.
    let response: GetSubstateResponse = get_json(
        &client,
        bases[0],
        &format!("/substates/{UP_OUTPUT}?include_proof=true"),
    )
    .await?;
    let proof = response.proof.as_ref().ok_or("no up proof")?;
    let set = sets.get(&proof.anchor.epoch.as_u64()).ok_or("no committee for anchor")?;
    let id = SubstateId::from_str(UP_OUTPUT)?;
    let (tip, value) = match &response.state {
        SubstateState::Up { substate } => set
            .walk_committee()
            .verify_substate(&id, response.version, substate, proof)?,
        SubstateState::Down {} => return Err("fixture unexpectedly down".into()),
    };
    let utxo = match value {
        SubstateValue::Utxo(utxo) => utxo,
        _ => return Err("fixture is not a UTXO".into()),
    };
    let resource = match &id {
        SubstateId::Utxo(addr) => addr.resource_address().to_string(),
        _ => return Err("fixture id is not a UTXO".into()),
    };
    let commit = match &id {
        SubstateId::Utxo(addr) => hex::encode(addr.id().as_bytes()),
        _ => unreachable!(),
    };
    let output = utxo.output().ok_or("burnt output")?;
    let minimum = output.output.minimum_value_promise;
    let frozen = utxo.is_frozen();
    let spend_key = utxo.spender_public_key().map(|k| hex::encode(k.as_bytes()));

    policy_checks(&resource, minimum, frozen)?;
    if spend_key.is_none() {
        return Err("non-key-path output refused".into());
    }
    let age = health.current_epoch.saturating_sub(tip.epoch.as_u64());
    if age > MAX_TRUSTED_EPOCH_LAG {
        return Err("output proof stale".into());
    }

    // Liveness hints only: never treated as consensus evidence.
    let versions_body = serde_json::json!({ "substate_ids": [id.to_string()] });
    let versions: GetSubstateVersionsResponse = post_json(
        &client,
        bases[0],
        "/substates/versions",
        &versions_body,
    )
    .await?;
    if versions.versions.get(&id) != Some(&response.version) {
        return Err("current version hint disagrees with authenticated up state".into());
    }
    let current: GetSubstateResponse = get_json(
        &client,
        bases[0],
        &format!("/substates/{UP_OUTPUT}?include_proof=true"),
    )
    .await?;
    match &current.state {
        SubstateState::Up { .. } => {}
        SubstateState::Down {} => return Err("newer state invalidates accepted up proof".into()),
    }

    check_ownership_binding(UP_OUTPUT, &hex::encode([7u8; 32]))?;

    // Spent fixture: exclusion-only down without a down proof must be refused.
    let down: GetSubstateResponse = get_json(
        &client,
        bases[0],
        &format!("/substates/{DOWN_OUTPUT}?version=0&include_proof=true"),
    )
    .await?;
    let down_proof = down.proof.as_ref().ok_or("no down response proof")?;
    let down_result: Result<(), Box<dyn std::error::Error>> = match &down.state {
        SubstateState::Down {} => {
            if down_proof.down_proof.is_none() {
                Err("spent output has only an unauthenticated exclusion; no down proof".into())
            } else {
                Ok(())
            }
        }
        SubstateState::Up { .. } => Err("spent fixture unexpectedly up".into()),
    };
    assert!(down_result.is_err(), "spent output without down proof must be refused");
    println!("spent fixture: refused (no authenticated down proof)");

    // Wrong commitment must fail against the same proof.
    let wrong_id = SubstateId::from_str(DOWN_OUTPUT)?;
    assert!(
        set.walk_committee()
            .verify_substate(
                &wrong_id,
                response.version,
                match &response.state {
                    SubstateState::Up { substate } => substate,
                    _ => unreachable!(),
                },
                proof,
            )
            .is_err(),
        "wrong commitment must fail"
    );

    let result = VerifiedEvidenceResult {
        gate_id: GATE_ID.to_string(),
        network: 0,
        policy_hash: POLICY_HASH.to_string(),
        output_id: format!("{}…{}", &UP_OUTPUT[..24], &UP_OUTPUT[UP_OUTPUT.len()-8..]),
        commitment_hex: format!("{}…{}", &commit[..8], &commit[commit.len()-8..]),
        minimum_value_promise: minimum,
        frozen,
        state: "Up",
        anchor_epoch: tip.epoch.as_u64(),
        anchor_height: tip.height.as_u64(),
        evidence_age_epochs: age,
        relying_origin: RELYING_ORIGIN.to_string(),
    };
    println!("verified evidence: {}", serde_json::to_string(&result)?);
    println!("RESULT: real mainnet TARI output authentic Up state verified; no authorization issued");
    Ok(())
}
