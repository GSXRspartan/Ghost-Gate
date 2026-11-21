use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use ghost_gate_ggbp1::{
    ESMERALDA_GENESIS_HASH, ESMERALDA_NETWORK, Ggbp1ChainPolicy, Ggbp1ChainSnapshot,
    Ggbp1ChainView, Ggbp1ChainViewError, Ggbp1ChallengeRequest, Ggbp1EvidenceSource,
    Ggbp1ObservedOutput, Ggbp1ServerError, Ggbp1TestServer, Ggbp1TestVerdictStatus,
    Ggbp1WireProof, SyntheticOutputWitness, SyntheticSubjectWitness, SyntheticStandardOutput,
    gate_configuration_version, gate_id_bytes, prove_synthetic,
};
use tari_crypto::{
    keys::PublicKey,
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
};

const GATE_ID: &str = "xtmtest";
const THRESHOLD: u64 = 1_000_000;
const NOW: u64 = 1_800_000_000;

struct MockChain {
    snapshot: Ggbp1ChainSnapshot,
    outputs: BTreeMap<[u8; 32], Ggbp1ObservedOutput>,
}

#[async_trait]
impl Ggbp1ChainView for MockChain {
    async fn snapshot(&self) -> Result<Ggbp1ChainSnapshot, Ggbp1ChainViewError> {
        Ok(self.snapshot.clone())
    }

    async fn output(
        &self,
        expected: &SyntheticStandardOutput,
    ) -> Result<Option<Ggbp1ObservedOutput>, Ggbp1ChainViewError> {
        Ok(self.outputs.get(&expected.output_hash).cloned())
    }
}

fn subject_secret() -> RistrettoSecretKey {
    RistrettoSecretKey::from(11u64)
}

fn outputs() -> Vec<SyntheticOutputWitness> {
    vec![
        SyntheticOutputWitness::new([1u8; 32], 600_000, RistrettoSecretKey::from(21u64), RistrettoSecretKey::from(31u64)),
        SyntheticOutputWitness::new([2u8; 32], 500_000, RistrettoSecretKey::from(22u64), RistrettoSecretKey::from(32u64)),
    ]
}

fn request() -> Ggbp1ChallengeRequest {
    Ggbp1ChallengeRequest {
        subject_id: [3u8; 16],
        origin_hash: [4u8; 32],
        subject_authentication_public_key: RistrettoPublicKey::from_secret_key(&subject_secret()),
        gate_id: gate_id_bytes(GATE_ID),
        gate_configuration_version: gate_configuration_version(GATE_ID, THRESHOLD, ESMERALDA_NETWORK),
        threshold_micro_xtm: THRESHOLD,
        requested_ttl_seconds: 60,
    }
}

fn observed(output: &SyntheticStandardOutput) -> Ggbp1ObservedOutput {
    Ggbp1ObservedOutput {
        output_hash: output.output_hash,
        commitment: output.commitment.clone(),
        script: output.script.clone(),
        script_public_key: output.script_public_key.clone(),
        mined_height: 100,
        mined_block_hash: [7u8; 32],
        confirmations: 5,
        maturity_height: 100,
        output_version: 0,
        output_type: 0,
        range_proof_type: 0,
        covenant_is_supported: Some(true),
        effective_lock_height: Some(100),
        is_unspent: true,
        is_in_best_chain: true,
    }
}

fn chain(source: Ggbp1EvidenceSource) -> Arc<MockChain> {
    let witnesses = outputs();
    let outputs = witnesses
        .iter()
        .map(|witness| (witness.public.output_hash, observed(&witness.public)))
        .collect();
    Arc::new(MockChain {
        snapshot: Ggbp1ChainSnapshot {
            source,
            network: ESMERALDA_NETWORK,
            genesis_hash: ESMERALDA_GENESIS_HASH,
            tip_height: 104,
            tip_hash: [9u8; 32],
            tip_timestamp_unix_seconds: NOW,
            is_synced: true,
        },
        outputs,
    })
}

fn server(policy: Ggbp1ChainPolicy, chain: Option<Arc<MockChain>>) -> Ggbp1TestServer {
    Ggbp1TestServer::new_for_tests(
        ESMERALDA_NETWORK,
        ESMERALDA_GENESIS_HASH,
        policy,
        chain.map(|chain| chain as Arc<dyn Ggbp1ChainView>),
    )
}

fn proof_response(challenge: ghost_gate_ggbp1::Ggbp1Challenge) -> Vec<u8> {
    let subject = SyntheticSubjectWitness::new(subject_secret());
    let outputs = outputs();
    let proof = prove_synthetic(&challenge, &subject, &outputs).unwrap();
    Ggbp1WireProof { challenge, proof }.to_bytes().unwrap()
}

#[tokio::test]
async fn a_valid_proof_is_verified_test_only_and_never_authorized() {
    let server = server(Ggbp1ChainPolicy::synthetic_test_fixture(), Some(chain(Ggbp1EvidenceSource::SyntheticFixture)));
    let mut rng = rand::rng();
    let issued = server.issue_challenge(request(), NOW, &mut rng).await.unwrap();
    let response = proof_response(issued.challenge.clone());
    let verdict = server.submit_response(&response, NOW + 1).await.unwrap();
    assert_eq!(verdict.status, Ggbp1TestVerdictStatus::VerifiedTestOnly);
    assert!(!verdict.authorized);
    assert_eq!(verdict.output_hashes, vec![[1u8; 32], [2u8; 32]]);
    assert_eq!(verdict.chain_evidence, Some(Ggbp1EvidenceSource::SyntheticFixture));
    assert_eq!(verdict.verified_tip_height, Some(104));
}

#[tokio::test]
async fn a_redeemed_challenge_cannot_be_replayed() {
    let server = server(Ggbp1ChainPolicy::synthetic_test_fixture(), Some(chain(Ggbp1EvidenceSource::SyntheticFixture)));
    let mut rng = rand::rng();
    let issued = server.issue_challenge(request(), NOW, &mut rng).await.unwrap();
    let response = proof_response(issued.challenge.clone());
    server.submit_response(&response, NOW + 1).await.unwrap();
    assert!(matches!(
        server.submit_response(&response, NOW + 2).await.unwrap_err(),
        Ggbp1ServerError::ChallengeRedeemed
    ));
}

#[tokio::test]
async fn an_output_cannot_be_used_by_a_second_challenge() {
    let server = server(Ggbp1ChainPolicy::synthetic_test_fixture(), Some(chain(Ggbp1EvidenceSource::SyntheticFixture)));
    let mut rng = rand::rng();
    let first = server.issue_challenge(request(), NOW, &mut rng).await.unwrap();
    server
        .submit_response(&proof_response(first.challenge), NOW + 1)
        .await
        .unwrap();
    let second = server.issue_challenge(request(), NOW + 2, &mut rng).await.unwrap();
    assert!(matches!(
        server
            .submit_response(&proof_response(second.challenge), NOW + 3)
            .await
            .unwrap_err(),
        Ggbp1ServerError::OutputAlreadyRegistered
    ));
}

#[tokio::test]
async fn a_response_for_a_different_challenge_is_refused_before_verification() {
    let server = server(Ggbp1ChainPolicy::synthetic_test_fixture(), Some(chain(Ggbp1EvidenceSource::SyntheticFixture)));
    let mut rng = rand::rng();
    let issued = server.issue_challenge(request(), NOW, &mut rng).await.unwrap();
    let mut other = issued.challenge.clone();
    other.origin_hash = [8u8; 32];
    let response = proof_response(other);
    assert!(matches!(
        server.submit_response(&response, NOW + 1).await.unwrap_err(),
        Ggbp1ServerError::ChallengeMismatch
    ));
    // The original challenge is still redeemable with the correct response.
    server
        .submit_response(&proof_response(issued.challenge), NOW + 1)
        .await
        .unwrap();
}

#[tokio::test]
async fn an_expired_challenge_is_refused() {
    let server = server(Ggbp1ChainPolicy::synthetic_test_fixture(), Some(chain(Ggbp1EvidenceSource::SyntheticFixture)));
    let mut rng = rand::rng();
    let issued = server.issue_challenge(request(), NOW, &mut rng).await.unwrap();
    assert!(matches!(
        server
            .submit_response(&proof_response(issued.challenge), NOW + 60)
            .await
            .unwrap_err(),
        Ggbp1ServerError::ChallengeExpired
    ));
}

#[tokio::test]
async fn a_tampered_proof_is_refused_and_the_challenge_stays_active() {
    let server = server(Ggbp1ChainPolicy::synthetic_test_fixture(), Some(chain(Ggbp1EvidenceSource::SyntheticFixture)));
    let mut rng = rand::rng();
    let issued = server.issue_challenge(request(), NOW, &mut rng).await.unwrap();
    let subject = SyntheticSubjectWitness::new(subject_secret());
    let outputs = outputs();
    let mut proof = prove_synthetic(&issued.challenge, &subject, &outputs).unwrap();
    proof.outputs[0].commitment = outputs[1].public.commitment.clone();
    let response = Ggbp1WireProof { challenge: issued.challenge.clone(), proof }.to_bytes().unwrap();
    assert!(matches!(
        server.submit_response(&response, NOW + 1).await.unwrap_err(),
        Ggbp1ServerError::Proof(_)
    ));
    // A corrected response can still redeem the same challenge.
    server
        .submit_response(&proof_response(issued.challenge), NOW + 2)
        .await
        .unwrap();
}

#[tokio::test]
async fn diagnostic_chain_evidence_is_never_positive() {
    let server = server(
        Ggbp1ChainPolicy::esmeralda_diagnostic(),
        Some(chain(Ggbp1EvidenceSource::UntrustedBaseNodeRpc)),
    );
    let mut rng = rand::rng();
    let issued = server.issue_challenge(request(), NOW, &mut rng).await.unwrap();
    let verdict = server
        .submit_response(&proof_response(issued.challenge), NOW + 1)
        .await
        .unwrap();
    assert_eq!(
        verdict.status,
        Ggbp1TestVerdictStatus::CryptographicallyValidChainUnverified
    );
    assert!(!verdict.authorized);
    assert_eq!(
        verdict.chain_evidence,
        Some(Ggbp1EvidenceSource::UntrustedBaseNodeRpc)
    );
}

#[tokio::test]
async fn no_chain_view_is_explicitly_unverified() {
    let server = server(Ggbp1ChainPolicy::esmeralda_authenticated_node(), None);
    let mut rng = rand::rng();
    let issued = server.issue_challenge(request(), NOW, &mut rng).await.unwrap();
    let verdict = server
        .submit_response(&proof_response(issued.challenge), NOW + 1)
        .await
        .unwrap();
    assert_eq!(
        verdict.status,
        Ggbp1TestVerdictStatus::CryptographicallyValidChainUnverified
    );
    assert!(!verdict.authorized);
    assert_eq!(verdict.chain_evidence, None);
}

#[tokio::test]
async fn malformed_and_oversized_responses_are_refused() {
    let server = server(Ggbp1ChainPolicy::synthetic_test_fixture(), Some(chain(Ggbp1EvidenceSource::SyntheticFixture)));
    assert!(matches!(
        server.submit_response(b"not a ggbp1 response", NOW).await.unwrap_err(),
        Ggbp1ServerError::Proof(_)
    ));
    let oversized = vec![0u8; 20_000];
    assert!(matches!(
        server.submit_response(&oversized, NOW).await.unwrap_err(),
        Ggbp1ServerError::ResponseTooLarge
    ));
}
