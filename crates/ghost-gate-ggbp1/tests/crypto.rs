//! Regression coverage for the vendored GGBP-1 v3 crypto, including the upstream review vectors.
//!
//! These tests are deliberately independent of the server and chain layers. They pin the exact
//! public behavior the upstream package shipped: threshold enforcement, canonical output records,
//! authority/subject binding, wire framing, and the five review vectors.

use ghost_gate_ggbp1::{
    ESMERALDA_GENESIS_HASH, ESMERALDA_NETWORK, GGBP1_EXPERIMENTAL_VERSION, Ggbp1Error,
    Ggbp1WireProof, SyntheticOutputWitness, SyntheticSubjectWitness, expected_commitment_generator_fingerprint,
    gate_configuration_version, gate_id_bytes, prove_synthetic, verify_synthetic, Ggbp1Challenge,
};
use tari_crypto::{
    commitment::HomomorphicCommitmentFactory,
    keys::PublicKey,
    ristretto::{
        RistrettoPublicKey, RistrettoSecretKey,
        pedersen::extended_commitment_factory::ExtendedPedersenCommitmentFactory,
    },
};
use tari_script::TariScript;

fn subject() -> SyntheticSubjectWitness {
    SyntheticSubjectWitness::new(RistrettoSecretKey::from(31u64))
}

fn challenge(threshold_micro_xtm: u64) -> Ggbp1Challenge {
    Ggbp1Challenge {
        network: ESMERALDA_NETWORK,
        genesis_hash: ESMERALDA_GENESIS_HASH,
        origin_hash: [2u8; 32],
        gate_id: gate_id_bytes("xtmtest"),
        gate_configuration_version: gate_configuration_version("xtmtest", threshold_micro_xtm, ESMERALDA_NETWORK),
        subject_id: [4u8; 16],
        subject_authentication_public_key: subject().public_key(),
        threshold_micro_xtm,
        nonce: [5u8; 32],
        expires_at_unix_seconds: 1_800_000_000,
        commitment_generator_fingerprint: expected_commitment_generator_fingerprint(),
    }
}

fn output(id: u8, value: u64, mask: u64, script_key: u64) -> SyntheticOutputWitness {
    SyntheticOutputWitness::new([id; 32], value, RistrettoSecretKey::from(mask), RistrettoSecretKey::from(script_key))
}

fn decode_vector(hex: &str) -> Ggbp1WireProof {
    let bytes = hex::decode(hex.trim()).expect("review vector hex");
    Ggbp1WireProof::from_bytes(&bytes).expect("review vector wire")
}

#[test]
fn upstream_review_vectors_match_the_vendored_crypto() {
    for (name, vector) in [
        ("exact_threshold", include_str!("vectors/exact_threshold.hex")),
        ("above_threshold", include_str!("vectors/above_threshold.hex")),
        ("multiple_outputs", include_str!("vectors/multiple_outputs.hex")),
        ("valid_output_authority", include_str!("vectors/valid_output_authority.hex")),
    ] {
        let wire = decode_vector(vector);
        verify_synthetic(&wire.challenge, &wire.proof)
            .unwrap_or_else(|error| panic!("{name} should verify: {error}"));
    }
}

#[test]
fn upstream_bp_only_negative_vector_is_rejected() {
    let wire = decode_vector(include_str!("vectors/bp_only_negative.hex"));
    assert!(matches!(
        verify_synthetic(&wire.challenge, &wire.proof),
        Err(Ggbp1Error::InvalidMinimumProof(_))
    ));
}

#[test]
fn threshold_is_enforced_and_zero_is_rejected() {
    let subject = subject();
    let below = output(1, 99, 11, 21);
    let equal = output(1, 100, 12, 22);
    let above = output(1, 101, 13, 23);

    assert!(matches!(
        prove_synthetic(&challenge(100), &subject, &[below]),
        Err(Ggbp1Error::BelowThreshold)
    ));
    let equal_proof = prove_synthetic(&challenge(100), &subject, &[equal.clone()]).unwrap();
    verify_synthetic(&challenge(100), &equal_proof).unwrap();
    let above_proof = prove_synthetic(&challenge(100), &subject, &[above]).unwrap();
    verify_synthetic(&challenge(100), &above_proof).unwrap();

    let zero = challenge(0);
    assert!(matches!(
        prove_synthetic(&zero, &subject, &[equal]),
        Err(Ggbp1Error::ZeroThreshold)
    ));
    assert!(matches!(
        verify_synthetic(&zero, &equal_proof),
        Err(Ggbp1Error::ZeroThreshold)
    ));
}

#[test]
fn aggregate_preserving_commitment_rewrite_is_rejected() {
    let subject = subject();
    let challenge = challenge(100);
    let mut proof = prove_synthetic(
        &challenge,
        &subject,
        &[output(1, 45, 11, 21), output(2, 55, 12, 22)],
    )
    .unwrap();

    // Preserve C1 + C2 while moving value between the two records. The transcript signs each
    // record exactly, so the unchanged authority signatures must reject the rewrite.
    let first = proof.outputs[0].commitment.clone();
    proof.outputs[0].commitment = &proof.outputs[0].commitment + &first;
    proof.outputs[1].commitment = &proof.outputs[1].commitment - &first;
    assert!(matches!(
        verify_synthetic(&challenge, &proof),
        Err(Ggbp1Error::InvalidAuthoritySignature)
    ));
}

#[test]
fn reordering_duplication_and_mismatch_are_rejected() {
    let subject = subject();
    let challenge = challenge(100);
    let proof = prove_synthetic(
        &challenge,
        &subject,
        &[output(1, 45, 11, 21), output(2, 55, 12, 22)],
    )
    .unwrap();

    let mut reordered = proof.clone();
    reordered.outputs.swap(0, 1);
    reordered.authority_signatures.swap(0, 1);
    assert!(matches!(
        verify_synthetic(&challenge, &reordered),
        Err(Ggbp1Error::NonCanonicalOutputHashes)
    ));

    let mut duplicated = proof.clone();
    duplicated.outputs[1] = duplicated.outputs[0].clone();
    duplicated.authority_signatures[1] = duplicated.authority_signatures[0].clone();
    assert!(matches!(
        verify_synthetic(&challenge, &duplicated),
        Err(Ggbp1Error::NonCanonicalOutputHashes)
    ));

    let mut mismatched = proof;
    let replacement = RistrettoPublicKey::from_secret_key(&RistrettoSecretKey::from(99u64));
    mismatched.outputs[0].script_public_key = replacement.clone();
    mismatched.outputs[0].script = tari_script::push_pubkey_script(
        &tari_crypto::compressed_key::CompressedKey::new_from_pk(replacement),
    );
    assert!(matches!(
        verify_synthetic(&challenge, &mismatched),
        Err(Ggbp1Error::InvalidAuthoritySignature)
    ));
}

#[test]
fn opening_or_observer_knowledge_cannot_replace_authority() {
    let subject = subject();
    let challenge = challenge(100);
    let mut proof = prove_synthetic(&challenge, &subject, &[output(1, 100, 11, 21)]).unwrap();
    // A different opening of the same value is not the output's authority. The transcript signs
    // the exact commitment, so the unchanged authority signature must reject the substitution.
    proof.outputs[0].commitment =
        ExtendedPedersenCommitmentFactory::default().commit_value(&RistrettoSecretKey::from(99u64), 100);
    assert!(matches!(
        verify_synthetic(&challenge, &proof),
        Err(Ggbp1Error::InvalidAuthoritySignature)
    ));
}

#[test]
fn overflow_and_cross_domain_signature_use_are_rejected() {
    let subject = subject();
    let largest = output(1, u64::MAX, 11, 21);
    let one = output(2, 1, 12, 22);
    assert!(matches!(
        prove_synthetic(&challenge(1), &subject, &[largest, one]),
        Err(Ggbp1Error::AggregateOverflow)
    ));

    let secret = RistrettoSecretKey::from(21u64);
    let public = RistrettoPublicKey::from_secret_key(&secret);
    let message = b"synthetic GGBP-1 domain-separation fixture";
    let mut rng = rand::rng();
    let proof_signature = ghost_gate_ggbp1::v3::Ggbp1AuthoritySignature::sign(&secret, message, &mut rng).unwrap();
    let script_signature = tari_script::CheckSigSchnorrSignature::new(
        proof_signature.get_public_nonce().clone(),
        proof_signature.get_signature().clone(),
    );
    assert!(proof_signature.verify(&public, message));
    assert!(!script_signature.verify(&public, message));
}

#[test]
fn wire_round_trip_is_canonical_and_truncation_is_refused() {
    let subject = subject();
    let challenge = challenge(100);
    let proof = prove_synthetic(&challenge, &subject, &[output(1, 100, 11, 21)]).unwrap();
    let encoded = Ggbp1WireProof {
        challenge: challenge.clone(),
        proof: proof.clone(),
    }
    .to_bytes()
    .unwrap();
    assert_eq!(encoded[0..6], *b"GGBP1R");
    assert_eq!(encoded[6], GGBP1_EXPERIMENTAL_VERSION);
    let decoded = Ggbp1WireProof::from_bytes(&encoded).unwrap();
    verify_synthetic(&decoded.challenge, &decoded.proof).unwrap();
    assert!(matches!(
        Ggbp1WireProof::from_bytes(&encoded[..encoded.len() - 1]),
        Err(Ggbp1Error::MalformedWire)
    ));
}

#[test]
fn identity_subject_and_unsupported_script_are_rejected() {
    let subject = subject();
    let mut identity = challenge(100);
    identity.subject_authentication_public_key = RistrettoPublicKey::default();
    assert!(matches!(
        prove_synthetic(&identity, &subject, &[output(1, 100, 11, 21)]),
        Err(Ggbp1Error::IdentityPublicKey)
    ));

    let challenge = challenge(100);
    let mut proof = prove_synthetic(&challenge, &subject, &[output(1, 100, 11, 21)]).unwrap();
    proof.outputs[0].script = TariScript::default();
    assert!(matches!(
        verify_synthetic(&challenge, &proof),
        Err(Ggbp1Error::UnsupportedScript)
    ));
}

#[test]
fn wire_rejects_duplicate_hashes() {
    let subject = subject();
    let challenge = challenge(100);
    let mut proof = prove_synthetic(
        &challenge,
        &subject,
        &[output(1, 45, 11, 21), output(2, 55, 12, 22)],
    )
    .unwrap();
    proof.outputs[1].output_hash = proof.outputs[0].output_hash;
    // Re-signing is not required for this assertion: the wire decoder validates the output-hash
    // table before any signature check, so a duplicate is refused as non-canonical.
    let encoded = Ggbp1WireProof { challenge, proof }.to_bytes();
    assert!(matches!(encoded, Err(Ggbp1Error::NonCanonicalOutputHashes)));
}