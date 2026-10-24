//! Synthetic-only GGBP-1 cryptographic feasibility spike.
//!
//! This module is intentionally behind `experimental-ggbp1`. It constructs no transaction,
//! opens no wallet, reads no chain data, and has no authorization integration. Its output model is
//! a deterministic fixture shape for the standard `PushPubKey` Tari script only; it is not a
//! `TransactionOutput` and cannot establish that a real UTXO is confirmed or unspent.

use tari_crypto::{
    commitment::{ExtensionDegree, HomomorphicCommitmentFactory},
    compressed_key::CompressedKey,
    extended_range_proof::ExtendedRangeProofService,
    hash_domain,
    keys::PublicKey,
    ristretto::{
        RistrettoPublicKey, RistrettoSchnorrWithDomain, RistrettoSecretKey,
        bulletproofs_plus::{
            BulletproofsPlusService, RistrettoAggregatedPublicStatement, RistrettoExtendedMask,
            RistrettoExtendedWitness, RistrettoStatement,
        },
        pedersen::{
            PedersenCommitment, extended_commitment_factory::ExtendedPedersenCommitmentFactory,
        },
    },
};
use tari_script::{TariScript, push_pubkey_script};
use thiserror::Error;

// This is deliberately distinct from the native Tari `CheckSigHashDomain` used for scripts.
hash_domain!(
    Ggbp1BalanceProofDomain,
    "com.ghost-gate.ggbp1.balance_proof",
    1
);

/// GGBP-1 uses Tari's Ristretto Schnorr implementation with a proof-only domain.
pub type Ggbp1AuthoritySignature = RistrettoSchnorrWithDomain<Ggbp1BalanceProofDomain>;

pub const GGBP1_EXPERIMENTAL_VERSION: u8 = 1;
pub const GGBP1_MAX_OUTPUTS: usize = 16;

/// Fixed-width, canonical challenge fields for the experimental fixture format.
///
/// Real deployments need a separately reviewed request encoding and authoritative chain view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ggbp1Challenge {
    pub network: u8,
    pub genesis_hash: [u8; 32],
    pub origin_hash: [u8; 32],
    pub gate_id: [u8; 16],
    pub subject_id: [u8; 16],
    pub threshold_micro_xtm: u64,
    pub nonce: [u8; 32],
    pub expires_at_unix_seconds: u64,
}

impl Ggbp1Challenge {
    fn canonical_message(&self, output_hashes: &[[u8; 32]]) -> Result<Vec<u8>, Ggbp1Error> {
        validate_output_hashes(output_hashes)?;

        let mut message =
            Vec::with_capacity(1 + 32 + 32 + 16 + 16 + 8 + 32 + 8 + 1 + output_hashes.len() * 32);
        message.extend_from_slice(b"GGBP1");
        message.push(GGBP1_EXPERIMENTAL_VERSION);
        message.push(self.network);
        message.extend_from_slice(&self.genesis_hash);
        message.extend_from_slice(&self.origin_hash);
        message.extend_from_slice(&self.gate_id);
        message.extend_from_slice(&self.subject_id);
        message.extend_from_slice(&self.threshold_micro_xtm.to_le_bytes());
        message.extend_from_slice(&self.nonce);
        message.extend_from_slice(&self.expires_at_unix_seconds.to_le_bytes());
        message.push(output_hashes.len() as u8);
        for output_hash in output_hashes {
            message.extend_from_slice(output_hash);
        }
        Ok(message)
    }
}

/// Public fixture data shaped like a standard Tari `PushPubKey` output.
///
/// `output_hash` is a synthetic fixture identifier, not a base-node observation.
#[derive(Clone, Debug)]
pub struct SyntheticStandardOutput {
    pub output_hash: [u8; 32],
    pub commitment: PedersenCommitment,
    pub script: TariScript,
    pub script_public_key: RistrettoPublicKey,
}

/// Process-local synthetic witness material. It is never placed in [`Ggbp1Proof`].
#[derive(Clone)]
pub struct SyntheticOutputWitness {
    pub public: SyntheticStandardOutput,
    mask: RistrettoSecretKey,
    script_secret_key: RistrettoSecretKey,
    value_micro_xtm: u64,
}

impl SyntheticOutputWitness {
    /// Builds only an in-memory synthetic standard-script output fixture.
    pub fn new(
        output_hash: [u8; 32],
        value_micro_xtm: u64,
        mask: RistrettoSecretKey,
        script_secret_key: RistrettoSecretKey,
    ) -> Self {
        let commitment_factory = ExtendedPedersenCommitmentFactory::default();
        let commitment = commitment_factory.commit_value(&mask, value_micro_xtm);
        let script_public_key = RistrettoPublicKey::from_secret_key(&script_secret_key);
        let script = push_pubkey_script(&CompressedKey::new_from_pk(script_public_key.clone()));
        Self {
            public: SyntheticStandardOutput {
                output_hash,
                commitment,
                script,
                script_public_key,
            },
            mask,
            script_secret_key,
            value_micro_xtm,
        }
    }
}

/// Public output proof material. The verifier receives no masks, values, or script private keys.
#[derive(Clone, Debug)]
pub struct Ggbp1Proof {
    pub outputs: Vec<SyntheticStandardOutput>,
    pub authority_signatures: Vec<Ggbp1AuthoritySignature>,
    pub aggregate_commitment: PedersenCommitment,
    pub aggregate_minimum_proof: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Ggbp1Error {
    #[error("at least one output is required")]
    EmptyOutputs,
    #[error("too many outputs")]
    TooManyOutputs,
    #[error("output hashes must be strictly ascending and unique")]
    NonCanonicalOutputHashes,
    #[error("aggregate amount overflow")]
    AggregateOverflow,
    #[error("aggregate value is below the requested threshold")]
    BelowThreshold,
    #[error("output script is not the exact supported PushPubKey script")]
    UnsupportedScript,
    #[error("authority signature count does not match the output count")]
    SignatureCount,
    #[error("a proof signature does not establish authority for its standard script key")]
    InvalidAuthoritySignature,
    #[error("proof aggregate commitment does not equal the sum of public commitments")]
    AggregateCommitmentMismatch,
    #[error("Bulletproofs+ minimum proof rejected: {0}")]
    InvalidMinimumProof(String),
}

/// Produces a synthetic, non-transactional proof from local test witnesses.
pub fn prove_synthetic<R: rand::Rng + rand::CryptoRng>(
    challenge: &Ggbp1Challenge,
    outputs: &[SyntheticOutputWitness],
    rng: &mut R,
) -> Result<Ggbp1Proof, Ggbp1Error> {
    let output_hashes = outputs
        .iter()
        .map(|output| output.public.output_hash)
        .collect::<Vec<_>>();
    let message = challenge.canonical_message(&output_hashes)?;

    let commitment_factory = ExtendedPedersenCommitmentFactory::default();
    let mut aggregate_commitment = commitment_factory.zero();
    let mut aggregate_mask = RistrettoSecretKey::default();
    let mut aggregate_value = 0u64;
    let mut authority_signatures = Vec::with_capacity(outputs.len());

    for output in outputs {
        check_standard_script(&output.public)?;
        aggregate_value = aggregate_value
            .checked_add(output.value_micro_xtm)
            .ok_or(Ggbp1Error::AggregateOverflow)?;
        aggregate_commitment = &aggregate_commitment + &output.public.commitment;
        aggregate_mask = &aggregate_mask + &output.mask;
        authority_signatures.push(
            Ggbp1AuthoritySignature::sign(&output.script_secret_key, &message, rng)
                .expect("Ristretto Schnorr signing with a synthetic key is infallible"),
        );
    }

    if aggregate_value < challenge.threshold_micro_xtm {
        return Err(Ggbp1Error::BelowThreshold);
    }
    if !commitment_factory.open_value(&aggregate_mask, aggregate_value, &aggregate_commitment) {
        return Err(Ggbp1Error::AggregateCommitmentMismatch);
    }

    let range_proof_service = BulletproofsPlusService::init(64, 1, commitment_factory)
        .map_err(|error| Ggbp1Error::InvalidMinimumProof(error.to_string()))?;
    let aggregate_mask =
        RistrettoExtendedMask::assign(ExtensionDegree::DefaultPedersen, vec![aggregate_mask])
            .map_err(|error| Ggbp1Error::InvalidMinimumProof(error.to_string()))?;
    let witness = RistrettoExtendedWitness::new(
        aggregate_mask,
        aggregate_value,
        challenge.threshold_micro_xtm,
    );
    let aggregate_minimum_proof = range_proof_service
        .construct_extended_proof(vec![witness], None)
        .map_err(|error| Ggbp1Error::InvalidMinimumProof(error.to_string()))?;

    Ok(Ggbp1Proof {
        outputs: outputs.iter().map(|output| output.public.clone()).collect(),
        authority_signatures,
        aggregate_commitment,
        aggregate_minimum_proof,
    })
}

/// Independent public verifier for the synthetic fixture format.
pub fn verify_synthetic(challenge: &Ggbp1Challenge, proof: &Ggbp1Proof) -> Result<(), Ggbp1Error> {
    let output_hashes = proof
        .outputs
        .iter()
        .map(|output| output.output_hash)
        .collect::<Vec<_>>();
    let message = challenge.canonical_message(&output_hashes)?;
    if proof.authority_signatures.len() != proof.outputs.len() {
        return Err(Ggbp1Error::SignatureCount);
    }

    let commitment_factory = ExtendedPedersenCommitmentFactory::default();
    let mut aggregate_commitment = commitment_factory.zero();
    for (output, signature) in proof.outputs.iter().zip(&proof.authority_signatures) {
        check_standard_script(output)?;
        if !signature.verify(&output.script_public_key, &message) {
            return Err(Ggbp1Error::InvalidAuthoritySignature);
        }
        aggregate_commitment = &aggregate_commitment + &output.commitment;
    }
    if aggregate_commitment != proof.aggregate_commitment {
        return Err(Ggbp1Error::AggregateCommitmentMismatch);
    }

    let range_proof_service = BulletproofsPlusService::init(64, 1, commitment_factory)
        .map_err(|error| Ggbp1Error::InvalidMinimumProof(error.to_string()))?;
    let statement = RistrettoAggregatedPublicStatement::init(vec![RistrettoStatement {
        commitment: proof.aggregate_commitment.clone(),
        minimum_value_promise: challenge.threshold_micro_xtm,
    }])
    .map_err(|error| Ggbp1Error::InvalidMinimumProof(error.to_string()))?;
    range_proof_service
        .verify_batch(vec![&proof.aggregate_minimum_proof], vec![&statement])
        .map_err(|error| Ggbp1Error::InvalidMinimumProof(error.to_string()))
}

fn validate_output_hashes(output_hashes: &[[u8; 32]]) -> Result<(), Ggbp1Error> {
    if output_hashes.is_empty() {
        return Err(Ggbp1Error::EmptyOutputs);
    }
    if output_hashes.len() > GGBP1_MAX_OUTPUTS {
        return Err(Ggbp1Error::TooManyOutputs);
    }
    if output_hashes.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(Ggbp1Error::NonCanonicalOutputHashes);
    }
    Ok(())
}

fn check_standard_script(output: &SyntheticStandardOutput) -> Result<(), Ggbp1Error> {
    let expected = push_pubkey_script(&CompressedKey::new_from_pk(
        output.script_public_key.clone(),
    ));
    if output.script != expected {
        return Err(Ggbp1Error::UnsupportedScript);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rand::{SeedableRng, rngs::StdRng};
    use tari_script::CheckSigSchnorrSignature;

    use super::*;

    fn key(n: u64) -> RistrettoSecretKey {
        RistrettoSecretKey::from(n)
    }

    fn challenge(threshold_micro_xtm: u64) -> Ggbp1Challenge {
        Ggbp1Challenge {
            network: 42,
            genesis_hash: [1; 32],
            origin_hash: [2; 32],
            gate_id: [3; 16],
            subject_id: [4; 16],
            threshold_micro_xtm,
            nonce: [5; 32],
            expires_at_unix_seconds: 1_800_000_000,
        }
    }

    fn output(id: u8, value: u64, mask: u64, script_key: u64) -> SyntheticOutputWitness {
        SyntheticOutputWitness::new([id; 32], value, key(mask), key(script_key))
    }

    #[test]
    fn single_output_is_proved_only_at_or_above_the_threshold() {
        let below = output(1, 99, 11, 21);
        let equal = output(1, 100, 12, 22);
        let above = output(1, 101, 13, 23);
        let mut rng = StdRng::from_seed([7; 32]);

        assert_eq!(
            prove_synthetic(&challenge(100), &[below], &mut rng).unwrap_err(),
            Ggbp1Error::BelowThreshold
        );

        let equal_proof = prove_synthetic(&challenge(100), &[equal], &mut rng).unwrap();
        verify_synthetic(&challenge(100), &equal_proof).unwrap();

        let above_proof = prove_synthetic(&challenge(100), &[above], &mut rng).unwrap();
        verify_synthetic(&challenge(100), &above_proof).unwrap();
    }

    #[test]
    fn aggregate_proof_is_verified_against_the_sum_of_public_commitments() {
        let first = output(1, 45, 11, 21);
        let second = output(2, 55, 12, 22);
        let witnesses = [first, second];
        let mut rng = StdRng::from_seed([8; 32]);
        let proof = prove_synthetic(&challenge(100), &witnesses, &mut rng).unwrap();

        verify_synthetic(&challenge(100), &proof).unwrap();
        assert_eq!(
            verify_synthetic(&challenge(101), &proof).unwrap_err(),
            Ggbp1Error::InvalidAuthoritySignature
        );

        let mut threshold_substitution = proof.clone();
        let substituted_challenge = challenge(101);
        let substituted_message = substituted_challenge
            .canonical_message(&[[1; 32], [2; 32]])
            .unwrap();
        threshold_substitution.authority_signatures = vec![
            Ggbp1AuthoritySignature::sign(
                &witnesses[0].script_secret_key,
                &substituted_message,
                &mut rng,
            )
            .unwrap(),
            Ggbp1AuthoritySignature::sign(
                &witnesses[1].script_secret_key,
                &substituted_message,
                &mut rng,
            )
            .unwrap(),
        ];
        assert!(matches!(
            verify_synthetic(&substituted_challenge, &threshold_substitution),
            Err(Ggbp1Error::InvalidMinimumProof(_))
        ));
    }

    #[test]
    fn verifier_rejects_tampering_and_noncanonical_inputs() {
        let first = output(1, 45, 11, 21);
        let second = output(2, 55, 12, 22);
        let mut rng = StdRng::from_seed([9; 32]);
        let challenge = challenge(100);
        let proof = prove_synthetic(&challenge, &[first, second], &mut rng).unwrap();

        let mut invalid_opening = output(1, 100, 11, 21);
        invalid_opening.mask = key(98);
        assert_eq!(
            prove_synthetic(&challenge, &[invalid_opening], &mut rng).unwrap_err(),
            Ggbp1Error::AggregateCommitmentMismatch
        );

        let mut wrong_signature = proof.clone();
        let message = challenge.canonical_message(&[[1; 32], [2; 32]]).unwrap();
        wrong_signature.authority_signatures[0] =
            Ggbp1AuthoritySignature::sign(&key(99), &message, &mut rng).unwrap();
        assert_eq!(
            verify_synthetic(&challenge, &wrong_signature).unwrap_err(),
            Ggbp1Error::InvalidAuthoritySignature
        );

        let mut wrong_commitment = proof.clone();
        wrong_commitment.outputs[0].commitment =
            ExtendedPedersenCommitmentFactory::default().commit_value(&key(99), 45);
        assert_eq!(
            verify_synthetic(&challenge, &wrong_commitment).unwrap_err(),
            Ggbp1Error::AggregateCommitmentMismatch
        );

        let mut wrong_script = proof.clone();
        wrong_script.outputs[0].script = TariScript::default();
        assert_eq!(
            verify_synthetic(&challenge, &wrong_script).unwrap_err(),
            Ggbp1Error::UnsupportedScript
        );

        let mut duplicate = proof.clone();
        duplicate.outputs[1].output_hash = duplicate.outputs[0].output_hash;
        assert_eq!(
            verify_synthetic(&challenge, &duplicate).unwrap_err(),
            Ggbp1Error::NonCanonicalOutputHashes
        );

        let mut malformed_range_proof = proof;
        malformed_range_proof.aggregate_minimum_proof.pop();
        assert!(matches!(
            verify_synthetic(&challenge, &malformed_range_proof),
            Err(Ggbp1Error::InvalidMinimumProof(_))
        ));
    }

    #[test]
    fn overflow_and_cross_domain_signature_use_are_rejected() {
        let largest = output(1, u64::MAX, 11, 21);
        let one = output(2, 1, 12, 22);
        let mut rng = StdRng::from_seed([10; 32]);
        assert_eq!(
            prove_synthetic(&challenge(1), &[largest, one], &mut rng).unwrap_err(),
            Ggbp1Error::AggregateOverflow
        );

        let secret = key(21);
        let public = RistrettoPublicKey::from_secret_key(&secret);
        let message = b"synthetic GGBP-1 domain-separation fixture";
        let proof_signature = Ggbp1AuthoritySignature::sign(&secret, message, &mut rng).unwrap();
        let script_signature = CheckSigSchnorrSignature::new(
            proof_signature.get_public_nonce().clone(),
            proof_signature.get_signature().clone(),
        );
        assert!(proof_signature.verify(&public, message));
        assert!(!script_signature.verify(&public, message));
    }
}
