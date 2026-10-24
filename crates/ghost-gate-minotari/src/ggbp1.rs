//! Synthetic-only GGBP-1 cryptographic feasibility spike.
//!
//! This module is intentionally behind `experimental-ggbp1`. It constructs no transaction,
//! opens no wallet, reads no chain data, and has no authorization integration. Its output model is
//! a deterministic fixture shape for the standard `PushPubKey` Tari script only; it is not a
//! `TransactionOutput` and cannot establish that a real UTXO is confirmed or unspent.

use sha2::{Digest, Sha256};
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
use tari_utilities::ByteArray;
use thiserror::Error;

// This is deliberately distinct from the native Tari `CheckSigHashDomain` used for scripts.
hash_domain!(
    Ggbp1BalanceProofDomain,
    "com.ghost-gate.ggbp1.balance_proof",
    1
);

/// GGBP-1 uses Tari's Ristretto Schnorr implementation with a proof-only domain.
pub type Ggbp1AuthoritySignature = RistrettoSchnorrWithDomain<Ggbp1BalanceProofDomain>;

// A subject must authenticate its binding separately from each output authority. This is not a Tari
// transaction or script-signing domain.
hash_domain!(
    Ggbp1SubjectBindingDomain,
    "com.ghost-gate.ggbp1.subject_binding",
    1
);

pub type Ggbp1SubjectSignature = RistrettoSchnorrWithDomain<Ggbp1SubjectBindingDomain>;

/// Version 2 binds every public output record to the authority and subject signatures.
///
/// Version 1 bound only the ordered output hashes. It is deliberately not accepted because an
/// aggregate-preserving replacement of individual commitments was possible without changing the
/// aggregate Bulletproofs+ statement.
pub const GGBP1_EXPERIMENTAL_VERSION: u8 = 2;
pub const GGBP1_MAX_OUTPUTS: usize = 16;
pub const GGBP1_MAX_PROOF_BYTES: usize = 8 * 1024;
pub const GGBP1_STANDARD_SCRIPT_BYTES: usize = 33;
const GGBP1_WIRE_MAGIC: &[u8; 6] = b"GGBP1R";

/// Fixed-width, canonical challenge fields for the experimental fixture format.
///
/// Real deployments need a separately reviewed request encoding and authoritative chain view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ggbp1Challenge {
    pub network: u8,
    pub genesis_hash: [u8; 32],
    pub origin_hash: [u8; 32],
    pub gate_id: [u8; 16],
    pub gate_configuration_version: u64,
    pub subject_id: [u8; 16],
    pub subject_authentication_public_key: RistrettoPublicKey,
    pub threshold_micro_xtm: u64,
    pub nonce: [u8; 32],
    pub expires_at_unix_seconds: u64,
    /// A hash of the concrete generators selected by Tari's default commitment factory.
    pub commitment_generator_fingerprint: [u8; 32],
}

impl Ggbp1Challenge {
    pub fn canonical_message(&self, output_hashes: &[[u8; 32]]) -> Result<Vec<u8>, Ggbp1Error> {
        validate_challenge(self)?;
        validate_output_hashes(output_hashes)?;

        let mut message = Vec::with_capacity(
            1 + 32 + 32 + 16 + 8 + 16 + 32 + 8 + 32 + 8 + 32 + 1 + output_hashes.len() * 32,
        );
        message.extend_from_slice(b"GGBP1");
        message.push(GGBP1_EXPERIMENTAL_VERSION);
        message.push(self.network);
        message.extend_from_slice(&self.genesis_hash);
        message.extend_from_slice(&self.origin_hash);
        message.extend_from_slice(&self.gate_id);
        message.extend_from_slice(&self.gate_configuration_version.to_le_bytes());
        message.extend_from_slice(&self.subject_id);
        message.extend_from_slice(self.subject_authentication_public_key.as_bytes());
        message.extend_from_slice(&self.threshold_micro_xtm.to_le_bytes());
        message.extend_from_slice(&self.nonce);
        message.extend_from_slice(&self.expires_at_unix_seconds.to_le_bytes());
        message.extend_from_slice(&self.commitment_generator_fingerprint);
        message.push(output_hashes.len() as u8);
        for output_hash in output_hashes {
            message.extend_from_slice(output_hash);
        }
        Ok(message)
    }
}

/// Computes a compatibility value from the actual default Tari Pedersen generators. A response
/// carrying a different value is rejected before any commitment arithmetic is trusted.
pub fn expected_commitment_generator_fingerprint() -> [u8; 32] {
    let factory = ExtendedPedersenCommitmentFactory::default();
    let masking_generator = factory.commit_value(&RistrettoSecretKey::from(1u64), 0);
    let value_generator = factory.commit_value(&RistrettoSecretKey::default(), 1);
    let mut hasher = Sha256::new();
    hasher.update(b"GGBP1 tari default extended Pedersen generators v1");
    hasher.update(masking_generator.as_bytes());
    hasher.update(value_generator.as_bytes());
    hasher.finalize().into()
}

/// A synthetic-only authenticated subject. Its secret never appears in a proof response.
#[derive(Clone)]
pub struct SyntheticSubjectWitness {
    secret_key: RistrettoSecretKey,
}

impl SyntheticSubjectWitness {
    pub fn new(secret_key: RistrettoSecretKey) -> Self {
        Self { secret_key }
    }

    pub fn public_key(&self) -> RistrettoPublicKey {
        RistrettoPublicKey::from_secret_key(&self.secret_key)
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

    /// Available only to the experimental wallet-core adapter while it selects synthetic
    /// fixtures. This is deliberately crate-private: proof callers never receive a value,
    /// mask, script key, seed, or a generic signing capability.
    #[allow(dead_code)] // Used only by the feature-disabled wallet-core fixture contract.
    pub(crate) fn value_for_wallet_selection(&self) -> u64 {
        self.value_micro_xtm
    }

    /// Checks the only script shape supported by this experiment without exposing any signing
    /// primitive to the adapter.
    pub(crate) fn is_supported_standard_output(&self) -> bool {
        check_standard_script(&self.public).is_ok()
    }

    /// Verifies that the wallet-held opening still matches the public commitment. The adapter uses
    /// this only as an internal consistency check; it never receives the opening material.
    pub(crate) fn opening_matches_public_commitment(&self) -> bool {
        ExtendedPedersenCommitmentFactory::default().open_value(
            &self.mask,
            self.value_micro_xtm,
            &self.public.commitment,
        )
    }

    #[cfg(test)]
    pub(crate) fn corrupt_mask_for_fixture_test(&mut self, replacement: RistrettoSecretKey) {
        self.mask = replacement;
    }
}

/// Public output proof material. The verifier receives no masks, values, or script private keys.
#[derive(Clone, Debug)]
pub struct Ggbp1Proof {
    pub outputs: Vec<SyntheticStandardOutput>,
    pub authority_signatures: Vec<Ggbp1AuthoritySignature>,
    pub subject_signature: Ggbp1SubjectSignature,
    pub aggregate_commitment: PedersenCommitment,
    pub aggregate_minimum_proof: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Ggbp1Error {
    #[error("a GGBP-1 threshold must be nonzero")]
    ZeroThreshold,
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
    #[error("the commitment-generator fingerprint is not supported by this Tari build")]
    CommitmentGeneratorMismatch,
    #[error("a proof signature does not establish authority for its standard script key")]
    InvalidAuthoritySignature,
    #[error("the subject signature does not authenticate the challenge binding")]
    InvalidSubjectSignature,
    #[error("proof aggregate commitment does not equal the sum of public commitments")]
    AggregateCommitmentMismatch,
    #[error("proof material exceeds its bounded experimental encoding")]
    ProofTooLarge,
    #[error("unsupported GGBP-1 proof encoding version")]
    UnsupportedWireVersion,
    #[error("proof material is not a canonical GGBP-1 response")]
    MalformedWire,
    #[error("Bulletproofs+ minimum proof rejected: {0}")]
    InvalidMinimumProof(String),
}

/// Produces a synthetic, non-transactional proof from local test witnesses.
pub fn prove_synthetic<R: rand::Rng + rand::CryptoRng>(
    challenge: &Ggbp1Challenge,
    subject: &SyntheticSubjectWitness,
    outputs: &[SyntheticOutputWitness],
    rng: &mut R,
) -> Result<Ggbp1Proof, Ggbp1Error> {
    validate_challenge(challenge)?;
    check_generator_compatibility(challenge)?;
    if subject.public_key() != challenge.subject_authentication_public_key {
        return Err(Ggbp1Error::InvalidSubjectSignature);
    }
    let public_outputs = outputs
        .iter()
        .map(|output| output.public.clone())
        .collect::<Vec<_>>();
    let transcript = canonical_output_transcript(challenge, &public_outputs)?;

    let commitment_factory = ExtendedPedersenCommitmentFactory::default();
    let mut aggregate_commitment = commitment_factory.zero();
    let mut aggregate_mask = RistrettoSecretKey::default();
    let mut aggregate_value = 0u64;
    let mut authority_signatures = Vec::with_capacity(outputs.len());

    for (index, output) in outputs.iter().enumerate() {
        check_standard_script(&output.public)?;
        aggregate_value = aggregate_value
            .checked_add(output.value_micro_xtm)
            .ok_or(Ggbp1Error::AggregateOverflow)?;
        aggregate_commitment = &aggregate_commitment + &output.public.commitment;
        aggregate_mask = &aggregate_mask + &output.mask;
        authority_signatures.push(
            Ggbp1AuthoritySignature::sign(
                &output.script_secret_key,
                &authority_signature_message(&transcript, index)?,
                rng,
            )
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
    if aggregate_minimum_proof.len() > GGBP1_MAX_PROOF_BYTES {
        return Err(Ggbp1Error::ProofTooLarge);
    }

    Ok(Ggbp1Proof {
        outputs: public_outputs,
        authority_signatures,
        subject_signature: Ggbp1SubjectSignature::sign(
            &subject.secret_key,
            &subject_signature_message(&transcript),
            rng,
        )
        .expect("Ristretto Schnorr signing with a synthetic key is infallible"),
        aggregate_commitment,
        aggregate_minimum_proof,
    })
}

/// Independent public verifier for the synthetic fixture format.
pub fn verify_synthetic(challenge: &Ggbp1Challenge, proof: &Ggbp1Proof) -> Result<(), Ggbp1Error> {
    validate_challenge(challenge)?;
    check_generator_compatibility(challenge)?;
    let transcript = canonical_output_transcript(challenge, &proof.outputs)?;
    if proof.authority_signatures.len() != proof.outputs.len() {
        return Err(Ggbp1Error::SignatureCount);
    }
    if proof.aggregate_minimum_proof.len() > GGBP1_MAX_PROOF_BYTES {
        return Err(Ggbp1Error::ProofTooLarge);
    }

    let commitment_factory = ExtendedPedersenCommitmentFactory::default();
    let mut aggregate_commitment = commitment_factory.zero();
    for (index, (output, signature)) in proof
        .outputs
        .iter()
        .zip(&proof.authority_signatures)
        .enumerate()
    {
        check_standard_script(output)?;
        if !signature.verify(
            &output.script_public_key,
            &authority_signature_message(&transcript, index)?,
        ) {
            return Err(Ggbp1Error::InvalidAuthoritySignature);
        }
        aggregate_commitment = &aggregate_commitment + &output.commitment;
    }
    if !proof.subject_signature.verify(
        &challenge.subject_authentication_public_key,
        &subject_signature_message(&transcript),
    ) {
        return Err(Ggbp1Error::InvalidSubjectSignature);
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

fn check_generator_compatibility(challenge: &Ggbp1Challenge) -> Result<(), Ggbp1Error> {
    if challenge.commitment_generator_fingerprint != expected_commitment_generator_fingerprint() {
        return Err(Ggbp1Error::CommitmentGeneratorMismatch);
    }
    Ok(())
}

fn validate_challenge(challenge: &Ggbp1Challenge) -> Result<(), Ggbp1Error> {
    if challenge.threshold_micro_xtm == 0 {
        return Err(Ggbp1Error::ZeroThreshold);
    }
    Ok(())
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

/// Returns the exact, bounded public-output transcript signed by this experimental protocol.
///
/// The synthetic fixture carries precisely four immutable public output fields: its identifier,
/// commitment, canonical standard-script bytes, and script public key. Every one is serialized in
/// output-hash order. A future trusted chain resolver must compare its resolved output data to
/// these signed fields exactly; it must not treat the aggregate commitment as a replacement for an
/// individual commitment.
fn canonical_output_transcript(
    challenge: &Ggbp1Challenge,
    outputs: &[SyntheticStandardOutput],
) -> Result<Vec<u8>, Ggbp1Error> {
    let output_hashes = outputs
        .iter()
        .map(|output| output.output_hash)
        .collect::<Vec<_>>();
    let challenge_message = challenge.canonical_message(&output_hashes)?;
    let mut transcript = Vec::with_capacity(
        b"GGBP1/output-transcript".len()
            + challenge_message.len()
            + 1
            + outputs.len() * (1 + 32 + 32 + GGBP1_STANDARD_SCRIPT_BYTES + 32),
    );
    transcript.extend_from_slice(b"GGBP1/output-transcript");
    transcript.extend_from_slice(&challenge_message);
    transcript.push(outputs.len() as u8);

    for (index, output) in outputs.iter().enumerate() {
        check_standard_script(output)?;
        let script = output.script.to_bytes();
        if script.len() != GGBP1_STANDARD_SCRIPT_BYTES {
            return Err(Ggbp1Error::UnsupportedScript);
        }
        transcript.push(index as u8);
        transcript.extend_from_slice(&output.output_hash);
        transcript.extend_from_slice(output.commitment.as_bytes());
        transcript.extend_from_slice(&script);
        transcript.extend_from_slice(output.script_public_key.as_bytes());
    }
    Ok(transcript)
}

/// Makes the authority signature specific to one index in the already canonical output table.
/// The GGBP-1 Schnorr domain itself remains dedicated and distinct from Tari script signing.
fn authority_signature_message(transcript: &[u8], index: usize) -> Result<Vec<u8>, Ggbp1Error> {
    let index = u8::try_from(index).map_err(|_| Ggbp1Error::TooManyOutputs)?;
    let mut message = Vec::with_capacity(b"GGBP1/output-authority".len() + 1 + transcript.len());
    message.extend_from_slice(b"GGBP1/output-authority");
    message.push(index);
    message.extend_from_slice(transcript);
    Ok(message)
}

/// Binds the authenticated subject to the same complete output table as the authority signatures.
fn subject_signature_message(transcript: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(b"GGBP1/subject-binding".len() + transcript.len());
    message.extend_from_slice(b"GGBP1/subject-binding");
    message.extend_from_slice(transcript);
    message
}

/// The versioned, bounded public response encoding. It includes every challenge field so that a
/// receiving server can compare it to its server-held challenge before it verifies crypto.
#[derive(Clone, Debug)]
pub struct Ggbp1WireProof {
    pub challenge: Ggbp1Challenge,
    pub proof: Ggbp1Proof,
}

impl Ggbp1WireProof {
    /// Serializes exactly one canonical proof response. The fixed-size supported script encoding
    /// prevents alternative script encodings or attacker-selected length fields.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Ggbp1Error> {
        validate_challenge(&self.challenge)?;
        check_generator_compatibility(&self.challenge)?;
        // Use the same canonical record validator that verifier-side transcript reconstruction
        // uses. Serialization must not admit an alternate public-output representation.
        canonical_output_transcript(&self.challenge, &self.proof.outputs)?;
        if self.proof.authority_signatures.len() != self.proof.outputs.len() {
            return Err(Ggbp1Error::SignatureCount);
        }
        if self.proof.aggregate_minimum_proof.len() > GGBP1_MAX_PROOF_BYTES {
            return Err(Ggbp1Error::ProofTooLarge);
        }
        let proof_len = u16::try_from(self.proof.aggregate_minimum_proof.len())
            .map_err(|_| Ggbp1Error::ProofTooLarge)?;

        let mut bytes = Vec::with_capacity(
            6 + 1
                + 1
                + 32
                + 32
                + 32
                + 16
                + 8
                + 16
                + 32
                + 8
                + 32
                + 8
                + 32
                + 1
                + self.proof.outputs.len() * (32 + 32 + GGBP1_STANDARD_SCRIPT_BYTES + 32 + 64)
                + 64
                + 32
                + 2
                + self.proof.aggregate_minimum_proof.len(),
        );
        bytes.extend_from_slice(GGBP1_WIRE_MAGIC);
        bytes.push(GGBP1_EXPERIMENTAL_VERSION);
        append_challenge(&mut bytes, &self.challenge);
        bytes.push(self.proof.outputs.len() as u8);

        for (output, signature) in self
            .proof
            .outputs
            .iter()
            .zip(&self.proof.authority_signatures)
        {
            check_standard_script(output)?;
            let script = output.script.to_bytes();
            if script.len() != GGBP1_STANDARD_SCRIPT_BYTES {
                return Err(Ggbp1Error::UnsupportedScript);
            }
            bytes.extend_from_slice(&output.output_hash);
            bytes.extend_from_slice(output.commitment.as_bytes());
            bytes.extend_from_slice(&script);
            bytes.extend_from_slice(output.script_public_key.as_bytes());
            append_authority_signature(&mut bytes, signature);
        }
        append_subject_signature(&mut bytes, &self.proof.subject_signature);
        bytes.extend_from_slice(self.proof.aggregate_commitment.as_bytes());
        bytes.extend_from_slice(&proof_len.to_le_bytes());
        bytes.extend_from_slice(&self.proof.aggregate_minimum_proof);
        Ok(bytes)
    }

    /// Parses only the canonical bounded response grammar. This performs no authorization; callers
    /// must compare [`Self::challenge`] to their issued challenge and then call
    /// [`verify_synthetic`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Ggbp1Error> {
        if bytes.len() > maximum_wire_size() {
            return Err(Ggbp1Error::ProofTooLarge);
        }
        let mut reader = WireReader::new(bytes);
        if reader.take_array::<6>()? != *GGBP1_WIRE_MAGIC {
            return Err(Ggbp1Error::MalformedWire);
        }
        if reader.byte()? != GGBP1_EXPERIMENTAL_VERSION {
            return Err(Ggbp1Error::UnsupportedWireVersion);
        }
        let challenge = read_challenge(&mut reader)?;
        validate_challenge(&challenge)?;
        let output_count = usize::from(reader.byte()?);
        if output_count == 0 || output_count > GGBP1_MAX_OUTPUTS {
            return Err(Ggbp1Error::MalformedWire);
        }

        let mut outputs = Vec::with_capacity(output_count);
        let mut authority_signatures = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            let output_hash = reader.take_array::<32>()?;
            let commitment = PedersenCommitment::from_canonical_bytes(&reader.take_array::<32>()?)
                .map_err(|_| Ggbp1Error::MalformedWire)?;
            let script =
                TariScript::from_bytes(&reader.take_array::<GGBP1_STANDARD_SCRIPT_BYTES>()?)
                    .map_err(|_| Ggbp1Error::MalformedWire)?;
            let script_public_key =
                RistrettoPublicKey::from_canonical_bytes(&reader.take_array::<32>()?)
                    .map_err(|_| Ggbp1Error::MalformedWire)?;
            authority_signatures.push(read_authority_signature(&mut reader)?);
            outputs.push(SyntheticStandardOutput {
                output_hash,
                commitment,
                script,
                script_public_key,
            });
        }
        let subject_signature = read_subject_signature(&mut reader)?;
        let aggregate_commitment =
            PedersenCommitment::from_canonical_bytes(&reader.take_array::<32>()?)
                .map_err(|_| Ggbp1Error::MalformedWire)?;
        let proof_len = usize::from(u16::from_le_bytes(reader.take_array::<2>()?));
        if proof_len > GGBP1_MAX_PROOF_BYTES || reader.remaining() != proof_len {
            return Err(Ggbp1Error::MalformedWire);
        }
        let aggregate_minimum_proof = reader.take(proof_len)?.to_vec();
        if reader.remaining() != 0 {
            return Err(Ggbp1Error::MalformedWire);
        }

        let output_hashes = outputs
            .iter()
            .map(|output| output.output_hash)
            .collect::<Vec<_>>();
        validate_output_hashes(&output_hashes)?;
        Ok(Self {
            challenge,
            proof: Ggbp1Proof {
                outputs,
                authority_signatures,
                subject_signature,
                aggregate_commitment,
                aggregate_minimum_proof,
            },
        })
    }
}

fn maximum_wire_size() -> usize {
    6 + 1
        + 1
        + 32
        + 32
        + 32
        + 16
        + 8
        + 16
        + 32
        + 8
        + 32
        + 8
        + 32
        + 1
        + GGBP1_MAX_OUTPUTS * (32 + 32 + GGBP1_STANDARD_SCRIPT_BYTES + 32 + 64)
        + 64
        + 32
        + 2
        + GGBP1_MAX_PROOF_BYTES
}

fn append_challenge(bytes: &mut Vec<u8>, challenge: &Ggbp1Challenge) {
    bytes.push(challenge.network);
    bytes.extend_from_slice(&challenge.genesis_hash);
    bytes.extend_from_slice(&challenge.origin_hash);
    bytes.extend_from_slice(&challenge.gate_id);
    bytes.extend_from_slice(&challenge.gate_configuration_version.to_le_bytes());
    bytes.extend_from_slice(&challenge.subject_id);
    bytes.extend_from_slice(challenge.subject_authentication_public_key.as_bytes());
    bytes.extend_from_slice(&challenge.threshold_micro_xtm.to_le_bytes());
    bytes.extend_from_slice(&challenge.nonce);
    bytes.extend_from_slice(&challenge.expires_at_unix_seconds.to_le_bytes());
    bytes.extend_from_slice(&challenge.commitment_generator_fingerprint);
}

fn read_challenge(reader: &mut WireReader<'_>) -> Result<Ggbp1Challenge, Ggbp1Error> {
    let network = reader.byte()?;
    let genesis_hash = reader.take_array::<32>()?;
    let origin_hash = reader.take_array::<32>()?;
    let gate_id = reader.take_array::<16>()?;
    let gate_configuration_version = u64::from_le_bytes(reader.take_array::<8>()?);
    let subject_id = reader.take_array::<16>()?;
    let subject_authentication_public_key =
        RistrettoPublicKey::from_canonical_bytes(&reader.take_array::<32>()?)
            .map_err(|_| Ggbp1Error::MalformedWire)?;
    let threshold_micro_xtm = u64::from_le_bytes(reader.take_array::<8>()?);
    let nonce = reader.take_array::<32>()?;
    let expires_at_unix_seconds = u64::from_le_bytes(reader.take_array::<8>()?);
    let commitment_generator_fingerprint = reader.take_array::<32>()?;
    Ok(Ggbp1Challenge {
        network,
        genesis_hash,
        origin_hash,
        gate_id,
        gate_configuration_version,
        subject_id,
        subject_authentication_public_key,
        threshold_micro_xtm,
        nonce,
        expires_at_unix_seconds,
        commitment_generator_fingerprint,
    })
}

fn append_authority_signature(bytes: &mut Vec<u8>, signature: &Ggbp1AuthoritySignature) {
    bytes.extend_from_slice(signature.get_public_nonce().as_bytes());
    bytes.extend_from_slice(signature.get_signature().as_bytes());
}

fn append_subject_signature(bytes: &mut Vec<u8>, signature: &Ggbp1SubjectSignature) {
    bytes.extend_from_slice(signature.get_public_nonce().as_bytes());
    bytes.extend_from_slice(signature.get_signature().as_bytes());
}

fn read_authority_signature(
    reader: &mut WireReader<'_>,
) -> Result<Ggbp1AuthoritySignature, Ggbp1Error> {
    let nonce = RistrettoPublicKey::from_canonical_bytes(&reader.take_array::<32>()?)
        .map_err(|_| Ggbp1Error::MalformedWire)?;
    let scalar = RistrettoSecretKey::from_canonical_bytes(&reader.take_array::<32>()?)
        .map_err(|_| Ggbp1Error::MalformedWire)?;
    Ok(Ggbp1AuthoritySignature::new(nonce, scalar))
}

fn read_subject_signature(
    reader: &mut WireReader<'_>,
) -> Result<Ggbp1SubjectSignature, Ggbp1Error> {
    let nonce = RistrettoPublicKey::from_canonical_bytes(&reader.take_array::<32>()?)
        .map_err(|_| Ggbp1Error::MalformedWire)?;
    let scalar = RistrettoSecretKey::from_canonical_bytes(&reader.take_array::<32>()?)
        .map_err(|_| Ggbp1Error::MalformedWire)?;
    Ok(Ggbp1SubjectSignature::new(nonce, scalar))
}

struct WireReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> WireReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.cursor)
    }

    fn byte(&mut self) -> Result<u8, Ggbp1Error> {
        Ok(self.take_array::<1>()?[0])
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], Ggbp1Error> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or(Ggbp1Error::MalformedWire)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(Ggbp1Error::MalformedWire)?;
        self.cursor = end;
        Ok(value)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], Ggbp1Error> {
        let mut value = [0u8; N];
        value.copy_from_slice(self.take(N)?);
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use rand::{SeedableRng, rngs::StdRng};
    use tari_script::CheckSigSchnorrSignature;

    use super::*;

    fn key(n: u64) -> RistrettoSecretKey {
        RistrettoSecretKey::from(n)
    }

    fn subject() -> SyntheticSubjectWitness {
        SyntheticSubjectWitness::new(key(31))
    }

    fn challenge(threshold_micro_xtm: u64) -> Ggbp1Challenge {
        Ggbp1Challenge {
            network: 42,
            genesis_hash: [1; 32],
            origin_hash: [2; 32],
            gate_id: [3; 16],
            gate_configuration_version: 7,
            subject_id: [4; 16],
            subject_authentication_public_key: subject().public_key(),
            threshold_micro_xtm,
            nonce: [5; 32],
            expires_at_unix_seconds: 1_800_000_000,
            commitment_generator_fingerprint: expected_commitment_generator_fingerprint(),
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
        let subject = subject();
        let mut rng = StdRng::from_seed([7; 32]);

        assert_eq!(
            prove_synthetic(&challenge(100), &subject, &[below], &mut rng).unwrap_err(),
            Ggbp1Error::BelowThreshold
        );

        let equal_proof = prove_synthetic(&challenge(100), &subject, &[equal], &mut rng).unwrap();
        verify_synthetic(&challenge(100), &equal_proof).unwrap();

        let above_proof = prove_synthetic(&challenge(100), &subject, &[above], &mut rng).unwrap();
        verify_synthetic(&challenge(100), &above_proof).unwrap();
    }

    #[test]
    fn zero_threshold_is_rejected_by_every_proof_entry_point() {
        let zero = challenge(0);
        let subject = subject();
        let witness = output(1, 1, 11, 21);
        let mut rng = StdRng::from_seed([13; 32]);

        assert_eq!(
            zero.canonical_message(&[[1; 32]]).unwrap_err(),
            Ggbp1Error::ZeroThreshold
        );
        assert_eq!(
            prove_synthetic(&zero, &subject, &[witness], &mut rng).unwrap_err(),
            Ggbp1Error::ZeroThreshold
        );

        let valid_challenge = challenge(1);
        let valid_proof = prove_synthetic(
            &valid_challenge,
            &subject,
            &[output(1, 1, 11, 21)],
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            verify_synthetic(&zero, &valid_proof).unwrap_err(),
            Ggbp1Error::ZeroThreshold
        );
        assert_eq!(
            Ggbp1WireProof {
                challenge: zero,
                proof: valid_proof,
            }
            .to_bytes()
            .unwrap_err(),
            Ggbp1Error::ZeroThreshold
        );

        let mut encoded = Ggbp1WireProof {
            challenge: valid_challenge,
            proof: prove_synthetic(&challenge(1), &subject, &[output(1, 1, 11, 21)], &mut rng)
                .unwrap(),
        }
        .to_bytes()
        .unwrap();
        // `GGBP1R` plus fixed-width header fields place the threshold at byte 144.
        encoded[144..152].fill(0);
        assert_eq!(
            Ggbp1WireProof::from_bytes(&encoded).unwrap_err(),
            Ggbp1Error::ZeroThreshold
        );
    }

    #[test]
    fn aggregate_proof_is_verified_against_the_sum_of_public_commitments() {
        let first = output(1, 45, 11, 21);
        let second = output(2, 55, 12, 22);
        let witnesses = [first, second];
        let subject = subject();
        let mut rng = StdRng::from_seed([8; 32]);
        let proof = prove_synthetic(&challenge(100), &subject, &witnesses, &mut rng).unwrap();

        verify_synthetic(&challenge(100), &proof).unwrap();
        assert_eq!(
            verify_synthetic(&challenge(101), &proof).unwrap_err(),
            Ggbp1Error::InvalidAuthoritySignature
        );

        let mut threshold_substitution = proof.clone();
        let substituted_challenge = challenge(101);
        let substituted_transcript =
            canonical_output_transcript(&substituted_challenge, &threshold_substitution.outputs)
                .unwrap();
        threshold_substitution.authority_signatures = vec![
            Ggbp1AuthoritySignature::sign(
                &witnesses[0].script_secret_key,
                &authority_signature_message(&substituted_transcript, 0).unwrap(),
                &mut rng,
            )
            .unwrap(),
            Ggbp1AuthoritySignature::sign(
                &witnesses[1].script_secret_key,
                &authority_signature_message(&substituted_transcript, 1).unwrap(),
                &mut rng,
            )
            .unwrap(),
        ];
        threshold_substitution.subject_signature = Ggbp1SubjectSignature::sign(
            &subject.secret_key,
            &subject_signature_message(&substituted_transcript),
            &mut rng,
        )
        .unwrap();
        assert!(matches!(
            verify_synthetic(&substituted_challenge, &threshold_substitution),
            Err(Ggbp1Error::InvalidMinimumProof(_))
        ));
    }

    #[test]
    fn verifier_rejects_tampering_and_noncanonical_inputs() {
        let first = output(1, 45, 11, 21);
        let second = output(2, 55, 12, 22);
        let subject = subject();
        let mut rng = StdRng::from_seed([9; 32]);
        let challenge = challenge(100);
        let proof = prove_synthetic(&challenge, &subject, &[first, second], &mut rng).unwrap();

        let mut invalid_opening = output(1, 100, 11, 21);
        invalid_opening.mask = key(98);
        assert_eq!(
            prove_synthetic(&challenge, &subject, &[invalid_opening], &mut rng).unwrap_err(),
            Ggbp1Error::AggregateCommitmentMismatch
        );

        let mut wrong_signature = proof.clone();
        let transcript = canonical_output_transcript(&challenge, &wrong_signature.outputs).unwrap();
        wrong_signature.authority_signatures[0] = Ggbp1AuthoritySignature::sign(
            &key(99),
            &authority_signature_message(&transcript, 0).unwrap(),
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            verify_synthetic(&challenge, &wrong_signature).unwrap_err(),
            Ggbp1Error::InvalidAuthoritySignature
        );

        let mut wrong_commitment = proof.clone();
        wrong_commitment.outputs[0].commitment =
            ExtendedPedersenCommitmentFactory::default().commit_value(&key(99), 45);
        assert_eq!(
            verify_synthetic(&challenge, &wrong_commitment).unwrap_err(),
            Ggbp1Error::InvalidAuthoritySignature
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
    fn aggregate_preserving_per_output_commitment_rewrite_is_rejected() {
        let subject = subject();
        let challenge = challenge(100);
        let mut rng = StdRng::from_seed([91; 32]);
        let mut proof = prove_synthetic(
            &challenge,
            &subject,
            &[output(1, 45, 11, 21), output(2, 55, 12, 22)],
            &mut rng,
        )
        .unwrap();

        // The audit reproduction preserves C1' + C2' = C1 + C2. Version 1 signed only the
        // output hashes, so its aggregate proof remained valid. Version 2 signs the exact
        // canonical public output records, so an unchanged authority signature now rejects it.
        let first_commitment = proof.outputs[0].commitment.clone();
        proof.outputs[0].commitment = &proof.outputs[0].commitment + &first_commitment;
        proof.outputs[1].commitment = &proof.outputs[1].commitment - &first_commitment;

        assert_eq!(
            verify_synthetic(&challenge, &proof).unwrap_err(),
            Ggbp1Error::InvalidAuthoritySignature
        );
    }

    #[test]
    fn output_record_reordering_duplication_and_mismatching_are_rejected() {
        let subject = subject();
        let challenge = challenge(100);
        let mut rng = StdRng::from_seed([92; 32]);
        let proof = prove_synthetic(
            &challenge,
            &subject,
            &[output(1, 45, 11, 21), output(2, 55, 12, 22)],
            &mut rng,
        )
        .unwrap();

        let mut reordered = proof.clone();
        reordered.outputs.swap(0, 1);
        reordered.authority_signatures.swap(0, 1);
        assert_eq!(
            verify_synthetic(&challenge, &reordered).unwrap_err(),
            Ggbp1Error::NonCanonicalOutputHashes
        );

        let mut duplicated = proof.clone();
        duplicated.outputs[1] = duplicated.outputs[0].clone();
        duplicated.authority_signatures[1] = duplicated.authority_signatures[0].clone();
        assert_eq!(
            verify_synthetic(&challenge, &duplicated).unwrap_err(),
            Ggbp1Error::NonCanonicalOutputHashes
        );

        let mut mismatched = proof;
        let replacement_key = key(99);
        let replacement_public_key = RistrettoPublicKey::from_secret_key(&replacement_key);
        mismatched.outputs[0].script_public_key = replacement_public_key.clone();
        mismatched.outputs[0].script =
            push_pubkey_script(&CompressedKey::new_from_pk(replacement_public_key));
        assert_eq!(
            verify_synthetic(&challenge, &mismatched).unwrap_err(),
            Ggbp1Error::InvalidAuthoritySignature
        );
    }

    #[test]
    fn opening_or_observer_knowledge_cannot_replace_output_authority() {
        let subject = subject();
        let challenge = challenge(100);
        let mut rng = StdRng::from_seed([93; 32]);
        let proof =
            prove_synthetic(&challenge, &subject, &[output(1, 100, 11, 21)], &mut rng).unwrap();

        // This fixture has no Tari view-key model. An observer is represented by an unrelated
        // secret, and an attacker with an alternative known commitment opening is represented by
        // this replacement commitment. Neither possesses the output's script authority.
        let mut opening_only_substitution = proof.clone();
        opening_only_substitution.outputs[0].commitment =
            ExtendedPedersenCommitmentFactory::default().commit_value(&key(99), 100);
        let transcript =
            canonical_output_transcript(&challenge, &opening_only_substitution.outputs).unwrap();
        opening_only_substitution.subject_signature = Ggbp1SubjectSignature::sign(
            &subject.secret_key,
            &subject_signature_message(&transcript),
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            verify_synthetic(&challenge, &opening_only_substitution).unwrap_err(),
            Ggbp1Error::InvalidAuthoritySignature
        );

        let mut observer_signature = proof;
        let transcript =
            canonical_output_transcript(&challenge, &observer_signature.outputs).unwrap();
        observer_signature.authority_signatures[0] = Ggbp1AuthoritySignature::sign(
            &key(99),
            &authority_signature_message(&transcript, 0).unwrap(),
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            verify_synthetic(&challenge, &observer_signature).unwrap_err(),
            Ggbp1Error::InvalidAuthoritySignature
        );
    }

    #[test]
    fn overflow_and_cross_domain_signature_use_are_rejected() {
        let largest = output(1, u64::MAX, 11, 21);
        let one = output(2, 1, 12, 22);
        let subject = subject();
        let mut rng = StdRng::from_seed([10; 32]);
        assert_eq!(
            prove_synthetic(&challenge(1), &subject, &[largest, one], &mut rng).unwrap_err(),
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

    #[test]
    fn canonical_wire_response_round_trips_without_witness_material() {
        let subject = subject();
        let challenge = challenge(100);
        let mut rng = StdRng::from_seed([11; 32]);
        let proof = prove_synthetic(
            &challenge,
            &subject,
            &[output(1, 45, 11, 21), output(2, 55, 12, 22)],
            &mut rng,
        )
        .unwrap();

        let encoded = Ggbp1WireProof {
            challenge: challenge.clone(),
            proof,
        }
        .to_bytes()
        .unwrap();
        let decoded = Ggbp1WireProof::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.challenge, challenge);
        verify_synthetic(&decoded.challenge, &decoded.proof).unwrap();

        let mut old_version = encoded.clone();
        old_version[6] = 1;
        assert_eq!(
            Ggbp1WireProof::from_bytes(&old_version).unwrap_err(),
            Ggbp1Error::UnsupportedWireVersion
        );

        let mut trailing_byte = encoded;
        trailing_byte.push(0);
        assert_eq!(
            Ggbp1WireProof::from_bytes(&trailing_byte).unwrap_err(),
            Ggbp1Error::MalformedWire
        );
    }

    #[test]
    fn generator_and_subject_binding_are_not_client_selectable() {
        let subject = subject();
        let mut invalid_generator = challenge(100);
        invalid_generator.commitment_generator_fingerprint = [0; 32];
        let mut rng = StdRng::from_seed([12; 32]);
        assert_eq!(
            prove_synthetic(
                &invalid_generator,
                &subject,
                &[output(1, 100, 11, 21)],
                &mut rng
            )
            .unwrap_err(),
            Ggbp1Error::CommitmentGeneratorMismatch
        );

        let challenge = challenge(100);
        let mut proof =
            prove_synthetic(&challenge, &subject, &[output(1, 100, 11, 21)], &mut rng).unwrap();
        let transcript = canonical_output_transcript(&challenge, &proof.outputs).unwrap();
        proof.subject_signature = Ggbp1SubjectSignature::sign(
            &key(99),
            &subject_signature_message(&transcript),
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            verify_synthetic(&challenge, &proof).unwrap_err(),
            Ggbp1Error::InvalidSubjectSignature
        );
    }
}
