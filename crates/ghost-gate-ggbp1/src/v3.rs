//! Synthetic-only GGBP1R v3 cryptographic review package.
//!
//! Vendored from the public `GSXRspartan/ggbp1-v3-external-review` package
//! (`ggbp1-v3-review/src/lib.rs`, fetched 2026-11-21). The protocol constants, wire grammar,
//! transcript construction, and verifier are kept byte-for-byte; only the upstream test module
//! (which depends on review-package vectors not shipped here) was removed. A `#[allow(dead_code)]`
//! was added to the test-only entropy helper because its callers lived in that module.
//!
//! This module constructs no transaction, opens no wallet, reads no chain data, and has no
//! authorization integration. Its output model is a fixture shape for the standard `PushPubKey`
//! Tari script only; it is not a `TransactionOutput` and cannot establish that a real UTXO is
//! confirmed or unspent. `ghost-gate-ggbp1::chain` is the separate, explicitly node-asserted
//! evidence layer that a caller must run before treating a response as anything more than
//! cryptographically well-formed.

use rand::{
    SeedableRng, TryRng,
    rngs::{StdRng, SysRng},
};
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
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

#[cfg(test)]
static RANGE_PROOF_VERIFIER_CALLS: AtomicUsize = AtomicUsize::new(0);

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

/// Version 3 binds every public output record *and* the aggregate-minimum-proof hash to authority
/// and subject signatures. Version 2 remains a historical compatibility format only.
pub const GGBP1_EXPERIMENTAL_VERSION: u8 = 3;
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
    #[allow(dead_code)]
    pub(crate) fn is_supported_standard_output(&self) -> bool {
        check_standard_script(&self.public).is_ok()
    }

    /// Verifies that the wallet-held opening still matches the public commitment. The adapter uses
    /// this only as an internal consistency check; it never receives the opening material.
    #[allow(dead_code)]
    pub(crate) fn opening_matches_public_commitment(&self) -> bool {
        ExtendedPedersenCommitmentFactory::default().open_value(
            &self.mask,
            self.value_micro_xtm,
            &self.public.commitment,
        )
    }

    #[cfg(test)]
    #[allow(dead_code)]
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
    #[error("identity public keys are not valid GGBP1R v3 signing keys")]
    IdentityPublicKey,
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
    #[error("the system CSPRNG was unavailable while deriving a signing nonce")]
    SecureRandomnessUnavailable,
}

/// Produces a synthetic, non-transactional proof from local test witnesses.
///
/// All Schnorr nonces are derived inside this function from system CSPRNG entropy, the signing key
/// and the proof-bound signing message. There is deliberately no caller-controlled RNG parameter.
pub fn prove_synthetic(
    challenge: &Ggbp1Challenge,
    subject: &SyntheticSubjectWitness,
    outputs: &[SyntheticOutputWitness],
) -> Result<Ggbp1Proof, Ggbp1Error> {
    validate_challenge(challenge)?;
    check_generator_compatibility(challenge)?;
    // BP+ obtains its own system randomness before signing. Fail before entering it when the
    // CSPRNG is unavailable, rather than allowing the proof constructor to be the first caller.
    ensure_system_entropy_available()?;
    if subject.public_key() != challenge.subject_authentication_public_key {
        return Err(Ggbp1Error::InvalidSubjectSignature);
    }
    let public_outputs = outputs
        .iter()
        .map(|output| output.public.clone())
        .collect::<Vec<_>>();
    let record_transcript = canonical_output_transcript(challenge, &public_outputs)?;

    let commitment_factory = ExtendedPedersenCommitmentFactory::default();
    let mut aggregate_commitment = commitment_factory.zero();
    let mut aggregate_mask = RistrettoSecretKey::default();
    let mut aggregate_value = 0u64;
    for output in outputs {
        check_standard_script(&output.public)?;
        aggregate_value = aggregate_value
            .checked_add(output.value_micro_xtm)
            .ok_or(Ggbp1Error::AggregateOverflow)?;
        aggregate_commitment = &aggregate_commitment + &output.public.commitment;
        aggregate_mask = &aggregate_mask + &output.mask;
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

    let signing_transcript = proof_bound_transcript(&record_transcript, &aggregate_minimum_proof);
    let mut authority_signatures = Vec::with_capacity(outputs.len());
    for (index, output) in outputs.iter().enumerate() {
        let message = authority_signature_message(&signing_transcript, index)?;
        let mut rng = hedged_signing_rng(&output.script_secret_key, b"authority", &message)?;
        authority_signatures.push(
            Ggbp1AuthoritySignature::sign(&output.script_secret_key, &message, &mut rng)
                .expect("Ristretto Schnorr signing with a synthetic key is infallible"),
        );
    }
    let subject_message = subject_signature_message(&signing_transcript);
    let mut subject_rng = hedged_signing_rng(&subject.secret_key, b"subject", &subject_message)?;

    Ok(Ggbp1Proof {
        outputs: public_outputs,
        authority_signatures,
        subject_signature: Ggbp1SubjectSignature::sign(
            &subject.secret_key,
            &subject_message,
            &mut subject_rng,
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
    let record_transcript = canonical_output_transcript(challenge, &proof.outputs)?;
    if proof.authority_signatures.len() != proof.outputs.len() {
        return Err(Ggbp1Error::SignatureCount);
    }
    if proof.aggregate_minimum_proof.len() > GGBP1_MAX_PROOF_BYTES {
        return Err(Ggbp1Error::ProofTooLarge);
    }
    let signing_transcript =
        proof_bound_transcript(&record_transcript, &proof.aggregate_minimum_proof);

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
            &authority_signature_message(&signing_transcript, index)?,
        ) {
            return Err(Ggbp1Error::InvalidAuthoritySignature);
        }
        aggregate_commitment = &aggregate_commitment + &output.commitment;
    }
    if !proof.subject_signature.verify(
        &challenge.subject_authentication_public_key,
        &subject_signature_message(&signing_transcript),
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
    #[cfg(test)]
    RANGE_PROOF_VERIFIER_CALLS.fetch_add(1, Ordering::Relaxed);
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
    if challenge.subject_authentication_public_key == RistrettoPublicKey::default() {
        return Err(Ggbp1Error::IdentityPublicKey);
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
    if output.script_public_key == RistrettoPublicKey::default() {
        return Err(Ggbp1Error::IdentityPublicKey);
    }
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

/// Binds the otherwise independent Bulletproofs+ byte string to the signatures protecting the
/// session and full output table. The hash is fixed-width and domain-separated for v3 only.
fn proof_bound_transcript(record_transcript: &[u8], aggregate_minimum_proof: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"GGBP1V3/aggregate-minimum-proof");
    hasher.update(aggregate_minimum_proof);
    let proof_hash: [u8; 32] = hasher.finalize().into();
    let mut transcript = Vec::with_capacity(
        b"GGBP1V3/proof-binding".len() + record_transcript.len() + proof_hash.len(),
    );
    transcript.extend_from_slice(b"GGBP1V3/proof-binding");
    transcript.extend_from_slice(record_transcript);
    transcript.extend_from_slice(&proof_hash);
    transcript
}

/// Probes the CSPRNG before entering BP+, which also depends on system randomness.
fn ensure_system_entropy_available() -> Result<(), Ggbp1Error> {
    let mut probe = [0u8; 32];
    SysRng
        .try_fill_bytes(&mut probe)
        .map_err(|_| Ggbp1Error::SecureRandomnessUnavailable)
}

/// Derives a per-signature CSPRNG from the signing secret, the domain-separated message and fresh
/// system entropy. A caller never supplies or observes this state.
fn hedged_signing_rng(
    signing_key: &RistrettoSecretKey,
    role: &[u8],
    message: &[u8],
) -> Result<StdRng, Ggbp1Error> {
    let mut entropy = [0u8; 32];
    SysRng
        .try_fill_bytes(&mut entropy)
        .map_err(|_| Ggbp1Error::SecureRandomnessUnavailable)?;
    Ok(StdRng::from_seed(derive_hedged_nonce_seed(
        signing_key,
        role,
        message,
        &entropy,
    )))
}

fn derive_hedged_nonce_seed(
    signing_key: &RistrettoSecretKey,
    role: &[u8],
    message: &[u8],
    entropy: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"GGBP1V3/hedged-schnorr-nonce");
    hasher.update(role);
    hasher.update(signing_key.as_bytes());
    hasher.update(message);
    hasher.update(entropy);
    hasher.finalize().into()
}

// This deliberately private seam exists only in unit tests to pin the construction below. The
// public prover always obtains entropy itself and never accepts caller-controlled RNG state.
#[cfg(test)]
#[allow(dead_code)]
fn hedged_signing_rng_from_test_entropy(
    signing_key: &RistrettoSecretKey,
    role: &[u8],
    message: &[u8],
    entropy: &[u8; 32],
) -> StdRng {
    StdRng::from_seed(derive_hedged_nonce_seed(
        signing_key,
        role,
        message,
        entropy,
    ))
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

