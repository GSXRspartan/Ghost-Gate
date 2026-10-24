//! Synthetic-only model of the smallest wallet-internal GGBP-1 operation.
//!
//! This module is deliberately not a wallet service, RPC endpoint, WASM export, transaction
//! builder, or generic signing API. It describes the single capability a future upstream wallet
//! implementation needs: select eligible, standard outputs, show a bound approval prompt, and
//! return a bounded GGBP-1 response. The synthetic fixture state here must never be replaced with
//! a wallet file, seed phrase, view key, spending key, or live output.

use rand::{CryptoRng, Rng};
use thiserror::Error;

use crate::ggbp1::{
    GGBP1_MAX_OUTPUTS, Ggbp1Challenge, Ggbp1Error, Ggbp1WireProof, SyntheticOutputWitness,
    SyntheticSubjectWitness, prove_synthetic,
};

/// Network and wallet-chain context a wallet must bind before it considers an output eligible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntheticWalletChainContext {
    pub network: u8,
    pub genesis_hash: [u8; 32],
    pub tip_height: u64,
    pub minimum_confirmations: u64,
}

/// A synthetic wallet-owned output record. The witness is private and is never returned from the
/// adapter. `confirmed` and `unspent` are fixture metadata only, not a chain assertion.
#[derive(Clone)]
pub struct SyntheticWalletOutput {
    witness: SyntheticOutputWitness,
    confirmed_height: Option<u64>,
    maturity_height: u64,
    unspent: bool,
}

impl SyntheticWalletOutput {
    /// Constructs an in-memory fixture for this experimental adapter only.
    pub fn new_fixture(
        witness: SyntheticOutputWitness,
        confirmed_height: Option<u64>,
        maturity_height: u64,
        unspent: bool,
    ) -> Self {
        Self {
            witness,
            confirmed_height,
            maturity_height,
            unspent,
        }
    }
}

/// Exact data that must be displayed by a wallet-controlled approval UI. The selected output
/// references are public fixture identifiers; no values, masks, or private keys are present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ggbp1WalletApprovalPrompt {
    pub network: u8,
    pub genesis_hash: [u8; 32],
    pub origin_hash: [u8; 32],
    pub gate_id: [u8; 16],
    pub gate_configuration_version: u64,
    pub subject_id: [u8; 16],
    pub threshold_micro_xtm: u64,
    pub expires_at_unix_seconds: u64,
    pub selected_output_hashes: Vec<[u8; 32]>,
}

/// A decision from wallet-owned user-interface code. A real implementation must invoke this
/// port inside the wallet process after explicit user interaction; a web caller must not provide
/// it or implement it across an origin boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ggbp1WalletApproval {
    Approved,
    Declined,
}

/// Deliberately narrow approval boundary. It has no method that receives a key ID, mask, seed,
/// view key, spending key, or arbitrary message to sign.
pub trait Ggbp1WalletApprovalPort {
    fn request_ggbp1_approval(&self, prompt: &Ggbp1WalletApprovalPrompt) -> Ggbp1WalletApproval;
}

/// A synthetic, process-local wallet core. It owns fixtures and can return only canonical,
/// bounded proof bytes after the approval port accepts the exact selected-output challenge.
pub struct SyntheticWalletGgbp1Prover {
    chain: SyntheticWalletChainContext,
    subject: SyntheticSubjectWitness,
    outputs: Vec<SyntheticWalletOutput>,
}

impl SyntheticWalletGgbp1Prover {
    /// This constructor is for synthetic test state only. It cannot open or attach a real wallet.
    pub fn new_fixture(
        chain: SyntheticWalletChainContext,
        subject: SyntheticSubjectWitness,
        outputs: Vec<SyntheticWalletOutput>,
    ) -> Self {
        Self {
            chain,
            subject,
            outputs,
        }
    }

    /// Produces a proof only after deterministic selection and an explicit wallet-owned decision.
    /// The result is the existing bounded canonical GGBP-1 wire response; no secret material is
    /// returned. This has no transaction, output reservation, or network side effect.
    pub fn prove_after_approval<R: Rng + CryptoRng>(
        &self,
        challenge: &Ggbp1Challenge,
        approval: &impl Ggbp1WalletApprovalPort,
        rng: &mut R,
    ) -> Result<Vec<u8>, Ggbp1WalletAdapterError> {
        self.check_challenge_context(challenge)?;
        let selected = self.select_eligible_outputs(challenge)?;
        let prompt = approval_prompt(challenge, &selected);
        if approval.request_ggbp1_approval(&prompt) != Ggbp1WalletApproval::Approved {
            return Err(Ggbp1WalletAdapterError::UserDeclined);
        }

        let proof = prove_synthetic(challenge, &self.subject, &selected, rng)?;
        Ggbp1WireProof {
            challenge: challenge.clone(),
            proof,
        }
        .to_bytes()
        .map_err(Into::into)
    }

    fn check_challenge_context(
        &self,
        challenge: &Ggbp1Challenge,
    ) -> Result<(), Ggbp1WalletAdapterError> {
        if challenge.network != self.chain.network {
            return Err(Ggbp1WalletAdapterError::NetworkMismatch);
        }
        if challenge.genesis_hash != self.chain.genesis_hash {
            return Err(Ggbp1WalletAdapterError::GenesisMismatch);
        }
        if challenge.threshold_micro_xtm == 0 {
            return Err(Ggbp1WalletAdapterError::ZeroThreshold);
        }
        if challenge.subject_authentication_public_key != self.subject.public_key() {
            return Err(Ggbp1WalletAdapterError::SubjectMismatch);
        }
        Ok(())
    }

    fn select_eligible_outputs(
        &self,
        challenge: &Ggbp1Challenge,
    ) -> Result<Vec<SyntheticOutputWitness>, Ggbp1WalletAdapterError> {
        let mut candidates = self
            .outputs
            .iter()
            .filter(|output| self.is_eligible(output))
            .map(|output| output.witness.clone())
            .collect::<Vec<_>>();
        candidates.sort_by_key(|output| output.public.output_hash);

        let mut selected = Vec::new();
        let mut total = 0u64;
        for output in candidates {
            if selected.len() == GGBP1_MAX_OUTPUTS {
                break;
            }
            total = total
                .checked_add(output.value_for_wallet_selection())
                .ok_or(Ggbp1WalletAdapterError::AggregateOverflow)?;
            selected.push(output);
            if total >= challenge.threshold_micro_xtm {
                return Ok(selected);
            }
        }
        Err(Ggbp1WalletAdapterError::InsufficientEligibleValue)
    }

    fn is_eligible(&self, output: &SyntheticWalletOutput) -> bool {
        let Some(confirmed_height) = output.confirmed_height else {
            return false;
        };
        let confirmations = self
            .chain
            .tip_height
            .saturating_sub(confirmed_height)
            .saturating_add(1);
        output.unspent
            && output.maturity_height <= self.chain.tip_height
            && confirmations >= self.chain.minimum_confirmations
            && output.witness.is_supported_standard_output()
    }
}

fn approval_prompt(
    challenge: &Ggbp1Challenge,
    selected: &[SyntheticOutputWitness],
) -> Ggbp1WalletApprovalPrompt {
    Ggbp1WalletApprovalPrompt {
        network: challenge.network,
        genesis_hash: challenge.genesis_hash,
        origin_hash: challenge.origin_hash,
        gate_id: challenge.gate_id,
        gate_configuration_version: challenge.gate_configuration_version,
        subject_id: challenge.subject_id,
        threshold_micro_xtm: challenge.threshold_micro_xtm,
        expires_at_unix_seconds: challenge.expires_at_unix_seconds,
        selected_output_hashes: selected
            .iter()
            .map(|output| output.public.output_hash)
            .collect(),
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Ggbp1WalletAdapterError {
    #[error("the GGBP-1 challenge network differs from the wallet chain context")]
    NetworkMismatch,
    #[error("the GGBP-1 challenge genesis hash differs from the wallet chain context")]
    GenesisMismatch,
    #[error("a zero threshold is not an approvable GGBP-1 request")]
    ZeroThreshold,
    #[error("the GGBP-1 challenge subject is not controlled by this synthetic wallet")]
    SubjectMismatch,
    #[error("eligible output values overflow the supported aggregate")]
    AggregateOverflow,
    #[error("there are insufficient eligible standard outputs for the requested threshold")]
    InsufficientEligibleValue,
    #[error("the wallet user declined the exact GGBP-1 approval prompt")]
    UserDeclined,
    #[error(transparent)]
    Proof(#[from] Ggbp1Error),
}

#[cfg(test)]
mod tests {
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;
    use tari_crypto::ristretto::RistrettoSecretKey;

    use crate::ggbp1::expected_commitment_generator_fingerprint;

    struct Approval(Ggbp1WalletApproval);

    impl Ggbp1WalletApprovalPort for Approval {
        fn request_ggbp1_approval(&self, _: &Ggbp1WalletApprovalPrompt) -> Ggbp1WalletApproval {
            self.0
        }
    }

    fn key(value: u64) -> RistrettoSecretKey {
        RistrettoSecretKey::from(value)
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

    fn output(
        id: u8,
        value: u64,
        confirmed_height: Option<u64>,
        unspent: bool,
    ) -> SyntheticWalletOutput {
        SyntheticWalletOutput::new_fixture(
            SyntheticOutputWitness::new(
                [id; 32],
                value,
                key(u64::from(id) + 10),
                key(u64::from(id) + 20),
            ),
            confirmed_height,
            10,
            unspent,
        )
    }

    fn prover(outputs: Vec<SyntheticWalletOutput>) -> SyntheticWalletGgbp1Prover {
        SyntheticWalletGgbp1Prover::new_fixture(
            SyntheticWalletChainContext {
                network: 42,
                genesis_hash: [1; 32],
                tip_height: 100,
                minimum_confirmations: 2,
            },
            subject(),
            outputs,
        )
    }

    #[test]
    fn explicit_approval_produces_a_verifiable_bounded_response_from_eligible_outputs_only() {
        let wallet = prover(vec![
            output(1, 45, Some(90), true),
            output(2, 55, Some(100), true), // insufficient confirmations
            output(3, 55, Some(90), true),
            output(4, 500, Some(90), false), // spent fixture
        ]);
        let challenge = challenge(100);
        let mut rng = StdRng::from_seed([21; 32]);
        let bytes = wallet
            .prove_after_approval(
                &challenge,
                &Approval(Ggbp1WalletApproval::Approved),
                &mut rng,
            )
            .unwrap();
        let wire = Ggbp1WireProof::from_bytes(&bytes).unwrap();

        assert_eq!(
            wire.proof
                .outputs
                .iter()
                .map(|output| output.output_hash)
                .collect::<Vec<_>>(),
            vec![[1; 32], [3; 32]]
        );
        crate::ggbp1::verify_synthetic(&challenge, &wire.proof).unwrap();
    }

    #[test]
    fn declined_or_mismatched_challenges_cannot_produce_a_response() {
        let wallet = prover(vec![output(1, 100, Some(90), true)]);
        let mut rng = StdRng::from_seed([22; 32]);
        assert_eq!(
            wallet
                .prove_after_approval(
                    &challenge(100),
                    &Approval(Ggbp1WalletApproval::Declined),
                    &mut rng
                )
                .unwrap_err(),
            Ggbp1WalletAdapterError::UserDeclined
        );

        let mut wrong_network = challenge(100);
        wrong_network.network = 43;
        assert_eq!(
            wallet
                .prove_after_approval(
                    &wrong_network,
                    &Approval(Ggbp1WalletApproval::Approved),
                    &mut rng
                )
                .unwrap_err(),
            Ggbp1WalletAdapterError::NetworkMismatch
        );
        assert_eq!(
            wallet
                .prove_after_approval(
                    &challenge(0),
                    &Approval(Ggbp1WalletApproval::Approved),
                    &mut rng
                )
                .unwrap_err(),
            Ggbp1WalletAdapterError::ZeroThreshold
        );
    }
}
