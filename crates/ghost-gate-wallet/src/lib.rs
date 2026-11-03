//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! Wallet-side Ghost Gate statement assembly.
//!
//! A Ghost Gate proof is a stealth transfer statement whose single output carries a public
//! `minimum_value_promise` at or above the gate threshold. Building that statement needs the
//! prover's Pedersen masks and keys, so it must happen **inside the wallet**: a third party that
//! assembles the statement would have to ask the wallet for the input masks, and a wallet that
//! hands out masks has given away everything the stealth primitive protects.
//!
//! This crate is the piece that sits inside that boundary. It takes the witnesses the wallet's own
//! crypto API produced and produces the Ghost Gate statement, changing exactly one thing versus an
//! ordinary transfer: the output's public minimum value promise.
//!
//! # Why the promise can be set here
//!
//! The wallet's `create_output_witness` fixes `minimum_value_promise` at zero and exposes no way to
//! change it (verified in `docs/V042_SOURCE_TRACE.md`, finding 12). That is correct for an ordinary
//! transfer, where the sender has no reason to publish a lower bound. For a Ghost Gate proof the
//! lower bound *is* the product, so it must be settable.
//!
//! Setting it on the witness before the statement is built is sound, and requires no secret: the
//! value is already committed inside the mask, `encrypted_data` is already encrypted to the owner's
//! view key, and the promise is a public field that the bulletproof is generated *over*. A promise
//! larger than the value is therefore not forgeable — `create_outputs_statement` proves the value
//! lies in `[minimum_value_promise, 2^64)` and the engine re-verifies exactly that range proof
//! (`tari_engine_types::crypto::range_proof::validate_bullet_proof`). Changing the promise after the
//! proof exists invalidates the proof; that is finding 5 and it is covered by a test.
//!
//! # What this crate does not do
//!
//! It never touches an account key, a spend key or a signing key. Signing is the wallet's job,
//! through its own signer, on its own process. This crate produces bytes.

use ghost_gate_core::{Challenge, GatePolicy};
use ootle_byte_type::ToByteType;
use tari_crypto::{
    keys::{PublicKey, SecretKey},
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
};
use tari_ootle_wallet_crypto::{
    MaskAndValue, OutputWitness, StealthInputWitness, StealthOutputWitness, stealth,
};
use tari_template_lib_types::{
    Amount, EncryptedData, ResourceAddress,
    crypto::{RistrettoPublicKeyBytes, UtxoTag},
    stealth::{RevealedOutput, SpendAuthorization, StealthTransferStatement},
};



/// A proof the wallet has been asked to produce, in wallet terms.
#[derive(Debug, Clone)]
pub struct ProofRequest {
    /// The gate's challenge, already bound to this site and session.
    pub challenge: Challenge,
    /// The resource whose hidden value must clear the threshold.
    pub resource: ResourceAddress,
    /// The value to put in the qualifying output, in the resource's smallest unit.
    ///
    /// This is a real amount the prover holds, not a promise: the output's hidden value is exactly
    /// this, and the wallet must be able to fund it. Must be at least the gate threshold.
    pub output_value: u64,
    /// The inputs to spend, already resolved and unlocked by the wallet.
    pub inputs: Vec<MaskAndValue>,
    /// The view-only key of the account that will own the qualifying output, used to encrypt it.
    pub owner_view_key: RistrettoPublicKey,
    /// The account public key, from which the output's one-time spend key is derived.
    pub owner_account_key: RistrettoPublicKey,
    /// The mask for the qualifying output. The wallet generates it; it must never leave the wallet.
    pub output_mask: RistrettoSecretKey,
    /// The network the output's stealth keys are derived for. Domain-separates the derived spend
    /// key so the same account key yields a different UTXO owner key on a different chain.
    pub network: ootle_network::Network,
}

impl ProofRequest {
    /// Rejects a request the wallet cannot honestly fulfil.
    ///
    /// Every comparison is on raw units of the gate's own resource. The wallet never sees a symbol,
    /// a name or a display amount, because none of them can decide whether this statement qualifies.
    pub fn validate(&self, policy: &GatePolicy) -> Result<(), AssembleError> {
        if self.inputs.is_empty() {
            return Err(AssembleError::NoInputs);
        }
        if self.resource != policy.resource {
            return Err(AssembleError::RequestResourceMismatch);
        }
        let total: u64 = self
            .inputs
            .iter()
            .fold(0u64, |acc, i| acc.saturating_add(i.value));
        if total < self.output_value {
            return Err(AssembleError::InsufficientFunds { available: total, required: self.output_value });
        }
        if self.output_value < policy.threshold {
            return Err(AssembleError::OutputBelowThreshold {
                value: self.output_value,
                threshold: policy.threshold,
            });
        }
        if self.challenge.resource != policy.resource {
            return Err(AssembleError::ChallengeResourceMismatch);
        }
        if self.challenge.threshold != policy.threshold {
            return Err(AssembleError::ChallengeThresholdMismatch);
        }
        if self.challenge.network != policy.network {
            return Err(AssembleError::NetworkMismatch {
                challenge: self.challenge.network,
                gate: policy.network,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AssembleError {
    #[error("GG: no stealth inputs were selected")]
    NoInputs,
    #[error("GG: selected inputs worth {available} cannot fund an output of {required}")]
    InsufficientFunds { available: u64, required: u64 },
    #[error("GG: output value {value} is below the gate threshold {threshold}")]
    OutputBelowThreshold { value: u64, threshold: u64 },
    #[error("GG: the proof request names a different resource than the gate")]
    RequestResourceMismatch,
    #[error("GG: challenge names a different resource than the gate")]
    ChallengeResourceMismatch,
    #[error("GG: challenge names a different threshold than the gate")]
    ChallengeThresholdMismatch,
    #[error("GG: challenge names network {challenge} but the gate is bound to {gate}")]
    NetworkMismatch { challenge: u8, gate: u8 },
    #[error("GG: crypto failure while assembling the proof: {0}")]
    Crypto(String),
}

/// Builds the qualifying output witness for a Ghost Gate proof.
///
/// Identical in every respect to an ordinary self-transfer output except that
/// `minimum_value_promise` is the gate threshold rather than zero.
pub fn qualifying_output_witness(
    amount: u64,
    minimum_value_promise: u64,
    network: ootle_network::Network,
    owner_account_key: &RistrettoPublicKey,
    owner_view_key: &RistrettoPublicKey,
    mask: &RistrettoSecretKey,
) -> Result<StealthOutputWitness, AssembleError> {
    if minimum_value_promise > amount {
        return Err(AssembleError::Crypto(format!(
            "minimum_value_promise ({minimum_value_promise}) exceeds the output value ({amount})"
        )));
    }

    let crypto = tari_ootle_wallet_crypto::StealthCryptoApi::new();
    let (nonce_secret, public_nonce) = RistrettoPublicKey::random_keypair(&mut rand::rng());
    let encrypted_data = crypto
        .encrypt_value_and_mask(amount, mask, owner_view_key, &nonce_secret, None)
        .map_err(|e| AssembleError::Crypto(e.to_string()))?;

    // Key-path authorisation: the one-time stealth spend key the owner will hold. The funds stay
    // spendable by a key, which is exactly what the gate's shape rule requires and what lets the
    // owner refresh the promise afterwards with an ordinary transfer.
    let spend_key = crypto.derive_stealth_owner_public_key(
        network,
        owner_account_key,
        owner_view_key,
        &nonce_secret,
    );

    Ok(StealthOutputWitness {
        witness: OutputWitness {
            amount,
            mask: mask.clone(),
            sender_public_nonce: public_nonce,
            minimum_value_promise,
            encrypted_data,
            resource_view_key: None,
        },
        auth: SpendAuthorization::Key(spend_key.to_byte_type()),
        tag: UtxoTag::new(0),
    })
}

/// Assembles the Ghost Gate proof statement.
///
/// The returned statement is a normal `StealthTransferStatement`: the engine treats a proof exactly
/// as it treats any other stealth transfer. That is the point — there is no Ghost Gate-specific
/// transaction type, no side channel, and nothing for a validator to special-case beyond running
/// this template.
pub fn assemble_proof_statement(
    request: &ProofRequest,
    policy: &GatePolicy,
) -> Result<StealthTransferStatement, AssembleError> {
    request.validate(policy)?;

    let output_witness = qualifying_output_witness(
        request.output_value,
        policy.threshold,
        request.network,
        &request.owner_account_key,
        &request.owner_view_key,
        &request.output_mask,
    )?;

    let inputs: Vec<StealthInputWitness> = request
        .inputs
        .iter()
        .cloned()
        .map(StealthInputWitness::new)
        .collect();

    // Key path only: every input is authorised by a signature from the UTXO's committed spend key.
    let statement = stealth::create_transfer_statement(
        inputs,
        Amount::zero(),
        [&output_witness],
        // No revealed output. A revealed output would materialise a cleartext bucket in the gate's
        // workspace and publish an exact amount, which the gate refuses and which would defeat the
        // product.
        None::<RevealedOutput>,
    )
    .map_err(|e| AssembleError::Crypto(e.to_string()))?;

    Ok(statement)
}

/// Builds a plain, promise-free self-transfer output — the privacy refresh.
///
/// After a gate proof commits, the qualifying output still carries a public promise of at least the
/// threshold. A later ordinary transfer that consolidates it into a fresh output with a zero promise
/// removes that persistent disclosure from the output the user carries forward.
///
/// It does not erase history: the gate transaction and its promise stay on chain forever. It only
/// stops the beacon from riding along on the user's current coin.
pub fn refresh_output_witness(
    amount: u64,
    network: ootle_network::Network,
    owner_account_key: &RistrettoPublicKey,
    owner_view_key: &RistrettoPublicKey,
    mask: &RistrettoSecretKey,
) -> Result<StealthOutputWitness, AssembleError> {
    qualifying_output_witness(
        amount,
        0,
        network,
        owner_account_key,
        owner_view_key,
        mask,
    )
}

/// A zero-mask output witness for tests and fixtures. Never use this in a wallet: a zero mask
/// publishes the value as the commitment's discrete-log-free component and is not stealth at all.
pub fn test_output_witness(amount: u64, mvp: u64) -> StealthOutputWitness {
    let mask = RistrettoSecretKey::random(&mut rand::rng());
    StealthOutputWitness {
        witness: OutputWitness {
            amount,
            mask: mask.clone(),
            sender_public_nonce: RistrettoPublicKey::from_secret_key(&RistrettoSecretKey::from(11u64)),
            minimum_value_promise: mvp,
            encrypted_data: EncryptedData::try_from(vec![0u8; EncryptedData::min_size()]).unwrap(),
            resource_view_key: None,
        },
        auth: SpendAuthorization::Key(RistrettoPublicKey::from_secret_key(&mask).to_byte_type()),
        tag: UtxoTag::new(0),
    }
}

/// The recipient key a revealed output would need, exposed only so tests can assert it is absent.
pub fn absent_revealed_receiver() -> Option<RistrettoPublicKeyBytes> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_gate_core::network;
    use tari_template_lib_types::{ComponentAddress, Hash32, MaxBytes, ObjectKey};

    const RESOURCE: ResourceAddress = ResourceAddress::new(ObjectKey::from_array([7u8; ObjectKey::LENGTH]));
    const GATE: ComponentAddress = ComponentAddress::new(ObjectKey::from_array([1u8; ObjectKey::LENGTH]));

    /// The cohort these fixtures pretend to run on.
    const NETWORK: u8 = network::LOCALNET;

    fn policy() -> GatePolicy {
        GatePolicy {
            resource: RESOURCE,
            threshold: 10_000,
            open: true,
            network: NETWORK,
        }
    }

    fn request(output_value: u64, input_value: u64) -> ProofRequest {
        ProofRequest {
            challenge: Challenge {
                gate: GATE,
                resource: RESOURCE,
                threshold: 10_000,
                network: network::LOCALNET,
                nonce: Hash32::from_array([5u8; 32]),
                expires_epoch: 1_000,
                relying_site: MaxBytes::new_checked(b"vip.example".to_vec()).unwrap(),
                session_commitment: MaxBytes::new_checked(b"s".to_vec()).unwrap(),
            },
            resource: RESOURCE,
            output_value,
            inputs: vec![MaskAndValue {
                mask: RistrettoSecretKey::random(&mut rand::rng()),
                value: input_value,
            }],
            owner_view_key: RistrettoPublicKey::from_secret_key(&RistrettoSecretKey::random(&mut rand::rng())),
            owner_account_key: RistrettoPublicKey::from_secret_key(&RistrettoSecretKey::random(&mut rand::rng())),
            output_mask: RistrettoSecretKey::random(&mut rand::rng()),
            network: ootle_network::Network::LocalNet,
        }
    }

    #[test]
    fn assembled_statement_carries_the_gate_threshold() {
        let request = request(25_000, 25_000);
        let statement = assemble_proof_statement(&request, &policy()).unwrap();
        assert_eq!(statement.outputs_statement.outputs.len(), 1);
        assert_eq!(
            statement.outputs_statement.outputs[0].output.minimum_value_promise,
            10_000,
            "the public promise is the gate threshold"
        );
    }

    #[test]
    fn assembled_statement_reveals_nothing() {
        let statement = assemble_proof_statement(&request(25_000, 25_000), &policy()).unwrap();
        assert!(statement.outputs_statement.revealed_output.is_none());
        assert!(statement.inputs_statement.revealed_amount.is_zero());
    }

    #[test]
    fn assembled_statement_has_a_balance_proof() {
        let statement = assemble_proof_statement(&request(25_000, 25_000), &policy()).unwrap();
        assert!(statement.balance_proof.is_some());
    }

    #[test]
    fn output_below_threshold_is_refused() {
        let err = assemble_proof_statement(&request(9_999, 9_999), &policy()).unwrap_err();
        assert_eq!(
            err,
            AssembleError::OutputBelowThreshold {
                value: 9_999,
                threshold: 10_000
            }
        );
    }

    #[test]
    fn inputs_cannot_fund_the_output_are_refused() {
        let err = assemble_proof_statement(&request(20_000, 15_000), &policy()).unwrap_err();
        assert_eq!(
            err,
            AssembleError::InsufficientFunds {
                available: 15_000,
                required: 20_000
            }
        );
    }

    #[test]
    fn no_inputs_is_refused() {
        let mut request = request(20_000, 20_000);
        request.inputs.clear();
        assert_eq!(assemble_proof_statement(&request, &policy()).unwrap_err(), AssembleError::NoInputs);
    }

    #[test]
    fn promise_above_value_is_refused() {
        let mask = RistrettoSecretKey::random(&mut rand::rng());
        let err = qualifying_output_witness(
            100,
            101,
            ootle_network::Network::LocalNet,
            &RistrettoPublicKey::from_secret_key(&RistrettoSecretKey::random(&mut rand::rng())),
            &RistrettoPublicKey::from_secret_key(&RistrettoSecretKey::random(&mut rand::rng())),
            &mask,
        )
        .unwrap_err();
        assert!(err.to_string().contains("minimum_value_promise"), "{err}");
    }

    #[test]
    fn fragmented_inputs_produce_one_proof() {
        let mut request = request(12_300, 12_300);
        request.inputs = vec![
            MaskAndValue {
                mask: RistrettoSecretKey::random(&mut rand::rng()),
                value: 3_100,
            },
            MaskAndValue {
                mask: RistrettoSecretKey::random(&mut rand::rng()),
                value: 2_900,
            },
            MaskAndValue {
                mask: RistrettoSecretKey::random(&mut rand::rng()),
                value: 4_800,
            },
            MaskAndValue {
                mask: RistrettoSecretKey::random(&mut rand::rng()),
                value: 1_500,
            },
        ];
        let statement = assemble_proof_statement(&request, &policy()).unwrap();
        assert_eq!(statement.inputs_statement.inputs.len(), 4);
        assert_eq!(statement.outputs_statement.outputs.len(), 1);
    }

    #[test]
    fn refresh_drops_the_promise() {
        let mask = RistrettoSecretKey::random(&mut rand::rng());
        let refreshed = refresh_output_witness(
            25_000,
            ootle_network::Network::LocalNet,
            &RistrettoPublicKey::from_secret_key(&RistrettoSecretKey::random(&mut rand::rng())),
            &RistrettoPublicKey::from_secret_key(&RistrettoSecretKey::random(&mut rand::rng())),
            &mask,
        )
        .unwrap();
        assert_eq!(refreshed.witness.minimum_value_promise, 0);
    }

    #[test]
    fn assembled_statement_survives_the_engines_shape_checks() {
        // The gate requires no revealed input and no revealed output. The wallet's own assembler
        // must produce exactly that, or every proof would be refused on shape before the threshold
        // is ever consulted.
        let statement = assemble_proof_statement(&request(25_000, 25_000), &policy()).unwrap();
        assert!(statement.inputs_statement.revealed_amount.is_zero());
        assert!(statement.outputs_statement.revealed_output.is_none());
        assert_eq!(statement.outputs_statement.outputs.len(), 1);
        assert!(statement.balance_proof.is_some());
        assert!(statement.covenant_claims.is_empty(), "key-path inputs join no covenant partition");
    }

    // -----------------------------------------------------------------------------------------
    // The wallet is resource- and network-agnostic: same code, any stealth fungible gate
    // -----------------------------------------------------------------------------------------

    /// A second resource address, standing in for a different user-created asset.
    const OTHER_RESOURCE: ResourceAddress =
        ResourceAddress::new(ObjectKey::from_array([8u8; ObjectKey::LENGTH]));

    #[test]
    fn the_same_assembler_serves_a_second_resource() {
        // Nothing in the assembly path names a resource: the same request shape, pointed at a
        // different gate over a different resource, produces a statement carrying that gate's
        // threshold.
        let other_policy = GatePolicy { resource: OTHER_RESOURCE, ..policy() };
        let mut request = request(40_000, 40_000);
        request.resource = OTHER_RESOURCE;
        request.challenge.resource = OTHER_RESOURCE;

        let statement = assemble_proof_statement(&request, &other_policy).unwrap();
        assert_eq!(
            statement.outputs_statement.outputs[0]
                .output
                .minimum_value_promise,
            other_policy.threshold,
            "the promise is the second gate's own threshold, not a constant"
        );
    }

    #[test]
    fn a_request_naming_another_resource_is_refused() {
        // A wallet holding plenty of one asset must not be talked into building a statement for a
        // gate over a different one.
        let mut request = request(25_000, 25_000);
        request.resource = OTHER_RESOURCE;
        assert_eq!(
            assemble_proof_statement(&request, &policy()).unwrap_err(),
            AssembleError::RequestResourceMismatch
        );
    }

    #[test]
    fn a_challenge_naming_another_resource_is_refused() {
        let mut request = request(25_000, 25_000);
        request.challenge.resource = OTHER_RESOURCE;
        assert_eq!(
            assemble_proof_statement(&request, &policy()).unwrap_err(),
            AssembleError::ChallengeResourceMismatch
        );
    }

    #[test]
    fn a_challenge_for_another_network_is_refused() {
        // The gate is bound to one cohort. A challenge minted for another is not redeemable here, and
        // the wallet refuses it before building anything rather than leaving consensus to refuse it.
        let mut request = request(25_000, 25_000);
        request.challenge.network = network::ESMERALDA;
        assert_eq!(
            assemble_proof_statement(&request, &policy()).unwrap_err(),
            AssembleError::NetworkMismatch {
                challenge: network::ESMERALDA,
                gate: network::LOCALNET,
            }
        );
    }
}
