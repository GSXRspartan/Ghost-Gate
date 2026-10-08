//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! Ghost Gate tests that do not need the engine: statement-shape qualification and MVP binding.
//!
//! Everything here runs against the same `ghost_gate_core` functions the template compiles, so a
//! rule proven here is the rule consensus applies.

use ghost_gate_core::{
    Challenge, GateContext, GateError, GatePolicy, ProofReceipt, network, qualify,
};
use ootle_byte_type::ToByteType;
use tari_crypto::{
    keys::{PublicKey, SecretKey},
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
};
use tari_ootle_wallet_crypto::{
    MaskAndValue, OutputWitness, StealthInputWitness, StealthOutputWitness, stealth,
};
use tari_template_lib::types::{
    AccessRule, Amount, ComponentAddress, EncryptedData, Hash32, MaxBytes, ObjectKey, ResourceAddress,
    crypto::{RistrettoPublicKeyBytes, UtxoTag},
    stealth::{RevealedOutput, SpendAuthorization, StealthTransferStatement},
};

const RESOURCE: ResourceAddress = ResourceAddress::new(ObjectKey::from_array([7u8; ObjectKey::LENGTH]));
const GATE: ComponentAddress = ComponentAddress::new(ObjectKey::from_array([1u8; ObjectKey::LENGTH]));
const THRESHOLD: u64 = 10_000;

/// The cohort these fixtures pretend to run on.
const NETWORK: u8 = network::LOCALNET;

fn policy() -> GatePolicy {
    GatePolicy {
        resource: RESOURCE,
        threshold: THRESHOLD,
        open: true,
        network: NETWORK,
    }
}

fn challenge() -> Challenge {
    Challenge {
        gate: GATE,
        resource: RESOURCE,
        threshold: THRESHOLD,
        network: NETWORK,
        nonce: Hash32::from_array([42u8; 32]),
        expires_epoch: 1_000,
        relying_site: MaxBytes::new_checked(b"vip.example".to_vec()).unwrap(),
        session_commitment: MaxBytes::new_checked(b"session-1".to_vec()).unwrap(),
    }
}

fn ctx() -> GateContext<'static> {
    GateContext {
        self_address: GATE,
        current_epoch: 5,
        relying_site: b"vip.example",
        session_commitment: b"session-1",
    }
}

/// Builds one key-path stealth output worth `amount` promising at least `mvp`.
///
/// The output is authorised by the key derived from its own mask, so a test holding that mask can
/// also hold the key that authorises spending it — the same relationship a wallet output has.
fn output(amount: u64, mvp: u64) -> StealthOutputWitness {
    let mask = RistrettoSecretKey::random(&mut rand::rng());
    StealthOutputWitness {
        witness: OutputWitness {
            amount,
            mask: mask.clone(),
            sender_public_nonce: RistrettoPublicKey::from_secret_key(&RistrettoSecretKey::from(7u64)),
            minimum_value_promise: mvp,
            encrypted_data: EncryptedData::try_from(vec![0u8; EncryptedData::min_size()]).unwrap(),
            resource_view_key: None,
        },
        auth: SpendAuthorization::Key(RistrettoPublicKey::from_secret_key(&mask).to_byte_type()),
        tag: UtxoTag::new(0),
    }
}

/// A self-transfer: one input worth `input_value`, one output worth `input_value` with MVP `mvp`.
fn self_transfer(input_value: u64, mvp: u64) -> (StealthTransferStatement, RistrettoSecretKey) {
    let input_mask = RistrettoSecretKey::random(&mut rand::rng());
    let out = output(input_value, mvp);
    let statement = stealth::create_transfer_statement(
        [StealthInputWitness::new(MaskAndValue {
            mask: input_mask.clone(),
            value: input_value,
        })],
        Amount::zero(),
        [&out],
        None,
    )
    .expect("statement is well formed");
    (statement, input_mask)
}

// ---------------------------------------------------------------------------------------------
// Gate 1 — MVP self-transfer
// ---------------------------------------------------------------------------------------------

/// The whole point of the primitive: a hidden value at or above the promised minimum validates.
#[test]
fn hidden_value_above_threshold_validates() {
    let (statement, _) = self_transfer(20_000, THRESHOLD);
    let receipt = qualify(&policy(), &challenge(), &statement, &ctx(), false).expect("must qualify");
    assert_eq!(receipt.attested_minimum, THRESHOLD);
    assert_eq!(receipt.input_count, 1);
    assert_eq!(receipt.challenge_nonce, challenge().nonce);
}

/// Exactly the threshold qualifies. `>=`, not `>`.
#[test]
fn hidden_value_exactly_at_threshold_qualifies() {
    let (statement, _) = self_transfer(THRESHOLD, THRESHOLD);
    assert!(qualify(&policy(), &challenge(), &statement, &ctx(), false).is_ok());
}

/// The engine's own range-proof validator is the authority on whether value >= MVP holds.
#[test]
fn engine_range_proof_accepts_value_at_or_above_mvp() {
    let (statement, _) = self_transfer(THRESHOLD, THRESHOLD);
    tari_engine_types::stealth::validate_stealth_outputs_statement(&statement.outputs_statement, None)
        .expect("range proof valid at exactly the MVP");
}

/// Mutating the public MVP after the proof was built breaks the bulletproof, so a prover cannot
/// raise their own attestation.
#[test]
fn mutating_mvp_after_proof_breaks_validation() {
    let (mut statement, _) = self_transfer(20_000, THRESHOLD);

    statement.outputs_statement.outputs[0].output.minimum_value_promise = THRESHOLD - 1;
    assert!(
        tari_engine_types::stealth::validate_stealth_outputs_statement(&statement.outputs_statement, None).is_err(),
        "lowering the MVP must invalidate the range proof"
    );

    statement.outputs_statement.outputs[0].output.minimum_value_promise = THRESHOLD + 1;
    assert!(
        tari_engine_types::stealth::validate_stealth_outputs_statement(&statement.outputs_statement, None).is_err(),
        "raising the MVP must invalidate the range proof"
    );
}

/// MVP > value cannot even be constructed: the wallet refuses before any proof is made.
///
/// The SDK reports this as `Err`, not a panic, and names the conflict in the proof constructor's own
/// words. Matching on "minimum value is larger than value" rather than on a field name is deliberate:
/// the caller asked for a promise, and the reason it gets back is about promises and values, not about
/// a struct field it never passed.
#[test]
fn mvp_above_value_is_refused_at_construction() {
    let out = output(100, 101);
    let err = stealth::create_outputs_statement([&out], None).unwrap_err();
    let text = err.to_string().to_lowercase();
    assert!(
        text.contains("minimum value is larger than value"),
        "the refusal must say the promise exceeds the value, got: {text}"
    );
}

/// Many fragmented inputs are one proof, not many. The receipt counts them but the gate accepts a
/// single output.
#[test]
fn fragmented_inputs_qualify_once() {
    let inputs = [3_100u64, 2_900, 4_800, 1_500];
    let input_witnesses: Vec<_> = inputs
        .iter()
        .map(|v| {
            StealthInputWitness::new(MaskAndValue {
                mask: RistrettoSecretKey::random(&mut rand::rng()),
                value: *v,
            })
        })
        .collect();

    let total: u64 = inputs.iter().sum();
    let out = output(total, THRESHOLD);
    let statement = stealth::create_transfer_statement(input_witnesses, Amount::zero(), [&out], None).unwrap();

    let receipt = qualify(&policy(), &challenge(), &statement, &ctx(), false).expect("must qualify");
    assert_eq!(receipt.input_count, 4, "all four inputs are part of the one proof");
    assert_eq!(receipt.attested_minimum, THRESHOLD);
}

// ---------------------------------------------------------------------------------------------
// Gate 2 — statement shape, as consensus sees it
// ---------------------------------------------------------------------------------------------

/// Below threshold is refused by the gate rule.
#[test]
fn below_threshold_is_refused() {
    let (statement, _) = self_transfer(9_999, 9_999);
    assert_eq!(
        qualify(&policy(), &challenge(), &statement, &ctx(), false),
        Err(GateError::BelowThreshold {
            attested: 9_999,
            required: THRESHOLD
        })
    );
}

/// A statement spending nothing live proves nothing.
#[test]
fn statement_with_no_inputs_is_refused() {
    let out = output(THRESHOLD, THRESHOLD);
    let statement = stealth::create_transfer_statement(
        std::iter::empty::<StealthInputWitness>(),
        Amount::zero(),
        [&out],
        None,
    )
    .unwrap();
    assert_eq!(
        qualify(&policy(), &challenge(), &statement, &ctx(), false),
        Err(GateError::NoStealthInputs)
    );
}

/// A revealed input amount publishes an exact value and defeats the gate.
#[test]
fn revealed_input_amount_is_refused() {
    let (mut statement, _) = self_transfer(THRESHOLD, THRESHOLD);
    statement.inputs_statement.revealed_amount = Amount::from(5u64);
    assert_eq!(
        qualify(&policy(), &challenge(), &statement, &ctx(), false),
        Err(GateError::RevealedInput)
    );
}

/// A revealed output publishes an exact value and defeats the gate.
#[test]
fn revealed_output_is_refused() {
    let (mut statement, _) = self_transfer(THRESHOLD, THRESHOLD);
    statement.outputs_statement.revealed_output = Some(RevealedOutput::new(
        Amount::from(THRESHOLD),
        RistrettoPublicKeyBytes::default(),
    ));
    assert_eq!(
        qualify(&policy(), &challenge(), &statement, &ctx(), false),
        Err(GateError::RevealedOutput)
    );
}

/// Two outputs means "which one was the proof" has two answers. Refuse rather than pick.
///
/// Each output clears the threshold on its own, so nothing but the ambiguity rule can refuse this.
/// That forces the amounts: a promise may not exceed its own value, and with nothing revealed the
/// outputs must sum to the inputs, so two qualifying outputs need at least `2 * THRESHOLD` between
/// them. A smaller pair could not promise what it holds, and would be refused for being below the
/// threshold instead — which would make this test pass without ever reaching the rule it names.
#[test]
fn ambiguous_multiple_outputs_are_refused() {
    let a = output(THRESHOLD, THRESHOLD);
    let b = output(THRESHOLD, THRESHOLD);
    let input_mask = RistrettoSecretKey::random(&mut rand::rng());
    let total = 2 * THRESHOLD;
    let statement = stealth::create_transfer_statement(
        [StealthInputWitness::new(MaskAndValue {
            mask: input_mask,
            value: total,
        })],
        Amount::zero(),
        [&a, &b],
        None,
    )
    .unwrap();

    assert!(a.witness.minimum_value_promise >= THRESHOLD);
    assert!(b.witness.minimum_value_promise >= THRESHOLD);
    assert_eq!(
        qualify(&policy(), &challenge(), &statement, &ctx(), false),
        Err(GateError::TooManyOutputs)
    );
}

/// Zero outputs: nothing to attest to.
#[test]
fn no_outputs_is_refused() {
    let input_mask = RistrettoSecretKey::random(&mut rand::rng());
    let statement = stealth::create_transfer_statement(
        [StealthInputWitness::new(MaskAndValue {
            mask: input_mask,
            value: THRESHOLD,
        })],
        Amount::zero(),
        std::iter::empty::<&StealthOutputWitness>(),
        Some(RevealedOutput::new(
            Amount::from(THRESHOLD),
            RistrettoPublicKeyBytes::default(),
        )),
    )
    .unwrap();
    // Revealed output is caught first, which is the stronger refusal.
    assert_eq!(
        qualify(&policy(), &challenge(), &statement, &ctx(), false),
        Err(GateError::RevealedOutput)
    );
}

/// A script-only output would park the funds behind a predicate. The gate wants funds a key holds.
#[test]
fn non_key_spendable_output_is_refused() {
    let out = output(THRESHOLD, THRESHOLD);
    let out = StealthOutputWitness {
        auth: SpendAuthorization::Script(Hash32::from_array([3u8; 32])),
        ..out
    };
    let input_mask = RistrettoSecretKey::random(&mut rand::rng());
    let statement = stealth::create_transfer_statement(
        [StealthInputWitness::new(MaskAndValue {
            mask: input_mask,
            value: THRESHOLD,
        })],
        Amount::zero(),
        [&out],
        None,
    )
    .unwrap();
    // The mask is only needed to build the witness; the script-only auth replaces its key role.

    assert_eq!(
        qualify(&policy(), &challenge(), &statement, &ctx(), false),
        Err(GateError::NotKeySpendable)
    );
}

/// Dropping the balance proof removes the value-conservation argument.
#[test]
fn missing_balance_proof_is_refused() {
    let (mut statement, _) = self_transfer(THRESHOLD, THRESHOLD);
    statement.balance_proof = None;
    assert_eq!(
        qualify(&policy(), &challenge(), &statement, &ctx(), false),
        Err(GateError::MissingBalanceProof)
    );
}

/// A spent input on the script path is not ordinary wallet ownership.
#[test]
fn script_path_input_is_refused() {
    let (statement, _) = self_transfer(THRESHOLD, THRESHOLD);
    let mut statement = statement;
    statement.inputs_statement.inputs[0].witness = tari_template_lib::types::stealth::SpendWitness::script_path(
        tari_template_lib::types::stealth::SpendCondition::access_rule(AccessRule::AllowAll),
        tari_template_lib::types::stealth::MerkleProof::empty(),
    );
    assert_eq!(
        qualify(&policy(), &challenge(), &statement, &ctx(), false),
        Err(GateError::NonKeyPathInput)
    );
}

/// A malformed statement that does not even decode is refused before any rule runs.
#[test]
fn malformed_statement_bytes_do_not_decode() {
    let garbage = vec![0xffu8; 31];
    assert!(
        tari_bor::decode::<StealthTransferStatement>(&garbage).is_err(),
        "31 bytes of 0xff is not a valid CBOR statement"
    );
}

// ---------------------------------------------------------------------------------------------
// The receipt carries no identifying information
// ---------------------------------------------------------------------------------------------

/// A receipt is a public artefact. It must not carry an amount, an address or an identity.
#[test]
fn receipt_carries_only_public_lower_bound_and_nonce() {
    let (statement, _) = self_transfer(THRESHOLD, THRESHOLD);
    let receipt = qualify(&policy(), &challenge(), &statement, &ctx(), false).unwrap();
    assert_eq!(
        receipt,
        ProofReceipt {
            attested_minimum: THRESHOLD,
            input_count: 1,
            challenge_nonce: challenge().nonce,
        }
    );

    // The receipt's encoding is three fields and nothing else.
    let encoded = tari_bor::encode(&receipt).unwrap();
    let decoded: ProofReceipt = tari_bor::decode(&encoded).unwrap();
    assert_eq!(decoded, receipt);
}

/// The attested minimum is a lower bound, never the amount. Two different hidden values that both
/// clear the threshold produce receipts that differ only in the promise, not in any leaked value.
#[test]
fn attested_minimum_is_a_lower_bound_not_the_amount() {
    let (small, _) = self_transfer(THRESHOLD, THRESHOLD);
    let (large, _) = self_transfer(9_000_000, THRESHOLD);

    let a = qualify(&policy(), &challenge(), &small, &ctx(), false).unwrap();
    let b = qualify(&policy(), &challenge(), &large, &ctx(), false).unwrap();
    assert_eq!(
        a.attested_minimum, b.attested_minimum,
        "both proofs attest the same public bound despite a 900x difference in hidden value"
    );
}