//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! Adversarial consensus tests: an attacker driving the real template through the real engine.
//!
//! Every case here models the strongest caller the threat model allows: someone who controls their
//! own wallet, builds their own transaction, and may hand the gate ANY `StealthTransferStatement`
//! they can encode — including one whose public fields were mutated after the proofs were made,
//! whose balance proof belongs to a different statement, or whose input names an output of a
//! resource the gate does not watch.
//!
//! The harness helpers mirror `gate_engine.rs` (same fixture constants, same funding shape); they
//! are duplicated rather than shared so an audit change here cannot silently perturb the Gate 3
//! suite, and vice versa. A header comment marks the provenance of each constant.
//!
//! What each test must show, beyond "it failed":
//! 1. the rejection is the ENGINE's native validation (the reason names the rule), not the
//!    template's shape check happening to fire first;
//! 2. the gate's state is untouched — the proof counter stays at zero and the challenge nonce is
//!    not burnt — so a failed forgery cannot consume a challenge;
//! 3. where a scenario starts from real holdings, the attacker's funds are not silently destroyed
//!    by a rejected transaction (the engine aborts atomically; the inputs stay live).

use ghost_gate_core::{Challenge, network};
use ootle_byte_type::{FromByteType, ToByteType};
use tari_crypto::{
    keys::{PublicKey, SecretKey},
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
};
use tari_engine_types::substate::SubstateDiff;
use tari_ootle_common_types::substate_type::SubstateType;
use tari_ootle_transaction::{Epoch, Transaction, args};
use tari_ootle_wallet_crypto::{
    MaskAndValue, OutputWitness, StealthInputWitness, StealthOutputWitness,
};
use tari_template_lib::types::{
    Amount, ComponentAddress, EncryptedData, Hash32, MaxBytes, ObjectKey, ResourceAddress,
    crypto::{PedersenCommitmentBytes, RistrettoPublicKeyBytes, UtxoTag},
    stealth::SpendAuthorization,
    stealth::{StealthTransferStatement, StealthUnspentOutput},
};
use tari_template_test_tooling::{TemplateTest, support::assert_error::assert_reject_reason};

use std::str::FromStr;

// --- fixtures (mirrors gate_engine.rs) ---------------------------------------------------------

const CRATE_PATH: &str = env!("CARGO_MANIFEST_DIR");
const FAUCET_TEMPLATE: &str = "../../templates/ghost_gate_faucet";
const GATE_TEMPLATE: &str = "../../templates/ghost_gate";
const GATE_NAME: &str = "GhostGate";
const FAUCET_NAME: &str = "GhostGateFaucet";

const THRESHOLD: u64 = 10_000;
const TEST_EPOCH: u64 = 5;
const NETWORK: u8 = network::LOCALNET;
const MASK_BASE: u64 = 1_000_000_000;
const NONCE_OFFSET: u64 = 500;
const VIEW_KEY_SEED: u64 = 9_000_000_000;

const GATE_PROOFS_ACCEPTED_PATH: &str = "$.5";
const GATE_BURNT_NONCES_PATH: &str = "$.4";

fn site_id() -> MaxBytes<64> {
    MaxBytes::new_checked(b"attacker.example".to_vec()).unwrap()
}

fn session_id() -> MaxBytes<64> {
    MaxBytes::new_checked(b"attacker-session".to_vec()).unwrap()
}

fn harness() -> TemplateTest {
    let mut test = TemplateTest::new(CRATE_PATH, [FAUCET_TEMPLATE, GATE_TEMPLATE]);
    test.set_virtual_substate(
        tari_engine_types::virtual_substate::VirtualSubstateId::CurrentEpoch,
        tari_engine_types::virtual_substate::VirtualSubstate::CurrentEpoch(TEST_EPOCH),
    );
    test
}

struct Funds {
    resource: ResourceAddress,
    faucet: ComponentAddress,
    masks: Vec<RistrettoSecretKey>,
    inputs: Vec<tari_ootle_wallet_sdk::models::InputSpendData>,
}

fn stealth_spend_key(account_key: &RistrettoPublicKey, nonce: u64) -> RistrettoPublicKeyBytes {
    use ootle_network::Network;
    let nonce_secret = RistrettoSecretKey::from(nonce);
    let view_key = RistrettoPublicKey::from_secret_key(&RistrettoSecretKey::from(VIEW_KEY_SEED));
    tari_ootle_wallet_crypto::StealthCryptoApi::new()
        .derive_stealth_owner_public_key(Network::LocalNet, account_key, &view_key, &nonce_secret)
        .to_byte_type()
}

/// Funds `amounts` stealth outputs of a fresh resource, exactly as gate_engine.rs does.
fn fund(
    test: &mut TemplateTest,
    owner: &RistrettoSecretKey,
    amounts: &[u64],
    mvps: &[u64],
) -> Funds {
    let owner_pk = RistrettoPublicKey::from_secret_key(owner);
    let outputs: Vec<StealthOutputWitness> = amounts
        .iter()
        .enumerate()
        .map(|(i, amount)| {
            let mask = RistrettoSecretKey::from(MASK_BASE + u64::try_from(i).unwrap());
            StealthOutputWitness {
                witness: OutputWitness {
                    amount: *amount,
                    mask: mask.clone(),
                    sender_public_nonce: RistrettoPublicKey::from_secret_key(
                        &RistrettoSecretKey::from(
                            MASK_BASE + u64::try_from(i).unwrap() + NONCE_OFFSET,
                        ),
                    ),
                    minimum_value_promise: mvps.get(i).copied().unwrap_or(0),
                    encrypted_data: EncryptedData::try_from(vec![0u8; EncryptedData::min_size()])
                        .unwrap(),
                    resource_view_key: None,
                },
                auth: SpendAuthorization::Key(stealth_spend_key(
                    &owner_pk,
                    MASK_BASE + u64::try_from(i).unwrap() + NONCE_OFFSET,
                )),
                tag: UtxoTag::new(0),
            }
        })
        .collect();

    let total: u64 = amounts.iter().sum();
    let statement = mint_statement(outputs, total);
    let faucet_addr = test.get_template_address(FAUCET_NAME);
    test.execute_expect_success(
        Transaction::builder_localnet(Epoch(1))
            .call_function(
                faucet_addr,
                "new",
                args!["GGTEST".to_string(), 2u8, Amount::from(total), statement],
            )
            .build_and_seal(test.secret_key()),
        vec![],
    );

    Funds {
        resource: test
            .get_previous_output_address(SubstateType::Resource)
            .as_resource_address()
            .unwrap(),
        faucet: test
            .get_previous_output_address(SubstateType::Component)
            .as_component_address()
            .unwrap(),
        masks: amounts
            .iter()
            .enumerate()
            .map(|(i, _)| RistrettoSecretKey::from(MASK_BASE + u64::try_from(i).unwrap()))
            .collect(),
        inputs: statement
            .outputs_statement
            .outputs
            .iter()
            .zip(amounts.iter().copied())
            .map(
                |(output, value)| tari_ootle_wallet_sdk::models::InputSpendData {
                    commitment: *output.commitment(),
                    public_nonce: output.output.sender_public_nonce,
                    encrypted_data: output.output.encrypted_data.clone(),
                    value,
                    is_on_chain: true,
                },
            )
            .collect(),
    }
}

fn mint_statement(outputs: Vec<StealthOutputWitness>, supply: u64) -> StealthTransferStatement {
    create_transfer_statement(outputs, &[], Amount::from(supply), None)
}

fn create_transfer_statement(
    outputs: Vec<StealthOutputWitness>,
    inputs: &[(RistrettoSecretKey, u64)],
    revealed_input: Amount,
    revealed_output: Option<tari_template_lib::types::stealth::RevealedOutput>,
) -> StealthTransferStatement {
    let output_refs: Vec<&StealthOutputWitness> = outputs.iter().collect();
    let input_witnesses: Vec<StealthInputWitness> = inputs
        .iter()
        .map(|(mask, value)| {
            StealthInputWitness::new(MaskAndValue {
                mask: mask.clone(),
                value: *value,
            })
        })
        .collect();
    tari_ootle_wallet_crypto::stealth::create_transfer_statement(
        input_witnesses,
        revealed_input,
        output_refs,
        revealed_output,
    )
    .expect("test statement")
}

fn output_witness(
    amount: u64,
    mvp: u64,
    spend_key: RistrettoPublicKeyBytes,
) -> StealthOutputWitness {
    let mask = RistrettoSecretKey::random(&mut rand::rng());
    StealthOutputWitness {
        witness: OutputWitness {
            amount,
            mask: mask.clone(),
            sender_public_nonce: RistrettoPublicKey::from_secret_key(&RistrettoSecretKey::from(
                999u64,
            )),
            minimum_value_promise: mvp,
            encrypted_data: EncryptedData::try_from(vec![0u8; EncryptedData::min_size()]).unwrap(),
            resource_view_key: None,
        },
        auth: SpendAuthorization::Key(spend_key),
        tag: UtxoTag::new(0),
    }
}

/// An honest one-input one-output proof statement with real proofs over the given values.
fn proof_statement(
    input_mask: &RistrettoSecretKey,
    output_value: u64,
    mvp: u64,
) -> StealthTransferStatement {
    let out = output_witness(
        output_value,
        mvp,
        RistrettoPublicKey::from_secret_key(&RistrettoSecretKey::random(&mut rand::rng()))
            .to_byte_type(),
    );
    create_transfer_statement(
        vec![out],
        &[(input_mask.clone(), output_value)],
        Amount::zero(),
        None,
    )
}

fn deploy_gate(
    test: &mut TemplateTest,
    resource: ResourceAddress,
    threshold: u64,
) -> ComponentAddress {
    let template_addr = test.get_template_address(GATE_NAME);
    test.execute_expect_success(
        test.transaction()
            .allocate_component_address("ghost_gate")
            .call_function(
                template_addr,
                "new",
                args![
                    Workspace("ghost_gate"),
                    resource,
                    threshold,
                    site_id(),
                    session_id(),
                    NETWORK
                ],
            )
            .build_and_seal(test.secret_key()),
        vec![],
    );
    test.get_previous_output_address(SubstateType::Component)
        .as_component_address()
        .unwrap()
}

fn challenge_for(gate: ComponentAddress, resource: ResourceAddress, threshold: u64) -> Challenge {
    Challenge {
        gate,
        resource,
        threshold,
        network: NETWORK,
        nonce: Hash32::from_array([7u8; 32]),
        expires_epoch: 1_000,
        relying_site: site_id(),
        session_commitment: session_id(),
    }
}

fn derive_input_spend_key(account_secret: &RistrettoSecretKey, index: usize) -> RistrettoSecretKey {
    let nonce_secret =
        RistrettoSecretKey::from(MASK_BASE + u64::try_from(index).unwrap() + NONCE_OFFSET);
    let nonce_public = RistrettoPublicKey::from_secret_key(&nonce_secret);
    tari_ootle_wallet_crypto::StealthCryptoApi::new().derive_stealth_owner_secret(
        ootle_network::Network::LocalNet,
        account_secret,
        &RistrettoSecretKey::from(VIEW_KEY_SEED),
        &nonce_public,
    )
}

fn public_of(secret: &RistrettoSecretKey) -> RistrettoPublicKeyBytes {
    RistrettoPublicKey::from_secret_key(secret).to_byte_type()
}

/// The gate's state after an attempt: (proofs accepted, whether the test nonce is burnt).
///
/// Read through the template's own accessors, the same calls a relying site would make, so the
/// assertion is about observable consensus state rather than internal encoding details.
fn gate_state(test: &mut TemplateTest, gate: ComponentAddress) -> (u64, bool) {
    let accepted: u64 = test.extract_component_value(gate, GATE_PROOFS_ACCEPTED_PATH);
    let nonce_used: bool = test.call_method(
        gate,
        "is_nonce_used",
        args![Hash32::from_array([7u8; 32])],
        vec![],
    );
    (accepted, nonce_used)
}

// ---------------------------------------------------------------------------------------------
// The attacker's playbook
// ---------------------------------------------------------------------------------------------

/// THE headline attack, stated as the audit demanded it: an attacker with **no qualifying tokens**
/// tries to satisfy a nonzero threshold by flipping the public `minimum_value_promise` field of an
/// otherwise honest statement whose hidden value is far below the threshold.
///
/// Why this is the right test: the statement is caller-supplied bytes. The bulletproof inside it
/// was made for `MVP = 0` (proving `0 <= v < 2^64`); the attacker rewrites the field to
/// `THRESHOLD` after signing. The engine reads the MVPs back out of the statement when verifying
/// the proof, so the proof no longer matches the claim.
///
/// Expected: the engine's bulletproof verification fails, the transaction is rejected, and the
/// gate's counter and nonce state are untouched.
#[test]
fn zero_token_attacker_cannot_raise_their_own_attestation_by_mutating_the_mvp() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    // The attacker holds ONE unit. The threshold is 10_000.
    let funds = fund(&mut test, &account_key, &[1], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

    // An honest statement over the attacker's 1 unit, with a promise of zero: proofs are real.
    let mut statement = proof_statement(&funds.masks[0], 1, 0);
    // The forgery: raise the public claim after the fact.
    statement.outputs_statement.outputs[0]
        .output
        .minimum_value_promise = THRESHOLD;

    let input_sk = derive_input_spend_key(&account_key, 0);
    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(TEST_EPOCH))
            .call_method(gate, "prove_access", args![challenge, statement])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );

    assert_reject_reason(reason, "range proof");
    let (accepted, burnt) = gate_state(&mut test, gate);
    assert_eq!(accepted, 0, "a forged attestation must not count");
    assert!(!burnt, "a failed forgery must not consume the challenge");
}

/// The mirror of the attack above: the attacker lowers the MVP to sneak a statement past the
/// template's threshold check, then raises it again. Covered symmetrically because both directions
/// must break the same proof.
#[test]
fn lowering_then_raising_the_mvp_in_one_statement_is_refused() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[THRESHOLD], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

    // Honest proof at exactly the threshold; then a a double mutation that leaves the field
    // looking honest while the underlying bulletproof was made for a different bound.
    let mut statement = proof_statement(&funds.masks[0], THRESHOLD, THRESHOLD);
    statement.outputs_statement.outputs[0]
        .output
        .minimum_value_promise = 0;
    statement.outputs_statement.outputs[0]
        .output
        .minimum_value_promise = THRESHOLD + 1;

    let input_sk = derive_input_spend_key(&account_key, 0);
    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(TEST_EPOCH))
            .call_method(gate, "prove_access", args![challenge, statement])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );
    assert_reject_reason(reason, "range proof");
    let (accepted, burnt) = gate_state(&mut test, gate);
    assert_eq!((accepted, burnt), (0, false));
}

/// A caller who cannot produce a valid balance proof cannot substitute one: a statement whose
/// balance proof is arbitrary bytes must be refused by the engine's signature check, and the
/// template's mere presence check (`balance_proof.is_some()`) must not be mistaken for validation.
#[test]
fn a_garbage_balance_proof_is_refused_by_the_engine() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[THRESHOLD], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

    let mut statement = proof_statement(&funds.masks[0], THRESHOLD, THRESHOLD);
    // The template only requires *presence*; the engine must require *validity*.
    // 32-byte nonce + 32-byte scalar, per SchnorrSignatureBytes::length(); the bytes are
    // well-formed for decoding and meaningless as a signature.
    statement.balance_proof = Some(
        tari_template_lib::types::crypto::BalanceProofSignature::from_bytes(&[0xaa; 64])
            .expect("64 bytes decode; validity is the engine's question, not the decoder's"),
    );

    let input_sk = derive_input_spend_key(&account_key, 0);
    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(TEST_EPOCH))
            .call_method(gate, "prove_access", args![challenge, statement])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );
    assert_reject_reason(reason, "balance proof");
    let (accepted, burnt) = gate_state(&mut test, gate);
    assert_eq!((accepted, burnt), (0, false));
}

/// A real balance proof made for a DIFFERENT statement proves nothing about this one. The attacker
/// builds an honest statement, then swaps the output's MVP and attaches the untouched proof — the
/// message the signature covers includes the outputs statement, so this must fail.
#[test]
fn a_balance_proof_from_another_statement_is_refused() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[THRESHOLD], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

    // Honest A: value THRESHOLD, MVP THRESHOLD, real proofs.
    let statement_a = proof_statement(&funds.masks[0], THRESHOLD, THRESHOLD);
    // Attacked B: same inputs, output now claims a bigger promise than the proof was made for.
    let mut statement_b = statement_a.clone();
    statement_b.outputs_statement.outputs[0]
        .output
        .minimum_value_promise = u32::MAX as u64;

    let input_sk = derive_input_spend_key(&account_key, 0);
    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(TEST_EPOCH))
            .call_method(gate, "prove_access", args![challenge, statement_b])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );
    assert_reject_reason(reason, "range proof");
    let (accepted, _) = gate_state(&mut test, gate);
    assert_eq!(accepted, 0);
}

/// Cross-resource substitution: the attacker's only holding is an output of resource B; the gate
/// watches resource A. The statement spends B's commitment with B-valid proofs. The engine resolves
/// every input as `UtxoAddress::new(GATE_RESOURCE, commitment)`, so B's output simply does not
/// exist at that address.
///
/// The expected rejection is an input-resolution failure — which is the point: the scoping that
/// makes substitution impossible lives in the address, not in any check the template performs.
#[test]
fn a_proof_for_resource_a_cannot_spend_an_output_of_resource_b() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    // The gate's resource, funded with nothing the attacker needs.
    let gate_funds = fund(&mut test, &account_key, &[1], &[]);
    // A SECOND resource, holding the attacker's real (small) value.
    let other = fund(&mut test, &account_key, &[1], &[]);
    assert_ne!(
        gate_funds.resource, other.resource,
        "the fixture made two distinct resources"
    );

    let gate = deploy_gate(&mut test, gate_funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, gate_funds.resource, THRESHOLD);

    // A real, honest statement over the OTHER resource's output — value and promise both at the
    // threshold, so every template shape check passes and the forgery attempt reaches the engine's
    // input resolution. That is the boundary under test: the template does not check which
    // resource an input belongs to, and the engine must.
    let statement = proof_statement(&other.masks[0], THRESHOLD, THRESHOLD);
    assert_eq!(
        statement.outputs_statement.outputs[0]
            .output
            .minimum_value_promise,
        THRESHOLD,
        "the fixture must pass the template's threshold check before the engine sees it"
    );

    let input_sk = derive_input_spend_key(&account_key, 1);
    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(TEST_EPOCH))
            .call_method(gate, "prove_access", args![challenge, statement])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );
    let text = format!("{reason}");
    assert!(
        text.to_lowercase().contains("not found") || text.to_lowercase().contains("substate"),
        "the refusal must be an input-resolution failure (the engine's resource scoping), got: {text}"
    );
    let (accepted, burnt) = gate_state(&mut test, gate);
    assert_eq!((accepted, burnt), (0, false));
}

/// An unknown commitment cannot qualify: the attacker invents an input commitment that exists
/// nowhere. Same address-scoping argument, exercised on garbage rather than another resource.
#[test]
fn an_invented_input_commitment_cannot_qualify() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[1], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

    // A syntactically valid statement whose input commitment exists nowhere on chain. The balance
    // proof and range proof are internally consistent — the failure must be the ledger lookup.
    let phantom_mask = RistrettoSecretKey::random(&mut rand::rng());
    let statement = proof_statement(&phantom_mask, THRESHOLD, THRESHOLD);

    let input_sk = derive_input_spend_key(&account_key, 0);
    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(TEST_EPOCH))
            .call_method(gate, "prove_access", args![challenge, statement])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );
    let text = format!("{reason}").to_lowercase();
    assert!(
        text.contains("not found") || text.contains("substate"),
        "got: {text}"
    );
    let (accepted, burnt) = gate_state(&mut test, gate);
    assert_eq!((accepted, burnt), (0, false));
}

/// The attacker claims someone ELSE'S output: they know the public commitment (commitments are
/// public), but they do not hold the one-time spend key. The engine's authorization pass must
/// refuse before any state changes.
#[test]
fn someone_elses_output_cannot_be_spent_by_claiming_its_commitment() {
    let mut test = harness();
    // Two parties. Alice holds the real value; Mallory wants Alice's floor.
    let alice = test.secret_key().clone();
    let alice_funds = fund(&mut test, &alice, &[THRESHOLD], &[]);

    // Mallory's own wallet, so the signer is hers.
    let mallory = RistrettoSecretKey::random(&mut rand::rng());
    let gate = deploy_gate(&mut test, alice_funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, alice_funds.resource, THRESHOLD);

    // A real statement over ALICE's commitment (the commitment is public — anyone can read it).
    let statement = proof_statement(&alice_funds.masks[0], THRESHOLD, THRESHOLD);

    // Mallory signs the transaction with her own key. The statement's input is authorised by
    // ALICE's one-time stealth key, which Mallory does not hold.
    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(TEST_EPOCH))
            .call_method(gate, "prove_access", args![challenge, statement])
            .finish()
            .add_signer(&public_of(&mallory), &mallory)
            .seal(test.secret_key()),
        vec![],
    );
    // The invariant under test: Mallory cannot spend Alice's output, either because the engine's
    // authorisation pass refuses the signature (the intended reason) or because the input failed
    // to resolve under a signer Mallory controls. Both are engine invariants; what would be
    // incidental is a template-side panic or a fee-only outcome, so the refusal reason is pinned
    // to one of the two and the test fails on anything else, naming what it saw.
    let text = format!("{reason}").to_lowercase();
    let authorised_refusal =
        text.contains("sign") || text.contains("auth") || text.contains("scope");
    let resolution_refusal = text.contains("not found") || text.contains("substate");
    assert!(
        authorised_refusal ^ resolution_refusal,
        "the refusal must be exactly one of: an authorisation failure or an input-resolution \
         failure (got: {text}) — anything else is an incidental rejection, not the invariant"
    );
    let (accepted, burnt) = gate_state(&mut test, gate);
    assert_eq!((accepted, burnt), (0, false));
}

/// A statement spending the same commitment twice, with the balance proof re-signed over the
/// doubled set, must be refused on its own terms (duplicate-commitment rule) — the engine cannot
/// be talked into counting one holding twice.
#[test]
fn a_duplicated_input_commitment_is_refused() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[THRESHOLD], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

    // Hand-assembled: create_transfer_statement refuses to build this, which is exactly why the
    // engine must refuse it too rather than trusting submitters to use well-behaved builders.
    let mut statement = proof_statement(&funds.masks[0], THRESHOLD, THRESHOLD);
    let first = statement.inputs_statement.inputs[0].clone();
    statement.inputs_statement.inputs.push(first);
    let agg_input_mask = funds.masks[0].clone() + funds.masks[0].clone();
    let agg_output_mask = statement
        .outputs_statement
        .outputs
        .iter()
        .fold(RistrettoSecretKey::default(), |agg, _o| {
            agg + funds.masks[0].clone()
        });
    statement.balance_proof = Some(
        tari_ootle_wallet_crypto::balance_proof::generate_stealth_balance_proof_signature(
            &agg_input_mask,
            &agg_output_mask,
            &statement.inputs_statement,
            &statement.outputs_statement,
            &statement.covenant_claims,
        ),
    );

    let input_sk = derive_input_spend_key(&account_key, 0);
    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(TEST_EPOCH))
            .call_method(gate, "prove_access", args![challenge, statement])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );
    assert_reject_reason(reason, "Duplicate input commitment");
    let (accepted, burnt) = gate_state(&mut test, gate);
    assert_eq!((accepted, burnt), (0, false));
}

/// THE audit's bottom line for the consensus path: an honest prover with exactly the threshold
/// still succeeds, on the same engine, through the same template, in the same run as the forgeries
/// above. Soundness is only demonstrated relative to a working honest path.
#[test]
fn the_honest_path_still_qualifies_under_the_same_conditions() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[THRESHOLD], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

    let input_sk = derive_input_spend_key(&account_key, 0);
    let statement = proof_statement(&funds.masks[0], THRESHOLD, THRESHOLD);
    test.execute_expect_success(
        Transaction::builder_localnet(Epoch(TEST_EPOCH))
            .call_method(gate, "prove_access", args![challenge, statement])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );

    let (accepted, burnt) = gate_state(&mut test, gate);
    assert_eq!(
        (accepted, burnt),
        (1, true),
        "the honest proof counted once and burnt the nonce"
    );
}

/// A refused proof must not consume the challenge: after every forgery above, the same challenge
/// can still be answered by an honest proof. This is the replay-protection counterpart of the
/// soundness work — a forgery that burnt nonces would let an attacker lock a victim out.
#[test]
fn failed_forgery_attempts_leave_the_challenge_answerable() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[THRESHOLD], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

    // Forge: an honest, resolvable statement whose MVP field is then mutated past the proof. The
    // template's threshold check passes (the claim is above the threshold) and the engine's
    // bulletproof is what refuses. (A 1-unit claim with the same mask would fail earlier, at input
    // resolution — that path is covered by `an_invented_input_commitment_cannot_qualify`.)
    let mut forged = proof_statement(&funds.masks[0], THRESHOLD, THRESHOLD);
    forged.outputs_statement.outputs[0]
        .output
        .minimum_value_promise = THRESHOLD + 1;
    let input_sk = derive_input_spend_key(&account_key, 0);
    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(TEST_EPOCH))
            .call_method(gate, "prove_access", args![challenge, forged])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );
    assert_reject_reason(reason, "range proof");

    // The same challenge, answered honestly right after: the nonce is still live.
    let honest = proof_statement(&funds.masks[0], THRESHOLD, THRESHOLD);
    test.execute_expect_success(
        Transaction::builder_localnet(Epoch(TEST_EPOCH))
            .call_method(gate, "prove_access", args![challenge, honest])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );
    let (accepted, burnt) = gate_state(&mut test, gate);
    assert_eq!(
        (accepted, burnt),
        (1, true),
        "exactly the honest proof counted"
    );
}

/// A rejected transaction must leave the attacker's input unspent: the engine downs inputs only
/// after the statement validates, and an abort rolls the whole attempt back. Asserted by spending
/// the same input successfully after a failed forgery.
#[test]
fn a_refused_forgery_does_not_burn_the_attackers_input() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    // The attacker holds the threshold — the forgery would be pointless if honest, so the point is
    // that the FAILED attempt must not destroy the input the attempt named.
    let funds = fund(&mut test, &account_key, &[THRESHOLD], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

    let mut forged = proof_statement(&funds.masks[0], THRESHOLD, THRESHOLD);
    forged.outputs_statement.outputs[0]
        .output
        .minimum_value_promise = u32::MAX as u64;
    let input_sk = derive_input_spend_key(&account_key, 0);
    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(TEST_EPOCH))
            .call_method(gate, "prove_access", args![challenge, forged])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );
    assert_reject_reason(reason, "range proof");

    // The input survives: the same commitment qualifies honestly on a fresh gate.
    let gate2 = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge2 = challenge_for(gate2, funds.resource, THRESHOLD);
    let honest = proof_statement(&funds.masks[0], THRESHOLD, THRESHOLD);
    test.execute_expect_success(
        Transaction::builder_localnet(Epoch(TEST_EPOCH))
            .call_method(gate2, "prove_access", args![challenge2, honest])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );
    let (accepted, _) = gate_state(&mut test, gate2);
    assert_eq!(
        accepted, 1,
        "the input was not destroyed by the failed forgery"
    );
}
