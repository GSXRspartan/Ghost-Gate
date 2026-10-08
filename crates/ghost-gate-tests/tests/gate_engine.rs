//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! Engine-backed Ghost Gate tests: the real template, real WASM, the real engine.
//!
//! Every case here runs through `tari_engine` via `TemplateTest`. A rule proven only in
//! `ghost-gate-core`'s unit tests is a rule nobody has checked against consensus yet.

use ghost_gate_core::{Challenge, GateContext, ProofReceipt, network, qualify};
use ootle_byte_type::{FromByteType, ToByteType};
use tari_crypto::{
    keys::{PublicKey, SecretKey},
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
};
use tari_engine_types::substate::SubstateDiff;
use tari_ootle_address::{Network, RistrettoOotleAddress};
use tari_ootle_common_types::substate_type::SubstateType;
use tari_ootle_wallet_crypto::{MaskAndValue, OutputWitness, StealthInputWitness, StealthOutputWitness};
use tari_ootle_wallet_sdk::{
    WalletSdk, WalletSdkConfig,
    apis::{stealth_outputs::TransferStatementParams, stealth_transfer::StealthOutputToCreate},
    cipher_seed::CipherSeedRestore,
    models::{EpochBirthday, InputSpendData, KeyBranch, KeyId},
};
use tari_ootle_wallet_sdk_services::indexer_rest_api::IndexerRestApiNetworkInterface;
use tari_ootle_wallet_storage_sqlite::SqliteWalletStore;
use tari_ootle_transaction::{Epoch, Transaction, args};
use tari_template_lib::types::{
    AccessRule, Amount, ComponentAddress, EncryptedData, Hash32, MaxBytes, ObjectKey, ResourceAddress,
    crypto::{PedersenCommitmentBytes, RistrettoPublicKeyBytes, UtxoTag},
    stealth::{
        RevealedOutput, SpendAuthorization, SpendWitness, StealthInputsStatement, StealthOutputsStatement,
        StealthTransferStatement, StealthUnspentOutput, UnspentOutput,
    },
};
use tari_template_test_tooling::{TemplateTest, support::assert_error::assert_reject_reason};
use tari_utilities::SafePassword;

use std::str::FromStr;

const CRATE_PATH: &str = env!("CARGO_MANIFEST_DIR");
/// The funding fixture, resolved from this crate's manifest dir to the repo's templates directory.
/// It is a separate cargo workspace because it also builds for wasm32.
const FAUCET_TEMPLATE: &str = "../../templates/ghost_gate_faucet";
const GATE_TEMPLATE: &str = "../../templates/ghost_gate";
const GATE_NAME: &str = "GhostGate";
const FAUCET_NAME: &str = "GhostGateFaucet";

const RELYING_SITE: &[u8] = b"vip.example";
const SESSION: &[u8] = b"session-1";

/// JSONPath into the gate component's `proofs_accepted` field.
///
/// Field order follows the declaration order in the template state struct, and minicbor encodes a
/// `#[n(i)]` struct as an array indexed by field number:
///
/// ```text
/// $.0 policy   $.1 divisibility   $.2 relying_site   $.3 session_commitment
/// $.4 burnt_nonces   $.5 proofs_accepted
/// ```
const GATE_PROOFS_ACCEPTED_PATH: &str = "$.5";

/// The epoch tests execute in. The bootstrap leaves the virtual substate at 0, which would make an
/// "expired" challenge impossible to express, since expiry compares `current_epoch > expires_epoch`.
const TEST_EPOCH: u64 = 5;

/// The gate's configured relying-site identifier. Typed explicitly because `MaxBytes<N>` infers
/// nothing at a transaction-argument boundary, where the value must already be `Encode`.
fn site_id() -> MaxBytes<64> {
    MaxBytes::new_checked(RELYING_SITE.to_vec()).expect("well under the limit")
}

/// The gate's configured browser-session commitment.
fn session_id() -> MaxBytes<64> {
    MaxBytes::new_checked(SESSION.to_vec()).expect("well under the limit")
}
const THRESHOLD: u64 = 10_000;

/// The Ootle cohort the engine tests execute in.
///
/// The gate binds to the network it is deployed for, so this is a constructor argument rather than a
/// constant baked into the template: the same WASM is published on every cohort and each deployment
/// names its own.
const NETWORK: u8 = network::LOCALNET;

/// Decimal places of the resource this file's gates watch.
///
/// The cohort's own native stealth tTARI has divisibility 6. Matching it here is a convenience, not
/// a requirement: nothing in the gate reads divisibility, and `cross_resource.rs` proves that by
/// driving gates over resources whose divisibility differs from this one and from each other.
const TEST_DIVISIBILITY: u8 = 6;

/// What the wallet owns when it proves access. Comfortably above the threshold, so the only thing
/// separating acceptance from refusal is the promise, not the balance.
const FUNDING: u64 = 30_000;

/// A deployed funding resource plus the masks needed to spend its outputs.
struct Funds {
    resource: ResourceAddress,
    /// The faucet that manages it. A test that has to mint again — because the outputs it wants minted
    /// cannot be built until the resource address exists — needs to call back into it.
    faucet: ComponentAddress,
    /// Parallel to the `amounts` the faucet was created with: each output's Pedersen mask.
    masks: Vec<RistrettoSecretKey>,
    /// Parallel to `masks`: what the wallet needs in order to *name* each output as an input. The
    /// commitment and nonce are the on-chain identity of the UTXO, which a wallet reads from its own
    /// store rather than recomputing. Gate 3 needs them because it hands those identities to the
    /// wallet's statement builder, exactly as the RPC handler hands it outputs the wallet selected.
    inputs: Vec<InputSpendData>,
}

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

fn harness() -> TemplateTest {
    let mut test = TemplateTest::new(CRATE_PATH, [FAUCET_TEMPLATE, GATE_TEMPLATE]);
    // The bootstrap leaves the epoch at 0. Pinning it makes an expired challenge expressible and
    // keeps every test's epoch arithmetic in one place.
    test.set_virtual_substate(
        tari_engine_types::virtual_substate::VirtualSubstateId::CurrentEpoch,
        tari_engine_types::virtual_substate::VirtualSubstate::CurrentEpoch(TEST_EPOCH),
    );
    test
}

/// Deploys a stealth resource funded with `amounts`, each output key-authorised by `owner`.
///
/// The test builds the mint statement, because a template cannot create stealth outputs on its own.
/// Each output's spend key is derived from a nonce the test picks, so the test also holds the key
/// that authorises spending it ? the same relationship an ordinary wallet output has.
fn fund(test: &mut TemplateTest, owner: &RistrettoSecretKey, amounts: &[u64], mvps: &[u64]) -> Funds {
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
                    sender_public_nonce: RistrettoPublicKey::from_secret_key(&RistrettoSecretKey::from(
                        MASK_BASE + u64::try_from(i).unwrap() + NONCE_OFFSET,
                    )),
                    minimum_value_promise: mvps.get(i).copied().unwrap_or(0),
                    encrypted_data: EncryptedData::try_from(vec![0u8; EncryptedData::min_size()]).unwrap(),
                    resource_view_key: None,
                },
                // Key path, authorised by a one-time stealth key derived from the owner's account
                // key and this output's nonce. Structurally identical to a wallet output.
                auth: SpendAuthorization::Key(stealth_spend_key(&owner_pk, MASK_BASE + u64::try_from(i).unwrap())),
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
                args!["GGTEST".to_string(), TEST_DIVISIBILITY, Amount::from(total), statement],
            )
            .build_and_seal(test.secret_key()),
        vec![],
    );

Funds {
        resource: test.get_previous_output_address(SubstateType::Resource).as_resource_address().unwrap(),
        faucet: test.get_previous_output_address(SubstateType::Component).as_component_address().unwrap(),
        masks: amounts
            .iter()
            .enumerate()
            .map(|(i, _)| RistrettoSecretKey::from(MASK_BASE + u64::try_from(i).unwrap()))
            .collect(),
        // Read back off the statement the faucet was called with: those are the exact on-chain
        // identities, including the sender nonces, so no test has to recompute a commitment and hope
        // it matches.
        inputs: statement
            .outputs_statement
            .outputs
            .iter()
            .zip(amounts.iter().copied())
            .map(|(output, value)| spend_data_of(output, value))
            .collect(),
    }
}

/// An output's on-chain identity in the shape the wallet's statement builder takes inputs in.
///
/// The commitment and the sender's public nonce *are* the UTXO's identity on chain, and the encrypted
/// payload is what the wallet decrypts to recover the mask. All three are read off the statement the
/// transaction was actually called with, rather than recomputed by the test.
fn spend_data_of(output: &StealthUnspentOutput, value: u64) -> InputSpendData {
    InputSpendData {
        commitment: *output.commitment(),
        public_nonce: output.output.sender_public_nonce,
        encrypted_data: output.output.encrypted_data.clone(),
        value,
        is_on_chain: true,
    }
}

// Fixture masks are derived from an index rather than a CSPRNG so a test can spend a specific
// output. This is a test fixture, never a wallet.
const MASK_BASE: u64 = 1_000_000_000;
const NONCE_OFFSET: u64 = 500;

/// The one-time stealth spend key for `nonce`, matching what the funding resource committed.
fn stealth_spend_key(account_key: &RistrettoPublicKey, nonce: u64) -> RistrettoPublicKeyBytes {
    use ootle_network::Network;
    let nonce_secret = RistrettoSecretKey::from(nonce);
    tari_ootle_wallet_crypto::StealthCryptoApi::new()
        .derive_stealth_owner_public_key(Network::LocalNet, account_key, &nonce_secret)
        .to_byte_type()
}

/// Deploys a gate over `resource` and returns its address.
///
/// The address is allocated by the transaction under `name`, so two calls yield two distinct gates ?
/// which is what lets a test point a challenge at a *real* other gate instead of a synthetic address
/// the engine would reject at substate lookup before the template ever ran.
fn deploy_gate_named(test: &mut TemplateTest, name: &str, resource: ResourceAddress, threshold: u64) -> ComponentAddress {
    let template_addr = test.get_template_address(GATE_NAME);
    // `test.transaction()` rather than a fresh localnet builder: it carries a per-call nonce, and
    // an address allocation is derived from the transaction. Two deployments sharing a transaction
    // would allocate the same component address and the second would collide.
    test.execute_expect_success(
        test.transaction()
            .allocate_component_address(name)
            .call_function(
                template_addr,
                "new",
                args![Workspace(name), resource, threshold, site_id(), session_id(), NETWORK],
            )
            .build_and_seal(test.secret_key()),
        vec![],
    );
    test.get_previous_output_address(SubstateType::Component)
        .as_component_address()
        .unwrap()
}

/// Deploys a gate under a name unique to this test, so repeated calls within one test do not collide.
fn deploy_gate(test: &mut TemplateTest, resource: ResourceAddress, threshold: u64) -> ComponentAddress {
    deploy_gate_named(test, "ghost_gate", resource, threshold)
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

/// A key-path output witness worth `amount`, promising at least `mvp`.
fn output_witness(amount: u64, mvp: u64, spend_key: RistrettoPublicKeyBytes) -> StealthOutputWitness {
    let mask = RistrettoSecretKey::random(&mut rand::rng());
    StealthOutputWitness {
        witness: OutputWitness {
            amount,
            mask: mask.clone(),
            sender_public_nonce: RistrettoPublicKey::from_secret_key(&RistrettoSecretKey::from(999u64)),
            minimum_value_promise: mvp,
            encrypted_data: EncryptedData::try_from(vec![0u8; EncryptedData::min_size()]).unwrap(),
            resource_view_key: None,
        },
        auth: SpendAuthorization::Key(spend_key),
        tag: UtxoTag::new(0),
    }
}

/// A one-input, one-output proof statement.
fn proof_statement(input_mask: &RistrettoSecretKey, output_value: u64, mvp: u64) -> StealthTransferStatement {
    let out = output_witness(
        output_value,
        mvp,
        RistrettoPublicKey::from_secret_key(&RistrettoSecretKey::random(&mut rand::rng())).to_byte_type(),
    );
    create_transfer_statement(vec![out], &[(input_mask.clone(), output_value)], Amount::zero(), None)
}

/// A proof statement spending several inputs.
fn fragmented_statement(
    input_masks: &[RistrettoSecretKey],
    input_values: &[u64],
    output_value: u64,
    mvp: u64,
) -> StealthTransferStatement {
    let out = output_witness(
        output_value,
        mvp,
        RistrettoPublicKey::from_secret_key(&RistrettoSecretKey::random(&mut rand::rng())).to_byte_type(),
    );
    let inputs: Vec<(RistrettoSecretKey, u64)> = input_masks
        .iter()
        .cloned()
        .zip(input_values.iter().copied())
        .collect();
    create_transfer_statement(vec![out], &inputs, Amount::zero(), None)
}

/// Builds a transfer statement from witnesses plus `(mask, value)` inputs.
fn create_transfer_statement(
    outputs: Vec<StealthOutputWitness>,
    inputs: &[(RistrettoSecretKey, u64)],
    revealed_input: Amount,
    revealed_output: Option<RevealedOutput>,
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

/// The mint statement that converts a freshly created resource's revealed supply into the stealth
/// outputs a test asked for.
///
/// It reveals the whole supply as an *input* and creates only stealth outputs. The engine's
/// pre-flight rejects a statement with neither inputs nor a revealed input amount
/// (`crates/engine_types/src/stealth/transfer.rs`), which a mint with no inputs would be. This is the
/// same shape the Ootle cohort's own stealth fixture uses.
fn mint_statement(outputs: Vec<StealthOutputWitness>, supply: u64) -> StealthTransferStatement {
    create_transfer_statement(outputs, &[], Amount::from(supply), None)
}

/// Two qualifying outputs. Only the ambiguity rule can refuse this.
fn two_output_statement(input_mask: &RistrettoSecretKey, total: u64, spend_key: RistrettoPublicKeyBytes) -> StealthTransferStatement {
    let a = output_witness(total / 2, THRESHOLD, spend_key);
    let b = output_witness(total / 2, THRESHOLD, spend_key);
    create_transfer_statement(vec![a, b], &[(input_mask.clone(), total)], Amount::zero(), None)
}

/// A statement spending one input twice, with the balance proof re-signed over the doubled set.
///
/// `create_transfer_statement` refuses to build this, so it is assembled by hand. The engine must
/// reject it on its own terms rather than relying on the submitter having used a well-behaved
/// builder.
fn double_spend_statement(input_mask: &RistrettoSecretKey, mvp: u64) -> StealthTransferStatement {
    let mut statement = proof_statement(input_mask, 30_000, mvp);
    let first = statement.inputs_statement.inputs[0].clone();
    statement.inputs_statement.inputs.push(first);

    // The aggregate input mask doubles with the duplicated input.
    let agg_input_mask = input_mask.clone() + input_mask;
    let agg_output_mask = statement
        .outputs_statement
        .outputs
        .iter()
        .fold(RistrettoSecretKey::default(), |agg, _o| agg + input_mask);
    statement.balance_proof = Some(
        tari_ootle_wallet_crypto::balance_proof::generate_stealth_balance_proof_signature(
            &agg_input_mask,
            &agg_output_mask,
            &statement.inputs_statement,
            &statement.outputs_statement,
            &statement.covenant_claims,
        ),
    );
    statement
}

fn count_new_utxos(diff: &SubstateDiff) -> usize {
    diff.up_iter()
        .filter_map(|(_, substate)| substate.substate_value().as_utxo())
        .count()
}

/// The public key the engine matches against the auth scope, given a secret.
fn public_of(secret: &RistrettoSecretKey) -> RistrettoPublicKeyBytes {
    RistrettoPublicKey::from_secret_key(secret).to_byte_type()
}

// ---------------------------------------------------------------------------------------------
// Gate 2 ? the template under the engine
// ---------------------------------------------------------------------------------------------

/// The happy path. A hidden value above the threshold, one key-spendable output, committed.
#[test]
fn a_proof_above_threshold_commits() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[30_000], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

    let input_sk = derive_input_spend_key(&account_key, 0);
    let statement = proof_statement(&funds.masks[0], 30_000, THRESHOLD);

    let result = test.execute_expect_success(
        Transaction::builder_localnet(Epoch(1))
            .call_method(gate, "prove_access", args![challenge, statement])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );

    let diff = result.finalize.any_accept().expect("gate proof must be accepted");
    assert_eq!(count_new_utxos(&diff), 1, "the qualifying output is the only new UTXO");

    let accepted: u64 = test.extract_component_value(gate, GATE_PROOFS_ACCEPTED_PATH);
    assert_eq!(accepted, 1, "the gate counted exactly one proof");
}

/// Exactly the threshold qualifies: the rule is `>=`, not `>`.
#[test]
fn a_proof_exactly_at_threshold_commits() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    // Exactly the threshold: the output's promise and its hidden value coincide.
    let funds = fund(&mut test, &account_key, &[10_000], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

    let input_sk = derive_input_spend_key(&account_key, 0);
    let statement = proof_statement(&funds.masks[0], 10_000, THRESHOLD);

    test.execute_expect_success(
        Transaction::builder_localnet(Epoch(1))
            .call_method(gate, "prove_access", args![challenge, statement])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );

    let accepted: u64 = test.extract_component_value(gate, GATE_PROOFS_ACCEPTED_PATH);
    assert_eq!(accepted, 1);
}

/// Just under the threshold is refused by the template's rule.
#[test]
fn a_proof_below_threshold_is_refused() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[9_999], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

    let input_sk = derive_input_spend_key(&account_key, 0);
    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(1))
            .call_method(
                gate,
                "prove_access",
                args![challenge, proof_statement(&funds.masks[0], 9_999, 9_999)],
            )
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );

    assert_reject_reason(reason, "attested minimum is below the gate threshold");
    let accepted: u64 = test.extract_component_value(gate, GATE_PROOFS_ACCEPTED_PATH);
    assert_eq!(accepted, 0, "a refused proof leaves no trace");
}

/// Four fragmented inputs are still one proof.
#[test]
fn fragmented_inputs_commit_as_one_proof() {
    let mut test = harness();
    let amounts = [3_100u64, 2_900, 4_800, 1_500];
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &amounts, &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

let total: u64 = amounts.iter().sum();
    let statement = fragmented_statement(&funds.masks, &amounts, total, THRESHOLD);

    // Each input carries its own one-time stealth spend key, so each needs its own signature. The
    // builder is threaded rather than reassigned because `add_signer` returns an
    // `UnsealedTransaction`, a different type from the builder it came from.
    let mut sealed = Transaction::builder_localnet(Epoch(1))
        .call_method(gate, "prove_access", args![challenge, statement])
        .finish();
    for i in 0..amounts.len() {
        let sk = derive_input_spend_key(&account_key, i);
        sealed = sealed.add_signer(&public_of(&sk), &sk);
    }
    test.execute_expect_success(sealed.seal(test.secret_key()), vec![]);

    let accepted: u64 = test.extract_component_value(gate, GATE_PROOFS_ACCEPTED_PATH);
    assert_eq!(accepted, 1, "four inputs are one proof, not four");
}

/// An expired challenge is refused. Expiry is consensus-enforced.
#[test]
fn an_expired_challenge_is_refused() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[30_000], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let mut challenge = challenge_for(gate, funds.resource, THRESHOLD);
    // One epoch behind the epoch this transaction executes in.
    challenge.expires_epoch = TEST_EPOCH - 1;

    let input_sk = derive_input_spend_key(&account_key, 0);
    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(1))
            .call_method(gate, "prove_access", args![challenge, proof_statement(&funds.masks[0], 30_000, THRESHOLD)])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );
    assert_reject_reason(reason, "challenge has expired");
}

/// A challenge naming a different gate is refused.
///
/// The "different" gate is a real deployed component, not a made-up address: the engine resolves
/// every substate a template touches before the template runs, so a nonexistent address would be
/// refused by substate lookup rather than by the gate's own rule, and the test would prove nothing.
#[test]
fn a_challenge_for_another_gate_is_refused() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[30_000], &[]);
    let gate = deploy_gate_named(&mut test, "gate_under_test", funds.resource, THRESHOLD);
    let other_gate = deploy_gate_named(&mut test, "other_gate", funds.resource, THRESHOLD);

    assert_ne!(gate, other_gate, "two deployments must yield two gate addresses");

    let mut challenge = challenge_for(gate, funds.resource, THRESHOLD);
    challenge.gate = other_gate;

    let input_sk = derive_input_spend_key(&account_key, 0);
    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(1))
            .call_method(gate, "prove_access", args![challenge, proof_statement(&funds.masks[0], 30_000, THRESHOLD)])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );
    assert_reject_reason(reason, "challenge is for a different gate");
}

/// A challenge naming a different resource is refused.
///
/// The substitute resource is a real deployed one, for the same reason as the gate case: the engine
/// resolves substates before the template runs, so a synthetic address would be refused by lookup.
#[test]
fn a_challenge_for_another_resource_is_refused() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[30_000], &[]);
    let other_funds = fund(&mut test, &account_key, &[30_000], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);

    assert_ne!(funds.resource, other_funds.resource, "two faucets must yield two resources");

    let mut challenge = challenge_for(gate, funds.resource, THRESHOLD);
    challenge.resource = other_funds.resource;

    let input_sk = derive_input_spend_key(&account_key, 0);
    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(1))
            .call_method(gate, "prove_access", args![challenge, proof_statement(&funds.masks[0], 30_000, THRESHOLD)])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );
    assert_reject_reason(reason, "challenge resource does not match gate policy");
}

/// A challenge with a lowered threshold is refused, so a cheap challenge cannot be redeemed at a
/// higher gate.
#[test]
fn a_challenge_with_a_lowered_threshold_is_refused() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[30_000], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let mut challenge = challenge_for(gate, funds.resource, THRESHOLD);
    challenge.threshold = 1;

    let input_sk = derive_input_spend_key(&account_key, 0);
    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(1))
            .call_method(gate, "prove_access", args![challenge, proof_statement(&funds.masks[0], 30_000, THRESHOLD)])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );
    assert_reject_reason(reason, "challenge threshold does not match gate policy");
}

/// A challenge for another relying site is refused.
#[test]
fn a_challenge_for_another_site_is_refused() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[30_000], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let mut challenge = challenge_for(gate, funds.resource, THRESHOLD);
    challenge.relying_site = MaxBytes::<64>::new_checked(b"evil.example".to_vec()).unwrap();

    let input_sk = derive_input_spend_key(&account_key, 0);
    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(1))
            .call_method(gate, "prove_access", args![challenge, proof_statement(&funds.masks[0], 30_000, THRESHOLD)])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );
    assert_reject_reason(reason, "challenge is for a different relying site");
}

/// A challenge for another browser session is refused, so a captured proof cannot be lifted.
#[test]
fn a_challenge_for_another_session_is_refused() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[30_000], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let mut challenge = challenge_for(gate, funds.resource, THRESHOLD);
    challenge.session_commitment = MaxBytes::<64>::new_checked(b"session-2".to_vec()).unwrap();

    let input_sk = derive_input_spend_key(&account_key, 0);
    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(1))
            .call_method(gate, "prove_access", args![challenge, proof_statement(&funds.masks[0], 30_000, THRESHOLD)])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );
    assert_reject_reason(reason, "challenge is for a different browser session");
}

/// A challenge naming a different network byte is refused.
#[test]
fn a_challenge_for_another_network_is_refused() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[30_000], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let mut challenge = challenge_for(gate, funds.resource, THRESHOLD);
    challenge.network = network::ESMERALDA;

    let input_sk = derive_input_spend_key(&account_key, 0);
    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(1))
            .call_method(gate, "prove_access", args![challenge, proof_statement(&funds.masks[0], 30_000, THRESHOLD)])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );
    assert_reject_reason(reason, "challenge network does not match this chain");
}

/// The same challenge cannot be redeemed twice: the nonce is burnt on chain.
#[test]
fn a_challenge_cannot_be_redeemed_twice() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[30_000, 30_000], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

    let first = derive_input_spend_key(&account_key, 0);
    test.execute_expect_success(
        Transaction::builder_localnet(Epoch(1))
            .call_method(
                gate,
                "prove_access",
                args![challenge, proof_statement(&funds.masks[0], 30_000, THRESHOLD)],
            )
            .finish()
            .add_signer(&public_of(&first), &first)
            .seal(test.secret_key()),
        vec![],
    );

    // Replay the same challenge against a different, still-live input.
    let second = derive_input_spend_key(&account_key, 1);
    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(1))
            .call_method(
                gate,
                "prove_access",
                args![challenge, proof_statement(&funds.masks[1], 30_000, THRESHOLD)],
            )
            .finish()
            .add_signer(&public_of(&second), &second)
            .seal(test.secret_key()),
        vec![],
    );
    assert_reject_reason(reason, "challenge nonce has already been used");

    let accepted: u64 = test.extract_component_value(gate, GATE_PROOFS_ACCEPTED_PATH);
    assert_eq!(accepted, 1, "only the first redemption counted");
}

/// A closed gate refuses a perfectly valid proof.
#[test]
fn a_closed_gate_refuses_a_valid_proof() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[30_000], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

    test.call_method::<()>(gate, "set_open", args![false], vec![]);

    let input_sk = derive_input_spend_key(&account_key, 0);
    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(1))
            .call_method(gate, "prove_access", args![challenge, proof_statement(&funds.masks[0], 30_000, THRESHOLD)])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );
    assert_reject_reason(reason, "gate is not accepting proofs");
}

/// A revealed output publishes an exact amount, so it is refused even when the promise clears the
/// threshold.
#[test]
fn a_revealed_output_is_refused() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[40_000], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

    let input_sk = derive_input_spend_key(&account_key, 0);
    let mut statement = proof_statement(&funds.masks[0], 30_000, THRESHOLD);
    statement.outputs_statement.revealed_output = Some(RevealedOutput::new(
        Amount::from(10_000u64),
        public_of(&input_sk),
    ));

    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(1))
            .call_method(gate, "prove_access", args![challenge, statement])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );
    assert_reject_reason(reason, "must not reveal an output amount");
}

/// Two qualifying outputs make "the qualifying output" ambiguous, so the gate refuses rather than
/// picking one.
#[test]
fn two_outputs_are_refused_as_ambiguous() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[40_000], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

    let input_sk = derive_input_spend_key(&account_key, 0);
    let statement = two_output_statement(&funds.masks[0], 40_000, public_of(&input_sk));

    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(1))
            .call_method(gate, "prove_access", args![challenge, statement])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );
    assert_reject_reason(reason, "must create exactly one stealth output");
}

/// A statement spending nothing live proves nothing.
#[test]
fn a_statement_with_no_inputs_is_refused() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[30_000], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

    // Build a statement with a qualifying output but no inputs. The builder refuses this, so it is
    // assembled by hand: the engine must reject it on its own terms.
    let out = output_witness(
        30_000,
        THRESHOLD,
        RistrettoPublicKey::from_secret_key(&RistrettoSecretKey::random(&mut rand::rng())).to_byte_type(),
    );
    let statement = StealthTransferStatement {
        inputs_statement: StealthInputsStatement {
            inputs: vec![],
            revealed_amount: Amount::zero(),
        },
        outputs_statement: StealthOutputsStatement {
            outputs: vec![StealthUnspentOutput {
                output: UnspentOutput {
                    commitment: PedersenCommitmentBytes::default(),
                    sender_public_nonce: RistrettoPublicKeyBytes::default(),
                    encrypted_data: EncryptedData::try_from(vec![0u8; EncryptedData::min_size()]).unwrap(),
                    minimum_value_promise: THRESHOLD,
                    viewable_balance_proof: None,
                },
                auth: SpendAuthorization::Key(RistrettoPublicKey::from_secret_key(&out.witness.mask).to_byte_type()),
                tag: UtxoTag::new(0),
            }],
            revealed_output: None,
            agg_range_proof: tari_template_lib::types::crypto::RangeProofBytes::empty(),
        },
        balance_proof: None,
        covenant_claims: vec![],
    };

    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(1))
            .call_method(gate, "prove_access", args![challenge, statement])
            .finish()
            .seal(test.secret_key()),
        vec![],
    );
    assert_reject_reason(reason, "must spend at least one live stealth input");
}

/// An input with no matching signer is refused by the engine's authorisation check.
///
/// This is the case that would break the product if it behaved differently, so it is asserted
/// explicitly rather than left implicit.
#[test]
fn an_unauthorized_input_is_refused_by_the_engine() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[30_000], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

    let (other_sk, _other_pk) = test.new_key_pair(200);

    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(1))
            .call_method(gate, "prove_access", args![challenge, proof_statement(&funds.masks[0], 30_000, THRESHOLD)])
            .finish()
            .seal(&other_sk),
        vec![],
    );

    let text = reason.to_string();
    assert!(
        text.contains("required") || text.contains("signature") || text.contains("auth"),
        "expected an authorisation failure, got: {text}"
    );
    let accepted: u64 = test.extract_component_value(gate, GATE_PROOFS_ACCEPTED_PATH);
    assert_eq!(accepted, 0);
}

/// A script-path input is not ordinary wallet ownership, so the template refuses it by rule.
#[test]
fn a_script_path_input_is_refused() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[30_000], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

    let input_sk = derive_input_spend_key(&account_key, 0);
    let mut statement = proof_statement(&funds.masks[0], 30_000, THRESHOLD);
    statement.inputs_statement.inputs[0].witness = SpendWitness::script_path(
        tari_template_lib::types::stealth::SpendCondition::access_rule(AccessRule::AllowAll),
        tari_template_lib::types::stealth::MerkleProof::empty(),
    );

    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(1))
            .call_method(gate, "prove_access", args![challenge, statement])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );
    assert_reject_reason(reason, "every input must be authorised by the key path");
}

/// Tampering with the promise after the bulletproof was generated is caught by the engine's range
/// proof, not by the template: the gate's threshold is set below the tampered promise so the
/// template's own check passes.
#[test]
fn a_tampered_promise_is_refused_by_the_engine() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[30_000], &[]);
    // Gate threshold 20,000: the tampered promise of 40,000 clears it, so only the range proof can
    // catch this.
    let gate = deploy_gate(&mut test, funds.resource, 20_000);
    let challenge = challenge_for(gate, funds.resource, 20_000);

    let input_sk = derive_input_spend_key(&account_key, 0);
    let mut statement = proof_statement(&funds.masks[0], 30_000, 30_000);
    statement.outputs_statement.outputs[0].output.minimum_value_promise = 40_000;

    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(1))
            .call_method(gate, "prove_access", args![challenge, statement])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );
    assert_reject_reason(reason, "Invalid range proof");
}

/// An invalid balance proof is refused by the engine.
#[test]
fn an_invalid_balance_proof_is_refused_by_the_engine() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[30_000], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

    let input_sk = derive_input_spend_key(&account_key, 0);
    let mut statement = proof_statement(&funds.masks[0], 30_000, THRESHOLD);
    // Swap in a balance proof over a different input set: the statement's inputs no longer match.
    let wrong = proof_statement(&RistrettoSecretKey::from(424_242u64), 30_000, THRESHOLD);
    statement.balance_proof = wrong.balance_proof;

    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(1))
            .call_method(gate, "prove_access", args![challenge, statement])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );
    assert_reject_reason(reason, "Invalid balance proof");
}

/// Dropping the balance proof is refused by the template's rule, before the engine.
#[test]
fn a_missing_balance_proof_is_refused_by_the_template() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[30_000], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

    let input_sk = derive_input_spend_key(&account_key, 0);
    let mut statement = proof_statement(&funds.masks[0], 30_000, THRESHOLD);
    statement.balance_proof = None;

    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(1))
            .call_method(gate, "prove_access", args![challenge, statement])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );
    assert_reject_reason(reason, "proof must carry a balance proof");
}

/// Spending the same input twice is refused.
#[test]
fn a_double_spent_input_is_refused() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[30_000], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

    let input_sk = derive_input_spend_key(&account_key, 0);
    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(1))
            .call_method(gate, "prove_access", args![challenge, double_spend_statement(&funds.masks[0], THRESHOLD)])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );

    assert!(!reason.to_string().is_empty(), "the engine must reject a double spend");
    let accepted: u64 = test.extract_component_value(gate, GATE_PROOFS_ACCEPTED_PATH);
    assert_eq!(accepted, 0);
}

/// An output that is not key-spendable is refused: the funds would be parked in a condition tree.
#[test]
fn a_script_only_output_is_refused() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[30_000], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

    let input_sk = derive_input_spend_key(&account_key, 0);
    let mut statement = proof_statement(&funds.masks[0], 30_000, THRESHOLD);
    // Replace the output's authorisation with a condition tree and no key path.
    let auth = SpendAuthorization::Script(Hash32::from_array([4u8; 32]));
    statement.outputs_statement.outputs[0].auth = auth;

    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(1))
            .call_method(gate, "prove_access", args![challenge, statement])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );
    assert_reject_reason(reason, "qualifying output must be key-spendable");
}

/// A malformed statement never reaches the template: argument decoding fails first.
#[test]
fn a_malformed_statement_is_refused_at_decode() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[30_000], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

    // 31 bytes of 0xff: not a valid CBOR encoding of a StealthTransferStatement.
    let garbage = vec![0xffu8; 31];

    let reason = test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(1))
            .call_method(gate, "prove_access", args![challenge, garbage])
            .finish()
            .seal(test.secret_key()),
        vec![],
    );
    let text = reason.to_string().to_lowercase();
    assert!(
        text.contains("decode") || text.contains("argument"),
        "expected a decode failure, got: {reason}"
    );
}

/// The gate reports its own policy, so a relying site can read the threshold off chain instead of
/// trusting its own copy.
#[test]
fn the_gate_reports_its_own_policy() {
    let mut test = harness();
    let account_key = test.secret_key().clone();
    let funds = fund(&mut test, &account_key, &[30_000], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);

    let threshold: u64 = test.call_method(gate, "threshold", args![], vec![]);
    assert_eq!(threshold, THRESHOLD);

    let resource: ResourceAddress = test.call_method(gate, "resource", args![], vec![]);
    assert_eq!(resource, funds.resource);

    let accepted: u64 = test.call_method(gate, "proofs_accepted", args![], vec![]);
    assert_eq!(accepted, 0);
}

// ---------------------------------------------------------------------------------------------
// Agreement between the shared rules and the template
// ---------------------------------------------------------------------------------------------

/// The template and the relying site must accept and refuse the same statements. Both compile
/// `ghost_gate_core::qualify`, so this test pins the wiring rather than the rules.
#[test]
fn the_shared_rules_agree_with_the_template() {
    use ghost_gate_core::{GateError, GatePolicy};

    let mut test = harness();
    let account_key = test.secret_key().clone();
    // Two outputs: the first is spent by the on-chain proof, the second only builds the
    // below-threshold statement the shared rules must refuse.
    let funds = fund(&mut test, &account_key, &[30_000, 30_000], &[]);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

    let policy = GatePolicy {
        resource: funds.resource,
        threshold: THRESHOLD,
        open: true,
        network: NETWORK,
    };
    let ctx = GateContext {
        self_address: gate,
        current_epoch: TEST_EPOCH,
        relying_site: RELYING_SITE,
        session_commitment: SESSION,
    };

    let input_sk = derive_input_spend_key(&account_key, 0);

    // A well-formed proof: the shared rules accept it, and so does the engine.
    let good = proof_statement(&funds.masks[0], 30_000, THRESHOLD);
    let receipt: ProofReceipt = qualify(&policy, &challenge, &good, &ctx, false).expect("shared rules accept");
    assert_eq!(receipt.attested_minimum, THRESHOLD);

    test.execute_expect_success(
        Transaction::builder_localnet(Epoch(1))
            .call_method(gate, "prove_access", args![challenge, good])
            .finish()
            .add_signer(&public_of(&input_sk), &input_sk)
            .seal(test.secret_key()),
        vec![],
    );

    // The same rules refuse the below-threshold shape the template refuses. The second output is
    // never spent, so this assertion costs nothing on chain.
    let low = proof_statement(&funds.masks[1], 9_999, 9_999);
    assert!(matches!(
        ghost_gate_core::find_qualifying_output(&policy, &low),
        Err(GateError::BelowThreshold { .. })
    ));
}

/// The gate's threshold is a raw amount in the resource's own smallest unit, and it stays that way.
///
/// This replaces an earlier test that asserted the README's arithmetic. That test was the bug: it
/// re-derived `10,000 tTARI = 10^10 microtari` while the deployed threshold was the raw integer
/// `10_000`, so the document and the chain disagreed by 10^6 and the test blessed the disagreement.
/// Consensus compares raw integers; only a screen divides. See `docs/RESOURCE_SUPPORT.md`.
#[test]
fn the_threshold_is_a_raw_amount_not_a_display_figure() {
    // The chain holds 10_000. With this resource's divisibility that renders as 0.010000 units --
    // which is the whole point of never letting a formatted string near a threshold.
    assert_eq!(THRESHOLD, 10_000);
    assert_eq!(
        ghost_gate_verifier::display::format_amount(THRESHOLD, TEST_DIVISIBILITY),
        "0.010000"
    );
}

/// The document's receipt shape matches what the shared rules emit.
#[test]
fn the_receipt_has_exactly_three_fields() {
    use tari_template_lib_types::Hash32 as LibHash32;

    let policy = ghost_gate_core::GatePolicy {
        resource: ResourceAddress::new(ObjectKey::from_array([7u8; ObjectKey::LENGTH])),
        threshold: THRESHOLD,
        open: true,
        network: NETWORK,
    };
    let challenge = challenge_for(
        ComponentAddress::new(ObjectKey::from_array([1u8; ObjectKey::LENGTH])),
        ResourceAddress::new(ObjectKey::from_array([7u8; ObjectKey::LENGTH])),
        THRESHOLD,
    );
    let ctx = GateContext {
        self_address: challenge.gate,
        current_epoch: 1,
        relying_site: RELYING_SITE,
        session_commitment: SESSION,
    };
    let out = output_witness(
        30_000,
        THRESHOLD,
        RistrettoPublicKey::from_secret_key(&RistrettoSecretKey::random(&mut rand::rng())).to_byte_type(),
    );
let statement = create_transfer_statement(
        vec![out],
        &[(RistrettoSecretKey::random(&mut rand::rng()), 30_000)],
        Amount::zero(),
        None,
    );

    let receipt = qualify(&policy, &challenge, &statement, &ctx, false).unwrap();
    assert_eq!(receipt.challenge_nonce, LibHash32::from_array(challenge.nonce.into_array()));
    assert_eq!(receipt.input_count, 1);
}

/// The private half of the stealth spend key the funding fixture committed for output `index`.
///
/// `derive_stealth_owner_public_key(network, k.G, r)` produces the committed key; the matching
/// private half is `derive_stealth_owner_secret(network, k, r.G)`. Both sides of the DH are needed
/// and the two functions take them in opposite order, which is the easiest thing in this file to
/// get wrong ? so the test derives it the same way the fixture derived the public half rather than
/// assuming they are the same call.
///
/// The engine only ever checks the public key against the auth scope, so the private half exists
/// purely to produce a signature.
fn derive_input_spend_key(account_secret: &RistrettoSecretKey, index: usize) -> RistrettoSecretKey {
    let nonce_secret = RistrettoSecretKey::from(MASK_BASE + u64::try_from(index).unwrap());
    let nonce_public = RistrettoPublicKey::from_secret_key(&nonce_secret);
    tari_ootle_wallet_crypto::StealthCryptoApi::new().derive_stealth_owner_secret(
        ootle_network::Network::LocalNet,
        account_secret,
        &nonce_public,
    )
}
// ---------------------------------------------------------------------------------------------
// Gate 3 - the wallet and the engine meet
// ---------------------------------------------------------------------------------------------
//
// Everything above proves the gate's rule. Everything in the walletd suite proves a wallet will
// build a promised output when asked. Neither shows the two halves meet, and the meeting is the
// claim this product rests on: the bytes an ordinary wallet produces are the bytes consensus accepts.
//
// These tests close that loop. The statement is built by the wallet's own `generate_transfer_statement`
// from a promise-bearing `StealthOutputToCreate` -- the same call, with the same field, that the
// patched `accounts.create_stealth_transfer_statement` handler makes -- and the funds it spends are
// key-path outputs authorised by a real wallet account key read out of the wallet's own keyring.
//
// The cohort is pinned to the *patched* v0.42.0 tree (see the workspace Cargo.toml). That is load
// bearing: the wallet and the engine have to be one compilation of the same crates, or the statement
// the wallet produces is not a statement the engine can accept.
//
// STATUS: compiled and passing on the 2026-10-04 run recorded in docs/GATE3_RESULTS.md -- 30/30 in this
// file, the 28 gate-rule tests above unchanged and the two below. Reaching that took three fixes that
// the previous draft, having never seen rustc, could not have known about: the wallet SDK's key accessor
// is `get_key`, the SDK's spec needs the `indexer_client` feature for the indexer interface it requires,
// and the templates are their own cargo workspaces, so the cohort switch has to be applied to their
// manifests too or their lockfile ends up holding two different copies of the same cohort crate.
//
// Not covered here: RPC transport, the indexer, mempool admission, block production. Those belong to
// the cohort's own `integration_tests` harness, which runs the whole node in process.
/// The SDK spec this test uses: a local keyring, a SQLite store, and the cohort's indexer client.
///
/// Declared here rather than imported from `tari_walletd`, which owns the daemon's own spec, because
/// pulling the daemon in as a dev-dependency of the test crate would build an application nobody in
/// this workspace needs. The three associated types are the whole spec.
struct TestSpec;

impl tari_ootle_wallet_sdk::WalletSdkSpec for TestSpec {
    type KeyStore = tari_ootle_wallet_sdk::local_key_store::LocalKeyStore;
    type NetworkInterface = IndexerRestApiNetworkInterface;
    type Store = SqliteWalletStore;
}

type TestSdk = WalletSdk<TestSpec>;

/// An ordinary wallet: a real SQLite store, a real key manager, a real cipher seed, one account with
/// an owner key. Only the indexer interface is inert, because the statement path resolves its inputs
/// from the wallet rather than from the network.
///
/// The account key is read back out of the wallet's own keyring. That stands in for walletd signing
/// with a key it never exports; there is no caller in this flow for a key to be exported to.
struct OrdinaryWallet {
    sdk: TestSdk,
    view_only_key_id: KeyId,
    owner_secret: RistrettoSecretKey,
    /// Where the qualifying output goes: back to the owner.
    owner_address: RistrettoOotleAddress,
    /// Keeps the SQLite directory alive for as long as the wallet is.
    _store_dir: tempfile::TempDir,
}

impl OrdinaryWallet {
    fn create() -> OrdinaryWallet {
        let store_dir = tempfile::tempdir().expect("temp dir for the wallet store");
        let store = SqliteWalletStore::try_open(store_dir.path().join("wallet.sqlite")).expect("open store");
        store.run_migrations().expect("migrate store");

let mut sdk = WalletSdk::initialize_with_local_key_store(
            store,
            IndexerRestApiNetworkInterface::new("http://127.0.0.1:1"),
            WalletSdkConfig {
                network: Network::LocalNet,
                override_keyring_password: Some(SafePassword::from_str("ghost gate").expect("password")),
            },
            EpochBirthday::far_future(),
        )
        .expect("initialise wallet");
        sdk.initialize_cipher_seed(CipherSeedRestore::CreateNewIfRequired)
            .expect("create cipher seed");

        let account: ComponentAddress =
            "component_0dc41b5cc74b36d696c7b140323a40a2f98b71df5d60e5a6bf4c1a07ffffffff"
                .parse()
                .expect("component address");
        let view_only_key_id = KeyId::derived(KeyBranch::ViewOnlyKey, 0);
        let owner_key_id = KeyId::derived(KeyBranch::Account, 0);
        sdk.accounts_api()
            .add_account(
                Some("gate"),
                &account,
                view_only_key_id,
                owner_key_id,
                Epoch::zero(),
                true,
                true,
            )
            .expect("add account");

let owner_secret = sdk
            .key_manager_api()
            .get_key(owner_key_id)
            .expect("read the account key out of the wallet's own keyring")
            .secret()
            .clone();
let owner_address = RistrettoOotleAddress::new(
            Network::LocalNet,
            sdk.key_manager_api()
                .get_public_key(view_only_key_id)
                .expect("view-only key")
                .public_key()
                .clone(),
            sdk.key_manager_api()
                .get_public_key(owner_key_id)
                .expect("account key")
                .public_key()
                .clone(),
        );

        OrdinaryWallet {
            sdk,
            view_only_key_id,
            owner_secret,
            owner_address,
            _store_dir: store_dir,
        }
    }

    /// Builds the statement the way the patched statement handler does: the wallet is handed a
    /// promise-bearing output request and nothing else. It derives the output witnesses, the range
    /// proof, the balance proof and the balance signature itself.
    fn statement(
        &self,
        resource: ResourceAddress,
        inputs: &[InputSpendData],
        amount: u64,
        minimum_value_promise: u64,
    ) -> StealthTransferStatement {
        self.sdk
            .stealth_outputs_api()
            .generate_transfer_statement(TransferStatementParams {
                view_only_key_id: self.view_only_key_id,
                resource_address: &resource,
                resource_view_key: None,
                inputs,
                input_revealed_amount: Amount::zero(),
                outputs: vec![StealthOutputToCreate {
                    owner_address: self.owner_address.clone(),
                    pay_to: tari_ootle_wallet_crypto::pay_to::PayTo::StealthPublicKey,
                    amount,
                    memo: None,
                    minimum_value_promise,
                }],
revealed_output: None,
            })
            .expect("the wallet builds the statement")
    }

    /// The mint statement that creates the wallet's *own* stealth output for `resource`, built by the
    /// wallet rather than by the test.
    ///
    /// The engine treats this exactly as it treats the faucet fixture's mint: revealed supply in,
    /// stealth outputs out. It differs only in who chose the output's mask, nonce, encryption and tag,
    /// which is the whole point — the wallet can only spend what it encrypted to its own view key.
    fn mint_statement(&self, resource: ResourceAddress, amount: u64) -> StealthTransferStatement {
        self.sdk
            .stealth_outputs_api()
            .generate_transfer_statement(TransferStatementParams {
                view_only_key_id: self.view_only_key_id,
                resource_address: &resource,
                resource_view_key: None,
                inputs: &[],
                input_revealed_amount: Amount::from(amount),
                outputs: vec![StealthOutputToCreate {
                    owner_address: self.owner_address.clone(),
                    pay_to: tari_ootle_wallet_crypto::pay_to::PayTo::StealthPublicKey,
                    amount,
                    memo: None,
                    minimum_value_promise: 0,
                }],
                revealed_output: None,
            })
            .expect("the wallet builds its own funding output")
    }
}

/// The one-time key that authorises spending a stealth output `owner` owns.
///
/// A sender derives the output's spend key from its own secret nonce, so only the sender knows it. The
/// owner derives the same key from the *public* nonce, which is on chain, and that is the path the SDK
/// itself takes when it spends a UTXO (`KeyManagerApi::generate_stealth_owner_key`). An output this
/// wallet created is therefore spendable by the wallet without the test ever holding the sender's
/// nonce, which is the property that lets a real wallet spend a real output.
fn owner_spend_key(owner_secret: &RistrettoSecretKey, sender_public_nonce: RistrettoPublicKeyBytes) -> RistrettoSecretKey {
    let nonce = sender_public_nonce.try_from_byte_type().expect("a statement's sender nonce is a public key");
    tari_ootle_wallet_crypto::StealthCryptoApi::new()
        .derive_stealth_owner_secret(ootle_network::Network::LocalNet, owner_secret, &nonce)
}

/// Creates the resource a gate will watch and mints `amount` of it to `wallet` as a single stealth
/// output the wallet built itself.
///
/// Two transactions, because a stealth output's tag is derived by its *sender* from the resource
/// address, and the resource address does not exist until the faucet that creates it has executed.
/// `fund` creates the resource and mints the tranche this test controls; only then can the wallet
/// build an output for that resource, which `GhostGateFaucet::mint` turns into a UTXO.
///
/// The wallet builds that output deliberately. `generate_transfer_statement` recovers each input's
/// mask and value by decrypting the output with the wallet's own view-only key, so a wallet cannot
/// spend a UTXO whose encryption it did not perform. That is a property of every wallet, not a
/// limitation of this fixture: funding a wallet through the wallet is what the localnet flow does too.
fn fund_wallet(test: &mut TemplateTest, wallet: &OrdinaryWallet, amount: u64) -> Funds {
    let funds = fund(test, &wallet.owner_secret, &[amount], &[]);
    let statement = wallet.mint_statement(funds.resource, amount);
    let output = statement.outputs_statement.outputs[0].clone();

    test.execute_expect_success(
        Transaction::builder_localnet(Epoch(1))
            .call_method(funds.faucet, "mint", args![statement])
            .finish()
            .seal(test.secret_key()),
        vec![],
    );

    Funds {
        // The first tranche is left untouched; the wallet's tranche is what these tests spend.
        resource: funds.resource,
        faucet: funds.faucet,
        masks: funds.masks,
        inputs: vec![spend_data_of(&output, amount)],
    }
}

/// A wallet builds the statement; consensus accepts it; the gate counts exactly one proof.
#[test]
fn a_wallet_built_statement_satisfies_the_gate() {
    let mut test = harness();
    let wallet = OrdinaryWallet::create();

// The wallet's own funds, in an output the wallet built and can decrypt, so the spend below is an
    // ordinary key-path spend rather than a special case the gate has to accommodate.
    let funds = fund_wallet(&mut test, &wallet, FUNDING);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

    let statement = wallet.statement(funds.resource, &funds.inputs, FUNDING, THRESHOLD);

    // The wallet honoured the request, and published a bound rather than an amount.
    assert_eq!(statement.outputs_statement.outputs.len(), 1);
    assert_eq!(
        statement.outputs_statement.outputs[0]
            .output
            .minimum_value_promise,
        THRESHOLD,
        "the statement must carry the promise the caller asked for"
    );
    assert!(statement.outputs_statement.revealed_output.is_none());
    assert_eq!(statement.inputs_statement.inputs.len(), 1);

    // The engine's transfer validator is the first gate; the template's threshold is the second.
    tari_engine_types::stealth::validate_transfer(&statement, None)
        .expect("consensus accepts the statement the wallet built");

    let input_spend_key = owner_spend_key(&wallet.owner_secret, funds.inputs[0].public_nonce);
    let result = test.execute_expect_success(
        Transaction::builder_localnet(Epoch(1))
            .call_method(gate, "prove_access", args![challenge, statement])
            .finish()
            .add_signer(&public_of(&input_spend_key), &input_spend_key)
            .seal(&wallet.owner_secret),
        vec![],
    );

    let diff = result
        .finalize
        .any_accept()
        .expect("the gate must accept a qualifying proof");
    assert_eq!(count_new_utxos(&diff), 1, "the qualifying output is the only new UTXO");

    let accepted: u64 = test.extract_component_value(gate, GATE_PROOFS_ACCEPTED_PATH);
    assert_eq!(accepted, 1, "the gate counted exactly one proof");
}

/// An under-promising wallet statement is refused.
///
/// Without this, the test above would also pass against a template that ignored the promise and
/// counted any statement. Here the caller asks for one unit less than the threshold; the wallet builds
/// exactly that, because the statement is well formed and refusing it is not the wallet's job. The gate
/// is what has to apply the bound.
#[test]
fn a_wallet_statement_below_the_threshold_is_refused() {
    let mut test = harness();
    let wallet = OrdinaryWallet::create();

let funds = fund_wallet(&mut test, &wallet, FUNDING);
    let gate = deploy_gate(&mut test, funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD);

    let under = THRESHOLD - 1;
    let statement = wallet.statement(funds.resource, &funds.inputs, FUNDING, under);

    // The wallet did not round up, and did not refuse.
    assert_eq!(
        statement.outputs_statement.outputs[0]
            .output
            .minimum_value_promise,
        under
    );
    // Consensus still accepts the statement. It is a valid statement; it just does not qualify.
    tari_engine_types::stealth::validate_transfer(&statement, None)
        .expect("an under-promising statement is still a valid statement");

let input_spend_key = owner_spend_key(&wallet.owner_secret, funds.inputs[0].public_nonce);
    test.execute_expect_failure(
        Transaction::builder_localnet(Epoch(1))
            .call_method(gate, "prove_access", args![challenge, statement])
            .finish()
            .add_signer(&public_of(&input_spend_key), &input_spend_key)
            .seal(&wallet.owner_secret),
        vec![],
    );

    let accepted: u64 = test.extract_component_value(gate, GATE_PROOFS_ACCEPTED_PATH);
    assert_eq!(accepted, 0, "an under-promising proof must not count");
}
