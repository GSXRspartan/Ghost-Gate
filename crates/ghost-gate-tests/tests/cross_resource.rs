//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! Ghost Gate over arbitrary stealth fungible resources, under the real engine.
//!
//! `gate_engine.rs` proves the gate's rules against one resource. This file proves the rules are not
//! about that resource: it drives gates over **two distinct user-created stealth fungible resources
//! that disagree about everything a display cares about** -- different symbol, different divisibility,
//! different resource address -- and checks that the only thing that decides a proof is the resource
//! address the gate was configured with and the raw integer threshold.
//!
//! # What each case establishes
//!
//! ```text
//! A  first asset, above threshold                      -> PASS
//! B  second asset, above threshold                     -> PASS
//! C  enough of the first, gate wants the second        -> FAIL
//! D  enough of the second, statement spends the first  -> FAIL
//! E  second asset, one unit below threshold            -> FAIL
//! F  second asset, exactly threshold                   -> PASS
//! G  second asset, well above threshold                -> PASS
//! H  the same challenge redeemed twice                 -> FAIL
//! I  wrong gate / site / session / threshold           -> FAIL
//! ```
//!
//! Case A on the chain's own *native* stealth tTARI is deliberately absent from this file, and the
//! reason is worth stating rather than working around. Under the engine harness the builtin XTR
//! faucet pays a component into an aggregate stealth *vault container*, not into individual stealth
//! outputs, so a wallet cannot come to own a native tTARI UTXO here at all: measured directly, the
//! faucet created 0 UTXOs and left a container holding 1_000_000_000 units. A wallet can only come to
//! hold native tTARI through a real transfer that creates a UTXO, which is the localnet's job, and
//! which the `@ghost_gate` scenario does. The two created resources below stand in for the
//! *mechanism* being resource-agnostic; `docs/RESOURCE_SUPPORT.md` records which layer proves what.
//!
//! Everything here runs through `tari_engine`, so a rule proven in this file is a rule consensus
//! applies, not a rule a mock agreed with.

use ghost_gate_core::{Challenge, network};
use ootle_byte_type::ToByteType;
use tari_crypto::{
    keys::{PublicKey, SecretKey},
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
};
use tari_engine_types::substate::SubstateDiff;
use tari_ootle_wallet_crypto::{MaskAndValue, OutputWitness, StealthInputWitness, StealthOutputWitness};
use tari_ootle_common_types::substate_type::SubstateType;
use tari_ootle_transaction::{Epoch, Transaction, args};
use tari_template_lib::types::{
    Amount, ComponentAddress, EncryptedData, Hash32, MaxBytes, ResourceAddress,
    crypto::{RistrettoPublicKeyBytes, UtxoTag},
    stealth::{RevealedOutput, SpendAuthorization, StealthTransferStatement},
};
use tari_template_test_tooling::{TemplateTest, support::assert_error::assert_reject_reason};

const CRATE_PATH: &str = env!("CARGO_MANIFEST_DIR");
const FAUCET_TEMPLATE: &str = "../../templates/ghost_gate_faucet";
const GATE_TEMPLATE: &str = "../../templates/ghost_gate";
const OTHER_CLASSES_TEMPLATE: &str = "../../templates/ghost_gate_other_classes";

const GATE_NAME: &str = "GhostGate";
const FAUCET_NAME: &str = "GhostGateFaucet";
const OTHER_CLASSES_NAME: &str = "GhostGateOtherClasses";

const RELYING_SITE: &[u8] = b"vip.example";
const SESSION: &[u8] = b"session-1";

/// The cohort the engine tests execute in. A constructor argument to each gate, not a constant in the
/// template: one WASM is published on every cohort and each deployment names its own.
const NETWORK: u8 = network::LOCALNET;

const THRESHOLD: u64 = 10_000;

/// Comfortably above the threshold, so the promise is the only thing separating pass from fail.
const FUNDING: u64 = 30_000;

/// Deterministic mask seeds, one per funded output, so a test can name the output it wants to spend
/// and re-derive the key that authorises spending it.
const FIRST_SEED: u64 = 1_000_000_000;
const SECOND_SEED: u64 = 2_000_000_000;
const THIRD_SEED: u64 = 3_000_000_000;

// ---------------------------------------------------------------------------------------------
// Two assets that disagree about everything except what matters
// ---------------------------------------------------------------------------------------------

/// The first test asset.
const FIRST_ASSET: Asset = Asset {
    symbol: "GHOSTALPHA",
    // Six decimal places, the same as native tTARI.
    divisibility: 6,
};

// The second test asset: a different symbol *and* a different number of decimal places from the
// first. Divisibility 2 means one whole unit is a hundred raw units, so `THRESHOLD` is one hundred
// whole GHOSTBETA and `FUNDING` is three hundred. A gate that let divisibility reach its threshold
// comparison would accept or refuse differently between the two assets, which is exactly what these
// cases rule out.
const SECOND_ASSET: Asset = Asset {
    symbol: "GHOSTBETA",
    divisibility: 2,
};

struct Asset {
    symbol: &'static str,
    divisibility: u8,
}

fn site_id() -> MaxBytes<64> {
    MaxBytes::new_checked(RELYING_SITE.to_vec()).expect("well under the limit")
}

fn session_id() -> MaxBytes<64> {
    MaxBytes::new_checked(SESSION.to_vec()).expect("well under the limit")
}

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

fn harness() -> TemplateTest {
    let mut test = TemplateTest::new(CRATE_PATH, [FAUCET_TEMPLATE, GATE_TEMPLATE, OTHER_CLASSES_TEMPLATE]);
    test.set_virtual_substate(
        tari_engine_types::virtual_substate::VirtualSubstateId::CurrentEpoch,
        tari_engine_types::virtual_substate::VirtualSubstate::CurrentEpoch(5),
    );
    test
}

/// A deployed stealth resource, its funding output, and the key that authorises spending it.
struct Funds {
    resource: ResourceAddress,
    mask: RistrettoSecretKey,
}

/// Creates a stealth fungible resource with `divisibility` decimal places, minted as one
/// key-path output the test can spend.
///
/// `seed` gives each call its own mask. That is load-bearing: a Pedersen commitment covers
/// (value, mask) and a stealth spend key is derived from (account key, nonce), *neither* of which
/// mentions the resource. Two outputs minted with the same mask and the same amount therefore commit
/// to the same value and are authorised by the same key -- two genuinely interchangeable outputs that
/// differ only in which resource they sit under. Varying the seed is what makes the cross-resource
/// cases below test resource binding instead of accidentally testing an identical output twice.
///
/// The test builds the mint statement itself because a template cannot construct stealth outputs:
/// that needs Pedersen commitments, a bulletproof and an encrypted payload, none of which WASM can
/// do. The output's spend key is derived from the test's own signing key, so the engine's ordinary
/// key-path authorisation path runs for real.
fn fund(test: &mut TemplateTest, asset: &Asset, amount: u64, seed: u64) -> Funds {
    let owner_pk = RistrettoPublicKey::from_secret_key(test.secret_key());
    let mask = RistrettoSecretKey::from(seed);

    let output = StealthOutputWitness {
        witness: OutputWitness {
            amount,
            mask: mask.clone(),
            sender_public_nonce: RistrettoPublicKey::from_secret_key(&RistrettoSecretKey::from(seed + 500)),
            minimum_value_promise: 0,
            encrypted_data: EncryptedData::try_from(vec![0u8; EncryptedData::min_size()]).unwrap(),
            resource_view_key: None,
        },
        auth: SpendAuthorization::Key(stealth_spend_key(&owner_pk, seed)),
        tag: UtxoTag::new(0),
    };

    let total: u64 = amount;
    let statement = tari_ootle_wallet_crypto::stealth::create_transfer_statement(
        vec![],
        Amount::from(total),
        [&output],
        None::<RevealedOutput>,
    )
    .expect("mint statement");

    let faucet_addr = test.get_template_address(FAUCET_NAME);
    test.execute_expect_success(
        Transaction::builder_localnet(Epoch(1))
            .call_function(
                faucet_addr,
                "new",
                args![
                    asset.symbol.to_string(),
                    asset.divisibility,
                    Amount::from(total),
                    statement.clone()
                ],
            )
            .build_and_seal(test.secret_key()),
        vec![],
    );

    let resource = test
        .get_previous_output_address(SubstateType::Resource)
        .as_resource_address()
        .unwrap();

    Funds { resource, mask }
}

/// Deploys a gate over `resource`. Named so repeated deployments in one test do not collide.
fn deploy_gate(test: &mut TemplateTest, name: &str, resource: ResourceAddress, threshold: u64) -> ComponentAddress {
    let template_addr = test.get_template_address(GATE_NAME);
    test.execute_expect_success(
        test.transaction()
            .allocate_component_address(name)
            .call_function(
                template_addr,
                "new",
                args![
                    Workspace(name),
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

fn challenge_for(gate: ComponentAddress, resource: ResourceAddress, threshold: u64, nonce: u8) -> Challenge {
    Challenge {
        gate,
        resource,
        threshold,
        network: NETWORK,
        nonce: Hash32::from_array([nonce; 32]),
        expires_epoch: 1_000,
        relying_site: site_id(),
        session_commitment: session_id(),
    }
}

/// A one-input, one-output proof statement spending `input_mask`, promising at least `mvp`.
///
/// `input_value` must equal the real value of the input being spent: the balance proof is over the
/// real amounts, so a mismatch is caught by the engine rather than by this file.
fn proof_statement(input_mask: &RistrettoSecretKey, input_value: u64, output_value: u64, mvp: u64) -> StealthTransferStatement {
    let mask = RistrettoSecretKey::random(&mut rand::rng());
    let out = tari_ootle_wallet_crypto::StealthOutputWitness {
        witness: OutputWitness {
            amount: output_value,
            mask,
            sender_public_nonce: RistrettoPublicKey::from_secret_key(&RistrettoSecretKey::from(999u64)),
            minimum_value_promise: mvp,
            encrypted_data: EncryptedData::try_from(vec![0u8; EncryptedData::min_size()]).unwrap(),
            resource_view_key: None,
        },
        auth: SpendAuthorization::Key(
            RistrettoPublicKey::from_secret_key(&RistrettoSecretKey::random(&mut rand::rng())).to_byte_type(),
        ),
        tag: UtxoTag::new(0),
    };
    tari_ootle_wallet_crypto::stealth::create_transfer_statement(
        vec![StealthInputWitness::new(MaskAndValue {
            mask: input_mask.clone(),
            value: input_value,
        })],
        Amount::zero(),
        [&out],
        None::<RevealedOutput>,
    )
    .expect("proof statement")
}

fn stealth_spend_key(account_key: &RistrettoPublicKey, nonce: u64) -> RistrettoPublicKeyBytes {
    use ootle_network::Network;
    tari_ootle_wallet_crypto::StealthCryptoApi::new()
        .derive_stealth_owner_public_key(Network::LocalNet, account_key, &RistrettoSecretKey::from(nonce))
        .to_byte_type()
}

/// The private half of the spend key `fund` committed for its output at `nonce`.
fn spend_secret(account_secret: &RistrettoSecretKey, nonce: u64) -> RistrettoSecretKey {
    tari_ootle_wallet_crypto::StealthCryptoApi::new().derive_stealth_owner_secret(
        ootle_network::Network::LocalNet,
        account_secret,
        &RistrettoPublicKey::from_secret_key(&RistrettoSecretKey::from(nonce)),
    )
}

fn public_of(secret: &RistrettoSecretKey) -> RistrettoPublicKeyBytes {
    RistrettoPublicKey::from_secret_key(secret).to_byte_type()
}

fn count_new_utxos(diff: &SubstateDiff) -> usize {
    diff.up_iter()
        .filter_map(|(_, substate)| substate.substate_value().as_utxo())
        .count()
}

/// Seals `statement` into a proof transaction spending `fund`'s funding output.
fn proof_transaction(
    test: &TemplateTest,
    gate: ComponentAddress,
    challenge: Challenge,
    statement: StealthTransferStatement,
    seed: u64,
) -> tari_ootle_transaction::Transaction {
    let sk = spend_secret(test.secret_key(), seed);
    Transaction::builder_localnet(Epoch(1))
        .call_method(gate, "prove_access", args![challenge, statement])
        .finish()
        .add_signer(&public_of(&sk), &sk)
        .seal(test.secret_key())
}

/// Runs case A/B/F/G: a qualifying proof over `asset`, and how many UTXOs it created.
fn expect_accepted_over(asset: &Asset, seed: u64, output_value: u64, mvp: u64) {
    let mut test = harness();
    // Fund exactly what the statement spends. A stealth output cannot be split, and with nothing
    // revealed the balance proof requires inputs and outputs to sum equally, so a funding larger than
    // the output would be refused by the engine for a reason that has nothing to do with the threshold.
    let funds = fund(&mut test, asset, output_value, seed);
    let gate = deploy_gate(&mut test, "gate_under_test", funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD, 7);

    let statement = proof_statement(&funds.mask, output_value, output_value, mvp);
    let transaction = proof_transaction(&test, gate, challenge, statement, seed);
    let result = test.execute_expect_success(transaction, vec![]);
    assert_eq!(
        count_new_utxos(&result.finalize.any_accept().expect("accepted")),
        1,
        "the qualifying output is the only new UTXO"
    );
    let accepted: u64 = test.extract_component_value(gate, "$.5");
    assert_eq!(accepted, 1, "the gate counted exactly one proof");
}

// ---------------------------------------------------------------------------------------------
// A and B: both assets work
// ---------------------------------------------------------------------------------------------

/// A. A gate over the first asset, with an amount above the threshold.
#[test]
fn a_gate_over_the_first_asset_accepts_a_qualifying_proof() {
    expect_accepted_over(&FIRST_ASSET, FIRST_SEED, FUNDING, THRESHOLD);
}

/// B. A gate over the second asset -- a different symbol and a different divisibility -- with an
/// amount above the threshold. The same WASM, the same rules, the same wallet shape.
#[test]
fn a_gate_over_the_second_asset_accepts_a_qualifying_proof() {
    expect_accepted_over(&SECOND_ASSET, SECOND_SEED, FUNDING, THRESHOLD);
}

// ---------------------------------------------------------------------------------------------
// C: enough of the wrong asset
// ---------------------------------------------------------------------------------------------

/// C. The wallet holds plenty of the first asset; the gate wants the second.
///
/// The challenge names the gate's own resource, so the gate's shape rules all pass. What refuses this
/// is the *engine*: a stealth UTXO's address is `(resource, commitment)`, so spending a first-asset
/// output through a second-asset resource manager looks for a UTXO that does not exist. Two
/// independent defences are asserted: the gate's own resource check, and the engine's.
#[test]
fn holding_only_the_first_asset_cannot_satisfy_a_gate_over_the_second() {
    let mut test = harness();
    let first = fund(&mut test, &FIRST_ASSET, FUNDING, FIRST_SEED);
    let second = fund(&mut test, &SECOND_ASSET, FUNDING, SECOND_SEED);
    assert_ne!(first.resource, second.resource, "two faucets must yield two resources");

    let gate = deploy_gate(&mut test, "gate_under_test", second.resource, THRESHOLD);
    // The challenge is internally consistent with the gate: right resource, right threshold.
    let challenge = challenge_for(gate, second.resource, THRESHOLD, 7);

    // ... but the statement spends a first-asset output.
    let statement = proof_statement(&first.mask, FUNDING, FUNDING, THRESHOLD);
    let transaction = proof_transaction(&test, gate, challenge, statement, FIRST_SEED);
    let reason = test.execute_expect_failure(transaction, vec![]);
    let text = reason.to_string();
    assert!(
        text.contains("not found") || text.contains("utxo_"),
        "a stealth UTXO's address is (resource, commitment), so the engine must fail to resolve a \
         first-asset output under the second asset's resource. Got: {text}"
    );
    let accepted: u64 = test.extract_component_value(gate, "$.5");
    assert_eq!(accepted, 0, "no proof may be counted");
}

/// C, second half: a challenge naming the *wallet's* resource against a gate over the other one is
/// refused by the gate's own rule, before the engine is ever consulted.
#[test]
fn a_challenge_naming_the_provers_resource_is_refused_by_a_gate_over_another() {
    let mut test = harness();
    let first = fund(&mut test, &FIRST_ASSET, FUNDING, FIRST_SEED);
    let second = fund(&mut test, &SECOND_ASSET, FUNDING, SECOND_SEED);
    let gate = deploy_gate(&mut test, "gate_under_test", second.resource, THRESHOLD);

    let mut challenge = challenge_for(gate, second.resource, THRESHOLD, 7);
    challenge.resource = first.resource;

    let statement = proof_statement(&first.mask, FUNDING, FUNDING, THRESHOLD);
    let transaction = proof_transaction(&test, gate, challenge, statement, SECOND_SEED);
    let reason = test.execute_expect_failure(transaction, vec![]);
    assert_reject_reason(reason, "challenge resource does not match gate policy");
}

// ---------------------------------------------------------------------------------------------
// D: the right resource named, the wrong funds spent
// ---------------------------------------------------------------------------------------------

/// D. The wallet holds the second asset, and the challenge correctly names the second asset, but the
/// statement spends the first asset's output.
///
/// This is the substitution a naive implementation would allow: the gate never looks at the
/// statement's inputs, only at the promise on its output, so the promise alone would clear. What stops
/// it is that the engine resolves every spent input under the gate's own resource address.
#[test]
fn a_statement_spending_another_resource_is_refused_even_when_the_challenge_agrees() {
    let mut test = harness();
    let first = fund(&mut test, &FIRST_ASSET, FUNDING, FIRST_SEED);
    let second = fund(&mut test, &SECOND_ASSET, FUNDING, SECOND_SEED);
    let gate = deploy_gate(&mut test, "gate_under_test", second.resource, THRESHOLD);
    let challenge = challenge_for(gate, second.resource, THRESHOLD, 7);

    // The statement clears every one of the gate's *own* rules: one output, key-spendable, promise at
    // the threshold, no revealed amounts, a balance proof. Only the resource is wrong.
    let statement = proof_statement(&first.mask, FUNDING, FUNDING, THRESHOLD);
    assert_eq!(
        statement.outputs_statement.outputs[0]
            .output
            .minimum_value_promise,
        THRESHOLD,
        "the promise clears the threshold, so the gate's own rules cannot be what refuses this"
    );

    let transaction = proof_transaction(&test, gate, challenge, statement, FIRST_SEED);
    let reason = test.execute_expect_failure(transaction, vec![]);
    let text = reason.to_string();
    assert!(
        text.contains("not found") || text.contains("utxo_"),
        "expected the engine to refuse an input from another resource, got: {text}"
    );

    let accepted: u64 = test.extract_component_value(gate, "$.5");
    assert_eq!(accepted, 0, "a substituted resource must never count");
}

// ---------------------------------------------------------------------------------------------
// E, F, G: the threshold boundary on the second asset
// ---------------------------------------------------------------------------------------------

/// E. One raw unit below the threshold on the second asset is refused.
#[test]
fn the_second_asset_one_unit_below_the_threshold_is_refused() {
    let mut test = harness();
    let funds = fund(&mut test, &SECOND_ASSET, FUNDING, SECOND_SEED);
    let gate = deploy_gate(&mut test, "gate_under_test", funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD, 7);

    let under = THRESHOLD - 1;
    let statement = proof_statement(&funds.mask, FUNDING, under, under);
    let transaction = proof_transaction(&test, gate, challenge, statement, SECOND_SEED);
    let reason = test.execute_expect_failure(transaction, vec![]);
    assert_reject_reason(reason, "attested minimum is below the gate threshold");

    let accepted: u64 = test.extract_component_value(gate, "$.5");
    assert_eq!(accepted, 0);
}

/// F. Exactly the threshold on the second asset qualifies: the rule is `>=`, not `>`. One raw unit,
/// whatever that unit is worth in the asset's own display.
#[test]
fn the_second_asset_exactly_at_the_threshold_is_accepted() {
    expect_accepted_over(&SECOND_ASSET, FIRST_SEED, THRESHOLD, THRESHOLD);
}

/// G. Well above the threshold on the second asset is accepted, and the receipt reports the floor the
/// gate asked for rather than the real amount.
#[test]
fn the_second_asset_well_above_the_threshold_is_accepted_and_reports_only_the_floor() {
    let mut test = harness();
    let funds = fund(&mut test, &SECOND_ASSET, FUNDING, SECOND_SEED);
    let gate = deploy_gate(&mut test, "gate_under_test", funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD, 7);

    let statement = proof_statement(&funds.mask, FUNDING, FUNDING, THRESHOLD);
    let transaction = proof_transaction(&test, gate, challenge, statement, SECOND_SEED);
    let result = test.execute_expect_success(transaction, vec![]);
    let diff = result.finalize.any_accept().expect("accepted");

    // The real amount was FUNDING; the only public number is the floor.
    assert_eq!(count_new_utxos(&diff), 1);
    // The qualifying output on chain promises the threshold, not the amount it really holds.
    let promises: Vec<u64> = diff
        .up_iter()
        .filter_map(|(_, substate)| substate.substate_value().as_utxo())
        .filter_map(|utxo| utxo.output().map(|o| o.output().minimum_value_promise))
        .collect();
    assert_eq!(promises, vec![THRESHOLD], "the public commitment is the floor, never the real amount");
    assert_ne!(FUNDING, THRESHOLD, "the real amount and the floor must differ for this to mean anything");
}

// ---------------------------------------------------------------------------------------------
// H: replay
// ---------------------------------------------------------------------------------------------

/// H. The same challenge cannot be redeemed twice against the second asset either: one-use is a
/// property of the gate, not of the resource.
#[test]
fn a_challenge_on_the_second_asset_cannot_be_redeemed_twice() {
    let mut test = harness();
    let funds = fund(&mut test, &SECOND_ASSET, FUNDING, SECOND_SEED);
    let gate = deploy_gate(&mut test, "gate_under_test", funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD, 7);

    test.execute_expect_success(
        proof_transaction(
            &test,
            gate,
            challenge.clone(),
            proof_statement(&funds.mask, FUNDING, FUNDING, THRESHOLD),
            SECOND_SEED,
        ),
        vec![],
    );

    // A second tranche of the same resource, minted at a different mask so the two transactions share
    // no output, no spend key and no commitment -- only the nonce. If this were accepted, one proof
    // would mint two sessions.
    let refreshed = refreshed_funds(&mut test);
    let reason = test.execute_expect_failure(
        proof_transaction(
            &test,
            gate,
            challenge.clone(),
            proof_statement(&refreshed.mask, FUNDING, FUNDING, THRESHOLD),
            THIRD_SEED,
        ),
        vec![],
    );
    assert_reject_reason(reason, "challenge nonce has already been used");

    let accepted: u64 = test.extract_component_value(gate, "$.5");
    assert_eq!(accepted, 1, "only the first redemption counted");
}

/// A second tranche on the same resource, funded at a different mask seed so its spend key differs.
fn refreshed_funds(test: &mut TemplateTest) -> Funds {
    fund(test, &SECOND_ASSET, FUNDING, THIRD_SEED)
}

// ---------------------------------------------------------------------------------------------
// I: the bindings that are not about the resource
// ---------------------------------------------------------------------------------------------

/// I. Every binding that is not the resource is still enforced on a gate over the second asset.
#[test]
fn a_second_asset_gate_still_binds_gate_site_session_and_threshold() {
    let mut test = harness();
    let funds = fund(&mut test, &SECOND_ASSET, FUNDING, SECOND_SEED);
    let gate = deploy_gate(&mut test, "gate_under_test", funds.resource, THRESHOLD);
    let other_gate = deploy_gate(&mut test, "other_gate", funds.resource, THRESHOLD);
    assert_ne!(gate, other_gate);
    let base = challenge_for(gate, funds.resource, THRESHOLD, 7);

    let cases: Vec<(&str, Box<dyn Fn(&mut Challenge)>, &str)> = vec![
        (
            "gate",
            Box::new(|c: &mut Challenge| c.gate = other_gate),
            "challenge is for a different gate",
        ),
        (
            "site",
            Box::new(|c: &mut Challenge| c.relying_site = MaxBytes::new_checked(b"evil.example".to_vec()).unwrap()),
            "challenge is for a different relying site",
        ),
        (
            "session",
            Box::new(|c: &mut Challenge| c.session_commitment = MaxBytes::new_checked(b"session-2".to_vec()).unwrap()),
            "challenge is for a different browser session",
        ),
        (
            "threshold",
            Box::new(|c: &mut Challenge| c.threshold = 1),
            "challenge threshold does not match gate policy",
        ),
        (
            "network",
            Box::new(|c: &mut Challenge| c.network = network::ESMERALDA),
            "challenge network does not match this chain",
        ),
    ];

    for (what, mutate, expected) in cases {
        let mut challenge = base.clone();
        mutate(&mut challenge);
        let reason = test.execute_expect_failure(
            proof_transaction(
                &test,
                gate,
                challenge,
                proof_statement(&funds.mask, FUNDING, FUNDING, THRESHOLD),
                SECOND_SEED,
            ),
            vec![],
        );
        assert_reject_reason(reason, expected);
        assert!(
            !what.is_empty(),
            "each binding case must be named so a failure says which one regressed"
        );
    }

    let accepted: u64 = test.extract_component_value(gate, "$.5");
    assert_eq!(accepted, 0, "no refused binding may count a proof");
}

// ---------------------------------------------------------------------------------------------
// Resource identity: address, not name
// ---------------------------------------------------------------------------------------------

/// The gate reports the address it was configured with and the divisibility it read off chain, and
/// the threshold as a raw integer. A site that renders a threshold from the reported address and
/// divisibility gets the same number consensus compares.
#[test]
fn a_gate_reports_its_own_resource_and_divisibility() {
    for asset in [&FIRST_ASSET, &SECOND_ASSET] {
        let mut test = harness();
        let funds = fund(&mut test, asset, FUNDING, FIRST_SEED);
        let gate = deploy_gate(&mut test, "gate_under_test", funds.resource, THRESHOLD);

        let resource: ResourceAddress = test.call_method(gate, "resource", args![], vec![]);
        assert_eq!(resource, funds.resource, "the gate must report the address it was given");

        let divisibility: u8 = test.call_method(gate, "divisibility", args![], vec![]);
        assert_eq!(
            divisibility,
            asset.divisibility,
            "divisibility comes from the resource's own chain record, not from a caller"
        );

        let threshold: u64 = test.call_method(gate, "threshold", args![], vec![]);
        assert_eq!(threshold, THRESHOLD, "the threshold is the raw integer consensus compares");

        let gate_network: u8 = test.call_method(gate, "network", args![], vec![]);
        assert_eq!(gate_network, NETWORK, "the gate is bound to the cohort it was deployed for");

        // The same raw threshold renders two different ways, and only one of them is wrong for the
        // asset it belongs to.
        let rendered = ghost_gate_verifier::display::render_threshold(
            threshold,
            divisibility,
            &ghost_gate_verifier::display::Symbol::Resolved(asset.symbol.to_string()),
        );
        assert_eq!(rendered.raw, THRESHOLD, "display never moves the number consensus uses");
        assert!(rendered.display.ends_with(asset.symbol));
    }
}

/// Two gates over two different assets report different resources, so a site reading the wrong gate
/// cannot mistake one asset for the other.
#[test]
fn two_gates_over_two_assets_report_different_resources() {
    let mut test = harness();
    let first = fund(&mut test, &FIRST_ASSET, FUNDING, FIRST_SEED);
    let second = fund(&mut test, &SECOND_ASSET, FUNDING, SECOND_SEED);
    let first_gate = deploy_gate(&mut test, "gate_first", first.resource, THRESHOLD);
    let second_gate = deploy_gate(&mut test, "gate_second", second.resource, THRESHOLD);

    let a: ResourceAddress = test.call_method(first_gate, "resource", args![], vec![]);
    let b: ResourceAddress = test.call_method(second_gate, "resource", args![], vec![]);
    assert_eq!(a, first.resource);
    assert_eq!(b, second.resource);
    assert_ne!(a, b);
}

// ---------------------------------------------------------------------------------------------
// Unsupported resource classes
// ---------------------------------------------------------------------------------------------

/// A gate refuses to be deployed over a resource class with no per-output minimum value promise.
///
/// Each class is refused with a message naming it, because "Ghost Gate only works with stealth
/// tokens" is a claim a user needs to be told at gate-creation time rather than discovered when
/// their proof keeps failing.
#[test]
fn a_gate_refuses_every_resource_class_it_cannot_prove() {
    let cases: Vec<(&str, Box<dyn Fn(&mut TemplateTest) -> ResourceAddress>, &str)> = vec![
        (
            "public fungible",
            Box::new(|t: &mut TemplateTest| {
                let tmpl = t.get_template_address(OTHER_CLASSES_NAME);
                t.execute_expect_success(
                    t.transaction()
                        .call_function(
                            tmpl,
                            "public_fungible",
                            args!["PUBLIC".to_string(), 6u8, Amount::from(1_000_000u64)],
                        )
                        .build_and_seal(t.secret_key()),
                    vec![],
                );
                t.get_previous_output_address(SubstateType::Resource)
                    .as_resource_address()
                    .unwrap()
            }),
            "public fungible",
        ),
        (
            "confidential",
            Box::new(|t: &mut TemplateTest| {
                let tmpl = t.get_template_address(OTHER_CLASSES_NAME);
                t.execute_expect_success(
                    t.transaction()
                        .call_function(
                            tmpl,
                            "confidential",
                            args!["CONF".to_string(), 6u8, Amount::from(1_000_000u64)],
                        )
                        .build_and_seal(t.secret_key()),
                    vec![],
                );
                t.get_previous_output_address(SubstateType::Resource)
                    .as_resource_address()
                    .unwrap()
            }),
            "confidential fungible",
        ),
        (
            "non-fungible",
            Box::new(|t: &mut TemplateTest| {
                let tmpl = t.get_template_address(OTHER_CLASSES_NAME);
                t.execute_expect_success(
                    t.transaction()
                        .call_function(tmpl, "non_fungible", args!["NFT".to_string(), 3u64])
                        .build_and_seal(t.secret_key()),
                    vec![],
                );
                t.get_previous_output_address(SubstateType::Resource)
                    .as_resource_address()
                    .unwrap()
            }),
            "non-fungible",
        ),
    ];

    for (what, create, expected_class) in cases {
        let mut test = harness();
        let resource = create(&mut test);
        let template_addr = test.get_template_address(GATE_NAME);
        let reason = test.execute_expect_failure(
            test.transaction()
                .allocate_component_address("gate_under_test")
                .call_function(
                    template_addr,
                    "new",
                    args![Workspace("gate_under_test"), resource, THRESHOLD, site_id(), session_id(), NETWORK],
                )
                .build_and_seal(test.secret_key()),
            vec![],
        );
        let text = reason.to_string();
        assert!(
            text.contains("a gate can only be denominated in a stealth fungible resource"),
            "the refusal must state the rule, got: {text}"
        );
        assert!(
            text.contains(expected_class),
            "the refusal must name the class it refused ({what}), got: {text}"
        );
    }
}

/// A zero threshold is refused at construction rather than producing a gate every statement clears.
#[test]
fn a_gate_refuses_a_zero_threshold() {
    let mut test = harness();
    let funds = fund(&mut test, &SECOND_ASSET, FUNDING, SECOND_SEED);
    let template_addr = test.get_template_address(GATE_NAME);
    let reason = test.execute_expect_failure(
        test.transaction()
            .allocate_component_address("gate_under_test")
            .call_function(
                template_addr,
                "new",
                args![Workspace("gate_under_test"), funds.resource, 0u64, site_id(), session_id(), NETWORK],
            )
            .build_and_seal(test.secret_key()),
        vec![],
    );
    assert_reject_reason(reason, "threshold must be positive");
}

/// A gate that closes refuses a perfectly valid proof over any asset.
#[test]
fn a_closed_gate_refuses_a_valid_second_asset_proof() {
    let mut test = harness();
    let funds = fund(&mut test, &SECOND_ASSET, FUNDING, SECOND_SEED);
    let gate = deploy_gate(&mut test, "gate_under_test", funds.resource, THRESHOLD);
    let challenge = challenge_for(gate, funds.resource, THRESHOLD, 7);

    test.call_method::<()>(gate, "set_open", args![false], vec![]);
    let open: bool = test.call_method(gate, "is_open", args![], vec![]);
    assert!(!open);

    let reason = test.execute_expect_failure(
        proof_transaction(
            &test,
            gate,
            challenge,
            proof_statement(&funds.mask, FUNDING, FUNDING, THRESHOLD),
            SECOND_SEED,
        ),
        vec![],
    );
    assert_reject_reason(reason, "gate is not accepting proofs");
}

/// The two-step funding path a wallet needs, exercised end to end: create the resource, *then* have
/// the wallet build the minting output, then spend it.
///
/// This is the shape the localnet uses for a user-created asset, so proving it here means the
/// localnet scenario is testing the mechanism and not a shortcut.
#[test]
fn a_wallet_can_be_funded_with_a_resource_created_in_a_separate_step() {
    let mut test = harness();
    let account_pk = RistrettoPublicKey::from_secret_key(test.secret_key());
    let faucet_tmpl = test.get_template_address(FAUCET_NAME);

    // Step one: the resource exists, with a supply held by the faucet.
    test.execute_expect_success(
        test.transaction()
            .call_function(
                faucet_tmpl,
                "new_resource",
                args![
                    SECOND_ASSET.symbol.to_string(),
                    SECOND_ASSET.divisibility,
                    Amount::from(FUNDING)
                ],
            )
            .build_and_seal(test.secret_key()),
        vec![],
    );
    let resource = test
        .get_previous_output_address(SubstateType::Resource)
        .as_resource_address()
        .unwrap();
    let faucet = test
        .get_previous_output_address(SubstateType::Component)
        .as_component_address()
        .unwrap();
    let divisibility: u8 = test.call_method(faucet, "divisibility", args![], vec![]);
    assert_eq!(divisibility, SECOND_ASSET.divisibility);

    // Step two: an output built with the resource address now available, encrypted to the wallet's
    // own view key -- which is the only reason a wallet can spend it later.
    let mask = RistrettoSecretKey::from(FIRST_SEED);
    let wallet_output = StealthOutputWitness {
        witness: OutputWitness {
            amount: FUNDING,
            mask: mask.clone(),
            sender_public_nonce: RistrettoPublicKey::from_secret_key(&RistrettoSecretKey::from(FIRST_SEED + 500)),
            minimum_value_promise: 0,
            encrypted_data: EncryptedData::try_from(vec![0u8; EncryptedData::min_size()]).unwrap(),
            resource_view_key: None,
        },
        auth: SpendAuthorization::Key(stealth_spend_key(&account_pk, FIRST_SEED)),
        tag: UtxoTag::new(0),
    };
    let mint_statement = tari_ootle_wallet_crypto::stealth::create_transfer_statement(
        vec![],
        Amount::from(FUNDING),
        [&wallet_output],
        None::<RevealedOutput>,
    )
    .expect("mint statement");

    test.execute_expect_success(
        test.transaction()
            .call_method(faucet, "mint", args![mint_statement.clone()])
            .build_and_seal(test.secret_key()),
        vec![],
    );

    // Step three: a gate over it, and a proof spending what the wallet just built.
    let gate = deploy_gate(&mut test, "gate_under_test", resource, THRESHOLD);
    let challenge = challenge_for(gate, resource, THRESHOLD, 7);
    let statement = proof_statement(&mask, FUNDING, FUNDING, THRESHOLD);
    let transaction = proof_transaction(&test, gate, challenge, statement, FIRST_SEED);
    let result = test.execute_expect_success(transaction, vec![]);
    assert_eq!(count_new_utxos(&result.finalize.any_accept().expect("accepted")), 1);

    let accepted: u64 = test.extract_component_value(gate, "$.5");
    assert_eq!(accepted, 1);
}
