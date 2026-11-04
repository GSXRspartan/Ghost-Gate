//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! The credential verifier against REAL chain state — the localnet's own indexer.
//!
//! Ignored by default: it needs the shared ShadowSwap localnet's indexer on 12007. Run it with
//! `cargo test -p ghost-gate-walletd --test credential_real_chain -- --ignored`.
//!
//! What it proves: the verifier genuinely reaches the chain, reads the output's own on-chain
//! `minimum_value_promise`, and refuses when that promise is below the gate's threshold. The
//! output used is a real, finalized, unspent tTARI stealth UTXO owned by the localnet's "Swap
//! Alice" account — read from the walletd's own `stealth_utxos.list` and confirmed through the
//! indexer REST API. Its promise is 0, so the ONLY honest verdict against a 10-tTARI gate is
//! BelowThreshold. A suite that can only pass against fixtures never tests this; this one does.
//!
//! This is an authentic NEGATIVE verification: real chain evidence, real verifier code, correct
//! fail-closed refusal. It is not the completed 10-tTARI milestone — that needs a promised
//! output, which needs a sequenced transaction, which needs the paused miner.

use ghost_gate_bridge::credential::{
    ChainReader, CredentialProofRequest, CredentialRefusal, CredentialVerifier,
};
use ghost_gate_walletd::IndexerChainReader;
use std::str::FromStr;
use tari_template_lib_types::{ResourceAddress, UtxoAddress};

/// The real, finalized tTARI stealth UTXO: `stealth_utxos.list` on the shared walletd for
/// account "Swap Alice" (component_974aaf…), verified through the indexer REST API.
const REAL_TTARI_UTXO: &str =
    "utxo_0101010101010101010101010101010101010101010101010101010101010101_a66c77cfed68833788b9d91dbece3e506cdbc590953d5c8f75ada7043f54b407";

const INDEXER: &str = "http://127.0.0.1:12007";
const TTARI: &str = "resource_0101010101010101010101010101010101010101010101010101010101010101";

/// Read-only compatibility probe for a current 0.49 indexer response. The operator supplies a
/// public UTXO id at run time so no wallet-specific output is committed as a fixture.
#[tokio::test]
#[ignore = "set GG_LIVE_INDEXER, GG_LIVE_UTXO and GG_LIVE_NETWORK_BYTE for a read-only live check"]
async fn a_configured_live_049_proof_response_decodes_and_verifies() {
    let endpoint = std::env::var("GG_LIVE_INDEXER").expect("GG_LIVE_INDEXER");
    let address = UtxoAddress::from_str(&std::env::var("GG_LIVE_UTXO").expect("GG_LIVE_UTXO"))
        .expect("GG_LIVE_UTXO is a UTXO address");
    let network = std::env::var("GG_LIVE_NETWORK_BYTE")
        .expect("GG_LIVE_NETWORK_BYTE")
        .parse::<u8>()
        .expect("GG_LIVE_NETWORK_BYTE is decimal");
    let reader = IndexerChainReader::connect(&endpoint).expect("the indexer client builds");
    let on_chain = reader
        .utxo(network, &address)
        .await
        .expect("the current proof envelope verifies");
    assert!(
        on_chain.verified,
        "the indexer's committee assertion is required"
    );
    assert!(
        on_chain.auth_key.is_some(),
        "credential mode requires a key path"
    );
}

/// Read-only: the chain's own record for the real output.
#[tokio::test]
#[ignore = "needs the shared localnet's indexer on 127.0.0.1:12007"]
async fn a_real_finalized_output_with_no_promise_is_refused_below_a_10_ttari_threshold() {
    let reader = IndexerChainReader::connect(INDEXER).expect("the indexer answers");

    // 1. The address parses, and names the gate's resource — the first verifier rule.
    let address = UtxoAddress::from_str(REAL_TTARI_UTXO).expect("a real utxo id");
    let resource = ResourceAddress::from_str(TTARI).expect("the native tTARI resource");
    assert_eq!(address.resource_address(), &resource);

    // 2. The output the chain actually holds: unspent, merkle-verified, promise recorded.
    let on_chain = reader
        .utxo(16, &address)
        .await
        .expect("the output is on chain and unspent");
    assert!(on_chain.verified, "the indexer's own merkle statement must hold");
    assert_eq!(
        on_chain.minimum_value_promise, 0,
        "the faucet-minted output carries no value promise — this is the finding, not a bug"
    );

    // 3. The verifier, wired exactly as the bridge wires it, against the 10-tTARI milestone.
    let verifier = CredentialVerifier {
        gate_id: "ten-ttari",
        network: 16,
        threshold: 10_000_000, // 10 tTARI, divisibility 6
        resource: &resource,
        challenge_string: "a1b2c3d4e5f6",
    };
    let request = CredentialProofRequest {
        gate_id: "ten-ttari".into(),
        challenge_nonce: "a1b2c3d4e5f6".into(),
        session_commitment: "00".repeat(32),
        substate_id: REAL_TTARI_UTXO.into(),
        ownership: ghost_gate_bridge::credential::OwnershipProof {
            public_key: String::new(),
            public_nonce: "11".repeat(32),
            signature: "22".repeat(32),
        },
    };

    // 4. The honest verdict: below the threshold, because the real promise is 0.
    let refusal = verifier.verify(&reader, &request).await.expect_err("must refuse");
    match refusal {
        CredentialRefusal::BelowThreshold { attested, required } => {
            assert_eq!(attested, 0);
            assert_eq!(required, 10_000_000);
        },
        other => panic!("expected BelowThreshold, got {other:?}"),
    }
}

/// The same refusal at the smallest honest threshold any proof could pass: without a promise,
/// even a 1-unit threshold has nothing to attest to.
#[tokio::test]
#[ignore = "needs the shared localnet's indexer on 127.0.0.1:12007"]
async fn no_promise_means_no_threshold_at_all_can_be_attested() {
    let reader = IndexerChainReader::connect(INDEXER).expect("the indexer answers");
    let resource = ResourceAddress::from_str(TTARI).unwrap();
    let verifier = CredentialVerifier {
        gate_id: "one-unit",
        network: 16,
        threshold: 1,
        resource: &resource,
        challenge_string: "ff",
    };
    let request = CredentialProofRequest {
        gate_id: "one-unit".into(),
        challenge_nonce: "ff".into(),
        session_commitment: "00".repeat(32),
        substate_id: REAL_TTARI_UTXO.into(),
        ownership: ghost_gate_bridge::credential::OwnershipProof {
            public_key: String::new(),
            public_nonce: "11".repeat(32),
            signature: "22".repeat(32),
        },
    };
    let refusal = verifier.verify(&reader, &request).await.expect_err("must refuse");
    assert!(
        matches!(refusal, CredentialRefusal::BelowThreshold { attested: 0, required: 1 }),
        "got {refusal:?}"
    );
}
