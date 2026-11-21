//! Tests for the chain-evidence checker's fail-closed boundaries.
//!
//! These are deliberately mock-chain tests. They do not claim that plain base-node RPC is
//! authenticated; they pin the policy decisions that a real authenticated view must satisfy.

use async_trait::async_trait;
use ghost_gate_ggbp1::{
    ESMERALDA_GENESIS_HASH, ESMERALDA_NETWORK, Ggbp1ChainChecker, Ggbp1ChainError,
    Ggbp1ChainPolicy, Ggbp1ChainSnapshot, Ggbp1ChainView, Ggbp1ChainViewError,
    Ggbp1EvidenceSource, Ggbp1ObservedOutput, SyntheticOutputWitness,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tari_crypto::ristretto::{RistrettoPublicKey, RistrettoSecretKey};

const NOW: u64 = 1_800_000_000;

struct FixedChain {
    snapshot: Ggbp1ChainSnapshot,
    output: Option<Ggbp1ObservedOutput>,
}

#[async_trait]
impl Ggbp1ChainView for FixedChain {
    async fn snapshot(&self) -> Result<Ggbp1ChainSnapshot, Ggbp1ChainViewError> {
        Ok(self.snapshot.clone())
    }

    async fn output(
        &self,
        _expected: &ghost_gate_ggbp1::SyntheticStandardOutput,
    ) -> Result<Option<Ggbp1ObservedOutput>, Ggbp1ChainViewError> {
        Ok(self.output.clone())
    }
}

struct FlipChain {
    snapshot: Ggbp1ChainSnapshot,
    output: Ggbp1ObservedOutput,
    calls: AtomicUsize,
}

#[async_trait]
impl Ggbp1ChainView for FlipChain {
    async fn snapshot(&self) -> Result<Ggbp1ChainSnapshot, Ggbp1ChainViewError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let mut snapshot = self.snapshot.clone();
        if call == 1 {
            snapshot.tip_hash = [99u8; 32];
        }
        Ok(snapshot)
    }

    async fn output(
        &self,
        _expected: &ghost_gate_ggbp1::SyntheticStandardOutput,
    ) -> Result<Option<Ggbp1ObservedOutput>, Ggbp1ChainViewError> {
        Ok(Some(self.output.clone()))
    }
}

fn snapshot(source: Ggbp1EvidenceSource) -> Ggbp1ChainSnapshot {
    Ggbp1ChainSnapshot {
        source,
        network: ESMERALDA_NETWORK,
        genesis_hash: ESMERALDA_GENESIS_HASH,
        tip_height: 104,
        tip_hash: [9u8; 32],
        tip_timestamp_unix_seconds: NOW,
        is_synced: true,
    }
}

fn expected_output() -> ghost_gate_ggbp1::SyntheticStandardOutput {
    SyntheticOutputWitness::new(
        [1u8; 32],
        1_000_000,
        RistrettoSecretKey::from(21u64),
        RistrettoSecretKey::from(31u64),
    )
    .public
}

fn observed() -> Ggbp1ObservedOutput {
    let expected = expected_output();
    Ggbp1ObservedOutput {
        output_hash: expected.output_hash,
        commitment: expected.commitment,
        script: expected.script,
        script_public_key: expected.script_public_key,
        mined_height: 100,
        mined_block_hash: [7u8; 32],
        confirmations: 5,
        maturity_height: 100,
        output_version: 0,
        output_type: 0,
        range_proof_type: 0,
        covenant_is_supported: Some(true),
        effective_lock_height: Some(100),
        is_unspent: true,
        is_in_best_chain: true,
    }
}

fn checker() -> Ggbp1ChainChecker {
    Ggbp1ChainChecker::new(
        ESMERALDA_NETWORK,
        ESMERALDA_GENESIS_HASH,
        Ggbp1ChainPolicy::synthetic_test_fixture(),
    )
}

async fn assert_ok(snapshot: Ggbp1ChainSnapshot, output: Ggbp1ObservedOutput) {
    let chain = FixedChain {
        snapshot,
        output: Some(output),
    };
    checker()
        .checked_outputs(&chain, &[expected_output()], NOW + 1)
        .await
        .expect("valid chain evidence");
}

#[tokio::test]
async fn valid_synthetic_chain_evidence_passes() {
    assert_ok(snapshot(Ggbp1EvidenceSource::SyntheticFixture), observed()).await;
}

#[tokio::test]
async fn wrong_network_and_genesis_fail_closed() {
    let mut wrong_network = snapshot(Ggbp1EvidenceSource::SyntheticFixture);
    wrong_network.network = 0x00;
    let chain = FixedChain {
        snapshot: wrong_network,
        output: Some(observed()),
    };
    assert!(matches!(
        checker().checked_outputs(&chain, &[expected_output()], NOW + 1).await,
        Err(Ggbp1ChainError::ChainBindingMismatch)
    ));

    let mut wrong_genesis = snapshot(Ggbp1EvidenceSource::SyntheticFixture);
    wrong_genesis.genesis_hash = [0u8; 32];
    let chain = FixedChain {
        snapshot: wrong_genesis,
        output: Some(observed()),
    };
    assert!(matches!(
        checker().checked_outputs(&chain, &[expected_output()], NOW + 1).await,
        Err(Ggbp1ChainError::ChainBindingMismatch)
    ));
}

#[tokio::test]
async fn stale_tip_and_unsynced_node_fail_closed() {
    let mut stale = snapshot(Ggbp1EvidenceSource::SyntheticFixture);
    stale.tip_timestamp_unix_seconds = NOW - 120;
    let chain = FixedChain {
        snapshot: stale,
        output: Some(observed()),
    };
    assert!(checker().checked_outputs(&chain, &[expected_output()], NOW + 1).await.is_err());

    let mut unsynced = snapshot(Ggbp1EvidenceSource::SyntheticFixture);
    unsynced.is_synced = false;
    let chain = FixedChain {
        snapshot: unsynced,
        output: Some(observed()),
    };
    assert!(checker().checked_outputs(&chain, &[expected_output()], NOW + 1).await.is_err());
}

#[tokio::test]
async fn untrusted_and_synthetic_sources_are_refused_by_an_authenticated_policy() {
    let policy = Ggbp1ChainPolicy::esmeralda_authenticated_node();
    let checker = Ggbp1ChainChecker::new(ESMERALDA_NETWORK, ESMERALDA_GENESIS_HASH, policy);

    let chain = FixedChain {
        snapshot: snapshot(Ggbp1EvidenceSource::UntrustedBaseNodeRpc),
        output: Some(observed()),
    };
    assert!(checker.checked_outputs(&chain, &[expected_output()], NOW + 1).await.is_err());

    let chain = FixedChain {
        snapshot: snapshot(Ggbp1EvidenceSource::SyntheticFixture),
        output: Some(observed()),
    };
    assert!(checker.checked_outputs(&chain, &[expected_output()], NOW + 1).await.is_err());
}

#[tokio::test]
async fn missing_spent_and_not_in_best_chain_outputs_fail_closed() {
    let chain = FixedChain {
        snapshot: snapshot(Ggbp1EvidenceSource::SyntheticFixture),
        output: None,
    };
    assert!(checker().checked_outputs(&chain, &[expected_output()], NOW + 1).await.is_err());

    let mut spent = observed();
    spent.is_unspent = false;
    let chain = FixedChain {
        snapshot: snapshot(Ggbp1EvidenceSource::SyntheticFixture),
        output: Some(spent),
    };
    assert!(checker().checked_outputs(&chain, &[expected_output()], NOW + 1).await.is_err());

    let mut not_best = observed();
    not_best.is_in_best_chain = false;
    let chain = FixedChain {
        snapshot: snapshot(Ggbp1EvidenceSource::SyntheticFixture),
        output: Some(not_best),
    };
    assert!(checker().checked_outputs(&chain, &[expected_output()], NOW + 1).await.is_err());
}

#[tokio::test]
async fn confirmation_maturity_lock_and_covenant_checks_fail_closed() {
    let mut shallow = observed();
    shallow.confirmations = 1;
    let chain = FixedChain {
        snapshot: snapshot(Ggbp1EvidenceSource::SyntheticFixture),
        output: Some(shallow),
    };
    assert!(checker().checked_outputs(&chain, &[expected_output()], NOW + 1).await.is_err());

    let mut immature = observed();
    immature.maturity_height = 200;
    immature.effective_lock_height = Some(200);
    let chain = FixedChain {
        snapshot: snapshot(Ggbp1EvidenceSource::SyntheticFixture),
        output: Some(immature),
    };
    assert!(checker().checked_outputs(&chain, &[expected_output()], NOW + 1).await.is_err());

    let mut bad_lock = observed();
    bad_lock.effective_lock_height = Some(50);
    let chain = FixedChain {
        snapshot: snapshot(Ggbp1EvidenceSource::SyntheticFixture),
        output: Some(bad_lock),
    };
    assert!(checker().checked_outputs(&chain, &[expected_output()], NOW + 1).await.is_err());

    let mut covenant = observed();
    covenant.covenant_is_supported = Some(false);
    let chain = FixedChain {
        snapshot: snapshot(Ggbp1EvidenceSource::SyntheticFixture),
        output: Some(covenant),
    };
    assert!(checker().checked_outputs(&chain, &[expected_output()], NOW + 1).await.is_err());

    let mut unknown_covenant = observed();
    unknown_covenant.covenant_is_supported = None;
    let chain = FixedChain {
        snapshot: snapshot(Ggbp1EvidenceSource::SyntheticFixture),
        output: Some(unknown_covenant),
    };
    assert!(checker().checked_outputs(&chain, &[expected_output()], NOW + 1).await.is_err());
}

#[tokio::test]
async fn output_mismatch_and_unsupported_format_fail_closed() {
    let mut mismatch = observed();
    mismatch.script_public_key = RistrettoPublicKey::default();
    let chain = FixedChain {
        snapshot: snapshot(Ggbp1EvidenceSource::SyntheticFixture),
        output: Some(mismatch),
    };
    assert!(checker().checked_outputs(&chain, &[expected_output()], NOW + 1).await.is_err());

    let mut format = observed();
    format.output_type = 1;
    let chain = FixedChain {
        snapshot: snapshot(Ggbp1EvidenceSource::SyntheticFixture),
        output: Some(format),
    };
    assert!(checker().checked_outputs(&chain, &[expected_output()], NOW + 1).await.is_err());
}

#[tokio::test]
async fn a_tip_change_during_check_fails_closed() {
    let chain = FlipChain {
        snapshot: snapshot(Ggbp1EvidenceSource::SyntheticFixture),
        output: observed(),
        calls: AtomicUsize::new(0),
    };
    assert!(checker().checked_outputs(&chain, &[expected_output()], NOW + 1).await.is_err());
}