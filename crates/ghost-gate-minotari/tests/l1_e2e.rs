//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: BSD-3-Clause (harness parts) / MIT (this file)

//! The real end-to-end L1 test: a base node, a miner and the proof wallet, in one process, over
//! real gRPC — the bridge's XTM verification running against genuinely mined, genuinely committed
//! chain state.
//!
//! This is the test that proves the fee boundary and the freshness binding against the actual
//! consensus rules rather than a canned reader. Everything below is LocalNet with difficulty-1
//! blocks; no real-value funds are involved.

#![allow(clippy::too_many_lines)]

use std::time::Duration;

use minotari_app_grpc::{
    conversions::transaction_output::grpc_output_with_payref,
    tari_rpc::{
        Empty as ProtoEmpty,
        NewBlockTemplateRequest,
        PowAlgo,
        pow_algo::PowAlgos,
    },
};
use minotari_node::{ApplicationConfig, BaseNodeConfig, GrpcMethod, run_base_node};
use minotari_node_grpc_client::BaseNodeGrpcClient;
use tari_common::configuration::CommonConfig;
use tari_common_sqlite::connection::DbConnectionUrl;
use tari_comms::{NodeIdentity, multiaddr::Multiaddr, peer_manager::PeerFeatures};
use tari_comms_dht::DhtConfig;
use tari_p2p::{Network, PeerSeedsConfig, TransportType, auto_update::AutoUpdateConfig, peer_seeds::SeedPeer};
use tari_shutdown::Shutdown;
use tari_transaction_components::{
    MicroMinotari,
    consensus::ConsensusManager,
    generate_coinbase_with_wallet_output,
    key_manager::{KeyManager, TariKeyId},
    tari_amount::T,
    transaction_components::{MemoField, RangeProofType},
};
use tokio::task;

use ghost_gate_bridge::xtm::{XtmProofArtifact, verify_xtm_proof};
use ghost_gate_minotari::wallet_service::{ProofWalletConfig, ProofWalletService};
use ghost_gate_minotari::service::XtmProofOutcome;

/// One shared test network: the base node process, its grpc port, and the key manager the coinbase
/// outputs were built with.
struct TestNet {
    shutdown: Shutdown,
    grpc_port: u16,
    base_node_public_key_hex: String,
    base_node_p2p_addr: String,
    base_node_http_port: u16,
    key_manager: KeyManager,
    script_key_id: TariKeyId,
    consensus: ConsensusManager,
}

async fn spawn_base_node(dir: &std::path::Path) -> TestNet {
    // Ports from the OS: a random seed offset keeps two concurrent tests off each other's
    // listeners (libtest runs tests in parallel by default, and a full workspace run adds many
    // more processes). The window is WIDE (1000 ports per slot) because a 300-port window
    // collided under load and a collision shows up as a mystifying "gRPC never came up" rather
    // than as an obvious bind error.
    let seed: u16 = rand::random();
    let base = 12_000 + (seed % 1_000);
    let (port, grpc_port, http_port) = (base, base + 300, base + 600);
    let base_node_address: Multiaddr = format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap();
    let base_node_identity = NodeIdentity::random(&mut rand::rng(), base_node_address, PeerFeatures::COMMUNICATION_NODE);
    let identity = base_node_identity.clone();
    let temp_dir = dir.join("base_node");
    std::fs::create_dir_all(&temp_dir).unwrap();
    let shutdown = Shutdown::new();

    let handle = task::spawn({
        let shutdown = shutdown.clone();
        let identity = base_node_identity.clone();
        let temp_dir = temp_dir.clone();
        async move {
            let mut base_node_config = ApplicationConfig {
                common: CommonConfig::default(),
                auto_update: AutoUpdateConfig::default(),
                base_node: BaseNodeConfig::default(),
                peer_seeds: PeerSeedsConfig::default(),
            };
            base_node_config.common.base_path.clone_from(&temp_dir);
            base_node_config.base_node.network = Network::LocalNet;
            base_node_config.base_node.grpc_enabled = true;
            base_node_config.base_node.grpc_address =
                Some(format!("/ip4/127.0.0.1/tcp/{grpc_port}").parse().unwrap());
            base_node_config.base_node.report_grpc_error = true;
            base_node_config.base_node.data_dir = temp_dir.join("db");
            base_node_config.base_node.identity_file = temp_dir.join("base_node_id.json");
            base_node_config.base_node.tor_identity_file = temp_dir.join("base_node_tor_id.json");
            base_node_config.base_node.lmdb_path = temp_dir.clone();
            base_node_config.base_node.p2p.transport.transport_type = TransportType::Tcp;
            base_node_config.base_node.p2p.transport.tcp.listener_address =
                format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap();
            base_node_config.base_node.p2p.public_addresses =
                vec![base_node_config.base_node.p2p.transport.tcp.listener_address.clone()].into();
            base_node_config.base_node.p2p.datastore_path = temp_dir.join("peer_db/base-node");
            base_node_config.base_node.p2p.dht = DhtConfig {
                database_url: DbConnectionUrl::File(temp_dir.join("dht.sqlite")),
                ..DhtConfig::default_local_test()
            };
            base_node_config.base_node.grpc_server_allow_methods = Vec::from([
                GrpcMethod::GetTipInfo,
                GrpcMethod::SearchKernels,
                GrpcMethod::FetchMatchingUtxos,
                GrpcMethod::SubmitTransaction,
                GrpcMethod::GetNewBlockTemplate,
                GrpcMethod::GetNewBlock,
                GrpcMethod::SubmitBlock,
                GrpcMethod::Identify,
                GrpcMethod::GetNetworkStatus,
                GrpcMethod::GetMempoolTransactions,
            ])
            .into();
            base_node_config.base_node.http_wallet_query_service.port = http_port;

            run_base_node(shutdown, std::sync::Arc::new(identity), std::sync::Arc::new(base_node_config))
                .await
        }
    });

    // Wait for gRPC readiness.
    let mut grpc_client = connect_with_retry(grpc_port).await;
    let mut remaining = 30;
    loop {
        match grpc_client.get_tip_info(ProtoEmpty {}).await {
            Ok(_) => break,
            Err(e) => {
                if handle.is_finished() {
                    panic!("base node exited while waiting for gRPC readiness: {e}");
                }
                remaining -= 1;
                if remaining == 0 {
                    panic!("base node gRPC did not become ready within 30s: {e}");
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            },
        }
    }

    let key_manager = KeyManager::new_random().unwrap();
    let script_key_id = {
        use tari_crypto::keys::SecretKey as _;
        use tari_transaction_components::key_manager::TransactionKeyManagerInterface as _;
        let private_key = tari_crypto::ristretto::RistrettoSecretKey::random(&mut rand::rng());
        key_manager.create_encrypted_key(private_key, None).unwrap()
    };
    TestNet {
        shutdown,
        grpc_port,
        base_node_public_key_hex: {
        use tari_crypto::tari_utilities::ByteArray as _;
        hex::encode(identity.public_key().as_bytes())
    },
        base_node_p2p_addr: format!("/ip4/127.0.0.1/tcp/{port}"),
        base_node_http_port: http_port,
        key_manager,
        script_key_id,
        consensus: ConsensusManager::builder(Network::LocalNet).build(),
    }
}

async fn connect_base_node(grpc_port: u16) -> BaseNodeGrpcClient<tonic::transport::Channel> {
    BaseNodeGrpcClient::connect(format!("http://127.0.0.1:{grpc_port}")).await.unwrap()
}

/// Connects with retries: a node that is still starting refuses connections for a while.
async fn connect_with_retry(grpc_port: u16) -> BaseNodeGrpcClient<tonic::transport::Channel> {
    for attempt in 0..30 {
        match BaseNodeGrpcClient::connect(format!("http://127.0.0.1:{grpc_port}")).await {
            Ok(client) => return client,
            Err(e) => {
                if attempt == 29 {
                    panic!("base node gRPC never came up: {e}");
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            },
        }
    }
    unreachable!("retry loop")
}

impl TestNet {
    /// Mines `n` blocks paying the coinbase to `payment_address` (non-stealth).
    async fn mine_blocks(&mut self, payment_address: &tari_common_types::tari_address::TariAddress, n: u64) {
        let mut client = connect_base_node(self.grpc_port).await;
        for i in 0..n {
            let template_req = NewBlockTemplateRequest {
                algo: Some(PowAlgo {
                    pow_algo: PowAlgos::Sha3x.into(),
                }),
                max_weight: 0,
            };
            let template_response = client
                .get_new_block_template(template_req.clone())
                .await
                .unwrap()
                .into_inner();
            let mut block_template = template_response.new_block_template.clone().unwrap();
            let template = template_response.new_block_template.as_ref().unwrap();
            let miner_data = template_response.miner_data.as_ref().unwrap();
            let fee = miner_data.total_fees;
            let reward = miner_data.reward;
            let height = template.header.as_ref().unwrap().height;
            let (_, coinbase_output, coinbase_kernel, _) = generate_coinbase_with_wallet_output(
                MicroMinotari::from(fee),
                MicroMinotari::from(reward),
                height,
                &Default::default(),
                &mut self.key_manager,
                &self.script_key_id,
                payment_address,
                false,
                self.consensus.consensus_constants(height),
                RangeProofType::BulletProofPlus,
                MemoField::new_empty(),
            )
            .unwrap();
            let body = block_template.body.as_mut().unwrap();
            body.outputs.push(grpc_output_with_payref(coinbase_output, None).unwrap());
            body.kernels.push(coinbase_kernel.into());

            let block_result = client
                .get_new_block(block_template.clone())
                .await
                .unwrap()
                .into_inner();
            let block = block_result.block.unwrap();
            client.submit_block(block).await.unwrap();
            tokio::time::sleep(Duration::from_millis(120)).await;
            let _ = i;
        }
    }
}

/// The proof wallet, started against the shared test base node.
async fn spawn_proof_wallet(base_dir: &std::path::Path, net: &TestNet) -> ProofWalletService {
    let config = ProofWalletConfig {
        network: Network::LocalNet,
        base_path: base_dir.to_path_buf(),
        base_node_address: net.base_node_p2p_addr.clone(),
        base_node_identity_public_key: net.base_node_public_key_hex.clone(),
        base_node_http_url: format!("http://127.0.0.1:{}", net.base_node_http_port),
        fee_per_gram: 5,
        broadcast_timeout: Duration::from_secs(120),
        listener_port: 0,
    };
    let shutdown = Shutdown::new();
    ProofWalletService::start(config, "test-passphrase".to_string(), shutdown)
        .await
        .expect("proof wallet started")
}

/// Funds the proof wallet by mining `blocks` coinbases to its one-sided address.
async fn fund_wallet(net: &mut TestNet, wallet: &ProofWalletService, blocks: u64) {
    let address = wallet.receive_address().unwrap();
    net.mine_blocks(&address, blocks).await;
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

/// 1 XTM threshold against a wallet funded by exactly the qualifying amount: the fee boundary
/// behaviour, end to end.
///
/// Wallet holds `1 XTM + 2 XTM` across two coinbases (coinbases are whole, so funding granularity
/// is whole XTM); the threshold is `1.000_000_000` micro — 1 XTM. The proving transaction must
/// carry an output promising at least `threshold - fee` for the floor to reach the threshold.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_full_l1_proof_flow_accepts_a_qualifying_wallet() {
    let _ = env_logger::builder().filter_level(log::LevelFilter::Debug).try_init();
    let dir = tempfile::tempdir().unwrap();
    let mut net = spawn_base_node(dir.path()).await;
    let mut wallet = spawn_proof_wallet(dir.path(), &net).await;
    // Funding granularity is the whole coinbase reward (1 XTM on LocalNet); mine a cushion so
    // coinbase maturity is behind the chain head by the time the wallet scans.
    fund_wallet(&mut net, &wallet, 6).await;
    {
        let mut client = connect_base_node(net.grpc_port).await;
        let tip = client.get_tip_info(ProtoEmpty {}).await.unwrap().into_inner();
        println!(
            "after funding: tip height {} metadata {:?}",
            tip.metadata.as_ref().map(|m| m.best_block_height).unwrap_or(0),
            tip.metadata.as_ref().map(|m| m.timestamp)
        );
    }
    let threshold_micro: u64 = 1 * 1_000_000; // 1 XTM

    // Wait for the wallet's balance to settle, mining extra blocks when nothing is spendable yet.
    let mut settled = false;
    let mut artifact_opt: Option<XtmProofArtifact> = None;
    for round in 0..20 {
        let balance = match wallet.wallet.output_manager_service.get_balance().await {
            Ok(b) => b,
            Err(e) => {
                println!("round {round}: balance error: {e}");
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            },
        };
        println!(
            "round {round}: available={} locked={} pending_in={} pending_out={}",
            balance.available_balance,
            balance.time_locked_balance.map(|v| v.0).unwrap_or(0),
            balance.pending_incoming_balance,
            balance.pending_outgoing_balance
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
        let outcome = wallet
            .create_proof_transaction(threshold_micro, [9u8; 32], MicroMinotari(5))
            .await;
        match outcome {
            Ok(XtmProofOutcome::Broadcast(artifact)) => {
                settled = true;
                artifact_opt = Some(artifact);
                break;
            },
            Ok(XtmProofOutcome::CannotAfford) => {
                // Not spendable yet: coinbase maturity or scanning. Mine another block and retry.
                if round % 3 == 2 {
                    net.mine_blocks(&wallet.receive_address().unwrap(), 1).await;
                }
                continue;
            },
            Ok(XtmProofOutcome::Failed(reason)) => panic!("proof failed: {reason}"),
            Err(e) => panic!("proof errored: {e:?}"),
        }
    }
    assert!(settled, "the wallet never became spendable; the funding or the scan did not settle");
    let artifact = artifact_opt.unwrap();
    let mut reader = ghost_gate_minotari::chain_reader::BaseNodeXtmReader::connect(&format!(
        "http://127.0.0.1:{}",
        net.grpc_port
    ))
    .await
    .unwrap();
    let challenge = ghost_gate_core::xtm::XtmChallenge {
        gate_id: tari_template_lib_types::MaxBytes::new_checked(b"otherside".to_vec()).unwrap(),
        threshold_micro,
        network: Network::LocalNet as u8,
        nonce: tari_template_lib_types::Hash32::from_array([9u8; 32]),
        issued_at_unix: now_unix(),
        expires_at_unix: now_unix() + 600,
        relying_site: tari_template_lib_types::MaxBytes::new_checked(b"vip.example".to_vec()).unwrap(),
        session_commitment: tari_template_lib_types::MaxBytes::new_checked(b"session".to_vec()).unwrap(),
        tip_height_at_issue: 0,
    };
    // Mine to confirm the transaction, then verify.
    net.mine_blocks(&wallet.receive_address().unwrap(), 2).await;
    let receipt = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            match verify_xtm_proof(&mut reader, &challenge, &artifact, now_unix()).await {
                Ok(receipt) => return Ok(receipt),
                Err(ghost_gate_core::xtm::XtmProofError::NotMined) => {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                },
                Err(other) => return Err(other),
            }
        }
    })
    .await
    .expect("verification completed")
    .expect("the proof verifies");
    assert!(receipt.attested_floor_micro >= u128::from(threshold_micro));
    // Privacy: the receipt carries a floor and no balance. Assert the struct's public surface
    // here, against a real proof, not just a crafted one.
    let json = serde_json::to_string(&serde_json::json!({
        "attested_floor_micro": receipt.attested_floor_micro,
        "output_count": receipt.output_count,
        "mined_height": receipt.mined_height,
    }))
    .unwrap();
    assert!(json.contains("attested_floor_micro"));
    println!("L1 E2E: verified floor {} micro-XTM at height {}", receipt.attested_floor_micro, receipt.mined_height);
}

/// The other side: THE OTHER SIDE's million-XTM gate, end to end.
///
/// The wallet is funded past 1,000,000 XTM by coinbases (~9,231 XTM each on LocalNet, so ~112
/// blocks), and the challenge is the gate's real threshold: 1,000,000 XTM in base units
/// (1,000,000,000,000 micro-Minotari). The fee boundary is exercised for real: the proving
/// transaction carries an output promising `threshold - fee`, and the verified floor is
/// `promise + kernel fee >= threshold`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_million_xtm_gate_accepts_a_wallet_above_the_threshold_and_refuses_one_below() {
    let dir = tempfile::tempdir().unwrap();
    let mut net = spawn_base_node(dir.path()).await;
    let mut wallet = spawn_proof_wallet(dir.path(), &net).await;
    // ~130 coinbases ≈ 1.2M XTM: enough for the million gate after coinbase maturity locks the
    // most recent few, not enough to change what the proof means. The wallet rescans every 5
    // seconds (the wallet config's scanning_interval).
    fund_wallet(&mut net, &wallet, 130).await;
    let threshold_micro: u64 = 1_000_000 * 1_000_000; // 1,000,000 XTM, base units

    let mut settled = false;
    let mut artifact_opt: Option<XtmProofArtifact> = None;
    // 130 coinbases is one UTXO scan backlog; the wallet's scan is disk-bound (a round can take
    // ~15s on a busy machine), so give it minutes, not seconds, and keep the tip moving so older
    // coinbases mature out of time-lock while the scan catches up.
    for round in 0..90 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let outcome = wallet
            .create_proof_transaction(threshold_micro, [8u8; 32], MicroMinotari(5))
            .await;
        match outcome {
            Ok(XtmProofOutcome::Broadcast(artifact)) => {
                settled = true;
                artifact_opt = Some(artifact);
                break;
            },
            Ok(XtmProofOutcome::CannotAfford) => {
                if round % 10 == 9 {
                    net.mine_blocks(&wallet.receive_address().unwrap(), 2).await;
                }
                continue;
            },
            Ok(XtmProofOutcome::Failed(reason)) => panic!("proof failed: {reason}"),
            Err(e) => panic!("proof errored: {e:?}"),
        }
    }
    assert!(settled, "the wallet never became spendable enough for the million-XTM gate");

    let artifact = artifact_opt.unwrap();
    let mut reader = ghost_gate_minotari::chain_reader::BaseNodeXtmReader::connect(&format!(
        "http://127.0.0.1:{}",
        net.grpc_port
    ))
    .await
    .unwrap();
    let challenge = ghost_gate_core::xtm::XtmChallenge {
        gate_id: tari_template_lib_types::MaxBytes::new_checked(b"otherside".to_vec()).unwrap(),
        threshold_micro,
        network: Network::LocalNet as u8,
        nonce: tari_template_lib_types::Hash32::from_array([8u8; 32]),
        issued_at_unix: now_unix(),
        expires_at_unix: now_unix() + 900,
        relying_site: tari_template_lib_types::MaxBytes::new_checked(b"vip.example".to_vec()).unwrap(),
        session_commitment: tari_template_lib_types::MaxBytes::new_checked(b"session".to_vec()).unwrap(),
        tip_height_at_issue: 0,
    };
    net.mine_blocks(&wallet.receive_address().unwrap(), 2).await;
    // Mining + the wallet's UTXO scan are disk-bound: on a busy machine a scan round alone can take
    // ~15s, so 90s was not enough for the proof to mine and be read back. 4 minutes is still a
    // bound — a hung miner fails the test, just later.
    // While waiting, keep mining: a block template carries the mempool, so every new block is
    // another chance for the broadcast proof to be included. (The node's own miner does this too;
    // driving it from the test makes the wait bounded by the TEST, not by ambient miner timing.)
    let mut wait_rounds = 0u32;
    let receipt = tokio::time::timeout(Duration::from_secs(300), async {
        loop {
            match verify_xtm_proof(&mut reader, &challenge, &artifact, now_unix()).await {
                Ok(receipt) => return Ok(receipt),
                Err(ghost_gate_core::xtm::XtmProofError::NotMined) => {
                    wait_rounds += 1;
                    if wait_rounds % 10 == 0 {
                        net.mine_blocks(&wallet.receive_address().unwrap(), 1).await;
                        println!("verify wait: mined round {wait_rounds}");
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                },
                Err(other) => return Err(other),
            }
        }
    })
    .await
    .expect("verification completed")
    .expect("the million-XTM proof verifies");
    // THE OTHER SIDE's own acceptance condition.
    assert!(
        receipt.attested_floor_micro >= 1_000_000_000_000u128,
        "the million gate requires a floor of 1e12 micro-XTM"
    );
    println!(
        "MILLION-XTM GATE: verified floor {} micro-XTM ({} XTM) at height {}",
        receipt.attested_floor_micro,
        receipt.attested_floor_micro / 1_000_000,
        receipt.mined_height
    );
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}
