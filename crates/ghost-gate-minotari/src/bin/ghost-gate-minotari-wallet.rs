//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! The Minotari proof wallet service.
//!
//! Runs a full Minotari wallet (synced against a base node) and exposes exactly two capabilities
//! over loopback HTTP: *status* and *prove* (plus rebroadcast for ambiguity resolution). It never
//! reports a balance, never signs anything but its own proof responses, and binds to the loopback
//! interface only.
//!
//! # Startup, end to end
//!
//! ```text
//!   base node (minotari_node, localnet)  ← the wallet syncs against this
//!        ↑ p2p + grpc
//!   ghost-gate-minotari-wallet           ← this binary; loopback HTTP :7807
//!        ↑ loopback HTTP
//!   ghost-gate-bridge  (GG_XTM_WALLET_ENDPOINT=http://127.0.0.1:7807)
//!        ↑ loopback HTTP
//!   Privacy Lab page
//! ```
//!
//! # Environment
//!
//! - `GG_XTM_BIND`            — loopback bind, default `127.0.0.1:7807` (non-loopback refused).
//! - `GG_XTM_NETWORK`         — `localnet` (default) / `esmeralda` / `stagenet` / `nextnet` / `mainnet`.
//! - `GG_XTM_BASE_PATH`       — where the wallet's databases live.
//! - `GG_XTM_PASSWORD`        — the wallet DB's passphrase. Required.
//! - `GG_XTM_BASE_NODE`       — the base node's p2p multiaddr (`/ip4/…/tcp/N`).
//! - `GG_XTM_BASE_NODE_KEY`   — the base node's public key, hex.
//! - `GG_XTM_BASE_NODE_HTTP`  — the base node's HTTP fetch address.
//! - `GG_XTM_FEE_PER_GRAM`    — micro-Minotari per gram, default 5.
//!
//! The passphrase may be provided by `GG_XTM_PASSWORD` only; it is never printed and never logged.

use std::process::ExitCode;
use std::str::FromStr;

use ghost_gate_minotari::artifact::XtmProofWire;
use ghost_gate_minotari::http::{ServeOp, serve};
use ghost_gate_minotari::service::{ProveRequestWire, ProveResponseWire, ServiceError, XtmProofOutcome};
use ghost_gate_minotari::wallet_service::{ProofWalletConfig, ProofWalletService};
use tari_common::configuration::Network;

fn main() -> ExitCode {
    let code = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(run());
    match code {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ghost-gate-minotari-wallet: {e}");
            ExitCode::FAILURE
        },
    }
}

async fn run() -> Result<(), String> {
    let bind = std::env::var("GG_XTM_BIND").unwrap_or_else(|_| "127.0.0.1:7807".to_string());
    let host = bind.split(':').next().unwrap_or("");
    if !matches!(host, "127.0.0.1" | "localhost" | "[::1]" | "::1") {
        return Err(format!(
            "GG_XTM_BIND must be a loopback address, got {bind:?}. This process holds a wallet's keys."
        ));
    }
    let password = std::env::var("GG_XTM_PASSWORD")
        .map_err(|_| "GG_XTM_PASSWORD must be set (the wallet database's passphrase)".to_string())?;
    let base_path = std::path::PathBuf::from(
        std::env::var("GG_XTM_BASE_PATH").unwrap_or_else(|_| "data/proof-wallet".to_string()),
    );
    let network = std::env::var("GG_XTM_NETWORK")
        .ok()
        .and_then(|n| Network::from_str(&n).ok())
        .unwrap_or(Network::LocalNet);
    let base_node_address = std::env::var("GG_XTM_BASE_NODE")
        .map_err(|_| "GG_XTM_BASE_NODE must name the base node's p2p multiaddr".to_string())?;
    let base_node_key = std::env::var("GG_XTM_BASE_NODE_KEY")
        .map_err(|_| "GG_XTM_BASE_NODE_KEY must be the base node's public key, hex".to_string())?;
    let base_node_http = std::env::var("GG_XTM_BASE_NODE_HTTP")
        .map_err(|_| "GG_XTM_BASE_NODE_HTTP must be the base node's HTTP address".to_string())?;
    let fee_per_gram = std::env::var("GG_XTM_FEE_PER_GRAM")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(ghost_gate_minotari::service::DEFAULT_FEE_PER_GRAM);

    let config = ProofWalletConfig {
        network,
        base_path: base_path.clone(),
        base_node_address,
        base_node_identity_public_key: base_node_key,
        base_node_http_url: base_node_http,
        fee_per_gram,
        broadcast_timeout: ghost_gate_minotari::service::DEFAULT_BROADCAST_TIMEOUT,
        listener_port: 0,
    };

    let shutdown = tari_shutdown::Shutdown::new();
    let service = ProofWalletService::start(config, password, shutdown.clone())
        .await
        .map_err(|e| e.to_string())?;

    let address = service
        .receive_address()
        .map_err(|e| e.to_string())?;
    println!("ghost-gate-minotari-wallet listening on {bind}");
    println!("  network: {}", network);
    println!("  spend public key: {}", service.spend_public_key_hex());
    println!("  receive address: {address}");
    println!("  wallet base path: {}", base_path.display());

    let fee = service.fee_per_gram;
    let mut service = service;
    serve(
        &bind,
        move |op| {
            match op {
                ServeOp::Status => {
                    let status = StatusWire::of(&service);
                    serde_json::to_string(&status).map_err(|e| ServiceError::Wallet(e.to_string()))
                },
                ServeOp::Prove(ProveRequestWire {
                    threshold_micro,
                    challenge_nonce_hex,
                }) => {
                    let nonce = parse_nonce(&challenge_nonce_hex)?;
                    let outcome = tokio_block_on(service.create_proof_transaction(
                        threshold_micro,
                        nonce,
                        tari_transaction_components::tari_amount::MicroMinotari(fee),
                    ));
                    match outcome {
                        Ok(XtmProofOutcome::Broadcast(artifact)) => {
                            serde_json::to_string(&ProveResponseWire::Broadcast {
                                artifact: XtmProofWire::from_artifact(&artifact),
                            })
                            .map_err(|e| ServiceError::Wallet(e.to_string()))
                        },
                        Ok(XtmProofOutcome::CannotAfford) => {
                            Ok(serde_json::to_string(&ProveResponseWire::CannotAfford).expect("static"))
                        },
                        Ok(XtmProofOutcome::Failed(reason)) => {
                            Ok(serde_json::to_string(&ProveResponseWire::Failed { reason }).expect("static"))
                        },
                        Err(e) => Ok(serde_json::to_string(&ProveResponseWire::Failed {
                            reason: e.to_string(),
                        })
                        .expect("static")),
                    }
                },
                ServeOp::Rebroadcast(tx_id) => {
                    let outcome = tokio_block_on(service.rebroadcast(tx_id));
                    match outcome {
                        Ok(()) => Ok("{}".to_string()),
                        Err(e) => Ok(format!(
                            "{{\"state\":\"failed\",\"reason\":\"{}\"}}",
                            e
                        )),
                    }
                },
            }
        },
        shutdown.to_signal(),
    )
    .await
    .map_err(|e| e.to_string())
}

/// The proof service runs its wallet work on the same runtime; the handler is synchronous by
/// shape, so this drives the future to completion. The service's own operations are the only
/// things that run here — no re-entrancy is possible on the loopback server's single connection.
fn tokio_block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(fut))
}

fn parse_nonce(hex_str: &str) -> Result<[u8; 32], ServiceError> {
    let bytes = hex::decode(hex_str.trim()).map_err(|_| ServiceError::MalformedNonce)?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| ServiceError::MalformedNonce)
}

#[derive(serde::Serialize)]
struct StatusWire {
    reachable: bool,
    network: u8,
    network_name: String,
    spend_public_key: Option<String>,
}

impl StatusWire {
    fn of(service: &ProofWalletService) -> Self {
        Self {
            reachable: true,
            network: service.network as u8,
            network_name: service.network.to_string(),
            spend_public_key: Some(service.spend_public_key_hex()),
        }
    }
}
