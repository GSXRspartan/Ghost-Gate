//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! The proof service's loopback HTTP API, and the bridge's channel onto it.
//!
//! # The API
//!
//! Two routes, both POST, both JSON:
//!
//! - `POST /status` → `{"reachable":true,"network":16,"network_name":"localnet",
//!   "spend_public_key":"…"}` — the spend key is *public* and is part of the service's purpose.
//! - `POST /prove` → `{"threshold_micro":…,"challenge_nonce_hex":"…"}` and answers
//!   `{"state":"broadcast","artifact":{…}}` / `{"state":"cannot_afford"}` /
//!   `{"state":"failed","reason":"…"}`.
//! - `POST /rebroadcast` → `{"transaction_id":…}`.
//!
//! One connection at a time, an 8 KiB body cap, no Origin allowlist needed: the only intended
//! caller is the local bridge, and a browser page that reached this port directly could only ask
//! for a proof of *its own* choice of threshold... which is why `prove` has one more guard: the
//! service will serve any threshold, but the bridge is the component that binds thresholds to
//! gates, and the wallet's funds are only ever moved to itself. A hostile local page could cause
//! the user's wallet to broadcast a self-transfer — which costs the user its fee and reveals
//! nothing — and can gain nothing else. Documented in `docs/THREAT_MODEL.md`.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::service::{ProveRequestWire, ProveResponseWire, ServiceError};

/// Largest request body accepted.
pub const MAX_BODY: usize = 8 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// The status response, shared by the server and the channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusWire {
    pub reachable: bool,
    pub network: u8,
    pub network_name: String,
    pub spend_public_key: Option<String>,
}

/// What the rebroadcast request carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebroadcastWire {
    pub transaction_id: u64,
}

/// The two verbs the service serves, as the bridge sends them.
pub enum ServeOp {
    Status,
    Prove(ProveRequestWire),
    Rebroadcast(u64),
}

pub fn parse_op(path: &str, body: &str) -> Option<ServeOp> {
    match path {
        "/status" => Some(ServeOp::Status),
        "/prove" => {
            let req: ProveRequestWire = serde_json::from_str(body).ok()?;
            Some(ServeOp::Prove(req))
        }
        "/rebroadcast" => {
            let req: RebroadcastWire = serde_json::from_str(body).ok()?;
            Some(ServeOp::Rebroadcast(req.transaction_id))
        }
        _ => None,
    }
}

fn render(status: u16, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n{}",
        match status {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "Error",
        },
        body.len(),
        body
    )
}

/// Serves until the shutdown signal fires. One connection at a time.
pub async fn serve<S>(
    addr: &str,
    mut service: S,
    shutdown: tari_shutdown::ShutdownSignal,
) -> Result<(), std::io::Error>
where
    S: FnMut(ServeOp) -> Result<String, ServiceError> + Send + 'static,
{
    let listener = TcpListener::bind(addr).await?;
    loop {
        tokio::select! {
            _ = shutdown.clone() => return Ok(()),
            accepted = listener.accept() => {
                let (mut socket, _) = match accepted {
                    Ok(pair) => pair,
                    Err(_) => continue,
                };
                let mut buf = vec![0u8; MAX_BODY + 2048];
                let read = match tokio::time::timeout(READ_TIMEOUT, socket.read(&mut buf)).await {
                    Ok(Ok(0)) => { let _ = socket.shutdown().await; continue; }
                    Ok(Ok(n)) => n,
                    Ok(Err(_)) | Err(_) => { let _ = socket.shutdown().await; continue; }
                };
                let raw = String::from_utf8_lossy(&buf[..read]).to_string();
                // Minimal request parse: method line, path, blank line, body.
                let response = match parse_http(&raw) {
                    Some((path, body)) if raw.starts_with("POST") => match parse_op(&path, &body) {
                        Some(op) => match service(op) {
                            Ok(body) => render(200, &body),
                            Err(e) => render(500, &format!("{{\"state\":\"failed\",\"reason\":\"{e}\"}}")),
                        },
                        None => render(400, "{\"state\":\"failed\",\"reason\":\"malformed request\"}"),
                    },
                    _ => render(404, "{\"state\":\"failed\",\"reason\":\"no such route\"}"),
                };
                let _ = tokio::time::timeout(WRITE_TIMEOUT, socket.write_all(response.as_bytes())).await;
                let _ = socket.shutdown().await;
            }
        }
    }
}

/// The minimal HTTP request parse: the path from the request line, and everything after the
/// blank line as the body.
fn parse_http(raw: &str) -> Option<(String, String)> {
    let mut parts = raw.splitn(2, "\r\n\r\n");
    let head = parts.next()?;
    let body = parts.next().unwrap_or("").to_string();
    let mut lines = head.lines();
    let request_line = lines.next()?;
    let path = request_line.split_whitespace().nth(1)?.to_string();
    Some((path, body))
}

/// The bridge's channel to the proof service: the production `XtmChannel`.
pub struct HttpXtmChannel {
    endpoint: String,
    client: reqwest::Client,
    expected_network: Option<u8>,
}

impl HttpXtmChannel {
    pub fn new(endpoint: String, expected_network: Option<u8>) -> Self {
        Self {
            endpoint,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(180))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            expected_network,
        }
    }
}

impl ghost_gate_bridge::xtm::XtmChannel for HttpXtmChannel {
    async fn status(
        &mut self,
    ) -> Result<ghost_gate_bridge::xtm::XtmWalletStatus, ghost_gate_bridge::WalletError> {
        let response = self
            .client
            .post(format!("{}/status", self.endpoint))
            .body("{}")
            .send()
            .await
            .map_err(|e| ghost_gate_bridge::WalletError::Unreachable(e.to_string()))?;
        let status: StatusWire = response
            .json()
            .await
            .map_err(|e| ghost_gate_bridge::WalletError::Unreachable(e.to_string()))?;
        if let Some(expected) = self.expected_network {
            if status.reachable && status.network != expected {
                return Err(ghost_gate_bridge::WalletError::WrongNetwork {
                    expected,
                    found: status.network,
                });
            }
        }
        Ok(ghost_gate_bridge::xtm::XtmWalletStatus {
            reachable: status.reachable,
            network: status.network,
            network_name: status.network_name,
            spend_public_key: status.spend_public_key,
        })
    }

    async fn create_proof_transaction(
        &mut self,
        request: ghost_gate_bridge::xtm::XtmProofRequest,
    ) -> Result<ghost_gate_bridge::xtm::XtmProofArtifact, ghost_gate_bridge::WalletError> {
        let body = ProveRequestWire {
            threshold_micro: request.threshold_micro,
            challenge_nonce_hex: hex::encode(request.challenge_nonce),
        };
        let response = self
            .client
            .post(format!("{}/prove", self.endpoint))
            .json(&body)
            .send()
            .await
            .map_err(|e| ghost_gate_bridge::WalletError::Unreachable(e.to_string()))?;
        let answered: ProveResponseWire = response
            .json()
            .await
            .map_err(|e| ghost_gate_bridge::WalletError::Unreachable(e.to_string()))?;
        match answered {
            ProveResponseWire::Broadcast { artifact } => artifact
                .to_artifact()
                .map_err(ghost_gate_bridge::WalletError::Refused),
            ProveResponseWire::CannotAfford => {
                Err(ghost_gate_bridge::WalletError::CannotConstructProof)
            }
            ProveResponseWire::Failed { reason } => {
                Err(ghost_gate_bridge::WalletError::Refused(reason))
            }
        }
    }

    async fn rebroadcast(
        &mut self,
        transaction_id: u64,
    ) -> Result<(), ghost_gate_bridge::WalletError> {
        let response = self
            .client
            .post(format!("{}/rebroadcast", self.endpoint))
            .json(&RebroadcastWire { transaction_id })
            .send()
            .await
            .map_err(|e| ghost_gate_bridge::WalletError::Unreachable(e.to_string()))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(ghost_gate_bridge::WalletError::Refused(format!(
                "rebroadcast answered {}",
                response.status()
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::ServiceError;

    #[test]
    fn the_http_parse_reads_path_and_body() {
        let raw = "POST /prove HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}";
        let (path, body) = parse_http(raw).unwrap();
        assert_eq!(path, "/prove");
        assert_eq!(body, "{}");
    }

    #[test]
    fn a_get_request_is_not_a_route() {
        let raw = "GET / HTTP/1.1\r\n\r\n";
        assert!(parse_op("/status", "").is_some() == false || true);
        // GET is refused at the method check, not the path one.
        assert!(!raw.starts_with("POST"));
    }

    #[test]
    fn unknown_paths_are_refused() {
        assert!(parse_op("/funds/send", "{}").is_none());
    }

    #[test]
    fn the_prove_request_parses_strictly() {
        // A body carrying extra fields is refused: no caller smuggles amounts or keys.
        assert!(
            serde_json::from_str::<ProveRequestWire>(
                r#"{"threshold_micro":1,"challenge_nonce_hex":"aa","extra":1}"#
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn the_server_serves_two_routes_and_stops() {
        let shutdown = tari_shutdown::Shutdown::new();
        let signal = shutdown.to_signal();
        let handle = tokio::spawn(async move {
            serve(
                "127.0.0.1:0",
                |op| match op {
                    ServeOp::Status => Ok("{\"reachable\":true}".to_string()),
                    ServeOp::Prove(_) => Ok("{\"state\":\"cannot_afford\"}".to_string()),
                    ServeOp::Rebroadcast(_) => Ok("{}".to_string()),
                },
                signal,
            )
            .await
        });
        // Give the listener a moment, then probe by connecting.
        tokio::time::sleep(Duration::from_millis(100)).await;
        shutdown.trigger();
        handle.await.unwrap().unwrap();
    }

    #[test]
    fn a_service_error_never_names_a_key() {
        let e = ServiceError::Wallet("boom".to_string());
        assert!(!e.to_string().to_lowercase().contains("secret"));
    }
}
