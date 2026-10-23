//! Loopback-only, read-only v0.47 consensus verification sidecar.
//!
//! It has no walletd client, wallet profile, signing key, transaction builder, or public bind.
//! A missing or unreviewed anchor intentionally leaves the service unready and every verification
//! request `UNKNOWN`; this makes an incomplete Esmeralda bootstrap operationally visible.

use std::{env, fs, process::ExitCode, sync::Arc};

use ghost_gate_v047_verifier::{ConsensusProofRequest, PinnedAnchorConfig};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpListener, sync::Mutex};

const MAX_REQUEST_BYTES: usize = 16 * 1024;

fn response(status: u16, body: &str) -> String {
    let phrase = match status { 200 => "OK", 401 => "Unauthorized", 404 => "Not Found", 413 => "Payload Too Large", 503 => "Service Unavailable", _ => "Bad Request" };
    format!("HTTP/1.1 {status} {phrase}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
}

fn request(raw: &str) -> Option<(&str, &str, Option<&str>, &str)> {
    let (head, body) = raw.split_once("\r\n\r\n")?;
    let mut lines = head.split("\r\n");
    let mut request = lines.next()?.split_ascii_whitespace();
    let method = request.next()?; let path = request.next()?;
    let authorization = lines.filter_map(|line| line.split_once(':'))
        .find_map(|(name, value)| name.eq_ignore_ascii_case("authorization").then_some(value.trim()));
    Some((method, path, authorization, body))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let bind = env::var("GG_V047_SIDECAR_BIND").unwrap_or_else(|_| "127.0.0.1:7902".into());
    if !bind.starts_with("127.0.0.1:") && !bind.starts_with("[::1]:") && !bind.starts_with("localhost:") {
        eprintln!("ghost-gate-v047-sidecar: bind must be loopback"); return ExitCode::FAILURE;
    }
    let token = match env::var("GG_V047_SIDECAR_TOKEN").ok().filter(|value| !value.is_empty()) {
        Some(value) => value, None => { eprintln!("ghost-gate-v047-sidecar: GG_V047_SIDECAR_TOKEN is required"); return ExitCode::FAILURE; }
    };
    let readiness = env::var("GG_V047_ANCHOR_CONFIG").ok()
        .and_then(|path| fs::read_to_string(path).ok())
        .and_then(|json| serde_json::from_str::<PinnedAnchorConfig>(&json).ok())
        .and_then(|config| config.into_verifier().ok());
    let readiness = Arc::new(Mutex::new(readiness));
    let listener = match TcpListener::bind(&bind).await { Ok(listener) => listener, Err(error) => { eprintln!("ghost-gate-v047-sidecar: cannot bind {bind}: {error}"); return ExitCode::FAILURE; } };
    eprintln!("ghost-gate-v047-sidecar: listening on {bind}; ready={}", readiness.lock().await.is_some());
    loop {
        let Ok((mut socket, _)) = listener.accept().await else { continue; };
        let mut bytes = vec![0u8; MAX_REQUEST_BYTES + 1];
        let Ok(read) = socket.read(&mut bytes).await else { continue; };
        let body = if read > MAX_REQUEST_BYTES { response(413, r#"{"verdict":"UNKNOWN","reason":"request_too_large"}"#) } else {
            match request(&String::from_utf8_lossy(&bytes[..read])) {
                Some(("GET", "/health", _, _)) if readiness.lock().await.is_some() => response(200, r#"{"service":"ghost-gate-v047-sidecar","ready":true,"mode":"pinned-anchor"}"#),
                Some(("GET", "/health", _, _)) => response(503, r#"{"service":"ghost-gate-v047-sidecar","ready":false,"reason":"untrusted_anchor"}"#),
                Some(("POST", "/v1/verify", Some(auth), body)) if auth == format!("Bearer {token}") => {
                    let mut state = readiness.lock().await;
                    match state.as_mut() {
                        None => response(503, r#"{"verdict":"ANCHOR_UNTRUSTED","reason":"untrusted_anchor"}"#),
                        Some((verifier, max_age)) => match serde_json::from_str::<ConsensusProofRequest>(body) {
                            Ok(request) => response(200, &serde_json::to_string(&verifier.verify_request(*max_age, &request)).expect("result serialises")),
                            Err(_) => response(400, r#"{"verdict":"EVIDENCE_UNAVAILABLE","reason":"malformed_request"}"#),
                        },
                    }
                }
                Some(("POST", "/v1/verify", _, _)) => response(401, r#"{"error":"GG: sidecar caller is not authorized"}"#),
                _ => response(404, r#"{"error":"GG: route not found"}"#),
            }
        };
        let _ = socket.write_all(body.as_bytes()).await;
        let _ = socket.shutdown().await;
    }
}
