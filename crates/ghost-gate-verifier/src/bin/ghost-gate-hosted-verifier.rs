//! Narrow, authenticated hosted-verifier endpoint.
//!
//! This process is intentionally useful before a chain adapter exists: it proves the Worker ↔
//! verifier authentication and canonical signature contract while returning only `UNKNOWN`. It
//! cannot grant access, spend funds, connect to walletd, or read a wallet profile.

use std::process::ExitCode;

use ghost_gate_verifier::hosted::{
    HostedVerificationRequest, canonical_request, sign_result, verification_id, verify_fail_closed,
    verify_hmac_sha256_hex,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const MAX_BODY: usize = 16 * 1024;

fn env_required(name: &str) -> Result<String, String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} is required"))
}

fn response(status: u16, body: &str, signature: Option<&str>) -> String {
    let phrase = match status { 200 => "OK", 202 => "Accepted", 400 => "Bad Request", 401 => "Unauthorized", 404 => "Not Found", _ => "Service Unavailable" };
    let signature = signature.map(|value| format!("X-GG-Verifier-Signature: {value}\r\n")).unwrap_or_default();
    format!("HTTP/1.1 {status} {phrase}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n{signature}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
}

fn parse(raw: &str) -> Option<(&str, &str, Option<&str>, Option<&str>, &str)> {
    let (head, body) = raw.split_once("\r\n\r\n")?;
    let mut lines = head.split("\r\n");
    let request = lines.next()?;
    let mut parts = request.split_ascii_whitespace();
    let method = parts.next()?; let path = parts.next()?;
    let headers = lines.filter_map(|line| line.split_once(':')).collect::<Vec<_>>();
    let value = |name: &str| headers.iter().find_map(|(header, value)|
        header.eq_ignore_ascii_case(name).then_some(value.trim()));
    Some((method, path, value("authorization"), value("x-gg-verifier-request-signature"), body))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let bind = std::env::var("GG_HOSTED_VERIFIER_BIND").unwrap_or_else(|_| "127.0.0.1:7901".into());
    if !bind.starts_with("127.0.0.1:") && !bind.starts_with("[::1]:") && !bind.starts_with("localhost:") {
        eprintln!("ghost-gate-hosted-verifier: bind must be loopback"); return ExitCode::FAILURE;
    }
    let token = match env_required("GG_VERIFIER_TOKEN") { Ok(value) => value, Err(error) => { eprintln!("ghost-gate-hosted-verifier: {error}"); return ExitCode::FAILURE; } };
    let request_key = match env_required("GG_VERIFIER_REQUEST_KEY") { Ok(value) => value, Err(error) => { eprintln!("ghost-gate-hosted-verifier: {error}"); return ExitCode::FAILURE; } };
    let signing_key = match env_required("GG_VERIFIER_RESPONSE_KEY") { Ok(value) => value, Err(error) => { eprintln!("ghost-gate-hosted-verifier: {error}"); return ExitCode::FAILURE; } };
    let listener = match TcpListener::bind(&bind).await { Ok(listener) => listener, Err(error) => { eprintln!("ghost-gate-hosted-verifier: cannot bind {bind}: {error}"); return ExitCode::FAILURE; } };
    eprintln!("ghost-gate-hosted-verifier: listening on {bind}; authenticated chain verification is disabled and every request returns UNKNOWN");
    loop {
        let Ok((mut socket, _)) = listener.accept().await else { continue; };
        let mut bytes = vec![0u8; MAX_BODY + 4096];
        let Ok(read) = socket.read(&mut bytes).await else { continue; };
        if read == 0 { continue; }
        let raw = String::from_utf8_lossy(&bytes[..read]);
        let output = match parse(&raw) {
            Some(("GET", "/health", _, _, _)) => response(200, r#"{"service":"ghost-gate-hosted-verifier","mode":"fail_closed"}"#, None),
            Some(("POST", "/v1/hosted/verify", Some(auth), Some(request_signature), body)) if auth == format!("Bearer {token}") => {
                match serde_json::from_str::<HostedVerificationRequest>(body) {
                    Ok(request) if verify_hmac_sha256_hex(request_signature, request_key.as_bytes(), canonical_request(&request).as_bytes()) => match verify_fail_closed(&request, verification_id(&request)) {
                    Ok(result) => {
                        let body = serde_json::to_string(&result).expect("result serialises");
                        let signature = sign_result(&result, signing_key.as_bytes());
                        response(200, &body, Some(&signature))
                    }
                    Err(_) => response(400, r#"{"error":"GG: invalid hosted verifier request"}"#, None),
                    },
                    Ok(_) => response(401, r#"{"error":"GG: verifier request signature is invalid"}"#, None),
                    Err(_) => response(400, r#"{"error":"GG: invalid hosted verifier request"}"#, None),
                }
            }
            Some(("POST", "/v1/hosted/verify", _, _, _)) => response(401, r#"{"error":"GG: verifier caller is not authorized"}"#, None),
            _ => response(404, r#"{"error":"GG: route not found"}"#, None),
        };
        let _ = socket.write_all(output.as_bytes()).await;
        let _ = socket.shutdown().await;
    }
}
