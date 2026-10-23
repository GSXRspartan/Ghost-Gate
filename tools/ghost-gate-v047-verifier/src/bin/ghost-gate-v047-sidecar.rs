//! Loopback-only, read-only v0.47 consensus verification sidecar.
//!
//! It has no walletd client, wallet profile, signing key, transaction builder, or public bind.
//! A missing or unreviewed anchor intentionally leaves the service unready and every verification
//! request `UNKNOWN`; this makes an incomplete Esmeralda bootstrap operationally visible.

use std::{env, fs, process::ExitCode, str, sync::Arc, time::Duration};

use ghost_gate_v047_verifier::{ConsensusProofRequest, PinnedAnchorConfig};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore},
    time::timeout,
};

/// The complete loopback HTTP request, including headers. A genuine captured Esmeralda checkpoint
/// was approximately 29 KiB; 64 KiB permits one checkpoint plus request framing while retaining
/// bounded memory and preventing an unbounded multi-handover request.
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_HEADER_BYTES: usize = 8 * 1024;
const MAX_BODY_BYTES: usize = MAX_REQUEST_BYTES - MAX_HEADER_BYTES - 4;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_IN_FLIGHT_REQUESTS: usize = 8;

#[derive(Debug, PartialEq, Eq)]
enum RequestReadError {
    TooLarge,
    Malformed,
    Truncated,
    TimedOut,
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    authorization: Option<String>,
    has_content_length: bool,
    body: Vec<u8>,
}

fn response(status: u16, body: &str) -> String {
    let phrase = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    format!(
        "HTTP/1.1 {status} {phrase}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_header(bytes: &[u8]) -> Result<(String, String, Option<String>, Option<usize>), RequestReadError> {
    let header = str::from_utf8(bytes).map_err(|_| RequestReadError::Malformed)?;
    let mut lines = header.split("\r\n");
    let request_line = lines.next().ok_or(RequestReadError::Malformed)?;
    let mut parts = request_line.split_ascii_whitespace();
    let method = parts.next().ok_or(RequestReadError::Malformed)?;
    let path = parts.next().ok_or(RequestReadError::Malformed)?;
    if method.is_empty() || path.is_empty() || parts.next() != Some("HTTP/1.1") || parts.next().is_some() {
        return Err(RequestReadError::Malformed);
    }

    let mut authorization = None;
    let mut content_length = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(RequestReadError::Malformed)?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("authorization") {
            if authorization.replace(value.to_owned()).is_some() {
                return Err(RequestReadError::Malformed);
            }
        } else if name.eq_ignore_ascii_case("content-length") {
            let parsed = value.parse::<usize>().map_err(|_| RequestReadError::Malformed)?;
            if content_length.replace(parsed).is_some() {
                return Err(RequestReadError::Malformed);
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(RequestReadError::Malformed);
        }
    }
    Ok((method.to_owned(), path.to_owned(), authorization, content_length))
}

async fn read_http_request_with_timeout<S: AsyncRead + Unpin>(
    socket: &mut S,
    deadline: Duration,
) -> Result<HttpRequest, RequestReadError> {
    timeout(deadline, read_http_request(socket))
        .await
        .map_err(|_| RequestReadError::TimedOut)?
}

async fn read_http_request<S: AsyncRead + Unpin>(socket: &mut S) -> Result<HttpRequest, RequestReadError> {
    let mut bytes = Vec::with_capacity(4096);
    let mut scratch = [0u8; 4096];
    let (header_end, method, path, authorization, content_length) = loop {
        if let Some(header_end) = header_end(&bytes) {
            if header_end > MAX_HEADER_BYTES {
                return Err(RequestReadError::TooLarge);
            }
            let (method, path, authorization, content_length) = parse_header(&bytes[..header_end])?;
            break (header_end, method, path, authorization, content_length);
        }
        if bytes.len() >= MAX_HEADER_BYTES {
            return Err(RequestReadError::TooLarge);
        }
        let read = socket.read(&mut scratch).await.map_err(|_| RequestReadError::Truncated)?;
        if read == 0 {
            return Err(RequestReadError::Truncated);
        }
        bytes.extend_from_slice(&scratch[..read]);
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(RequestReadError::TooLarge);
        }
    };

    let has_content_length = content_length.is_some();
    let content_length = content_length.unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        return Err(RequestReadError::TooLarge);
    }
    let body_start = header_end + 4;
    let expected_len = body_start.checked_add(content_length).ok_or(RequestReadError::TooLarge)?;
    if expected_len > MAX_REQUEST_BYTES {
        return Err(RequestReadError::TooLarge);
    }
    while bytes.len() < expected_len {
        let read = socket.read(&mut scratch).await.map_err(|_| RequestReadError::Truncated)?;
        if read == 0 {
            return Err(RequestReadError::Truncated);
        }
        bytes.extend_from_slice(&scratch[..read]);
        if bytes.len() > expected_len {
            return Err(RequestReadError::Malformed);
        }
    }
    if bytes.len() != expected_len {
        return Err(RequestReadError::Malformed);
    }
    Ok(HttpRequest {
        method,
        path,
        authorization,
        has_content_length,
        body: bytes[body_start..].to_vec(),
    })
}

async fn serve_connection(
    mut socket: TcpStream,
    token: Arc<String>,
    readiness: Arc<Mutex<Option<(ghost_gate_v047_verifier::PinnedConsensusVerifier, u64)>>>,
) {
    let body = match read_http_request_with_timeout(&mut socket, REQUEST_TIMEOUT).await {
        Err(RequestReadError::TooLarge) => response(413, r#"{"verdict":"UNKNOWN","reason":"request_too_large"}"#),
        Err(RequestReadError::TimedOut) => response(408, r#"{"verdict":"UNKNOWN","reason":"request_timeout"}"#),
        Err(_) => response(400, r#"{"verdict":"UNKNOWN","reason":"malformed_request"}"#),
        Ok(request) => match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/health") if request.body.is_empty() => {
                if readiness.lock().await.is_some() {
                    response(200, r#"{"service":"ghost-gate-v047-sidecar","ready":true,"mode":"pinned-anchor"}"#)
                } else {
                    response(503, r#"{"service":"ghost-gate-v047-sidecar","ready":false,"reason":"untrusted_anchor"}"#)
                }
            }
            ("POST", "/v1/verify") if !request.has_content_length => {
                response(400, r#"{"verdict":"EVIDENCE_UNAVAILABLE","reason":"content_length_required"}"#)
            }
            ("POST", "/v1/verify") if request.authorization.as_deref() != Some(&format!("Bearer {token}")) => {
                response(401, r#"{"error":"GG: sidecar caller is not authorized"}"#)
            }
            ("POST", "/v1/verify") => {
                let mut state = readiness.lock().await;
                match state.as_mut() {
                    None => response(503, r#"{"verdict":"ANCHOR_UNTRUSTED","reason":"untrusted_anchor"}"#),
                    Some((verifier, max_age)) => match serde_json::from_slice::<ConsensusProofRequest>(&request.body) {
                        Ok(request) => response(
                            200,
                            &serde_json::to_string(&verifier.verify_request(*max_age, &request))
                                .expect("result serialises"),
                        ),
                        Err(_) => response(400, r#"{"verdict":"EVIDENCE_UNAVAILABLE","reason":"malformed_request"}"#),
                    },
                }
            }
            _ => response(404, r#"{"error":"GG: route not found"}"#),
        },
    };
    let _ = timeout(REQUEST_TIMEOUT, socket.write_all(body.as_bytes())).await;
    let _ = socket.shutdown().await;
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let bind = env::var("GG_V047_SIDECAR_BIND").unwrap_or_else(|_| "127.0.0.1:7902".into());
    if !bind.starts_with("127.0.0.1:") && !bind.starts_with("[::1]:") && !bind.starts_with("localhost:") {
        eprintln!("ghost-gate-v047-sidecar: bind must be loopback");
        return ExitCode::FAILURE;
    }
    let token = match env::var("GG_V047_SIDECAR_TOKEN").ok().filter(|value| !value.is_empty()) {
        Some(value) => Arc::new(value),
        None => {
            eprintln!("ghost-gate-v047-sidecar: GG_V047_SIDECAR_TOKEN is required");
            return ExitCode::FAILURE;
        }
    };
    let readiness = env::var("GG_V047_ANCHOR_CONFIG")
        .ok()
        .and_then(|path| fs::read_to_string(path).ok())
        .and_then(|json| serde_json::from_str::<PinnedAnchorConfig>(&json).ok())
        .and_then(|config| config.into_verifier().ok());
    let readiness = Arc::new(Mutex::new(readiness));
    let listener = match TcpListener::bind(&bind).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("ghost-gate-v047-sidecar: cannot bind {bind}: {error}");
            return ExitCode::FAILURE;
        }
    };
    let permits = Arc::new(Semaphore::new(MAX_IN_FLIGHT_REQUESTS));
    eprintln!("ghost-gate-v047-sidecar: listening on {bind}; ready={}", readiness.lock().await.is_some());
    loop {
        let Ok((socket, _)) = listener.accept().await else {
            continue;
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            let _ = timeout(REQUEST_TIMEOUT, async {
                let mut socket = socket;
                socket.write_all(response(503, r#"{"verdict":"UNKNOWN","reason":"sidecar_busy"}"#).as_bytes()).await
            }).await;
            continue;
        };
        let token = Arc::clone(&token);
        let readiness = Arc::clone(&readiness);
        tokio::spawn(async move {
            let _permit = permit;
            serve_connection(socket, token, readiness).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncWriteExt, duplex};

    use super::*;

    async fn read_from_chunks(chunks: Vec<Vec<u8>>) -> Result<HttpRequest, RequestReadError> {
        let (mut client, mut server) = duplex(MAX_REQUEST_BYTES + 1024);
        let writer = tokio::spawn(async move {
            for chunk in chunks {
                client.write_all(&chunk).await.unwrap();
            }
            client.shutdown().await.unwrap();
        });
        let request = read_http_request_with_timeout(&mut server, Duration::from_secs(1)).await;
        writer.await.unwrap();
        request
    }

    #[tokio::test]
    async fn accepts_fragmented_checkpoint_sized_request() {
        // The genuine 12634 checkpoint response captured for review was approximately 29 KiB.
        // This is a syntactic stand-in for its body, not consensus evidence.
        let body = format!(r#"{{"checkpoint":"{}"}}"#, "a".repeat(29 * 1024));
        let header = format!(
            "POST /v1/verify HTTP/1.1\r\nAuthorization: Bearer test\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let request = read_from_chunks(vec![
            [header.as_bytes(), &body.as_bytes()[..73]].concat(),
            body.as_bytes()[73..4096].to_vec(),
            body.as_bytes()[4096..].to_vec(),
        ])
        .await
        .unwrap();
        assert_eq!(request.body.len(), body.len());
        assert_eq!(request.authorization.as_deref(), Some("Bearer test"));
    }

    #[tokio::test]
    async fn rejects_oversized_and_truncated_requests() {
        let oversized = format!(
            "POST /v1/verify HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        assert_eq!(
            read_from_chunks(vec![oversized.into_bytes()]).await.unwrap_err(),
            RequestReadError::TooLarge
        );
        let truncated = b"POST /v1/verify HTTP/1.1\r\nContent-Length: 5\r\n\r\n12".to_vec();
        assert_eq!(
            read_from_chunks(vec![truncated]).await.unwrap_err(),
            RequestReadError::Truncated
        );
    }

    #[tokio::test]
    async fn rejects_malformed_framing_and_times_out() {
        let malformed = b"POST /v1/verify HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        assert_eq!(
            read_from_chunks(vec![malformed]).await.unwrap_err(),
            RequestReadError::Malformed
        );
        let (_client, mut server) = duplex(32);
        assert_eq!(
            read_http_request_with_timeout(&mut server, Duration::from_millis(1))
                .await
                .unwrap_err(),
            RequestReadError::TimedOut
        );
    }
}
