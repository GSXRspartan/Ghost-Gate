//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! A deliberately small HTTP surface.
//!
//! Six routes, no framework, no middleware stack, no router crate. The reason is auditability: the
//! security-relevant behaviour of this process is "which request may do what", and that should be
//! readable in one screen rather than assembled from a framework's defaults. Everything a framework
//! would have done here — path parsing, header extraction, JSON encoding, status codes — is a dozen
//! lines each, and writing them out means there is no behaviour nobody chose.
//!
//! ```text
//! GET  /health                 is the bridge up, and how many gates it serves
//! GET  /wallet/status          is a wallet reachable, and on which cohort
//! GET  /gate/:id               public gate metadata: address, threshold, divisibility
//! POST /gate/:id/challenge     mint a fresh, single-use challenge for that gate
//! POST /gate/:id/prove         ask for a proof; returns a job id immediately
//! GET  /proof/:id/status       poll the job: accepted, refused, or still working
//! ```
//!
//! # What the responses may contain
//!
//! Every response body is one of: [`PublicGate`], a challenge (which the prover must publish anyway),
//! a [`ProofStatus`], [`WalletStatus`], or an error string. There is no route that returns a balance, a
//! key, a mask, a UTXO identifier or an inventory, and there is no route that accepts one. That is the
//! privacy boundary expressed as an API surface rather than as a promise.

use serde::Serialize;

/// A parsed request, reduced to what the routes use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: &'static str,
    /// The path with its leading slash, and no query string.
    pub path: String,
    /// The `Origin` header, if the caller sent one. `None` means not a browser.
    pub origin: Option<String>,
    /// Query parameters, parsed from the target. Only routes that take parameters read this; the
    /// map is present so a route can require a parameter rather than silently defaulting.
    pub query: std::collections::BTreeMap<String, String>,
    /// The `Host` header, if the caller sent one.
    ///
    /// Checked because of DNS rebinding: a page that resolves a name it controls to `127.0.0.1`
    /// reaches this bridge with *same-origin* requests, which carry no `Origin` header and so pass
    /// the origin allowlist precisely because they look like the operator's own CLI. The `Host`
    /// header is what distinguishes them: a browser sends the name it typed, not the address it
    /// connected to. See `Bridge::handle`.
    pub host: Option<String>,
    /// The request body, already bounded by the caller.
    pub body: String,
}

/// A response, ready to serialise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: String,
    /// Binary payload for the rare assets that are not text (the Spire's audio). When set it is
    /// written instead of `body`, which then stays empty. An mp3 is bytes, not lossy UTF-8, and a
    /// bridge that mangles its own assets is a bridge the game cannot use.
    pub raw: Option<Vec<u8>>,
}

impl Response {
    pub fn json<T: Serialize>(status: u16, value: &T) -> Self {
        // Serialising our own types cannot fail; a failure here would mean a type with a map key that is
        // not a string, which serde_json reports rather than panicking.
        let body = serde_json::to_string(value).unwrap_or_else(|e| {
            format!(
                "{{\"error\":\"response could not be serialised: {}\"}}",
                e.to_string().replace('"', "'")
            )
        });
        Self {
            status,
            content_type: "application/json",
            body,
            raw: None,
        }
    }

    /// A raw binary payload (audio, images). Never routed through the UTF-8 text path.
    pub fn binary(status: u16, content_type: &'static str, bytes: Vec<u8>) -> Self {
        Self { status, content_type, body: String::new(), raw: Some(bytes) }
    }

    pub fn error(status: u16, message: impl std::fmt::Display) -> Self {
        Self::json(status, &serde_json::json!({ "error": message.to_string() }))
    }
}

/// Which route a path names, and what it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route<'a> {
    Health,
    WalletStatus,
    /// `GET /gate/:id`
    Gate(&'a str),
    /// `POST /gate/:id/challenge`
    Challenge(&'a str),
    /// `POST /gate/:id/prove`
    Prove(&'a str),
    /// `POST /gate/:id/credential` — the credential proof mode (browser wallets).
    Credential(&'a str),
    /// `GET /proof/:id/status`
    ProofStatus(&'a str),
    /// Server-side verified-access check: token + gate. The decision is computed here, never in
    /// a browser.
    AccessCheck,
    /// A file from the bridge's own static directory: `GET /`, `/app.css`, `/app.js`.
    ///
    /// Served by the bridge rather than by a second server so the page and the API share one origin.
    /// That is not cosmetic: a page on any other origin would need CORS, and a CORS-enabled wallet
    /// bridge is a wallet bridge every page can reach.
    Asset(&'a str),
    /// A file of the Buried Spire game (the reused dungeon crawler), addressed relative to
    /// `web/spire/`. Same fixed-allowlist discipline as `Asset`: the route only captures the
    /// name, and the serve path re-checks it against the game's file list before touching disk.
    SpireAsset(&'a str),
    /// No such route.
    NotFound,
}

impl<'a> Route<'a> {
    /// Resolves a method and path.
    ///
    /// A path that matches a shape but not this method is `NotFound` rather than a 405: there is no
    /// reason to tell an unpermitted caller which verbs a route accepts.
    pub fn resolve(method: &str, path: &'a str) -> Self {
        // The query string is dropped here rather than at the parsing layer, so a caller that builds a
        // Request by hand cannot smuggle one past a route.
        let path = path.split('?').next().unwrap_or("");
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        match (method, segments.as_slice()) {
            ("GET", ["health"]) => Route::Health,
            ("GET", ["wallet", "status"]) => Route::WalletStatus,
            ("GET", ["gate", id]) => Route::Gate(id),
            ("POST", ["gate", id, "challenge"]) => Route::Challenge(id),
            ("POST", ["gate", id, "prove"]) => Route::Prove(id),
            ("POST", ["gate", id, "credential"]) => Route::Credential(id),
            ("GET", ["proof", id, "status"]) => Route::ProofStatus(id),
            ("GET", ["access", "check"]) => Route::AccessCheck,
            ("GET", []) => Route::Asset("index.html"),
            ("GET", ["index.html"]) => Route::Asset("index.html"),
            ("GET", ["app.css"]) => Route::Asset("app.css"),
            ("GET", ["app.js"]) => Route::Asset("app.js"),
            // The multi-wallet front end. Still a fixed list, still no traversal: `serve_asset`
            // re-checks the name, so widening this route cannot silently widen the surface.
            ("GET", ["js", "ghost", "capabilities.js"]) => Route::Asset("js/ghost/capabilities.js"),
            ("GET", ["js", "ghost", "provider.js"]) => Route::Asset("js/ghost/provider.js"),
            ("GET", ["js", "ghost", "ghost-gate.js"]) => Route::Asset("js/ghost/ghost-gate.js"),
            ("GET", ["js", "ghost", "test.js"]) => Route::Asset("js/ghost/test.js"),
            ("GET", ["vendor", "tari-connector.js"]) => Route::Asset("vendor/tari-connector.js"),
            ("GET", ["vendor", "tari-dapp.d.ts"]) => Route::Asset("vendor/tari-dapp.d.ts"),
            // The Haunted Vault. Same fixed-name rule as every other asset.
            ("GET", ["game"]) => Route::Asset("game/index.html"),
            ("GET", ["game", "sanctum.js"]) => Route::Asset("game/sanctum.js"),
            ("GET", ["game", "story.js"]) => Route::Asset("game/story.js"),
            ("GET", ["game", "chapters.js"]) => Route::Asset("game/chapters.js"),
            ("GET", ["game", "game.css"]) => Route::Asset("game/game.css"),
            // The Buried Spire — the reused dungeon crawler (upstream: albader94/maze-game-html,
            // MIT). Every file is a fixed allowlist name; there is no dynamic path serving.
            ("GET", ["spire"]) => Route::Asset("spire/index.html"),
            ("GET", ["spire", "spire.css"]) => Route::Asset("spire/spire.css"),
            ("GET", ["spire", "ghostgate.css"]) => Route::Asset("spire/ghostgate.css"),
            ("GET", ["spire", "ghostgate.js"]) => Route::Asset("spire/ghostgate.js"),
            ("GET", ["spire", name]) if Self::is_spire_script(name) => Route::SpireAsset(name),
            ("GET", ["spire", "sound", name]) if Self::is_spire_sound(name) => Route::SpireAsset(name),
            // The Telegram join flow, served same-origin so the credential flow works.
            ("GET", ["telegram", "join"]) => Route::Asset("telegram/join.html"),
            ("GET", ["telegram", "claim.js"]) => Route::Asset("telegram/claim.js"),
            _ => Route::NotFound,
        }
    }

    /// The Buried Spire's JavaScript files, by exact name. The game's scripts were imported
    /// upstream-intact (minus the removed leaderboard/PWA), so this list is the game's own module
    /// list plus Ghost Gate's shim — a new file must be added HERE and to disk, never served by
    /// pattern.
    pub fn is_spire_script(name: &str) -> bool {
        matches!(
            name,
            "config.js"
                | "messages.js"
                | "utils.js"
                | "soundManager.js"
                | "gameState.js"
                | "tutorial.js"
                | "input.js"
                | "mapGenerator.js"
                | "entities.js"
                | "inventory.js"
                | "renderer.js"
                | "gameLogic.js"
                | "storyNarration.js"
                | "main.js"
                | "ghostgate.js"
        )
    }

    /// The Buried Spire's sound files, by exact name (imported flat from upstream's tree; the two
    /// "Wind through passages" files were renamed on import because a space in a URL segment is a
    /// request-parsing hazard this bridge does not need).
    pub fn is_spire_sound(name: &str) -> bool {
        matches!(
            name,
            "Underground_ambience.mp3"
                | "backfround-sound.mp3"
                | "gold-orb.mp3"
                | "white-orb.mp3"
                | "red-orb.mp3"
                | "green-orb.mp3"
                | "purple-orb.mp3"
                | "blue-orb.mp3"
                | "ghoul-detection.mp3"
                | "Footsteps_Stone.mp3"
                | "stalking.mp3"
                | "Death_sound_Ominous.mp3"
                | "Orb_collection.mp3"
                | "Button_selection.mp3"
                | "wind-passage-1.mp3"
                | "wind-passage-2.mp3"
                | "part1.mp3"
                | "part2.mp3"
                | "part3.mp3"
                | "part4.mp3"
        )
    }
}

/// Parses a request line and headers out of a raw HTTP request.
///
/// Returns `None` for anything malformed rather than guessing, because a bridge that guesses what a
/// request meant is a bridge that can be made to mean something else.
pub fn parse_request(raw: &str) -> Option<Request> {
    let mut lines = raw.split("\r\n");
    let request_line = lines.next()?;
    // `GET /health HTTP/1.1` -- the method is the *first* token.
    let mut parts = request_line.split(' ');
    let method = parts.next()?;
    let target = parts.next()?;

    let method: &'static str = match method {
        "GET" => "GET",
        "POST" => "POST",
        _ => return None,
    };

    // Query parameters are captured verbatim; no route interprets them unless it needs one, and
    // /access/check reads them server-side only.
    let (path_raw, query_raw) = match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target, ""),
    };
    let path = path_raw.to_string();
    let mut query = std::collections::BTreeMap::new();
    for pair in query_raw.split('&') {
        if pair.is_empty() { continue; }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        query.insert(url_decode(k), url_decode(v));
    }

    let mut origin = None;
    let mut host = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let value = value.trim().to_string();
            if name.eq_ignore_ascii_case("origin") {
                origin = Some(value);
            } else if name.eq_ignore_ascii_case("host") {
                host = Some(value);
            }
        }
    }

    let body_start = raw.find("\r\n\r\n").map(|i| i + 4).unwrap_or(raw.len());
    Some(Request {
        method,
        path,
        query,
        origin,
        host,
        body: raw[body_start..].to_string(),
    })
}

/// Percent-decoding for query values, minimal and strict: `%XX` and `+` only. A value that does
/// not decode cleanly stays as-is rather than being half-transformed.
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex_bytes = [bytes[i + 1], bytes[i + 2]];
                if let Ok(text) = std::str::from_utf8(&hex_bytes) {
                    if let Ok(v) = u8::from_str_radix(text, 16) {
                        out.push(v);
                        i += 3;
                        continue;
                    }
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => { out.push(b' '); i += 1; }
            c => { out.push(c); i += 1; }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

/// Renders a response as an HTTP/1.1 message.
///
/// `Content-Length` and `Connection: close` are both mandatory here and neither is negotiable: without
/// the first the browser hangs, and without the second a client may keep the socket open and let this
/// process accumulate one per request.
pub fn render(response: &Response) -> Vec<u8> {
    let reason = match response.status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "OK",
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n",
        response.status,
        reason,
        response.content_type,
        response.raw.as_ref().map_or(response.body.len(), |b| b.len()),
    );
    match &response.raw {
        // Binary and text both flow out as bytes; the head is assembled once either way.
        Some(bytes) => {
            let mut out = head.into_bytes();
            out.extend_from_slice(bytes);
            out
        }
        None => {
            let mut out = head.into_bytes();
            out.extend_from_slice(response.body.as_bytes());
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_header_is_parsed_from_the_request() {
        let raw = "GET /health HTTP/1.1\r\nHost: evil.com:7799\r\nAccept: */*\r\n\r\n";
        let req = parse_request(raw).expect("a well-formed request parses");
        assert_eq!(req.host.as_deref(), Some("evil.com:7799"));
        assert_eq!(req.origin, None, "no Origin header means not a browser");

        // Absent Host is None, not an error: HTTP/1.0 clients omit it, and the operator's curl
        // never sends one to a loopback bridge.
        let bare = "GET /health HTTP/1.1\r\n\r\n";
        assert_eq!(parse_request(bare).unwrap().host, None);
    }

    #[test]
    fn every_documented_route_resolves() {
        assert_eq!(Route::resolve("GET", "/health"), Route::Health);
        assert_eq!(Route::resolve("GET", "/wallet/status"), Route::WalletStatus);
        assert_eq!(Route::resolve("GET", "/gate/g1"), Route::Gate("g1"));
        assert_eq!(
            Route::resolve("POST", "/gate/g1/challenge"),
            Route::Challenge("g1")
        );
        assert_eq!(Route::resolve("POST", "/gate/g1/prove"), Route::Prove("g1"));
        assert_eq!(
            Route::resolve("POST", "/gate/g1/credential"),
            Route::Credential("g1")
        );
        assert_eq!(
            Route::resolve("GET", "/proof/p1/status"),
            Route::ProofStatus("p1")
        );
    }

    #[test]
    fn a_trailing_slash_and_a_query_string_do_not_change_the_route() {
        assert_eq!(Route::resolve("GET", "/health/"), Route::Health);
        assert_eq!(Route::resolve("GET", "/gate/g1?x=1"), Route::Gate("g1"));
    }

    #[test]
    fn the_static_assets_are_the_only_files_served() {
        // A fixed list, not a path join. `GET /../../.ssh/id_rsa` has to resolve to nothing at all,
        // rather than to a normalised path that happens to escape.
        assert_eq!(Route::resolve("GET", "/"), Route::Asset("index.html"));
        assert_eq!(Route::resolve("GET", "/js/ghost/provider.js"), Route::Asset("js/ghost/provider.js"));
        assert_eq!(Route::resolve("GET", "/vendor/tari-connector.js"), Route::Asset("vendor/tari-connector.js"));
        assert_eq!(Route::resolve("GET", "/game"), Route::Asset("game/index.html"));
        assert_eq!(Route::resolve("GET", "/game/sanctum.js"), Route::Asset("game/sanctum.js"));
        // The fixed-name list must stay closed: no subdirectory walk, no query suffix.
        assert_eq!(Route::resolve("GET", "/js/ghost/../secret.js"), Route::NotFound);
        assert_eq!(Route::resolve("GET", "/vendor/../Cargo.toml"), Route::NotFound);
        assert_eq!(Route::resolve("GET", "/app.js"), Route::Asset("app.js"));
        for bad in [
            "/app.js.map",
            "/Cargo.toml",
            "/../../etc/passwd",
            "/templates",
        ] {
            assert_eq!(
                Route::resolve("GET", bad),
                Route::NotFound,
                "{bad} must not be served"
            );
        }
    }

    #[test]
    fn a_wrong_method_is_not_a_route() {
        // No 405: an unpermitted caller learns nothing about which verbs a path accepts.
        assert_eq!(Route::resolve("DELETE", "/gate/g1"), Route::NotFound);
        assert_eq!(Route::resolve("GET", "/gate/g1/prove"), Route::NotFound);
        assert_eq!(Route::resolve("POST", "/health"), Route::NotFound);
    }

    #[test]
    fn there_is_no_route_that_names_a_balance_or_an_output() {
        // Anything resembling a wallet-data route must not resolve. This is the API-level statement of the
        // privacy boundary: a browser cannot ask for these because they do not exist.
        for path in [
            "/wallet/balance",
            "/wallet/utxos",
            "/wallet/inventory",
            "/gate/g1/keys",
            "/proof/p1/statement",
        ] {
            assert_eq!(
                Route::resolve("GET", path),
                Route::NotFound,
                "{path} must not exist"
            );
        }
        for path in ["/wallet/transfer", "/gate/g1/spend", "/proof/p1/broadcast"] {
            assert_eq!(
                Route::resolve("POST", path),
                Route::NotFound,
                "{path} must not exist"
            );
        }
    }

    #[test]
    fn an_origin_header_is_read_out_of_the_request() {
        let raw =
            "GET /health HTTP/1.1\r\nHost: 127.0.0.1:7799\r\nOrigin: https://vip.example\r\n\r\n";
        let req = parse_request(raw).expect("parses");
        assert_eq!(req.origin.as_deref(), Some("https://vip.example"));
        assert_eq!(req.path, "/health");
        assert_eq!(req.body, "");
    }

    #[test]
    fn a_request_without_an_origin_reports_none() {
        let req = parse_request("GET /health HTTP/1.1\r\nHost: x\r\n\r\n").expect("parses");
        assert_eq!(
            req.origin, None,
            "a CLI is not a browser, and the header's absence says so"
        );
    }

    #[test]
    fn an_origin_header_name_is_matched_case_insensitively() {
        let req = parse_request("GET /health HTTP/1.1\r\noRiGiN: https://vip.example\r\n\r\n")
            .expect("parses");
        assert_eq!(req.origin.as_deref(), Some("https://vip.example"));
    }

    #[test]
    fn a_post_body_is_carried_through() {
        let raw = "POST /gate/g1/prove HTTP/1.1\r\nOrigin: https://vip.example\r\n\r\n{\"gate_id\":\"g1\"}";
        let req = parse_request(raw).expect("parses");
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/gate/g1/prove");
        assert_eq!(req.body, "{\"gate_id\":\"g1\"}");
    }

    #[test]
    fn an_unknown_method_is_refused_rather_than_guessed() {
        assert!(parse_request("TRACE /health HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_request("garbage\r\n\r\n").is_none());
    }

    #[test]
    fn a_rendered_response_declares_its_length_and_closes() -> Result<(), Box<dyn std::error::Error>> {
        let rendered = String::from_utf8(render(&Response::json(200, &serde_json::json!({"ok": true}))))?;
        assert!(rendered.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(rendered.contains("Content-Length: 11\r\n"), "{rendered}");
        assert!(rendered.contains("Connection: close\r\n"));
        // `no-store` matters: a cached challenge response would let a page replay one it never saw.
        assert!(rendered.contains("Cache-Control: no-store\r\n"));
        assert!(rendered.ends_with("\r\n\r\n{\"ok\":true}"));
        Ok(())
    }

    #[test]
    fn an_error_response_is_json_with_a_reason() -> Result<(), Box<dyn std::error::Error>> {
        let r = String::from_utf8(render(&Response::error(
            403,
            "GG: origin http://evil.test is not permitted",
        )))?;
        assert!(r.starts_with("HTTP/1.1 403 Forbidden\r\n"));
        assert!(r.ends_with("{\"error\":\"GG: origin http://evil.test is not permitted\"}"));
        Ok(())
    }
}
