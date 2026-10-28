//! The administrator control plane's HTTP server.
//!
//! # The rules, enforced here and nowhere else
//!
//! - Every mutating route requires: a live admin session cookie, the session's CSRF token as a
//!   request header, and an Origin header that matches the admin origin exactly.
//! - Policy-changing routes additionally require a FRESH step-up (a completed authentication
//!   ceremony within [`ghost_gate_registry::STEPUP_WINDOW`]).
//! - Every accepted or refused privileged action lands in the audit log with the actor, the
//!   timestamp, the old and new policy versions and the outcome.
//! - No write route exists for unauthenticated callers: the route table itself refuses before any
//!   handler runs.
//! - Connections are bounded (read/write timeouts) and bodies are size-limited: the dashboard is
//!   a control plane, not a free port.

use ghost_gate_registry::{
    admin_session_for, append_audit, derive_bindings, expire_admin_sessions, load_bindings, load_registry,
    load_sessions, new_token, save_bindings, save_registry, AdminCredential, AdminSession,
    AuditEntry, AuditOutcome, CredentialKind, Registry, StoreLock, StorePaths,
};
use crate::auth::{
    new_challenge, verify_wallet_signature, verify_webauthn_assertion,
    verify_webauthn_registration, CeremonyKind as AuthKind, PendingChallenge,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::Duration;

/// Bound every connection like the bridge (GG-012).
const IO_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_BODY: usize = 256 * 1024;
const MAX_PENDING_CHALLENGES: usize = 100;

pub struct AdminState {
    pub paths: StorePaths,
    pub origin: String,
    pub rp_id: String,
    pub pending: Mutex<BTreeMap<String, PendingChallenge>>,
    /// The bootstrap token, required for the FIRST credential registration only.
    pub bootstrap_token: Option<String>,
    /// The deployment's ledger identity (GG_GENESIS_HASH): applied to every application that does
    /// not name its own. Set once at startup so the dashboard's identity fields default correctly.
    pub genesis_hash: Option<String>,
    /// The deployment's starting Ootle chain generation (GG_CHAIN_GENERATION): applied to a new
    /// application that does not name its own. `None` falls back to generation `1` at create time.
    pub chain_generation: Option<u64>,
}

/// Draft mutations are intentionally absent from the bridge binding file.  The only exceptions
/// are an explicit policy publication, and the revocation list (which must stay available even
/// while an operator has an unfinished draft open).
#[derive(Clone, Copy)]
enum BindingUpdate {
    None,
    RebuildPublished,
    RevocationsOnly,
}

pub type SharedState = Arc<AdminState>;

pub struct Request {
    pub method: String,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_ascii_lowercase()).map(|s| s.as_str())
    }
    pub fn cookie(&self, name: &str) -> Option<String> {
        let raw = self.header("cookie")?;
        for part in raw.split(';') {
            let mut kv = part.trim().splitn(2, '=');
            if kv.next()? == name {
                return kv.next().map(|v| v.to_string());
            }
        }
        None
    }
    pub fn json(&self) -> Result<serde_json::Value, String> {
        serde_json::from_slice(&self.body).map_err(|e| format!("body is not valid JSON: {e}"))
    }
}

pub struct Response {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
    pub set_cookie: Option<String>,
}

impl Response {
    pub fn json(status: u16, value: &serde_json::Value) -> Self {
        Self {
            status,
            content_type: "application/json".into(),
            body: serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec()),
            set_cookie: None,
        }
    }
    pub fn error(status: u16, message: &str) -> Self {
        Self::json(status, &serde_json::json!({ "error": message }))
    }
    pub fn ok_json(value: &serde_json::Value) -> Self {
        Self::json(200, value)
    }
}

/// Everything the dashboard may learn about the caller's authority, in one decision. Fail-closed:
/// an absent or expired session is "visitor".
pub struct Authority {
    pub session: AdminSession,
}

impl AdminState {
    /// Resolve the caller's authority from the cookie. Returns None for visitors.
    pub fn authority(&self, req: &Request) -> Option<Authority> {
        let token = req.cookie("gg_admin")?;
        let now = ghost_gate_registry::now_unix();
        let reg = self.registry().ok()?;
        let session = admin_session_for(&reg, &token, now)?;
        Some(Authority { session })
    }

    pub fn registry(&self) -> Result<Registry, String> {
        load_registry(&self.paths)
    }

    /// The single draft-write path: lock, load, mutate, validate, save and audit.  It does not
    /// publish bridge bindings; callers must explicitly select one of the narrowly scoped
    /// publication paths below.
    pub fn commit<F>(&self, actor: &str, action: &str, mutate: F) -> Result<Registry, String>
    where
        F: FnOnce(&mut Registry) -> Result<(), String>,
    {
        self.commit_ctx(actor, action, None, mutate)
    }

    /// As [`commit`](Self::commit), with audit context: the application and gate the change
    /// touched and the policy versions before/after. The audit requirement — actor, timestamp,
    /// old/new policy versions, outcome — is satisfied here or nowhere.
    pub fn commit_ctx<F>(
        &self,
        actor: &str,
        action: &str,
        ctx: Option<(String, Option<String>, Option<u64>, Option<u64>)>,
        mutate: F,
    ) -> Result<Registry, String>
    where
        F: FnOnce(&mut Registry) -> Result<(), String>,
    {
        self.commit_ctx_with_bindings(actor, action, ctx, BindingUpdate::None, mutate)
    }

    fn commit_ctx_published<F>(
        &self,
        actor: &str,
        action: &str,
        ctx: Option<(String, Option<String>, Option<u64>, Option<u64>)>,
        mutate: F,
    ) -> Result<Registry, String>
    where
        F: FnOnce(&mut Registry) -> Result<(), String>,
    {
        self.commit_ctx_with_bindings(actor, action, ctx, BindingUpdate::RebuildPublished, mutate)
    }

    fn commit_ctx_revocation<F>(
        &self,
        actor: &str,
        action: &str,
        ctx: Option<(String, Option<String>, Option<u64>, Option<u64>)>,
        mutate: F,
    ) -> Result<Registry, String>
    where
        F: FnOnce(&mut Registry) -> Result<(), String>,
    {
        self.commit_ctx_with_bindings(actor, action, ctx, BindingUpdate::RevocationsOnly, mutate)
    }

    fn commit_ctx_with_bindings<F>(
        &self,
        actor: &str,
        action: &str,
        ctx: Option<(String, Option<String>, Option<u64>, Option<u64>)>,
        binding_update: BindingUpdate,
        mutate: F,
    ) -> Result<Registry, String>
    where
        F: FnOnce(&mut Registry) -> Result<(), String>,
    {
        let (app_ctx, gate_ctx, old_v, new_v_provided) = match ctx {
            None => (None, None, None, None),
            Some((a, g, o, n)) => (Some(a), g, o, n),
        };
        let _lock = StoreLock::acquire(&self.paths)?;
        let mut reg = load_registry(&self.paths)?;
        let before_rev = reg.store_revision;
        match mutate(&mut reg) {
            Ok(()) => {
                // Validate the WHOLE registry after every mutation: nothing half-formed ships.
                if let Err(e) = reg.validate_all() {
                    // Preserve the last valid registry, but record the refused attempt in its
                    // durable audit tail and ndjson log.  Saving `reg` here would persist the
                    // invalid draft that validation just rejected.
                    let entry = AuditEntry {
                        unix: ghost_gate_registry::now_unix(),
                        actor: actor.to_string(),
                        action: action.to_string(),
                        application_id: app_ctx.clone(),
                        gate_id: gate_ctx.clone(),
                        old_version: old_v,
                        new_version: new_v_provided,
                        outcome: AuditOutcome::Refused,
                        detail: format!("validation refused the change: {e}"),
                    };
                    let mut refused_reg = load_registry(&self.paths)?;
                    refused_reg.audit(entry.clone());
                    save_registry(&self.paths, &refused_reg)?;
                    append_audit(&self.paths, &entry)?;
                    return Err(e);
                }
                reg.store_revision = before_rev + 1;
                // Expire dead admin sessions while we hold the lock.
                expire_admin_sessions(&mut reg, ghost_gate_registry::now_unix());
                // The audit entry lands in BOTH the tail (in-file, what the dashboard reads) and
                // the permanent ndjson log — and it lands BEFORE the save, so a change and its
                // audit record are one atomic write.
                let entry = AuditEntry {
                    unix: ghost_gate_registry::now_unix(),
                    actor: actor.to_string(),
                    action: action.to_string(),
                    application_id: app_ctx.clone(),
                    gate_id: gate_ctx.clone(),
                    old_version: old_v,
                    new_version: new_v_provided,
                    outcome: AuditOutcome::Accepted,
                    detail: format!("registry revision {}", reg.store_revision),
                };
                reg.audit(entry.clone());
                // Compute the next published snapshot before installing either file.  A bad or
                // incomplete draft therefore leaves both the registry's live bindings and the
                // bridge untouched.  The two atomic renames are intentionally fail-closed: if a
                // process crashes between them, the bridge has either the previous snapshot or a
                // new snapshot whose registry checks cannot yet succeed; it never obtains a
                // mixed authorizing policy.
                let bindings = match binding_update {
                    BindingUpdate::None => None,
                    BindingUpdate::RebuildPublished => Some(derive_bindings(&reg)?),
                    BindingUpdate::RevocationsOnly => {
                        let mut prior = load_bindings(&self.paths)?.unwrap_or_default();
                        prior.generated_unix = ghost_gate_registry::now_unix();
                        prior.revoked_session_prefixes = reg
                            .revocations
                            .iter()
                            .map(|r| r.token_prefix.clone())
                            .collect();
                        Some(prior)
                    }
                };
                save_registry(&self.paths, &reg)?;
                if let Some(bindings) = bindings {
                    save_bindings(&self.paths, &bindings)?;
                }
                append_audit(&self.paths, &entry)?;
                Ok(reg)
            }
            Err(e) => {
                // A refused privileged action is audited with the same completeness as an
                // accepted one: actor, context, versions, outcome. The registry is saved so the
                // dashboard's tail shows the refusal even though no policy changed.
                let entry = AuditEntry {
                    unix: ghost_gate_registry::now_unix(),
                    actor: actor.to_string(),
                    action: action.to_string(),
                    application_id: app_ctx,
                    gate_id: gate_ctx,
                    old_version: old_v,
                    new_version: new_v_provided,
                    outcome: AuditOutcome::Refused,
                    detail: e.clone(),
                };
                let mut refused_reg = load_registry(&self.paths).unwrap_or_default();
                refused_reg.audit(entry.clone());
                let _ = save_registry(&self.paths, &refused_reg);
                let _ = append_audit(&self.paths, &entry);
                Err(e)
            }
        }
    }

    /// Store a pending authentication challenge, bounded: new challenges evict the oldest when
    /// the cap is hit, and any entry older than the TTL is dead on arrival.
    pub fn put_pending(&self, key: String, pending: PendingChallenge) {
        let mut p = self.pending.lock().unwrap();
        if p.len() >= MAX_PENDING_CHALLENGES {
            if let Some(oldest) = p.keys().next().cloned() {
                p.remove(&oldest);
            }
        }
        p.insert(key, pending);
    }

    /// Consume a pending challenge — exactly once, and only inside its TTL. A challenge older than
    /// CHALLENGE_TTL is refused even if it was never attempted, so a value observed in a log or a
    /// proxy cache cannot be replayed late. Removal makes every challenge single-use.
    pub fn take_pending(&self, key: &str) -> Option<PendingChallenge> {
        let pending = self.pending.lock().unwrap().remove(key)?;
        let age = ghost_gate_registry::now_unix().saturating_sub(pending.created_unix);
        if pending.used || age > ghost_gate_core::policy::CHALLENGE_TTL.as_secs() as u64 {
            return None;
        }
        Some(pending)
    }
}

/// The route table. Returns Ok(response) for handled routes, Err(()) when the path is unknown.
pub fn route(state: &SharedState, req: &Request) -> Result<Response, ()> {
    let path = req.path.as_str();
    let method = req.method.as_str();

    // ---- static dashboard assets (fixed allowlist, no traversal) ----
    if method == "GET" {
        match path {
            "/admin" | "/admin/" | "/admin/index.html" => return Ok(asset(state, "admin/index.html", "text/html; charset=utf-8")),
            "/admin/admin.css" => return Ok(asset(state, "admin/admin.css", "text/css; charset=utf-8")),
            "/admin/admin.js" => return Ok(asset(state, "admin/admin.js", "text/javascript; charset=utf-8")),
            "/admin/api/bootstrap" => return Ok(bootstrap(state, req)),
            _ => {}
        }
    }

    // ---- authentication ceremonies (no session required; these CREATE authority) ----
    if path == "/admin/api/auth/challenge" && method == "POST" {
        return Ok(auth_challenge(state, req));
    }
    if path == "/admin/api/auth/register" && method == "POST" {
        return Ok(auth_register(state, req));
    }
    if path == "/admin/api/auth/login" && method == "POST" {
        return Ok(auth_login(state, req));
    }
    if path == "/admin/api/auth/logout" && method == "POST" {
        return Ok(auth_logout(state, req));
    }

    // ---- everything below requires a live admin session ----
    let authority = match state.authority(req) {
        Some(a) => a,
        None => return Ok(Response::error(401, "GG: administrator authentication required")),
    };

    // The divisibility-aware converter: the dashboard sends the HUMAN amount and the resource's
    // divisibility; the server computes the exact raw units. No dashboard float arithmetic is
    // ever authoritative, and an amount that cannot be represented exactly is refused with the
    // reason, never truncated.
    if path == "/admin/api/convert" && (method == "POST" || method == "GET") {
        // The dashboard POSTs JSON; a command line may pass the query string. Both reach the same
        // server-side conversion — the client is never trusted to have done the arithmetic.
        let mut amount = req.query.get("amount").cloned().unwrap_or_default();
        let mut div_raw = req.query.get("divisibility").cloned();
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&req.body) {
            if let Some(v) = value.get("amount").and_then(|v| v.as_str()) {
                amount = v.to_string();
            }
            if let Some(v) = value.get("divisibility") {
                div_raw = match v {
                    serde_json::Value::String(s) => Some(s.clone()),
                    serde_json::Value::Number(n) => Some(n.to_string()),
                    _ => None,
                };
            }
        }
        let div: u8 = div_raw.and_then(|d| d.parse().ok()).unwrap_or(6);
        if amount.is_empty() {
            return Ok(Response::error(400, "GG: amount is required"));
        }
        let converted = match ghost_gate_core::policy::GatePolicy::raw_units_for(&amount, div) {
            Some(raw) => Response::ok_json(&serde_json::json!({
                "raw": raw.to_string(),
                "exact": true,
                "display": ghost_gate_core::policy::GatePolicy::format_raw(raw, div),
            })),
            None => Response::error(400, &format!(
                "GG: {amount:?} cannot be represented exactly at divisibility {div} — refused, never rounded"
            )),
        };
        return Ok(converted);
    }

    // Read routes.
    if method == "GET" && path == "/admin/api/state" {
        return Ok(admin_state(state, &authority));
    }
    if method == "GET" && path == "/admin/api/sessions" {
        return Ok(list_sessions(state, &authority));
    }
    if method == "GET" && path == "/admin/api/audit" {
        return Ok(list_audit(state, &authority));
    }

    // Every mutation from here on: CSRF + same-origin, enforced before the handler runs.
    if let Some(deny) = require_csrf(state, req, &authority) {
        return Ok(deny);
    }

    match (method, path) {
        ("POST", "/admin/api/app/create") => Ok(create_application(state, req, &authority)),
        ("POST", "/admin/api/app/update") => Ok(update_application(state, req, &authority)),
        ("POST", "/admin/api/app/migrate-generation") => Ok(migrate_generation(state, req, &authority)),
        ("POST", "/admin/api/app/delete") => Ok(delete_application(state, req, &authority)),
        ("POST", "/admin/api/gate/set") => Ok(set_gate(state, req, &authority)),
        ("POST", "/admin/api/gate/remove") => Ok(remove_gate(state, req, &authority)),
        ("POST", "/admin/api/gate/reorder") => Ok(reorder_gates(state, req, &authority)),
        ("POST", "/admin/api/policy/publish") => Ok(publish_policy(state, req, &authority)),
        ("POST", "/admin/api/session/revoke") => Ok(revoke_session(state, req, &authority)),
        ("POST", "/admin/api/session/revoke-all") => Ok(revoke_all_sessions(state, req, &authority)),
        _ => Err(()),
    }
}

/// Origin-only enforcement, for the authentication ceremonies that run BEFORE a session (and so
/// have no CSRF token to present yet). Login CSRF is a real attack — a hostile page can silently
/// sign the operator into an account the attacker controls — so the ceremony still must be
/// same-origin. The passkey ceremony additionally pins the RP ID to this origin's host.
fn require_same_origin(state: &SharedState, req: &Request) -> Option<Response> {
    let origin = req.header("origin").unwrap_or("");
    if origin.is_empty() || origin != state.origin {
        return Some(Response::error(403, "GG: cross-origin authentication is refused"));
    }
    None
}

/// CSRF + origin enforcement for mutations. Returns Some(deny) when the request must be refused.
fn require_csrf(state: &SharedState, req: &Request, authority: &Authority) -> Option<Response> {
    // Origin must match exactly: a cross-site POST never gets to the handler.
    let origin = req.header("origin").unwrap_or("");
    if origin != state.origin {
        return Some(Response::error(403, "GG: cross-origin writes are refused"));
    }
    let got = req.header("x-gg-csrf").unwrap_or("");
    if got.is_empty() || !constant_time_eq(got.as_bytes(), authority.session.csrf.as_bytes()) {
        return Some(Response::error(403, "GG: missing or wrong CSRF token"));
    }
    None
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) { diff |= x ^ y; }
    diff == 0
}

fn asset(_state: &SharedState, name: &str, content_type: &str) -> Response {
    // Fixed names only; the admin crate embeds its assets at compile time so the served set is
    // exactly what was reviewed.
    let bytes: &[u8] = match name {
        "admin/index.html" => include_bytes!("../assets/index.html"),
        "admin/admin.css" => include_bytes!("../assets/admin.css"),
        "admin/admin.js" => include_bytes!("../assets/admin.js"),
        _ => return Response::error(404, "GG: no such asset"),
    };
    Response {
        status: 200,
        content_type: content_type.into(),
        body: bytes.to_vec(),
        set_cookie: None,
    }
}

/// Public bootstrap: what a fresh dashboard needs before authentication. Deliberately reveals
/// nothing about policy contents: names of nothing, no thresholds, no gates.
fn bootstrap(state: &SharedState, req: &Request) -> Response {
    let has_admins = state
        .registry()
        .map(|r| !r.credentials.is_empty())
        .unwrap_or(false);
    let bootstrap_required = !has_admins;
    Response::ok_json(&serde_json::json!({
        "origin": state.origin,
        "rpId": state.rp_id,
        "bootstrapRequired": bootstrap_required,
        "authenticated": state.authority(req).is_some(),
        "limits": {
            "maxSessionDays": ghost_gate_core::policy::MAX_SESSION_TTL.as_secs() / 86_400,
            "challengeTtlSecs": ghost_gate_core::policy::CHALLENGE_TTL.as_secs(),
        },
    }))
}

/// Issue a single-use authentication challenge.
fn auth_challenge(state: &SharedState, req: &Request) -> Response {
    // Even a ceremony that creates authority must come from the dashboard itself: a cross-site
    // request must not be able to make the browser hand this page a challenge, and a cross-site
    // POST must not be able to ride the operator's cookie into a login or a bootstrap.
    if let Some(deny) = require_same_origin(state, req) {
        return deny;
    }
    let body = match req.json() {
        Ok(v) => v,
        Err(e) => return Response::error(400, &e),
    };
    let kind = match body.get("kind").and_then(|k| k.as_str()) {
        Some("register") => AuthKind::Registration,
        Some("login") => AuthKind::Authentication,
        _ => return Response::error(400, "kind must be register or login"),
    };
    let method = match body.get("method").and_then(|m| m.as_str()) {
        Some("passkey") => "passkey",
        Some("wallet") => "wallet",
        _ => return Response::error(400, "method must be passkey or wallet"),
    };
    let challenge = new_challenge();
    state.put_pending(
        challenge.clone(),
        PendingChallenge { challenge: challenge.clone(), kind, created_unix: ghost_gate_registry::now_unix(), used: false },
    );
    // For a passkey LOGIN, return the registered credential ids so the browser can target the
    // specific credential through `allowCredentials`. A Windows Hello credential registered with
    // `residentKey: "preferred"` may be non-discoverable; without the id the browser cannot find it
    // on the platform authenticator and falls back to prompting for a roaming USB security key.
    // A WebAuthn credential id is a public handle, not a secret, and this endpoint is loopback +
    // same-origin + CSRF-checked; the server's assertion verification is entirely unchanged.
    let allow_credentials: Vec<serde_json::Value> = if matches!(kind, AuthKind::Authentication) && method == "passkey" {
        ghost_gate_registry::load_registry(&state.paths)
            .map(|reg| {
                reg.credentials
                    .iter()
                    .filter(|c| c.kind == ghost_gate_registry::CredentialKind::Passkey)
                    .filter_map(|c| c.credential_id.strip_prefix("passkey:"))
                    .map(|id| serde_json::json!({ "id": id, "type": "public-key" }))
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    Response::ok_json(&serde_json::json!({ "challenge": challenge, "method": method, "allowCredentials": allow_credentials }))
}

/// First registration: requires the bootstrap token when no credential exists. The first
/// credential becomes the deployment's administrator; later registrations require an
/// authenticated, stepped-up administrator (managed credentials), so a stranger can never join.
fn auth_register(state: &SharedState, req: &Request) -> Response {
    if let Some(deny) = require_same_origin(state, req) {
        return deny;
    }
    let body = match req.json() {
        Ok(v) => v,
        Err(e) => return Response::error(400, &e),
    };
    let label = body.get("label").and_then(|l| l.as_str()).unwrap_or("admin").to_string();
    let reg = match state.registry() {
        Ok(r) => r,
        Err(e) => return Response::error(500, &e),
    };
    let first = reg.credentials.is_empty();
    if !first {
        // Registration is closed once an administrator exists. 403, not 400: the request was
        // well-formed and the answer is a policy decision, not a malformed body.
        return Response::error(
            403,
            "GG: registration is closed: an administrator already exists. Add another credential from \
             the dashboard while signed in.",
        );
    }
    if first {
        let provided = body.get("bootstrapToken").and_then(|t| t.as_str()).unwrap_or("");
        let expected = match &state.bootstrap_token {
            Some(t) => t,
            None => return Response::error(503, "GG: bootstrap is not available (no token on disk)"),
        };
        if !constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
            return Response::error(403, "GG: wrong bootstrap token");
        }
    }
    let method = body.get("method").and_then(|m| m.as_str()).unwrap_or("passkey");
    let credential = if method == "wallet" {
        // Wallet path: the client signs the challenge with its wallet key.
        let Some(pending) = body.get("challenge").and_then(|c| c.as_str()).and_then(|c| state.take_pending(c)) else {
            return Response::error(400, "GG: unknown or expired challenge");
        };
        if pending.kind != AuthKind::Registration { return Response::error(400, "GG: challenge was not for registration"); }
        let public_hex = match body.get("publicKey").and_then(|p| p.as_str()) {
            Some(p) => p.to_string(),
            None => return Response::error(400, "wallet registration needs the public key"),
        };
        let sig = |k: &str| body.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        if let Err(e) = verify_wallet_signature(&pending.challenge, &public_hex, &sig("publicNonce"), &sig("signature")) {
            return Response::error(403, &format!("GG: {e}"));
        }
        AdminCredential {
            credential_id: format!("wallet:{public_hex}"),
            kind: CredentialKind::WalletKey,
            label,
            registered_unix: ghost_gate_registry::now_unix(),
            es256_public_sec1: None,
            ristretto_public_hex: Some(public_hex),
        }
    } else {
        // Passkey path: verify the registration ceremony's bytes.
        let Some(pending) = body.get("challenge").and_then(|c| c.as_str()).and_then(|c| state.take_pending(c)) else {
            return Response::error(400, "GG: unknown or expired challenge");
        };
        if pending.kind != AuthKind::Registration { return Response::error(400, "GG: challenge was not for registration"); }
        let parsed: crate::auth::WebAuthnResponse = match serde_json::from_value(body.get("webauthn").cloned().unwrap_or(serde_json::Value::Null)) {
            Ok(v) => v,
            Err(e) => return Response::error(400, &format!("GG: malformed webauthn payload: {e}")),
        };
        let (cred_id, sec1) = match verify_webauthn_registration(&parsed, &pending.challenge, &state.origin, &state.rp_id) {
            Ok(v) => v,
            Err(e) => return Response::error(403, &format!("GG: registration refused: {e}")),
        };
        AdminCredential {
            credential_id: format!("passkey:{cred_id}"),
            kind: CredentialKind::Passkey,
            label,
            registered_unix: ghost_gate_registry::now_unix(),
            es256_public_sec1: Some(sec1),
            ristretto_public_hex: None,
        }
    };

    let cred_id = credential.credential_id.clone();
    let result = state.commit("bootstrap", "admin.register", |r| {
        if !r.credentials.is_empty() && !first {
            // A second registration needs an authenticated stepped-up administrator — handled by
            // the /admin/api/admin/register route below, never here.
            return Err("registration is closed: an administrator already exists".into());
        }
        r.credentials.push(credential);
        Ok(())
    });
    match result {
        Ok(_) => {
            // Log in immediately: the registrar proved possession during registration.
            let (session, cookie) = match start_session(state, &cred_id, true) {
                Ok(v) => v,
                Err(e) => return Response::error(500, &e),
            };
            let _ = append_audit(&state.paths, &AuditEntry {
                unix: ghost_gate_registry::now_unix(),
                actor: cred_id.clone(),
                action: "admin.registered".into(),
                application_id: None,
                gate_id: None,
                old_version: None,
                new_version: None,
                outcome: AuditOutcome::Accepted,
                detail: "first administrator registered via bootstrap".into(),
            });
            Response::ok_json(&serde_json::json!({
                "credentialId": cred_id, "csrf": session.csrf, "stepupUntil": session.stepup_until_unix,
            }))
            .with_cookie(cookie)
        }
        Err(e) => Response::error(403, &format!("GG: {e}")),
    }
}

/// Login or step-up with an EXISTING credential.
fn auth_login(state: &SharedState, req: &Request) -> Response {
    if let Some(deny) = require_same_origin(state, req) {
        return deny;
    }
    let body = match req.json() {
        Ok(v) => v,
        Err(e) => return Response::error(400, &e),
    };
    let reg = match state.registry() {
        Ok(r) => r,
        Err(e) => return Response::error(500, &e),
    };
    let method = body.get("method").and_then(|m| m.as_str()).unwrap_or("passkey");
    let stepup = body.get("stepup").and_then(|s| s.as_bool()).unwrap_or(false);
    let now = ghost_gate_registry::now_unix();

    // Which credential is authenticating?
    let (cred_id, verified) = if method == "wallet" {
        let Some(pending) = body.get("challenge").and_then(|c| c.as_str()).and_then(|c| state.take_pending(c)) else {
            return Response::error(400, "GG: unknown or expired challenge");
        };
        let public_hex = match body.get("publicKey").and_then(|p| p.as_str()) {
            Some(p) => p.to_string(),
            None => return Response::error(400, "wallet login needs the public key"),
        };
        let cred_id = format!("wallet:{public_hex}");
        if !reg.credentials.iter().any(|c| c.credential_id == cred_id) {
            return Response::error(403, "GG: that wallet is not a registered administrator");
        }
        let sig = |k: &str| body.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        if let Err(e) = verify_wallet_signature(&pending.challenge, &public_hex, &sig("publicNonce"), &sig("signature")) {
            return Response::error(403, &format!("GG: {e}"));
        }
        (cred_id.clone(), true)
    } else {
        let Some(pending) = body.get("challenge").and_then(|c| c.as_str()).and_then(|c| state.take_pending(c)) else {
            return Response::error(400, "GG: unknown or expired challenge");
        };
        let parsed: crate::auth::WebAuthnResponse = match serde_json::from_value(body.get("webauthn").cloned().unwrap_or(serde_json::Value::Null)) {
            Ok(v) => v,
            Err(e) => return Response::error(400, &format!("GG: malformed webauthn payload: {e}")),
        };
        // The dashboard tells us which credential it used; we verify against THAT credential's
        // registered key and never against an attacker-chosen one.
        let claimed = body.get("credentialId").and_then(|c| c.as_str()).unwrap_or("");
        let cred_id = format!("passkey:{claimed}");
        let Some(cred) = reg.credentials.iter().find(|c| c.credential_id == cred_id) else {
            return Response::error(403, "GG: that passkey is not a registered administrator");
        };
        let Some(sec1) = &cred.es256_public_sec1 else {
            return Response::error(403, "GG: the credential is not a passkey");
        };
        if let Err(e) = verify_webauthn_assertion(
            &parsed,
            &pending.challenge,
            &state.origin,
            &state.rp_id,
            claimed,
            sec1,
            // A step-up must prove user verification; a plain login needs presence.
            stepup,
        ) {
            return Response::error(403, &format!("GG: assertion refused: {e}"));
        }
        (cred_id.clone(), true)
    };
    let _ = verified;

    if stepup {
        // Refresh the step-up window on the CURRENT session (the cookie identifies it).
        let token = match req.cookie("gg_admin") {
            Some(t) => t,
            None => return Response::error(401, "GG: no admin session to step up"),
        };
        let result = state.commit(&cred_id, "admin.stepup", |r| {
            let Some(session) = r.admin_sessions.iter_mut().find(|s| s.token == token) else {
                return Err("no such admin session".into());
            };
            if session.credential_id != cred_id {
                return Err("the session belongs to a different administrator".into());
            }
            session.stepup_until_unix = now + ghost_gate_registry::STEPUP_WINDOW.as_secs();
            Ok(())
        });
        return match result {
            Ok(_) => Response::ok_json(&serde_json::json!({ "stepup": true })),
            Err(e) => Response::error(403, &format!("GG: {e}")),
        };
    }

    match start_session(state, &cred_id, false) {
        Ok((session, cookie)) => Response::ok_json(&serde_json::json!({
            "credentialId": cred_id, "csrf": session.csrf,
        })).with_cookie(cookie),
        Err(e) => Response::error(500, &e),
    }
}

fn auth_logout(state: &SharedState, req: &Request) -> Response {
    // Logging out is a state-changing write: same-origin plus the session's own CSRF token.
    if let Some(deny) = require_same_origin(state, req) {
        return deny;
    }
    let Some(authority) = state.authority(req) else {
        return Response::error(401, "GG: no session");
    };
    if let Some(deny) = require_csrf(state, req, &authority) {
        return deny;
    }
    let Some(token) = req.cookie("gg_admin") else {
        return Response::error(401, "GG: no session");
    };
    let actor = authority.session.credential_id.clone();
    let result = state.commit(&actor, "admin.logout", |r| {
        r.admin_sessions.retain(|s| s.token != token);
        Ok(())
    });
    match result {
        Ok(_) => Response::ok_json(&serde_json::json!({ "loggedOut": true }))
            .with_cookie("gg_admin=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0".to_string()),
        Err(e) => Response::error(500, &e),
    }
}

fn start_session(state: &SharedState, credential_id: &str, privileged_start: bool) -> Result<(AdminSession, String), String> {
    let now = ghost_gate_registry::now_unix();
    let token = new_token();
    let csrf = new_token();
    let session = AdminSession {
        token: token.clone(),
        credential_id: credential_id.to_string(),
        created_unix: now,
        expires_unix: now + ghost_gate_registry::ADMIN_SESSION_TTL.as_secs(),
        csrf: csrf.clone(),
        // The bootstrap registrar starts privileged; a plain login must step up first.
        stepup_until_unix: if privileged_start { now + ghost_gate_registry::STEPUP_WINDOW.as_secs() } else { 0 },
        last_seen_unix: now,
    };
    let cookie = format!(
        "gg_admin={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
        ghost_gate_registry::ADMIN_SESSION_TTL.as_secs()
    );
    let _lock = StoreLock::acquire(&state.paths)?;
    let mut reg = load_registry(&state.paths)?;
    reg.admin_sessions.push(session.clone());
    expire_admin_sessions(&mut reg, now);
    save_registry(&state.paths, &reg)?;
    Ok((session, cookie))
}

fn admin_state(state: &SharedState, authority: &Authority) -> Response {
    let reg = match state.registry() {
        Ok(r) => r,
        Err(e) => return Response::error(500, &e),
    };
    let now = ghost_gate_registry::now_unix();
    let sessions = load_sessions(&state.paths).unwrap_or_default();

    let mut apps_json = Vec::new();
    for a in &reg.applications {
        let mut gates_json = Vec::new();
        for g in &a.gates {
            let version = reg.current_version(&a.application_id, &g.gate_id);
            gates_json.push(serde_json::json!({
                "gateId": g.gate_id,
                "name": g.name,
                "resourceAddress": g.resource_address,
                "symbol": g.symbol,
                "divisibility": g.divisibility,
                "thresholdRaw": g.threshold_raw.to_string(),
                "proofMode": g.proof_mode.to_string(),
                "challengeDomain": g.challenge_domain,
                "sessionTtlOverrideSecs": g.session_ttl_override,
                "grants": g.grants,
                "enabled": g.enabled,
                "testLane": g.test_lane,
                "useMode": g.use_mode.as_str(),
                "componentAddress": g.component_address,
                "publishedVersion": version.map(|v| v.version),
                "publishedHash": version.map(|v| v.policy_hash.clone()),
                "activatable": g.proof_mode.is_activatable(),
                "blockedReason": g.proof_mode.blocked_reason(),
            }));
        }
        apps_json.push(serde_json::json!({
            "applicationId": a.application_id,
            "displayName": a.display_name,
            "owner": a.owner_credential,
            "ownedByYou": a.owner_credential == authority.session.credential_id,
            "topology": if a.topology == ghost_gate_core::policy::GateTopology::Hierarchical { "hierarchical" } else { "independent" },
            "defaultSessionTtlSecs": a.default_session_ttl,
            "maxGates": a.max_gates,
            "production": a.production,
            "revision": a.revision,
            "network": a.network,
            "networkName": network_name(a.network),
            "genesisHash": a.genesis_hash,
            // The live Ootle chain generation, and the durable floor it may never drop below. A
            // reset migration raises both; an operator reads these to confirm the deployment is on
            // the current chain.
            "chainGeneration": a.chain_generation,
            "generationFloor": reg.generation_floor_of(&a.application_id),
            "gates": gates_json,
        }));
    }
    let sessions_json: Vec<serde_json::Value> = sessions
        .iter()
        .map(|s| {
            serde_json::json!({
                "tokenPrefix": s.token.chars().take(8).collect::<String>(),
                "applicationId": s.application_id,
                "provenGate": s.proven_gate,
                "granted": s.granted,
                "issuedUnix": s.issued_unix,
                "expiresUnix": s.expires_unix,
                "revoked": s.revoked,
                "testLane": s.test_lane,
                // The tier this session ACHIEVED from its evidence, and the evidence class behind
                // it. Distinct from a gate's "Max tier" (the ceiling its proof mode could ever
                // reach): this is what was actually verified for this session.
                "trustTier": s.trust_tier.as_str(),
                "evidenceKind": s.evidence_kind.as_str(),
            })
        })
        .collect();
    let credentials_json: Vec<serde_json::Value> = reg
        .credentials
        .iter()
        .map(|c| {
            serde_json::json!({
                "credentialId": c.credential_id,
                "kind": match c.kind { CredentialKind::Passkey => "passkey", CredentialKind::WalletKey => "wallet" },
                "label": c.label,
            })
        })
        .collect();

    Response::ok_json(&serde_json::json!({
        "actor": authority.session.credential_id,
        "csrf": authority.session.csrf,
        "stepupUntil": authority.session.stepup_until_unix,
        "stepupValid": authority.session.stepup_until_unix > now,
        "registryRevision": reg.store_revision,
        "applications": apps_json,
        "sessions": sessions_json,
        "credentials": credentials_json,
    }))
}

fn list_sessions(state: &SharedState, _authority: &Authority) -> Response {
    let sessions = load_sessions(&state.paths).unwrap_or_default();
    Response::ok_json(&serde_json::json!({ "sessions": sessions.len() }))
}

fn list_audit(state: &SharedState, _authority: &Authority) -> Response {
    let reg = match state.registry() {
        Ok(r) => r,
        Err(e) => return Response::error(500, &e),
    };
    Response::ok_json(&serde_json::json!({ "tail": reg.audit_tail.iter().rev().take(100).collect::<Vec<_>>() }))
}

// ---- policy mutations, all owner-gated and step-up-gated ----

/// Common gatekeeping for every policy mutation: the application must exist, the caller must own
/// it, and the change must be fresh (stepped-up). Returns the application id on success.
fn gatekeep(state: &SharedState, _req: &Request, authority: &Authority, app_id: &str, action: &str) -> Result<(), Response> {
    let now = ghost_gate_registry::now_unix();
    if authority.session.stepup_until_unix <= now {
        return Err(Response::error(403, "GG: this change requires fresh authentication (step up first)"));
    }
    let reg = match state.registry() {
        Ok(r) => r,
        Err(e) => return Err(Response::error(500, &e)),
    };
    let Some(app) = reg.application(app_id) else {
        return Err(Response::error(404, "GG: no such application"));
    };
    if app.owner_credential != authority.session.credential_id {
        // Audited: an administrator touching another application's gates is a security event.
        let _ = append_audit(&state.paths, &AuditEntry {
            unix: now,
            actor: authority.session.credential_id.clone(),
            action: action.into(),
            application_id: Some(app_id.into()),
            gate_id: None,
            old_version: None,
            new_version: None,
            outcome: AuditOutcome::Refused,
            detail: "the caller does not own this application".into(),
        });
        return Err(Response::error(403, "GG: you do not own this application"));
    }
    Ok(())
}

fn parse_body<T: serde::de::DeserializeOwned>(req: &Request) -> Result<T, Response> {
    serde_json::from_slice(&req.body).map_err(|e| Response::error(400, &format!("GG: bad request body: {e}")))
}

/// Accept "localnet", "0x10" or "16" for the cohort. Names, because an operator should not have to
/// remember hex, but the value stored is the byte the chain uses.
fn network_name(byte: u8) -> &'static str {
    match byte {
        ghost_gate_core::network::MAINNET => "mainnet",
        ghost_gate_core::network::STAGENET => "stagenet",
        ghost_gate_core::network::NEXTNET => "nextnet",
        ghost_gate_core::network::LOCALNET => "localnet",
        ghost_gate_core::network::IGOR => "igor",
        ghost_gate_core::network::ESMERALDA => "esmeralda",
        _ => "unknown",
    }
}

fn resolve_network(raw: Option<&str>) -> Result<u8, String> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(ghost_gate_core::network::LOCALNET);
    };
    let named = match raw.to_ascii_lowercase().as_str() {
        "mainnet" => Some(ghost_gate_core::network::MAINNET),
        "stagenet" => Some(ghost_gate_core::network::STAGENET),
        "nextnet" => Some(ghost_gate_core::network::NEXTNET),
        "localnet" => Some(ghost_gate_core::network::LOCALNET),
        "igor" => Some(ghost_gate_core::network::IGOR),
        "esmeralda" => Some(ghost_gate_core::network::ESMERALDA),
        _ => None,
    };
    if let Some(byte) = named {
        return Ok(byte);
    }
    let hexed = raw.strip_prefix("0x").unwrap_or(raw);
    let byte = u8::from_str_radix(hexed, 16)
        .map_err(|_| format!("GG: {raw:?} is not a network name or a hex byte (localnet, 0x10, 16)"))?;
    if !ghost_gate_core::network::is_known(byte) {
        return Err(format!("GG: network byte 0x{byte:02x} is not a known cohort"));
    }
    Ok(byte)
}

fn create_application(state: &SharedState, req: &Request, authority: &Authority) -> Response {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Body {
        application_id: String,
        display_name: String,
        topology: String,
        default_session_ttl: u64,
        #[serde(default)]
        max_gates: Option<usize>,
        #[serde(default)]
        production: bool,
        /// The network cohort this deployment serves (hex byte or a name). Refused when unknown.
        #[serde(default)]
        network: Option<String>,
        /// The ledger's genesis identity, hex. Falls back to GG_GENESIS_HASH so an operator sets it
        /// once for the whole deployment instead of once per application.
        #[serde(default)]
        genesis_hash: Option<String>,
        /// The Ootle chain generation this application starts at. Falls back to GG_CHAIN_GENERATION,
        /// then to `1` (the first generation) so a fresh deployment authorizes. A reset later moves
        /// it forward through the dedicated migrate operation, never through an ordinary edit.
        #[serde(default)]
        chain_generation: Option<u64>,
    }
    let body: Body = match parse_body(req) {
        Ok(b) => b,
        Err(r) => return r,
    };
    // Step-up is required to create an application at all; ownership is claimed by the creator.
    if authority.session.stepup_until_unix <= ghost_gate_registry::now_unix() {
        return Response::error(403, "GG: creating an application requires fresh authentication");
    }
    let topology = match body.topology.as_str() {
        "independent" => ghost_gate_core::policy::GateTopology::Independent,
        "hierarchical" => ghost_gate_core::policy::GateTopology::Hierarchical,
        _ => return Response::error(400, "GG: topology must be independent or hierarchical"),
    };
    let network = match resolve_network(body.network.as_deref()) {
        Ok(n) => n,
        Err(e) => return Response::error(400, &e),
    };
    let genesis_hash = match body.genesis_hash.clone().filter(|g| !g.is_empty()).or_else(|| state.genesis_hash.clone()) {
        Some(g) => g,
        None => {
            return Response::error(
                400,
                "GG: genesisHash is required — set it per application or once for the deployment with GG_GENESIS_HASH",
            )
        }
    };
    let actor = authority.session.credential_id.clone();
    // A fresh application starts at the deployment's declared generation (or 1). It only ever moves
    // forward via the migrate operation; an ordinary create/edit never advances it past the floor.
    let chain_generation = body.chain_generation.or(state.chain_generation).unwrap_or(1);
    let app = ghost_gate_core::policy::Application {
        application_id: body.application_id.clone(),
        display_name: body.display_name,
        owner_credential: actor.clone(),
        topology,
        default_session_ttl: body.default_session_ttl,
        max_gates: body.max_gates.unwrap_or(ghost_gate_core::policy::DEFAULT_MAX_GATES_PER_APP),
        gates: vec![],
        revision: 1,
        production: body.production,
        network,
        genesis_hash,
        chain_generation,
    };
    if let Err(e) = app.validate() {
        return Response::error(400, &format!("GG: {e}"));
    }
    let app_id = app.application_id.clone();
    match state.commit_ctx(&actor, "app.create", Some((app_id.clone(), None, None, None)), |r| {
        if r.applications.iter().any(|a| a.application_id == app_id) {
            return Err(format!("application {app_id} already exists"));
        }
        r.applications.push(app);
        Ok(())
    }) {
        Ok(_) => Response::ok_json(&serde_json::json!({ "created": app_id })),
        Err(e) => Response::error(400, &format!("GG: {e}")),
    }
}

fn update_application(state: &SharedState, req: &Request, authority: &Authority) -> Response {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Body {
        application_id: String,
        #[serde(default)]
        display_name: Option<String>,
        #[serde(default)]
        topology: Option<String>,
        #[serde(default)]
        default_session_ttl: Option<u64>,
        #[serde(default)]
        max_gates: Option<usize>,
    }
    let body: Body = match parse_body(req) { Ok(b) => b, Err(r) => return r };
    if let Err(resp) = gatekeep(state, req, authority, &body.application_id, "app.update") { return resp; }
    let actor = authority.session.credential_id.clone();
    let app_id = body.application_id.clone();
    let topology = body.topology.as_deref().map(|t| match t {
        "independent" => ghost_gate_core::policy::GateTopology::Independent,
        "hierarchical" => ghost_gate_core::policy::GateTopology::Hierarchical,
        _ => unreachable!(),
    });
    match state.commit_ctx(&actor, "app.update", Some((app_id.clone(), None, None, None)), |r| {
        let Some(app) = r.applications.iter_mut().find(|a| a.application_id == app_id) else {
            return Err(format!("application {app_id} vanished"));
        };
        if let Some(n) = &body.display_name { app.display_name = n.clone(); }
        if let Some(t) = topology { app.topology = t; }
        if let Some(ttl) = body.default_session_ttl { app.default_session_ttl = ttl; }
        if let Some(m) = body.max_gates { app.max_gates = m; }
        app.revision += 1;
        Ok(())
    }) {
        Ok(_) => Response::ok_json(&serde_json::json!({ "updated": app_id })),
        Err(e) => Response::error(400, &format!("GG: {e}")),
    }
}

/// Migrate an application to a new Ootle chain generation after a reset. This is the ONLY operation
/// that advances the generation — ordinary edits never do. It raises the durable generation floor,
/// retires every prior session, and so refuses pre-reset authorizations from then on. It needs the
/// owner's fresh authentication, like creating an application.
fn migrate_generation(state: &SharedState, req: &Request, authority: &Authority) -> Response {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Body {
        application_id: String,
        new_generation: u64,
    }
    let body: Body = match parse_body(req) {
        Ok(b) => b,
        Err(r) => return r,
    };
    if let Err(resp) = gatekeep(state, req, authority, &body.application_id, "app.migrate-generation") {
        return resp;
    }
    // A reset migration invalidates every existing authorization for the application; it is at
    // least as sensitive as creating one, so it requires fresh authentication.
    if authority.session.stepup_until_unix <= ghost_gate_registry::now_unix() {
        return Response::error(403, "GG: migrating a chain generation requires fresh authentication");
    }
    let actor = authority.session.credential_id.clone();
    let app_id = body.application_id.clone();
    let new_generation = body.new_generation;
    match state.commit_ctx(
        &actor,
        "app.migrate-generation",
        Some((app_id.clone(), None, None, Some(new_generation))),
        |r| ghost_gate_registry::migrate_generation(&state.paths, r, &app_id, new_generation, &actor),
    ) {
        Ok(_) => Response::ok_json(&serde_json::json!({
            "migrated": app_id,
            "generation": new_generation,
        })),
        Err(e) => Response::error(400, &format!("GG: {e}")),
    }
}

fn delete_application(state: &SharedState, req: &Request, authority: &Authority) -> Response {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Body { application_id: String }
    let body: Body = match parse_body(req) { Ok(b) => b, Err(r) => return r };
    if let Err(resp) = gatekeep(state, req, authority, &body.application_id, "app.delete") { return resp; }
    let actor = authority.session.credential_id.clone();
    let app_id = body.application_id.clone();
    match state.commit_ctx_published(&actor, "app.delete", Some((app_id.clone(), None, None, None)), |r| {
        r.applications.retain(|a| a.application_id != app_id);
        r.versions.retain(|v| v.application_id != app_id);
        Ok(())
    }) {
        Ok(_) => Response::ok_json(&serde_json::json!({ "deleted": app_id })),
        Err(e) => Response::error(400, &format!("GG: {e}")),
    }
}

/// Create or replace a gate's DRAFT policy. Publishing is a separate, explicit step.
fn set_gate(state: &SharedState, req: &Request, authority: &Authority) -> Response {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Body {
        application_id: String,
        gate: ghost_gate_core::policy::GatePolicy,
    }
    let body: Body = match parse_body(req) { Ok(b) => b, Err(r) => return r };
    if let Err(resp) = gatekeep(state, req, authority, &body.application_id, "gate.set") { return resp; }
    let actor = authority.session.credential_id.clone();
    let app_id = body.application_id.clone();
    let gate = body.gate;
    if let Err(reason) = ghost_gate_core::policy::validate_challenge_domain(&gate.challenge_domain) {
        return Response::error(400, &format!("GG: {reason}"));
    }
    // A test lane cannot be enabled inside a production application; the registry's validation
    // also enforces this, but the dashboard reports it precisely here.
    let was_test = gate.test_lane;
    let gate_id_for_lookup = gate.gate_id.clone();
    let published_before = state
        .registry()
        .ok()
        .and_then(|r| r.current_version(&app_id, &gate_id_for_lookup).map(|v| v.version));
    match state.commit_ctx(
        &actor,
        "gate.set",
        Some((app_id.clone(), Some(gate_id_for_lookup.clone()), published_before, None)),
        |r| {
        let Some(app) = r.applications.iter_mut().find(|a| a.application_id == app_id) else {
            return Err(format!("application {app_id} vanished"));
        };
        let Some(existing) = app.gate(&gate_id_for_lookup).cloned() else {
            // New gate: honour the application's gate cap.
            if app.gates.len() >= app.max_gates {
                return Err(format!("the application already holds {} gates (limit {})", app.gates.len(), app.max_gates));
            }
            app.gates.push(gate.clone());
            app.revision += 1;
            return Ok(());
        };
        if existing.test_lane != was_test {
            return Err("the test-lane flag cannot be flipped after creation; remove and re-add the gate".into());
        }
        // This is always a draft replacement, even for a currently published gate.  The bridge
        // consumes only the immutable bindings snapshot, so none of these fields become live
        // until the separate Publish action atomically cuts new versions.
            app.revision += 1;
            *app.gate_mut(&gate_id_for_lookup).unwrap() = gate;
            Ok(())
        },
    ) {
        Ok(_) => Response::ok_json(&serde_json::json!({ "set": true })),
        Err(e) => Response::error(400, &format!("GG: {e}")),
    }
}

fn remove_gate(state: &SharedState, req: &Request, authority: &Authority) -> Response {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Body { application_id: String, gate_id: String }
    let body: Body = match parse_body(req) { Ok(b) => b, Err(r) => return r };
    if let Err(resp) = gatekeep(state, req, authority, &body.application_id, "gate.remove") { return resp; }
    let actor = authority.session.credential_id.clone();
    let (app_id, gate_id) = (body.application_id.clone(), body.gate_id.clone());
    match state.commit_ctx_published(&actor, "gate.remove", Some((app_id.clone(), Some(gate_id.clone()), None, None)), |r| {
        let Some(app) = r.applications.iter_mut().find(|a| a.application_id == app_id) else {
            return Err("application vanished".into());
        };
        let before = app.gates.len();
            app.gates.retain(|g| g.gate_id != gate_id);
            if app.gates.len() == before {
                return Err(format!("gate {gate_id} not found"));
            }
            app.revision += 1;
            Ok(())
        },
    ) {
        Ok(_) => Response::ok_json(&serde_json::json!({ "removed": gate_id })),
        Err(e) => Response::error(400, &format!("GG: {e}")),
    }
}

fn reorder_gates(state: &SharedState, req: &Request, authority: &Authority) -> Response {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Body { application_id: String, order: Vec<String> }
    let body: Body = match parse_body(req) { Ok(b) => b, Err(r) => return r };
    if let Err(resp) = gatekeep(state, req, authority, &body.application_id, "gate.reorder") { return resp; }
    let actor = authority.session.credential_id.clone();
    let app_id = body.application_id.clone();
    let order = body.order;
    match state.commit_ctx(&actor, "gate.reorder", Some((app_id.clone(), None, None, None)), |r| {
        let Some(app) = r.applications.iter_mut().find(|a| a.application_id == app_id) else {
            return Err("application vanished".into());
        };
        // Order is cosmetic: refuse a reorder that drops or duplicates gates.
        let mut sorted_current: Vec<String> = app.gates.iter().map(|g| g.gate_id.clone()).collect();
        sorted_current.sort();
        let mut sorted_new = order.clone();
        sorted_new.sort();
        if sorted_current != sorted_new {
            return Err("the reorder must name exactly the existing gates".into());
        }
        app.gates.sort_by_key(|g| order.iter().position(|id| id == &g.gate_id).unwrap_or(usize::MAX));
        app.revision += 1;
        Ok(())
    }) {
        Ok(_) => Response::ok_json(&serde_json::json!({ "reordered": true })),
        Err(e) => Response::error(400, &format!("GG: {e}")),
    }
}

/// Publish (or replace) the policy for one gate: freeze the current draft as the next immutable
/// version, record the replacement, and refresh the bridge's bindings. The gate must already
/// validate; a draft XTM gate can be SAVED but never published.
fn publish_policy(state: &SharedState, req: &Request, authority: &Authority) -> Response {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Body { application_id: String, gate_id: String, #[serde(default)] reason: String }
    let body: Body = match parse_body(req) { Ok(b) => b, Err(r) => return r };
    if let Err(resp) = gatekeep(state, req, authority, &body.application_id, "policy.publish") { return resp; }
    let actor = authority.session.credential_id.clone();
    let app_id = body.application_id.clone();
    let gate_id = body.gate_id.clone();
    let reason = if body.reason.is_empty() { "published from the dashboard".to_string() } else { body.reason };
    let old_version = state
        .registry()
        .ok()
        .and_then(|r| r.current_version(&app_id, &gate_id).map(|v| v.version));
    let result = state.commit_ctx_published(
        &actor,
        "policy.publish",
        Some((app_id.clone(), Some(gate_id.clone()), old_version, None)),
        |r| {
        let app = match r.applications.iter().find(|a| a.application_id == app_id) {
            Some(a) => a.clone(),
            None => return Err("application vanished".into()),
        };
        let Some(_gate) = app.gate(&gate_id).cloned() else {
            return Err(format!("gate {gate_id} not found"));
        };
        app.validate().map_err(|e| format!("the application does not validate: {e}"))?;
        // Publish the complete application draft as one versioned snapshot.  Application-wide
        // settings (topology/default TTL/production tier) affect more than one gate, so freezing
        // only the clicked gate would create a mixed authorization policy.  Unchanged v2 gates
        // retain their versions; every legacy v1 gate is deliberately re-published into v2.
        let hasher = ghost_gate_registry::Blake3Hasher;
        let mut published = Vec::new();
        for gate in &app.gates {
            let previous = r.current_version(&app_id, &gate.gate_id).cloned();
            let already_current = previous.as_ref().is_some_and(|v| {
                v.policy_hash_version == ghost_gate_registry::POLICY_HASH_V2
                    && v.policy == *gate
                    && ghost_gate_registry::hash_policy_versioned(
                        &hasher,
                        &app,
                        &v.policy,
                        v.version,
                        v.policy_hash_version,
                    ).map(|hash| hash == v.policy_hash).unwrap_or(false)
            });
            if already_current {
                continue;
            }
            let version = match &previous {
                Some(v) => v.next(&hasher, &app, gate)?,
                None => ghost_gate_registry::PolicyVersion {
                    application_id: app_id.clone(),
                    gate_id: gate.gate_id.clone(),
                    version: 1,
                    policy_hash: ghost_gate_registry::hash_policy_versioned(
                        &hasher,
                        &app,
                        gate,
                        1,
                        ghost_gate_registry::POLICY_HASH_V2,
                    )?,
                    policy_hash_version: ghost_gate_registry::POLICY_HASH_V2,
                    policy_context: Some(ghost_gate_core::policy::PublishedApplicationContext::from_application(&app)),
                    network: app.network,
                    genesis_hash: app.genesis_hash.clone(),
                    policy: gate.clone(),
                    app_revision: app.revision,
                    created_unix: ghost_gate_registry::now_unix(),
                },
            };
            r.replacements.push(ghost_gate_registry::ReplacementRecord {
                gate_id: gate.gate_id.clone(),
                from_version: previous.as_ref().map(|v| v.version).unwrap_or(0),
                to_version: version.version,
                reason: reason.clone(),
                outstanding_challenges_invalidated: vec![],
                sessions_carried: Vec::new(),
                sessions_revoked: Vec::new(),
                authorized_by: actor.clone(),
                created_unix: ghost_gate_registry::now_unix(),
            });
            r.versions.push(version);
            published.push(gate.gate_id.clone());
        }
        if published.is_empty() {
            return Err("application policy is already published at hash format v2".into());
        }
            Ok(())
        },
    );
    match result {
        Ok(reg) => {
            let published: Vec<String> = reg
                .replacements
                .iter()
                .rev()
                .take_while(|r| r.reason == reason)
                .map(|r| r.gate_id.clone())
                .collect();
            Response::ok_json(&serde_json::json!({ "published": gate_id, "publishedGates": published }))
        }
        Err(e) => Response::error(400, &format!("GG: {e}")),
    }
}

fn revoke_session(state: &SharedState, req: &Request, authority: &Authority) -> Response {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Body { token_prefix: String, #[serde(default)] reason: String }
    let body: Body = match parse_body(req) { Ok(b) => b, Err(r) => return r };
    if authority.session.stepup_until_unix <= ghost_gate_registry::now_unix() {
        return Response::error(403, "GG: revocation requires fresh authentication");
    }
    let actor = authority.session.credential_id.clone();
    let prefix = body.token_prefix.clone();
    let reason = if body.reason.is_empty() { "revoked from the dashboard".into() } else { body.reason };
    // Revocations are shared with the bridge through the registry file.
    let result = state.commit_ctx_revocation(&actor, "session.revoke", Some(("sessions".into(), None, None, None)), |r| {
        let _lock_free_zone = ();
        r.revocations.push(ghost_gate_registry::Revocation {
            token_prefix: prefix.clone(),
            reason: reason.clone(),
            by: actor.clone(),
            unix: ghost_gate_registry::now_unix(),
        });
        Ok(())
    });
    match result {
        Ok(_) => Response::ok_json(&serde_json::json!({ "revoked": prefix })),
        Err(e) => Response::error(400, &format!("GG: {e}")),
    }
}

fn revoke_all_sessions(state: &SharedState, req: &Request, authority: &Authority) -> Response {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Body { application_id: String, #[serde(default)] reason: String }
    let body: Body = match parse_body(req) { Ok(b) => b, Err(r) => return r };
    if let Err(resp) = gatekeep(state, req, authority, &body.application_id, "session.revoke-all") { return resp; }
    let actor = authority.session.credential_id.clone();
    let app_id = body.application_id.clone();
    // Full revocation is expressed as a policy-version bump-free "kill switch": every live
    // session for this application is recorded as revoked by prefix. The bridge honours it.
    let result = state.commit_ctx_revocation(&actor, "session.revoke-all", Some((app_id.clone(), None, None, None)), |r| {
        let now = ghost_gate_registry::now_unix();
        let _ = now;
        r.revocations.push(ghost_gate_registry::Revocation {
            token_prefix: format!("app:{app_id}:*"),
            reason: if body.reason.is_empty() { "all sessions revoked".into() } else { body.reason.clone() },
            by: actor.clone(),
            unix: ghost_gate_registry::now_unix(),
        });
        Ok(())
    });
    match result {
        Ok(_) => Response::ok_json(&serde_json::json!({ "revokedAll": app_id })),
        Err(e) => Response::error(400, &format!("GG: {e}")),
    }
}

impl Response {
    pub fn with_cookie(mut self, cookie: String) -> Self {
        self.set_cookie = Some(cookie);
        self
    }
}

/// Serve forever. Bounded connections, bounded bodies, same discipline as the bridge (GG-012).
pub async fn serve(state: SharedState, addr: &str) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    loop {
        let (mut socket, _peer) = match listener.accept().await {
            Ok(p) => p,
            Err(_) => continue,
        };
        let state = state.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_BODY + 2048];
            let read = match tokio::time::timeout(IO_TIMEOUT, socket.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => { let _ = socket.shutdown().await; return; }
                Ok(Ok(n)) => n,
            };
            let raw = String::from_utf8_lossy(&buf[..read]).to_string();
            let response = match parse_http(&raw) {
                Some(req) => match route(&state, &req) {
                    Ok(resp) => resp,
                    Err(()) => Response::error(404, "GG: no such route"),
                },
                None => Response::error(400, "GG: malformed request"),
            };
            let mut head = format!(
                "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n",
                response.status,
                status_text(response.status),
                response.content_type,
                response.body.len(),
            );
            if let Some(c) = &response.set_cookie {
                head.push_str(&format!("Set-Cookie: {c}\r\n"));
            }
            head.push_str("\r\n");
            let mut out = head.into_bytes();
            out.extend_from_slice(&response.body);
            let _ = tokio::time::timeout(IO_TIMEOUT, socket.write_all(&out)).await;
            let _ = socket.shutdown().await;
        });
    }
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK", 400 => "Bad Request", 401 => "Unauthorized", 403 => "Forbidden",
        404 => "Not Found", 500 => "Internal Server Error", _ => "Status",
    }
}

fn parse_http(raw: &str) -> Option<Request> {
    let (head, body) = raw.split_once("\r\n\r\n")?;
    let mut lines = head.lines();
    let first = lines.next()?;
    let mut parts = first.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.clone(), String::new()),
    };
    let mut qmap = BTreeMap::new();
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            qmap.insert(url_decode(k), url_decode(v));
        }
    }
    let content_length = headers.get("content-length").and_then(|v| v.parse::<usize>().ok()).unwrap_or(0);
    if content_length > MAX_BODY {
        return None;
    }
    let body = body.as_bytes().get(..content_length.min(body.len())).unwrap_or(&[]).to_vec();
    Some(Request { method, path, query: qmap, headers, body })
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() + 1 && i + 2 <= bytes.len() - 1 + 1 => {
                let hex_part = bytes.get(i + 1..i + 3);
                if let Some(h) = hex_part {
                    if let Ok(v) = u8::from_str_radix(std::str::from_utf8(h).unwrap_or("zz"), 16) {
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
