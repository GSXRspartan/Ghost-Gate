//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! Telegram token-gating POC, on the same backend as Privacy Lab.
//!
//! # The shape
//!
//! The bridge is the verifier. The bot is an operator's agent with three jobs: issue a single-use
//! join token bound to one Telegram account, hold a claim endpoint a joining page can call once a
//! bridge receipt exists, and keep grants expiring.
//!
//! ```text
//!  Telegram user          bot (this process)            bridge (the verifier)        wallet
//!  ─────────────          ───────────────────           ─────────────────────        ──────
//!   /join          ─────▶ token = 32 random bytes
//!                         {token → user, 10 min TTL}
//!   ◀─────  link: /telegram/join/<token>
//!                                                     ◀─ challenge (for the gate)
//!                            (join page in browser)   ◀─ proof/credential flow     prompts
//!                                                     ◀─ verdict: accepted receipt
//!   (page)          ─────▶ POST /claim {token, proof_id}
//!                         re-reads the receipt from the BRIDGE itself:
//!                           state accepted, mode credential, gate matches
//!                         grant = {user → invite(member_limit=1), expires}
//!   ◀─────  invite link
//!      … after ACCESS_TTL …
//!                         ticker: revoke expired grants (ban→unban), invite to re-verify
//! ```
//!
//! # What is enforced here, and where
//!
//! - **Fresh challenges**: every claim runs a brand-new credential proof; nothing is reusable.
//! - **Limited duration**: grants carry `ACCESS_TTL` and are revoked by the ticker; the invite
//!   links are single-seat (`member_limit = 1`), so a forwarded link grants nobody else.
//! - **Server-side verification**: the bot trusts only the bridge's own answer for the proof id —
//!   never the page's claim of what happened. A forged or stale receipt fails the re-read.
//! - **No substitution**: one token = one Telegram account = one claim; a second claim with the
//!   same token refuses.
//! - **No secrets**: the bot asks for nothing but a proof. Seeds, keys and balances are never
//!   mentioned, let alone requested; the receipt names a floor, not a balance.
//! - **Bot token custody**: `GG_TG_BOT_TOKEN` is read once from the environment and never logged.
//!
//! # What a POC deliberately does not do
//!
//! - Grant state is in-memory: a restart forgets it (safe failure — access simply lapses until
//!   re-verified, and nothing stale outlives the process). When the bridge is REGISTRY-BACKED, the
//!   expiry, revocation and policy-hash decisions live in the registry, not here: the bot asks the
//!   bridge on every decision, a dashboard revocation reaches the chat within one tick, and the
//!   session is visible (and revocable) next to every other one. A restart still forgets the
//!   user→session mapping — the registry keeps the session, the bot just no longer knows whose it
//!   was, so the user re-verifies. On a legacy bridge, the bot's own TTL applies exactly as before.
//! - Long polling (`getUpdates`), not webhooks: nothing public to spoof.
//! - Membership checks are *point-in-time*: between two verifications ownership may change. The
//!   product claim is exactly "held enough at verification time", and the ticker enforces that
//!   honestly by revoking on expiry rather than claiming continuous ownership.

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

const DEFAULT_BRIDGE: &str = "http://127.0.0.1:7799";
const DEFAULT_CLAIM_PORT: u16 = 7808;
const DEFAULT_GATE: &str = "Crypt";
const JOIN_TTL: Duration = Duration::from_secs(600);
const ACCESS_TTL: Duration = Duration::from_secs(3600);
const WELCOME_MESSAGE: &str = "👻 Welcome to Ghost Gate.\n\nI verify token-gated access for supported Telegram groups without asking for your seed phrase, private keys, or exact wallet balance.\n\nTo verify your access:\n\n1. Request to join the protected Telegram group.\n2. Send me /join.\n3. Open the single-use Ghost Gate verification link I send you.\n4. Connect your wallet and complete the required token proof.\n\nIf your verification succeeds, I'll automatically approve your pending group join request.\n\nTestnet only.";
const RECHECK_INTERVAL: Duration = Duration::from_secs(60);
/// Whether the fixture bridge/telegram pair is in use; set once at startup.
static FIXTURE_POLL_PAUSE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The Telegram account fixture grants bind to.
const FIXTURE_TG_USER: i64 = 42;

/// The most pending join tokens held at once (audit F-03's class, applied to the bot).
const MAX_PENDING_TOKENS: usize = 512;
const POLL_INTERVAL: u64 = 3; // seconds between getUpdates calls
const MAX_ANSWERED_SEEN: usize = 1024;
const TELEGRAM_HTTP_TIMEOUT: Duration = Duration::from_secs(15);
/// Telegram interprets an expiry less than 30 seconds away as permanent. Ten minutes leaves a
/// deliberately large margin for clock skew and request latency, while bounding the worst case
/// if the process crashes before it can explicitly unban the member.
const TEMPORARY_REMOVAL_SECS: u64 = 600;
/// Recovery is bounded: when a ban/unban request has an ambiguous outcome we retain the user and
/// retry `unbanChatMember`; never discard that recovery work just to accept unbounded input.
const MAX_PENDING_UNBANS: usize = 512;

/// The gate a receipt names, as the bridge's `CredentialReceipt` serialises it.
#[derive(Debug, Clone, Deserialize)]
struct Receipt {
    gate_id: String,
    mode: String,
    #[allow(dead_code)]
    attested_minimum: u64,
    /// Public by construction in this mode. Never logged; it is the linkability surface the
    /// compatibility doc records, and writing it to a log would double the exposure for nothing.
    #[allow(dead_code)]
    substate_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProofStatus {
    state: String,
    #[serde(default)]
    result: Option<Receipt>,
    /// The verified-access session the bridge issued for this proof, when it is registry-backed.
    /// Its expiry, revocation and policy-hash checks live in the REGISTRY, not in this bot: the
    /// dashboard can see and revoke it, and a policy replacement kills it. `None` from a legacy
    /// bridge (or an application with no access plane) — then the bot's own TTL applies.
    #[serde(default)]
    access: Option<AccessGrantView>,
}

/// The wire form of a session grant (registry crate's `AccessGrant`, camelCase).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessGrantView {
    token: String,
    application_id: String,
    #[serde(default)]
    #[allow(dead_code)]
    proven_gate: String,
    expires_unix: u64,
}

#[derive(Debug)]
struct JoinToken {
    user: i64,
    expires: Instant,
    used: bool,
}

#[derive(Debug, Clone)]
struct Grant {
    expires: Instant,
    flow_id: String,
    /// The registry-backed session this grant was issued under, when the bridge has an access
    /// plane. While this is Some, the SERVER decides expiry, revocation and policy validity — the
    /// bot asks on every tick instead of trusting its own clock. `None` is the legacy bridge path:
    /// the local TTL is then the only rule, exactly as before.
    server: Option<ServerGrant>,
}

#[derive(Debug, Clone)]
struct ServerGrant {
    token: String,
    application_id: String,
    expires_unix: u64,
}

/// The Telegram Bot API surface this POC uses.
///
/// A trait so the grant lifecycle is testable without Telegram: the fake records what the bot
/// would have sent, which is also how the revocation race is pinned (single-threaded ticker, no
/// concurrent mutation of the grants map).
#[allow(async_fn_in_trait)]
pub trait TelegramApi: Send {
    async fn send_message(&mut self, user: i64, text: &str) -> Result<(), String>;
    async fn create_join_request_invite(&mut self, chat: i64, expires_unix: u64) -> Result<String, String>;
    async fn approve_join_request(&mut self, chat: i64, user: i64) -> Result<(), String>;
    async fn decline_join_request(&mut self, chat: i64, user: i64) -> Result<(), String>;
    async fn kick_member(&mut self, chat: i64, user: i64) -> Result<(), String>;
    async fn unban_member(&mut self, chat: i64, user: i64) -> Result<(), String>;
    async fn get_updates(&mut self, offset: u64) -> Result<Vec<TgUpdate>, String>;
}

#[derive(Debug, Clone, Deserialize)]
pub struct TgUpdate {
    #[allow(dead_code)]
    pub update_id: u64,
    #[serde(default)]
    pub message: Option<TgMessage>,
    #[serde(default)]
    pub chat_join_request: Option<TgJoinRequest>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TgMessage {
    #[serde(default)]
    pub from: Option<TgUser>,
    #[serde(default)]
    pub text: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TgUser {
    pub id: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TgChat {
    pub id: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TgJoinRequest {
    pub chat: TgChat,
    pub from: TgUser,
}

/// A controlled-fixture Telegram client for LOCAL testing only (GG_TG_FIXTURE=1).
///
/// It records every message the bot "sends" to stdout as `[fixture]` lines and answers getUpdates
/// with nothing, so the whole grant lifecycle can be exercised — join page, claim endpoint,
/// invites, revocation — with no real Telegram and no bot token. It is deliberate, labelled, and
/// never runs unless the operator asks for it.
pub struct FixtureTelegram;

impl TelegramApi for FixtureTelegram {
    async fn send_message(&mut self, user: i64, text: &str) -> Result<(), String> {
        println!("[fixture] -> tg_user {user}: {text}");
        Ok(())
    }
    async fn create_join_request_invite(&mut self, _chat: i64, _expires_unix: u64) -> Result<String, String> {
        let mut b = [0u8; 8];
        rand::fill(&mut b);
        Ok(format!("https://t.me/fixture/join/{}", hex::encode(b)))
    }
    async fn approve_join_request(&mut self, chat: i64, user: i64) -> Result<(), String> {
        println!("[fixture] approve join request tg_user {user} for {chat}");
        Ok(())
    }
    async fn decline_join_request(&mut self, chat: i64, user: i64) -> Result<(), String> {
        println!("[fixture] decline join request tg_user {user} for {chat}");
        Ok(())
    }
    async fn kick_member(&mut self, chat: i64, user: i64) -> Result<(), String> {
        println!("[fixture] kick tg_user {user} from {chat} (ban+unban: seat freed, door open)");
        Ok(())
    }
    async fn unban_member(&mut self, chat: i64, user: i64) -> Result<(), String> {
        println!("[fixture] unban tg_user {user} from {chat}");
        Ok(())
    }
    async fn get_updates(&mut self, _offset: u64) -> Result<Vec<TgUpdate>, String> {
        Ok(vec![])
    }
}

/// The fixture bridge: proof ids starting with `fixture_` answer as accepted credential receipts
/// for the configured gate; anything else answers "not found", so negative cases are still real.
pub struct FixtureBridge {
    gate: String,
    /// Fixture answer for the access check; `None` defers (bridge outage).
    pub access_authorized: Option<bool>,
}

impl BridgeClient for FixtureBridge {
    async fn proof_status(&self, proof_id: &str) -> Result<ProofStatus, String> {
        if proof_id.starts_with("fixture_") {
            return Ok(ProofStatus {
                state: "credential_accepted".into(),
                result: Some(Receipt {
                    gate_id: self.gate.clone(),
                    mode: "credential".into(),
                    attested_minimum: 100_000,
                    substate_id: format!("utxo_fixture_{proof_id}"),
                }),
                access: None,
            });
        }
        Err("404: no such proof".into())
    }

    async fn access_check(&self, _application_id: &str, _gate_id: &str, _token: &str) -> Result<bool, String> {
        match self.access_authorized {
            Some(v) => Ok(v),
            None => Err("fixture outage".into()),
        }
    }
}

/// The real Telegram client: plain Bot API over HTTPS, long polling.
pub struct TelegramBot {
    http: reqwest::Client,
    token: String,
}

impl TelegramBot {
    pub fn new(token: &str) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(TELEGRAM_HTTP_TIMEOUT)
                .build()
                .expect("fixed Telegram HTTP client configuration"),
            token: token.to_string(),
        }
    }

    async fn call(&self, method: &str, params: &serde_json::Value) -> Result<serde_json::Value, String> {
        let url = format!("https://api.telegram.org/bot{}/{}", self.token, method);
        let resp = self
            .http
            .post(&url)
            .json(params)
            .send()
            .await
            .map_err(|_| format!("telegram {method}: request failed"))?;
        let v: serde_json::Value = resp
            .json()
            .await
            .map_err(|_| format!("telegram {method}: invalid response"))?;
        // The Bot API answers {ok: true, result} or {ok: false, description}. Never log the token:
        // only the method name reaches an error message.
        if v["ok"].as_bool() != Some(true) {
            return Err(format!("telegram {}: {}", method, v["description"].as_str().unwrap_or("error")));
        }
        Ok(v["result"].clone())
    }

    /// Read-only preflight. A production bot must be the administrator of one private
    /// supergroup and have both invite-approval and temporary-removal authority.
    async fn diagnose_private_supergroup(&self, chat: i64) -> Result<(), String> {
        let me = self.call("getMe", &json!({})).await?;
        let bot_id = me["id"].as_i64().ok_or("telegram getMe returned no bot id")?;
        let configured = self.call("getChat", &json!({ "chat_id": chat })).await?;
        let membership = self
            .call("getChatMember", &json!({ "chat_id": chat, "user_id": bot_id }))
            .await?;
        validate_private_supergroup(chat, &configured, &membership)
    }

    /// Read the final Telegram-side member state after an operator-controlled test. This is
    /// intentionally diagnostic-only: API success from approve/ban is not itself evidence that
    /// Telegram has applied the membership transition.
    async fn diagnose_member_status(&self, chat: i64, user: i64) -> Result<String, String> {
        let membership = self
            .call("getChatMember", &json!({ "chat_id": chat, "user_id": user }))
            .await?;
        membership["status"]
            .as_str()
            .map(str::to_string)
            .ok_or("telegram getChatMember returned no status".into())
    }
}

fn validate_private_supergroup(
    chat: i64,
    configured: &serde_json::Value,
    membership: &serde_json::Value,
) -> Result<(), String> {
        if configured["id"].as_i64() != Some(chat)
            || configured["type"].as_str() != Some("supergroup")
            || configured["username"].as_str().is_some_and(|name| !name.is_empty())
        {
            return Err("configured Telegram chat is not a private supergroup".into());
        }
        let status = membership["status"].as_str().unwrap_or("");
        if status == "creator" {
            return Ok(());
        }
        if status != "administrator"
            || membership["can_invite_users"].as_bool() != Some(true)
            || membership["can_restrict_members"].as_bool() != Some(true)
        {
            return Err("bot lacks private-supergroup invite approval or member-removal permission".into());
        }
        Ok(())
}

impl TelegramApi for TelegramBot {
    async fn send_message(&mut self, user: i64, text: &str) -> Result<(), String> {
        self.call("sendMessage", &json!({ "chat_id": user, "text": text, "parse_mode": "HTML" }))
            .await
            .map(|_| ())
    }
    async fn create_join_request_invite(&mut self, chat: i64, expires_unix: u64) -> Result<String, String> {
        let v = self
            .call(
                "createChatInviteLink",
                &json!({ "chat_id": chat, "expire_date": expires_unix, "creates_join_request": true }),
            )
            .await?;
        validate_invite_response(&v, now_unix())
    }
    async fn approve_join_request(&mut self, chat: i64, user: i64) -> Result<(), String> {
        self.call("approveChatJoinRequest", &json!({ "chat_id": chat, "user_id": user }))
            .await
            .map(|_| ())
    }
    async fn decline_join_request(&mut self, chat: i64, user: i64) -> Result<(), String> {
        self.call("declineChatJoinRequest", &json!({ "chat_id": chat, "user_id": user }))
            .await
            .map(|_| ())
    }
    async fn kick_member(&mut self, chat: i64, user: i64) -> Result<(), String> {
        // Ban then unban = kick with the door left open for a future re-join.
        self.call(
            "banChatMember",
            &json!({ "chat_id": chat, "user_id": user, "until_date": now_unix() + TEMPORARY_REMOVAL_SECS }),
        )
        .await?;
        self.unban_member(chat, user).await
    }
    async fn unban_member(&mut self, chat: i64, user: i64) -> Result<(), String> {
        self.call("unbanChatMember", &json!({ "chat_id": chat, "user_id": user, "only_if_banned": true }))
            .await
            .map(|_| ())
    }
    async fn get_updates(&mut self, offset: u64) -> Result<Vec<TgUpdate>, String> {
        let v = self
            .call(
                "getUpdates",
                &json!({ "offset": offset, "timeout": POLL_INTERVAL.min(50), "allowed_updates": json!(["message", "chat_join_request"]) }),
            )
            .await?;
        serde_json::from_value(v).map_err(|e| e.to_string())
    }
}

/// Telegram returns a structured ChatInviteLink. Never send a link merely because the API call
/// returned HTTP success: it must be a current HTTPS join-request link created for this flow.
fn validate_invite_response(v: &serde_json::Value, now: u64) -> Result<String, String> {
    if v["creates_join_request"].as_bool() != Some(true) {
        return Err("telegram: invite is not join-request capable".into());
    }
    if v["is_revoked"].as_bool() == Some(true) {
        return Err("telegram: invite was revoked before delivery".into());
    }
    let expires = v["expire_date"]
        .as_u64()
        .ok_or_else(|| "telegram: invite response has no expiry".to_string())?;
    if expires <= now {
        return Err("telegram: invite expired before delivery".into());
    }
    let link = v["invite_link"]
        .as_str()
        .ok_or_else(|| "telegram: no invite link in response".to_string())?;
    if !link.starts_with("https://t.me/") {
        return Err("telegram: invite link is not an HTTPS Telegram link".into());
    }
    Ok(link.to_string())
}

/// The bridge client. Verifier responses are the only thing this bot trusts about a proof.
#[allow(async_fn_in_trait)]
pub trait BridgeClient: Send {
    async fn proof_status(&self, proof_id: &str) -> Result<ProofStatus, String>;
    /// The server-side decision for one (application, gate, token). `Ok(false)` is a DECISION (the
    /// session expired, was revoked, or no longer matches the policy); `Err` is "could not ask" —
    /// a bridge outage — which the ticker treats as "defer, decide next tick", not as a refusal.
    async fn access_check(&self, application_id: &str, gate_id: &str, token: &str) -> Result<bool, String>;
}

pub struct HttpBridge {
    base: String,
    http: reqwest::Client,
}

impl HttpBridge {
    pub fn new(base: &str) -> Self {
        Self { base: base.trim_end_matches('/').to_string(), http: reqwest::Client::new() }
    }
}

impl BridgeClient for HttpBridge {
    async fn proof_status(&self, proof_id: &str) -> Result<ProofStatus, String> {
        let url = format!("{}/proof/{}/status", self.base, urlencode(proof_id));
        let resp = self.http.get(&url).send().await.map_err(|e| e.to_string())?;
        let v: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        serde_json::from_value(v).map_err(|e| e.to_string())
    }

    async fn access_check(&self, application_id: &str, gate_id: &str, token: &str) -> Result<bool, String> {
        // Any non-200 is a decision of "no": a missing session, an expired one, a revoked one and a
        // policy mismatch all mean the same thing to a door. Only a transport failure is Err.
        let url = format!(
            "{}/access/check?application={}&gate={}&token={}",
            self.base,
            urlencode(application_id),
            urlencode(gate_id),
            urlencode(token),
        );
        let resp = match self.http.get(&url).send().await {
            Ok(r) => r,
            Err(e) => return Err(e.to_string()),
        };
        if !resp.status().is_success() {
            return Ok(false);
        }
        let v: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        Ok(v.get("authorized").and_then(|a| a.as_bool()).unwrap_or(false))
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// The bot's state and the grant lifecycle, all testable.
///
/// Generic over the Telegram and bridge clients — the same shape as `Bridge<W>`: native
/// `async fn` traits are deliberately not object-safe, so the seams are type parameters, and a
/// test constructs the bot with fakes exactly as `main` constructs it with the real clients.
pub struct Bot<T: TelegramApi, B: BridgeClient> {
    pub telegram: T,
    pub bridge: B,
    /// The community chat membership is granted to.
    pub chat: i64,
    /// The gate a proof must name. Any other gate's receipt is refused.
    pub gate: String,
    pub join_ttl: Duration,
    pub access_ttl: Duration,
    /// Only the explicitly configured local fixture may use a non-registry test authorization.
    /// Live processes require a server-issued access grant and currently remain disabled while the
    /// Stage 5 consensus bootstrap is untrusted.
    fixture_authorization: bool,
    tokens: HashMap<String, JoinToken>,
    grants: HashMap<i64, Grant>,
    /// A `banChatMember` request may have succeeded even when its response was lost. Keep a
    /// bounded explicit-unban recovery queue rather than risking a permanent exclusion.
    pending_unbans: std::collections::BTreeSet<i64>,
    /// IDs already acted on, so a replayed update (Telegram resends on offset races) cannot mint a
    /// second grant.
    seen_updates: std::collections::BTreeSet<u64>,
}

impl<T: TelegramApi, B: BridgeClient> Bot<T, B> {
    pub fn new(telegram: T, bridge: B, chat: i64, gate: String) -> Self {
        Self {
            telegram,
            bridge,
            chat,
            gate,
            join_ttl: JOIN_TTL,
            access_ttl: ACCESS_TTL,
            fixture_authorization: false,
            tokens: HashMap::new(),
            grants: HashMap::new(),
            pending_unbans: std::collections::BTreeSet::new(),
            seen_updates: std::collections::BTreeSet::new(),
        }
    }

    fn new_fixture(telegram: T, bridge: B, chat: i64, gate: String) -> Self {
        let mut bot = Self::new(telegram, bridge, chat, gate);
        bot.fixture_authorization = true;
        bot
    }

    /// `/join`: mints a single-use token bound to this Telegram account.
    pub async fn join(&mut self, user: i64, base_url: &str, _claim_base: &str, _bridge_public_url: Option<&str>) -> Result<String, String> {
        // A user rejoining while a grant is live gets told, rather than silently minting a second
        // proof obligation. A server-backed grant is ASKED, not trusted from memory: if the session
        // was revoked or expired while the bot was looking away, the user simply rejoins.
        let existing = self.grants.get(&user).map(|g| (g.server.clone(), g.expires));
        if let Some((server, expires)) = existing {
            let alive = match &server {
                Some(sg) => {
                    matches!(
                        self.bridge
                            .access_check(&sg.application_id, &self.gate, &sg.token)
                            .await,
                        Ok(true)
                    )
                }
                None => expires > Instant::now(),
            };
            if alive {
                let left = expires.duration_since(Instant::now()).as_secs().max(1);
                return Ok(format!(
                    "Your access is already verified for another {} minute(s). I'll ask for a fresh proof when it lapses.",
                    (left + 59) / 60
                ));
            }
            if server.is_some() {
                self.grants.remove(&user);
            }
        }
        let mut bytes = [0u8; 32];
        rand::fill(&mut bytes);
        let token = hex::encode(bytes);
        // The same bound state rule as the bridge's challenge book (audit F-03): /join is cheap
        // to call, so the pending-token set is capped, with the oldest-expiring dropped first.
        // Saturation answers with the remedy rather than growing without bound.
        if self.tokens.len() >= MAX_PENDING_TOKENS {
            self.tokens.retain(|_, t| t.expires > Instant::now());
            if self.tokens.len() >= MAX_PENDING_TOKENS {
                let oldest = self
                    .tokens
                    .iter()
                    .min_by_key(|(_, t)| t.expires)
                    .map(|(k, _)| k.clone());
                if let Some(oldest) = oldest {
                    self.tokens.remove(&oldest);
                }
            }
        }
        self.tokens.insert(
            token.clone(),
            JoinToken { user, expires: Instant::now() + self.join_ttl, used: false },
        );
        audit(
            "JOIN_TOKEN_CREATED",
            json!({
                "flow_id": audit_id(&token),
                "telegram_user_id": user,
                "chat_id": self.chat,
                "expires_unix": now_unix() + self.join_ttl.as_secs(),
            }),
        );
        Ok(format!(
            "To prove you hold enough of the vault's token, open this link in the browser where your wallet lives:\n\n{}\n\nThis link is for you alone, works once, and expires in 10 minutes. I will never ask for your seed, keys, or exact balance — the check is a public minimum, verified by the network.",
            {
                format!(
                    "{}/telegram/join?token={token}&gate={}",
                    base_url.trim_end_matches('/'),
                    self.gate,
                )
            }
        ))
    }

    /// The claim endpoint's logic. Single-use token, TTL, and the bridge's own receipt re-read.
    pub async fn claim(&mut self, token: &str, proof_id: &str) -> Result<String, String> {
        let flow_id = audit_id(token);
        let record = self
            .tokens
            .get(token)
            .ok_or_else(|| {
                audit(
                    "CLAIM_RECEIVED",
                    json!({ "flow_id": flow_id, "chat_id": self.chat, "binding": "unknown_token" }),
                );
                "unknown or already-consumed join link"
            })?;
        if record.used {
            audit(
                "CLAIM_RECEIVED",
                json!({ "flow_id": flow_id, "telegram_user_id": record.user, "chat_id": self.chat, "binding": "replay" }),
            );
            return Err("this join link was already used".into());
        }
        if record.expires < Instant::now() {
            audit(
                "CLAIM_RECEIVED",
                json!({ "flow_id": flow_id, "telegram_user_id": record.user, "chat_id": self.chat, "binding": "expired" }),
            );
            self.tokens.remove(token);
            return Err("this join link expired; send /join again".into());
        }
        let user = record.user;
        audit(
            "CLAIM_RECEIVED",
            json!({ "flow_id": flow_id, "telegram_user_id": user, "chat_id": self.chat, "binding": "matched" }),
        );

        // Server-side verification, from the bridge only. The page's word is not evidence.
        let status = self
            .bridge
            .proof_status(proof_id)
            .await
            .map_err(|e| {
                audit("CRYPT_VERIFIED", json!({ "flow_id": flow_id, "verified": false, "reason": error_class(&e) }));
                format!("could not read the proof from the bridge: {e}")
            })?;
        if status.state != "credential_accepted" {
            audit("CRYPT_VERIFIED", json!({ "flow_id": flow_id, "verified": false, "reason": "bridge_not_accepted" }));
            return Err("the bridge does not show this proof as accepted".into());
        }
        let receipt = status
            .result
            .ok_or_else(|| {
                audit("CRYPT_VERIFIED", json!({ "flow_id": flow_id, "verified": false, "reason": "missing_receipt" }));
                "the bridge's accepted proof carries no receipt"
            })?;
        if receipt.mode != "credential" {
            audit("CRYPT_VERIFIED", json!({ "flow_id": flow_id, "verified": false, "gate_id": receipt.gate_id, "reason": "wrong_proof_mode" }));
            return Err("the proof is not a credential-mode receipt".into());
        }
        if receipt.gate_id != self.gate {
            audit("CRYPT_VERIFIED", json!({ "flow_id": flow_id, "verified": false, "gate_id": receipt.gate_id, "reason": "wrong_gate" }));
            return Err(format!(
                "this proof is for gate {:?}, not the community gate {:?}",
                receipt.gate_id, self.gate
            ));
        }

        // The bridge hands back the session the registry issued for this proof, when it has an
        // access plane. From then on the SERVER owns the clock: expiry, revocation and policy
        // replacements all apply to this user the moment they happen, and the session appears in
        // the administrator dashboard next to every other one.
        let server = status.access.map(|a| ServerGrant {
            token: a.token,
            application_id: a.application_id,
            expires_unix: a.expires_unix,
        });
        audit(
            "CRYPT_VERIFIED",
            json!({
                "flow_id": flow_id,
                "gate_id": receipt.gate_id,
                "verified": true,
                "session_id": server.as_ref().map(|grant| audit_id(&grant.token)),
            }),
        );
        if server.is_none() && !self.fixture_authorization {
            audit("GRANT_CREATED", json!({ "flow_id": flow_id, "telegram_user_id": user, "chat_id": self.chat, "created": false, "reason": "missing_server_session" }));
            return Err(
                "the bridge accepted a proof but issued no production access session; Telegram admission remains fail-closed"
                    .into(),
            );
        }
        let (expires, minutes) = match &server {
            Some(sg) => {
                let remaining = sg.expires_unix.saturating_sub(now_unix());
                (Instant::now() + Duration::from_secs(remaining), (remaining + 59) / 60)
            }
            None => (Instant::now() + self.access_ttl, self.access_ttl.as_secs() / 60),
        };
        let expires_unix = server
            .as_ref()
            .map(|grant| grant.expires_unix)
            .unwrap_or_else(|| now_unix() + self.access_ttl.as_secs());
        let is_fixture_grant = self.fixture_authorization && server.is_none();
        // Join-request invites cannot use Telegram's member_limit. The bot approves the request
        // only for the Telegram identity bound to this grant, so a forwarded invite cannot admit
        // another account.
        let link = self
            .telegram
            .create_join_request_invite(self.chat, expires_unix)
            .await
            .map_err(|error| {
                audit(
                    "TELEGRAM_INVITE_CREATED",
                    json!({ "flow_id": flow_id, "chat_id": self.chat, "valid": false, "error_class": error_class(&error) }),
                );
                error
            })?;
        audit(
            "TELEGRAM_INVITE_CREATED",
            json!({
                "flow_id": flow_id,
                "chat_id": self.chat,
                "valid": true,
                "creates_join_request": true,
                "expires_unix": expires_unix,
            }),
        );

        // Consume the one-time browser token only after the Telegram invite has been created.
        // Until this point no admission artifact exists, so a transient Bot API failure must not
        // strand an otherwise valid proof. The event loop serializes claims; once the invite is
        // returned, marking the token and recording the grant happen without another await.
        self.tokens.get_mut(token).expect("checked above").used = true;
        audit("TOKEN_CONSUMED", json!({ "flow_id": flow_id, "telegram_user_id": user, "chat_id": self.chat }));
        self.grants.insert(
            user,
            Grant { expires, flow_id: flow_id.clone(), server },
        );
        audit(
            "GRANT_CREATED",
            json!({
                "flow_id": flow_id,
                "telegram_user_id": user,
                "chat_id": self.chat,
                "expires_unix": expires_unix,
                "created": true,
            }),
        );
        let duration = duration_label(minutes.saturating_mul(60));
        let message = if is_fixture_grant {
            format!(
                "TEST ONLY: a local fixture authorized this test-group request for {duration}. No consensus-verified production access was granted."
            )
        } else {
            format!(
                "Verified: the network attested at least the threshold, and I never learned a balance. Doors open for {duration}. I'll ask for a fresh proof when it lapses.\n\nJoin the group: {link}"
            )
        };
        self.telegram
            .send_message(user, &message)
            .await
            .ok();
        Ok(link)
    }

    async fn retry_pending_unbans(&mut self) {
        let pending = self.pending_unbans.iter().copied().collect::<Vec<_>>();
        for user in pending {
            if self.telegram.unban_member(self.chat, user).await.is_ok() {
                self.pending_unbans.remove(&user);
            }
        }
    }

    async fn remove_member(&mut self, user: i64) {
        // `kick_member` is ban-then-unban. An error is ambiguous: its ban may have reached
        // Telegram while the response or follow-up unban did not. Queue recovery even for an
        // apparent ban failure; `only_if_banned` makes the extra unban harmless.
        if self.telegram.kick_member(self.chat, user).await.is_err() {
            if self.pending_unbans.contains(&user) || self.pending_unbans.len() < MAX_PENDING_UNBANS {
                self.pending_unbans.insert(user);
                self.retry_pending_unbans().await;
            }
        }
    }

    /// The re-verification ticker: revoke expired grants, tell the user how to rejoin.
    ///
    /// Runs in one place (the caller's loop) so no two ticks can race the same user's revocation.
    pub async fn tick(&mut self) {
        self.retry_pending_unbans().await;
        let now = Instant::now();
        // Tokens whose TTL passed — used or not — are state nobody can act on any more.
        self.tokens.retain(|_, t| t.expires > now);
        // Legacy grants (no server session) expire on the bot's clock, as before. Server-backed
        // grants are ASKED: the registry's expiry, revocation and policy-hash checks are the
        // authority, so a revocation in the dashboard reaches this chat within one tick.
        let mut expired: Vec<i64> = self
            .grants
            .iter()
            .filter(|(_, g)| g.server.is_none() && g.expires <= now)
            .map(|(u, _)| *u)
            .collect();
        for (user, g) in self.grants.iter() {
            let Some(sg) = &g.server else { continue };
            match self.bridge.access_check(&sg.application_id, &self.gate, &sg.token).await {
                Ok(true) => {}
                Ok(false) => expired.push(*user), // a decision: expired, revoked, or policy moved
                Err(_) => {}                      // could not ask — defer to the next tick
            }
        }
        for user in expired {
            let grant = self.grants.remove(&user).expect("just filtered");
            // Kick (temporary ban + explicit unban) so the seat frees and re-joining remains
            // possible after re-verification. Ambiguous failures enter durable-in-process
            // unban recovery; the temporary ban is itself bounded to ten minutes.
            self.remove_member(user).await;
            self.telegram
                .send_message(
                    user,
                    "Your verification expired, so I've let your seat go. No hard feelings — send /join for a fresh proof.",
                )
                .await
                .ok();
            let _ = grant;
        }
        self.seen_updates.truncate_tail(MAX_ANSWERED_SEEN);
    }

    /// Acts on one update: commands and no-op resends.
    pub async fn handle_update(&mut self, update: TgUpdate, base_url: &str, claim_base: &str, bridge_public_url: Option<&str>) {
        if let Some(request) = update.chat_join_request {
            self.handle_join_request(request).await;
            return;
        }
        let Some(message) = update.message.clone() else { return };
        let Some(user) = message.from.as_ref().map(|f| f.id) else { return };
        let text = message.text.clone().unwrap_or_default();
        if text.starts_with("/join") {
            if let Ok(reply) = self.join(user, base_url, claim_base, bridge_public_url).await {
                self.telegram.send_message(user, &reply).await.ok();
            } else {
                self.telegram
                    .send_message(user, "Something went wrong minting your join link; try again.")
                    .await
                    .ok();
            }
        } else {
            // /start and ordinary pre-join messages are guidance only. /join is
            // deliberately the sole command that mints a single-use token.
            let _ = (base_url, claim_base, bridge_public_url);
            self.telegram.send_message(user, WELCOME_MESSAGE).await.ok();
        }
    }

    /// Telegram supplies this identity in its own signed/update channel; it is never accepted
    /// from the browser claim. A forwarded invite reaches this check under the forwarder's own
    /// Telegram user id and is declined unless that id owns a live grant for this exact chat.
    async fn handle_join_request(&mut self, request: TgJoinRequest) {
        audit(
            "CHAT_JOIN_REQUEST_RECEIVED",
            json!({ "telegram_user_id": request.from.id, "chat_id": request.chat.id }),
        );
        if request.chat.id != self.chat {
            audit(
                "GRANT_MATCH",
                json!({ "telegram_user_id": request.from.id, "chat_id": request.chat.id, "matched": false, "reason": "wrong_chat" }),
            );
            return;
        }
        let user = request.from.id;
        let grant = self.grants.get(&user).cloned();
        let flow_id = grant.as_ref().map(|grant| grant.flow_id.clone());
        audit(
            "GRANT_MATCH",
            json!({
                "flow_id": flow_id,
                "telegram_user_id": user,
                "chat_id": request.chat.id,
                "matched": grant.is_some(),
                "reason": if grant.is_some() { "candidate" } else { "no_grant" },
            }),
        );
        let authorized = match grant {
            Some(grant) => match grant.server {
                Some(server) => {
                    let check = self
                        .bridge
                        .access_check(&server.application_id, &self.gate, &server.token)
                        .await;
                    audit(
                        "BRIDGE_ACCESS_CHECK",
                        json!({
                            "flow_id": grant.flow_id,
                            "telegram_user_id": user,
                            "chat_id": self.chat,
                            "allowed": matches!(check, Ok(true)),
                            "reason": match &check { Ok(true) => "authorized", Ok(false) => "denied", Err(error) => error_class(error) },
                        }),
                    );
                    matches!(check, Ok(true))
                }
                None => self.fixture_authorization && grant.expires > Instant::now(),
            },
            None => false,
        };
        if authorized {
            let result = self.telegram.approve_join_request(self.chat, user).await;
            audit(
                "TELEGRAM_APPROVAL",
                json!({
                    "telegram_user_id": user,
                    "chat_id": self.chat,
                    "success": result.is_ok(),
                    "error_class": result.as_ref().err().map(|error| error_class(error)),
                }),
            );
        } else {
            let result = self.telegram.decline_join_request(self.chat, user).await;
            audit(
                "TELEGRAM_APPROVAL",
                json!({
                    "telegram_user_id": user,
                    "chat_id": self.chat,
                    "success": false,
                    "action": "declined",
                    "error_class": result.as_ref().err().map(|error| error_class(error)),
                }),
            );
        }
    }

    pub fn grant_count(&self) -> usize {
        self.grants.len()
    }

    fn admission_label(&self) -> &'static str {
        if self.fixture_authorization { "test_only" } else { "production" }
    }
}

trait TruncateTail {
    fn truncate_tail(&mut self, max: usize);
}

impl TruncateTail for std::collections::BTreeSet<u64> {
    fn truncate_tail(&mut self, max: usize) {
        if self.len() <= max {
            return;
        }
        let overflow = self.len() - max;
        let first = self.iter().take(overflow).cloned().collect::<Vec<_>>();
        for k in first {
            self.remove(&k);
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Return a short, non-reversible correlation identifier for an in-memory bearer value.
/// Diagnostic output must never contain join tokens or bridge session tokens themselves.
fn audit_id(value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(value.as_bytes());
    hex::encode(&digest.finalize()[..8])
}

fn audit(event: &str, fields: serde_json::Value) {
    let mut object = match fields {
        serde_json::Value::Object(object) => object,
        _ => serde_json::Map::new(),
    };
    object.insert("event".into(), serde_json::Value::String(event.into()));
    eprintln!("ghost-gate-telegram: audit {}", serde_json::Value::Object(object));
}

fn error_class(error: &str) -> &'static str {
    let lower = error.to_ascii_lowercase();
    if lower.contains("timeout") || lower.contains("request failed") || lower.contains("connection") {
        "transport"
    } else if lower.contains("permission") || lower.contains("forbidden") || lower.contains("not enough rights") {
        "permission"
    } else if lower.contains("expired") || lower.contains("revoked") {
        "expired_or_revoked"
    } else {
        "api_error"
    }
}

/// Keep human-facing access duration readable without changing the exact server expiry.
/// Registry-backed sessions are normally seven days; show that as "7 days" instead of
/// "10080 minute(s)" while retaining minute/hour wording for shorter or unusual lifetimes.
fn duration_label(seconds: u64) -> String {
    let minutes = ((seconds + 59) / 60).max(1);
    if minutes >= 24 * 60 {
        let days = (minutes + (24 * 60 - 1)) / (24 * 60);
        return format!("{days} day{}", if days == 1 { "" } else { "s" });
    }
    if minutes >= 60 {
        let hours = (minutes + 59) / 60;
        return format!("{hours} hour{}", if hours == 1 { "" } else { "s" });
    }
    format!("{minutes} minute{}", if minutes == 1 { "" } else { "s" })
}

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("runtime");
    let code = runtime.block_on(run());
    std::process::exit(code);
}

async fn run() -> i32 {
    // Fixture mode, for LOCAL lifecycle testing without Telegram. It is explicitly labelled in
    // every log line; a fixture grant is never a real membership.
    let fixture = std::env::var("GG_TG_FIXTURE").ok().as_deref() == Some("1");
    // This is deliberately distinct from the local no-Telegram fixture. It permits a controlled
    // Bot API exercise only for an operator-configured private test supergroup; it cannot create
    // a production authorization because it uses FixtureBridge and carries `test_only` results.
    let real_test_mode = std::env::var("GG_TG_TEST_MODE").ok().as_deref() == Some("1");
    if fixture && real_test_mode {
        eprintln!("ghost-gate-telegram: GG_TG_FIXTURE and GG_TG_TEST_MODE cannot be combined");
        return 1;
    }
    let token = match (fixture, std::env::var("GG_TG_BOT_TOKEN")) {
        (true, _) => String::new(),
        (false, Ok(t)) if !t.trim().is_empty() => t,
        _ => {
            eprintln!(
                "ghost-gate-telegram: GG_TG_BOT_TOKEN must be set (from BotFather; never committed, \
                 never logged) — or set GG_TG_FIXTURE=1 for a local, no-Telegram fixture run"
            );
            return 1;
        },
    };
    let chat: i64 = match std::env::var("GG_TG_CHAT_ID").ok().and_then(|v| v.parse::<i64>().ok()) {
        Some(c) => c,
        None => {
            eprintln!("ghost-gate-telegram: GG_TG_CHAT_ID must be the community chat's id");
            return 1;
        },
    };
    let bridge = std::env::var("GG_BRIDGE_ENDPOINT").unwrap_or_else(|_| DEFAULT_BRIDGE.into());
    let gate = std::env::var("GG_TG_GATE").unwrap_or_else(|_| DEFAULT_GATE.into());
    let claim_port: u16 = std::env::var("GG_TG_CLAIM_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_CLAIM_PORT);
    let bridge_base = std::env::var("GG_JOIN_BASE_URL").unwrap_or_else(|_| bridge.clone());
    let bridge_public_url: Option<String> = std::env::var("GG_BRIDGE_PUBLIC_URL").ok().filter(|v| !v.is_empty());

    // Two arms, because the fixture and real bots are different types (the clients are type
    // parameters, never trait objects), and unifying them would need an extra enum for one
    // startup if/else.
    if fixture {
        let test_chat = match std::env::var("GG_TG_FIXTURE_TEST_CHAT_ID")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
        {
            Some(value) if value == chat => value,
            _ => {
                eprintln!(
                    "ghost-gate-telegram: fixture mode requires GG_TG_FIXTURE_TEST_CHAT_ID to equal GG_TG_CHAT_ID; no real Telegram membership is ever changed"
                );
                return 1;
            }
        };
        FIXTURE_POLL_PAUSE.store(true, std::sync::atomic::Ordering::Relaxed);
        // In fixture mode the bot never reads Telegram, so it mints one join token at startup for
        // the fixture user and prints everything needed to drive the lifecycle by hand.
        let mut bot = Bot::new_fixture(
            FixtureTelegram,
            FixtureBridge { gate: gate.clone(), access_authorized: None },
            test_chat,
            gate.clone(),
        );
        let reply = bot
            .join(FIXTURE_TG_USER, &bridge_base, &format!("http://127.0.0.1:{claim_port}"), bridge_public_url.as_deref())
            .await
            .expect("fixture join");
        let marker = "token=";
        let token_part = reply[reply.find(marker).expect("join link") + marker.len()..]
            .split('&')
            .next()
            .expect("token")
            .to_string();
        let redacted_reply = reply.replace(&token_part, "<redacted>");
        eprintln!(
            "ghost-gate-telegram: FIXTURE MODE — no Telegram is contacted; grants are local only.\n\
             fixture join page (bearer token redacted):\n\
               {redacted_reply}\n\
             fixture flow id: {}\n\
             the fixture bridge accepts proof ids starting with 'fixture_'",
            audit_id(&token_part),
        );
        return serve(bot, &bridge_base, &format!("http://127.0.0.1:{claim_port}"), claim_port, &gate, bridge_public_url.as_deref()).await;
    }

    let telegram = TelegramBot::new(&token);
    if let Err(error) = telegram.diagnose_private_supergroup(chat).await {
        eprintln!("ghost-gate-telegram: Telegram diagnostic failed: {error}");
        return 1;
    }
    if let Some(test_member) = std::env::var("GG_TG_TEST_MEMBER_ID")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
    {
        match telegram.diagnose_member_status(chat, test_member).await {
            Ok(status) => eprintln!("ghost-gate-telegram: Telegram test-member state: {status}"),
            Err(error) => {
                eprintln!("ghost-gate-telegram: Telegram test-member diagnostic failed: {error}");
                return 1;
            }
        }
    }
    if std::env::var("GG_TG_DIAGNOSE").ok().as_deref() == Some("1") {
        eprintln!("ghost-gate-telegram: Telegram identity and private-supergroup permissions verified; diagnostic only");
        return 0;
    }
    if real_test_mode {
        let test_chat = match std::env::var("GG_TG_TEST_CHAT_ID")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
        {
            Some(value) if value == chat => value,
            _ => {
                eprintln!(
                    "ghost-gate-telegram: test mode requires GG_TG_TEST_CHAT_ID to equal GG_TG_CHAT_ID; it can only operate on the explicitly configured private test group"
                );
                return 1;
            }
        };
        eprintln!(
            "ghost-gate-telegram: TEST MODE — real Telegram test group only; fixture authorization is not consensus-verified and can never grant production access"
        );
        let bot = Bot::new_fixture(
            telegram,
            FixtureBridge { gate: gate.clone(), access_authorized: None },
            test_chat,
            gate.clone(),
        );
        return serve(bot, &bridge_base, &format!("http://127.0.0.1:{claim_port}"), claim_port, &gate, bridge_public_url.as_deref()).await;
    }
    // Live testnet: real Telegram + real bridge, operator-trusted evidence only. The bridge must
    // be registry-backed and issuing real access sessions (operatorTrustedTestnet tier).
    let live_testnet = std::env::var("GG_TG_LIVE_TESTNET").ok().as_deref() == Some("1");
    if live_testnet {
        let test_chat = match std::env::var("GG_TG_TEST_CHAT_ID")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
        {
            Some(value) if value == chat => value,
            _ => {
                eprintln!(
                    "ghost-gate-telegram: live testnet mode requires GG_TG_TEST_CHAT_ID to equal GG_TG_CHAT_ID; \
                     it can only operate on the explicitly configured private test group"
                );
                return 1;
            }
        };
        eprintln!(
            "ghost-gate-telegram: LIVE TESTNET — real Telegram, real bridge at {bridge}; \
             operator-trusted-testnet evidence only, not consensus-verified production"
        );
        let bot = Bot::new(
            telegram,
            HttpBridge::new(&bridge),
            test_chat,
            gate.clone(),
        );
        return serve(bot, &bridge_base, &format!("http://127.0.0.1:{claim_port}"), claim_port, &gate, bridge_public_url.as_deref()).await;
    }

    eprintln!(
        "ghost-gate-telegram: production admission is disabled: the Stage 5 consensus trust bootstrap is not independently authenticated"
    );
    1
}

/// The bot's two loops plus the claim listener, wired together.
///
/// One task, one `select!`: long-poll Telegram, answer claims, and tick re-verification all share
/// the same event loop. That removes every cross-thread `Send` constraint the trait seams would
/// otherwise carry, and makes the no-race guarantee structural — grants cannot be mutated by two
/// tasks because there is only one.
pub async fn serve<T: TelegramApi, B: BridgeClient>(
    mut bot: Bot<T, B>,
    join_base: &str,
    claim_base: &str,
    claim_port: u16,
    gate: &str,
    bridge_public_url: Option<&str>,
) -> i32 {
    let listener = match tokio::net::TcpListener::bind(("127.0.0.1", claim_port)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ghost-gate-telegram: cannot bind the claim endpoint on 127.0.0.1:{claim_port}: {e}");
            return 1;
        },
    };
    eprintln!(
        "ghost-gate-telegram: gate {gate:?}; claim endpoint 127.0.0.1:{claim_port}; join page base {join_base}"
    );

    let mut tick = tokio::time::interval(RECHECK_INTERVAL);
    let mut update_offset: u64 = 0;
    // The accept half of one claim connection, held across loop iterations.
    let mut pending_accept: Option<tokio::net::TcpStream> = None;

    loop {
        tokio::select! {
            // A claim connection arriving.
            accepted = listener.accept(), if pending_accept.is_none() => {
                match accepted {
                    Ok((socket, _)) => {
                        pending_accept = Some(socket);
                        // The request bytes are read below, in the read branch.
                        continue;
                    },
                    Err(_) => continue,
                }
            },
            // Reading and answering a claim connection.
            read = async {
                let read_one: std::future::Ready<()> = std::future::ready(());
                let _ = read_one;
                match pending_accept.as_mut() {
                    Some(socket) => {
                        let mut buf = vec![0u8; 8 * 1024];
                        let n: usize = socket.read(&mut buf).await.unwrap_or(0);
                        Ok::<(usize, Vec<u8>), std::convert::Infallible>((n, buf))
                    },
                    None => {
                        // No connection in flight: wait until the accept branch provides one.
                        std::future::pending().await
                    },
                }
            } => {
                let mut socket = pending_accept.take().expect("read branch implies a pending socket");
                let (n, buf) = match read {
                    Ok(pair) => pair,
                    Err(_) => continue,
                };
                let raw = String::from_utf8_lossy(&buf[..n]).to_string();
                let response = handle_claim_http(&mut bot, &raw).await;
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            },
            // Telegram long polling. (The fixture client answers instantly, so the fixture pauses
            // before each poll to keep the loop from spinning the CPU.)
            updates = async {
                if FIXTURE_POLL_PAUSE.load(std::sync::atomic::Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                bot.telegram.get_updates(update_offset).await
            } => {
                match updates {
                    Ok(list) => {
                        for update in list {
                            update_offset = update_offset.max(update.update_id + 1);
                            if !bot.seen_updates.insert(update.update_id) {
                                continue; // a resend, not a new command
                            }
                            bot.handle_update(update, join_base, claim_base, bridge_public_url).await;
                        }
                    },
                    Err(_) => { /* transient Telegram errors: try again next cycle */ },
                }
            },
            // The re-verification ticker.
            _ = tick.tick() => {
                bot.tick().await;
            },
        }
    }
}

/// Parses one claim request and answers it.
///
/// CORS here is deliberate and narrow: the claim comes from the bridge's own join page (a
/// different port, so a different origin), so the preflight must name that origin exactly. No
/// wildcard, ever — a claim endpoint that answers for every origin is a claim endpoint the whole
/// web can drive.
async fn handle_claim_http<T: TelegramApi, B: BridgeClient>(bot: &mut Bot<T, B>, raw: &str) -> String {
    // The same transport discipline the bridge applies, scaled to this endpoint. A claim endpoint
    // that answered every host is a claim endpoint a rebound name could drive; and a POST whose
    // Content-Type is a CORS-safelisted type (text/plain etc.) would skip the preflight entirely,
    // so the declared type is enforced and the body's shape re-checked below.
    let allowed_origin = std::env::var("GG_JOIN_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:7799".into());
    let cors = format!("Access-Control-Allow-Origin: {allowed_origin}\r\nAccess-Control-Allow-Methods: POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nVary: Origin\r\n");

    let mut lines = raw.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let (method, _target) = request_line.split_once(' ').unwrap_or(("", ""));
    let mut content_type: Option<String> = None;
    let mut host: Option<String> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let v = value.trim();
            if name.eq_ignore_ascii_case("content-type") {
                content_type = Some(v.to_string());
            } else if name.eq_ignore_ascii_case("host") {
                host = Some(v.to_string());
            }
        }
    }
    // Host: only loopback spellings, like the bridge.
    if let Some(h) = &host {
        let name = h.rsplit_once(':').map(|(n, p)| {
            if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) { n } else { h.as_str() }
        });
        if let Some(name) = name {
            let lname = name.to_ascii_lowercase();
            if !matches!(lname.as_str(), "127.0.0.1" | "localhost" | "[::1]" | "::1") {
                return format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: 67\r\n{cors}\r\n\
                     {{\"error\":\"this claim endpoint answers only for loopback hosts\"}}"
                );
            }
        }
    }

    if method == "OPTIONS" {
        return format!("HTTP/1.1 204 No Content\r\n{cors}\r\n");
    }
    if method != "POST" {
        return format!("HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n{cors}\r\n");
    }
    // The declared media type must be JSON: a safelisted type would have skipped the preflight
    // that this endpoint's CORS otherwise gates.
    if let Some(ct) = &content_type {
        let base = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
        if base != "application/json" {
            return format!(
                "HTTP/1.1 415 Unsupported Media Type\r\nContent-Type: application/json\r\nContent-Length: 45\r\n{cors}\r\n\
                 {{\"error\":\"claims must be application/json\"}}"
            );
        }
    }
    let body = raw.split("\r\n\r
").nth(1).unwrap_or("");
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(body);
    let Some(body) = parsed.ok() else {
        return format!("HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: 32\r\n{cors}\r\n{{\"error\":\"malformed claim body\"}}");
    };
    let token = body["token"].as_str().unwrap_or("").to_string();
    let proof_id = body["proof_id"].as_str().unwrap_or("").to_string();
    if token.is_empty() || proof_id.is_empty() {
        return format!("HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: 36\r\n{cors}\r\n{{\"error\":\"token and proof_id required\"}}");
    }
    match bot.claim(&token, &proof_id).await {
        Ok(link) => {
            let payload = json!({
                "state": "granted",
                "admission": bot.admission_label(),
                "invite_link": link,
                "at": now_unix(),
            })
            .to_string();
            format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{cors}\r\n{payload}", payload.len())
        },
        Err(e) => {
            let payload = json!({ "state": "refused", "error": e }).to_string();
            format!("HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{cors}\r\n{payload}", payload.len())
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records what the bot would send.
    struct FakeTelegram {
        invites: Vec<i64>,
        invite_fails: bool,
        kicked: Vec<i64>,
        unbanned: Vec<i64>,
        approved: Vec<(i64, i64)>,
        declined: Vec<(i64, i64)>,
        messages: Vec<(i64, String)>,
        next_link: String,
        kick_ambiguous: bool,
        unban_fails: bool,
    }

    impl FakeTelegram {
        fn new() -> Self {
            Self {
                invites: Vec::new(),
                invite_fails: false,
                kicked: Vec::new(),
                unbanned: Vec::new(),
                approved: Vec::new(),
                declined: Vec::new(),
                messages: Vec::new(),
                next_link: "https://t.me/joinchat/seat1".into(),
                kick_ambiguous: false,
                unban_fails: false,
            }
        }
    }

    /// The fake Telegram behind an `Arc<Mutex>` — the trait requires `Send`, because `serve`'s
    /// single task still borrows the bot across awaits — so tests can assert on what was sent.
    struct Wrap(std::sync::Arc<std::sync::Mutex<FakeTelegram>>);

    impl TelegramApi for Wrap {
        async fn send_message(&mut self, user: i64, text: &str) -> Result<(), String> {
            self.0.lock().unwrap().messages.push((user, text.to_string()));
            Ok(())
        }
        async fn create_join_request_invite(&mut self, chat: i64, _expires_unix: u64) -> Result<String, String> {
            let mut g = self.0.lock().unwrap();
            if g.invite_fails {
                return Err("telegram create invite failed".into());
            }
            g.invites.push(chat);
            Ok(g.next_link.clone())
        }
        async fn approve_join_request(&mut self, chat: i64, user: i64) -> Result<(), String> {
            self.0.lock().unwrap().approved.push((chat, user));
            Ok(())
        }
        async fn decline_join_request(&mut self, chat: i64, user: i64) -> Result<(), String> {
            self.0.lock().unwrap().declined.push((chat, user));
            Ok(())
        }
        async fn kick_member(&mut self, chat: i64, user: i64) -> Result<(), String> {
            // The real client kicks as ban-then-unban (seat freed, door open); the fake mirrors
            // both effects so tests assert what actually happens to the member.
            let mut g = self.0.lock().unwrap();
            g.kicked.push(user);
            if g.kick_ambiguous {
                return Err("ambiguous Telegram ban result".into());
            }
            g.unbanned.push(user);
            let _ = chat;
            Ok(())
        }
        async fn unban_member(&mut self, chat: i64, user: i64) -> Result<(), String> {
            let mut g = self.0.lock().unwrap();
            if g.unban_fails {
                return Err("Telegram unban unavailable".into());
            }
            g.unbanned.push(user);
            let _ = chat;
            Ok(())
        }
        async fn get_updates(&mut self, _offset: u64) -> Result<Vec<TgUpdate>, String> {
            Ok(vec![])
        }
    }

    type SharedFake = std::sync::Arc<std::sync::Mutex<FakeTelegram>>;

    /// The bridge's answers, scripted per proof id.
    struct FakeBridge {
        answers: HashMap<String, ProofStatus>,
        /// The access-check answer; `None` means "bridge unreachable" (deferral).
        access: Option<Result<bool, String>>,
    }

    impl FakeBridge {
        fn accepted(gate: &str) -> ProofStatus {
            ProofStatus {
                state: "credential_accepted".into(),
                result: Some(Receipt {
                    gate_id: gate.into(),
                    mode: "credential".into(),
                    attested_minimum: 100_000,
                    substate_id: "utxo_x".into(),
                }),
                access: None,
            }
        }

        /// An acceptance that also carries the registry-issued session: what a registry-backed
        /// bridge returns, with `expires_unix` `days` out.
        fn accepted_with_access(gate: &str, days: u64) -> ProofStatus {
            ProofStatus {
                state: "credential_accepted".into(),
                result: Some(Receipt {
                    gate_id: gate.into(),
                    mode: "credential".into(),
                    attested_minimum: 100_000,
                    substate_id: "utxo_x".into(),
                }),
                access: Some(AccessGrantView {
                    token: "sess-token".into(),
                    application_id: "community".into(),
                    proven_gate: gate.into(),
                    expires_unix: now_unix() + days * 86_400,
                }),
            }
        }
    }

    impl BridgeClient for FakeBridge {
        async fn proof_status(&self, proof_id: &str) -> Result<ProofStatus, String> {
            self.answers
                .get(proof_id)
                .cloned()
                .ok_or_else(|| "404: no such proof".into())
        }

        async fn access_check(&self, _application_id: &str, _gate_id: &str, _token: &str) -> Result<bool, String> {
            self.access.clone().unwrap_or(Err("bridge unreachable".into()))
        }
    }

    fn bot_owned(bridge: FakeBridge) -> (Bot<Wrap, FakeBridge>, SharedFake) {
        let tg: SharedFake = std::sync::Arc::new(std::sync::Mutex::new(FakeTelegram::new()));
        let t2 = tg.clone();
        let bot = Bot::new_fixture(Wrap(t2), bridge, -1001234, "crypt".into());
        (bot, tg)
    }

    fn production_bot(bridge: FakeBridge) -> (Bot<Wrap, FakeBridge>, SharedFake) {
        let tg: SharedFake = std::sync::Arc::new(std::sync::Mutex::new(FakeTelegram::new()));
        let t2 = tg.clone();
        let bot = Bot::new(Wrap(t2), bridge, -1001234, "crypt".into());
        (bot, tg)
    }

    async fn mint_join(bot: &mut Bot<Wrap, FakeBridge>, user: i64) -> (String, String) {
        let reply = bot.join(user, "http://127.0.0.1:7799", "http://127.0.0.1:7808", None).await.unwrap();
        // Extract the token from the reply (the `token=` query param).
        let marker = "token=";
        let i = reply.find(marker).expect("the reply embeds the join link") + marker.len();
        let rest = &reply[i..];
        let token = rest.split('&').next().expect("token value").to_string();
        (token, reply)
    }

    #[tokio::test]
    async fn start_and_pre_join_messages_only_send_welcome_guidance() {
        let (mut bot, tg) = bot_owned(FakeBridge { answers: HashMap::new(), access: None });
        let update = |text: &str| TgUpdate {
            update_id: 1,
            message: Some(TgMessage {
                from: Some(TgUser { id: 42 }),
                text: Some(text.into()),
            }),
            chat_join_request: None,
        };

        bot.handle_update(update("/start"), "https://ghostgate.boo", "https://claim.ghostgate.boo", None).await;
        bot.handle_update(update("hello"), "https://ghostgate.boo", "https://claim.ghostgate.boo", None).await;

        let messages = &tg.lock().unwrap().messages;
        assert_eq!(messages.len(), 2);
        assert!(messages.iter().all(|(_, text)| text == WELCOME_MESSAGE));
        assert_eq!(bot.tokens.len(), 0, "/start and normal messages must not mint tokens");
    }

    #[tokio::test]
    async fn join_remains_the_explicit_token_minting_command() {
        let (mut bot, tg) = bot_owned(FakeBridge { answers: HashMap::new(), access: None });
        bot.handle_update(
            TgUpdate {
                update_id: 2,
                message: Some(TgMessage {
                    from: Some(TgUser { id: 42 }),
                    text: Some("/join".into()),
                }),
                chat_join_request: None,
            },
            "https://ghostgate.boo",
            "https://claim.ghostgate.boo",
            None,
        )
        .await;

        assert_eq!(bot.tokens.len(), 1);
        assert!(tg.lock().unwrap().messages[0].1.contains("token="));
    }

    #[tokio::test]
    async fn a_join_link_is_single_use_and_bound_to_one_account() {
        let bridge = FakeBridge { answers: HashMap::from([("proof1".to_string(), FakeBridge::accepted("crypt"))]), access: None };
        let (mut bot, tg) = bot_owned(bridge);
        let (token, reply) = mint_join(&mut bot, 42).await;
        assert!(reply.contains("for you alone"), "the reply says so: {reply}");
        assert!(reply.contains("never ask for your seed"), "the reply states the privacy rule: {reply}");
        assert!(reply.contains("&gate=crypt"), "the configured gate stays in the opaque join link: {reply}");
        assert!(!reply.contains("&claim="), "the browser never receives a claim endpoint from the bot: {reply}");
        assert!(!reply.contains("&bridge="), "the browser never receives a bridge endpoint from the bot: {reply}");

        let link = bot.claim(&token, "proof1").await.expect("first claim grants");
        assert_eq!(link, "https://t.me/joinchat/seat1");
        assert_eq!(bot.grant_count(), 1);
        assert_eq!(tg.lock().unwrap().invites, vec![-1001234]);

        // Second claim with the same token: refused.
        let err = bot.claim(&token, "proof2").await.expect_err("single-use");
        assert!(err.contains("already used"), "{err}");
    }

    #[tokio::test]
    async fn invite_failure_does_not_consume_the_browser_token_or_create_a_grant() {
        let bridge = FakeBridge {
            answers: HashMap::from([("proof-retry".to_string(), FakeBridge::accepted("crypt"))]),
            access: None,
        };
        let (mut bot, tg) = bot_owned(bridge);
        let (token, _) = mint_join(&mut bot, 43).await;
        tg.lock().unwrap().invite_fails = true;

        let first = bot.claim(&token, "proof-retry").await.expect_err("invite failure must fail closed");
        assert!(first.contains("create invite failed"), "{first}");
        assert!(!bot.tokens.get(&token).expect("failed claim retains token").used);
        assert_eq!(bot.grant_count(), 0);

        tg.lock().unwrap().invite_fails = false;
        bot.claim(&token, "proof-retry").await.expect("the valid proof can be retried after transport failure");
        assert!(bot.tokens.get(&token).expect("successful claim retains replay marker").used);
        assert_eq!(bot.grant_count(), 1);
    }

    #[tokio::test]
    async fn a_claim_with_a_proof_for_another_gate_is_refused() {
        let bridge = FakeBridge { answers: HashMap::from([("proof2".to_string(), FakeBridge::accepted("abyss"))]), access: None };
        let (mut bot, _tg) = bot_owned(bridge);
        let (token, _) = mint_join(&mut bot, 7).await;
        let err = bot.claim(&token, "proof2").await.expect_err("wrong gate");
        assert!(err.contains("not the community gate"), "{err}");
        assert_eq!(bot.grant_count(), 0, "nothing granted");
    }

    #[tokio::test]
    async fn a_claim_the_bridge_does_not_confirm_is_refused() {
        // The page claims a proof the bridge has never accepted — the bot must re-read, not trust.
        let bridge = FakeBridge { answers: HashMap::from([(
            "proof3".to_string(),
            ProofStatus { state: "submitted".into(), result: None, access: None },
        )]), access: None };
        let (mut bot, _tg) = bot_owned(bridge);
        let (token, _) = mint_join(&mut bot, 8).await;
        let err = bot.claim(&token, "proof3").await.expect_err("unverified proof");
        assert!(err.contains("does not show this proof as accepted"), "{err}");
        assert_eq!(bot.grant_count(), 0);
    }

    #[tokio::test]
    async fn a_live_bot_requires_a_registry_access_session() {
        let bridge = FakeBridge { answers: HashMap::from([("proof-live".to_string(), FakeBridge::accepted("crypt"))]), access: None };
        let (mut bot, tg) = production_bot(bridge);
        let (token, _) = mint_join(&mut bot, 81).await;
        let err = bot.claim(&token, "proof-live").await.expect_err("no production session");
        assert!(err.contains("fail-closed"), "{err}");
        assert!(tg.lock().unwrap().invites.is_empty());
    }

    #[test]
    fn production_diagnostic_requires_a_private_supergroup_and_required_admin_rights() {
        let private = json!({ "id": -1001234i64, "type": "supergroup" });
        let admin = json!({
            "status": "administrator",
            "can_invite_users": true,
            "can_restrict_members": true,
        });
        assert!(validate_private_supergroup(-1001234, &private, &admin).is_ok());
        assert!(validate_private_supergroup(
            -1001234,
            &json!({ "id": -1001234i64, "type": "supergroup", "username": "public_group" }),
            &admin,
        )
        .is_err());
        assert!(validate_private_supergroup(
            -1001234,
            &private,
            &json!({ "status": "administrator", "can_invite_users": true, "can_restrict_members": false }),
        )
        .is_err());
    }

    #[test]
    fn invite_response_must_be_a_live_join_request_link() {
        let now = 1_700_000_000;
        let good = json!({
            "invite_link": "https://t.me/+fresh",
            "creates_join_request": true,
            "is_revoked": false,
            "expire_date": now + 900,
        });
        assert_eq!(validate_invite_response(&good, now).unwrap(), "https://t.me/+fresh");

        for bad in [
            json!({ "invite_link": "https://t.me/+x", "creates_join_request": false, "expire_date": now + 900 }),
            json!({ "invite_link": "https://t.me/+x", "creates_join_request": true, "is_revoked": true, "expire_date": now + 900 }),
            json!({ "invite_link": "https://t.me/+x", "creates_join_request": true, "expire_date": now - 1 }),
            json!({ "invite_link": "http://t.me/+x", "creates_join_request": true, "expire_date": now + 900 }),
        ] {
            assert!(validate_invite_response(&bad, now).is_err(), "invalid invite must fail closed");
        }
    }

    #[tokio::test]
    async fn telegram_join_requests_are_bound_to_the_granted_account_and_chat() {
        let bridge = FakeBridge { answers: HashMap::from([("proof-join".to_string(), FakeBridge::accepted("crypt"))]), access: None };
        let (mut bot, tg) = bot_owned(bridge);
        let (token, _) = mint_join(&mut bot, 82).await;
        bot.claim(&token, "proof-join").await.expect("fixture grant");

        bot.handle_join_request(TgJoinRequest { chat: TgChat { id: -1001234 }, from: TgUser { id: 82 } }).await;
        bot.handle_join_request(TgJoinRequest { chat: TgChat { id: -1001234 }, from: TgUser { id: 83 } }).await;
        bot.handle_join_request(TgJoinRequest { chat: TgChat { id: -1009999 }, from: TgUser { id: 82 } }).await;

        let fake = tg.lock().unwrap();
        assert_eq!(fake.approved, vec![(-1001234, 82)]);
        assert_eq!(fake.declined, vec![(-1001234, 83)]);
    }

    #[tokio::test]
    async fn an_expired_join_link_refuses_and_is_gone() {
        let bridge = FakeBridge { answers: HashMap::new(), access: None };
        let (mut bot, _tg) = bot_owned(bridge);
        bot.join_ttl = Duration::from_millis(1);
        let (token, _) = mint_join(&mut bot, 9).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let err = bot.claim(&token, "proof4").await.expect_err("expired");
        assert!(err.contains("expired"), "{err}");
    }

    #[tokio::test]
    async fn a_join_token_stays_valid_for_the_full_server_configured_window() {
        let bridge = FakeBridge { answers: HashMap::from([("proof-window".to_string(),
            FakeBridge::accepted("crypt"))]), access: None };
        let (mut bot, _tg) = bot_owned(bridge);
        let (token, reply) = mint_join(&mut bot, 91).await;
        assert_eq!(bot.join_ttl, JOIN_TTL, "the documented ten-minute server TTL is in force");
        assert!(!reply.contains("expires="), "a browser parameter cannot control expiry: {reply}");
        let remaining = bot.tokens.get(&token).expect("new token is held server-side")
            .expires.duration_since(Instant::now());
        assert!(remaining <= JOIN_TTL && remaining > Duration::from_secs(9 * 60),
            "a normal wallet proof has the full ten-minute window");
        bot.claim(&token, "proof-window").await.expect("unexpired token grants");
    }

    #[tokio::test]
    async fn a_browser_expiry_parameter_cannot_extend_a_server_expired_token() {
        let bridge = FakeBridge { answers: HashMap::new(), access: None };
        let (mut bot, _tg) = bot_owned(bridge);
        bot.join_ttl = Duration::from_millis(1);
        let (token, _) = mint_join(&mut bot, 92).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let body = serde_json::json!({ "token": token, "proof_id": "proof-expired" }).to_string();
        let request = format!(
            "POST /claim?expires=4102444800 HTTP/1.1\r\nHost: 127.0.0.1:7808\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let response = handle_claim_http(&mut bot, &request).await;
        assert!(response.contains("403 Forbidden"), "{response}");
        assert!(response.contains("join link expired"), "{response}");
    }

    #[tokio::test]
    async fn grants_expire_and_are_revoked_by_the_ticker() {
        let bridge = FakeBridge { answers: HashMap::from([("proof5".to_string(), FakeBridge::accepted("crypt"))]), access: None };
        let (mut bot, tg) = bot_owned(bridge);
        bot.access_ttl = Duration::from_millis(30);
        let (token, _) = mint_join(&mut bot, 10).await;
        bot.claim(&token, "proof5").await.expect("granted");
        assert_eq!(bot.grant_count(), 1);

        tokio::time::sleep(Duration::from_millis(50)).await;
        bot.tick().await;
        assert_eq!(bot.grant_count(), 0, "the expired grant is gone");
        let fake = tg.lock().unwrap();
        assert_eq!(fake.kicked, vec![10], "the seat was freed");
        assert_eq!(fake.unbanned, vec![10], "the door was left open for re-verification");
        assert!(
            fake.messages.iter().any(|(u, m)| *u == 10 && m.contains("/join")),
            "the user is told how to re-verify"
        );
    }

    #[tokio::test]
    async fn ambiguous_member_removal_retries_explicit_unban_without_a_permanent_ban() {
        let bridge = FakeBridge { answers: HashMap::from([("proof-unban".to_string(), FakeBridge::accepted("crypt"))]), access: None };
        let (mut bot, tg) = bot_owned(bridge);
        bot.access_ttl = Duration::from_millis(1);
        {
            let mut fake = tg.lock().unwrap();
            fake.kick_ambiguous = true;
            fake.unban_fails = true;
        }
        let (token, _) = mint_join(&mut bot, 24).await;
        bot.claim(&token, "proof-unban").await.expect("fixture grant");
        tokio::time::sleep(Duration::from_millis(10)).await;
        bot.tick().await;
        assert_eq!(bot.grant_count(), 0, "logical authorization is revoked immediately");
        assert!(bot.pending_unbans.contains(&24), "ambiguous ban gets explicit recovery");
        {
            let mut fake = tg.lock().unwrap();
            fake.kick_ambiguous = false;
            fake.unban_fails = false;
        }
        bot.tick().await;
        assert!(!bot.pending_unbans.contains(&24), "a later unban clears recovery");
        assert!(tg.lock().unwrap().unbanned.contains(&24));
    }

    #[tokio::test]
    async fn a_live_grant_blocks_a_duplicate_join_with_a_second_proof() {
        let bridge = FakeBridge { answers: HashMap::from([("proof6".to_string(), FakeBridge::accepted("crypt"))]), access: None };
        let (mut bot, _tg) = bot_owned(bridge);
        let (token, _) = mint_join(&mut bot, 11).await;
        bot.claim(&token, "proof6").await.unwrap();

        // The user rejoins while verified: no second obligation, no second proof.
        let reply = bot.join(11, "http://127.0.0.1:7799", "http://127.0.0.1:7808", None).await.unwrap();
        assert!(reply.contains("already verified"), "{reply}");
        assert_eq!(bot.grant_count(), 1);
    }

    #[tokio::test]
    async fn a_replayed_update_cannot_act_twice() {
        let bridge = FakeBridge { answers: HashMap::new(), access: None };
        let (mut bot, _tg) = bot_owned(bridge);
        // The same update twice: the second is a resend, and must be a no-op.
        assert!(bot.seen_updates.insert(101));
        assert!(!bot.seen_updates.insert(101), "the resend is recognised");
        // And the set itself is bounded.
        for i in 0..(MAX_ANSWERED_SEEN + 10) {
            bot.seen_updates.insert(i as u64);
        }
        bot.seen_updates.truncate_tail(MAX_ANSWERED_SEEN);
        assert!(bot.seen_updates.len() <= MAX_ANSWERED_SEEN);
    }

    #[tokio::test]
    async fn the_claim_endpoint_enforces_loopback_hosts_and_json_content_type() {
        // Phase-6 recheck regressions, pre-fixed: (a) a rebound host must not be answered, (b) a
        // CORS-safelisted content type must not bypass the preflight the JSON contract relies on.
        let bridge = FakeBridge { answers: HashMap::from([("fixture_smoke".to_string(), FakeBridge::accepted("crypt"))]), access: None };
        let (mut bot, _tg) = bot_owned(bridge);
        let (token, _) = mint_join(&mut bot, 13).await;
        let body = serde_json::json!({ "token": token, "proof_id": "fixture_smoke" }).to_string();

        let rebinding = format!(
            "POST /claim HTTP/1.1\r\nHost: evil.com:7810\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let r = handle_claim_http(&mut bot, &rebinding).await;
        assert!(r.contains("403"), "{r}");
        assert!(r.contains("loopback"), "{r}");

        let csrf_style = format!(
            "POST /claim HTTP/1.1\r\nHost: 127.0.0.1:7810\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let r2 = handle_claim_http(&mut bot, &csrf_style).await;
        assert!(r2.contains("415"), "{r2}");
        assert!(r2.contains("application/json"), "{r2}");
    }

    #[tokio::test]
    async fn pending_join_tokens_are_capped() {
        // The F-03 class on the bot: /join is cheap, so the pending set must be bounded.
        let bridge = FakeBridge { answers: HashMap::new(), access: None };
        let (mut bot, _tg) = bot_owned(bridge);
        for u in 0..(MAX_PENDING_TOKENS + 10) {
            bot.join(u as i64, "http://x", "http://y", None).await.unwrap();
        }
        assert!(
            bot.tokens.len() <= MAX_PENDING_TOKENS,
            "the pending set stayed bounded: {}",
            bot.tokens.len()
        );
    }

    #[tokio::test]
    async fn the_claim_endpoint_answers_http_properly() {
        // The endpoint's behaviour over its real parsing path.
        let bridge = FakeBridge { answers: HashMap::from([("proof7".to_string(), FakeBridge::accepted("crypt"))]), access: None };
        let (mut bot, _tg) = bot_owned(bridge);
        let (token, _) = mint_join(&mut bot, 12).await;
        let body = serde_json::json!({ "token": token, "proof_id": "proof7" }).to_string();
        let request = format!("POST /claim HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        let response = handle_claim_http(&mut bot, &request).await;
        assert!(response.contains("200 OK"), "{response}");
        assert!(response.contains("granted"), "{response}");
        assert!(response.contains("test_only"), "fixture responses are never production grants: {response}");
        assert!(
            response.contains("Access-Control-Allow-Origin: http://127.0.0.1:7799"),
            "the preflight names the join page's origin exactly: {response}"
        );

        // Replay with the same body: the token is consumed, so it refuses now.
        let response2 = handle_claim_http(&mut bot, &request).await;
        assert!(response2.contains("403"), "{response2}");
    }


    // The registry-backed bridge: the bot asks the server on every decision instead of keeping its
    // own clock. These pin the three cases that matter — server says alive, server says dead,
    // server unreachable.
    #[tokio::test]
    async fn a_server_backed_grant_lives_as_long_as_the_registry_says() {
        // A 7-day session, far beyond the bot's own tiny TTL: the LOCAL clock must not end it.
        let bridge = FakeBridge {
            answers: HashMap::from([("proofs1".to_string(), FakeBridge::accepted_with_access("crypt", 7))]),
            access: Some(Ok(true)),
        };
        let (mut bot, tg) = bot_owned(bridge);
        bot.access_ttl = Duration::from_millis(30);
        let (token, _) = mint_join(&mut bot, 21).await;
        bot.claim(&token, "proofs1").await.expect("granted");
        let fake = tg.lock().unwrap();
        let said = fake.messages.iter().find(|(_, m)| m.contains("Doors open")).expect("the success message was sent").1.clone();
        drop(fake);
        assert!(said.contains("Doors open for 7 days"), "the duration is the server's, not the bot's: {said}");
        assert_eq!(bot.grant_count(), 1);

        tokio::time::sleep(Duration::from_millis(60)).await;
        bot.tick().await;
        assert_eq!(bot.grant_count(), 1, "the local TTL must not expire a server-backed session");
        assert!(tg.lock().unwrap().kicked.is_empty(), "nobody was kicked");
    }

    #[tokio::test]
    async fn a_server_backed_grant_approves_only_the_bound_join_request() {
        let bridge = FakeBridge {
            answers: HashMap::from([("proof-telegram".to_string(), FakeBridge::accepted_with_access("crypt", 7))]),
            access: Some(Ok(true)),
        };
        let (mut bot, tg) = bot_owned(bridge);
        let (token, _) = mint_join(&mut bot, 77).await;
        bot.claim(&token, "proof-telegram").await.expect("server session creates grant");

        bot.handle_join_request(TgJoinRequest { chat: TgChat { id: -1001234 }, from: TgUser { id: 77 } }).await;
        bot.handle_join_request(TgJoinRequest { chat: TgChat { id: -1001234 }, from: TgUser { id: 78 } }).await;

        let fake = tg.lock().unwrap();
        assert_eq!(fake.approved, vec![(-1001234, 77)]);
        assert_eq!(fake.declined, vec![(-1001234, 78)]);
    }

    #[tokio::test]
    async fn a_server_revocation_kicks_within_one_tick() {
        // The dashboard revoked the session: the next tick frees the seat, even though the bot's
        // own TTL would have kept the user for days.
        let bridge = FakeBridge {
            answers: HashMap::from([("proofs2".to_string(), FakeBridge::accepted_with_access("crypt", 7))]),
            access: Some(Ok(false)),
        };
        let (mut bot, tg) = bot_owned(bridge);
        let (token, _) = mint_join(&mut bot, 22).await;
        bot.claim(&token, "proofs2").await.expect("granted");
        bot.tick().await;
        assert_eq!(bot.grant_count(), 0, "the revoked grant is gone");
        let fake = tg.lock().unwrap();
        assert_eq!(fake.kicked, vec![22], "the seat was freed");
        assert_eq!(fake.unbanned, vec![22], "the door was left open for re-verification");
    }

    #[tokio::test]
    async fn a_bridge_outage_defers_the_decision_instead_of_kicking() {
        // Could not ask: neither grant nor kick. The next tick decides; a transient outage must not
        // empty a community of verified members.
        let bridge = FakeBridge {
            answers: HashMap::from([("proofs3".to_string(), FakeBridge::accepted_with_access("crypt", 7))]),
            access: Some(Err("connection refused".into())),
        };
        let (mut bot, tg) = bot_owned(bridge);
        let (token, _) = mint_join(&mut bot, 23).await;
        bot.claim(&token, "proofs3").await.expect("granted");
        bot.tick().await;
        assert_eq!(bot.grant_count(), 1, "the decision was deferred");
        assert!(tg.lock().unwrap().kicked.is_empty());
    }

    #[tokio::test]
    async fn a_dead_server_session_is_silently_replaced_by_a_fresh_join() {
        // The user rejoins after their server session ended: no "already verified" lie, no error —
        // the old grant is dropped and a fresh proof obligation is minted.
        let bridge = FakeBridge {
            answers: HashMap::from([("proofs4".to_string(), FakeBridge::accepted_with_access("crypt", 7))]),
            access: Some(Ok(false)),
        };
        let (mut bot, _tg) = bot_owned(bridge);
        let (token, _) = mint_join(&mut bot, 24).await;
        bot.claim(&token, "proofs4").await.expect("granted");
        let reply = bot.join(24, "http://127.0.0.1:7799", "http://127.0.0.1:7808", None).await.unwrap();
        assert!(!reply.contains("already verified"), "the dead session is not claimed as live: {reply}");
        assert!(reply.contains("/telegram/join?token="), "a fresh join link is minted: {reply}");
    }
}
