//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! Telegram token-gating POC, on the same backend the game and the demo page use.
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
//!                         grant = {user → join-request invite, expires}
//!   ◀─────  invite link
//!      … after ACCESS_TTL …
//!                         ticker: expire tracked grants without changing membership
//! ```
//!
//! # What is enforced here, and where
//!
//! - **Bridge freshness**: the receipt is backed by the bridge's challenge, expiry, policy, and
//!   replay checks. The bot re-reads that receipt instead of trusting a browser verdict.
//! - **Limited tracked duration**: grants carry `ACCESS_TTL` and are expired by the ticker while
//!   this process retains their user-to-session mapping. Existing membership is never removed.
//! - **Server-side verification**: the bot trusts only the bridge's own answer for the proof id —
//!   never the page's claim of what happened. A forged or stale receipt fails the re-read.
//! - **Join-token identity**: one join token = one Telegram account = one claim; a second claim
//!   with the same join token refuses, and a forwarded invite is declined for another account.
//! - **No secrets**: the bot asks for nothing but a proof. Seeds, keys and balances are never
//!   mentioned, let alone requested; the receipt names a floor, not a balance.
//! - **Bot token custody**: `GG_TG_BOT_TOKEN` is read once from the environment and never logged.
//!
//! # What a POC deliberately does not do
//!
//! - Grant state is mostly in-memory.  When `GG_BOT_SESSION_STORE_DIR` is set, the bot
//!   persists admission sessions and unapproved Telegram admissions across restarts.  Grant
//!   records (the `grants` table) remain in-memory; a restart forgets those, but Telegram
//!   membership approved by the previous process persists.  Until durable reconciliation
//!   exists, expiry/revocation cannot be guaranteed across a restart. When the bridge is
//!   REGISTRY-BACKED, the
//!   expiry, revocation and policy-hash decisions live in the registry, not here: the bot asks the
//!   bridge on each tracked decision, and the session is visible (and revocable) next to every
//!   other one. Revocation does not remove existing members. On a legacy bridge, the bot's own
//!   TTL applies exactly as before.
//! - The accepted proof receipt is not yet committed to the bot-minted join token. Someone who
//!   obtains a still-readable accepted proof id can present it with another valid join token. A
//!   production design must bind the join-token commitment into the challenge and receipt.
//! - The bot does not consume `chat_member` updates. Other administrators, manual adds, or old
//!   invite links remain Telegram-side admission paths unless operations remove those powers and
//!   links; code-enforced reconciliation is still required for a production claim.
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
/// Maximum bot-admission sessions held before expiry (per bridge). Prevents unbounded growth on
/// join-request storms exactly as MAX_PENDING_TOKENS bounds the legacy token set.
const MAX_PENDING_BOT_SESSIONS: usize = 512;

// ── HMAC domain constants ─────────────────────────────────────────────────────────────────────
// These MUST match the bridge's bot_session_interface.rs and bot_admission.rs byte-for-byte.
// A mismatch produces an authentication failure at the bridge, not a silent wrong answer.
const BOT_SESSION_DOMAIN: &[u8] = b"ghost-gate/bot-session/v1\0POST\0/v1/bot/sessions\0";
const BOT_REDEEM_DOMAIN: &[u8]  = b"ghost-gate/bot-redeem/v1\0POST\0/v1/bot/sessions/redeem\0";
const WELCOME_MESSAGE: &str = "👻 Welcome to Ghost Gate.\n\nI verify token-gated access for supported Telegram groups without asking for your seed phrase, private keys, or exact wallet balance.\n\nTo verify your access:\n\n1. Request to join the protected Telegram group.\n2. Send me /join.\n3. Open the single-use Ghost Gate verification link I send you.\n4. Connect your wallet and complete the required token proof.\n\nIf your verification succeeds, I'll automatically approve your pending group join request.\n\nTestnet only.";
const RECHECK_INTERVAL: Duration = Duration::from_secs(60);
/// Whether the fixture bridge/telegram pair is in use; set once at startup.
static FIXTURE_POLL_PAUSE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The Telegram account fixture grants bind to.
const FIXTURE_TG_USER: i64 = 42;

// ── Bot-to-bridge admission client ───────────────────────────────────────────────────────────

/// Wire response from `POST /v1/bot/sessions`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct BotSessionCreated {
    pub session_id: String,
    pub expires_unix: u64,
}

/// Wire response from `POST /v1/bot/sessions/redeem`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct BotAdmission {
    pub telegram_user_id: i64,
    pub telegram_chat_id: i64,
    pub gate_id: String,
    pub wallet_output: String,
}

/// One pending admission session, tracking which user and bridge it belongs to.
#[derive(Debug, Clone)]
struct PendingBotSession {
    /// The bridge that issued this session (index into `Bot::admission_bridges`).
    bridge_index: usize,
    telegram_user_id: i64,
    expires: Instant,
    /// Human-readable network label captured at session creation. Stored so the audit
    /// record on redeem reflects the network the session was opened on, even if the bridge
    /// array is reconfigured before the session is consumed.
    network_label: String,
}

/// Serialisable form of `PendingBotSession` for the restart-safety store.
/// `Instant` is not meaningful across restarts; `expires_unix` is seconds since the UNIX epoch.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StoredSession {
    bridge_index: usize,
    telegram_user_id: i64,
    expires_unix: u64,
    /// Network label stored alongside the session so the audit record survives a restart with a
    /// differently-ordered bridge array. `default` accepts old store files that lack this field.
    #[serde(default)]
    network_label: String,
}

/// A bridge admission that completed but whose Telegram `approve_join_request` has not yet
/// confirmed.  Persisted to disk so a transient Telegram failure does not permanently strand
/// a verified user.  Retried on each `tick()`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PendingApproval {
    telegram_user_id: i64,
    telegram_chat_id: i64,
    gate_id: String,
    network_label: String,
    /// How many Telegram calls have been attempted so far (first try is 0 → 1 on first attempt).
    attempt_count: u32,
    /// Unix timestamp of the first bridge redeem, for operator visibility.
    first_seen_unix: u64,
}

/// HMAC-authenticated loopback client for the bridge's bot-only admission routes.
///
/// Each instance is bound to ONE bridge endpoint, ONE bot key, and ONE network. For dual-network
/// operation (testnet + mainnet, same bot + group), hold two instances in `Bot::admission_bridges`.
pub struct BotAdmissionBridge {
    /// The bridge's base URL (always a loopback address in production).
    pub endpoint: String,
    /// 32-byte HMAC key — distinct from all other credential keys.
    bot_key: [u8; 32],
    /// The page path the user opens to verify their wallet (e.g. `/lab` or `/mainnet`).
    page: String,
    /// The gate this bridge's admission is for.
    pub gate_id: String,
    /// 64 hex-char policy hash, bound into every challenge by the bridge.
    pub policy_hash: String,
    /// Human-readable label for audit messages and user-facing links.
    pub network_label: String,
    http: reqwest::Client,
}

impl BotAdmissionBridge {
    pub fn new(
        endpoint: String,
        bot_key: [u8; 32],
        gate_id: String,
        policy_hash: String,
        network_label: String,
        page: String,
    ) -> Self {
        Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            bot_key,
            page,
            gate_id,
            policy_hash,
            network_label,
            http: reqwest::Client::builder()
                .timeout(CLAIM_HTTP_TIMEOUT)
                .build()
                .expect("fixed admission HTTP client"),
        }
    }

    fn sign_body(key: &[u8; 32], domain: &[u8], body: &[u8]) -> String {
        use hmac::Mac;
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key)
            .expect("HMAC accepts any key length");
        mac.update(domain);
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    /// Create a session bound to one Telegram update. The bridge deduplicates on `update_id` so
    /// a resent Telegram update cannot mint a second session for the same user.
    pub async fn create_session(
        &self,
        update_id: u64,
        user_id: i64,
        chat_id: i64,
    ) -> Result<BotSessionCreated, String> {
        let body = serde_json::to_vec(&serde_json::json!({
            "update_id": update_id as i64,
            "telegram_user_id": user_id,
            "telegram_chat_id": chat_id,
            "gate_id": self.gate_id,
            "policy_hash": self.policy_hash,
            "sent_unix": now_unix(),
        }))
        .map_err(|e| e.to_string())?;
        let sig = Self::sign_body(&self.bot_key, BOT_SESSION_DOMAIN, &body);
        let resp = self
            .http
            .post(format!("{}/v1/bot/sessions", self.endpoint))
            .header("Authorization", format!("GG-Bot-HMAC {sig}"))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| format!("bot create_session: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!(
                "bot create_session refused: {}",
                resp.status().as_u16()
            ));
        }
        resp.json::<BotSessionCreated>().await.map_err(|e| e.to_string())
    }

    /// Atomically consume a Verified session and return the admission record.
    ///
    /// The bridge enforces single-use: a second call with the same session_id returns 403.
    pub async fn redeem(&self, session_id: &str) -> Result<BotAdmission, String> {
        let body = serde_json::to_vec(&serde_json::json!({
            "session_id": session_id,
            "sent_unix": now_unix(),
        }))
        .map_err(|e| e.to_string())?;
        let sig = Self::sign_body(&self.bot_key, BOT_REDEEM_DOMAIN, &body);
        let resp = self
            .http
            .post(format!("{}/v1/bot/sessions/redeem", self.endpoint))
            .header("Authorization", format!("GG-Bot-HMAC {sig}"))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| format!("bot redeem: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!(
                "bot redeem refused: {}",
                resp.status().as_u16()
            ));
        }
        resp.json::<BotAdmission>().await.map_err(|e| e.to_string())
    }

    /// Build the verification page URL to send to the user.
    ///
    /// The page must call the bridge's challenge + proof endpoints with this session_id. The bot
    /// never sends the full session_id in a human-visible message — it embeds it in the URL only.
    pub fn verify_url(&self, session_id: &str, join_base: &str) -> String {
        let page = &self.page;
        format!(
            "{}{page}?bot_session={session_id}&gate={}",
            join_base.trim_end_matches('/'),
            urlencode(&self.gate_id)
        )
    }
}

/// The most pending join tokens held at once (audit F-03's class, applied to the bot).
const MAX_PENDING_TOKENS: usize = 512;
const POLL_INTERVAL: u64 = 3; // seconds between getUpdates calls
const MAX_ANSWERED_SEEN: usize = 1024;
const TELEGRAM_HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const CLAIM_HTTP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CLAIM_REQUEST_BYTES: usize = 8 * 1024;

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
    /// Base URL for the Bot API. Defaults to `https://api.telegram.org`.
    /// Overridable for M8 E2E testing via `TelegramBot::with_api_url`, which requires the token
    /// to start with `fixture_` so this cannot be misconfigured in production.
    base_url: String,
}

impl TelegramBot {
    pub fn new(token: &str) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(TELEGRAM_HTTP_TIMEOUT)
                .build()
                .expect("fixed Telegram HTTP client configuration"),
            token: token.to_string(),
            base_url: "https://api.telegram.org".to_string(),
        }
    }

    /// M8 test-only constructor: points the client at a local fixture Telegram server.
    ///
    /// The token MUST start with `fixture_` to prevent accidental production use. A production
    /// token from BotFather never starts with that prefix, so there is no way to misconfigure
    /// a live bot into this mode without an obviously wrong token.
    pub fn with_api_url(token: &str, base_url: &str) -> Self {
        assert!(
            token.starts_with("fixture_"),
            "with_api_url requires a fixture_ token prefix; real bot tokens must use TelegramBot::new"
        );
        Self {
            http: reqwest::Client::builder()
                .timeout(TELEGRAM_HTTP_TIMEOUT)
                .build()
                .expect("fixed Telegram HTTP client configuration"),
            token: token.to_string(),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    async fn call(&self, method: &str, params: &serde_json::Value) -> Result<serde_json::Value, String> {
        let url = format!("{}/bot{}/{}", self.base_url, self.token, method);
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
    /// supergroup and have invite-approval authority. Member removal is not required.
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
        {
            return Err("bot lacks private-supergroup invite approval permission".into());
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
        let url = format!("{}/access/check", self.base);
        let body = serde_json::json!({
            "application": application_id,
            "gate": gate_id,
            "token": token,
        });
        let resp = match self.http.post(&url).json(&body).send().await {
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
    /// IDs already acted on, so a replayed update (Telegram resends on offset races) cannot mint a
    /// second grant.
    seen_updates: std::collections::BTreeSet<u64>,

    // ── M6 bot-admission fields ────────────────────────────────────────────────────────────────
    /// Bot-to-bridge admission clients, one per network. Usually one (Esmeralda) or two
    /// (Esmeralda + mainnet). Empty in fixture/legacy mode: use `fixture_authorization` instead.
    pub admission_bridges: Vec<BotAdmissionBridge>,
    /// Sessions created by `admission_bridges`, awaiting proof verification by the browser.
    /// Maps session_id → pending record. Expired entries are pruned on each `tick()`.
    bot_sessions: HashMap<String, PendingBotSession>,

    // ── M6+ durable state ─────────────────────────────────────────────────────────────────────
    /// Directory for the restart-safety JSON stores.  `None` = in-memory only (tests and dev).
    /// Set from `GG_BOT_SESSION_STORE_DIR` at production startup.
    bot_store_dir: Option<std::path::PathBuf>,
    /// Bridge admissions whose `approve_join_request` has not yet returned success.
    /// Keyed by the opaque bridge session_id.  Retried on every `tick()`.
    pending_approvals: HashMap<String, PendingApproval>,
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
            seen_updates: std::collections::BTreeSet::new(),
            admission_bridges: Vec::new(),
            bot_sessions: HashMap::new(),
            bot_store_dir: None,
            pending_approvals: HashMap::new(),
        }
    }

    fn new_fixture(telegram: T, bridge: B, chat: i64, gate: String) -> Self {
        let mut bot = Self::new(telegram, bridge, chat, gate);
        bot.fixture_authorization = true;
        bot
    }

    // ── M6+ durable-state helpers ──────────────────────────────────────────────────────────────

    /// Load previously-persisted sessions and pending approvals from `bot_store_dir`.
    /// Non-expired sessions are restored to `bot_sessions`; pending approvals to `pending_approvals`.
    /// Call once at production startup, before entering the serve loop.
    pub fn load_stores(&mut self) {
        let Some(dir) = self.bot_store_dir.clone() else { return };
        // Remove any stale .tmp files left by a crash mid-write so they don't confuse readers.
        for name in &["pending_sessions.json.tmp", "pending_approvals.json.tmp"] {
            let p = dir.join(name);
            if p.exists() {
                let _ = std::fs::remove_file(&p);
            }
        }
        let sessions_path = dir.join("pending_sessions.json");
        if let Ok(data) = std::fs::read_to_string(&sessions_path) {
            if let Ok(map) = serde_json::from_str::<HashMap<String, StoredSession>>(&data) {
                let now_secs = now_unix();
                for (id, s) in map {
                    if s.expires_unix > now_secs {
                        let secs_left = s.expires_unix - now_secs;
                        self.bot_sessions.insert(id, PendingBotSession {
                            bridge_index: s.bridge_index,
                            telegram_user_id: s.telegram_user_id,
                            expires: Instant::now() + Duration::from_secs(secs_left),
                            network_label: s.network_label.clone(),
                        });
                    }
                }
                if !self.bot_sessions.is_empty() {
                    eprintln!("ghost-gate-telegram: restored {} pending bot session(s) from disk", self.bot_sessions.len());
                }
            }
        }
        let approvals_path = dir.join("pending_approvals.json");
        if let Ok(data) = std::fs::read_to_string(&approvals_path) {
            if let Ok(map) = serde_json::from_str::<HashMap<String, PendingApproval>>(&data) {
                if !map.is_empty() {
                    eprintln!("ghost-gate-telegram: loaded {} pending Telegram approval(s) from disk", map.len());
                }
                self.pending_approvals = map;
            }
        }
    }

    fn write_sessions_store(&self) {
        let Some(dir) = &self.bot_store_dir else { return };
        let now_secs = now_unix();
        let map: HashMap<&String, StoredSession> = self.bot_sessions.iter()
            .filter_map(|(id, s)| {
                let left = s.expires.saturating_duration_since(Instant::now());
                if left.is_zero() { return None; }
                Some((id, StoredSession {
                    bridge_index: s.bridge_index,
                    telegram_user_id: s.telegram_user_id,
                    expires_unix: now_secs.saturating_add(left.as_secs()),
                    network_label: s.network_label.clone(),
                }))
            })
            .collect();
        if let Ok(data) = serde_json::to_string(&map) {
            atomic_write_json(&dir.join("pending_sessions.json"), &data);
        }
    }

    fn write_approvals_store(&self) {
        let Some(dir) = &self.bot_store_dir else { return };
        if let Ok(data) = serde_json::to_string(&self.pending_approvals) {
            atomic_write_json(&dir.join("pending_approvals.json"), &data);
        }
    }

    /// `/join`: mints a single-use token (or bot-admission session) bound to this Telegram account.
    ///
    /// `update_id` is the Telegram update that triggered this call, used for idempotency at the
    /// bridge. The bridge's deduplication table rejects the same `update_id` twice, so a resent
    /// Telegram update cannot create two sessions for the same user.
    pub async fn join(&mut self, user: i64, update_id: u64, base_url: &str, _claim_base: &str, _bridge_public_url: Option<&str>) -> Result<String, String> {
        // A user rejoining while a grant is live gets told, rather than silently minting a second
        // proof obligation. A server-backed grant is ASKED, not trusted from memory: if the session
        // was revoked or expired while the bot was looking away, the user simply rejoins.
        let existing = self.grants.get(&user).map(|g| (g.server.clone(), g.expires));
        if let Some((server, expires)) = existing {
            let alive = match &server {
                Some(sg) => match self.bridge.access_check(&sg.application_id, &self.gate, &sg.token).await {
                    Ok(alive) => alive,
                    Err(_) => return Err("verification service unavailable; existing state retained".into()),
                },
                None => expires > Instant::now(),
            };
            if alive {
                let left = expires.saturating_duration_since(Instant::now()).as_secs().max(1);
                return Ok(format!(
                    "Your access is already verified for another {} minute(s). I'll ask for a fresh proof when it lapses.",
                    (left + 59) / 60
                ));
            }
            if server.is_some() {
                self.grants.remove(&user);
            }
        }
        // ── M6 admission-bridge path ──────────────────────────────────────────────────────────
        // When admission bridges are configured, create sessions on each bridge (testnet + mainnet)
        // and return link(s) for the user to verify their wallet. Each session is bound to the
        // exact (user, chat, gate, policy_hash, network) tuple at the bridge — no browser-supplied
        // identity can substitute for it.
        if !self.admission_bridges.is_empty() {
            self.bot_sessions.retain(|_, s| s.expires > Instant::now());
            if self.bot_sessions.len() >= MAX_PENDING_BOT_SESSIONS {
                // Evict the entry that expires soonest.
                let oldest_key = self.bot_sessions
                    .iter()
                    .min_by_key(|(_, s)| s.expires)
                    .map(|(k, _)| k.clone());
                if let Some(k) = oldest_key { self.bot_sessions.remove(&k); }
            }
            let mut links: Vec<String> = Vec::new();
            // Collect what each bridge needs before the await so we don't hold a borrow on
            // self.admission_bridges across the await point while also needing &mut self.bot_sessions.
            let bridge_count = self.admission_bridges.len();
            for idx in 0..bridge_count {
                let (result, gate_id, network_label) = {
                    let bridge = &self.admission_bridges[idx];
                    let r = bridge.create_session(update_id, user, self.chat).await;
                    (r, bridge.gate_id.clone(), bridge.network_label.clone())
                };
                match result {
                    Ok(session) => {
                        let ttl = session.expires_unix.saturating_sub(now_unix()).min(600).max(60);
                        let expires = Instant::now() + Duration::from_secs(ttl);
                        audit("BOT_SESSION_CREATED", json!({
                            "flow_id": audit_id(&session.session_id),
                            "telegram_user_id": user,
                            "chat_id": self.chat,
                            "gate_id": gate_id,
                            "network": network_label,
                            "expires_unix": session.expires_unix,
                        }));
                        self.bot_sessions.insert(session.session_id.clone(), PendingBotSession {
                            bridge_index: idx,
                            telegram_user_id: user,
                            expires,
                            network_label: network_label.clone(),
                        });
                        self.write_sessions_store();
                        let url = self.admission_bridges[idx].verify_url(&session.session_id, base_url);
                        links.push(format!("{} verification:\n{}", network_label, url));
                    }
                    Err(e) => {
                        audit("BOT_SESSION_CREATE_FAILED", json!({
                            "telegram_user_id": user,
                            "chat_id": self.chat,
                            "network": network_label,
                            "error_class": error_class(&e),
                        }));
                        eprintln!("ghost-gate-telegram: could not create admission session on {network_label}: {e}");
                    }
                }
            }
            return if links.is_empty() {
                Err("verification service unavailable — please try again shortly".into())
            } else {
                Ok(format!(
                    "To verify wallet access, open one of the following links in the browser where your wallet lives:\n\n{}\n\nEach link is for you alone, works once, and expires shortly. I will never ask for your seed phrase, keys, or exact balance.",
                    links.join("\n\n")
                ))
            };
        }

        // ── Legacy fixture / token-based path ─────────────────────────────────────────────────
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
        // A bridge receipt is not yet bound to a Telegram identity. Do not turn it into a real
        // admission until a durable, single-use identity-bound proof protocol is implemented.
        if !self.fixture_authorization {
            return Err("Telegram admission is temporarily unavailable: identity-bound verification is required".into());
        }
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

    /// Redeem a bot admission session created via the M5 session-based flow.
    ///
    /// The browser POSTs `{bot_session_id}` after the wallet proof completes. The bot looks up
    /// which bridge owns that session, calls `redeem`, and approves the join request via Telegram.
    /// No Telegram identity ever comes from the browser — it comes from the bridge's response.
    pub async fn claim_bot_admission(&mut self, session_id: &str) -> Result<String, String> {
        let flow_id = audit_id(session_id);
        audit("BOT_CLAIM_RECEIVED", json!({ "flow_id": flow_id, "session_id_len": session_id.len() }));

        let entry = self.bot_sessions.get(session_id).ok_or_else(|| {
            audit("BOT_CLAIM_REJECTED", json!({ "flow_id": flow_id, "reason": "unknown_session" }));
            "unknown or already-consumed session"
        })?;
        if entry.expires < Instant::now() {
            self.bot_sessions.remove(session_id);
            audit("BOT_CLAIM_REJECTED", json!({ "flow_id": flow_id, "reason": "expired" }));
            return Err("session expired; use /join to start again".into());
        }
        let bridge_index = entry.bridge_index;
        let expected_user = entry.telegram_user_id;
        // Use the label stored in the session (captured at creation), not the current bridge
        // array position, so audit records are correct after a restart with a different bridge order.
        let network_label = entry.network_label.clone();

        // Extract the bridge result before the await to avoid holding a borrow on
        // self.admission_bridges across the await point.
        let result = {
            let bridge = self.admission_bridges.get(bridge_index).ok_or_else(|| {
                "internal: bridge index out of range".to_string()
            })?;
            bridge.redeem(session_id).await
        };
        let admission = result.map_err(|e| {
            audit("BOT_REDEEM_FAILED", json!({ "flow_id": flow_id, "network": network_label, "error_class": error_class(&e) }));
            format!("bridge could not complete admission: {e}")
        })?;

        // The bridge binds user and chat at session creation; verify nothing changed.
        if admission.telegram_user_id != expected_user {
            audit("BOT_CLAIM_REJECTED", json!({ "flow_id": flow_id, "reason": "user_mismatch" }));
            return Err("session identity mismatch".into());
        }
        if admission.telegram_chat_id != self.chat {
            audit("BOT_CLAIM_REJECTED", json!({ "flow_id": flow_id, "reason": "chat_mismatch",
                "expected_chat": self.chat, "got_chat": admission.telegram_chat_id }));
            return Err("session belongs to a different chat".into());
        }

        audit("BOT_REDEEMED", json!({
            "flow_id": flow_id,
            "telegram_user_id": admission.telegram_user_id,
            "chat_id": self.chat,
            "gate_id": admission.gate_id,
            "network": network_label,
        }));
        // Consume the session before the Telegram call; a double-approve is harmless,
        // but a bridge replay must never open a second session window.
        self.bot_sessions.remove(session_id);
        self.write_sessions_store();

        // Record the admission durably BEFORE calling Telegram: if the network call fails,
        // the record stays in `pending_approvals` and `tick()` retries it automatically.
        // The bridge-side session is already single-use; this cannot cause a second bridge replay.
        self.pending_approvals.insert(session_id.to_string(), PendingApproval {
            telegram_user_id: admission.telegram_user_id,
            telegram_chat_id: admission.telegram_chat_id,
            gate_id: admission.gate_id.clone(),
            network_label: network_label.clone(),
            attempt_count: 0,
            first_seen_unix: now_unix(),
        });
        self.write_approvals_store();

        let result = self.telegram.approve_join_request(self.chat, admission.telegram_user_id).await;
        let approval_ok = result.is_ok();
        audit("TELEGRAM_APPROVAL", json!({
            "flow_id": flow_id,
            "telegram_user_id": admission.telegram_user_id,
            "chat_id": self.chat,
            "success": approval_ok,
            "queued_for_retry": !approval_ok,
            "error_class": result.as_ref().err().map(|e| error_class(e)),
        }));

        if approval_ok {
            // Success: clean up the durable record and send the confirmation DM.
            self.pending_approvals.remove(session_id);
            self.write_approvals_store();
            self.telegram
                .send_message(admission.telegram_user_id, "Wallet verified. Your join request has been approved — welcome to the group.")
                .await
                .ok();
        } else {
            // Telegram temporarily unavailable.  The pending approval is already on disk and
            // `tick()` will retry until Telegram responds.  Return success to the browser anyway:
            // the bridge-side proof is complete and no replay is possible.
            eprintln!(
                "ghost-gate-telegram: Telegram approval queued for retry (user {}, chat {}, attempt 1): {}",
                admission.telegram_user_id, self.chat, result.unwrap_err()
            );
        }
        Ok("approved".into())
    }

    /// Expire tracked grants without modifying existing Telegram membership.
    ///
    /// Runs in one place (the caller's loop) so no two ticks can race the same user's revocation.
    pub async fn tick(&mut self) {
        let now = Instant::now();
        // Tokens whose TTL passed — used or not — are state nobody can act on any more.
        self.tokens.retain(|_, t| t.expires > now);
        // Admission sessions that expired are state nobody can act on any more.
        let sessions_before = self.bot_sessions.len();
        self.bot_sessions.retain(|_, s| s.expires > now);
        if self.bot_sessions.len() < sessions_before {
            self.write_sessions_store();
        }

        // Retry any pending Telegram approvals (from bridge redeems where approve_join_request
        // failed transiently).  `approve_join_request` is idempotent — a second call for a user
        // who already joined is a no-op.  After 24 h of retries, log a warning and stop.
        if !self.pending_approvals.is_empty() {
            let ids: Vec<String> = self.pending_approvals.keys().cloned().collect();
            let mut approved: Vec<String> = Vec::new();
            let mut store_changed = false;
            const MAX_ATTEMPTS: u32 = 1440; // ~24 h at 60-second ticks
            for id in ids {
                // Extract all fields and update attempt_count in one block so the mutable borrow
                // drops before the await.
                let (attempt, user_id, chat_id, network_label, gate_id, first_seen) = {
                    let Some(approval) = self.pending_approvals.get_mut(&id) else { continue };
                    approval.attempt_count += 1;
                    (approval.attempt_count, approval.telegram_user_id, approval.telegram_chat_id,
                     approval.network_label.clone(), approval.gate_id.clone(), approval.first_seen_unix)
                };
                store_changed = true; // attempt_count changed regardless of Telegram result
                if attempt > MAX_ATTEMPTS {
                    eprintln!(
                        "ghost-gate-telegram: pending approval for user {} (gate {}, {}) abandoned after {} attempts (first seen unix {}); operator review required",
                        user_id, gate_id, network_label, attempt, first_seen
                    );
                    approved.push(id.clone()); // remove from map to stop logging every tick
                    continue;
                }
                let result = self.telegram.approve_join_request(chat_id, user_id).await;
                if result.is_ok() {
                    self.telegram
                        .send_message(user_id, "Wallet verified. Your join request has been approved — welcome to the group.")
                        .await
                        .ok();
                    approved.push(id);
                }
            }
            for id in &approved {
                self.pending_approvals.remove(id);
            }
            if store_changed {
                self.write_approvals_store();
            }
        }
        // Legacy grants (no server session) expire on the bot's clock, as before. Server-backed
        // grants are ASKED: the registry's expiry, revocation and policy-hash checks are the
        // authority for tracked grants; revocation does not change Telegram membership.
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
            // Membership is intentionally preserved even when authorization expires.
            self.telegram
                .send_message(
                    user,
                    "Your verification expired. Your existing group membership has not been changed.",
                )
                .await
                .ok();
            let _ = grant;
        }
        self.seen_updates.truncate_tail(MAX_ANSWERED_SEEN);
    }

    /// Acts on one update: commands and no-op resends.
    pub async fn handle_update(&mut self, update: TgUpdate, base_url: &str, claim_base: &str, bridge_public_url: Option<&str>) {
        let update_id = update.update_id;
        if let Some(request) = update.chat_join_request {
            self.handle_join_request(request, update_id).await;
            return;
        }
        let Some(message) = update.message.clone() else { return };
        let Some(user) = message.from.as_ref().map(|f| f.id) else { return };
        let text = message.text.clone().unwrap_or_default();
        if text.starts_with("/join") {
            // When admission bridges are configured, /join is always available.
            // Legacy fixture-only gate: guard still applies when no bridges are set up.
            if self.admission_bridges.is_empty() && !self.fixture_authorization {
                self.telegram.send_message(user, "Telegram verification is temporarily unavailable. Existing group membership is unchanged.").await.ok();
                return;
            }
            if let Ok(reply) = self.join(user, update_id, base_url, claim_base, bridge_public_url).await {
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
    async fn handle_join_request(&mut self, request: TgJoinRequest, _update_id: u64) {
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
        let authorized = self.fixture_authorization && match grant {
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

/// Write `data` to `path` atomically: write to a `.tmp` sibling, fsync, then rename.
/// Sets file permissions to 0o600 on Unix so session state is not world-readable.
/// Syncs the parent directory entry after rename for durability on Linux ext4/xfs.
/// Silently ignores failures — the in-memory state is always authoritative.
fn atomic_write_json(path: &std::path::Path, data: &str) {
    use std::io::Write as _;
    let tmp = path.with_extension("json.tmp");
    let write_result = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(data.as_bytes())?;
        f.sync_all()?; // flush data + metadata to storage before rename
        Ok(())
    })();
    if write_result.is_ok() {
        if std::fs::rename(&tmp, path).is_ok() {
            // Sync parent directory so the rename (new directory entry) is durable.
            #[cfg(unix)]
            if let Some(parent) = path.parent() {
                if let Ok(dir) = std::fs::File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
        }
    }
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
        // M8 HTTP fixture mode: GG_TG_FIXTURE=1 + token starting with "fixture_".
        // The fixture_ prefix is the safety check that prevents a real BotFather token from
        // accidentally routing to a local fixture server via GG_TG_API_URL.
        (true, Ok(t)) if t.trim().starts_with("fixture_") => t.trim().to_string(),
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

    // Three arms for three distinct startup modes. The fixture and real bots are different types
    // (the clients are type parameters, never trait objects), so each path returns independently.
    if fixture {
        // M8: HTTP fixture mode — real bot process, simulated Telegram API, real bridge.
        // Activated when GG_TG_FIXTURE=1 AND GG_TG_API_URL is set AND token starts with "fixture_".
        let api_url = std::env::var("GG_TG_API_URL").ok().filter(|v| !v.trim().is_empty());
        if let Some(ref api_base) = api_url {
            if !token.starts_with("fixture_") {
                eprintln!(
                    "ghost-gate-telegram: GG_TG_API_URL requires GG_TG_BOT_TOKEN to start with \
                     'fixture_' — this prevents a production token from routing to the fixture server"
                );
                return 1;
            }
            let test_chat = match std::env::var("GG_TG_FIXTURE_TEST_CHAT_ID")
                .ok()
                .and_then(|v| v.parse::<i64>().ok())
            {
                Some(v) if v == chat => v,
                _ => {
                    eprintln!(
                        "ghost-gate-telegram: HTTP fixture mode requires GG_TG_FIXTURE_TEST_CHAT_ID \
                         to equal GG_TG_CHAT_ID; no real Telegram membership is ever changed"
                    );
                    return 1;
                }
            };
            let mut bridges = configure_admission_bridges();
            if bridges.is_empty() {
                eprintln!(
                    "ghost-gate-telegram: HTTP fixture mode requires at least one admission bridge \
                     (GG_BOT_ESMERALDA_BRIDGE / GG_BOT_MAINNET_BRIDGE)"
                );
                return 1;
            }
            let store_dir_val = std::env::var("GG_BOT_SESSION_STORE_DIR").unwrap_or_default();
            let store_dir_trimmed = store_dir_val.trim();
            if store_dir_trimmed.is_empty() {
                eprintln!(
                    "ghost-gate-telegram: GG_BOT_SESSION_STORE_DIR is required in HTTP fixture mode \
                     so that restart-safety tests can verify session persistence"
                );
                return 1;
            }
            let dir = std::path::PathBuf::from(store_dir_trimmed);
            if let Err(e) = std::fs::create_dir_all(&dir) {
                eprintln!(
                    "ghost-gate-telegram: cannot create session store dir {}: {e}",
                    dir.display()
                );
                return 1;
            }
            eprintln!(
                "ghost-gate-telegram: HTTP FIXTURE MODE — real bot binary, simulated Telegram API \
                 at {api_base}, {} bridge(s): {}",
                bridges.len(),
                bridges.iter().map(|b| b.network_label.as_str()).collect::<Vec<_>>().join(", ")
            );
            let telegram = TelegramBot::with_api_url(&token, api_base);
            let mut bot = Bot::new(telegram, HttpBridge::new(&bridge), test_chat, gate.clone());
            bot.admission_bridges.append(&mut bridges);
            bot.bot_store_dir = Some(dir);
            bot.load_stores();
            return serve(bot, &bridge_base, &format!("http://127.0.0.1:{claim_port}"), claim_port, &gate, bridge_public_url.as_deref()).await;
        }

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
            .join(FIXTURE_TG_USER, 0, &bridge_base, &format!("http://127.0.0.1:{claim_port}"), bridge_public_url.as_deref())
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
        let mut bot = Bot::new_fixture(
            telegram,
            FixtureBridge { gate: gate.clone(), access_authorized: None },
            test_chat,
            gate.clone(),
        );
        // Fixture authorization must never approve a real Telegram join request.
        bot.fixture_authorization = false;
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

    // M6 production path: build admission bridges from env vars and launch.
    // GG_BOT_ESMERALDA_BRIDGE / GG_BOT_MAINNET_BRIDGE control which networks are live.
    // A network with any missing var is skipped — only those with a complete config are active.
    let mut bridges = configure_admission_bridges();
    if bridges.is_empty() {
        eprintln!(
            "ghost-gate-telegram: production admission is disabled: the Stage 5 consensus trust bootstrap is not independently authenticated"
        );
        return 1;
    }
    eprintln!(
        "ghost-gate-telegram: PRODUCTION M6 — {} admission network(s) configured: {}",
        bridges.len(),
        bridges.iter().map(|b| b.network_label.as_str()).collect::<Vec<_>>().join(", ")
    );
    let mut bot = Bot::new(
        telegram,
        HttpBridge::new(&bridge),
        chat,
        gate.clone(),
    );
    bot.admission_bridges.append(&mut bridges);
    // Durable state is MANDATORY when production admission bridges are active.
    // A missing, empty, or unwritable store dir is a hard failure — admission must not run
    // without durable state because pending sessions and approvals would be lost on restart.
    let store_dir_val = std::env::var("GG_BOT_SESSION_STORE_DIR").unwrap_or_default();
    let store_dir_trimmed = store_dir_val.trim();
    if store_dir_trimmed.is_empty() {
        eprintln!("ghost-gate-telegram: GG_BOT_SESSION_STORE_DIR is required when admission bridges are configured; refusing to start");
        return 1;
    }
    let dir = std::path::PathBuf::from(store_dir_trimmed);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("ghost-gate-telegram: cannot create session store dir {}: {e}; refusing to start", dir.display());
        return 1;
    }
    // Verify the directory is actually writable by touching a probe file.
    let probe = dir.join(".write-probe");
    match std::fs::write(&probe, b"probe") {
        Ok(_) => { let _ = std::fs::remove_file(&probe); }
        Err(e) => {
            eprintln!("ghost-gate-telegram: session store dir {} is not writable: {e}; refusing to start", dir.display());
            return 1;
        }
    }
    eprintln!("ghost-gate-telegram: durable session store: {}", dir.display());
    bot.bot_store_dir = Some(dir);
    bot.load_stores();
    serve(bot, &bridge_base, &format!("http://127.0.0.1:{claim_port}"), claim_port, &gate, bridge_public_url.as_deref()).await
}

/// Build `BotAdmissionBridge` instances from environment variables.
///
/// Each network requires a complete set of vars. Missing or empty any single field skips that
/// network — a partial config never starts a half-wired bridge.
fn configure_admission_bridges() -> Vec<BotAdmissionBridge> {
    let mut bridges: Vec<BotAdmissionBridge> = Vec::new();
    for (prefix, label, page) in &[
        ("GG_BOT_ESMERALDA", "Esmeralda testnet", "/lab"),
        ("GG_BOT_MAINNET",   "Tari mainnet",      "/mainnet"),
    ] {
        let key_hex  = std::env::var(format!("{prefix}_KEY")).unwrap_or_default();
        let endpoint = std::env::var(format!("{prefix}_BRIDGE")).unwrap_or_default();
        let gate_id  = std::env::var(format!("{prefix}_GATE_ID")).unwrap_or_default();
        let ph       = std::env::var(format!("{prefix}_POLICY_HASH")).unwrap_or_default();
        if [&key_hex, &endpoint, &gate_id, &ph].iter().any(|v| v.trim().is_empty()) {
            continue;
        }
        let key_bytes = match hex::decode(key_hex.trim()) {
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            }
            Ok(_) => {
                eprintln!("ghost-gate-telegram: {prefix}_KEY must be 32 bytes (64 hex chars); skipping {label}");
                continue;
            }
            Err(e) => {
                eprintln!("ghost-gate-telegram: {prefix}_KEY is not valid hex: {e}; skipping {label}");
                continue;
            }
        };
        bridges.push(BotAdmissionBridge::new(
            endpoint.trim().to_string(),
            key_bytes,
            gate_id.trim().to_string(),
            ph.trim().to_string(),
            label.to_string(),
            page.to_string(),
        ));
        eprintln!("ghost-gate-telegram: admission bridge configured: {label} at {}", endpoint.trim());
    }
    bridges
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
                        let mut buf = vec![0u8; MAX_CLAIM_REQUEST_BYTES + 1];
                        let n: usize = match tokio::time::timeout(CLAIM_HTTP_TIMEOUT, socket.read(&mut buf)).await {
                            Ok(Ok(n)) => n,
                            _ => 0,
                        };
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
    handle_claim_http_for_origin(bot, raw, allowed_origin.trim_end_matches('/')).await
}

fn claim_http_response(status: &str, body: &str, allowed_origin: &str) -> String {
    let content_type = if body.is_empty() { "" } else { "Content-Type: application/json\r\n" };
    format!(
        "HTTP/1.1 {status}\r\n{content_type}Content-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nAccess-Control-Allow-Origin: {allowed_origin}\r\nAccess-Control-Allow-Methods: POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nVary: Origin\r\n\r\n{body}",
        body.len()
    )
}

fn is_loopback_host(value: &str) -> bool {
    let value = value.trim().to_ascii_lowercase();
    if matches!(value.as_str(), "127.0.0.1" | "localhost" | "[::1]" | "::1") {
        return true;
    }
    if let Some(rest) = value.strip_prefix('[') {
        return rest.split_once(']').is_some_and(|(host, suffix)| {
            host == "::1"
                && suffix.strip_prefix(':').is_some_and(|port| {
                    !port.is_empty() && port.chars().all(|c| c.is_ascii_digit())
                })
        });
    }
    value.rsplit_once(':').is_some_and(|(host, port)| {
        matches!(host, "127.0.0.1" | "localhost")
            && !port.is_empty()
            && port.chars().all(|c| c.is_ascii_digit())
    })
}

async fn handle_claim_http_for_origin<T: TelegramApi, B: BridgeClient>(
    bot: &mut Bot<T, B>,
    raw: &str,
    allowed_origin: &str,
) -> String {
    if raw.len() > MAX_CLAIM_REQUEST_BYTES {
        return claim_http_response(
            "413 Content Too Large",
            &json!({ "error": "claim request too large" }).to_string(),
            allowed_origin,
        );
    }

    let mut lines = raw.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or("");
    let target = request_parts.next().unwrap_or("");
    let mut content_type: Option<String> = None;
    let mut host: Option<String> = None;
    let mut origin: Option<String> = None;
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
            } else if name.eq_ignore_ascii_case("origin") {
                origin = Some(v.to_string());
            }
        }
    }
    // Host: only loopback spellings, like the bridge.
    if !host.as_deref().is_some_and(is_loopback_host) {
        return claim_http_response(
            "403 Forbidden",
            &json!({ "error": "this claim endpoint answers only for loopback hosts" }).to_string(),
            allowed_origin,
        );
    }
    if target.split('?').next() != Some("/claim") {
        return claim_http_response(
            "404 Not Found",
            &json!({ "error": "claim endpoint not found" }).to_string(),
            allowed_origin,
        );
    }
    if origin.as_deref() != Some(allowed_origin) {
        return claim_http_response(
            "403 Forbidden",
            &json!({ "error": "claim origin not allowed" }).to_string(),
            allowed_origin,
        );
    }

    if method == "OPTIONS" {
        return claim_http_response("204 No Content", "", allowed_origin);
    }
    if method != "POST" {
        return claim_http_response("405 Method Not Allowed", "", allowed_origin);
    }
    // The declared media type must be JSON: a safelisted type would have skipped the preflight
    // that this endpoint's CORS otherwise gates.
    let json_content_type = content_type.as_deref().is_some_and(|ct| {
        ct.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("application/json")
    });
    if !json_content_type {
        return claim_http_response(
            "415 Unsupported Media Type",
            &json!({ "error": "claims must be application/json" }).to_string(),
            allowed_origin,
        );
    }
    let body = raw.split_once("\r\n\r\n").map(|(_, body)| body).unwrap_or("");
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(body);
    let Some(body) = parsed.ok() else {
        return claim_http_response(
            "400 Bad Request",
            &json!({ "error": "malformed claim body" }).to_string(),
            allowed_origin,
        );
    };
    // M5 admission-bridge claim: browser posts `{bot_session_id}` after the wallet proof.
    if let Some(session_id) = body["bot_session_id"].as_str() {
        if session_id.is_empty() {
            return claim_http_response(
                "400 Bad Request",
                &json!({ "error": "bot_session_id must not be empty" }).to_string(),
                allowed_origin,
            );
        }
        return match bot.claim_bot_admission(session_id).await {
            Ok(_) => {
                let payload = json!({ "state": "granted", "admission": "production", "at": now_unix() }).to_string();
                claim_http_response("200 OK", &payload, allowed_origin)
            },
            Err(e) => {
                let payload = json!({ "state": "refused", "error": e }).to_string();
                claim_http_response("403 Forbidden", &payload, allowed_origin)
            },
        };
    }

    // Legacy / fixture claim: browser posts `{token, proof_id}`.
    let token = body["token"].as_str().unwrap_or("").to_string();
    let proof_id = body["proof_id"].as_str().unwrap_or("").to_string();
    if token.is_empty() || proof_id.is_empty() {
        return claim_http_response(
            "400 Bad Request",
            &json!({ "error": "token and proof_id required" }).to_string(),
            allowed_origin,
        );
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
            claim_http_response("200 OK", &payload, allowed_origin)
        },
        Err(e) => {
            let payload = json!({ "state": "refused", "error": e }).to_string();
            claim_http_response("403 Forbidden", &payload, allowed_origin)
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records what the bot would send.
    struct FakeTelegram {
        members: std::collections::BTreeSet<i64>,
        invites: Vec<i64>,
        invite_fails: bool,
        approve_fails: bool,
        kicked: Vec<i64>,
        unbanned: Vec<i64>,
        approved: Vec<(i64, i64)>,
        declined: Vec<(i64, i64)>,
        messages: Vec<(i64, String)>,
        next_link: String,
    }

    impl FakeTelegram {
        fn new() -> Self {
            Self {
                members: std::collections::BTreeSet::new(),
                invites: Vec::new(),
                invite_fails: false,
                approve_fails: false,
                kicked: Vec::new(),
                unbanned: Vec::new(),
                approved: Vec::new(),
                declined: Vec::new(),
                messages: Vec::new(),
                next_link: "https://t.me/joinchat/seat1".into(),
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
            let mut g = self.0.lock().unwrap();
            if g.approve_fails {
                return Err("telegram approve_join_request failed (injected test failure)".into());
            }
            g.approved.push((chat, user));
            g.members.insert(user);
            Ok(())
        }
        async fn decline_join_request(&mut self, chat: i64, user: i64) -> Result<(), String> {
            self.0.lock().unwrap().declined.push((chat, user));
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
        let reply = bot.join(user, 0, "http://127.0.0.1:7799", "http://127.0.0.1:7808", None).await.unwrap();
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
    async fn real_join_command_does_not_issue_an_unusable_link() {
        let (mut bot, tg) = production_bot(FakeBridge { answers: HashMap::new(), access: None });
        bot.handle_update(
            TgUpdate { update_id: 2, message: Some(TgMessage {
                from: Some(TgUser { id: 42 }), text: Some("/join".into()),
            }), chat_join_request: None },
            "https://ghostgate.boo", "https://claim.ghostgate.boo", None,
        ).await;
        assert!(bot.tokens.is_empty());
        let messages = &tg.lock().unwrap().messages;
        assert!(messages[0].1.contains("temporarily unavailable"));
        assert!(!messages[0].1.contains("token="));
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
        assert!(err.contains("identity-bound verification"), "{err}");
        assert!(tg.lock().unwrap().invites.is_empty());
    }

    #[tokio::test]
    async fn real_admission_fails_closed_even_with_an_accepted_unbound_receipt() {
        let bridge = FakeBridge {
            answers: HashMap::from([("shared-proof".to_string(), FakeBridge::accepted_with_access("crypt", 7))]),
            access: Some(Ok(true)),
        };
        let (mut bot, tg) = production_bot(bridge);
        let (first, _) = mint_join(&mut bot, 81).await;
        let (second, _) = mint_join(&mut bot, 82).await;
        for token in [&first, &second] {
            assert!(bot.claim(token, "shared-proof").await.unwrap_err().contains("identity-bound"));
        }
        assert_eq!(bot.grant_count(), 0);
        assert!(tg.lock().unwrap().invites.is_empty());
    }

    #[tokio::test]
    async fn restart_and_legacy_grant_do_not_approve_or_remove_members() {
        let bridge = FakeBridge { answers: HashMap::new(), access: Some(Ok(true)) };
        let (mut bot, tg) = production_bot(bridge);
        let original_members = std::collections::BTreeSet::from([81, 82, 83]);
        tg.lock().unwrap().members = original_members.clone();
        // Even if legacy in-memory state is present, it has no identity-bound proof.
        bot.grants.insert(81, Grant {
            expires: Instant::now() + Duration::from_secs(60),
            flow_id: "legacy".into(),
            server: Some(ServerGrant { token: "legacy".into(), application_id: "crypt".into(), expires_unix: now_unix() + 60 }),
        });
        bot.handle_join_request(TgJoinRequest { chat: TgChat { id: -1001234 }, from: TgUser { id: 81 } }, 0).await;
        // Simulate process replacement while retaining Telegram's independent membership state.
        let bridge = FakeBridge { answers: HashMap::new(), access: None };
        let mut restarted = Bot::new(Wrap(tg.clone()), bridge, -1001234, "crypt".into());
        restarted.handle_join_request(TgJoinRequest { chat: TgChat { id: -1001234 }, from: TgUser { id: 82 } }, 0).await;
        restarted.tick().await;
        let fake = tg.lock().unwrap();
        assert_eq!(fake.members, original_members);
        assert!(fake.approved.is_empty());
        assert!(fake.kicked.is_empty());
        assert!(fake.unbanned.is_empty());
        assert_eq!(fake.declined, vec![(-1001234, 81), (-1001234, 82)]);
    }

    #[tokio::test]
    async fn returning_user_bridge_outage_preserves_tracked_grant() {
        let bridge = FakeBridge { answers: HashMap::new(), access: Some(Err("offline".into())) };
        let (mut bot, _) = production_bot(bridge);
        bot.grants.insert(81, Grant {
            expires: Instant::now() + Duration::from_secs(60),
            flow_id: "legacy".into(),
            server: Some(ServerGrant { token: "legacy".into(), application_id: "crypt".into(), expires_unix: now_unix() + 60 }),
        });
        assert!(bot.join(81, 0, "http://localhost", "http://localhost", None).await.is_err());
        assert!(bot.grants.contains_key(&81));
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
        ).is_ok());
        assert!(validate_private_supergroup(
            -1001234,
            &private,
            &json!({ "status": "administrator", "can_invite_users": false }),
        ).is_err());
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

        bot.handle_join_request(TgJoinRequest { chat: TgChat { id: -1001234 }, from: TgUser { id: 82 } }, 0).await;
        bot.handle_join_request(TgJoinRequest { chat: TgChat { id: -1001234 }, from: TgUser { id: 83 } }, 0).await;
        bot.handle_join_request(TgJoinRequest { chat: TgChat { id: -1009999 }, from: TgUser { id: 82 } }, 0).await;

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
            "POST /claim?expires=4102444800 HTTP/1.1\r\nHost: 127.0.0.1:7808\r\nOrigin: http://127.0.0.1:7799\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let response = handle_claim_http_for_origin(&mut bot, &request, "http://127.0.0.1:7799").await;
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
        assert!(fake.kicked.is_empty(), "existing membership is preserved");
        assert!(fake.unbanned.is_empty(), "membership is not modified");
        assert!(
            fake.messages.iter().any(|(u, m)| *u == 10 && m.contains("membership has not been changed")),
            "the user is told that membership is preserved"
        );
    }

    #[tokio::test]
    async fn expired_authorizations_never_trigger_member_removal() {
        let bridge = FakeBridge { answers: HashMap::from([("proof-unban".to_string(), FakeBridge::accepted("crypt"))]), access: None };
        let (mut bot, tg) = bot_owned(bridge);
        bot.access_ttl = Duration::from_millis(1);
        let (token, _) = mint_join(&mut bot, 24).await;
        bot.claim(&token, "proof-unban").await.expect("fixture grant");
        tokio::time::sleep(Duration::from_millis(10)).await;
        bot.tick().await;
        assert_eq!(bot.grant_count(), 0, "logical authorization is revoked immediately");
        bot.tick().await;
        let fake = tg.lock().unwrap();
        assert!(fake.kicked.is_empty());
        assert!(fake.unbanned.is_empty());
    }

    #[tokio::test]
    async fn a_live_grant_blocks_a_duplicate_join_with_a_second_proof() {
        let bridge = FakeBridge { answers: HashMap::from([("proof6".to_string(), FakeBridge::accepted("crypt"))]), access: None };
        let (mut bot, _tg) = bot_owned(bridge);
        let (token, _) = mint_join(&mut bot, 11).await;
        bot.claim(&token, "proof6").await.unwrap();

        // The user rejoins while verified: no second obligation, no second proof.
        let reply = bot.join(11, 0, "http://127.0.0.1:7799", "http://127.0.0.1:7808", None).await.unwrap();
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
    async fn the_claim_endpoint_enforces_request_boundaries() {
        // Phase-6 recheck regressions, pre-fixed: (a) a rebound host must not be answered, (b) a
        // CORS-safelisted content type must not bypass the preflight the JSON contract relies on.
        let bridge = FakeBridge { answers: HashMap::from([("fixture_smoke".to_string(), FakeBridge::accepted("crypt"))]), access: None };
        let (mut bot, _tg) = bot_owned(bridge);
        let (token, _) = mint_join(&mut bot, 13).await;
        let body = serde_json::json!({ "token": token, "proof_id": "fixture_smoke" }).to_string();

        let rebinding = format!(
            "POST /claim HTTP/1.1\r\nHost: evil.com\r\nOrigin: http://127.0.0.1:7799\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let r = handle_claim_http_for_origin(&mut bot, &rebinding, "http://127.0.0.1:7799").await;
        assert!(r.contains("403"), "{r}");
        assert!(r.contains("loopback"), "{r}");

        let csrf_style = format!(
            "POST /claim HTTP/1.1\r\nHost: 127.0.0.1:7810\r\nOrigin: http://127.0.0.1:7799\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let r2 = handle_claim_http_for_origin(&mut bot, &csrf_style, "http://127.0.0.1:7799").await;
        assert!(r2.contains("415"), "{r2}");
        assert!(r2.contains("application/json"), "{r2}");

        let missing_type = format!(
            "POST /claim HTTP/1.1\r\nHost: localhost\r\nOrigin: http://127.0.0.1:7799\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let r3 = handle_claim_http_for_origin(&mut bot, &missing_type, "http://127.0.0.1:7799").await;
        assert!(r3.contains("415"), "{r3}");

        let wrong_origin = format!(
            "POST /claim HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://evil.example\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let r4 = handle_claim_http_for_origin(&mut bot, &wrong_origin, "http://127.0.0.1:7799").await;
        assert!(r4.contains("403"), "{r4}");
        assert!(r4.contains("origin"), "{r4}");

        let missing_origin = format!(
            "POST /claim HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let r5 = handle_claim_http_for_origin(&mut bot, &missing_origin, "http://127.0.0.1:7799").await;
        assert!(r5.contains("403"), "{r5}");
        assert!(r5.contains("origin"), "{r5}");

        let wrong_path = format!(
            "POST /other HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://127.0.0.1:7799\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let r6 = handle_claim_http_for_origin(&mut bot, &wrong_path, "http://127.0.0.1:7799").await;
        assert!(r6.contains("404"), "{r6}");
    }

    #[tokio::test]
    async fn pending_join_tokens_are_capped() {
        // The F-03 class on the bot: /join is cheap, so the pending set must be bounded.
        let bridge = FakeBridge { answers: HashMap::new(), access: None };
        let (mut bot, _tg) = bot_owned(bridge);
        for u in 0..(MAX_PENDING_TOKENS + 10) {
            bot.join(u as i64, u as u64, "http://x", "http://y", None).await.unwrap();
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
        let request = format!("POST /claim HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://127.0.0.1:7799\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        let response = handle_claim_http_for_origin(&mut bot, &request, "http://127.0.0.1:7799").await;
        assert!(response.contains("200 OK"), "{response}");
        assert!(response.contains("granted"), "{response}");
        assert!(response.contains("test_only"), "fixture responses are never production grants: {response}");
        assert!(
            response.contains("Access-Control-Allow-Origin: http://127.0.0.1:7799"),
            "the preflight names the join page's origin exactly: {response}"
        );
        assert!(response.contains("Cache-Control: no-store"), "claim responses are not cacheable: {response}");
        assert!(response.contains("X-Content-Type-Options: nosniff"), "claim responses disable sniffing: {response}");

        // Replay with the same body: the token is consumed, so it refuses now.
        let response2 = handle_claim_http_for_origin(&mut bot, &request, "http://127.0.0.1:7799").await;
        assert!(response2.contains("403"), "{response2}");
    }

    #[tokio::test]
    async fn access_checks_keep_the_bearer_out_of_the_request_target() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let read = socket.read(&mut chunk).await.unwrap();
                assert!(read > 0, "client closed before sending a complete request");
                request.extend_from_slice(&chunk[..read]);
                let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n") else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| line.split_once(':').filter(|(name, _)| name.eq_ignore_ascii_case("content-length")))
                    .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if request.len() >= header_end + 4 + content_length {
                    break;
                }
            }
            let body = r#"{"authorized":true}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8(request).unwrap()
        });

        let bridge = HttpBridge::new(&format!("http://{address}"));
        assert!(bridge.access_check("Crypt", "Crypt", "session-secret").await.unwrap());
        let request = server.await.unwrap();
        assert_eq!(request.lines().next(), Some("POST /access/check HTTP/1.1"));
        assert!(!request.lines().next().unwrap().contains("session-secret"));
        let body = request.split_once("\r\n\r\n").unwrap().1;
        let json: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(json["application"], "Crypt");
        assert_eq!(json["gate"], "Crypt");
        assert_eq!(json["token"], "session-secret");
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

        bot.handle_join_request(TgJoinRequest { chat: TgChat { id: -1001234 }, from: TgUser { id: 77 } }, 0).await;
        bot.handle_join_request(TgJoinRequest { chat: TgChat { id: -1001234 }, from: TgUser { id: 78 } }, 0).await;

        let fake = tg.lock().unwrap();
        assert_eq!(fake.approved, vec![(-1001234, 77)]);
        assert_eq!(fake.declined, vec![(-1001234, 78)]);
    }

    #[tokio::test]
    async fn a_server_revocation_preserves_membership() {
        // A dashboard revocation expires the tracked grant without changing membership.
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
        assert!(fake.kicked.is_empty());
        assert!(fake.unbanned.is_empty());
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
        let reply = bot.join(24, 0, "http://127.0.0.1:7799", "http://127.0.0.1:7808", None).await.unwrap();
        assert!(!reply.contains("already verified"), "the dead session is not claimed as live: {reply}");
        assert!(reply.contains("/telegram/join?token="), "a fresh join link is minted: {reply}");
    }

    // ── M6 admission-bridge integration tests ──────────────────────────────────────────────────
    //
    // These tests run a real HTTP listener on a loopback port that speaks the M5 bot admission
    // API. The bot calls it exactly as it would call a real bridge; the listener records calls and
    // controls what it returns, so each test drives a specific outcome without touching Telegram.

    use std::sync::{Arc, Mutex};

    struct FakeAdmissionServer {
        port: u16,
        created_sessions: Arc<Mutex<Vec<serde_json::Value>>>,
        redeemed_sessions: Arc<Mutex<Vec<String>>>,
        /// If Some, create_session returns this session_id; None → 500
        create_response: Arc<Mutex<Option<String>>>,
        /// If Some, redeem returns this admission JSON; None → 404
        redeem_response: Arc<Mutex<Option<serde_json::Value>>>,
    }

    impl FakeAdmissionServer {
        fn start(port: u16) -> Self {
            let created_sessions = Arc::new(Mutex::new(Vec::new()));
            let redeemed_sessions = Arc::new(Mutex::new(Vec::new()));
            let create_response: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(Some(format!("session-{port}"))));
            let redeem_response: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));

            let cs = created_sessions.clone();
            let rs = redeemed_sessions.clone();
            let cr = create_response.clone();
            let rr = redeem_response.clone();

            tokio::spawn(async move {
                let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.unwrap();
                loop {
                    let Ok((mut socket, _)) = listener.accept().await else { continue };
                    let cs2 = cs.clone();
                    let rs2 = rs.clone();
                    let cr2 = cr.clone();
                    let rr2 = rr.clone();
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut buf = vec![0u8; 8192];
                        let n = match socket.read(&mut buf).await { Ok(n) => n, Err(_) => return };
                        let raw = String::from_utf8_lossy(&buf[..n]).to_string();
                        let (head, body_raw) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
                        let first_line = head.lines().next().unwrap_or("");
                        let target = first_line.split_whitespace().nth(1).unwrap_or("");

                        let body_val: serde_json::Value = serde_json::from_str(body_raw).unwrap_or_default();

                        let response = if target == "/v1/bot/sessions" {
                            cs2.lock().unwrap().push(body_val);
                            match cr2.lock().unwrap().clone() {
                                Some(id) => {
                                    let exp = now_unix() + 300;
                                    let resp = serde_json::json!({ "session_id": id, "expires_unix": exp }).to_string();
                                    format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", resp.len(), resp)
                                }
                                None => "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 2\r\n\r\n{}".into(),
                            }
                        } else if target == "/v1/bot/sessions/redeem" {
                            let sid = body_val["session_id"].as_str().unwrap_or("").to_string();
                            rs2.lock().unwrap().push(sid);
                            match rr2.lock().unwrap().clone() {
                                Some(admission) => {
                                    let s = admission.to_string();
                                    format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", s.len(), s)
                                }
                                None => {
                                    let err = r#"{"error":"not found"}"#;
                                    format!("HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", err.len(), err)
                                }
                            }
                        } else {
                            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".into()
                        };
                        let _ = socket.write_all(response.as_bytes()).await;
                    });
                }
            });
            Self { port, created_sessions, redeemed_sessions, create_response, redeem_response }
        }

        fn set_create_response(&self, session_id: Option<&str>) {
            *self.create_response.lock().unwrap() = session_id.map(|s| s.to_string());
        }

        fn set_redeem_response(&self, admission: Option<serde_json::Value>) {
            *self.redeem_response.lock().unwrap() = admission;
        }

        fn bridge(&self, page: &str) -> BotAdmissionBridge {
            BotAdmissionBridge::new(
                format!("http://127.0.0.1:{}", self.port),
                [0u8; 32],
                "gate1".into(),
                "ph1".into(),
                "testnet".into(),
                page.into(),
            )
        }
    }

    fn admission_bot(server: &FakeAdmissionServer) -> (Bot<Wrap, FakeBridge>, SharedFake) {
        let tg = Arc::new(Mutex::new(FakeTelegram::new()));
        let t2 = tg.clone();
        let bridge = FakeBridge { answers: HashMap::new(), access: None };
        let mut bot = Bot::new(Wrap(t2), bridge, -1001234, "gate1".into());
        bot.admission_bridges.push(server.bridge("/lab"));
        (bot, tg)
    }

    #[tokio::test]
    async fn admission_qualified_user_admitted() {
        let srv = FakeAdmissionServer::start(7920);
        srv.set_create_response(Some("sess-qualified"));
        srv.set_redeem_response(Some(serde_json::json!({
            "telegram_user_id": 55i64,
            "telegram_chat_id": -1001234i64,
            "gate_id": "gate1",
            "wallet_output": "abc123",
        })));
        let (mut bot, tg) = admission_bot(&srv);

        // /join creates a session and returns a /lab link.
        let reply = bot.join(55, 101, "http://127.0.0.1:7799", "http://claim", None).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(reply.contains("bot_session=sess-qualified"), "join link embeds session id: {reply}");
        assert_eq!(srv.created_sessions.lock().unwrap().len(), 1);

        // /claim with bot_session_id redeems and approves the join request.
        let request = format!(
            "POST /claim HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://127.0.0.1:7799\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            r#"{"bot_session_id":"sess-qualified"}"#.len(),
            r#"{"bot_session_id":"sess-qualified"}"#,
        );
        let response = handle_claim_http_for_origin(&mut bot, &request, "http://127.0.0.1:7799").await;
        assert!(response.contains("200 OK"), "{response}");
        assert!(response.contains("granted"), "{response}");
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(srv.redeemed_sessions.lock().unwrap().as_slice(), &["sess-qualified"]);
        let fake = tg.lock().unwrap();
        assert!(fake.approved.contains(&(-1001234, 55)), "join request was approved; approved={:?}", fake.approved);
    }

    #[tokio::test]
    async fn admission_replay_rejected() {
        let srv = FakeAdmissionServer::start(7921);
        srv.set_create_response(Some("sess-replay"));
        srv.set_redeem_response(Some(serde_json::json!({
            "telegram_user_id": 56i64,
            "telegram_chat_id": -1001234i64,
            "gate_id": "gate1",
            "wallet_output": "def456",
        })));
        let (mut bot, _tg) = admission_bot(&srv);
        bot.join(56, 102, "http://127.0.0.1:7799", "http://claim", None).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        let make_req = |sid: &str| format!(
            "POST /claim HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://127.0.0.1:7799\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{{\"bot_session_id\":\"{}\"}}",
            4 + sid.len() + 18, sid
        );
        let r1 = handle_claim_http_for_origin(&mut bot, &make_req("sess-replay"), "http://127.0.0.1:7799").await;
        assert!(r1.contains("200 OK"), "first claim succeeds: {r1}");
        // Second claim on the same session_id: session was consumed, so it's unknown.
        let r2 = handle_claim_http_for_origin(&mut bot, &make_req("sess-replay"), "http://127.0.0.1:7799").await;
        assert!(r2.contains("403"), "replay is rejected: {r2}");
    }

    #[tokio::test]
    async fn admission_wrong_user_rejected() {
        let srv = FakeAdmissionServer::start(7922);
        srv.set_create_response(Some("sess-wrong-user"));
        // Bridge returns a different user_id than the one who called /join.
        srv.set_redeem_response(Some(serde_json::json!({
            "telegram_user_id": 999i64,
            "telegram_chat_id": -1001234i64,
            "gate_id": "gate1",
            "wallet_output": "xyz789",
        })));
        let (mut bot, _tg) = admission_bot(&srv);
        bot.join(57, 103, "http://127.0.0.1:7799", "http://claim", None).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        let body = r#"{"bot_session_id":"sess-wrong-user"}"#;
        let req = format!(
            "POST /claim HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://127.0.0.1:7799\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let response = handle_claim_http_for_origin(&mut bot, &req, "http://127.0.0.1:7799").await;
        assert!(response.contains("403"), "user mismatch is rejected: {response}");
        assert!(response.contains("mismatch"), "{response}");
    }

    #[tokio::test]
    async fn admission_unknown_session_rejected() {
        let srv = FakeAdmissionServer::start(7923);
        let (mut bot, _tg) = admission_bot(&srv);
        let body = r#"{"bot_session_id":"no-such-session"}"#;
        let req = format!(
            "POST /claim HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://127.0.0.1:7799\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let response = handle_claim_http_for_origin(&mut bot, &req, "http://127.0.0.1:7799").await;
        assert!(response.contains("403"), "unknown session rejected: {response}");
    }

    #[tokio::test]
    async fn admission_session_expires_on_tick() {
        let srv = FakeAdmissionServer::start(7924);
        srv.set_create_response(Some("sess-expiry"));
        let (mut bot, _tg) = admission_bot(&srv);
        bot.join(58, 104, "http://127.0.0.1:7799", "http://claim", None).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(bot.bot_sessions.len(), 1);
        // Manually expire by overwriting the entry's expires field.
        for s in bot.bot_sessions.values_mut() {
            s.expires = Instant::now() - Duration::from_secs(1);
        }
        bot.tick().await;
        assert!(bot.bot_sessions.is_empty(), "expired session pruned by tick");
    }

    /// If Telegram's approve_join_request fails, the admission is queued in `pending_approvals`.
    /// The browser-visible response is still 200 (the bridge proof is complete, no replay possible).
    #[tokio::test]
    async fn admission_telegram_failure_queued_for_retry() {
        let srv = FakeAdmissionServer::start(7925);
        srv.set_create_response(Some("sess-tg-fail"));
        srv.set_redeem_response(Some(serde_json::json!({
            "telegram_user_id": 60i64,
            "telegram_chat_id": -1001234i64,
            "gate_id": "gate1",
            "wallet_output": "abc",
        })));
        let (mut bot, tg) = admission_bot(&srv);
        // Inject Telegram failure.
        tg.lock().unwrap().approve_fails = true;
        bot.join(60, 110, "http://127.0.0.1:7799", "http://claim", None).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        let body = r#"{"bot_session_id":"sess-tg-fail"}"#;
        let req = format!(
            "POST /claim HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://127.0.0.1:7799\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let response = handle_claim_http_for_origin(&mut bot, &req, "http://127.0.0.1:7799").await;
        // Bridge proof succeeded; we return 200 and queue the Telegram approval.
        assert!(response.contains("200 OK"), "claim returns 200 even when Telegram temporarily fails: {response}");
        // Session was consumed (no replay).
        assert!(bot.bot_sessions.is_empty(), "session consumed regardless of Telegram outcome");
        // Pending approval queued.
        assert_eq!(bot.pending_approvals.len(), 1, "pending_approvals has the queued entry");
        // No actual Telegram approval yet.
        assert!(tg.lock().unwrap().approved.is_empty(), "no Telegram approval yet");
    }

    /// After a Telegram failure, the next tick() retries and clears `pending_approvals` on success.
    #[tokio::test]
    async fn admission_telegram_retry_succeeds_on_tick() {
        let srv = FakeAdmissionServer::start(7926);
        srv.set_create_response(Some("sess-tg-retry"));
        srv.set_redeem_response(Some(serde_json::json!({
            "telegram_user_id": 61i64,
            "telegram_chat_id": -1001234i64,
            "gate_id": "gate1",
            "wallet_output": "abc",
        })));
        let (mut bot, tg) = admission_bot(&srv);
        tg.lock().unwrap().approve_fails = true;
        bot.join(61, 111, "http://127.0.0.1:7799", "http://claim", None).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        let body = r#"{"bot_session_id":"sess-tg-retry"}"#;
        let req = format!(
            "POST /claim HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://127.0.0.1:7799\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        handle_claim_http_for_origin(&mut bot, &req, "http://127.0.0.1:7799").await;
        assert_eq!(bot.pending_approvals.len(), 1, "queued after Telegram fail");

        // Repair Telegram and tick.
        tg.lock().unwrap().approve_fails = false;
        bot.tick().await;

        assert!(bot.pending_approvals.is_empty(), "pending_approvals cleared after tick retry");
        assert!(
            tg.lock().unwrap().approved.contains(&(-1001234, 61)),
            "Telegram approved on retry"
        );
    }

    /// `load_stores` removes stale `.tmp` files left by a crash mid-write.
    #[test]
    fn load_stores_removes_stale_tmp_files() {
        let dir = std::env::temp_dir().join(format!("gg-test-store-tmp-{}", now_unix()));
        std::fs::create_dir_all(&dir).unwrap();
        let sess_tmp = dir.join("pending_sessions.json.tmp");
        let appr_tmp = dir.join("pending_approvals.json.tmp");
        std::fs::write(&sess_tmp, b"stale").unwrap();
        std::fs::write(&appr_tmp, b"stale").unwrap();
        assert!(sess_tmp.exists() && appr_tmp.exists(), "stale files must exist before load");

        let tg = std::sync::Arc::new(std::sync::Mutex::new(FakeTelegram::new()));
        let bridge = FakeBridge { answers: HashMap::new(), access: None };
        let mut bot = Bot::new(Wrap(tg), bridge, -1001i64, "test-gate".into());
        bot.bot_store_dir = Some(dir.clone());
        bot.load_stores();

        assert!(!sess_tmp.exists(), "stale sessions.json.tmp removed by load_stores");
        assert!(!appr_tmp.exists(), "stale approvals.json.tmp removed by load_stores");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `atomic_write_json` writes data atomically and leaves no stale `.tmp` on success.
    #[test]
    fn atomic_write_json_persists_and_is_readable() {
        let dir = std::env::temp_dir().join(format!("gg-test-atomic-{}", now_unix()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.json");
        let payload = r#"{"key":"value"}"#;
        atomic_write_json(&path, payload);
        let read_back = std::fs::read_to_string(&path).expect("file should exist after atomic write");
        assert_eq!(read_back, payload);
        assert!(!dir.join("test.json.tmp").exists(), "no .tmp sibling after successful write");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Sessions saved to `bot_store_dir` survive restart: `load_stores` restores them from disk.
    #[tokio::test]
    async fn admission_sessions_survive_restart_via_store() {
        let dir = std::env::temp_dir().join(format!("gg-test-store-{}", now_unix()));
        std::fs::create_dir_all(&dir).unwrap();

        let srv = FakeAdmissionServer::start(7927);
        srv.set_create_response(Some("sess-restart"));

        // First "process": create the session and persist it.
        {
            let (mut bot, _tg) = admission_bot(&srv);
            bot.bot_store_dir = Some(dir.clone());
            bot.join(62, 112, "http://127.0.0.1:7799", "http://claim", None).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            assert_eq!(bot.bot_sessions.len(), 1);
        }

        // Second "process": load from disk and verify the session is there.
        {
            let (mut bot2, _tg2) = admission_bot(&srv);
            bot2.bot_store_dir = Some(dir.clone());
            assert!(bot2.bot_sessions.is_empty(), "fresh bot has no sessions in memory");
            bot2.load_stores();
            assert_eq!(bot2.bot_sessions.len(), 1, "session restored from disk");
            assert!(bot2.bot_sessions.contains_key("sess-restart"), "correct session_id loaded");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
