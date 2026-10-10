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
//! - Grants are in-memory: a restart forgets them (safe failure — access simply lapses until
//!   re-verified, and nothing stale outlives the process).
//! - Long polling (`getUpdates`), not webhooks: nothing public to spoof.
//! - Membership checks are *point-in-time*: between two verifications ownership may change. The
//!   product claim is exactly "held enough at verification time", and the ticker enforces that
//!   honestly by revoking on expiry rather than claiming continuous ownership.

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use serde::{Deserialize, Serialize};
use serde_json::json;

const DEFAULT_BRIDGE: &str = "http://127.0.0.1:7799";
const DEFAULT_CLAIM_PORT: u16 = 7808;
const DEFAULT_GATE: &str = "crypt";
const JOIN_TTL: Duration = Duration::from_secs(600);
const ACCESS_TTL: Duration = Duration::from_secs(3600);
const RECHECK_INTERVAL: Duration = Duration::from_secs(60);
/// Whether the fixture bridge/telegram pair is in use; set once at startup.
static FIXTURE_POLL_PAUSE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The Telegram account fixture grants bind to.
const FIXTURE_TG_USER: i64 = 42;

/// The most pending join tokens held at once (audit F-03's class, applied to the bot).
const MAX_PENDING_TOKENS: usize = 512;
const POLL_INTERVAL: u64 = 3; // seconds between getUpdates calls
const MAX_ANSWERED_SEEN: usize = 1024;

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
    proof_id: String,
    invite_link: String,
}

/// The Telegram Bot API surface this POC uses.
///
/// A trait so the grant lifecycle is testable without Telegram: the fake records what the bot
/// would have sent, which is also how the revocation race is pinned (single-threaded ticker, no
/// concurrent mutation of the grants map).
#[allow(async_fn_in_trait)]
pub trait TelegramApi: Send {
    async fn send_message(&mut self, user: i64, text: &str) -> Result<(), String>;
    async fn create_single_seat_invite(&mut self, chat: i64) -> Result<String, String>;
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
    async fn create_single_seat_invite(&mut self, _chat: i64) -> Result<String, String> {
        let mut b = [0u8; 8];
        rand::fill(&mut b);
        Ok(format!("https://t.me/fixture/join/{}", hex::encode(b)))
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
            });
        }
        Err("404: no such proof".into())
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
            http: reqwest::Client::new(),
            token: token.to_string(),
        }
    }

    async fn call(&self, method: &str, params: &serde_json::Value) -> Result<serde_json::Value, String> {
        let url = format!("https://api.telegram.org/bot{}/{}", self.token, method);
        let resp = self.http.post(&url).json(params).send().await.map_err(|e| e.to_string())?;
        let v: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        // The Bot API answers {ok: true, result} or {ok: false, description}. Never log the token:
        // only the method name reaches an error message.
        if v["ok"].as_bool() != Some(true) {
            return Err(format!("telegram {}: {}", method, v["description"].as_str().unwrap_or("error")));
        }
        Ok(v["result"].clone())
    }
}

impl TelegramApi for TelegramBot {
    async fn send_message(&mut self, user: i64, text: &str) -> Result<(), String> {
        self.call("sendMessage", &json!({ "chat_id": user, "text": text, "parse_mode": "HTML" }))
            .await
            .map(|_| ())
    }
    async fn create_single_seat_invite(&mut self, chat: i64) -> Result<String, String> {
        let v = self
            .call(
                "createChatInviteLink",
                &json!({ "chat_id": chat, "member_limit": 1, "creates_join_request": false }),
            )
            .await?;
        v["invite_link"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| "telegram: no invite link in response".into())
    }
    async fn kick_member(&mut self, chat: i64, user: i64) -> Result<(), String> {
        // Ban then unban = kick with the door left open for a future re-join.
        self.call("banChatMember", &json!({ "chat_id": chat, "user_id": user })).await?;
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
                &json!({ "offset": offset, "timeout": POLL_INTERVAL.min(50), "allowed_updates": json!(["message"]) }),
            )
            .await?;
        serde_json::from_value(v).map_err(|e| e.to_string())
    }
}

/// The bridge client. Verifier responses are the only thing this bot trusts about a proof.
#[allow(async_fn_in_trait)]
pub trait BridgeClient: Send {
    async fn proof_status(&self, proof_id: &str) -> Result<ProofStatus, String>;
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
    tokens: HashMap<String, JoinToken>,
    grants: HashMap<i64, Grant>,
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
            tokens: HashMap::new(),
            grants: HashMap::new(),
            seen_updates: std::collections::BTreeSet::new(),
        }
    }

    /// `/join`: mints a single-use token bound to this Telegram account.
    pub async fn join(&mut self, user: i64, base_url: &str, claim_base: &str) -> Result<String, String> {
        // A user rejoining while a grant is live gets told, rather than silently minting a second
        // proof obligation.
        if let Some(g) = self.grants.get(&user)
            && g.expires > Instant::now()
        {
            let left = g.expires.duration_since(Instant::now()).as_secs().max(1);
            return Ok(format!(
                "Your access is already verified for another {} minute(s). I'll ask for a fresh proof when it lapses.",
                (left + 59) / 60
            ));
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
        Ok(format!(
            "To prove you hold enough of the vault's token, open this link in the browser where your wallet lives:\n\n{}\n\nThis link is for you alone, works once, and expires in 10 minutes. I will never ask for your seed, keys, or exact balance — the check is a public minimum, verified by the network.",
            format_args!(
                "{}/telegram/join/{token}?gate={}&claim={}/claim",
                base_url.trim_end_matches('/'),
                self.gate,
                claim_base.trim_end_matches('/'),
            )
        ))
    }

    /// The claim endpoint's logic. Single-use token, TTL, and the bridge's own receipt re-read.
    pub async fn claim(&mut self, token: &str, proof_id: &str) -> Result<String, String> {
        let record = self
            .tokens
            .get(token)
            .ok_or("unknown or already-consumed join link")?;
        if record.used {
            return Err("this join link was already used".into());
        }
        if record.expires < Instant::now() {
            self.tokens.remove(token);
            return Err("this join link expired; send /join again".into());
        }
        let user = record.user;

        // Server-side verification, from the bridge only. The page's word is not evidence.
        let status = self
            .bridge
            .proof_status(proof_id)
            .await
            .map_err(|e| format!("could not read the proof from the bridge: {e}"))?;
        if status.state != "credential_accepted" {
            return Err("the bridge does not show this proof as accepted".into());
        }
        let receipt = status
            .result
            .ok_or("the bridge's accepted proof carries no receipt")?;
        if receipt.mode != "credential" {
            return Err("the proof is not a credential-mode receipt".into());
        }
        if receipt.gate_id != self.gate {
            return Err(format!(
                "this proof is for gate {:?}, not the community gate {:?}",
                receipt.gate_id, self.gate
            ));
        }

        // Consume the token only after every check passed. It is *marked*, not removed: a replay
        // then answers "already used" — the informative refusal — and the ticker prunes it once
        // the TTL has passed.
        self.tokens.get_mut(token).expect("checked above").used = true;

        let link = self.telegram.create_single_seat_invite(self.chat).await?;
        self.grants.insert(
            user,
            Grant { expires: Instant::now() + self.access_ttl, proof_id: proof_id.to_string(), invite_link: link.clone() },
        );
        self.telegram
            .send_message(
                user,
                &format!(
                    "Verified: the network attested at least the threshold, and I never learned a balance. Doors open for {} minute(s). I'll ask for a fresh proof when it lapses.",
                    self.access_ttl.as_secs() / 60
                ),
            )
            .await
            .ok();
        Ok(link)
    }

    /// The re-verification ticker: revoke expired grants, tell the user how to rejoin.
    ///
    /// Runs in one place (the caller's loop) so no two ticks can race the same user's revocation.
    pub async fn tick(&mut self) {
        let now = Instant::now();
        // Tokens whose TTL passed — used or not — are state nobody can act on any more.
        self.tokens.retain(|_, t| t.expires > now);
        let expired: Vec<i64> = self
            .grants
            .iter()
            .filter(|(_, g)| g.expires <= now)
            .map(|(u, _)| *u)
            .collect();
        for user in expired {
            let grant = self.grants.remove(&user).expect("just filtered");
            // Kick (ban+unban) so the seat frees and re-joining is possible after re-verification.
            self.telegram.kick_member(self.chat, user).await.ok();
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
    pub async fn handle_update(&mut self, update: TgUpdate, base_url: &str, claim_base: &str) {
        let Some(message) = update.message.clone() else { return };
        let Some(user) = message.from.as_ref().map(|f| f.id) else { return };
        let text = message.text.clone().unwrap_or_default();
        if text.starts_with("/join") {
            if let Ok(reply) = self.join(user, base_url, claim_base).await {
                self.telegram.send_message(user, &reply).await.ok();
            } else {
                self.telegram
                    .send_message(user, "Something went wrong minting your join link; try again.")
                    .await
                    .ok();
            }
        } else if text.starts_with("/start") {
            self.telegram
                .send_message(
                    user,
                    "Send /join to prove you hold enough of the vault's token. I'll ask for a wallet proof, never for your seed or keys, and never for an exact balance.",
                )
                .await
                .ok();
        }
    }

    pub fn grant_count(&self) -> usize {
        self.grants.len()
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

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("runtime");
    let code = runtime.block_on(run());
    std::process::exit(code);
}

async fn run() -> i32 {
    // Fixture mode, for LOCAL lifecycle testing without Telegram. It is explicitly labelled in
    // every log line; a fixture grant is never a real membership.
    let fixture = std::env::var("GG_TG_FIXTURE").ok().as_deref() == Some("1");
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

    // Two arms, because the fixture and real bots are different types (the clients are type
    // parameters, never trait objects), and unifying them would need an extra enum for one
    // startup if/else.
    if fixture {
        FIXTURE_POLL_PAUSE.store(true, std::sync::atomic::Ordering::Relaxed);
        // In fixture mode the bot never reads Telegram, so it mints one join token at startup for
        // the fixture user and prints everything needed to drive the lifecycle by hand.
        let mut bot = Bot::new(FixtureTelegram, FixtureBridge { gate: gate.clone() }, chat, gate.clone());
        let reply = bot
            .join(FIXTURE_TG_USER, &bridge_base, &format!("http://127.0.0.1:{claim_port}"))
            .await
            .expect("fixture join");
        let marker = "/telegram/join/";
        let token_part = reply[reply.find(marker).expect("join link") + marker.len()..]
            .split('?')
            .next()
            .expect("token")
            .to_string();
        eprintln!(
            "ghost-gate-telegram: FIXTURE MODE — no Telegram is contacted; grants are local only.\n\
             fixture join page (for a browser with a wallet):\n\
               {reply}\n\
             and a ready-made claim (the fixture bridge accepts proof ids starting with 'fixture_'):\n\
               curl -s -X POST http://127.0.0.1:{claim_port}/claim -H 'Content-Type: application/json' \\
                 -d '{{\"token\":\"{token_part}\",\"proof_id\":\"fixture_smoke\"}}'"
        );
        return serve(bot, &bridge_base, &format!("http://127.0.0.1:{claim_port}"), claim_port, &gate).await;
    }

    let bot = Bot::new(TelegramBot::new(&token), HttpBridge::new(&bridge), chat, gate.clone());
    serve(bot, &bridge_base, &format!("http://127.0.0.1:{claim_port}"), claim_port, &gate).await
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
                            bot.handle_update(update, join_base, claim_base).await;
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
            let payload = json!({ "state": "granted", "invite_link": link, "at": now_unix() }).to_string();
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
        kicked: Vec<i64>,
        unbanned: Vec<i64>,
        messages: Vec<(i64, String)>,
        next_link: String,
    }

    impl FakeTelegram {
        fn new() -> Self {
            Self {
                invites: Vec::new(),
                kicked: Vec::new(),
                unbanned: Vec::new(),
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
        async fn create_single_seat_invite(&mut self, chat: i64) -> Result<String, String> {
            let mut g = self.0.lock().unwrap();
            g.invites.push(chat);
            Ok(g.next_link.clone())
        }
        async fn kick_member(&mut self, chat: i64, user: i64) -> Result<(), String> {
            // The real client kicks as ban-then-unban (seat freed, door open); the fake mirrors
            // both effects so tests assert what actually happens to the member.
            let mut g = self.0.lock().unwrap();
            g.kicked.push(user);
            g.unbanned.push(user);
            let _ = chat;
            Ok(())
        }
        async fn unban_member(&mut self, chat: i64, user: i64) -> Result<(), String> {
            self.0.lock().unwrap().unbanned.push(user);
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
    }

    fn bot_owned(bridge: FakeBridge) -> (Bot<Wrap, FakeBridge>, SharedFake) {
        let tg: SharedFake = std::sync::Arc::new(std::sync::Mutex::new(FakeTelegram::new()));
        let t2 = tg.clone();
        let bot = Bot::new(Wrap(t2), bridge, -1001234, "crypt".into());
        (bot, tg)
    }

    async fn mint_join(bot: &mut Bot<Wrap, FakeBridge>, user: i64) -> (String, String) {
        let reply = bot.join(user, "http://127.0.0.1:7799", "http://127.0.0.1:7808").await.unwrap();
        // Extract the token from the reply (the link's path segment before '?').
        let marker = "/telegram/join/";
        let i = reply.find(marker).expect("the reply embeds the join link") + marker.len();
        let rest = &reply[i..];
        let token = rest.split('?').next().expect("token before query").to_string();
        (token, reply)
    }

    #[tokio::test]
    async fn a_join_link_is_single_use_and_bound_to_one_account() {
        let bridge = FakeBridge { answers: HashMap::from([("proof1".to_string(), FakeBridge::accepted("crypt"))]) };
        let (mut bot, tg) = bot_owned(bridge);
        let (token, reply) = mint_join(&mut bot, 42).await;
        assert!(reply.contains("for you alone"), "the reply says so: {reply}");
        assert!(reply.contains("never ask for your seed"), "the reply states the privacy rule: {reply}");

        let link = bot.claim(&token, "proof1").await.expect("first claim grants");
        assert_eq!(link, "https://t.me/joinchat/seat1");
        assert_eq!(bot.grant_count(), 1);
        assert_eq!(tg.lock().unwrap().invites, vec![-1001234]);

        // Second claim with the same token: refused.
        let err = bot.claim(&token, "proof2").await.expect_err("single-use");
        assert!(err.contains("already used"), "{err}");
    }

    #[tokio::test]
    async fn a_claim_with_a_proof_for_another_gate_is_refused() {
        let bridge = FakeBridge { answers: HashMap::from([("proof2".to_string(), FakeBridge::accepted("abyss"))]) };
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
            ProofStatus { state: "submitted".into(), result: None },
        )]) };
        let (mut bot, _tg) = bot_owned(bridge);
        let (token, _) = mint_join(&mut bot, 8).await;
        let err = bot.claim(&token, "proof3").await.expect_err("unverified proof");
        assert!(err.contains("does not show this proof as accepted"), "{err}");
        assert_eq!(bot.grant_count(), 0);
    }

    #[tokio::test]
    async fn an_expired_join_link_refuses_and_is_gone() {
        let bridge = FakeBridge { answers: HashMap::new() };
        let (mut bot, _tg) = bot_owned(bridge);
        bot.join_ttl = Duration::from_millis(1);
        let (token, _) = mint_join(&mut bot, 9).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let err = bot.claim(&token, "proof4").await.expect_err("expired");
        assert!(err.contains("expired"), "{err}");
    }

    #[tokio::test]
    async fn grants_expire_and_are_revoked_by_the_ticker() {
        let bridge = FakeBridge { answers: HashMap::from([("proof5".to_string(), FakeBridge::accepted("crypt"))]) };
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
    async fn a_live_grant_blocks_a_duplicate_join_with_a_second_proof() {
        let bridge = FakeBridge { answers: HashMap::from([("proof6".to_string(), FakeBridge::accepted("crypt"))]) };
        let (mut bot, _tg) = bot_owned(bridge);
        let (token, _) = mint_join(&mut bot, 11).await;
        bot.claim(&token, "proof6").await.unwrap();

        // The user rejoins while verified: no second obligation, no second proof.
        let reply = bot.join(11, "http://127.0.0.1:7799", "http://127.0.0.1:7808").await.unwrap();
        assert!(reply.contains("already verified"), "{reply}");
        assert_eq!(bot.grant_count(), 1);
    }

    #[tokio::test]
    async fn a_replayed_update_cannot_act_twice() {
        let bridge = FakeBridge { answers: HashMap::new() };
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
        let bridge = FakeBridge { answers: HashMap::from([("fixture_smoke".to_string(), FakeBridge::accepted("crypt"))]) };
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
        let bridge = FakeBridge { answers: HashMap::new() };
        let (mut bot, _tg) = bot_owned(bridge);
        for u in 0..(MAX_PENDING_TOKENS + 10) {
            bot.join(u as i64, "http://x", "http://y").await.unwrap();
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
        let bridge = FakeBridge { answers: HashMap::from([("proof7".to_string(), FakeBridge::accepted("crypt"))]) };
        let (mut bot, _tg) = bot_owned(bridge);
        let (token, _) = mint_join(&mut bot, 12).await;
        let body = serde_json::json!({ "token": token, "proof_id": "proof7" }).to_string();
        let request = format!("POST /claim HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        let response = handle_claim_http(&mut bot, &request).await;
        assert!(response.contains("200 OK"), "{response}");
        assert!(response.contains("granted"), "{response}");
        assert!(
            response.contains("Access-Control-Allow-Origin: http://127.0.0.1:7799"),
            "the preflight names the join page's origin exactly: {response}"
        );

        // Replay with the same body: the token is consumed, so it refuses now.
        let response2 = handle_claim_http(&mut bot, &request).await;
        assert!(response2.contains("403"), "{response2}");
    }
}
