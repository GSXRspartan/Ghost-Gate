//! Disabled-by-default bot-only session creation handler. This module does not start a listener.
//! The caller must obtain policy from the live published gate, not from a request. The bot key is
//! distinct from all administrator and hosted-verifier credentials and is trusted to assert the
//! Telegram update identity. No browser-facing caller may access or possess it.

use std::{net::SocketAddr, time::{SystemTime, UNIX_EPOCH}};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::Deserialize;

use crate::authorization_coordinator::{AuthorizationContext, AuthorizationCoordinator};

const DOMAIN: &[u8] = b"ghost-gate/bot-session/v1\0POST\0/v1/bot/sessions\0";
const MAX_BODY: usize = 2048;
const MAX_SKEW_SECS: u64 = 60;

/// Server-sourced gate snapshot, never populated from the bot's HTTP request.
pub struct BotGatePolicy {
    pub gate_id: String,
    pub policy_hash: String,
    pub network: u8,
    pub resource: String,
    pub threshold: u64,
    pub telegram_chat_id: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BotRequest {
    update_id: i64,
    telegram_user_id: i64,
    telegram_chat_id: i64,
    gate_id: String,
    policy_hash: String,
    sent_unix: u64,
}

/// Opaque public response; identity, credentials and the challenge nonce remain server-side.
#[derive(serde::Serialize)]
pub struct SessionCreated {
    pub session_id: String,
    pub expires_unix: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum BotSessionError {
    #[error("bot request refused")]
    Refused,
    #[error("bot session storage unavailable")]
    Unavailable,
}

/// Scoped authenticated operation; the caller must pass the socket's actual peer, never a header.
/// HMAC authenticates the raw body, fixed method and fixed route. Replays are rejected in SQLite.
pub fn create_session(
    db: &mut AuthorizationCoordinator,
    policy: &BotGatePolicy,
    bot_key: &[u8; 32],
    peer: SocketAddr,
    origin: Option<&str>,
    signature_hex: &str,
    body: &[u8],
) -> Result<SessionCreated, BotSessionError> {
    if !peer.ip().is_loopback() || origin.is_some() || body.len() > MAX_BODY
        || signature_hex.len() != 64 || bot_key == &[0; 32] {
        return Err(BotSessionError::Refused);
    }
    let signature = hex::decode(signature_hex).map_err(|_| BotSessionError::Refused)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(bot_key).map_err(|_| BotSessionError::Refused)?;
    mac.update(DOMAIN);
    mac.update(body);
    mac.verify_slice(&signature).map_err(|_| BotSessionError::Refused)?;
    let request: BotRequest = serde_json::from_slice(body).map_err(|_| BotSessionError::Refused)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| BotSessionError::Unavailable)?.as_secs();
    if request.sent_unix.abs_diff(now) > MAX_SKEW_SECS || request.update_id < 0
        || request.telegram_user_id <= 0 || request.telegram_chat_id != policy.telegram_chat_id
        || policy.telegram_chat_id >= 0 || request.gate_id != policy.gate_id
        || request.policy_hash != policy.policy_hash {
        return Err(BotSessionError::Refused);
    }
    let expires = now.checked_add(180).ok_or(BotSessionError::Unavailable)?;
    let context = AuthorizationContext {
        telegram_user_id: request.telegram_user_id,
        telegram_chat_id: policy.telegram_chat_id,
        gate_id: policy.gate_id.clone(),
        policy_hash: policy.policy_hash.clone(),
        network: policy.network,
        resource: policy.resource.clone(),
        threshold: policy.threshold,
        challenge_nonce: String::new(),
        issued_unix: now,
        expires_unix: expires,
    };
    let auth = db.issue_bot_event(request.update_id, context).map_err(|_| BotSessionError::Unavailable)?;
    Ok(SessionCreated { session_id: auth.session_id, expires_unix: expires })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization_coordinator::AuthorizationState;
    use serde_json::json;

    struct TestDb(std::path::PathBuf);
    impl TestDb {
        fn new() -> Self {
            let mut nonce = [0u8; 16]; rand::fill(&mut nonce);
            let path = std::env::temp_dir().join(format!("gg-bot-sessions-{}", hex::encode(nonce)));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> std::path::PathBuf { self.0.join("authorization.sqlite") }
    }
    impl Drop for TestDb { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
    fn policy() -> BotGatePolicy {
        BotGatePolicy { gate_id: "Crypt".into(), policy_hash: "ab".repeat(32), network: 38,
            resource: "resource_test".into(), threshold: 100_000_000, telegram_chat_id: -1001234 }
    }
    fn request(id: i64, user: i64, chat: i64, gate: &str, hash: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({ "update_id": id, "telegram_user_id": user,
            "telegram_chat_id": chat, "gate_id": gate, "policy_hash": hash,
            "sent_unix": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() })).unwrap()
    }
    fn sign(key: &[u8; 32], body: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        mac.update(DOMAIN); mac.update(body); hex::encode(mac.finalize().into_bytes())
    }
    fn local() -> SocketAddr { "127.0.0.1:1234".parse().unwrap() }

    #[test]
    fn authenticated_event_creates_only_one_durable_server_policy_bound_session() {
        let dir = TestDb::new(); let key = [1; 32]; let policy = policy();
        let mut db = AuthorizationCoordinator::create_new(&dir.path()).unwrap();
        db.initialize_bot_event_store().unwrap();
        let body = request(7, 42, policy.telegram_chat_id, &policy.gate_id, &policy.policy_hash);
        let response = create_session(&mut db, &policy, &key, local(), None, &sign(&key, &body), &body).unwrap();
        let wire = serde_json::to_value(&response).unwrap();
        assert_eq!(wire.as_object().unwrap().len(), 2);
        assert!(wire.get("telegram_user_id").is_none());
        assert!(wire.get("admin_sessions").is_none());
        assert!(create_session(&mut db, &policy, &key, local(), None, &sign(&key, &body), &body).is_err());
        drop(db);
        let mut db = AuthorizationCoordinator::open_existing(&dir.path()).unwrap();
        let saved = db.get(&response.session_id).unwrap();
        assert_eq!(saved.state, AuthorizationState::Created);
        assert_eq!(saved.context.telegram_user_id, 42);
        assert_eq!(saved.context.telegram_chat_id, policy.telegram_chat_id);
        assert_eq!(saved.context.threshold, 100_000_000);
        assert_eq!(saved.context.network, 38);
    }

    #[test]
    fn credentials_origin_peer_and_signed_identity_are_checked() {
        let dir = TestDb::new(); let key = [1; 32]; let policy = policy();
        let mut db = AuthorizationCoordinator::create_new(&dir.path()).unwrap();
        db.initialize_bot_event_store().unwrap();
        let body = request(8, 42, policy.telegram_chat_id, &policy.gate_id, &policy.policy_hash);
        let signature = sign(&key, &body);
        assert!(create_session(&mut db, &policy, &key, local(), None, "", &body).is_err());
        assert!(create_session(&mut db, &policy, &key, local(), None, &sign(&[2; 32], &body), &body).is_err());
        assert!(create_session(&mut db, &policy, &key, local(), Some("https://evil.example"), &signature, &body).is_err());
        assert!(create_session(&mut db, &policy, &key, "192.0.2.1:1234".parse().unwrap(), None, &signature, &body).is_err());
        let altered_user = request(8, 43, policy.telegram_chat_id, &policy.gate_id, &policy.policy_hash);
        assert!(create_session(&mut db, &policy, &key, local(), None, &signature, &altered_user).is_err());
        let wrong_chat = request(9, 42, -1005678, &policy.gate_id, &policy.policy_hash);
        assert!(create_session(&mut db, &policy, &key, local(), None, &sign(&key, &wrong_chat), &wrong_chat).is_err());
        let wrong_gate = request(10, 42, policy.telegram_chat_id, "other", &policy.policy_hash);
        assert!(create_session(&mut db, &policy, &key, local(), None, &sign(&key, &wrong_gate), &wrong_gate).is_err());
        let wrong_policy = request(11, 42, policy.telegram_chat_id, &policy.gate_id, &"cd".repeat(32));
        assert!(create_session(&mut db, &policy, &key, local(), None, &sign(&key, &wrong_policy), &wrong_policy).is_err());
        let mut stale: serde_json::Value = serde_json::from_slice(&body).unwrap();
        stale["sent_unix"] = json!(0);
        let stale = serde_json::to_vec(&stale).unwrap();
        assert!(create_session(&mut db, &policy, &key, local(), None, &sign(&key, &stale), &stale).is_err());
        let oversized = vec![b'x'; MAX_BODY + 1];
        assert!(create_session(&mut db, &policy, &key, local(), None, &sign(&key, &oversized), &oversized).is_err());
    }

    #[test]
    fn concurrent_authenticated_requests_keep_both_records() {
        let dir = TestDb::new();
        AuthorizationCoordinator::create_new(&dir.path()).unwrap().initialize_bot_event_store().unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let mut threads = Vec::new();
        for id in [21, 22] {
            let path = dir.path(); let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                let policy = policy(); let key = [1; 32];
                let body = request(id, id, policy.telegram_chat_id, &policy.gate_id, &policy.policy_hash);
                let mut db = AuthorizationCoordinator::open_existing(&path).unwrap();
                barrier.wait();
                create_session(&mut db, &policy, &key, local(), None, &sign(&key, &body), &body).unwrap().session_id
            }));
        }
        let sessions: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert_ne!(sessions[0], sessions[1]);
        let mut db = AuthorizationCoordinator::open_existing(&dir.path()).unwrap();
        assert_eq!(db.get(&sessions[0]).unwrap().state, AuthorizationState::Created);
        assert_eq!(db.get(&sessions[1]).unwrap().state, AuthorizationState::Created);
    }

    #[test]
    fn authenticated_creation_rate_is_bounded_across_reopen() {
        let dir = TestDb::new(); let key = [1; 32]; let policy = policy();
        let mut db = AuthorizationCoordinator::create_new(&dir.path()).unwrap();
        db.initialize_bot_event_store().unwrap();
        for id in 100..130 {
            let body = request(id, id, policy.telegram_chat_id, &policy.gate_id, &policy.policy_hash);
            assert!(create_session(&mut db, &policy, &key, local(), None, &sign(&key, &body), &body).is_ok());
        }
        drop(db);
        let mut db = AuthorizationCoordinator::open_existing(&dir.path()).unwrap();
        let body = request(130, 130, policy.telegram_chat_id, &policy.gate_id, &policy.policy_hash);
        assert!(create_session(&mut db, &policy, &key, local(), None, &sign(&key, &body), &body).is_err());
    }
}
