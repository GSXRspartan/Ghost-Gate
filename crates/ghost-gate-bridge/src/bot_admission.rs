//! Telegram admission transport: the path from an authenticated bot event to a single
//! admitted member, and the trust boundary that keeps a browser out of it.
//!
//! Three primitives already existed and were verified in isolation, but nothing connected
//! them, so no real admission could happen. This module is that connection and nothing more:
//!
//!   * [`crate::bot_session_interface::create_session`] — HMAC-authenticated session creation.
//!   * [`crate::credential::TelegramProofContext`] — the Telegram-bound ownership challenge.
//!   * [`crate::authorization_coordinator`] — durable state and atomic single-use redemption.
//!
//! # The trust boundary
//!
//! The **bot** holds the HMAC key and reaches the bridge over loopback. Only the bot can create
//! a session, and only the bot can redeem one — redemption is the only operation that returns
//! the Telegram identity, so only the holder of the key can learn whom to admit.
//!
//! The **browser** holds one opaque session id and nothing else. It can ask for a challenge and
//! submit a proof. It cannot read the Telegram identity, cannot choose it, cannot create a
//! session, and cannot admit anyone: the browser-reachable operations never return identity and
//! never move a record to `Redeemed`.
//!
//! # Why the substate is supplied by the wallet but cannot be substituted
//!
//! The visitor chooses which output to stand on, so the substate id arrives from the browser.
//! It is bound into the signing challenge before the wallet ever sees it, so a wallet that signs
//! for output A cannot have that signature replayed against output B: the challenge, and
//! therefore the signature, differ. Chain state for the named output is then read by the bridge
//! from the indexer, never accepted from the page.

use std::{net::SocketAddr, str::FromStr, time::{SystemTime, UNIX_EPOCH}};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tari_template_lib_types::ResourceAddress;

use crate::authorization_coordinator::{
    Authorization, AuthorizationContext, AuthorizationCoordinator, AuthorizationState,
};
use crate::credential::{ChainReader, CredentialProofRequest, TelegramProofContext};

/// Domain for the bot's redemption request. Distinct from the session-creation domain so a
/// captured creation signature can never be replayed as a redemption, or the reverse.
const REDEEM_DOMAIN: &[u8] = b"ghost-gate/bot-redeem/v1\0POST\0/v1/bot/sessions/redeem\0";
const MAX_BODY: usize = 2048;
const MAX_SKEW_SECS: u64 = 60;

#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    /// Deliberately uniform. A caller learns that the operation was refused, never which of the
    /// session id, state, policy, signature or chain evidence was the reason.
    #[error("admission request refused")]
    Refused,
    #[error("admission storage unavailable")]
    Unavailable,
    /// The one case a visitor can act on: their proof was read and found wanting. The message
    /// comes from `CredentialRefusal`, which is documented to name only public quantities.
    #[error("{0}")]
    ProofRejected(String),
}

type Result<T> = std::result::Result<T, AdmissionError>;

fn now_unix() -> Result<u64> {
    SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| AdmissionError::Unavailable)
}

fn hex32(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).map_err(|_| AdmissionError::Refused)?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| AdmissionError::Refused)
}

/// Rebuild the server-owned proof context from durable state plus the one field the wallet
/// chooses. Every other field comes from the stored authorization, so a browser cannot move
/// the gate, the threshold, the network, the identity or the nonce.
fn proof_context(context: &AuthorizationContext, substate_id: &str) -> Result<TelegramProofContext> {
    if substate_id.is_empty() || substate_id.len() > 512 {
        return Err(AdmissionError::Refused);
    }
    // The resource is policy, so it comes from the stored authorization — never derived from the
    // substate the browser named. `CredentialVerifier` then refuses an output whose own resource
    // disagrees, which is how a wallet is stopped from proving the wrong asset.
    let resource = ResourceAddress::from_str(&context.resource)
        .map_err(|_| AdmissionError::Refused)?;
    Ok(TelegramProofContext {
        user_id: context.telegram_user_id,
        chat_id: context.telegram_chat_id,
        gate_id: context.gate_id.clone(),
        policy_hash: hex32(&context.policy_hash)?,
        network: context.network,
        resource,
        threshold: context.threshold,
        substate_id: substate_id.to_string(),
        issued_unix: context.issued_unix,
        expires_unix: context.expires_unix,
        nonce: hex32(&context.challenge_nonce)?,
    })
}

/// Load a record and require it to be in the expected state. Used instead of inspecting state at
/// the call sites so that "wrong state" and "no such session" produce the same refusal.
fn load_in_state(
    db: &mut AuthorizationCoordinator,
    session_id: &str,
    expected: AuthorizationState,
) -> Result<Authorization> {
    let authorization = db.get(session_id).map_err(|_| AdmissionError::Refused)?;
    if authorization.state != expected {
        return Err(AdmissionError::Refused);
    }
    Ok(authorization)
}

// ---------------------------------------------------------------------------------------
// Browser-reachable: challenge
// ---------------------------------------------------------------------------------------

/// What the wallet must sign, and when the opportunity closes.
#[derive(Debug, Serialize)]
pub struct ChallengeIssued {
    /// The exact string to hand to `tari_signOwnershipChallenge`.
    pub challenge: String,
    /// Echoed so the page can show a countdown. Not authority: the server re-checks expiry.
    pub expires_unix: u64,
    /// The nonce this challenge commits to, as the proof request must echo it.
    pub challenge_nonce: String,
    pub network: u8,
    pub gate_id: String,
}

/// Issue the signing challenge for one chosen output.
///
/// Returns no identity. Reachable by the browser holding the session id, and by nothing else:
/// the session id is 32 random bytes minted inside a transaction the bot authenticated.
pub fn challenge_for(
    db: &mut AuthorizationCoordinator,
    session_id: &str,
    substate_id: &str,
    now: u64,
) -> Result<ChallengeIssued> {
    let authorization = load_in_state(db, session_id, AuthorizationState::Created)?;
    let context = proof_context(&authorization.context, substate_id)?;
    let challenge = context
        .signing_challenge(now)
        .map_err(|_| AdmissionError::Refused)?;
    Ok(ChallengeIssued {
        challenge,
        expires_unix: authorization.context.expires_unix,
        challenge_nonce: authorization.context.challenge_nonce.clone(),
        network: authorization.context.network,
        gate_id: authorization.context.gate_id.clone(),
    })
}

// ---------------------------------------------------------------------------------------
// Browser-reachable: proof submission
// ---------------------------------------------------------------------------------------

/// The outcome a visitor is allowed to see: that the proof was accepted, and against which
/// public floor. No identity, no session material, no chat.
#[derive(Debug, Serialize)]
pub struct ProofAccepted {
    pub verified: bool,
    pub gate_id: String,
    pub attested_minimum: u64,
    pub required_minimum: u64,
}

/// Verify a Telegram-bound credential proof and durably record the result.
///
/// Order matters and is not negotiable: the signature and chain evidence are checked *before*
/// any state moves, and the state move itself is conditional on the full stored context, so two
/// concurrent submissions cannot both land.
pub async fn verify_proof(
    db: &mut AuthorizationCoordinator,
    reader: &impl ChainReader,
    session_id: &str,
    request: &CredentialProofRequest,
    now: u64,
) -> Result<ProofAccepted> {
    let authorization = load_in_state(db, session_id, AuthorizationState::Created)?;
    let context = proof_context(&authorization.context, &request.substate_id)?;

    // The gate the proof names must be the gate the bot opened the session for. Checked here as
    // well as inside `verify` so a mismatch is refused before any chain lookup is spent on it.
    if request.gate_id != authorization.context.gate_id {
        return Err(AdmissionError::Refused);
    }

    let receipt = context
        .verify(reader, request, now)
        .await
        .map_err(|refusal| AdmissionError::ProofRejected(refusal.to_string()))?;

    // Only now, with chain evidence and a verified signature in hand, does the record move.
    db.mark_verified_by_trusted_verifier(session_id, &authorization.context, &receipt.substate_id)
        .map_err(|_| AdmissionError::Refused)?;

    Ok(ProofAccepted {
        verified: true,
        gate_id: receipt.gate_id,
        attested_minimum: receipt.attested_minimum,
        required_minimum: receipt.required_minimum,
    })
}

// ---------------------------------------------------------------------------------------
// Bot-reachable: redemption
// ---------------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedeemRequest {
    session_id: String,
    sent_unix: u64,
}

/// Everything the bot needs to admit exactly one person, returned exactly once.
#[derive(Debug, Serialize)]
pub struct Admission {
    pub telegram_user_id: i64,
    pub telegram_chat_id: i64,
    pub gate_id: String,
    /// The output the admission stands on, for the audit record.
    pub wallet_output: String,
}

/// Atomically consume a verified authorization and return the identity to admit.
///
/// This is the only operation in the module that returns a Telegram identity, and it is gated on
/// the same loopback + HMAC conditions as session creation. It is single-use by construction:
/// the `Verified -> Redeemed` transition is a conditional update inside a transaction, so a
/// second call — concurrent or later, same process or another — cannot succeed.
pub fn redeem(
    db: &mut AuthorizationCoordinator,
    bot_key: &[u8; 32],
    peer: SocketAddr,
    origin: Option<&str>,
    signature_hex: &str,
    body: &[u8],
) -> Result<Admission> {
    if !peer.ip().is_loopback() || origin.is_some() || body.len() > MAX_BODY
        || signature_hex.len() != 64 || bot_key == &[0; 32] {
        return Err(AdmissionError::Refused);
    }
    let signature = hex::decode(signature_hex).map_err(|_| AdmissionError::Refused)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(bot_key).map_err(|_| AdmissionError::Refused)?;
    mac.update(REDEEM_DOMAIN);
    mac.update(body);
    mac.verify_slice(&signature).map_err(|_| AdmissionError::Refused)?;

    let request: RedeemRequest = serde_json::from_slice(body).map_err(|_| AdmissionError::Refused)?;
    let now = now_unix()?;
    if request.sent_unix.abs_diff(now) > MAX_SKEW_SECS {
        return Err(AdmissionError::Refused);
    }

    let authorization = load_in_state(db, &request.session_id, AuthorizationState::Verified)?;
    let output = authorization.wallet_output.clone().ok_or(AdmissionError::Refused)?;
    db.redeem(&request.session_id, &authorization.context, &output)
        .map_err(|_| AdmissionError::Refused)?;

    Ok(Admission {
        telegram_user_id: authorization.context.telegram_user_id,
        telegram_chat_id: authorization.context.telegram_chat_id,
        gate_id: authorization.context.gate_id.clone(),
        wallet_output: output,
    })
}

/// Sign a redemption body with the bot key. Exposed so the Telegram bot links against one
/// implementation of the wire format rather than reimplementing the domain separation.
pub fn sign_redeem_body(bot_key: &[u8; 32], body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(bot_key).expect("HMAC accepts any key length");
    mac.update(REDEEM_DOMAIN);
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bot_session_interface::{self, BotGatePolicy};
    use crate::credential::{
        ownership_proof_message, OwnershipProof, UtxoOnChain,
    };
    use rand::rng;
    use serde_json::json;
    use tari_crypto::keys::{PublicKey, SecretKey};
    use tari_crypto::ristretto::{RistrettoPublicKey, RistrettoSecretKey};
    use tari_crypto::signatures::{SchnorrSigChallenge, SchnorrSignature};
    use tari_crypto::tari_utilities::ByteArray;
    use tari_template_lib_types::UtxoAddress;

    const NETWORK: u8 = 0x26; // Esmeralda
    const CHAT: i64 = -1001234;
    const USER: i64 = 42;
    const THRESHOLD: u64 = 10_000_000;
    const BOT_KEY: [u8; 32] = [1; 32];

    struct TestDb(std::path::PathBuf);
    impl TestDb {
        fn new() -> Self {
            let mut nonce = [0u8; 16];
            rand::fill(&mut nonce);
            let path = std::env::temp_dir().join(format!("gg-admission-{}", hex::encode(nonce)));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> std::path::PathBuf { self.0.join("authorization.sqlite") }
        fn open(&self) -> AuthorizationCoordinator {
            AuthorizationCoordinator::open_existing(&self.path()).unwrap()
        }
    }
    impl Drop for TestDb {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }

    /// A chain that reports one output's real floor and spend key.
    struct FixedReader { promise: u64, auth_key: Option<[u8; 32]> }
    impl ChainReader for FixedReader {
        // Fully qualified: this module's `Result` alias fixes the error type to AdmissionError.
        async fn utxo(&self, _address: &UtxoAddress) -> std::result::Result<UtxoOnChain, String> {
            Ok(UtxoOnChain {
                minimum_value_promise: self.promise,
                auth_key: self.auth_key,
                verified: true,
                is_frozen: false,
            })
        }
    }

    fn resource(byte: u8) -> ResourceAddress {
        ResourceAddress::new(tari_template_lib_types::ObjectKey::from_array([byte; 32]))
    }

    fn substate_of(res: &ResourceAddress) -> String {
        format!(
            "utxo_{}_2c713522a4aaf79f2b219d869b5033d3d71d63c0537e5e0bbed2d717d8b2a67e",
            res.as_object_key()
        )
    }

    fn keypair() -> (RistrettoSecretKey, RistrettoPublicKey) {
        let k = RistrettoSecretKey::random(&mut rng());
        let p = RistrettoPublicKey::from_secret_key(&k);
        (k, p)
    }

    fn key_bytes(pk: &RistrettoPublicKey) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(pk.as_bytes());
        out
    }

    fn policy(res: &ResourceAddress) -> BotGatePolicy {
        BotGatePolicy {
            gate_id: "crypt".into(),
            policy_hash: "ab".repeat(32),
            network: NETWORK,
            resource: res.to_string(),
            threshold: THRESHOLD,
            telegram_chat_id: CHAT,
        }
    }

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    fn local() -> SocketAddr { "127.0.0.1:1234".parse().unwrap() }

    /// Create one authenticated bot session, exactly as the live bot would.
    fn open_session(db: &mut AuthorizationCoordinator, policy: &BotGatePolicy, update_id: i64) -> String {
        const CREATE_DOMAIN: &[u8] = b"ghost-gate/bot-session/v1\0POST\0/v1/bot/sessions\0";
        let body = serde_json::to_vec(&json!({
            "update_id": update_id, "telegram_user_id": USER, "telegram_chat_id": CHAT,
            "gate_id": policy.gate_id, "policy_hash": policy.policy_hash, "sent_unix": now(),
        })).unwrap();
        let mut mac = Hmac::<Sha256>::new_from_slice(&BOT_KEY).unwrap();
        mac.update(CREATE_DOMAIN);
        mac.update(&body);
        let signature = hex::encode(mac.finalize().into_bytes());
        bot_session_interface::create_session(db, policy, &BOT_KEY, local(), None, &signature, &body)
            .unwrap()
            .session_id
    }

    /// A genuine wallet submission: a real Schnorr signature over the framed message, with the
    /// challenge string the bridge actually issued.
    fn sign_proof(
        res: &ResourceAddress,
        substate: &str,
        challenge: &ChallengeIssued,
        secret: &RistrettoSecretKey,
        gate_id: &str,
    ) -> CredentialProofRequest {
        let message = ownership_proof_message(challenge.network, res, substate, &challenge.challenge);
        let signature = SchnorrSignature::<RistrettoPublicKey, RistrettoSecretKey, SchnorrSigChallenge>
            ::sign(secret, &message, &mut rng()).unwrap();
        let key = RistrettoPublicKey::from_secret_key(secret);
        CredentialProofRequest {
            gate_id: gate_id.to_string(),
            challenge_nonce: challenge.challenge_nonce.clone(),
            session_commitment: "11".repeat(32),
            substate_id: substate.to_string(),
            ownership: OwnershipProof {
                public_key: hex::encode(key.as_bytes()),
                public_nonce: hex::encode(signature.get_public_nonce().as_bytes()),
                signature: hex::encode(signature.get_signature().as_bytes()),
            },
        }
    }

    fn redeem_body(session_id: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({ "session_id": session_id, "sent_unix": now() })).unwrap()
    }

    // ===================================================================================
    // The acceptance test.
    // ===================================================================================

    #[tokio::test]
    async fn a_qualifying_wallet_is_admitted_exactly_once() {
        let dir = TestDb::new();
        let res = resource(7);
        let policy = policy(&res);
        let substate = substate_of(&res);
        let (secret, public) = keypair();
        let mut db = AuthorizationCoordinator::create_new(&dir.path()).unwrap();
        db.initialize_bot_event_store().unwrap();

        // 1. The bot authenticates a Telegram update and opens a session.
        let session = open_session(&mut db, &policy, 1);

        // 2. The browser asks what to sign. It learns no identity.
        let challenge = challenge_for(&mut db, &session, &substate, now()).unwrap();
        let wire = serde_json::to_value(&challenge).unwrap();
        assert!(wire.get("telegram_user_id").is_none(), "challenge must not carry identity");
        assert!(wire.get("telegram_chat_id").is_none());

        // 3. The wallet signs it. The chain says the output clears the threshold.
        let request = sign_proof(&res, &substate, &challenge, &secret, &policy.gate_id);
        let reader = FixedReader { promise: 50_000_000, auth_key: Some(key_bytes(&public)) };

        // 4. The bridge verifies signature AND chain evidence, then records it durably.
        let accepted = verify_proof(&mut db, &reader, &session, &request, now()).await.unwrap();
        assert!(accepted.verified);
        assert_eq!(accepted.attested_minimum, 50_000_000, "the floor is the chain's, not the request's");
        assert_eq!(accepted.required_minimum, THRESHOLD);
        let outcome = serde_json::to_value(&accepted).unwrap();
        assert!(outcome.get("telegram_user_id").is_none(), "proof outcome must not carry identity");

        // 5. Only the bot, holding the key, can redeem — and learns whom to admit.
        let body = redeem_body(&session);
        let admission = redeem(&mut db, &BOT_KEY, local(), None, &sign_redeem_body(&BOT_KEY, &body), &body).unwrap();
        assert_eq!(admission.telegram_user_id, USER);
        assert_eq!(admission.telegram_chat_id, CHAT);
        assert_eq!(admission.gate_id, policy.gate_id);
        assert_eq!(admission.wallet_output, substate);

        // 6. The authorization is spent. A second admission is impossible.
        let again = redeem_body(&session);
        assert!(redeem(&mut db, &BOT_KEY, local(), None, &sign_redeem_body(&BOT_KEY, &again), &again).is_err(),
            "an authorization must admit at most one person");
        assert_eq!(db.get(&session).unwrap().state, AuthorizationState::Redeemed);
    }

    #[tokio::test]
    async fn an_unqualified_wallet_is_refused_and_never_becomes_redeemable() {
        let dir = TestDb::new();
        let res = resource(7);
        let policy = policy(&res);
        let substate = substate_of(&res);
        let (secret, public) = keypair();
        let mut db = AuthorizationCoordinator::create_new(&dir.path()).unwrap();
        db.initialize_bot_event_store().unwrap();
        let session = open_session(&mut db, &policy, 2);
        let challenge = challenge_for(&mut db, &session, &substate, now()).unwrap();
        let request = sign_proof(&res, &substate, &challenge, &secret, &policy.gate_id);

        // The signature is genuine; the holding is one unit short of the gate.
        let reader = FixedReader { promise: THRESHOLD - 1, auth_key: Some(key_bytes(&public)) };
        let refusal = verify_proof(&mut db, &reader, &session, &request, now()).await;
        assert!(matches!(refusal, Err(AdmissionError::ProofRejected(_))));

        // The record never left Created, so redemption cannot find anything to spend.
        assert_eq!(db.get(&session).unwrap().state, AuthorizationState::Created);
        let body = redeem_body(&session);
        assert!(redeem(&mut db, &BOT_KEY, local(), None, &sign_redeem_body(&BOT_KEY, &body), &body).is_err(),
            "an unverified session must never admit");
    }

    #[tokio::test]
    async fn a_browser_cannot_redeem_or_forge_the_bot() {
        let dir = TestDb::new();
        let res = resource(7);
        let policy = policy(&res);
        let substate = substate_of(&res);
        let (secret, public) = keypair();
        let mut db = AuthorizationCoordinator::create_new(&dir.path()).unwrap();
        db.initialize_bot_event_store().unwrap();
        let session = open_session(&mut db, &policy, 3);
        let challenge = challenge_for(&mut db, &session, &substate, now()).unwrap();
        let request = sign_proof(&res, &substate, &challenge, &secret, &policy.gate_id);
        let reader = FixedReader { promise: 50_000_000, auth_key: Some(key_bytes(&public)) };
        verify_proof(&mut db, &reader, &session, &request, now()).await.unwrap();

        let body = redeem_body(&session);
        let good = sign_redeem_body(&BOT_KEY, &body);

        // Holding the session id is not holding the bot key: the bridge always verifies against
        // its own configured key, so a body signed with any other key fails to authenticate.
        assert!(redeem(&mut db, &BOT_KEY, local(), None, &sign_redeem_body(&[2; 32], &body), &body).is_err(),
            "a signature from a key the bridge is not configured with must not redeem");
        assert!(redeem(&mut db, &BOT_KEY, local(), None, "", &body).is_err(), "an empty signature must not redeem");
        // A browser request carries an Origin; the bot's never does.
        assert!(redeem(&mut db, &BOT_KEY, local(), Some("https://ghostgate.boo"), &good, &body).is_err(),
            "a browser-originated request must not redeem");
        // Off-host callers are refused even with a valid signature.
        assert!(redeem(&mut db, &BOT_KEY, "192.0.2.9:443".parse().unwrap(), None, &good, &body).is_err(),
            "a non-loopback peer must not redeem");
        // An all-zero key is never a configured key.
        assert!(redeem(&mut db, &[0; 32], local(), None, &sign_redeem_body(&[0; 32], &body), &body).is_err());

        // After all of that the authorization is still spendable exactly once by the real bot.
        assert_eq!(db.get(&session).unwrap().state, AuthorizationState::Verified);
        assert!(redeem(&mut db, &BOT_KEY, local(), None, &good, &body).is_ok());
    }

    #[tokio::test]
    async fn a_signature_for_one_output_cannot_be_moved_to_another() {
        let dir = TestDb::new();
        let res = resource(7);
        let policy = policy(&res);
        let mine = substate_of(&res);
        let other = format!(
            "utxo_{}_aaaa3522a4aaf79f2b219d869b5033d3d71d63c0537e5e0bbed2d717d8b2a67e",
            res.as_object_key()
        );
        let (secret, public) = keypair();
        let mut db = AuthorizationCoordinator::create_new(&dir.path()).unwrap();
        db.initialize_bot_event_store().unwrap();
        let session = open_session(&mut db, &policy, 4);

        // The wallet signs the challenge bound to `mine`...
        let challenge = challenge_for(&mut db, &session, &mine, now()).unwrap();
        let mut request = sign_proof(&res, &mine, &challenge, &secret, &policy.gate_id);
        // ...and the submission is then re-pointed at a different output.
        request.substate_id = other;

        let reader = FixedReader { promise: 50_000_000, auth_key: Some(key_bytes(&public)) };
        assert!(verify_proof(&mut db, &reader, &session, &request, now()).await.is_err(),
            "the challenge commits to the output, so the signature cannot be moved");
        assert_eq!(db.get(&session).unwrap().state, AuthorizationState::Created);
    }

    #[tokio::test]
    async fn a_proof_naming_another_gate_is_refused() {
        let dir = TestDb::new();
        let res = resource(7);
        let policy = policy(&res);
        let substate = substate_of(&res);
        let (secret, public) = keypair();
        let mut db = AuthorizationCoordinator::create_new(&dir.path()).unwrap();
        db.initialize_bot_event_store().unwrap();
        let session = open_session(&mut db, &policy, 5);
        let challenge = challenge_for(&mut db, &session, &substate, now()).unwrap();
        let request = sign_proof(&res, &substate, &challenge, &secret, "a-different-gate");
        let reader = FixedReader { promise: 50_000_000, auth_key: Some(key_bytes(&public)) };
        assert!(verify_proof(&mut db, &reader, &session, &request, now()).await.is_err());
        assert_eq!(db.get(&session).unwrap().state, AuthorizationState::Created);
    }

    #[tokio::test]
    async fn an_unrelated_key_cannot_prove_someone_elses_output() {
        let dir = TestDb::new();
        let res = resource(7);
        let policy = policy(&res);
        let substate = substate_of(&res);
        let (_owner_secret, owner_public) = keypair();
        let (attacker_secret, _attacker_public) = keypair();
        let mut db = AuthorizationCoordinator::create_new(&dir.path()).unwrap();
        db.initialize_bot_event_store().unwrap();
        let session = open_session(&mut db, &policy, 6);
        let challenge = challenge_for(&mut db, &session, &substate, now()).unwrap();

        // Signed by the attacker, but the chain says the output is spendable by the owner.
        let request = sign_proof(&res, &substate, &challenge, &attacker_secret, &policy.gate_id);
        let reader = FixedReader { promise: 50_000_000, auth_key: Some(key_bytes(&owner_public)) };
        assert!(verify_proof(&mut db, &reader, &session, &request, now()).await.is_err(),
            "the on-chain key is the verification key, never the self-reported one");
        assert_eq!(db.get(&session).unwrap().state, AuthorizationState::Created);
    }

    #[tokio::test]
    async fn a_verified_authorization_survives_a_restart_and_then_admits() {
        let dir = TestDb::new();
        let res = resource(7);
        let policy = policy(&res);
        let substate = substate_of(&res);
        let (secret, public) = keypair();
        let session = {
            let mut db = AuthorizationCoordinator::create_new(&dir.path()).unwrap();
            db.initialize_bot_event_store().unwrap();
            let session = open_session(&mut db, &policy, 7);
            let challenge = challenge_for(&mut db, &session, &substate, now()).unwrap();
            let request = sign_proof(&res, &substate, &challenge, &secret, &policy.gate_id);
            let reader = FixedReader { promise: 50_000_000, auth_key: Some(key_bytes(&public)) };
            verify_proof(&mut db, &reader, &session, &request, now()).await.unwrap();
            session
        }; // the process holding the database goes away here

        let mut db = dir.open();
        assert_eq!(db.get(&session).unwrap().state, AuthorizationState::Verified,
            "verification must outlive the process that performed it");
        let body = redeem_body(&session);
        let admission = redeem(&mut db, &BOT_KEY, local(), None, &sign_redeem_body(&BOT_KEY, &body), &body).unwrap();
        assert_eq!(admission.telegram_user_id, USER);

        // And the spend is durable too.
        drop(db);
        let mut db = dir.open();
        assert_eq!(db.get(&session).unwrap().state, AuthorizationState::Redeemed);
    }

    #[tokio::test]
    async fn concurrent_redemption_admits_exactly_one() {
        let dir = TestDb::new();
        let res = resource(7);
        let policy = policy(&res);
        let substate = substate_of(&res);
        let (secret, public) = keypair();
        let mut db = AuthorizationCoordinator::create_new(&dir.path()).unwrap();
        db.initialize_bot_event_store().unwrap();
        let session = open_session(&mut db, &policy, 8);
        let challenge = challenge_for(&mut db, &session, &substate, now()).unwrap();
        let request = sign_proof(&res, &substate, &challenge, &secret, &policy.gate_id);
        let reader = FixedReader { promise: 50_000_000, auth_key: Some(key_bytes(&public)) };
        verify_proof(&mut db, &reader, &session, &request, now()).await.unwrap();
        drop(db);

        // Eight independent connections race to spend the same authorization.
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let path = dir.path();
            let session = session.clone();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                let mut db = AuthorizationCoordinator::open_existing(&path).unwrap();
                let body = redeem_body(&session);
                let signature = sign_redeem_body(&BOT_KEY, &body);
                barrier.wait();
                redeem(&mut db, &BOT_KEY, local(), None, &signature, &body).is_ok()
            }));
        }
        let wins = threads.into_iter().filter(|_| true)
            .map(|t| t.join().unwrap())
            .filter(|ok| *ok)
            .count();
        assert_eq!(wins, 1, "exactly one concurrent redemption may succeed, got {wins}");

        let mut db = dir.open();
        assert_eq!(db.get(&session).unwrap().state, AuthorizationState::Redeemed);
    }

    #[tokio::test]
    async fn a_proof_cannot_be_submitted_twice_against_one_session() {
        let dir = TestDb::new();
        let res = resource(7);
        let policy = policy(&res);
        let substate = substate_of(&res);
        let (secret, public) = keypair();
        let mut db = AuthorizationCoordinator::create_new(&dir.path()).unwrap();
        db.initialize_bot_event_store().unwrap();
        let session = open_session(&mut db, &policy, 9);
        let challenge = challenge_for(&mut db, &session, &substate, now()).unwrap();
        let request = sign_proof(&res, &substate, &challenge, &secret, &policy.gate_id);
        let reader = FixedReader { promise: 50_000_000, auth_key: Some(key_bytes(&public)) };

        assert!(verify_proof(&mut db, &reader, &session, &request, now()).await.is_ok());
        // The record has left Created, so the identical submission no longer applies.
        assert!(verify_proof(&mut db, &reader, &session, &request, now()).await.is_err());
        // And a challenge can no longer be drawn for it either.
        assert!(challenge_for(&mut db, &session, &substate, now()).is_err());
    }

    #[test]
    fn an_unknown_session_is_refused_without_revealing_which_check_failed() {
        let dir = TestDb::new();
        let mut db = AuthorizationCoordinator::create_new(&dir.path()).unwrap();
        db.initialize_bot_event_store().unwrap();
        let unknown = "ab".repeat(32);
        assert!(challenge_for(&mut db, &unknown, "utxo_x", now()).is_err());
        let body = redeem_body(&unknown);
        assert!(redeem(&mut db, &BOT_KEY, local(), None, &sign_redeem_body(&BOT_KEY, &body), &body).is_err());
    }

    #[test]
    fn a_creation_signature_cannot_be_replayed_as_a_redemption() {
        const CREATE_DOMAIN: &[u8] = b"ghost-gate/bot-session/v1\0POST\0/v1/bot/sessions\0";
        let body = br#"{"session_id":"x","sent_unix":0}"#;
        let mut mac = Hmac::<Sha256>::new_from_slice(&BOT_KEY).unwrap();
        mac.update(CREATE_DOMAIN);
        mac.update(body);
        let creation_signature = hex::encode(mac.finalize().into_bytes());
        assert_ne!(creation_signature, sign_redeem_body(&BOT_KEY, body),
            "the two operations must be domain-separated");
    }
}
