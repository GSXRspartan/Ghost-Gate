//! Dedicated SQLite authorization coordinator. No HTTP, Telegram, or registry access.
//!
//! The caller must authenticate the Telegram identity and independently verify the wallet proof
//! before invoking `mark_verified_by_trusted_verifier`. Never expose that operation to a browser.
//! SQLite transactions and conditional updates serialize state changes across connections. Use a
//! private directory on a local filesystem with reliable SQLite locking; see the M4-B1 runbook.

use std::{fs::OpenOptions, path::Path};

use diesel::{connection::SimpleConnection, prelude::*, sql_types::{Nullable, Text}};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationContext {
    pub telegram_user_id: i64,
    pub telegram_chat_id: i64,
    pub gate_id: String,
    pub policy_hash: String,
    pub network: u8,
    pub resource: String,
    pub threshold: u64,
    pub challenge_nonce: String,
    pub issued_unix: u64,
    pub expires_unix: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Authorization {
    pub session_id: String,
    pub context: AuthorizationContext,
    pub wallet_output: Option<String>,
    pub state: AuthorizationState,
}

impl std::fmt::Debug for Authorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authorization").field("state", &self.state).finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationState { Created, Verified, Redeemed, Expired }

#[derive(Debug, thiserror::Error)]
pub enum CoordinatorError {
    #[error("authorization storage unavailable or invalid")]
    Storage,
    #[error("invalid authorization request or transition")]
    Refused,
}

type Result<T> = std::result::Result<T, CoordinatorError>;

#[derive(QueryableByName)]
struct Stored {
    #[diesel(sql_type = Text)] context: String,
    #[diesel(sql_type = Nullable<Text>)] wallet_output: Option<String>,
    #[diesel(sql_type = Text)] state: String,
}

#[derive(QueryableByName)]
struct CheckValue { #[diesel(sql_type = Text)] result: String }
#[derive(QueryableByName)]
struct Version { #[diesel(sql_type = diesel::sql_types::Integer)] user_version: i32 }
#[derive(QueryableByName)]
struct ApplicationId { #[diesel(sql_type = diesel::sql_types::Integer)] application_id: i32 }
pub struct AuthorizationCoordinator { connection: SqliteConnection }

impl AuthorizationCoordinator {
    /// Initialize a new, dedicated database. Never overwrites an existing file, even an empty one.
    pub fn create_new(path: &Path) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
        options.open(path).map_err(|_| CoordinatorError::Storage)?;
        let mut db = Self::connect(path)?;
        db.connection.batch_execute(
            "BEGIN IMMEDIATE;
             CREATE TABLE authorizations (
                 session_id TEXT PRIMARY KEY NOT NULL,
                 context TEXT NOT NULL,
                 wallet_output TEXT,
                 state TEXT NOT NULL CHECK(state IN ('CREATED','VERIFIED','REDEEMED','EXPIRED'))
             );
             PRAGMA application_id = 1195852081;
             PRAGMA user_version = 1;
             COMMIT;"
        ).map_err(|_| CoordinatorError::Storage)?;
        db.validate()?;
        Ok(db)
    }

    /// Open only an initialized, compatible database. Never creates or repairs one.
    pub fn open_existing(path: &Path) -> Result<Self> {
        if !path.is_file() || std::fs::metadata(path).map_err(|_| CoordinatorError::Storage)?.len() == 0 {
            return Err(CoordinatorError::Storage);
        }
        let mut db = Self::connect(path)?;
        db.validate()?;
        Ok(db)
    }

    fn connect(path: &Path) -> Result<Self> {
        // Diesel normally requests SQLITE_OPEN_CREATE. SQLite's `mode=rw` URI overrides that
        // flag so a removed or missing database is never silently recreated during open.
        let absolute = if path.is_absolute() { path.to_path_buf() } else {
            std::env::current_dir().map_err(|_| CoordinatorError::Storage)?.join(path)
        };
        let name = absolute.to_str().ok_or(CoordinatorError::Storage)?.replace('\\', "/");
        let mut uri = String::from("file:");
        for byte in name.bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b':' | b'-' | b'_' | b'.' | b'~') {
                uri.push(byte as char);
            } else {
                uri.push_str(&format!("%{byte:02X}"));
            }
        }
        uri.push_str("?mode=rw");
        let mut connection = SqliteConnection::establish(&uri).map_err(|_| CoordinatorError::Storage)?;
        connection.batch_execute("PRAGMA busy_timeout=5000; PRAGMA synchronous=FULL;")
            .map_err(|_| CoordinatorError::Storage)?;
        Ok(Self { connection })
    }

    fn validate(&mut self) -> Result<()> {
        let check: CheckValue = diesel::sql_query("SELECT quick_check AS result FROM pragma_quick_check")
            .get_result(&mut self.connection).map_err(|_| CoordinatorError::Storage)?;
        let version: Version = diesel::sql_query("PRAGMA user_version")
            .get_result(&mut self.connection).map_err(|_| CoordinatorError::Storage)?;
        let application: ApplicationId = diesel::sql_query("PRAGMA application_id")
            .get_result(&mut self.connection).map_err(|_| CoordinatorError::Storage)?;
        if check.result != "ok" || version.user_version != 1 || application.application_id != 1195852081 {
            return Err(CoordinatorError::Storage);
        }
        // Force SQLite to parse the exact required columns before allowing operations.
        diesel::sql_query("SELECT session_id, context, wallet_output, state FROM authorizations LIMIT 0")
            .execute(&mut self.connection).map_err(|_| CoordinatorError::Storage)?;
        Ok(())
    }

    /// Create a random session and challenge nonce. Identity and policy must be server-sourced.
    pub fn issue(&mut self, mut context: AuthorizationContext) -> Result<Authorization> {
        context.challenge_nonce = random_hex();
        validate_context(&context)?;
        let now = now_unix()?;
        if now < context.issued_unix || now >= context.expires_unix { return Err(CoordinatorError::Refused); }
        let session_id = random_hex();
        let encoded = serde_json::to_string(&context).map_err(|_| CoordinatorError::Storage)?;
        diesel::sql_query("INSERT INTO authorizations (session_id, context, wallet_output, state) VALUES (?, ?, NULL, 'CREATED')")
            .bind::<Text, _>(&session_id).bind::<Text, _>(&encoded)
            .execute(&mut self.connection).map_err(|_| CoordinatorError::Storage)?;
        Ok(Authorization { session_id, context, wallet_output: None, state: AuthorizationState::Created })
    }

    pub fn get(&mut self, session_id: &str) -> Result<Authorization> {
        valid_id(session_id)?;
        let row: Stored = diesel::sql_query("SELECT context, wallet_output, state FROM authorizations WHERE session_id = ?")
            .bind::<Text, _>(session_id).get_result(&mut self.connection).map_err(|_| CoordinatorError::Storage)?;
        let context: AuthorizationContext = serde_json::from_str(&row.context).map_err(|_| CoordinatorError::Storage)?;
        validate_context(&context).map_err(|_| CoordinatorError::Storage)?;
        let state = match row.state.as_str() {
            "CREATED" => AuthorizationState::Created, "VERIFIED" => AuthorizationState::Verified,
            "REDEEMED" => AuthorizationState::Redeemed, "EXPIRED" => AuthorizationState::Expired,
            _ => return Err(CoordinatorError::Storage),
        };
        if (state == AuthorizationState::Verified || state == AuthorizationState::Redeemed) && row.wallet_output.as_deref().is_none_or(str::is_empty) {
            return Err(CoordinatorError::Storage);
        }
        Ok(Authorization { session_id: session_id.into(), context, wallet_output: row.wallet_output, state })
    }

    /// Trusted bridge-internal operation, after the caller has checked chain evidence and signature.
    /// This type offers no browser-facing API and does not itself verify a wallet proof. The future
    /// integration must call this only on successful server-side verification.
    #[allow(dead_code)]
    pub(crate) fn mark_verified_by_trusted_verifier(&mut self, session_id: &str, expected: &AuthorizationContext, wallet_output: &str) -> Result<()> {
        if wallet_output.is_empty() || wallet_output.len() > 512 { return Err(CoordinatorError::Refused); }
        self.transition(session_id, expected, None, Some(wallet_output), "CREATED", "VERIFIED", now_unix()?)
    }

    /// Atomically consume a verified record only for the full, independently expected context and output.
    pub fn redeem(&mut self, session_id: &str, expected: &AuthorizationContext, wallet_output: &str) -> Result<()> {
        self.transition(session_id, expected, Some(wallet_output), None, "VERIFIED", "REDEEMED", now_unix()?)
    }

    fn transition(&mut self, session_id: &str, expected: &AuthorizationContext, existing_output: Option<&str>, new_output: Option<&str>, from: &str, to: &str, now: u64) -> Result<()> {
        valid_id(session_id)?;
        validate_context(expected)?;
        if now < expected.issued_unix || now >= expected.expires_unix { return Err(CoordinatorError::Refused); }
        let encoded = serde_json::to_string(expected).map_err(|_| CoordinatorError::Storage)?;
        self.connection.immediate_transaction::<_, diesel::result::Error, _>(|connection| {
            // Re-read the clock after the write lock is held: waiting for a competing transaction
            // must never let an authorization cross its expiry and then be redeemed.
            let locked_now = now_unix().map_err(|_| diesel::result::Error::RollbackTransaction)?.max(now);
            if locked_now < expected.issued_unix || locked_now >= expected.expires_unix {
                return Err(diesel::result::Error::RollbackTransaction);
            }
            let changed = diesel::sql_query(
                "UPDATE authorizations SET state = ?, wallet_output = COALESCE(?, wallet_output)
                 WHERE session_id = ? AND state = ? AND context = ? AND (? IS NULL OR wallet_output = ?)"
            ).bind::<Text, _>(to).bind::<Nullable<Text>, _>(new_output)
                .bind::<Text, _>(session_id).bind::<Text, _>(from).bind::<Text, _>(&encoded)
                .bind::<Nullable<Text>, _>(existing_output).bind::<Nullable<Text>, _>(existing_output)
                .execute(connection)?;
            if changed == 1 { Ok(()) } else { Err(diesel::result::Error::RollbackTransaction) }
        }).map_err(|e| if matches!(e, diesel::result::Error::RollbackTransaction) { CoordinatorError::Refused } else { CoordinatorError::Storage })
    }

    /// Persist expiration as a terminal state. Unexpired records are untouched.
    pub fn expire(&mut self, session_id: &str, expected: &AuthorizationContext) -> Result<()> {
        self.expire_at(session_id, expected, now_unix()?)
    }

    fn expire_at(&mut self, session_id: &str, expected: &AuthorizationContext, now: u64) -> Result<()> {
        valid_id(session_id)?;
        validate_context(expected)?;
        if now < expected.expires_unix { return Err(CoordinatorError::Refused); }
        let encoded = serde_json::to_string(expected).map_err(|_| CoordinatorError::Storage)?;
        let changed = diesel::sql_query("UPDATE authorizations SET state = 'EXPIRED' WHERE session_id = ? AND context = ? AND state IN ('CREATED', 'VERIFIED')")
            .bind::<Text, _>(session_id).bind::<Text, _>(&encoded).execute(&mut self.connection)
            .map_err(|_| CoordinatorError::Storage)?;
        if changed == 1 { Ok(()) } else { Err(CoordinatorError::Refused) }
    }
}

fn random_hex() -> String { let mut bytes = [0u8; 32]; rand::fill(&mut bytes); hex::encode(bytes) }
fn now_unix() -> Result<u64> {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs()).map_err(|_| CoordinatorError::Storage)
}
fn valid_id(id: &str) -> Result<()> {
    if id.len() == 64 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) { Ok(()) } else { Err(CoordinatorError::Refused) }
}
fn validate_context(c: &AuthorizationContext) -> Result<()> {
    if c.telegram_user_id <= 0 || c.telegram_chat_id >= 0 || c.gate_id.is_empty() || c.gate_id.len() > 64
        || c.resource.is_empty() || c.resource.len() > 256 || c.threshold == 0
        || c.issued_unix >= c.expires_unix || c.expires_unix - c.issued_unix > 600
        || valid_id(&c.policy_hash).is_err() || valid_id(&c.challenge_nonce).is_err() {
        return Err(CoordinatorError::Refused);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    struct TestDb(std::path::PathBuf);
    impl TestDb {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("gg-auth-test-{}", random_hex()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> std::path::PathBuf { self.0.join("auth.sqlite") }
    }
    impl Drop for TestDb {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }
    fn context() -> AuthorizationContext {
        let now = now_unix().unwrap();
        AuthorizationContext {
            telegram_user_id: 42, telegram_chat_id: -1001234, gate_id: "Crypt".into(),
            policy_hash: "12".repeat(32), network: 38, resource: "resource_test".into(),
            threshold: 100_000_000, challenge_nonce: String::new(), issued_unix: now, expires_unix: now + 180,
        }
    }
    fn create() -> (TestDb, Authorization) {
        let dir = TestDb::new();
        let mut db = AuthorizationCoordinator::create_new(&dir.path()).unwrap();
        let auth = db.issue(context()).unwrap();
        (dir, auth)
    }
    fn verify(db: &mut AuthorizationCoordinator, auth: &Authorization) {
        db.mark_verified_by_trusted_verifier(&auth.session_id, &auth.context, "utxo_test").unwrap();
    }

    #[test]
    fn created_and_verified_records_survive_reopening() {
        let (dir, auth) = create();
        assert!(!format!("{auth:?}").contains(&auth.session_id));
        let mut db = AuthorizationCoordinator::open_existing(&dir.path()).unwrap();
        assert_eq!(db.get(&auth.session_id).unwrap(), auth);
        verify(&mut db, &auth);
        drop(db);
        let mut reopened = AuthorizationCoordinator::open_existing(&dir.path()).unwrap();
        let saved = reopened.get(&auth.session_id).unwrap();
        assert_eq!(saved.state, AuthorizationState::Verified);
        assert_eq!(saved.wallet_output.as_deref(), Some("utxo_test"));
        assert_ne!(auth.session_id, auth.context.challenge_nonce);
    }

    #[test]
    fn unverified_expired_and_replayed_authorizations_fail_closed() {
        let (dir, auth) = create();
        let mut db = AuthorizationCoordinator::open_existing(&dir.path()).unwrap();
        assert!(db.redeem(&auth.session_id, &auth.context, "utxo_test").is_err());
        assert!(db.transition(&auth.session_id, &auth.context, None, Some("utxo_test"), "CREATED", "VERIFIED", auth.context.expires_unix).is_err());
        verify(&mut db, &auth);
        assert!(db.transition(&auth.session_id, &auth.context, Some("utxo_test"), None, "VERIFIED", "REDEEMED", auth.context.expires_unix).is_err());
        db.redeem(&auth.session_id, &auth.context, "utxo_test").unwrap();
        assert!(db.redeem(&auth.session_id, &auth.context, "utxo_test").is_err());
        assert!(db.mark_verified_by_trusted_verifier(&auth.session_id, &auth.context, "utxo_test").is_err());
    }

    #[test]
    fn wrong_identity_chat_and_authorization_context_are_rejected() {
        let (dir, auth) = create();
        let mut db = AuthorizationCoordinator::open_existing(&dir.path()).unwrap();
        verify(&mut db, &auth);
        let mut variants = Vec::new();
        let mut c = auth.context.clone(); c.telegram_user_id += 1; variants.push(c);
        let mut c = auth.context.clone(); c.telegram_chat_id -= 1; variants.push(c);
        let mut c = auth.context.clone(); c.gate_id = "different".into(); variants.push(c);
        let mut c = auth.context.clone(); c.policy_hash = "34".repeat(32); variants.push(c);
        let mut c = auth.context.clone(); c.network ^= 1; variants.push(c);
        let mut c = auth.context.clone(); c.resource = "other".into(); variants.push(c);
        let mut c = auth.context.clone(); c.threshold += 1; variants.push(c);
        for c in variants { assert!(db.redeem(&auth.session_id, &c, "utxo_test").is_err()); }
        assert!(db.redeem(&auth.session_id, &auth.context, "other_output").is_err());
        assert_eq!(db.get(&auth.session_id).unwrap().state, AuthorizationState::Verified);
        db.redeem(&auth.session_id, &auth.context, "utxo_test").unwrap();
    }

    #[test]
    fn simultaneous_connections_redeem_exactly_once() {
        let (dir, auth) = create();
        verify(&mut AuthorizationCoordinator::open_existing(&dir.path()).unwrap(), &auth);
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let path = dir.path(); let auth = auth.clone(); let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                let mut db = AuthorizationCoordinator::open_existing(&path).unwrap();
                barrier.wait();
                db.redeem(&auth.session_id, &auth.context, "utxo_test").is_ok()
            }));
        }
        assert_eq!(handles.into_iter().map(|h| h.join().unwrap()).filter(|success| *success).count(), 1);
        assert_eq!(AuthorizationCoordinator::open_existing(&dir.path()).unwrap().get(&auth.session_id).unwrap().state, AuthorizationState::Redeemed);
    }

    #[test]
    fn child_process_redeem() {
        let Ok(dir) = std::env::var("GG_COORDINATOR_CHILD_DIR") else { return };
        let worker = std::env::var("GG_COORDINATOR_CHILD_ID").unwrap();
        let path = std::path::PathBuf::from(&dir);
        let context: AuthorizationContext = serde_json::from_str(&std::env::var("GG_COORDINATOR_CHILD_CONTEXT").unwrap()).unwrap();
        let session = std::env::var("GG_COORDINATOR_CHILD_SESSION").unwrap();
        let mut db = AuthorizationCoordinator::open_existing(&path.join("auth.sqlite")).unwrap();
        std::fs::write(path.join(format!("ready-{worker}")), b"ready").unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !path.join("start").exists() {
            assert!(std::time::Instant::now() < deadline, "parent did not start race");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if db.redeem(&session, &context, "utxo_test").is_ok() { println!("GG_COORDINATOR_REDEEMED"); }
    }

    #[test]
    fn separate_processes_redeem_exactly_once() {
        let (dir, auth) = create();
        verify(&mut AuthorizationCoordinator::open_existing(&dir.path()).unwrap(), &auth);
        let mut children = Vec::new();
        for worker in 0..2 {
            children.push(std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "authorization_coordinator::tests::child_process_redeem", "--nocapture"])
                .env("GG_COORDINATOR_CHILD_DIR", &dir.0)
                .env("GG_COORDINATOR_CHILD_ID", worker.to_string())
                .env("GG_COORDINATOR_CHILD_CONTEXT", serde_json::to_string(&auth.context).unwrap())
                .env("GG_COORDINATOR_CHILD_SESSION", &auth.session_id)
                .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped())
                .spawn().unwrap());
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !(dir.0.join("ready-0").exists() && dir.0.join("ready-1").exists()) {
            assert!(std::time::Instant::now() < deadline, "children did not reach the race");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        std::fs::write(dir.0.join("start"), b"go").unwrap();
        let outputs: Vec<_> = children.into_iter().map(|child| child.wait_with_output().unwrap()).collect();
        assert!(outputs.iter().all(|output| output.status.success()));
        assert_eq!(outputs.iter().filter(|output| String::from_utf8_lossy(&output.stdout).contains("GG_COORDINATOR_REDEEMED")).count(), 1);
    }

    #[test]
    fn abandoned_transaction_rolls_back_on_connection_close() {
        let (dir, auth) = create();
        let mut db = AuthorizationCoordinator::open_existing(&dir.path()).unwrap();
        verify(&mut db, &auth);
        db.connection.batch_execute("BEGIN IMMEDIATE; UPDATE authorizations SET state = 'REDEEMED';").unwrap();
        drop(db);
        let mut reopened = AuthorizationCoordinator::open_existing(&dir.path()).unwrap();
        assert_eq!(reopened.get(&auth.session_id).unwrap().state, AuthorizationState::Verified);
        reopened.redeem(&auth.session_id, &auth.context, "utxo_test").unwrap();
    }

    #[test]
    fn child_process_interrupted_transaction() {
        let Ok(dir) = std::env::var("GG_COORDINATOR_CRASH_DIR") else { return };
        let mut db = AuthorizationCoordinator::open_existing(&std::path::Path::new(&dir).join("auth.sqlite")).unwrap();
        db.connection.batch_execute("BEGIN IMMEDIATE; UPDATE authorizations SET state = 'REDEEMED';").unwrap();
        std::fs::write(std::path::Path::new(&dir).join("transaction-open"), b"open").unwrap();
        // Simulate abrupt process termination: do not run destructors or commit.
        std::process::exit(0);
    }

    #[test]
    fn process_exit_during_transaction_does_not_commit_redemption() {
        let (dir, auth) = create();
        verify(&mut AuthorizationCoordinator::open_existing(&dir.path()).unwrap(), &auth);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "authorization_coordinator::tests::child_process_interrupted_transaction"])
            .env("GG_COORDINATOR_CRASH_DIR", &dir.0)
            .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
            .status().unwrap();
        assert!(status.success());
        assert!(dir.0.join("transaction-open").exists(), "child must reach the uncommitted update");
        let mut reopened = AuthorizationCoordinator::open_existing(&dir.path()).unwrap();
        assert_eq!(reopened.get(&auth.session_id).unwrap().state, AuthorizationState::Verified);
        reopened.redeem(&auth.session_id, &auth.context, "utxo_test").unwrap();
    }

    #[test]
    fn public_redeem_refuses_an_expired_verified_record() {
        let (dir, auth) = create();
        let mut db = AuthorizationCoordinator::open_existing(&dir.path()).unwrap();
        verify(&mut db, &auth);
        // Arrange a representative record that expired before this test, without sleeping.
        let mut expired = auth.context.clone();
        expired.issued_unix = now_unix().unwrap() - 2;
        expired.expires_unix = now_unix().unwrap() - 1;
        let encoded = serde_json::to_string(&expired).unwrap();
        diesel::sql_query("UPDATE authorizations SET context = ? WHERE session_id = ?")
            .bind::<Text, _>(&encoded).bind::<Text, _>(&auth.session_id)
            .execute(&mut db.connection).unwrap();
        assert!(db.redeem(&auth.session_id, &expired, "utxo_test").is_err());
        assert_eq!(db.get(&auth.session_id).unwrap().state, AuthorizationState::Verified);
        db.expire(&auth.session_id, &expired).unwrap();
        assert_eq!(db.get(&auth.session_id).unwrap().state, AuthorizationState::Expired);
    }

    #[test]
    fn corrupt_missing_empty_and_incompatible_files_never_reset() {
        let (dir, auth) = create();
        std::fs::write(dir.path(), b"not a sqlite database").unwrap();
        assert!(AuthorizationCoordinator::open_existing(&dir.path()).is_err());
        assert!(AuthorizationCoordinator::create_new(&dir.path()).is_err());
        assert_eq!(std::fs::read(dir.path()).unwrap(), b"not a sqlite database");
        assert!(AuthorizationCoordinator::open_existing(&dir.0.join("missing.sqlite")).is_err());
        assert!(!dir.0.join("missing.sqlite").exists());
        let empty = dir.0.join("empty.sqlite");
        std::fs::write(&empty, b"").unwrap();
        assert!(AuthorizationCoordinator::open_existing(&empty).is_err());
        assert!(AuthorizationCoordinator::create_new(&empty).is_err());
        let incompatible = dir.0.join("incompatible.sqlite");
        let mut wrong = AuthorizationCoordinator::create_new(&incompatible).unwrap();
        wrong.connection.batch_execute("PRAGMA user_version = 99;").unwrap();
        drop(wrong);
        assert!(AuthorizationCoordinator::open_existing(&incompatible).is_err());
        assert!(AuthorizationCoordinator::create_new(&incompatible).is_err());
        let _ = auth;
    }

    #[test]
    fn expiration_is_terminal() {
        let (dir, auth) = create();
        let mut db = AuthorizationCoordinator::open_existing(&dir.path()).unwrap();
        assert!(db.expire_at(&auth.session_id, &auth.context, auth.context.expires_unix - 1).is_err());
        db.expire_at(&auth.session_id, &auth.context, auth.context.expires_unix).unwrap();
        assert_eq!(db.get(&auth.session_id).unwrap().state, AuthorizationState::Expired);
        assert!(db.mark_verified_by_trusted_verifier(&auth.session_id, &auth.context, "utxo_test").is_err());
    }
}
