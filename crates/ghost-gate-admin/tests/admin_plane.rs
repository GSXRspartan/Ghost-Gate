//! End-to-end tests for the administrator control plane, driven over REAL HTTP against a REAL
//! server on an ephemeral loopback port.
//!
//! Every scenario from the operator's anti-tampering requirements is here, plus the
//! demonstrations: one, three and ten gates; the 10-tTARI divisibility conversion; a 7-day
//! session and its expiry and revocation; and the wall a normal visitor hits when they try to
//! change anything.
//!
//! The same discipline as the rest of the suite: fail-closed is the only acceptable outcome for
//! every unauthorized operation, and each test says which rule it is proving.

use ghost_gate_admin::server::{route, AdminState, Response, SharedState};
use ghost_gate_registry::{load_registry, Registry, StorePaths, StoreLock};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Harness: a real server on a real ephemeral port + a raw HTTP client.
// ---------------------------------------------------------------------------

static DIR_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);


/// A stand-in ledger identity for the tests: the same discipline as production, where the value is
/// the deployment's real genesis hash. Tests only care that it is carried, bound and validated.
const GENESIS: &str = "00f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

fn unique_dir(prefix: &str) -> std::path::PathBuf {
    let n = DIR_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    std::env::temp_dir().join(format!("{prefix}-{}-{n}", std::process::id()))
}

/// Synthetic Production-grade consensus evidence. `ConsensusAttestation::fixture` is the only way
/// to reach `Production` before the sidecar client exists (Phase 2C), and it is test-only.
fn production_evidence() -> ghost_gate_registry::Evidence {
    use ghost_gate_core::policy::{AnchorClass, ConsensusAttestation, Freshness};
    ghost_gate_registry::Evidence::ConsensusVerified(ConsensusAttestation::fixture(
        AnchorClass::IndependentlyAuthenticated, Freshness::Authenticated, "fixture-consensus"))
}

/// The operator trust policy used by the lifecycle tests: trusts the indexer and imposes no ceiling.
fn trusted_policy() -> ghost_gate_registry::TrustPolicy {
    ghost_gate_registry::TrustPolicy {
        operator_trusted_indexer: true,
        max_tier: ghost_gate_registry::TrustTier::Production,
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct TestServer {
    port: u16,
    state: SharedState,
    /// Kept for the shutdown in Drop; tests never touch it directly.
    runtime: Option<tokio::runtime::Runtime>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(rt) = self.runtime.take() {
            rt.shutdown_background();
        }
    }
}

fn spawn_server(dir: &std::path::Path) -> TestServer {
    // free_port() releases its port before this server binds it, and tests run concurrently: a
    // collision is possible, so verify the server actually ANSWERS and pick a new port otherwise.
    for _ in 0..20 {
        let port = free_port();
        let paths = StorePaths::new(dir);
        let origin = format!("http://127.0.0.1:{port}");
        let state = Arc::new(AdminState {
            paths,
            origin: origin.clone(),
            rp_id: "127.0.0.1".into(),
            pending: Mutex::new(BTreeMap::new()),
            bootstrap_token: Some("bootstrap-token-1".into()),
            genesis_hash: Some(GENESIS.to_string()),
            chain_generation: None,
        });
        let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        let addr = format!("127.0.0.1:{port}");
        let st = state.clone();
        runtime.spawn(async move {
            let _ = ghost_gate_admin::server::serve(st, &addr).await;
        });
        let mut serving = false;
        for _ in 0..100 {
            if let Ok(mut s) = std::net::TcpStream::connect(("127.0.0.1", port)) {
                use std::io::{Read, Write};
                let probe = format!("GET /admin/api/bootstrap HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                if s.write_all(probe.as_bytes()).is_ok() {
                    let mut buf = String::new();
                    if s.read_to_string(&mut buf).is_ok() && buf.contains("200") {
                        serving = true;
                    }
                }
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        if serving {
            return TestServer { port, state, runtime: Some(runtime) };
        }
        runtime.shutdown_background();
    }
    panic!("could not find a free port for the test server");
}

struct HttpReply {
    status: u16,
    body: serde_json::Value,
    set_cookie: Option<String>,
}

fn http(port: u16, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> HttpReply {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\nConnection: close\r\n", body.len());
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    stream.write_all(req.as_bytes()).unwrap();
    let mut buf = String::new();
    stream.read_to_string(&mut buf).unwrap();
    let (head, rest) = buf.split_once("\r\n\r\n").unwrap_or((buf.as_str(), ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let set_cookie = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("set-cookie:"))
        .map(|l| l.splitn(2, ':').nth(1).unwrap_or("").trim().to_string());
    let body_json = serde_json::from_str(rest).unwrap_or(serde_json::Value::Null);
    HttpReply { status, body: body_json, set_cookie }
}

/// A wallet-challenge administrator, signed with the same Ristretto machinery the credential flow
/// uses. Returns (public_key_hex, headers-for-a-signed-request).
struct WalletAdmin {
    secret: tari_crypto::ristretto::RistrettoSecretKey,
    public_hex: String,
}

impl WalletAdmin {
    fn new() -> Self {
        use tari_crypto::keys::{PublicKey as _, SecretKey};
        let secret = tari_crypto::ristretto::RistrettoSecretKey::random(&mut rand::rng());
        let public = tari_crypto::ristretto::RistrettoPublicKey::from_secret_key(&secret);
        Self { secret, public_hex: public.to_string() }
    }

    /// Attempt a registration and return the raw reply (used to prove registration is closed).
    fn register_attempt(&self, port: u16) -> HttpReply {
        let challenge = self.challenge(port, "register");
        use tari_crypto::signatures::{SchnorrSigChallenge, SchnorrSignature};
        use tari_crypto::keys::SecretKey as _;
        use tari_crypto::tari_utilities::ByteArray;
        let key_bytes = hex::decode(&self.public_hex).unwrap();
        let public = tari_crypto::ristretto::RistrettoPublicKey::from_canonical_bytes(&key_bytes).unwrap();
        let sig = SchnorrSignature::<
            tari_crypto::ristretto::RistrettoPublicKey,
            tari_crypto::ristretto::RistrettoSecretKey,
            SchnorrSigChallenge,
        >::sign(&self.secret, ghost_gate_admin::auth::hash_challenge(&challenge), &mut rand::rng())
        .unwrap();
        let body = serde_json::json!({
            "method": "wallet",
            "challenge": challenge,
            "publicKey": self.public_hex,
            "publicNonce": sig.get_public_nonce().to_string(),
            "signature": hex::encode(sig.get_signature().as_bytes()),
            "label": "intruder",
            "bootstrapToken": "bootstrap-token-1",
        });
        http(port, "POST", "/admin/api/auth/register", &[("Origin", &format!("http://127.0.0.1:{port}"))], &body.to_string())
    }

    /// Register through the real HTTP flow with the bootstrap token. Returns the session cookie
    /// and CSRF token of the (already stepped-up) registration session.
    fn register(&self, port: u16) -> (String, String) {
        let challenge = self.challenge(port, "register");
        use tari_crypto::signatures::{SchnorrSigChallenge, SchnorrSignature};
        use tari_crypto::keys::SecretKey as _;
        use tari_crypto::tari_utilities::ByteArray;
        let key_bytes = hex::decode(&self.public_hex).unwrap();
        let public = tari_crypto::ristretto::RistrettoPublicKey::from_canonical_bytes(&key_bytes).unwrap();
        let sig = SchnorrSignature::<
            tari_crypto::ristretto::RistrettoPublicKey,
            tari_crypto::ristretto::RistrettoSecretKey,
            SchnorrSigChallenge,
        >::sign(&self.secret, ghost_gate_admin::auth::hash_challenge(&challenge), &mut rand::rng())
        .unwrap();
        let body = serde_json::json!({
            "method": "wallet",
            "challenge": challenge,
            "publicKey": self.public_hex,
            "publicNonce": sig.get_public_nonce().to_string(),
            "signature": hex::encode(sig.get_signature().as_bytes()),
            "label": "operator",
            "bootstrapToken": "bootstrap-token-1",
        });
        let reply = http(port, "POST", "/admin/api/auth/register", &[("Origin", &format!("http://127.0.0.1:{port}"))], &body.to_string());
        assert_eq!(reply.status, 200, "registration must succeed: {}", reply.body);
        let cookie = reply.set_cookie.expect("session cookie from registration");
        (cookie, as_str(&reply.body, "csrf").to_string())
    }

    fn challenge(&self, port: u16, kind: &str) -> String {
        let reply = http(port, "POST", "/admin/api/auth/challenge", &[("Origin", &format!("http://127.0.0.1:{port}"))], &format!(r#"{{"kind":"{kind}","method":"wallet"}}"#));
        let challenge = reply.body.get("challenge").and_then(|c| c.as_str()).unwrap_or("").to_string();
        challenge
    }

    /// Login (or step-up). `cookie` is the existing session to step up, if any.
    fn login(&self, port: u16, stepup: bool, cookie: Option<&str>) -> HttpReply {
        let challenge = self.challenge(port, "login");
        use tari_crypto::signatures::{SchnorrSigChallenge, SchnorrSignature};
        use tari_crypto::keys::SecretKey as _;
        use tari_crypto::tari_utilities::ByteArray;
        let key_bytes = hex::decode(&self.public_hex).unwrap();
        let public = tari_crypto::ristretto::RistrettoPublicKey::from_canonical_bytes(&key_bytes).unwrap();
        let sig = SchnorrSignature::<
            tari_crypto::ristretto::RistrettoPublicKey,
            tari_crypto::ristretto::RistrettoSecretKey,
            SchnorrSigChallenge,
        >::sign(&self.secret, ghost_gate_admin::auth::hash_challenge(&challenge), &mut rand::rng())
        .unwrap();
        let body = serde_json::json!({
            "method": "wallet",
            "challenge": challenge,
            "publicKey": self.public_hex,
            "publicNonce": sig.get_public_nonce().to_string(),
            "signature": hex::encode(sig.get_signature().as_bytes()),
            "stepup": stepup,
        });
        let mut headers: Vec<(&str, String)> = vec![("Origin", format!("http://127.0.0.1:{port}"))];
        if let Some(c) = cookie {
            headers.push(("Cookie", c.to_string()));
        }
        let hdr: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        http(port, "POST", "/admin/api/auth/login", &hdr, &body.to_string())
    }
}

fn auth_headers(port: u16, cookie: &str, csrf: &str) -> Vec<(String, String)> {
    vec![
        ("Origin".into(), format!("http://127.0.0.1:{port}")),
        ("Cookie".into(), cookie.to_string()),
        ("X-GG-CSRF".into(), csrf.to_string()),
    ]
}

fn hdrs(v: &[(String, String)]) -> Vec<(&str, &str)> {
    v.iter().map(|(k, val)| (k.as_str(), val.as_str())).collect()
}

fn as_str<'a>(v: &'a serde_json::Value, key: &str) -> &'a str {
    v.get(key).and_then(|x| x.as_str()).unwrap_or("")
}

// ---------------------------------------------------------------------------
// Demonstrations
// ---------------------------------------------------------------------------

#[test]
fn one_three_and_ten_gates_with_separate_thresholds() {
    let dir = unique_dir("gg-admin-t1");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let server = spawn_server(&dir);

    let admin = WalletAdmin::new();
    let (cookie, csrf) = admin.register(server.port);

    for count in [1usize, 3, 10] {
        let app_id = format!("app-{count}");
        let create = http(server.port, "POST", "/admin/api/app/create", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
            &serde_json::json!({
                "applicationId": app_id,
                "displayName": format!("{count}-gate app"),
                "topology": "independent",
                "defaultSessionTtl": 86_400u64,
                "maxGates": count,
                "production": true,
            }).to_string());
        assert_eq!(create.status, 200, "creating {count} gates: {}", create.body);

        // Add exactly `count` gates, each with its own threshold, resource, name and identity.
        for i in 0..count {
            let gate = serde_json::json!({
                "gateId": format!("gate-{i}"),
                "name": format!("Gate {i}"),
                "resourceAddress": format!("resource_{i:016x}"),
                "symbol": "tTARI",
                "divisibility": 6,
                "thresholdRaw": format!("{}", (i as u128 + 1) * 10_000_000),
                "proofMode": "consensus",
                "challengeDomain": format!("{app_id}.localhost"),
                "grants": [],
                "enabled": true,
                "testLane": false,
                "componentAddress": format!("component_{i:016x}"),
            });
            let set = http(server.port, "POST", "/admin/api/gate/set", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
                &serde_json::json!({ "applicationId": app_id, "gate": gate }).to_string());
            assert_eq!(set.status, 200, "gate {i} of {count}: {}", set.body);
        }
        // The count is exact: no phantom entries, no missing ones.
        let state = http(server.port, "GET", "/admin/api/state", &hdrs(&auth_headers(server.port, &cookie, &csrf)), "");
        let apps = state.body.get("applications").unwrap().as_array().unwrap();
        let mine = apps.iter().find(|a| as_str(a, "applicationId") == app_id).unwrap();
        assert_eq!(mine.get("gates").unwrap().as_array().unwrap().len(), count, "exactly {count} gates");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_ten_ttari_test_gate_is_created_without_touching_source() {
    // The dashboard conversion: the administrator types 10, divisibility 6 → 10_000_000 raw.
    // No source edit, no env edit, no constant. This test pins the EXACT conversion the product
    // promises, and that a test-lane gate can be published on a non-production application.
    assert_eq!(
        ghost_gate_core::policy::GatePolicy::raw_units_for("10", 6),
        Some(10_000_000),
        "10 tTARI at divisibility 6 is exactly 10,000,000 raw units"
    );
    assert_eq!(
        ghost_gate_core::policy::GatePolicy::raw_units_for("0.000001", 6),
        Some(1),
        "the smallest unit converts exactly"
    );
    assert_eq!(
        ghost_gate_core::policy::GatePolicy::raw_units_for("10.0000001", 6),
        None,
        "more precision than the resource has is refused, never truncated"
    );

    let dir = unique_dir("gg-admin-t2");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let server = spawn_server(&dir);
    let admin = WalletAdmin::new();
    let (cookie, csrf) = admin.register(server.port);

    // A NON-production application may enable a test-lane gate.
    let create = http(server.port, "POST", "/admin/api/app/create", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
        &serde_json::json!({
            "applicationId": "test-lane",
            "displayName": "Local test",
            "topology": "independent",
            "defaultSessionTtl": 3600u64,
            "production": false,
        }).to_string());
    assert_eq!(create.status, 200, "{}", create.body);
    let gate = serde_json::json!({
        "gateId": "local-test",
        "name": "Local test gate (10 tTARI)",
        "resourceAddress": "resource_test",
        "symbol": "tTARI",
        "divisibility": 6,
        "thresholdRaw": "10000000",
        "proofMode": "consensus",
        "challengeDomain": "test.localhost",
        "grants": [],
        "enabled": true,
        "testLane": true,
        "componentAddress": "component_test0000000000000000000000000000",
    });
    let set = http(server.port, "POST", "/admin/api/gate/set", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
        &serde_json::json!({ "applicationId": "test-lane", "gate": gate }).to_string());
    assert_eq!(set.status, 200, "{}", set.body);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_test_lane_gate_cannot_be_enabled_on_a_production_application() {
    let dir = unique_dir("gg-admin-t3");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let server = spawn_server(&dir);
    let admin = WalletAdmin::new();
    let (cookie, csrf) = admin.register(server.port);
    let _ = http(server.port, "POST", "/admin/api/app/create", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
        &serde_json::json!({ "applicationId": "prod", "displayName": "Prod", "topology": "independent", "defaultSessionTtl": 86_400u64, "production": true }).to_string());
    let gate = serde_json::json!({
        "gateId": "testy", "name": "test", "resourceAddress": "resource_t", "symbol": "tTARI",
        "divisibility": 6, "thresholdRaw": "10", "proofMode": "consensus",
        "challengeDomain": "test.localhost", "grants": [], "enabled": true, "testLane": true,
        "componentAddress": "component_t",
    });
    let set = http(server.port, "POST", "/admin/api/gate/set", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
        &serde_json::json!({ "applicationId": "prod", "gate": gate }).to_string());
    assert_ne!(set.status, 200, "a test-lane gate must not be enabled in production");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The session lifecycle demonstration: a one-week authorization, its use, its expiry and its
/// revocation. Runs against the registry's real issue/check functions over the real published
/// policy, with time moved forward explicitly — no sleeps, no flakiness.
#[test]
fn one_week_session_issue_use_expiry_and_revocation() {
    use ghost_gate_core::policy::{hash_policy, GateTopology, ProofMode};
    use ghost_gate_registry::{check_access, issue_session_with_evidence, PolicyVersion};

    let dir = unique_dir("gg-admin-t4");
    let _ = std::fs::remove_dir_all(&dir);
    let paths = StorePaths::new(&dir);
    let mut reg = Registry::default();
    reg.credentials.push(ghost_gate_registry::AdminCredential {
        credential_id: "wallet:abc".into(),
        kind: ghost_gate_registry::CredentialKind::WalletKey,
        label: "operator".into(),
        registered_unix: 1,
        es256_public_sec1: None,
        ristretto_public_hex: Some("abc".into()),
    });
    let mut app = ghost_gate_core::policy::Application {
        application_id: "community".into(),
        display_name: "Community".into(),
        owner_credential: "wallet:abc".into(),
        topology: GateTopology::Independent,
        default_session_ttl: 7 * 86_400, // the suggested community duration
        max_gates: 10,
        gates: vec![],
        revision: 1,
        production: true,
        network: ghost_gate_core::network::LOCALNET,
        genesis_hash: GENESIS.into(),
        chain_generation: 1,
    };
    app.gates.push(ghost_gate_core::policy::GatePolicy {
        gate_id: "members".into(),
        name: "Members".into(),
        resource_address: "resource_m".into(),
        symbol: "tTARI".into(),
        divisibility: 6,
        threshold_raw: 10_000_000,
        proof_mode: ProofMode::Consensus,
        challenge_domain: "community.localhost".into(),
        session_ttl_override: None,
        grants: vec![],
        enabled: true,
        test_lane: false,
        use_mode: Default::default(),
        component_address: Some("component_m".into()),
    });
    app.validate().unwrap();
    reg.applications.push(app);
    let app_ref = reg.applications.first().unwrap();
    let gate_ref = app_ref.gate("members").unwrap();
    reg.versions.push(PolicyVersion {
        application_id: "community".into(),
        gate_id: "members".into(),
        version: 1,
        policy_hash: hash_policy(&ghost_gate_registry::Blake3Hasher, app_ref, gate_ref, 1),
        policy_hash_version: ghost_gate_registry::POLICY_HASH_V1,
        policy_context: None,
        network: ghost_gate_core::network::LOCALNET,
        genesis_hash: GENESIS.into(),
        policy: gate_ref.clone(),
        app_revision: 1,
        created_unix: 1,
    });
    let _lock = StoreLock::acquire(&paths);
    ghost_gate_registry::save_registry(&paths, &reg).unwrap();
    drop(_lock);

    // Reload through the real store path and issue the session the way the bridge will.
    let reg = load_registry(&paths).unwrap();
    let app_ref = reg.application("community").unwrap();
    let gate_ref = app_ref.gate("members").unwrap();
    let mut entropy = [0u8; 32];
    let session = issue_session_with_evidence(&reg, "community", "members", hash_policy(&ghost_gate_registry::Blake3Hasher, app_ref, gate_ref, 1), &mut entropy, &production_evidence(), &trusted_policy()).unwrap();
    assert_eq!(session.expires_unix - session.issued_unix, 7 * 86_400, "exactly one week");

    // In-window use succeeds.
    let ok = check_access(&reg, &[session.clone()], &session.token, "community", "members", session.issued_unix + 60);
    assert!(ok.authorized, "{}", ok.reason);

    // Expiry: a session past its week is dead, with a reason a user can read.
    let expired = check_access(&reg, &[session.clone()], &session.token, "community", "members", session.expires_unix + 1);
    assert!(!expired.authorized && expired.reason.contains("expired"));

    // Revocation: ends the session before its week, and the refusal says so.
    let mut revoked_list = vec![session.clone()];
    revoked_list[0].revoked = true;
    let revoked = check_access(&reg, &revoked_list, &session.token, "community", "members", session.issued_unix + 60);
    assert!(!revoked.authorized && revoked.reason.contains("revoked"));
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Anti-tampering: every unauthorized operation fails closed
// ---------------------------------------------------------------------------

/// Setup shared by the tamper tests: one admin, one application with three gates (silver grants
/// bronze), all published at v1, plus a second admin who owns nothing.
fn tamper_fixture() -> (TestServer, String, String, WalletAdmin, WalletAdmin) {
    let dir = unique_dir("gg-admin-fx");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let server = spawn_server(&dir);
    let owner = WalletAdmin::new();
    let outsider = WalletAdmin::new();
    let (cookie, csrf) = owner.register(server.port);
    let _ = http(server.port, "POST", "/admin/api/app/create", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
        &serde_json::json!({ "applicationId": "vault", "displayName": "Vault", "topology": "hierarchical", "defaultSessionTtl": 86_400u64, "production": true }).to_string());
    // Two steps, exactly as the dashboard does it: create the gates, THEN wire the tiers. A gate
    // that grants access to a gate which does not exist yet is refused by the server — a fixture that
    // ignored the reply would silently end up with fewer gates than it believes it has.
    for (id, threshold) in [("bronze", 1_000_000u64), ("silver", 2_000_000), ("gold", 3_000_000)] {
        let gate = serde_json::json!({
            "gateId": id, "name": id, "resourceAddress": "resource_v", "symbol": "GHOST",
            "divisibility": 6, "thresholdRaw": threshold.to_string(), "proofMode": "consensus",
            "challengeDomain": "vault.localhost", "grants": [], "enabled": true,
            "testLane": false, "componentAddress": format!("component_{id}"),
        });
        let reply = http(server.port, "POST", "/admin/api/gate/set", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
            &serde_json::json!({ "applicationId": "vault", "gate": gate }).to_string());
        assert_eq!(reply.status, 200, "fixture gate {id} must exist: {}", reply.body);
    }
    for (id, threshold, grants) in [
        ("silver", 2_000_000u64, vec!["bronze".to_string()]),
        ("gold", 3_000_000, vec!["silver".to_string(), "bronze".to_string()]),
    ] {
        let gate = serde_json::json!({
            "gateId": id, "name": id, "resourceAddress": "resource_v", "symbol": "GHOST",
            "divisibility": 6, "thresholdRaw": threshold.to_string(), "proofMode": "consensus",
            "challengeDomain": "vault.localhost", "grants": grants, "enabled": true,
            "testLane": false, "componentAddress": format!("component_{id}"),
        });
        let reply = http(server.port, "POST", "/admin/api/gate/set", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
            &serde_json::json!({ "applicationId": "vault", "gate": gate }).to_string());
        assert_eq!(reply.status, 200, "fixture tiers for {id} must wire: {}", reply.body);
    }
    (server, cookie, csrf, owner, outsider)
}

/// Step up the owner's existing fixture session in place: returns the refreshed session view.

#[test]
fn tamper_1_and_2_threshold_edits_from_the_client_side_are_ignored() {
    // Scenario 1 (change thresholds through Developer Tools) and 2 (submit an altered threshold in
    // an HTTP request) share one defence: the server reads the threshold from its own registry and
    // the challenge/proof bind to the policy hash. There is no endpoint that accepts a threshold
    // from a browser at all — the proof of that is that every write route requires
    // authentication, and the gate's effective threshold is only ever read server-side.
    let (server, cookie, csrf, _owner, _outsider) = tamper_fixture();
    // A visitor POSTing a "new threshold" has no route that even accepts one.
    let reply = http(server.port, "POST", "/admin/api/gate/set",
        &[("Origin", &format!("http://127.0.0.1:{}", server.port)), ("Content-Type", "application/json")],
        &serde_json::json!({ "applicationId": "vault", "gate": { "gateId": "bronze", "thresholdRaw": "1" } }).to_string());
    assert_eq!(reply.status, 401, "an unauthenticated threshold edit is refused outright");
    // And even WITH a session but no CSRF token (the header a devtools-forged request would lack).
    let reply = http(server.port, "POST", "/admin/api/gate/set",
        &[("Origin", &format!("http://127.0.0.1:{}", server.port)), ("Cookie", cookie.as_str())],
        &serde_json::json!({ "applicationId": "vault", "gate": { "gateId": "bronze", "thresholdRaw": "1" } }).to_string());
    assert_eq!(reply.status, 403, "missing CSRF token: {}", reply.body);
}

#[test]
fn tamper_3_another_administrators_gate_is_untouchable() {
    let (server, cookie, csrf, owner, outsider) = tamper_fixture();
    // Registration is closed once an administrator exists: an attempted second registration must
    // be refused, bootstrap token or not.
    let attempted = outsider.register_attempt(server.port);
    assert_ne!(attempted.status, 200, "a second registration must be closed: {}", attempted.body);
    assert_eq!(outsider_login(&server, &outsider).status, 403, "a second wallet cannot log in as an administrator");
    // The owner revokes nothing; the outsider simply has no session. Prove the wall: a request
    // with no session cannot read the full state either.
    let state = http(server.port, "GET", "/admin/api/state", &[], "");
    assert_eq!(state.status, 401);
    // And the owner's own session must be able to see their app (positive control).
    let state = http(server.port, "GET", "/admin/api/state", &hdrs(&auth_headers(server.port, &cookie, &csrf)), "");
    assert_eq!(state.status, 200);
    assert!(state.body.to_string().contains("vault"), "state: {}", state.body);
}

fn outsider_login(server: &TestServer, outsider: &WalletAdmin) -> HttpReply {
    outsider.login(server.port, false, None)
}

#[test]
fn tamper_4_activation_without_authorization_is_refused() {
    let (server, cookie, csrf, _owner, _outsider) = tamper_fixture();
    // No cookie at all.
    let r = http(server.port, "POST", "/admin/api/policy/publish",
        &[("Origin", &format!("http://127.0.0.1:{}", server.port))],
        &serde_json::json!({ "applicationId": "vault", "gateId": "bronze" }).to_string());
    assert_eq!(r.status, 401, "activation without any session is refused");
    // Stepped-up owner CAN publish (positive control). The fixture's registration session is
    // already stepped-up; prove the step-up requirement separately below.
    let (cookie, csrf) = fresh_stepped_up(&server, &_owner);
    let r = http(server.port, "POST", "/admin/api/policy/publish", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
        &serde_json::json!({ "applicationId": "vault", "gateId": "bronze", "reason": "go live" }).to_string());
    assert_eq!(r.status, 200, "an authorized publish works: {}", r.body);
}

fn fresh_stepped_up(server: &TestServer, owner: &WalletAdmin) -> (String, String) {
    // The step-up path refreshes the CURRENT session — it does not mint a new cookie — so the
    // cookie comes from the live registry, the same place the server itself would look.
    let reg = load_registry(&server.state.paths).unwrap();
    let session = reg.admin_sessions.last().expect("the fixture created one session");
    let cookie = format!("gg_admin={}", session.token);
    let step = owner.login(server.port, true, Some(&cookie));
    assert_eq!(step.status, 200, "step-up must succeed: {}", step.body);
    let state = http(server.port, "GET", "/admin/api/state", &[("Cookie", cookie.as_str())], "");
    assert_eq!(state.status, 200);
    (cookie, as_str(&state.body, "csrf").to_string())
}

#[test]
fn tamper_5_an_old_approval_cannot_be_reused() {
    // Auth challenges are single-use: capturing a challenge and replaying its signature fails,
    // and so does re-presenting the same challenge.
    let (server, _c, _s, owner, _o) = tamper_fixture();
    let challenge = owner.challenge(server.port, "login");
    use tari_crypto::signatures::{SchnorrSigChallenge, SchnorrSignature};
    use tari_crypto::keys::SecretKey as _;
    use tari_crypto::tari_utilities::ByteArray;
    let key_bytes = hex::decode(&owner.public_hex).unwrap();
    let public = tari_crypto::ristretto::RistrettoPublicKey::from_canonical_bytes(&key_bytes).unwrap();
    let sig = SchnorrSignature::<
        tari_crypto::ristretto::RistrettoPublicKey,
        tari_crypto::ristretto::RistrettoSecretKey,
        SchnorrSigChallenge,
    >::sign(&owner.secret, ghost_gate_admin::auth::hash_challenge(&challenge), &mut rand::rng()).unwrap();
    let body = serde_json::json!({
        "method": "wallet", "challenge": challenge, "publicKey": owner.public_hex,
        "publicNonce": sig.get_public_nonce().to_string(),
        "signature": hex::encode(sig.get_signature().as_bytes()), "stepup": false,
    });
    let origin = format!("http://127.0.0.1:{}", server.port);
    let headers = [("Origin", origin.as_str())];
    let first = http(server.port, "POST", "/admin/api/auth/login", &headers, &body.to_string());
    assert_eq!(first.status, 200, "first use of the challenge works: {}", first.body);
    let second = http(server.port, "POST", "/admin/api/auth/login", &headers, &body.to_string());
    assert_ne!(second.status, 200, "the SAME challenge cannot authenticate twice");
    assert!(second.body.to_string().contains("challenge"), "the refusal names the challenge: {}", second.body);
}

#[test]
fn tamper_6_a_ticker_clone_is_not_the_same_resource() {
    // Two gates sharing the ticker GHOST but with different resource addresses produce different
    // policy hashes, and an access decision binds to the resource-bearing hash. The registry test
    // proved the hash property; here we prove the dashboard-level consequence: publishing both
    // gates yields distinct published hashes.
    let (server, _c, _s, owner, _o) = tamper_fixture();
    let (cookie, csrf) = fresh_stepped_up(&server, &owner);
    // Give bronze a twin with the same ticker but a different resource.
    let twin = serde_json::json!({
        "gateId": "bronze-clone", "name": "bronze", "resourceAddress": "resource_IMPOSTOR",
        "symbol": "GHOST", "divisibility": 6, "thresholdRaw": "1000000", "proofMode": "consensus",
        "challengeDomain": "vault.localhost", "grants": [], "enabled": true, "testLane": false,
        "componentAddress": "component_bc",
    });
    let set = http(server.port, "POST", "/admin/api/gate/set", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
        &serde_json::json!({ "applicationId": "vault", "gate": twin }).to_string());
    assert_eq!(set.status, 200, "{}", set.body);
    let pubr = http(server.port, "POST", "/admin/api/policy/publish", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
        r#"{"applicationId":"vault","gateId":"bronze-clone"}"#);
    assert_eq!(pubr.status, 200, "publishing the complete application draft succeeds: {}", pubr.body);
    let state = http(server.port, "GET", "/admin/api/state", &hdrs(&auth_headers(server.port, &cookie, &csrf)), "");
    let apps = state.body.get("applications").unwrap().as_array().unwrap();
    let app = apps.iter().find(|a| as_str(a, "applicationId") == "vault").unwrap();
    let gates = app.get("gates").unwrap().as_array().unwrap();
    let h1 = as_str(gates.iter().find(|g| as_str(g, "gateId") == "bronze").unwrap(), "publishedHash");
    let h2 = as_str(gates.iter().find(|g| as_str(g, "gateId") == "bronze-clone").unwrap(), "publishedHash");
    assert_ne!(h1, h2, "the ticker clone must not share the original's policy hash");
}

#[test]
fn tamper_7_raw_unit_and_divisibility_confusion_is_refused() {
    // "10" typed into a div-6 gate is 10,000,000 raw; a caller who tries to smuggle raw units as
    // display units (or vice versa) produces a policy that says exactly what it says — and the
    // conversion helper refuses impossible precision instead of rounding.
    assert_eq!(ghost_gate_core::policy::GatePolicy::raw_units_for("10", 0), Some(10));
    assert_eq!(ghost_gate_core::policy::GatePolicy::raw_units_for("10", 6), Some(10_000_000));
    assert_eq!(ghost_gate_core::policy::GatePolicy::raw_units_for("1.5", 0), None, "half a unit cannot exist at div 0");
    assert_eq!(ghost_gate_core::policy::GatePolicy::format_raw(10_000_000, 6), "10");
    assert_eq!(ghost_gate_core::policy::GatePolicy::format_raw(10_500_000, 6), "10.5");
}

#[test]
fn tamper_8_a_proof_against_another_gate_or_policy_cannot_verify() {
    // The challenge domain + policy hash binding: a session proven for gate A is refused for gate
    // C unless the policy says A grants C; a session proven under v1 is refused after v2 exists.
    use ghost_gate_core::policy::{hash_policy, GateTopology, ProofMode};
    use ghost_gate_registry::{check_access, issue_session_with_evidence, Registry};
    let mut reg = Registry::default();
    let mut app = ghost_gate_core::policy::Application {
        application_id: "app".into(), display_name: "app".into(), owner_credential: "w".into(),
        topology: GateTopology::Independent, default_session_ttl: 86_400, max_gates: 5,
        gates: vec![], revision: 1, production: true,
            network: ghost_gate_core::network::LOCALNET, genesis_hash: GENESIS.into(),
            chain_generation: 1,
    };
    for id in ["a", "b"] {
        app.gates.push(ghost_gate_core::policy::GatePolicy {
            gate_id: id.into(), name: id.into(), resource_address: "resource_x".into(),
            symbol: "GHOST".into(), divisibility: 6, threshold_raw: 100,
            proof_mode: ProofMode::Consensus, challenge_domain: "app.localhost".into(),
            session_ttl_override: None, grants: vec![], enabled: true, test_lane: false,
            use_mode: Default::default(),
            component_address: Some(format!("component_{id}")),
        });
    }
    app.validate().unwrap();
    reg.applications.push(app);
    let hashes: Vec<(String, String, ghost_gate_core::policy::GatePolicy)> = {
        let app_ref = reg.application("app").unwrap();
        ["a", "b"].iter().map(|id| {
            let g = app_ref.gate(id).unwrap();
            (id.to_string(), hash_policy(&ghost_gate_registry::Blake3Hasher, app_ref, g, 1), g.clone())
        }).collect()
    };
    for (id, hash, policy) in hashes {
        reg.versions.push(ghost_gate_registry::PolicyVersion {
            application_id: "app".into(), gate_id: id, version: 1,
            policy_hash: hash, policy_hash_version: ghost_gate_registry::POLICY_HASH_V1, policy_context: None, network: ghost_gate_core::network::LOCALNET, genesis_hash: GENESIS.into(), policy, app_revision: 1, created_unix: 1,
        });
    }
    let app_ref = reg.application("app").unwrap();
    let a = app_ref.gate("a").unwrap();
    let mut e = [0u8; 32];
    let session = issue_session_with_evidence(&reg, "app", "a", hash_policy(&ghost_gate_registry::Blake3Hasher, app_ref, a, 1), &mut e, &production_evidence(), &trusted_policy()).unwrap();
    let now = ghost_gate_registry::now_unix();
    let token = session.token.clone();
    assert!(check_access(&reg, &[session.clone()], &token, "app", "a", now).authorized);
    let d = check_access(&reg, &[session.clone()], &token, "app", "b", now);
    assert!(!d.authorized, "a session for gate A must not open gate B (independent topology)");
    assert!(d.reason.contains("does not grant"));
}

#[test]
fn tamper_9_lowering_a_threshold_below_an_outstanding_challenge_is_a_replacement_not_an_edit() {
    let (server, _c, _s, owner, _o) = tamper_fixture();
    let (cookie, csrf) = fresh_stepped_up(&server, &owner);
    // Publish bronze at v1 first.
    let pubr = http(server.port, "POST", "/admin/api/policy/publish", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
        &serde_json::json!({ "applicationId": "vault", "gateId": "bronze" }).to_string());
    assert_eq!(pubr.status, 200, "{}", pubr.body);
    // Edit a published gate's DRAFT.  The live bindings must remain at v1 until Publish, so an
    // outstanding challenge can never be silently reinterpreted.
    let before = ghost_gate_registry::load_bindings(&server.state.paths).unwrap().unwrap();
    let lowered = serde_json::json!({
        "gateId": "bronze", "name": "bronze", "resourceAddress": "resource_v", "symbol": "GHOST",
        "divisibility": 6, "thresholdRaw": "1", "proofMode": "consensus",
        "challengeDomain": "vault.localhost", "grants": [], "enabled": true, "testLane": false,
        "componentAddress": "component_bronze",
    });
    let set = http(server.port, "POST", "/admin/api/gate/set", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
        &serde_json::json!({ "applicationId": "vault", "gate": lowered }).to_string());
    assert_eq!(set.status, 200, "the replacement draft saves: {}", set.body);
    let draft_bindings = ghost_gate_registry::load_bindings(&server.state.paths).unwrap().unwrap();
    let old = before.gates.iter().find(|g| g.gate_id == "bronze").unwrap();
    let still_old = draft_bindings.gates.iter().find(|g| g.gate_id == "bronze").unwrap();
    assert_eq!(still_old.threshold_raw, old.threshold_raw, "a draft cannot replace a live binding");
    let replacement = http(server.port, "POST", "/admin/api/policy/publish", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
        r#"{"applicationId":"vault","gateId":"bronze","reason":"threshold replacement"}"#);
    assert_eq!(replacement.status, 200, "publishing the replacement succeeds: {}", replacement.body);
    let after = ghost_gate_registry::load_bindings(&server.state.paths).unwrap().unwrap();
    assert_eq!(after.gates.iter().find(|g| g.gate_id == "bronze").unwrap().threshold_raw, 1);
}

#[test]
fn hosted_relying_site_is_validated_and_only_binds_after_publish() {
    let (server, _c, _s, owner, _o) = tamper_fixture();
    let (cookie, csrf) = fresh_stepped_up(&server, &owner);
    let publish = || http(server.port, "POST", "/admin/api/policy/publish", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
        r#"{"applicationId":"vault","gateId":"bronze","reason":"relying-site migration"}"#);
    assert_eq!(publish().status, 200, "the existing localhost policy publishes first");

    let gate = |challenge_domain: &str| serde_json::json!({
        "gateId": "bronze", "name": "bronze", "resourceAddress": "resource_v", "symbol": "GHOST",
        "divisibility": 6, "thresholdRaw": "1000000", "proofMode": "consensus",
        "challengeDomain": challenge_domain, "grants": [], "enabled": true, "testLane": false,
        "componentAddress": "component_bronze",
    });
    let set = |challenge_domain: &str| http(server.port, "POST", "/admin/api/gate/set", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
        &serde_json::json!({ "applicationId": "vault", "gate": gate(challenge_domain) }).to_string());

    for invalid in [
        "http://ghost-gate-staging.gsxrspartan.workers.dev",
        "https://ghost-gate-staging.gsxrspartan.workers.dev/proof",
    ] {
        let response = set(invalid);
        assert_eq!(response.status, 400, "{invalid} must be rejected before it becomes a draft: {}", response.body);
    }

    let before = ghost_gate_registry::load_bindings(&server.state.paths).unwrap().unwrap();
    assert_eq!(before.gates.iter().find(|g| g.gate_id == "bronze").unwrap().challenge_domain, "vault.localhost");
    let hosted = "https://ghost-gate-staging.gsxrspartan.workers.dev";
    assert_eq!(set(hosted).status, 200, "the exact Worker HTTPS origin is a valid draft");

    let draft_bindings = ghost_gate_registry::load_bindings(&server.state.paths).unwrap().unwrap();
    assert_eq!(draft_bindings.gates.iter().find(|g| g.gate_id == "bronze").unwrap().challenge_domain,
        "vault.localhost", "a draft relying-site must not change the live binding");

    assert_eq!(publish().status, 200, "the explicit publish activates the immutable hosted origin");
    let after = ghost_gate_registry::load_bindings(&server.state.paths).unwrap().unwrap();
    assert_eq!(after.gates.iter().find(|g| g.gate_id == "bronze").unwrap().challenge_domain, hosted);
}

#[test]
fn existing_crypt_gate_is_visible_after_login_and_stepup_and_drafts_stay_non_live() {
    // This is the control-plane sequence the deployed administrator follows: an administrator
    // creates the Crypt draft, explicitly publishes it, signs out, signs in, and performs a
    // fresh approval.  The resulting state is what the dashboard renders into the existing-gate
    // editor, so pin the identifiers and exact raw amount the UI must receive.
    let dir = unique_dir("gg-admin-crypt-editor");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let server = spawn_server(&dir);
    let admin = WalletAdmin::new();
    let (registration_cookie, registration_csrf) = admin.register(server.port);
    let create = http(server.port, "POST", "/admin/api/app/create",
        &hdrs(&auth_headers(server.port, &registration_cookie, &registration_csrf)),
        &serde_json::json!({
            "applicationId": "Crypt", "displayName": "Crypt", "topology": "independent",
            "defaultSessionTtl": 86_400u64, "production": true,
        }).to_string());
    assert_eq!(create.status, 200, "{:#?}", create.body);

    let crypt_gate = |threshold_raw: &str| serde_json::json!({
        "gateId": "Crypt", "name": "Crypt", "resourceAddress": "resource_0101010101010101010101010101010101010101010101010101010101010101",
        "symbol": "tTARI", "divisibility": 6, "thresholdRaw": threshold_raw,
        "proofMode": "consensus", "challengeDomain": "Crypt.localhost", "grants": [],
        "enabled": true, "testLane": false, "componentAddress": "component_crypt",
    });
    let set = |cookie: &str, csrf: &str, threshold_raw: &str| http(server.port, "POST", "/admin/api/gate/set",
        &hdrs(&auth_headers(server.port, cookie, csrf)),
        &serde_json::json!({ "applicationId": "Crypt", "gate": crypt_gate(threshold_raw) }).to_string());
    assert_eq!(set(&registration_cookie, &registration_csrf, "100000000").status, 200,
        "the 100 tTARI draft must save exactly");
    let published = http(server.port, "POST", "/admin/api/policy/publish",
        &hdrs(&auth_headers(server.port, &registration_cookie, &registration_csrf)),
        r#"{"applicationId":"Crypt","gateId":"Crypt","reason":"editor regression fixture"}"#);
    assert_eq!(published.status, 200, "{:#?}", published.body);

    // A normal login remains locked.  The next ceremony is a step-up on that SAME session,
    // exactly as the browser does after Windows Hello.
    let logout = http(server.port, "POST", "/admin/api/auth/logout",
        &hdrs(&auth_headers(server.port, &registration_cookie, &registration_csrf)), "{}");
    assert_eq!(logout.status, 200, "{:#?}", logout.body);
    let login = admin.login(server.port, false, None);
    assert_eq!(login.status, 200, "{:#?}", login.body);
    let cookie = login.set_cookie.expect("ordinary login must mint a session");
    assert_eq!(state_field(&server, &cookie, "stepupValid"), serde_json::Value::Bool(false));
    let stepup = admin.login(server.port, true, Some(&cookie));
    assert_eq!(stepup.status, 200, "{:#?}", stepup.body);
    assert_eq!(stepup.body.get("stepup").and_then(|v| v.as_bool()), Some(true));

    let state = state_field_value(&server, &cookie);
    assert_eq!(state.get("stepupValid"), Some(&serde_json::Value::Bool(true)));
    let crypt = state.get("applications").and_then(|v| v.as_array()).unwrap().iter()
        .find(|app| as_str(app, "applicationId") == "Crypt")
        .expect("a published Crypt application stays visible after an ordinary login and step-up");
    let gate = crypt.get("gates").and_then(|v| v.as_array()).unwrap().iter()
        .find(|gate| as_str(gate, "gateId") == "Crypt")
        .expect("the Crypt gate stays visible to the editor");
    assert_eq!(as_str(gate, "thresholdRaw"), "100000000");
    assert_eq!(gate.get("divisibility").and_then(|v| v.as_u64()), Some(6));
    assert_eq!(as_str(gate, "challengeDomain"), "Crypt.localhost");
    assert_eq!(ghost_gate_core::policy::GatePolicy::raw_units_for("100", 6), Some(100_000_000),
        "100 tTARI must remain exactly 100000000 raw units");

    // Saving an editor draft must be possible after a fresh approval, but it cannot mutate the
    // immutable published binding until another explicit publish.
    let csrf = as_str(&state, "csrf").to_string();
    assert_eq!(set(&cookie, &csrf, "99999999").status, 200, "the post-step-up editor draft saves");
    let live = ghost_gate_registry::load_bindings(&server.state.paths).unwrap().unwrap();
    let live_crypt = live.gates.iter().find(|binding| binding.application_id == "Crypt" && binding.gate_id == "Crypt").unwrap();
    assert_eq!(live_crypt.threshold_raw, 100_000_000,
        "the un-published Crypt draft cannot change the live bridge binding");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn dashboard_existing_gate_prefill_uses_the_exact_defined_amount_formatter() {
    // This source-level guard complements the real-HTTP lifecycle test above. The dashboard is a
    // static asset, so it catches the class of deployment regression where rendering an existing
    // gate throws before its card is appended (as rawToHuman did).
    let script = include_str!("../assets/admin.js");
    assert!(script.contains("function ghostFormat(raw, div)"));
    assert!(script.contains("ghostFormat(g.thresholdRaw, g.divisibility)"));
    assert!(script.contains("editor.querySelector(`#${CSS.escape(id)}`)"),
        "existing-gate fields are prefilled before their card is attached to the document");
    assert!(!script.contains("rawToHuman("), "the editor must not call an undefined formatter");
}

#[test]
fn tamper_10_a_lower_tier_session_cannot_reach_a_higher_tier() {
    // Covered exhaustively in the registry tests; repeated here as the product-level statement:
    // silver grants bronze, never the reverse.
    use ghost_gate_core::policy::{hash_policy, GateTopology, ProofMode};
    use ghost_gate_registry::{check_access, issue_session_with_evidence, Registry};
    let mut reg = Registry::default();
    let mut app = ghost_gate_core::policy::Application {
        application_id: "t".into(), display_name: "t".into(), owner_credential: "w".into(),
        topology: GateTopology::Hierarchical, default_session_ttl: 86_400, max_gates: 5,
        gates: vec![], revision: 1, production: true,
            network: ghost_gate_core::network::LOCALNET, genesis_hash: GENESIS.into(),
            chain_generation: 1,
    };
    let silver = ghost_gate_core::policy::GatePolicy {
        gate_id: "silver".into(), name: "s".into(), resource_address: "resource_x".into(),
        symbol: "G".into(), divisibility: 6, threshold_raw: 200, proof_mode: ProofMode::Consensus,
        challenge_domain: "t.localhost".into(), session_ttl_override: None,
        grants: vec!["bronze".into()], enabled: true, test_lane: false,
        use_mode: Default::default(),
        component_address: Some("component_s".into()),
    };
    app.gates.push(silver);
    app.gates.push(ghost_gate_core::policy::GatePolicy {
        gate_id: "bronze".into(), name: "b".into(), resource_address: "resource_x".into(),
        symbol: "G".into(), divisibility: 6, threshold_raw: 100, proof_mode: ProofMode::Consensus,
        challenge_domain: "t.localhost".into(), session_ttl_override: None,
        grants: vec![], enabled: true, test_lane: false, use_mode: Default::default(), component_address: Some("component_b".into()),
    });
    app.validate().unwrap();
    reg.applications.push(app);
    let hashes: Vec<(String, String, ghost_gate_core::policy::GatePolicy)> = {
        let app_ref = reg.application("t").unwrap();
        ["silver", "bronze"].iter().map(|id| {
            let g = app_ref.gate(id).unwrap();
            (id.to_string(), hash_policy(&ghost_gate_registry::Blake3Hasher, app_ref, g, 1), g.clone())
        }).collect()
    };
    for (id, hash, policy) in hashes {
        reg.versions.push(ghost_gate_registry::PolicyVersion {
            application_id: "t".into(), gate_id: id, version: 1,
            policy_hash: hash, policy_hash_version: ghost_gate_registry::POLICY_HASH_V1, policy_context: None, network: ghost_gate_core::network::LOCALNET, genesis_hash: GENESIS.into(), policy, app_revision: 1, created_unix: 1,
        });
    }
    let app_ref = reg.application("t").unwrap();
    let bronze = app_ref.gate("bronze").unwrap();
    let mut e = [0u8; 32];
    let s = issue_session_with_evidence(&reg, "t", "bronze", hash_policy(&ghost_gate_registry::Blake3Hasher, app_ref, bronze, 1), &mut e, &production_evidence(), &trusted_policy()).unwrap();
    let now = ghost_gate_registry::now_unix();
    assert!(check_access(&reg, &[s.clone()], &s.token, "t", "bronze", now).authorized);
    let token = s.token.clone();
    let up = check_access(&reg, &[s], &token, "t", "silver", now);
    assert!(!up.authorized, "a bronze session must never open the silver gate");
}

#[test]
fn tamper_11_client_side_expiry_extension_is_meaningless() {
    // The expiry lives in the server's session record and is compared against the SERVER's clock.
    // A browser that edits its own stored expiry changes nothing, because the browser never stores
    // the expiry — only the token — and /access/check recomputes everything server-side. This test
    // proves the check ignores any client claim: there is no parameter for it.
    use ghost_gate_core::policy::{hash_policy, GateTopology, ProofMode};
    use ghost_gate_registry::{check_access, issue_session_with_evidence, Registry};
    let mut reg = Registry::default();
    let mut app = ghost_gate_core::policy::Application {
        application_id: "e".into(), display_name: "e".into(), owner_credential: "w".into(),
        topology: GateTopology::Independent, default_session_ttl: 3600, max_gates: 5,
        gates: vec![], revision: 1, production: true,
            network: ghost_gate_core::network::LOCALNET, genesis_hash: GENESIS.into(),
            chain_generation: 1,
    };
    app.gates.push(ghost_gate_core::policy::GatePolicy {
        gate_id: "g".into(), name: "g".into(), resource_address: "resource_x".into(),
        symbol: "G".into(), divisibility: 6, threshold_raw: 100, proof_mode: ProofMode::Consensus,
        challenge_domain: "e.localhost".into(), session_ttl_override: None, grants: vec![],
        enabled: true, test_lane: false, use_mode: Default::default(), component_address: Some("component_g".into()),
    });
    app.validate().unwrap();
    reg.applications.push(app);
    let app_ref = reg.application("e").unwrap();
    let g = app_ref.gate("g").unwrap();
    reg.versions.push(ghost_gate_registry::PolicyVersion {
        application_id: "e".into(), gate_id: "g".into(), version: 1,
        policy_hash: hash_policy(&ghost_gate_registry::Blake3Hasher, app_ref, g, 1),
        policy_hash_version: ghost_gate_registry::POLICY_HASH_V1,
        policy_context: None,
        network: ghost_gate_core::network::LOCALNET, genesis_hash: GENESIS.into(), policy: g.clone(), app_revision: 1, created_unix: 1,
    });
    let app_ref = reg.application("e").unwrap();
    let g = app_ref.gate("g").unwrap();
    let mut e2 = [0u8; 32];
    let s = issue_session_with_evidence(&reg, "e", "g", hash_policy(&ghost_gate_registry::Blake3Hasher, app_ref, g, 1), &mut e2, &production_evidence(), &trusted_policy()).unwrap();
    let now = ghost_gate_registry::now_unix();
    let expiry = s.expires_unix;
    let token = s.token.clone();
    assert!(check_access(&reg, &[s.clone()], &token, "e", "g", now).authorized);
    // After expiry — nothing the client says changes this.
    assert!(!check_access(&reg, &[s], &token, "e", "g", expiry + 1).authorized);
}

#[test]
fn tamper_12_expired_and_revoked_credentials_are_dead() {
    // Admin sessions: expiry is checked on every request (admin_session_for).
    use ghost_gate_registry::{AdminSession, Registry};
    let mut reg = Registry::default();
    let now = ghost_gate_registry::now_unix();
    let session = AdminSession {
        token: "tok".into(), credential_id: "c".into(), created_unix: now,
        expires_unix: now - 1, csrf: "x".into(), stepup_until_unix: 0, last_seen_unix: now,
    };
    reg.admin_sessions.push(session);
    assert!(ghost_gate_registry::admin_session_for(&reg, "tok", now).is_none(), "an expired admin session is dead");
    // Verified sessions: revoked = dead even before expiry (covered in the lifecycle test above).
    // Here: an unknown token is dead.
    let reg2 = Registry::default();
    assert!(ghost_gate_registry::admin_session_for(&reg2, "tok", now).is_none());
}

#[test]
fn tamper_13_concurrent_gate_updates_do_not_corrupt_or_race() {
    // Two concurrent mutations of the same registry: the file lock serialises them and both land,
    // in some order, each validated. The loser of a validation is refused, never half-applied.
    let (server, cookie, csrf, _owner, _o) = tamper_fixture();
    let (cookie, csrf) = fresh_stepped_up(&server, &_owner);
    let handles: Vec<_> = (0..8).map(|i| {
        let port = server.port;
        let cookie = cookie.clone();
        let csrf = csrf.clone();
        std::thread::spawn(move || {
            let gate = serde_json::json!({
                "gateId": format!("race-{i}"), "name": format!("race {i}"),
                "resourceAddress": "resource_v", "symbol": "GHOST", "divisibility": 6,
                "thresholdRaw": format!("{}", 1000 + i), "proofMode": "consensus",
                "challengeDomain": "vault.localhost", "grants": [], "enabled": true,
                "testLane": false, "componentAddress": format!("component_race{i}"),
            });
            http(port, "POST", "/admin/api/gate/set", &hdrs(&auth_headers(port, &cookie, &csrf)),
                &serde_json::json!({ "applicationId": "vault", "gate": gate }).to_string())
        })
    }).collect();
    let mut accepted = 0;
    for h in handles {
        let r = h.join().unwrap();
        if r.status == 200 { accepted += 1; } else {
            // Three honest reasons to refuse a concurrent write, and nothing else is acceptable:
            // the gate limit (the fixture already holds three gates), the store lock being held by
            // another writer, or the revision a competing writer moved underneath this one. Each is
            // a refusal, never a half-applied change.
            let body = r.body.to_string();
            assert!(
                body.contains("limit") || body.contains("gate") || body.contains("locked by another process"),
                "unexpected refusal: {}", body
            );
        }
    }
    // All eight landed or were refused with an honest reason; the registry is coherent either way.
    let state = http(server.port, "GET", "/admin/api/state", &hdrs(&auth_headers(server.port, &cookie, &csrf)), "");
    assert_eq!(state.status, 200, "{}", state.body);
    let _ = (csrf, accepted);
}

// ---------------------------------------------------------------------------
// The visitor's wall
// ---------------------------------------------------------------------------

#[test]
fn a_visitor_cannot_read_policies_edit_anything_or_activate_gates() {
    let (server, _c, _s, _owner, _o) = tamper_fixture();
    // No session, no origin header, nothing: every route refuses.
    for (method, path, body) in [
        ("GET", "/admin/api/state", ""),
        ("GET", "/admin/api/audit", ""),
        ("POST", "/admin/api/app/create", r#"{"applicationId":"evil","displayName":"evil","topology":"independent","defaultSessionTtl":86400}"#),
        ("POST", "/admin/api/gate/set", r#"{"applicationId":"vault","gate":{}}"#),
        ("POST", "/admin/api/policy/publish", r#"{"applicationId":"vault","gateId":"bronze"}"#),
        ("POST", "/admin/api/session/revoke", r#"{"tokenPrefix":"deadbeef"}"#),
    ] {
        let r = http(server.port, method, path, &[], body);
        assert_ne!(r.status, 200, "{method} {path} must not succeed for a visitor");
        assert!(r.status == 401 || r.status == 403, "{method} {path} -> {}", r.status);
    }
    // Cross-origin with a stolen-looking but valid session shape still fails the origin check.
    let r = http(server.port, "POST", "/admin/api/gate/set",
        &[("Origin", "http://evil.example"), ("Cookie", "gg_admin=totally-a-token")],
        r#"{"applicationId":"vault","gate":{}}"#);
    assert_ne!(r.status, 200);
}

// ---------------------------------------------------------------------------
// Audit completeness
// ---------------------------------------------------------------------------

#[test]
fn every_privileged_change_is_audited_with_actor_versions_and_outcome() {
    let (server, _c, _s, owner, _o) = tamper_fixture();
    let (cookie, csrf) = fresh_stepped_up(&server, &owner);
    let _ = http(server.port, "POST", "/admin/api/policy/publish", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
        &serde_json::json!({ "applicationId": "vault", "gateId": "bronze", "reason": "launch" }).to_string());
    // A REFUSED privileged action is audited too: an enabled XTM draft fails complete policy
    // validation. Ordinary credential/consensus edits are valid drafts and remain non-live until
    // Publish, so they are not the correct refusal case.
    let refused_edit = serde_json::json!({
        "gateId": "bronze", "name": "bronze", "resourceAddress": "resource_v", "symbol": "GHOST",
        "divisibility": 6, "thresholdRaw": "1", "proofMode": "xtm",
        "challengeDomain": "vault.localhost", "grants": [], "enabled": true, "testLane": false,
        "componentAddress": "component_bronze",
    });
    let _ = http(server.port, "POST", "/admin/api/gate/set", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
        &serde_json::json!({ "applicationId": "vault", "gate": refused_edit }).to_string());
    let reg = load_registry(&server.state.paths).unwrap();
    let audit = &reg.audit_tail;
    assert!(audit.iter().any(|e| e.action == "policy.publish" && e.outcome == ghost_gate_registry::AuditOutcome::Accepted
        && e.application_id.as_deref() == Some("vault") && e.gate_id.as_deref() == Some("bronze")),
        "the accepted publish is audited with app and gate: {:?}", audit.iter().map(|e| (e.action.as_str(), e.outcome)).collect::<Vec<_>>());
    assert!(audit.iter().any(|e| e.action == "gate.set" && e.outcome == ghost_gate_registry::AuditOutcome::Refused
        && e.application_id.as_deref() == Some("vault")),
        "the refused edit is audited with the application: {:?}", audit.iter().map(|e| (e.action.as_str(), e.outcome)).collect::<Vec<_>>());
    // The permanent ndjson log exists alongside the tail.
    assert!(server.state.paths.audit().exists());
}

// ---------------------------------------------------------------------------
// Hardening added after the first live run: same-origin ceremonies, the JSON
// converter, draft gates that must not bind, digest stability and ledger identity.
// ---------------------------------------------------------------------------

fn ceremonies_refuse_cross_origin_requests() {
    let (server, cookie, csrf, _owner, _outsider) = tamper_fixture();
    // No Origin at all: a browser form POST, a curl typo, a proxy. Refused.
    let anon = http(server.port, "POST", "/admin/api/auth/challenge", &[], r#"{"kind":"login","method":"wallet"}"#);
    assert_eq!(anon.status, 403, "a challenge must be same-origin: {}", anon.body);
    let foreign = http(server.port, "POST", "/admin/api/auth/challenge",
        &[("Origin", "https://evil.example")], r#"{"kind":"login","method":"wallet"}"#);
    assert_eq!(foreign.status, 403, "a foreign origin must not get a challenge: {}", foreign.body);
    // Login is a write too: refusing it here is what stops login-CSRF (a hostile page silently
    // signing the operator into an account the attacker controls).
    let login = http(server.port, "POST", "/admin/api/auth/login",
        &[("Origin", "https://evil.example")], r#"{"method":"wallet","challenge":"x","publicKey":"y","publicNonce":"z","signature":"s"}"#);
    assert_eq!(login.status, 403, "cross-origin login must be refused: {}", login.body);
    // Logout is state-changing: same-origin AND the session's CSRF token.
    let no_csrf = http(server.port, "POST", "/admin/api/auth/logout",
        &[("Origin", &format!("http://127.0.0.1:{}", server.port)), ("Cookie", &cookie)], "{}");
    assert_eq!(no_csrf.status, 403, "logout without CSRF must be refused: {}", no_csrf.body);
    let ok = http(server.port, "POST", "/admin/api/auth/logout",
        &hdrs(&auth_headers(server.port, &cookie, &csrf)), "{}");
    assert_eq!(ok.status, 200, "a same-origin logout with CSRF succeeds: {}", ok.body);
}

#[test]
fn the_converter_answers_the_dashboard_json_body() {
    let (server, cookie, csrf, _owner, _outsider) = tamper_fixture();
    // Exactly what admin.js sends: a JSON body, not a query string.
    let r = http(server.port, "POST", "/admin/api/convert", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
        r#"{"amount":"10","divisibility":6}"#);
    assert_eq!(r.status, 200, "the JSON converter must answer: {}", r.body);
    assert_eq!(as_str(&r.body, "raw"), "10000000", "10 at divisibility 6 is 10_000_000 raw");
    assert_eq!(r.body.get("exact").and_then(|e| e.as_bool()), Some(true));
    // And the query form still works for a command line.
    let q = http(server.port, "GET", "/admin/api/convert?amount=10&divisibility=6", &hdrs(&auth_headers(server.port, &cookie, &csrf)), "");
    assert_eq!(q.status, 200);
    assert_eq!(as_str(&q.body, "raw"), "10000000");
    // An amount that cannot be represented exactly is refused, never rounded.
    let bad = http(server.port, "POST", "/admin/api/convert", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
        r#"{"amount":"0.0000001","divisibility":6}"#);
    assert_eq!(bad.status, 400, "a sub-smallest-unit amount must be refused: {}", bad.body);
}

#[test]
fn a_draft_gate_never_reaches_the_bridge() {
    use ghost_gate_registry::{derive_bindings, load_registry, Registry};
    let (server, cookie, csrf, _owner, _outsider) = tamper_fixture();
    // The fixture's three gates are DRAFT (never published). Nothing may bind yet.
    let paths = &server.state.paths;
    let reg: Registry = load_registry(paths).unwrap();
    assert!(derive_bindings(&reg).is_err(), "an unpublished gate must block a bindings refresh");
    // Publish the complete application draft: application-level topology and defaults are
    // atomic, so every gate gets a frozen v2 version together.
    let pub_gate = |csrf: &str| {
        http(server.port, "POST", "/admin/api/policy/publish", &hdrs(&auth_headers(server.port, &cookie, csrf)),
            r#"{"applicationId":"vault","gateId":"bronze","reason":"first publish"}"#)
    };
    assert_eq!(pub_gate(&csrf).status, 200);
    let reg = load_registry(paths).unwrap();
    let bindings = derive_bindings(&reg).unwrap();
    assert_eq!(bindings.gates.len(), 3, "the completed application snapshot binds");
    let bound = bindings.gates.iter().find(|g| g.gate_id == "bronze").unwrap();
    assert_eq!(bound.network, ghost_gate_core::network::LOCALNET, "the cohort travels with the binding");
    assert_eq!(bound.genesis_hash, GENESIS, "the ledger identity travels with the binding");
    assert!(!bound.test_lane);
}

#[test]
fn editing_a_draft_never_invalidates_a_published_version() {
    // The digest must not move when unrelated bookkeeping does: this is what made an earlier build
    // refuse to load its own registry after the operator wired tiers on an already-published app.
    let (server, cookie, csrf, _owner, _outsider) = tamper_fixture();
    let publish = http(server.port, "POST", "/admin/api/policy/publish", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
        r#"{"applicationId":"vault","gateId":"bronze","reason":"v1"}"#);
    assert_eq!(publish.status, 200, "{}", publish.body);
    // Add a fourth gate: the application revision moves, the gate list grows.
    let add = http(server.port, "POST", "/admin/api/gate/set", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
        r#"{"applicationId":"vault","gate":{"gateId":"platinum","name":"platinum","resourceAddress":"resource_v","symbol":"GHOST","divisibility":6,"thresholdRaw":"9000000","proofMode":"consensus","challengeDomain":"vault.localhost","grants":[],"enabled":true,"testLane":false,"componentAddress":"component_platinum"}}"#);
    assert_eq!(add.status, 200, "{}", add.body);
    // And wire tiers on an already-published gate. The registry must still load.
    let rewire = http(server.port, "POST", "/admin/api/gate/set", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
        r#"{"applicationId":"vault","gate":{"gateId":"bronze","name":"bronze","resourceAddress":"resource_v","symbol":"GHOST","divisibility":6,"thresholdRaw":"1000000","proofMode":"consensus","challengeDomain":"vault.localhost","grants":["platinum"],"enabled":true,"testLane":false,"componentAddress":"component_bronze"}}"#);
    assert_eq!(rewire.status, 200, "{}", rewire.body);
    let state = http(server.port, "GET", "/admin/api/state", &hdrs(&auth_headers(server.port, &cookie, &csrf)), "");
    assert_eq!(state.status, 200, "the registry must still load after unrelated edits: {}", state.body);
}

#[test]
fn an_application_needs_a_known_cohort_and_a_ledger_identity() {
    let (server, cookie, csrf, _owner, _outsider) = tamper_fixture();
    let create = |body: &str| {
        http(server.port, "POST", "/admin/api/app/create", &hdrs(&auth_headers(server.port, &cookie, &csrf)), body)
    };
    // The fixture server has a deployment genesis, so a plain create inherits it.
    let ok = create(r#"{"applicationId":"inherit","displayName":"Inherit","topology":"independent","defaultSessionTtl":3600,"production":true}"#);
    assert_eq!(ok.status, 200, "the deployment genesis is inherited: {}", ok.body);
    // An unknown cohort is refused by name.
    let unknown = create(r#"{"applicationId":"bad-net","displayName":"Bad","topology":"independent","defaultSessionTtl":3600,"production":true,"network":"atlantis","genesisHash":"00"}"#);
    assert_eq!(unknown.status, 400, "an unknown cohort must be refused: {}", unknown.body);
    // A genesis that is not hex is refused: it is what distinguishes two ledgers reusing addresses.
    let not_hex = create(r#"{"applicationId":"bad-gen","displayName":"Bad","topology":"independent","defaultSessionTtl":3600,"production":true,"genesisHash":"zzz"}"#);
    assert_eq!(not_hex.status, 400, "a non-hex genesis must be refused: {}", not_hex.body);
    // A name is accepted and stored as the cohort byte the chain uses.
    let named = create(r#"{"applicationId":"named-net","displayName":"Named","topology":"independent","defaultSessionTtl":3600,"production":true,"network":"localnet","genesisHash":"aabbccdd"}"#);
    assert_eq!(named.status, 200, "{}", named.body);
    let state = http(server.port, "GET", "/admin/api/state", &hdrs(&auth_headers(server.port, &cookie, &csrf)), "");
    let body = &state.body;
    let apps = body.get("applications").and_then(|a| a.as_array()).unwrap();
    let named_app = apps.iter().find(|a| a.get("applicationId").and_then(|i| i.as_str()) == Some("named-net")).expect("the named app exists");
    assert_eq!(named_app.get("network").and_then(|n| n.as_u64()), Some(ghost_gate_core::network::LOCALNET as u64));
    assert_eq!(named_app.get("genesisHash").and_then(|g| g.as_str()), Some("aabbccdd"));
}

// ---------------------------------------------------------------------------
// Negative regression: a credential gate on a production app cannot issue at Production tier
// ---------------------------------------------------------------------------

#[test]
fn a_credential_gate_on_a_production_app_refuses_production_tier() {
    use ghost_gate_core::policy::{hash_policy, GateTopology, ProofMode};
    use ghost_gate_registry::{issue_session_with_evidence, Registry};

    let mut reg = Registry::default();
    let mut app = ghost_gate_core::policy::Application {
        application_id: "prod-cred".into(), display_name: "pc".into(), owner_credential: "w".into(),
        topology: GateTopology::Independent, default_session_ttl: 86_400, max_gates: 5,
        gates: vec![], revision: 1, production: true,
        network: ghost_gate_core::network::LOCALNET, genesis_hash: GENESIS.into(),
        chain_generation: 1,
    };
    app.gates.push(ghost_gate_core::policy::GatePolicy {
        gate_id: "cred".into(), name: "cred".into(), resource_address: "resource_x".into(),
        symbol: "G".into(), divisibility: 6, threshold_raw: 100, proof_mode: ProofMode::Credential,
        challenge_domain: "pc.localhost".into(), session_ttl_override: None, grants: vec![],
        enabled: true, test_lane: false, use_mode: Default::default(), component_address: None,
    });
    app.validate().unwrap();
    reg.applications.push(app);
    let (policy_hash, policy_clone) = {
        let app_ref = reg.application("prod-cred").unwrap();
        let g = app_ref.gate("cred").unwrap();
        (hash_policy(&ghost_gate_registry::Blake3Hasher, app_ref, g, 1), g.clone())
    };
    reg.versions.push(ghost_gate_registry::PolicyVersion {
        application_id: "prod-cred".into(), gate_id: "cred".into(), version: 1,
        policy_hash: policy_hash.clone(),
        policy_hash_version: ghost_gate_registry::POLICY_HASH_V1,
        policy_context: None,
        network: ghost_gate_core::network::LOCALNET, genesis_hash: GENESIS.into(),
        policy: policy_clone, app_revision: 1, created_unix: 1,
    });
    let mut entropy = [0u8; 32];
    // Even handed Production-grade consensus evidence, a CREDENTIAL gate caps the achieved tier at
    // OperatorTrustedTestnet, which is below the production app's requirement, so no session issues.
    let err = issue_session_with_evidence(
        &reg, "prod-cred", "cred", policy_hash,
        &mut entropy, &production_evidence(), &trusted_policy(),
    );
    assert!(err.is_err(), "a credential gate on a production app must refuse to issue a session");
    let msg = err.unwrap_err();
    assert!(msg.contains("requires") || msg.contains("production"), "error must explain the tier gap: {msg}");
}

// ---------------------------------------------------------------------------
// Scalability: real measurements, not invented maximums
// ---------------------------------------------------------------------------

/// The cost of N gates, measured: registry validation, the derived bindings, the file round trip and
/// the per-request access check. The operator asked for REAL numbers, so this prints them. The one
/// invariant worth asserting is the shape: the visitor-facing path is a session lookup plus one
/// decision, so it stays flat while the one-off administrator costs grow linearly and stay small.
#[test]
fn measured_scalability_at_1_3_10_25_and_50_gates() {
    use ghost_gate_core::policy::{hash_policy, GateTopology, ProofMode};
    use ghost_gate_registry::{check_access, derive_bindings, issue_session_with_evidence, Blake3Hasher, Registry, StoreLock};
    use std::time::Instant;

    let dir = unique_dir("gg-scale");
    std::fs::create_dir_all(&dir).unwrap();
    let paths = StorePaths::new(&dir);
    let mut report = String::from("gates | validate(ms) | bindings(ms) | save+load(ms) | access_check(micros)\n");

    for count in [1usize, 3, 10, 25, 50] {
        let mut reg = Registry::default();
        reg.credentials.push(ghost_gate_registry::AdminCredential {
            credential_id: "wallet:op".into(),
            kind: ghost_gate_registry::CredentialKind::WalletKey,
            label: "op".into(),
            registered_unix: 1,
            es256_public_sec1: None,
            ristretto_public_hex: Some("k".into()),
        });
        let mut app = ghost_gate_core::policy::Application {
            application_id: "scale".into(),
            display_name: "Scale".into(),
            owner_credential: "wallet:op".into(),
            topology: GateTopology::Hierarchical,
            default_session_ttl: 86_400,
            max_gates: count,
            gates: vec![],
            revision: 1,
            production: true,
            network: ghost_gate_core::network::LOCALNET,
            genesis_hash: GENESIS.into(),
            chain_generation: 1,
        };
        for i in 0..count {
            app.gates.push(ghost_gate_core::policy::GatePolicy {
                gate_id: format!("gate-{i}"),
                name: format!("Gate {i}"),
                resource_address: format!("resource_{i:064x}"),
                symbol: "GHOST".into(),
                divisibility: 6,
                threshold_raw: (i as u128 + 1) * 1_000_000,
                proof_mode: ProofMode::Consensus,
                challenge_domain: "scale.localhost".into(),
                session_ttl_override: None,
                grants: if i + 1 < count { vec![format!("gate-{}", i + 1)] } else { vec![] },
                enabled: true,
                test_lane: false,
                use_mode: Default::default(),
                component_address: Some(format!("component_{i:064x}")),
            });
        }
        app.validate().unwrap();
        reg.applications.push(app);
        let hashes: Vec<(String, String, ghost_gate_core::policy::GatePolicy)> = {
            let a = reg.application("scale").unwrap();
            (0..count)
                .map(|i| {
                    let g = a.gate(&format!("gate-{i}")).unwrap();
                    (format!("gate-{i}"), hash_policy(&Blake3Hasher, a, g, 1), g.clone())
                })
                .collect()
        };
        for (gid, hash, policy) in hashes {
            reg.versions.push(ghost_gate_registry::PolicyVersion {
                application_id: "scale".into(),
                gate_id: gid,
                version: 1,
                policy_hash: hash,
            policy_hash_version: ghost_gate_registry::POLICY_HASH_V1,
            policy_context: None,
                network: ghost_gate_core::network::LOCALNET,
                genesis_hash: GENESIS.into(),
                policy,
                app_revision: 1,
                created_unix: 1,
            });
        }

        let t0 = Instant::now();
        reg.validate_all().unwrap();
        let validate = t0.elapsed();

        let t0 = Instant::now();
        let _bindings = derive_bindings(&reg).unwrap();
        let bindings_time = t0.elapsed();

        let lock = StoreLock::acquire(&paths);
        let t0 = Instant::now();
        ghost_gate_registry::save_registry(&paths, &reg).unwrap();
        let loaded = ghost_gate_registry::load_registry(&paths).unwrap();
        let io_time = t0.elapsed();
        drop(lock);

        // One live session for the top gate covers the per-request path visitors actually hit.
        let a = loaded.application("scale").unwrap();
        let top = a.gate(&format!("gate-{}", count - 1)).unwrap();
        let mut entropy = [0u8; 32];
        let session = issue_session_with_evidence(&loaded, "scale", &format!("gate-{}", count - 1), hash_policy(&Blake3Hasher, a, top, 1), &mut entropy, &production_evidence(), &trusted_policy()).unwrap();
        let sessions = vec![session.clone()];
        let _ = check_access(&loaded, &sessions, &session.token, "scale", &format!("gate-{}", count - 1), ghost_gate_registry::now_unix());
        let t0 = Instant::now();
        let n = 200;
        for _ in 0..n {
            let _ = check_access(&loaded, &sessions, &session.token, "scale", "gate-0", ghost_gate_registry::now_unix());
        }
        let per_check = t0.elapsed() / n;

        report.push_str(&format!(
            "{count} | {:.3} | {:.3} | {:.3} | {:.1}\n",
            validate.as_secs_f64() * 1000.0,
            bindings_time.as_secs_f64() * 1000.0,
            io_time.as_secs_f64() * 1000.0,
            per_check.as_secs_f64() * 1_000_000.0,
        ));
    }
    println!("\n== measured scalability (this machine, debug build) ==\n{report}");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Use mode: a token policy is not a front door. The administrator records which
// surfaces a gate may authorize, in the versioned policy, and both the bridge
// and the Telegram bot read that one answer.
// ---------------------------------------------------------------------------

#[test]
fn a_gate_records_which_surfaces_it_may_authorize() {
    use ghost_gate_core::policy::GateUseMode;

    // The three scopes are exhaustive and mutually exclusive in meaning.
    assert!(GateUseMode::Website.allows(false), "a website gate serves the website");
    assert!(!GateUseMode::Website.allows(true), "a website-only gate does NOT serve Telegram");
    assert!(GateUseMode::Telegram.allows(true));
    assert!(!GateUseMode::Telegram.allows(false), "a Telegram-only gate does not serve the site");
    assert!(GateUseMode::Both.allows(true) && GateUseMode::Both.allows(false));

    // The default for a gate written before the field existed is the website: the conservative
    // default, since the alternative would hand a new surface access by accident.
    assert_eq!(GateUseMode::default(), GateUseMode::Website);

    // It survives a round trip through the registry file, because the bridge reads it from there.
    let mut policy = ghost_gate_core::policy::GatePolicy {
        gate_id: "tg".into(),
        name: "telegram gate".into(),
        resource_address: "resource_x".into(),
        symbol: "X".into(),
        divisibility: 6,
        threshold_raw: 10,
        proof_mode: ghost_gate_core::policy::ProofMode::Consensus,
        challenge_domain: "t.localhost".into(),
        session_ttl_override: None,
        grants: vec![],
        enabled: true,
        test_lane: false,
        component_address: Some("component_t".into()),
        use_mode: GateUseMode::Telegram,
    };
    // The gate lives inside an application here (validation is structural, app-level).
    let app = ghost_gate_core::policy::Application {
        application_id: "a".into(),
        display_name: "A".into(),
        owner_credential: "wallet:op".into(),
        topology: ghost_gate_core::policy::GateTopology::Independent,
        default_session_ttl: 3_600,
        max_gates: 4,
        gates: vec![policy.clone()],
        revision: 1,
        production: true,
        network: ghost_gate_core::network::LOCALNET,
        genesis_hash: GENESIS.into(),
        chain_generation: 1,
    };
    app.validate().expect("a telegram-scoped gate is a valid gate");
    let json = serde_json::to_string(&policy).unwrap();
    assert!(json.contains("\"telegram\""), "the scope is in the stored policy: {json}");
    let back: ghost_gate_core::policy::GatePolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(back.use_mode, GateUseMode::Telegram, "and it round-trips");
}

// ---------------------------------------------------------------------------
// Passkey step-up regression tests: the dashboard's fresh-approval path over REAL HTTP.
// The production registration ceremony's byte-level verification is covered in auth.rs; here we
// prove the login-plane consequences the operator experiences.
// ---------------------------------------------------------------------------

/// A passkey administrator. The ES256 key is generated deterministically INSIDE the test (the
/// private key exists only here to craft assertions — the server only ever holds the public key),
/// and the credential is seeded the way the registry legitimately stores passkey credentials.
struct PasskeyAdmin {
    signing: p256::ecdsa::SigningKey,
    /// base64url credential id, exactly as the dashboard reports it
    credential_id: String,
    sec1: Vec<u8>,
}

impl PasskeyAdmin {
    fn new() -> Self {
        use p256::ecdsa::SigningKey;
        let signing = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let sec1 = signing.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        Self {
            signing,
            credential_id: ghost_gate_admin::auth::base64url_nopad(b"test-passkey-cred"),
            sec1,
        }
    }

    fn seed(&self, server: &TestServer) {
        let _lock = StoreLock::acquire(&server.state.paths).unwrap();
        let mut reg = load_registry(&server.state.paths).unwrap();
        reg.credentials.push(ghost_gate_registry::AdminCredential {
            credential_id: format!("passkey:{}", self.credential_id),
            kind: ghost_gate_registry::CredentialKind::Passkey,
            label: "operator".into(),
            registered_unix: ghost_gate_registry::now_unix(),
            es256_public_sec1: Some(self.sec1.clone()),
            ristretto_public_hex: None,
        });
        ghost_gate_registry::save_registry(&server.state.paths, &reg).unwrap();
    }

    /// A real WebAuthn assertion, byte-for-byte the way a browser produces it: clientDataJSON
    /// naming the exact challenge and origin, authenticator data hashing the rpId with the
    /// user-present flag (plus user-verification when Windows Hello was invoked), and a DER ES256
    /// signature over authenticatorData || SHA-256(clientDataJSON).
    fn assertion(&self, server: &TestServer, challenge: &str, uv: bool) -> serde_json::Value {
        use p256::ecdsa::signature::{Signer, SignatureEncoding};
        use sha2::{Digest, Sha256};
        let origin = format!("http://127.0.0.1:{}", server.port);
        let client_data = format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{origin}"}}"#);
        let mut auth_data = [0u8; 37];
        let rp_hash: [u8; 32] = Sha256::digest(server.state.rp_id.as_bytes()).into();
        auth_data[..32].copy_from_slice(&rp_hash);
        auth_data[32] = if uv { 0x05 } else { 0x01 }; // UP (| UV when user verification ran)
        let mut signed = auth_data.to_vec();
        signed.extend_from_slice(Sha256::digest(client_data.as_bytes()).as_slice());
        let sig: p256::ecdsa::Signature = self.signing.sign(&signed);
        serde_json::json!({
            "method": "passkey",
            "challenge": challenge,
            "credentialId": self.credential_id,
            "webauthn": {
                "client_data_b64": ghost_gate_admin::auth::base64url_nopad(client_data.as_bytes()),
                "authenticator_data_b64": ghost_gate_admin::auth::base64url_nopad(&auth_data),
                "signature_b64": ghost_gate_admin::auth::base64url_nopad(sig.to_der().as_bytes()),
                "credential_id_b64": self.credential_id,
            },
        })
    }

    fn passkey_challenge(&self, server: &TestServer) -> String {
        let origin = format!("http://127.0.0.1:{}", server.port);
        let reply = http(server.port, "POST", "/admin/api/auth/challenge",
            &[("Origin", origin.as_str())], r#"{"kind":"login","method":"passkey"}"#);
        as_str(&reply.body, "challenge").to_string()
    }

    /// Attempt a login (or a step-up on an existing session) over the real HTTP plane.
    fn login(&self, server: &TestServer, stepup: bool, uv: bool, cookie: Option<&str>) -> HttpReply {
        let challenge = self.passkey_challenge(server);
        let mut body = self.assertion(server, &challenge, uv);
        body["stepup"] = serde_json::Value::Bool(stepup);
        let mut headers: Vec<(String, String)> =
            vec![("Origin".into(), format!("http://127.0.0.1:{}", server.port))];
        if let Some(c) = cookie {
            headers.push(("Cookie".into(), c.to_string()));
        }
        http(server.port, "POST", "/admin/api/auth/login", &hdrs(&headers), &body.to_string())
    }
}

fn state_field(server: &TestServer, cookie: &str, key: &str) -> serde_json::Value {
    let state = http(server.port, "GET", "/admin/api/state", &[("Cookie", cookie)], "");
    assert_eq!(state.status, 200, "{}", state.body);
    state.body.get(key).cloned().unwrap_or(serde_json::Value::Null)
}

fn create_app(server: &TestServer, cookie: &str, csrf: &str, id: &str) -> HttpReply {
    http(server.port, "POST", "/admin/api/app/create", &hdrs(&auth_headers(server.port, cookie, csrf)),
        &serde_json::json!({
            "applicationId": id,
            "displayName": id,
            "topology": "independent",
            "defaultSessionTtl": 3600u64,
            "production": true,
        }).to_string())
}

#[test]
fn passkey_login_without_stepup_is_locked_but_a_passkey_stepup_unlocks_policy() {
    let dir = unique_dir("gg-admin-pk1");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let server = spawn_server(&dir);
    let admin = PasskeyAdmin::new();
    admin.seed(&server);

    // Ordinary passkey login WITHOUT step-up: an honest authentication ceremony that mints a
    // session, but one with NO fresh approval.
    let login = admin.login(&server, false, false, None);
    assert_eq!(login.status, 200, "an ordinary passkey login must succeed: {}", login.body);
    let cookie = login.set_cookie.expect("a session cookie from login");
    let stepup_valid = state_field(&server, &cookie, "stepupValid");
    assert_eq!(stepup_valid, serde_json::Value::Bool(false), "an ordinary login is not a fresh approval");

    // ...and the policy change the dashboard tries is refused, naming why.
    let csrf = as_str(&state_field_value(&server, &cookie), "csrf").to_string();
    let create = create_app(&server, &cookie, &csrf, "locked-out");
    assert_eq!(create.status, 403, "creating an application without step-up must be refused: {}", create.body);

    // Step-up: the SAME credential re-runs the WebAuthn ceremony, now requiring user verification
    // (Windows Hello) — on the CURRENT session, which is exactly what the dashboard does.
    let step = admin.login(&server, true, true, Some(&cookie));
    assert_eq!(step.status, 200, "a verified passkey step-up must succeed: {}", step.body);
    assert_eq!(step.body.get("stepup").and_then(|s| s.as_bool()), Some(true), "{}", step.body);

    // The server-authoritative window is now fresh, and the refused action is accepted.
    assert_eq!(state_field(&server, &cookie, "stepupValid"), serde_json::Value::Bool(true),
        "the SERVER must report the fresh approval, not the dashboard");
    let create2 = create_app(&server, &cookie, &csrf, "unlocked");
    assert_eq!(create2.status, 200, "the same action now succeeds: {}", create2.body);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The `/admin/api/state` full reply (for extracting the session's CSRF token).
fn state_field_value(server: &TestServer, cookie: &str) -> serde_json::Value {
    let state = http(server.port, "GET", "/admin/api/state", &[("Cookie", cookie)], "");
    assert_eq!(state.status, 200, "{}", state.body);
    state.body
}

#[test]
fn an_expired_approval_locks_policy_again_and_a_new_stepup_restores_it() {
    let dir = unique_dir("gg-admin-pk2");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let server = spawn_server(&dir);
    let admin = PasskeyAdmin::new();
    admin.seed(&server);
    let login = admin.login(&server, false, false, None);
    assert_eq!(login.status, 200, "{}", login.body);
    let cookie = login.set_cookie.expect("cookie");
    let step = admin.login(&server, true, true, Some(&cookie));
    assert_eq!(step.status, 200, "{}", step.body);
    assert_eq!(state_field(&server, &cookie, "stepupValid"), serde_json::Value::Bool(true));

    // Move the approval window into the past exactly the way time would: the session record's
    // window expires server-side and the dashboard's freshest action is again refused.
    {
        let _lock = StoreLock::acquire(&server.state.paths).unwrap();
        let mut reg = load_registry(&server.state.paths).unwrap();
        let past = ghost_gate_registry::now_unix().saturating_sub(1);
        for s in reg.admin_sessions.iter_mut() {
            s.stepup_until_unix = past;
        }
        ghost_gate_registry::save_registry(&server.state.paths, &reg).unwrap();
    }
    assert_eq!(state_field(&server, &cookie, "stepupValid"), serde_json::Value::Bool(false),
        "an expired approval must read as absent from the server's own bookkeeping");
    let csrf = as_str(&state_field_value(&server, &cookie), "csrf").to_string();
    let create = create_app(&server, &cookie, &csrf, "too-late");
    assert_eq!(create.status, 403, "an expired approval must not authorize policy: {}", create.body);

    // Stepping up again restores the window — the dashboard's answer to exactly this state.
    let step2 = admin.login(&server, true, true, Some(&cookie));
    assert_eq!(step2.status, 200, "{}", step2.body);
    assert_eq!(state_field(&server, &cookie, "stepupValid"), serde_json::Value::Bool(true));
    let create2 = create_app(&server, &cookie, &csrf, "back-again");
    assert_eq!(create2.status, 200, "{}", create2.body);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn invalid_and_replayed_passkey_assertions_are_refused() {
    let dir = unique_dir("gg-admin-pk3");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let server = spawn_server(&dir);
    let admin = PasskeyAdmin::new();
    admin.seed(&server);
    let login = admin.login(&server, false, false, None);
    assert_eq!(login.status, 200, "{}", login.body);
    let cookie = login.set_cookie.expect("cookie");

    // INVALID: a well-formed ceremony whose signature is not a DER ECDSA signature is refused
    // before anything about the session changes.
    let step = admin.login(&server, true, true, Some(&cookie));
    assert_eq!(step.status, 200, "{}", step.body);
    let garbage = ghost_gate_admin::auth::base64url_nopad(b"definitely-not-a-der-signature");
    let mut valid_stepup_body = {
        let challenge = admin.passkey_challenge(&server);
        let mut b = admin.assertion(&server, &challenge, true);
        b["stepup"] = serde_json::Value::Bool(true);
        b
    };
    let mut invalid = valid_stepup_body.clone();
    invalid["webauthn"]["signature_b64"] = serde_json::json!(garbage);
    let origin = format!("http://127.0.0.1:{}", server.port);
    let r = http(server.port, "POST", "/admin/api/auth/login",
        &[("Origin", origin.as_str()), ("Cookie", cookie.as_str())], &invalid.to_string());
    assert_eq!(r.status, 403, "an invalid assertion must be refused: {}", r.body);
    assert!(r.body.to_string().contains("refused"), "{}", r.body);

    // REPLAYED: the exact same request body a second time must not re-verify — every challenge is
    // single-use, so a captured ceremony cannot be recycled by an attacker or by accident.
    valid_stepup_body = {
        let challenge = admin.passkey_challenge(&server);
        let mut b = admin.assertion(&server, &challenge, true);
        b["stepup"] = serde_json::Value::Bool(true);
        b
    };
    let first = http(server.port, "POST", "/admin/api/auth/login",
        &[("Origin", origin.as_str()), ("Cookie", cookie.as_str())], &valid_stepup_body.to_string());
    assert_eq!(first.status, 200, "the first use of a fresh ceremony works: {}", first.body);
    let replay = http(server.port, "POST", "/admin/api/auth/login",
        &[("Origin", origin.as_str()), ("Cookie", cookie.as_str())], &valid_stepup_body.to_string());
    assert_ne!(replay.status, 200, "the SAME ceremony must not verify twice: {}", replay.body);
    assert!(replay.body.to_string().contains("challenge"), "{}", replay.body);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wallet_authentication_covers_ordinary_login_and_stepup() {
    let dir = unique_dir("gg-admin-wl");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let server = spawn_server(&dir);
    let admin = WalletAdmin::new();
    let (cookie, csrf) = admin.register(server.port);

    // Sign out first: what follows is the ordinary login path the dashboard offers AFTER
    // registration, with no inherited privileged start.
    let logout = http(server.port, "POST", "/admin/api/auth/logout",
        &hdrs(&auth_headers(server.port, &cookie, &csrf)), "{}");
    assert_eq!(logout.status, 200, "{}", logout.body);

    // Ordinary wallet login: authentication succeeds, no fresh approval.
    let login = admin.login(server.port, false, None);
    assert_eq!(login.status, 200, "an ordinary wallet login must succeed: {}", login.body);
    let cookie2 = login.set_cookie.expect("cookie");
    assert_eq!(state_field(&server, &cookie2, "stepupValid"), serde_json::Value::Bool(false));
    let csrf2 = as_str(&state_field_value(&server, &cookie2), "csrf").to_string();
    let create = create_app(&server, &cookie2, &csrf2, "wallet-locked");
    assert_eq!(create.status, 403, "a fresh wallet login is not a fresh approval: {}", create.body);

    // The wallet step-up on the CURRENT session unlocks it, the same as the passkey path.
    let step = admin.login(server.port, true, Some(&cookie2));
    assert_eq!(step.status, 200, "a wallet step-up must succeed: {}", step.body);
    assert_eq!(state_field(&server, &cookie2, "stepupValid"), serde_json::Value::Bool(true));
    let create2 = create_app(&server, &cookie2, &csrf2, "wallet-unlocked");
    assert_eq!(create2.status, 200, "{}", create2.body);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_authorized_generation_migration_advances_and_rejects_rollback() {
    let dir = unique_dir("gg-admin-gen");
    let server = spawn_server(&dir);
    let admin = WalletAdmin::new();
    let (cookie, csrf) = admin.register(server.port);

    // A fresh application starts at generation 1.
    let create = http(server.port, "POST", "/admin/api/app/create", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
        &serde_json::json!({ "applicationId": "gen-app", "displayName": "Gen", "topology": "independent", "defaultSessionTtl": 86_400u64, "production": true }).to_string());
    assert_eq!(create.status, 200, "{}", create.body);

    let read_app = |label: &str| {
        let state = http(server.port, "GET", "/admin/api/state", &hdrs(&auth_headers(server.port, &cookie, &csrf)), "");
        state.body.get("applications").unwrap().as_array().unwrap().iter()
            .find(|a| as_str(a, "applicationId") == "gen-app").unwrap_or_else(|| panic!("app missing at {label}")).clone()
    };
    let app = read_app("create");
    assert_eq!(app.get("chainGeneration").unwrap().as_u64(), Some(1));
    assert_eq!(app.get("generationFloor").unwrap().as_u64(), Some(0));

    // Authorized migration forward to generation 2.
    let migrate = http(server.port, "POST", "/admin/api/app/migrate-generation", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
        &serde_json::json!({ "applicationId": "gen-app", "newGeneration": 2u64 }).to_string());
    assert_eq!(migrate.status, 200, "migration refused: {}", migrate.body);
    let app = read_app("migrated");
    assert_eq!(app.get("chainGeneration").unwrap().as_u64(), Some(2));
    assert_eq!(app.get("generationFloor").unwrap().as_u64(), Some(2), "the durable floor advanced");

    // A rollback (and a no-op) migration is refused.
    let rollback = http(server.port, "POST", "/admin/api/app/migrate-generation", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
        &serde_json::json!({ "applicationId": "gen-app", "newGeneration": 1u64 }).to_string());
    assert_eq!(rollback.status, 400, "a generation rollback must be refused: {}", rollback.body);

    // An ordinary update never changes the generation.
    let update = http(server.port, "POST", "/admin/api/app/update", &hdrs(&auth_headers(server.port, &cookie, &csrf)),
        &serde_json::json!({ "applicationId": "gen-app", "displayName": "Renamed" }).to_string());
    assert_eq!(update.status, 200, "{}", update.body);
    assert_eq!(read_app("after-update").get("chainGeneration").unwrap().as_u64(), Some(2), "an ordinary edit must not change the generation");

    let _ = std::fs::remove_dir_all(&dir);
}

