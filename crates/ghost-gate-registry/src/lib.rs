//! The one authoritative store for Ghost Gate: applications, published gate policies, verified
//! sessions, administrator credentials and the audit log.
//!
//! # Who owns what
//!
//! - The **admin plane** (the `ghost-gate-admin` server) is the only writer of the registry. It
//!   authenticates administrators, validates every mutation, and publishes immutable policy
//!   versions.
//! - The **bridge** is a reader: it loads a derived bindings snapshot and re-reads it when the file
//!   changes. It never takes policy from a browser.
//! - Integrations (Haunted Vault, Telegram, third parties) consume the same registry through the
//!   bridge's access routes. No integration implements its own weaker authorization rules.
//!
//! # Fail-closed discipline
//!
//! - A registry file that fails validation is *refused*, not repaired: the admin plane answers
//!   every write with an error and the bridge keeps its last-known-good bindings.
//! - Writes are atomic (temp file + rename in the same directory) and serialised behind an
//!   exclusive lock file, so a crash mid-write can never publish a half policy.
//! - Sessions are bound to a policy hash at issue time. A session issued under version N proves
//!   nothing about version N+1: re-verification needs fresh evidence.

pub use ghost_gate_core::policy::{
    hash_policy, now_unix, Application, GatePolicy, PolicyHasher, PolicyVersion,
    ReplacementRecord, CHALLENGE_TTL, DEFAULT_SESSION_TTL, MAX_SESSION_TTL, MIN_SESSION_TTL,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Idle lifetime of an administrator session. Short on purpose: an unattended dashboard must not
/// stay privileged, and privileged changes additionally require a fresh step-up.
pub const ADMIN_SESSION_TTL: Duration = Duration::from_secs(30 * 60);
/// How long a step-up (fresh re-authentication) authorises privileged changes.
pub const STEPUP_WINDOW: Duration = Duration::from_secs(5 * 60);
/// How long a pending WebAuthn/wallet authentication challenge stays answerable.
pub const AUTH_CHALLENGE_TTL: Duration = Duration::from_secs(120);
/// Audit entries kept in the live registry file. The full history lives in `audit.ndjson`.
pub const AUDIT_TAIL: usize = 5_000;

/// A registered administrator credential.
///
/// Two kinds, both verified server-side:
/// - `Passkey`: a WebAuthn credential. ES256 public key, stored as the raw SEC1 point. The
///   private key never exists server-side and never leaves the authenticator.
/// - `WalletKey`: a Ristretto public key, verified with the same Schnorr machinery the audited
///   credential flow uses — a properly verified wallet challenge, not a frontend promise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminCredential {
    /// The credential id (WebAuthn) or the hex public key (wallet). This is the actor identity.
    pub credential_id: String,
    pub kind: CredentialKind,
    /// Human label the administrator gave it.
    pub label: String,
    pub registered_unix: u64,
    /// ES256 public key, SEC1 uncompressed (0x04 || X || Y), for passkeys.
    #[serde(default)]
    pub es256_public_sec1: Option<Vec<u8>>,
    /// Ristretto public key hex, for wallet-challenge administrators.
    #[serde(default)]
    pub ristretto_public_hex: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialKind {
    Passkey,
    WalletKey,
}

/// A live administrator session. The cookie carries only the opaque token; everything else stays
/// server-side. No administrator secret ever reaches JavaScript or localStorage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminSession {
    pub token: String,
    pub credential_id: String,
    pub created_unix: u64,
    pub expires_unix: u64,
    /// Per-session CSRF token. Delivered in the authenticated bootstrap body, required back as a
    /// header on every mutation. Not a cookie, so it cannot be replayed by a cross-site form.
    pub csrf: String,
    /// Until this unix time, privileged (policy-changing) mutations are authorised. Set by a
    /// successful step-up; every privileged mutation re-checks it.
    pub stepup_until_unix: u64,
    pub last_seen_unix: u64,
}

/// A verified-access session: the thing a *successful proof* buys.
///
/// Deliberately separate from a challenge. A challenge is short and single-use; a session is
/// longer but still bound to the policy version it was proved under, revocable, and never
/// renewable by anything but a fresh proof — a prior proof does not establish continuous token
/// ownership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedSession {
    pub token: String,
    pub application_id: String,
    /// The gate the proof actually satisfied.
    pub proven_gate: String,
    /// The policy hash the proof was made under. Access is refused if the published policy for the
    /// gate has moved on: new policy, new evidence required.
    pub policy_hash: String,
    /// The full set of gates this session opens, resolved SERVER-SIDE from the policy at issue
    /// time (tier inheritance lives here, never in a browser).
    pub granted: Vec<String>,
    pub issued_unix: u64,
    pub expires_unix: u64,
    pub revoked: bool,
    /// Sessions issued by test-lane gates can never authorise production gates.
    pub test_lane: bool,
}

/// Why a session was revoked — the audit trail wants the reason, not just the fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    pub token_prefix: String,
    pub reason: String,
    pub by: String,
    pub unix: u64,
}

/// One privileged event. Actor, timestamp, old and new policy versions, outcome — the whole
/// requirement, nothing less.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub unix: u64,
    pub actor: String,
    pub action: String,
    pub application_id: Option<String>,
    pub gate_id: Option<String>,
    /// Version identifiers before/after, when the action touched policies.
    pub old_version: Option<u64>,
    pub new_version: Option<u64>,
    pub outcome: AuditOutcome,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditOutcome {
    Accepted,
    Refused,
}

/// The whole registry, as persisted. Every load runs `validate_all`, so a hand-edited or corrupted
/// file is refused wholesale rather than half-trusted.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Registry {
    #[serde(default)]
    pub applications: Vec<Application>,
    #[serde(default)]
    pub credentials: Vec<AdminCredential>,
    /// Frozen policy versions, append-only. The current version of a gate is the highest-numbered
    /// version for that (application, gate).
    #[serde(default)]
    pub versions: Vec<PolicyVersion>,
    #[serde(default)]
    pub replacements: Vec<ReplacementRecord>,
    #[serde(default)]
    pub revocations: Vec<Revocation>,
    /// The most recent audit entries. The complete log is `audit.ndjson`.
    #[serde(default)]
    pub audit_tail: Vec<AuditEntry>,
    #[serde(default)]
    pub admin_sessions: Vec<AdminSession>,
    /// Verified sessions. Written by the bridge on issue/expire, read by the admin plane.
    #[serde(default)]
    pub sessions: Vec<VerifiedSession>,
    /// Incremented on every accepted mutation, for optimistic concurrency.
    #[serde(default)]
    pub store_revision: u64,
}

impl Registry {
    /// The live version of a gate: the highest version recorded for it. Published means present
    /// here; editing an application does not publish anything.
    pub fn current_version(&self, application_id: &str, gate_id: &str) -> Option<&PolicyVersion> {
        self.versions
            .iter()
            .filter(|v| v.application_id == application_id && v.gate_id == gate_id)
            .max_by_key(|v| v.version)
    }

    pub fn application(&self, application_id: &str) -> Option<&Application> {
        self.applications.iter().find(|a| a.application_id == application_id)
    }

    /// The session for a token, if present and unrevoked. Expiry is checked by the caller (which
    /// owns the clock policy) but also here, belt and braces.
    pub fn session(&self, token: &str, now: u64) -> Option<&VerifiedSession> {
        self.sessions
            .iter()
            .find(|s| s.token == token && !s.revoked && s.expires_unix > now)
    }

    /// Structural validation of the whole registry. Refuses rather than repairs.
    pub fn validate_all(&self) -> Result<(), String> {
        let mut ids = std::collections::BTreeSet::new();
        for a in &self.applications {
            if !ids.insert(a.application_id.clone()) {
                return Err(format!("duplicate application {}", a.application_id));
            }
            a.validate().map_err(|e| format!("application {}: {e}", a.application_id))?;
        }
        let mut cred_ids = std::collections::BTreeSet::new();
        for c in &self.credentials {
            if !cred_ids.insert(c.credential_id.clone()) {
                return Err("duplicate admin credential".into());
            }
            if c.kind == CredentialKind::Passkey && c.es256_public_sec1.is_none() {
                return Err(format!("passkey {} has no public key", c.credential_id));
            }
            if c.kind == CredentialKind::WalletKey && c.ristretto_public_hex.is_none() {
                return Err(format!("wallet credential {} has no public key", c.credential_id));
            }
        }
        // Every owner must be a registered credential: applications cannot be owned by a ghost.
        for a in &self.applications {
            if !cred_ids.contains(&a.owner_credential) {
                return Err(format!(
                    "application {} is owned by unregistered credential {}",
                    a.application_id, a.owner_credential
                ));
            }
        }
        // Versions must be a clean, increasing per-gate history with matching hashes.
        let hasher = Blake3Hasher;
        let mut seen: BTreeMap<(String, String), u64> = BTreeMap::new();
        for v in &self.versions {
            let key = (v.application_id.clone(), v.gate_id.clone());
            let last = seen.get(&key).copied().unwrap_or(0);
            if v.version != last + 1 {
                return Err(format!(
                    "policy version history for {}/{} is not contiguous at v{}",
                    v.application_id, v.gate_id, v.version
                ));
            }
            let app = self
                .application(&v.application_id)
                .ok_or_else(|| format!("version names unknown application {}", v.application_id))?;
            // The hash must match the frozen content: a tampered version file is refused.
            let expect = hash_policy(&hasher, app, &v.policy, v.version);
            if expect != v.policy_hash {
                return Err(format!(
                    "policy hash mismatch for {}/{} v{}: the stored policy does not match its digest",
                    v.application_id, v.gate_id, v.version
                ));
            }
            if v.policy.gate_id != v.gate_id || v.application_id != v.application_id {
                return Err("policy version identity mismatch".into());
            }
            // A version belongs to the ledger the application is bound to. If the application was
            // re-pointed at another cohort or genesis, its frozen versions no longer describe this
            // deployment and the registry refuses to load rather than serving a stale gate.
            if v.network != app.network || v.genesis_hash != app.genesis_hash {
                return Err(format!(
                    "policy version {}/{} v{} was frozen for network 0x{:02x}/{} but the application now declares 0x{:02x}/{}",
                    v.application_id, v.gate_id, v.version, v.network, v.genesis_hash, app.network, app.genesis_hash
                ));
            }
            seen.insert(key, v.version);
        }
        Ok(())
    }

    /// Append to the audit log: the tail lives in the registry, the full history in ndjson.
    pub fn audit(&mut self, entry: AuditEntry) {
        self.audit_tail.push(entry);
        if self.audit_tail.len() > AUDIT_TAIL {
            let excess = self.audit_tail.len() - AUDIT_TAIL;
            self.audit_tail.drain(0..excess);
        }
    }
}

/// Opaque 32-byte token, hex. Used for admin sessions and their CSRF tokens.
pub fn new_token() -> String {
    let mut b = [0u8; 32];
    rand::fill(&mut b);
    hex::encode(b)
}

/// The live admin session for a cookie token, or None. Expired sessions are dead here.
pub fn admin_session_for(reg: &Registry, token: &str, now: u64) -> Option<AdminSession> {
    reg.admin_sessions
        .iter()
        .find(|s| s.token == token && s.expires_unix > now)
        .cloned()
}

/// Drop expired admin sessions. Called under the store lock, so it never races a login.
pub fn expire_admin_sessions(reg: &mut Registry, now: u64) {
    reg.admin_sessions.retain(|s| s.expires_unix > now);
}

/// blake3 hasher backed by tari_core, which is on the bridge/admin side of the dependency line.
pub struct Blake3Hasher;

impl PolicyHasher for Blake3Hasher {
    fn hex_digest(&self, bytes: &[u8]) -> String {
        blake3::hash(bytes).to_hex().to_string()
    }
}

/// Where the registry lives, plus the derived artefacts other processes consume.
#[derive(Debug, Clone)]
pub struct StorePaths {
    pub dir: PathBuf,
}

impl StorePaths {
    pub fn new<P: AsRef<Path>>(dir: P) -> Self {
        Self { dir: dir.as_ref().to_path_buf() }
    }
    pub fn registry(&self) -> PathBuf { self.dir.join("registry.json") }
    pub fn bindings(&self) -> PathBuf { self.dir.join("bindings.json") }
    pub fn sessions(&self) -> PathBuf { self.dir.join("sessions.json") }
    pub fn audit(&self) -> PathBuf { self.dir.join("audit.ndjson") }
    pub fn lock(&self) -> PathBuf { self.dir.join("store.lock") }
    pub fn bootstrap(&self) -> PathBuf { self.dir.join("bootstrap.token") }
}

/// An exclusive, patient file lock around read-modify-write cycles. Both processes take it, so a
/// rewrite from either side can never interleave.
pub struct StoreLock {
    file: Option<fs::File>,
    path: Option<PathBuf>,
}

impl StoreLock {
    pub fn acquire(paths: &StorePaths) -> Result<Self, String> {
        let _ = fs::create_dir_all(&paths.dir);
        let path = paths.lock();
        // Open the lock file; O_EXCL semantics via create_new, with a bounded retry.
        for attempt in 0..200 {
            match fs::OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(f) => return Ok(Self { file: Some(f), path: Some(path.clone()) }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Stale lock from a crashed process: older than 30s is treated as abandoned.
                    if let Ok(meta) = fs::metadata(&path) {
                        if let Ok(modified) = meta.modified() {
                            if std::time::SystemTime::now()
                                .duration_since(modified)
                                .map(|d| d > std::time::Duration::from_secs(30))
                                .unwrap_or(false)
                            {
                                let _ = fs::remove_file(&path);
                                continue;
                            }
                        }
                    }
                    std::thread::sleep(Duration::from_millis(25 + attempt % 5 * 10));
                }
                Err(e) => return Err(format!("cannot open the registry lock: {e}")),
            }
        }
        Err("the registry is locked by another process; refusing to write".into())
    }

    /// Marker so the lock file carries the holder's intent in the file listing.
    pub fn annotate(&mut self, note: &str) {
        if let Some(f) = self.file.as_mut() {
            let _ = f.write_all(note.as_bytes());
            let _ = f.flush();
        }
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        drop(self.file.take());
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(&path);
        }
    }
}

/// Load the registry from disk, validating it. `create` controls whether a missing file is an
/// error (admin plane: no — it starts empty and bootstraps; bridge: also no, it just has nothing
/// to bind yet).
pub fn load_registry(paths: &StorePaths) -> Result<Registry, String> {
    let path = paths.registry();
    if !path.exists() {
        return Ok(Registry::default());
    }
    let bytes = fs::read(&path).map_err(|e| format!("cannot read the registry: {e}"))?;
    let reg: Registry =
        serde_json::from_slice(&bytes).map_err(|e| format!("the registry file is not valid JSON: {e}"))?;
    reg.validate_all().map_err(|e| format!("the registry file failed validation: {e}"))?;
    Ok(reg)
}

/// Atomically persist the registry: temp file in the same directory, fsync, rename. A crash can
/// leave the temp file behind but never a torn registry.
pub fn save_registry(paths: &StorePaths, reg: &Registry) -> Result<(), String> {
    let _ = fs::create_dir_all(&paths.dir);
    let path = paths.registry();
    let tmp = paths.dir.join(format!("registry.json.tmp{}", std::process::id()));
    let json = serde_json::to_vec_pretty(reg).map_err(|e| format!("cannot serialise the registry: {e}"))?;
    {
        let mut f = fs::File::create(&tmp).map_err(|e| format!("cannot write the registry: {e}"))?;
        f.write_all(&json).and_then(|_| f.sync_all())
            .map_err(|e| format!("cannot write the registry: {e}"))?;
    }
    fs::rename(&tmp, &path).map_err(|e| format!("cannot install the registry: {e}"))?;
    Ok(())
}

/// Append one audit line to the permanent ndjson log. Best-effort on I/O errors is NOT good
/// enough for an audit log: a failure to record a privileged change is returned as an error so
/// the caller can refuse the change rather than perform it unlogged.
pub fn append_audit(paths: &StorePaths, entry: &AuditEntry) -> Result<(), String> {
    let _ = fs::create_dir_all(&paths.dir);
    let line = format!("{}\n", serde_json::to_string(entry).map_err(|e| e.to_string())?);
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(paths.audit())
        .map_err(|e| format!("cannot open the audit log: {e}"))?;
    f.write_all(line.as_bytes()).and_then(|_| f.flush())
        .map_err(|e| format!("cannot write the audit log: {e}"))
}

/// The derived bindings snapshot the bridge consumes. This is the ONLY channel policy reaches the
/// bridge through, and it contains nothing the bridge does not need.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Bindings {
    pub generated_unix: u64,
    pub gates: Vec<GateBindingSnapshot>,
    #[serde(default)]
    pub revoked_session_prefixes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateBindingSnapshot {
    pub application_id: String,
    pub gate_id: String,
    pub name: String,
    /// The deployed on-chain gate component. Enabled gates require one.
    pub component_address: String,
    pub resource_address: String,
    pub symbol: String,
    pub divisibility: u8,
    pub threshold_raw: u128,
    pub proof_mode: String,
    pub challenge_domain: String,
    pub session_ttl_secs: u64,
    pub policy_version: u64,
    pub policy_hash: String,
    pub grants: Vec<String>,
    pub test_lane: bool,
    /// The cohort this gate is served on, and the ledger's genesis identity. Carried all the way
    /// into the bridge binding so "this gate" can never mean a different chain's gate with a
    /// colliding address.
    pub network: u8,
    pub genesis_hash: String,
    /// Which surfaces this gate may authorize (`website`, `telegram`, `both`). The Telegram bot
    /// refuses a website-only gate; the Lab shows the scope rather than implying it.
    pub use_mode: String,
}

/// Derive the snapshot from a validated registry: only enabled, activatable gates with a deployed
/// component appear. Test lanes appear too — the bridge tags their sessions — but a test-lane
/// session can never authorise a production gate (checked at access time).
pub fn derive_bindings(reg: &Registry) -> Bindings {
    let mut gates = Vec::new();
    for app in &reg.applications {
        for g in &app.gates {
            if !g.enabled || !g.proof_mode.is_activatable() {
                continue;
            }
            let Some(component) = g.component_address.as_ref() else { continue };
            // Only a PUBLISHED gate binds. A draft lives in the dashboard until an administrator
            // publishes it: the publish step is where the version is frozen, the reason is recorded
            // and the audit entry is written, so a draft must never reach the bridge behind the
            // operator's back with a self-computed hash.
            let version = reg.current_version(&app.application_id, &g.gate_id);
            let Some(version) = version else { continue };
            gates.push(GateBindingSnapshot {
                application_id: app.application_id.clone(),
                gate_id: g.gate_id.clone(),
                name: g.name.clone(),
                component_address: component.clone(),
                resource_address: g.resource_address.clone(),
                symbol: g.symbol.clone(),
                divisibility: g.divisibility,
                threshold_raw: g.threshold_raw,
                proof_mode: g.proof_mode.to_string(),
                challenge_domain: g.challenge_domain.clone(),
                session_ttl_secs: g.effective_ttl(app.default_session_ttl).as_secs(),
                policy_version: version.version,
                policy_hash: version.policy_hash.clone(),
                grants: app.granted_by(&g.gate_id),
                test_lane: g.test_lane,
                network: app.network,
                genesis_hash: app.genesis_hash.clone(),
                use_mode: g.use_mode.as_str().to_string(),
            });
        }
    }
    Bindings {
        generated_unix: now_unix(),
        gates,
        revoked_session_prefixes: reg.revocations.iter().map(|r| r.token_prefix.clone()).collect(),
    }
}

/// Persist the derived snapshot. Called by the admin plane after every accepted policy change.
pub fn save_bindings(paths: &StorePaths, bindings: &Bindings) -> Result<(), String> {
    let _ = fs::create_dir_all(&paths.dir);
    let tmp = paths.dir.join(format!("bindings.json.tmp{}", std::process::id()));
    let json = serde_json::to_vec_pretty(bindings).map_err(|e| e.to_string())?;
    fs::File::create(&tmp)
        .and_then(|mut f| f.write_all(&json).and_then(|_| f.sync_all()))
        .map_err(|e| format!("cannot write bindings: {e}"))?;
    fs::rename(&tmp, paths.bindings()).map_err(|e| format!("cannot install bindings: {e}"))
}

/// Load the bindings snapshot for the bridge. Missing file = nothing to bind.
pub fn load_bindings(paths: &StorePaths) -> Result<Option<Bindings>, String> {
    let path = paths.bindings();
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path).map_err(|e| format!("cannot read bindings: {e}"))?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| format!("bindings file is corrupt: {e}"))
}

/// Session persistence: the bridge issues and updates sessions; the admin plane reads them and
/// writes revocations. One file, one lock, atomic rewrites.
pub fn load_sessions(paths: &StorePaths) -> Result<Vec<VerifiedSession>, String> {
    let path = paths.sessions();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = fs::read(&path).map_err(|e| format!("cannot read sessions: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("sessions file is corrupt: {e}"))
}

pub fn save_sessions(paths: &StorePaths, sessions: &[VerifiedSession]) -> Result<(), String> {
    let _ = fs::create_dir_all(&paths.dir);
    let tmp = paths.dir.join(format!("sessions.json.tmp{}", std::process::id()));
    let json = serde_json::to_vec_pretty(sessions).map_err(|e| e.to_string())?;
    fs::File::create(&tmp)
        .and_then(|mut f| f.write_all(&json).and_then(|_| f.sync_all()))
        .map_err(|e| format!("cannot write sessions: {e}"))?;
    fs::rename(&tmp, paths.sessions()).map_err(|e| format!("cannot install sessions: {e}"))
}

/// Issue a verified session for a proven gate, resolving tiers server-side from the CURRENT
/// policy. The caller has already verified the proof and knows the gate + policy hash it was made
/// under.
///
/// Returns an error rather than a session when the application or gate is unknown, the gate is
/// disabled, or the TTL falls outside the enforced bounds — the honest failure, never a best-effort
/// token.
pub fn issue_session(
    reg: &Registry,
    application_id: &str,
    gate_id: &str,
    policy_hash: String,
    fresh_entropy: &mut [u8; 32],
) -> Result<VerifiedSession, String> {
    let app = reg
        .application(application_id)
        .ok_or_else(|| format!("unknown application {application_id}"))?;
    let gate = app
        .gate(gate_id)
        .ok_or_else(|| format!("unknown gate {gate_id} in {application_id}"))?;
    if !gate.enabled {
        return Err(format!("gate {gate_id} is not enabled"));
    }
    if !gate.proof_mode.is_activatable() {
        return Err(format!("gate {gate_id} uses a proof mode that cannot authorise sessions"));
    }
    let ttl = gate.effective_ttl(app.default_session_ttl);
    if ttl < MIN_SESSION_TTL || ttl > MAX_SESSION_TTL {
        return Err(format!(
            "session duration {}s is outside the enforced 1h..{}d bounds",
            ttl.as_secs(),
            MAX_SESSION_TTL.as_secs() / 86_400
        ));
    }
    let granted = app.granted_by(gate_id);
    let issued = now_unix();
    rand::fill(fresh_entropy);
    Ok(VerifiedSession {
        token: hex::encode(fresh_entropy),
        application_id: application_id.to_string(),
        proven_gate: gate_id.to_string(),
        policy_hash,
        granted,
        issued_unix: issued,
        expires_unix: issued + ttl.as_secs(),
        revoked: false,
        test_lane: gate.test_lane,
    })
}

/// The access decision for one request, computed entirely server-side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessDecision {
    pub authorized: bool,
    pub reason: String,
    pub granted: Vec<String>,
    pub expires_unix: u64,
    pub policy_version: u64,
}

/// Check a session against a gate: expiry, revocation, test-lane isolation, policy-version match
/// and tier resolution. This is the function integrations call; none of them re-implement it.
pub fn check_access(
    reg: &Registry,
    sessions: &[VerifiedSession],
    token: &str,
    application_id: &str,
    gate_id: &str,
    now: u64,
) -> AccessDecision {
    let Some(session) = sessions.iter().find(|s| s.token == token) else {
        return AccessDecision { authorized: false, reason: "unknown session".into(), granted: vec![], expires_unix: 0, policy_version: 0 };
    };
    if session.revoked {
        return AccessDecision { authorized: false, reason: "session revoked".into(), granted: vec![], expires_unix: session.expires_unix, policy_version: 0 };
    }
    if session.expires_unix <= now {
        return AccessDecision { authorized: false, reason: "session expired".into(), granted: vec![], expires_unix: session.expires_unix, policy_version: 0 };
    }
    if session.application_id != application_id {
        return AccessDecision { authorized: false, reason: "session belongs to a different application".into(), granted: vec![], expires_unix: session.expires_unix, policy_version: 0 };
    }
    let Some(app) = reg.application(application_id) else {
        return AccessDecision { authorized: false, reason: "unknown application".into(), granted: vec![], expires_unix: session.expires_unix, policy_version: 0 };
    };
    let Some(gate) = app.gate(gate_id) else {
        return AccessDecision { authorized: false, reason: "unknown gate".into(), granted: vec![], expires_unix: session.expires_unix, policy_version: 0 };
    };
    // A test-lane session can never authorise a production gate, whatever it proves.
    if session.test_lane && !gate.test_lane {
        return AccessDecision { authorized: false, reason: "a test session cannot authorise a production gate".into(), granted: vec![], expires_unix: session.expires_unix, policy_version: 0 };
    }
    // The session is only as valid as the policy it proved under. If the published version moved
    // on, fresh evidence is required: re-verification, not inheritance.
    let version = match reg.current_version(application_id, &session.proven_gate) {
        Some(v) => v,
        None => return AccessDecision { authorized: false, reason: "no published policy for the proven gate".into(), granted: vec![], expires_unix: session.expires_unix, policy_version: 0 },
    };
    if version.policy_hash != session.policy_hash {
        return AccessDecision {
            authorized: false,
            reason: format!(
                "the policy changed (v{} -> v{}): fresh proof required",
                version.version.saturating_sub(1),
                version.version
            ),
            granted: vec![],
            expires_unix: session.expires_unix,
            policy_version: version.version,
        };
    }
    // Tier resolution, server-side, from the CURRENT policy — never from the client's claim.
    if !session.granted.contains(&gate_id.to_string()) {
        return AccessDecision { authorized: false, reason: "this session does not grant that gate".into(), granted: session.granted.clone(), expires_unix: session.expires_unix, policy_version: version.version };
    }
    AccessDecision {
        authorized: true,
        reason: "ok".into(),
        granted: app.granted_by(gate_id),
        expires_unix: session.expires_unix,
        policy_version: version.version,
    }
}

/// Prune expired sessions from the list (called on save by both sides).
pub fn prune_sessions(sessions: &mut Vec<VerifiedSession>) {
    let now = now_unix();
    sessions.retain(|s| s.expires_unix > now || s.revoked);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_gate_core::policy::{GateTopology, ProofMode};

    /// A stand-in ledger identity for the tests; production uses the deployment's real genesis hash.
    const GENESIS: &str = "00f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

    fn hasher() -> Blake3Hasher {
        Blake3Hasher
    }

    fn gate(id: &str, threshold: u128, test: bool) -> GatePolicy {
        GatePolicy {
            gate_id: id.into(),
            name: id.into(),
            resource_address: "resource_abc".into(),
            symbol: "tTARI".into(),
            divisibility: 6,
            threshold_raw: threshold,
            proof_mode: ProofMode::Consensus,
            challenge_domain: "app.localhost".into(),
            session_ttl_override: None,
            grants: vec![],
            enabled: true,
            test_lane: test,
            use_mode: Default::default(),
            component_address: Some("component_abc".into()),
        }
    }

    fn app(id: &str, owner: &str) -> Application {
        Application {
            application_id: id.into(),
            display_name: id.into(),
            owner_credential: owner.into(),
            topology: GateTopology::Independent,
            default_session_ttl: 86_400,
            max_gates: 10,
            gates: vec![],
            revision: 1,
            production: true,
            network: ghost_gate_core::network::LOCALNET,
            genesis_hash: "00f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0".into(),
        }
    }

    fn cred(id: &str) -> AdminCredential {
        AdminCredential {
            credential_id: id.into(),
            kind: CredentialKind::WalletKey,
            label: id.into(),
            registered_unix: 1,
            es256_public_sec1: None,
            ristretto_public_hex: Some("abc".into()),
        }
    }

    fn registry_with_tiers() -> Registry {
        let mut reg = Registry::default();
        let mut a = app("meme", "admin-1");
        a.topology = GateTopology::Hierarchical;
        let mut gold = gate("gold", 3_000_000, false);
        gold.grants = vec!["silver".into()];
        let mut silver = gate("silver", 2_000_000, false);
        silver.grants = vec!["bronze".into()];
        a.gates = vec![gold, silver, gate("bronze", 1_000_000, false)];
        a.validate().unwrap();
        let app_id = a.application_id.clone();
        let app_rev = a.revision;
        let gates = a.gates.clone();
        reg.applications.push(a);
        reg.credentials.push(cred("admin-1"));
        // Publish versions so sessions can bind to hashes.
        for g in &gates {
            reg.versions.push(PolicyVersion {
                application_id: app_id.clone(),
                gate_id: g.gate_id.clone(),
                version: 1,
                policy_hash: hash_policy(&hasher(), reg.applications.first().unwrap(), g, 1),
                network: ghost_gate_core::network::LOCALNET,
                genesis_hash: GENESIS.to_string(),
                policy: g.clone(),
                app_revision: app_rev,
                created_unix: 1,
            });
        }
        reg
    }

    #[test]
    fn a_session_resolves_tiers_server_side_and_refuses_everything_else() {
        let reg = registry_with_tiers();
        let app = reg.application("meme").unwrap();
        let gold = app.gate("gold").unwrap();
        let silver = app.gate("silver").unwrap();
        let gold_hash = hash_policy(&hasher(), app, gold, 1);
        let silver_hash = hash_policy(&hasher(), app, silver, 1);
        let mut entropy = [0u8; 32];
        let session = issue_session(&reg, "meme", "gold", gold_hash, &mut entropy).unwrap();
        assert_eq!(session.granted, vec!["gold", "silver", "bronze"]);

        let now = now_unix();
        assert!(check_access(&reg, &[session.clone()], &session.token, "meme", "gold", now).authorized);
        assert!(check_access(&reg, &[session.clone()], &session.token, "meme", "bronze", now).authorized);
        // A lower-tier session does NOT reach up.
        let s2 = issue_session(&reg, "meme", "silver", silver_hash, &mut entropy).unwrap();
        let d = check_access(&reg, &[s2.clone()], &s2.token, "meme", "gold", now);
        assert!(!d.authorized, "a lower tier must not unlock a higher gate");
        // Unknown session / expired / wrong application.
        assert!(!check_access(&reg, &[], "nope", "meme", "gold", now).authorized);
        let mut expired = session.clone();
        expired.expires_unix = now - 1;
        assert!(!check_access(&reg, &[expired], &session.token, "meme", "gold", now).authorized);
        assert!(!check_access(&reg, &[session.clone()], &session.token, "OTHER", "gold", now).authorized);
    }

    #[test]
    fn a_policy_change_kills_old_sessions_evidence_even_within_ttl() {
        let reg = registry_with_tiers();
        let app = reg.application("meme").unwrap();
        let gold = app.gate("gold").unwrap();
        let mut entropy = [0u8; 32];
        let session = issue_session(&reg, "meme", "gold", hash_policy(&hasher(), app, gold, 1), &mut entropy).unwrap();

        // Publish v2 with a raised threshold: same session, new hash required.
        let token = session.token.clone();
        let mut reg2 = reg.clone();
        let v1 = reg2.current_version("meme", "gold").unwrap().clone();
        let mut gold2 = v1.policy.clone();
        gold2.threshold_raw += 1;
        // Bump the application revision first so the borrows stay separate.
        let app2 = {
            let a = reg2.applications.first_mut().unwrap();
            a.revision += 1;
            a.clone()
        };
        let v2 = v1.next(&hasher(), &app2, &gold2).unwrap();
        reg2.versions.push(v2);

        let d = check_access(&reg2, &[session], &token, "meme", "gold", now_unix());
        assert!(!d.authorized, "a session from the old policy must not survive a policy change");
        assert!(d.reason.contains("fresh proof"), "the refusal must say why: {}", d.reason);
    }

    #[test]
    fn test_lane_sessions_never_authorise_production_gates() {
        let mut reg = registry_with_tiers();
        let mut a = app("prod", "admin-1");
        a.gates.push(gate("prod-gate", 1_000_000, false));
        let mut t = app("test", "admin-1");
        t.production = false;
        t.gates.push(gate("test-gate", 10, true));
        t.validate().unwrap();
        reg.applications.push(a);
        reg.applications.push(t);
        for (aid, gid) in [("prod", "prod-gate"), ("test", "test-gate")] {
            let app = reg.application(aid).unwrap();
            let g = app.gate(gid).unwrap();
            reg.versions.push(PolicyVersion {
                application_id: aid.into(),
                gate_id: gid.into(),
                version: 1,
                policy_hash: hash_policy(&hasher(), app, g, 1),
                network: ghost_gate_core::network::LOCALNET,
                genesis_hash: GENESIS.to_string(),
                policy: g.clone(),
                app_revision: 1,
                created_unix: 1,
            });
        }
        let tapp = reg.application("test").unwrap();
        let tg = tapp.gate("test-gate").unwrap();
        let test_hash = hash_policy(&hasher(), tapp, tg, 1);
        let mut e = [0u8; 32];
        let ts = issue_session(&reg, "test", "test-gate", test_hash, &mut e).unwrap();
        assert!(ts.test_lane);
        let ts_token = ts.token.clone();
        let d = check_access(&reg, &[ts.clone()], &ts_token, "prod", "prod-gate", now_unix());
        assert!(!d.authorized, "a test session must not authorise a production gate");
        assert!(check_access(&reg, &[ts], &ts_token, "test", "test-gate", now_unix()).authorized);
    }

    #[test]
    fn the_store_round_trips_and_refuses_tampering() {
        let dir = std::env::temp_dir().join(format!("gg-registry-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let paths = StorePaths::new(&dir);
        let mut reg = registry_with_tiers();
        reg.store_revision = 1;
        save_registry(&paths, &reg).unwrap();
        let loaded = load_registry(&paths).unwrap();
        assert_eq!(loaded.applications.len(), 1);

        // Tamper with a frozen policy's threshold: the digest no longer matches, so the load must
        // refuse the whole file — a tampered policy is not quietly accepted.
        let mut tampered = loaded.clone();
        tampered.versions[0].policy.threshold_raw += 1;
        save_registry(&paths, &tampered).unwrap();
        assert!(load_registry(&paths).is_err(), "a tampered policy version must be refused");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn bindings_contain_only_activatable_enabled_gates_with_components() {
        let mut reg = registry_with_tiers();
        let app = reg.applications.first_mut().unwrap();
        let mut draft = gate("draft", 5, false);
        draft.enabled = false;
        draft.proof_mode = ProofMode::Xtm;
        app.gates.push(draft);
        // An ENABLED gate with no deployed component is refused outright, not quietly excluded.
        let mut no_component = gate("ghost", 5, false);
        no_component.component_address = None;
        app.gates.push(no_component);
        assert!(app.validate().is_err(), "an enabled gate without a component must be refused");
        app.gates.pop();
        app.validate().unwrap();
        let b = derive_bindings(&reg);
        assert_eq!(b.gates.len(), 3, "only enabled, activatable, deployed gates bind");
        assert!(b.gates.iter().all(|g| g.policy_version == 1));
    }

    #[test]
    fn session_bounds_match_the_policy_bounds() {
        assert_eq!(CHALLENGE_TTL, std::time::Duration::from_secs(180));
        assert!(MIN_SESSION_TTL <= DEFAULT_SESSION_TTL);
    }
}

/// The access plane the bridge uses: it issues verified sessions on accepted proofs, answers
/// access checks entirely server-side, and re-reads the registry's derived bindings when they
/// change. Sessions persist to disk so a bridge restart does not silently end anyone's session
/// early — and so the admin plane can see and revoke them.
pub struct AccessPlane {
    pub paths: StorePaths,
    /// Cached registry with the mtime it was loaded at; re-read when the file changes.
    cached_registry: Option<(Registry, std::time::SystemTime)>,
    /// Cached sessions with the mtime they were loaded at.
    cached_sessions: Option<(Vec<VerifiedSession>, std::time::SystemTime)>,
}

/// What the bridge needs to know about one bound gate, derived from the snapshot. Tier grants
/// come from the policy, resolved server-side — never from anything a browser says.
#[derive(Debug, Clone)]
pub struct GateAccessInfo {
    pub application_id: String,
    pub policy_hash: String,
    pub policy_version: u64,
    pub session_ttl_secs: u64,
    pub test_lane: bool,
    pub grants: Vec<String>,
}

impl AccessPlane {
    pub fn new(paths: StorePaths) -> Self {
        Self { paths, cached_registry: None, cached_sessions: None }
    }

    /// Fresh registry, re-reading the file when it changed. A corrupt file is refused: the caller
    /// keeps its last-known-good state and logs — never half-trusts.
    pub fn registry(&mut self) -> Result<Registry, String> {
        let path = self.paths.bindings(); // touch the pair, but the registry is the source
        let _ = &path;
        let reg_path = self.paths.registry();
        let mtime = fs::metadata(&reg_path).and_then(|m| m.modified()).ok();
        if let Some((_, cached_at)) = &self.cached_registry {
            if mtime == Some(*cached_at) {
                return Ok(self.cached_registry.as_ref().unwrap().0.clone());
            }
        }
        let reg = load_registry(&self.paths)?;
        if let Some(t) = mtime {
            self.cached_registry = Some((reg.clone(), t));
        }
        Ok(reg)
    }

    pub fn sessions(&mut self) -> Result<Vec<VerifiedSession>, String> {
        let path = self.paths.sessions();
        let mtime = fs::metadata(&path).and_then(|m| m.modified()).ok();
        if let (Some((list, cached_at)), Some(t)) = (&self.cached_sessions, &mtime) {
            if t == cached_at {
                return Ok(list.clone());
            }
        }
        let list = load_sessions(&self.paths)?;
        if let Some(t) = mtime {
            self.cached_sessions = Some((list.clone(), t));
        }
        Ok(list)
    }

    /// Issue a session for an accepted proof and persist it. Returns the grant for the wire.
    pub fn issue(
        &mut self,
        application_id: &str,
        gate_id: &str,
        policy_hash: String,
    ) -> Result<AccessGrant, String> {
        let reg = self.registry()?;
        let _lock = StoreLock::acquire(&self.paths)?;
        // Reload under the lock: another process (or our own past self) may have written.
        let mut fresh = load_sessions(&self.paths)?;
        prune_sessions(&mut fresh);
        let mut entropy = [0u8; 32];
        let session = issue_session(&reg, application_id, gate_id, policy_hash, &mut entropy)?;
        let grant = AccessGrant {
            token: session.token.clone(),
            application_id: session.application_id.clone(),
            proven_gate: session.proven_gate.clone(),
            granted: session.granted.clone(),
            expires_unix: session.expires_unix,
            test_lane: session.test_lane,
        };
        fresh.push(session);
        save_sessions(&self.paths, &fresh)?;
        self.cached_sessions = Some((fresh, std::time::SystemTime::now()));
        Ok(grant)
    }

    /// The policy hash currently in force for a gate, if it is published. Used by the bridge to bind
    /// each minted challenge to the policy it was minted under, so an outstanding challenge cannot be
    /// answered after that policy was replaced.
    pub fn current_policy_hash(&mut self, gate_id: &str) -> Option<String> {
        let reg = self.registry().ok()?;
        reg.versions
            .iter()
            .filter(|v| v.gate_id == gate_id)
            .max_by_key(|v| v.version)
            .map(|v| v.policy_hash.clone())
    }

    /// The server-side access decision for one (token, application, gate) request.
    pub fn check(
        &mut self,
        token: &str,
        application_id: &str,
        gate_id: &str,
    ) -> Result<AccessDecision, String> {
        let reg = self.registry()?;
        let sessions = self.sessions()?;
        Ok(check_access(&reg, &sessions, token, application_id, gate_id, now_unix()))
    }

    /// Apply revoked-token prefixes from the bindings snapshot: any live session whose token
    /// starts with a prefix is revoked and persisted.
    pub fn apply_revocations(&mut self, prefixes: &[String]) -> Result<usize, String> {
        if prefixes.is_empty() {
            return Ok(0);
        }
        let _lock = StoreLock::acquire(&self.paths)?;
        let mut sessions = load_sessions(&self.paths)?;
        let mut n = 0;
        for s in sessions.iter_mut() {
            if !s.revoked && prefixes.iter().any(|p| s.token.starts_with(p.as_str())) {
                s.revoked = true;
                n += 1;
            }
            // Whole-application kill switch: `app:<id>:*`.
            for p in prefixes {
                if let Some(app_id) = p.strip_prefix("app:").and_then(|r| r.strip_suffix(":*")) {
                    if !s.revoked && s.application_id == app_id {
                        s.revoked = true;
                        n += 1;
                    }
                }
            }
        }
        save_sessions(&self.paths, &sessions)?;
        self.cached_sessions = None; // force a re-read next check
        Ok(n)
    }
}

/// The wire form of a newly granted session, returned inside an accepted proof status.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessGrant {
    pub token: String,
    pub application_id: String,
    pub proven_gate: String,
    pub granted: Vec<String>,
    pub expires_unix: u64,
    pub test_lane: bool,
}
