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
//! - Integrations (the Privacy Lab site, Telegram, third parties) consume the same registry through the
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
    achieved_tier, effective_generation, hash_policy, hash_policy_versioned, now_unix, required_tier, Application, Evidence,
    EvidenceKind, GatePolicy, PolicyHasher, PolicyVersion, ProofMode, ReplacementRecord, TrustPolicy,
    TrustTier, POLICY_HASH_V1, POLICY_HASH_V2, CHALLENGE_TTL, DEFAULT_SESSION_TTL, MAX_SESSION_TTL, MIN_SESSION_TTL,
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
    /// Stable server-side authorization identity from the replay coordinator. It makes recovery
    /// idempotent after a crash between recording an authorization and returning its session.
    #[serde(default)]
    pub authorization_id: Option<String>,
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
    /// The verification strength at the moment this session was issued. Defaults to
    /// `Development` so sessions written before this field existed are never silently upgraded —
    /// and `check_access` refuses `Development`, so a legacy session authorizes nothing.
    #[serde(default)]
    pub trust_tier: TrustTier,
    /// The class of evidence the tier was derived from, recorded for the dashboard and the audit.
    /// Legacy sessions load as `None`, which is consistent with their `Development` tier.
    #[serde(default)]
    pub evidence_kind: EvidenceKind,
    /// The Ootle chain generation this session was issued under. `check_access` refuses a session
    /// whose generation is not the application's current effective generation, so a legacy session
    /// (loads as `0`) authorizes nothing, and a session from a retired generation cannot be
    /// resurrected by restoring an older configuration after a reset migration.
    #[serde(default)]
    pub chain_generation: u64,
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
    /// Durable, monotonic per-application generation floor, loaded from `generations.ndjson` — NOT
    /// from this file. It is `#[serde(skip)]` so it is never written into `registry.json`: a
    /// restored registry snapshot carries no floor, and the floor is re-read from its own
    /// append-only ledger, which a config rollback cannot lower. See [`effective_generation`].
    #[serde(skip)]
    pub generation_floor: BTreeMap<String, u64>,
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

    /// The durable generation floor for an application: the highest generation ever activated for
    /// it. Absent means never migrated, so the floor is `0` and only a declared generation `>= 1`
    /// can authorize.
    pub fn generation_floor_of(&self, application_id: &str) -> u64 {
        self.generation_floor.get(application_id).copied().unwrap_or(0)
    }

    /// The generation this application may authorize under right now, or `None` when it may
    /// authorize nothing (unknown generation, or a declared generation below the durable floor —
    /// a rollback). This is the one place issuance and the access check agree on the live
    /// generation; see [`effective_generation`].
    pub fn effective_generation(&self, application_id: &str) -> Option<u64> {
        let app = self.application(application_id)?;
        effective_generation(app.chain_generation, self.generation_floor_of(application_id))
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
            // v2 carries the application fields that were frozen with the version.  This lets
            // an administrator save a new default/topology/production draft without rewriting
            // the old policy hash.  Legacy v1 has no such context: it remains valid only while
            // the current application still reproduces its historic canonical form, forcing an
            // explicit v2 re-publish before those global settings can change.
            let hash_app = match (&v.policy_context, v.policy_hash_version) {
                (Some(context), POLICY_HASH_V2) => {
                    if context.network != v.network || context.genesis_hash != v.genesis_hash {
                        return Err(format!(
                            "policy context mismatch for {}/{} v{}",
                            v.application_id, v.gate_id, v.version
                        ));
                    }
                    context.apply_to(app)
                }
                (None, POLICY_HASH_V1) => app.clone(),
                (None, POLICY_HASH_V2) => return Err(format!(
                    "policy {}/{} v{} uses v2 but has no frozen application context; explicitly re-publish it",
                    v.application_id, v.gate_id, v.version
                )),
                (Some(_), POLICY_HASH_V1) => return Err(format!(
                    "policy {}/{} v{} has an invalid v1 application context",
                    v.application_id, v.gate_id, v.version
                )),
                (_, other) => return Err(format!("unsupported policy hash version {other}")),
            };
            let expect = hash_policy_versioned(
                &hasher,
                &hash_app,
                &v.policy,
                v.version,
                v.policy_hash_version,
            )?;
            if expect != v.policy_hash {
                return Err(format!(
                    "policy hash mismatch for {}/{} v{}: the stored policy does not match its digest",
                    v.application_id, v.gate_id, v.version
                ));
            }
            // The policy must name the gate this version was filed under. (The application
            // identity is already established two lines up: the version was looked up through
            // `application(&v.application_id)`, and a policy carries no application id of its
            // own to compare. The old second operand compared the field with itself — a
            // tautology clippy rightly refuses — so the honest check is this one comparison.)
            if v.policy.gate_id != v.gate_id {
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
    /// The durable, append-only generation floor. It is deliberately a SEPARATE file from
    /// `registry.json`: restoring an older `registry.json` (or `sessions.json`) must not lower the
    /// floor, so the monotonic high-water mark cannot live inside the config snapshot it protects.
    pub fn generations(&self) -> PathBuf { self.dir.join("generations.ndjson") }
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
    let floor = load_generation_floor(paths)?;
    let path = paths.registry();
    if !path.exists() {
        return Ok(Registry { generation_floor: floor, ..Registry::default() });
    }
    let bytes = fs::read(&path).map_err(|e| format!("cannot read the registry: {e}"))?;
    let mut reg: Registry =
        serde_json::from_slice(&bytes).map_err(|e| format!("the registry file is not valid JSON: {e}"))?;
    reg.validate_all().map_err(|e| format!("the registry file failed validation: {e}"))?;
    // The floor comes from its own append-only ledger, never from `registry.json`. A restored or
    // hand-edited registry therefore inherits the real floor, so an older generation it still
    // declares is caught as a rollback by `effective_generation`.
    reg.generation_floor = floor;
    Ok(reg)
}

/// One activation of a new chain generation for an application. Appended, never rewritten, so the
/// floor can only rise. The actor and timestamp are kept for the audit of a reset migration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerationActivation {
    pub application_id: String,
    pub generation: u64,
    pub activated_unix: u64,
    pub actor: String,
}

/// Rebuild the per-application floor from the append-only ledger: the floor is the maximum
/// generation ever activated for each application. A missing ledger means nothing was migrated.
pub fn load_generation_floor(paths: &StorePaths) -> Result<BTreeMap<String, u64>, String> {
    let path = paths.generations();
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let text = fs::read_to_string(&path)
        .map_err(|e| format!("cannot read the generation ledger: {e}"))?;
    let mut floor: BTreeMap<String, u64> = BTreeMap::new();
    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let rec: GenerationActivation = serde_json::from_str(line).map_err(|e| {
            format!("the generation ledger is corrupt at line {}: {e}", lineno + 1)
        })?;
        let slot = floor.entry(rec.application_id).or_insert(0);
        *slot = (*slot).max(rec.generation);
    }
    Ok(floor)
}

/// Append one activation to the durable ledger and raise the in-memory floor. The append is
/// rejected unless it strictly raises the application's floor, so the floor is monotonic and a
/// generation can never be rolled back through this path. The ledger is fsync'd before the floor
/// is advanced, so a crash can lose nothing that a later authorization would rely on.
pub fn append_generation_activation(
    paths: &StorePaths,
    reg: &mut Registry,
    activation: &GenerationActivation,
) -> Result<(), String> {
    let current = reg.generation_floor_of(&activation.application_id);
    if activation.generation <= current {
        return Err(format!(
            "refusing a generation rollback for {}: {} does not exceed the durable floor {}",
            activation.application_id, activation.generation, current
        ));
    }
    let _ = fs::create_dir_all(&paths.dir);
    let line = serde_json::to_string(activation)
        .map_err(|e| format!("cannot serialise the generation activation: {e}"))?;
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(paths.generations())
        .map_err(|e| format!("cannot open the generation ledger: {e}"))?;
    f.write_all(line.as_bytes()).and_then(|_| f.write_all(b"\n")).and_then(|_| f.sync_all())
        .map_err(|e| format!("cannot append to the generation ledger: {e}"))?;
    reg.generation_floor.insert(activation.application_id.clone(), activation.generation);
    Ok(())
}

/// The sanctioned, explicit operation that moves an application to a new chain generation after a
/// reset. Ordinary edits never change the generation; only this does. It raises the durable floor
/// FIRST (so the old generation is retired even if the process dies mid-migration), then advances
/// the application and retires every session it held, so nothing from before the migration can
/// authorize under the new generation. Challenges and replay records are retired at the bridge by
/// the same generation gate on its next registry load. Historical records are never deleted.
///
/// The caller holds the store lock and persists the registry (and its sessions) afterward.
pub fn migrate_generation(
    paths: &StorePaths,
    reg: &mut Registry,
    application_id: &str,
    new_generation: u64,
    actor: &str,
) -> Result<(), String> {
    let current_declared = reg
        .application(application_id)
        .ok_or_else(|| format!("unknown application {application_id}"))?
        .chain_generation;
    let floor = reg.generation_floor_of(application_id);
    if new_generation == 0 {
        return Err("a chain generation must be >= 1; 0 means unknown and authorizes nothing".into());
    }
    // Monotonic: a migration may only move strictly forward, past both the declared generation and
    // the durable floor. This is the one place a generation rollback is rejected during normal
    // operation — an operator who wants an older generation back must re-migrate forward, which
    // records a new, higher generation rather than resurrecting a retired one.
    if new_generation <= floor || new_generation <= current_declared {
        return Err(format!(
            "refusing a generation migration for {application_id}: {new_generation} does not advance \
             past the current generation {current_declared} / durable floor {floor}"
        ));
    }
    // Raise the durable floor first (fsync'd inside): a crash after this point leaves the old
    // generation retired rather than silently re-authorizable.
    append_generation_activation(
        paths,
        reg,
        &GenerationActivation {
            application_id: application_id.to_string(),
            generation: new_generation,
            activated_unix: now_unix(),
            actor: actor.to_string(),
        },
    )?;
    let now = now_unix();
    let app = reg
        .applications
        .iter_mut()
        .find(|a| a.application_id == application_id)
        .expect("application presence was checked above");
    app.chain_generation = new_generation;
    app.revision = app.revision.saturating_add(1);
    // Retire every session the application held. The runtime generation gate already refuses them,
    // but marking them revoked makes the invalidation explicit in the store and the audit.
    let mut retired = 0usize;
    for s in reg.sessions.iter_mut().filter(|s| s.application_id == application_id && !s.revoked) {
        s.revoked = true;
        retired += 1;
    }
    reg.audit(AuditEntry {
        unix: now,
        actor: actor.to_string(),
        action: "migrate-generation".into(),
        application_id: Some(application_id.to_string()),
        gate_id: None,
        old_version: Some(current_declared),
        new_version: Some(new_generation),
        outcome: AuditOutcome::Accepted,
        detail: format!(
            "chain generation {current_declared} -> {new_generation}; {retired} session(s) retired"
        ),
    });
    Ok(())
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

/// The scope a gate had before the field existed: the website. An upgrade must never grant a
/// gate a new surface by omission.
fn default_use_mode() -> String {
    "website".to_string()
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
    /// The Ootle chain generation this gate is served under, carried into the bridge binding so a
    /// republish after a reset migration advances it. `0` (a binding written before this field, or
    /// an un-migrated application) means the bridge serves no live generation and authorizes
    /// nothing — the fail-closed default.
    #[serde(default)]
    pub chain_generation: u64,
    /// Which surfaces this gate may authorize (`website`, `telegram`, `both`). The Telegram bot
    /// refuses a website-only gate; the Lab shows the scope rather than implying it.
    ///
    /// Defaults to `website` so a bindings snapshot written before this field existed keeps its
    /// previous meaning: the bridge serves the website and gains no Telegram surface by upgrade.
    #[serde(default = "default_use_mode")]
    pub use_mode: String,
    /// The highest trust tier this gate's proof mode can reach. Defaults to `"development"`
    /// so snapshots written before this field existed are never silently upgraded.
    #[serde(default = "default_trust_tier")]
    pub max_trust_tier: String,
}

fn default_trust_tier() -> String {
    "development".to_string()
}

/// Proves that the mutable administrator workspace still describes exactly the complete published
/// policy.  This is intentionally stricter than `validate_all`: structural validity is not
/// publication.  New authorization is unavailable while there is a draft, rather than using a
/// mix of draft application fields and published gate versions.
pub fn require_published_policy_snapshot(reg: &Registry) -> Result<(), String> {
    for app in &reg.applications {
        for g in &app.gates {
            // Bindings are the live authorization plane.  They may only be regenerated when
            // every live gate exactly matches the immutable version that was explicitly
            // published.  This turns the mutable `applications` record into a draft-only
            // workspace: any un-published edit (including grants, scope, TTL, enablement,
            // defaults/topology through the version hash) blocks publication instead of leaking
            // into a bridge reload.
            let version = reg.current_version(&app.application_id, &g.gate_id).ok_or_else(|| {
                format!(
                    "application {}/{} has an unpublished draft; publish before refreshing live bindings",
                    app.application_id, g.gate_id
                )
            })?;
            if version.policy != *g {
                return Err(format!(
                    "application {}/{} differs from its published policy; refusing to refresh live bindings",
                    app.application_id, g.gate_id
                ));
            }
            let hasher = Blake3Hasher;
            let expected = hash_policy_versioned(
                &hasher,
                app,
                &version.policy,
                version.version,
                version.policy_hash_version,
            )?;
            if expected != version.policy_hash {
                return Err(format!(
                    "application {}/{} no longer matches its published policy context; refusing to refresh live bindings",
                    app.application_id, g.gate_id
                ));
            }
        }
    }
    Ok(())
}

pub fn derive_bindings(reg: &Registry) -> Result<Bindings, String> {
    require_published_policy_snapshot(reg)?;
    let mut gates = Vec::new();
    for app in &reg.applications {
        for g in &app.gates {
            if !g.enabled || !g.proof_mode.is_activatable() {
                continue;
            }
            let version = reg.current_version(&app.application_id, &g.gate_id)
                .expect("published snapshot check established a version for every gate");
            // Consensus gates require a real component; credential gates are component-free.
            let component = match g.proof_mode {
                ProofMode::Consensus => {
                    let Some(c) = g.component_address.as_ref() else { continue };
                    c.clone()
                }
                ProofMode::Credential => String::new(),
                _ => continue,
            };
            // Only a PUBLISHED gate binds. A draft lives in the dashboard until an administrator
            // publishes it: the publish step is where the version is frozen, the reason is recorded
            // and the audit entry is written, so a draft must never reach the bridge behind the
            // operator's back with a self-computed hash.
            gates.push(GateBindingSnapshot {
                application_id: app.application_id.clone(),
                gate_id: g.gate_id.clone(),
                name: g.name.clone(),
                component_address: component,
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
                chain_generation: app.chain_generation,
                use_mode: g.use_mode.as_str().to_string(),
                max_trust_tier: g.proof_mode.max_trust_tier().as_str().to_string(),
            });
        }
    }
    Ok(Bindings {
        generated_unix: now_unix(),
        gates,
        revoked_session_prefixes: reg.revocations.iter().map(|r| r.token_prefix.clone()).collect(),
    })
}

/// Persist the derived snapshot.  Only an explicit policy publication (or a revocation-only
/// update preserving the existing gates) may call this; drafts are deliberately not live.
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
pub fn issue_session_with_evidence(
    reg: &Registry,
    application_id: &str,
    gate_id: &str,
    policy_hash: String,
    fresh_entropy: &mut [u8; 32],
    evidence: &Evidence,
    policy: &TrustPolicy,
) -> Result<VerifiedSession, String> {
    rand::fill(fresh_entropy);
    let token = hex::encode(fresh_entropy);
    issue_session_with_token(
        reg, application_id, gate_id, policy_hash, &format!("legacy-{token}"), &token, evidence, policy,
    )
}

/// Issue a session for a proof the caller has already verified, resolving the trust tier
/// SERVER-SIDE from the supplied `evidence` and the gate's own proof machinery.
///
/// `evidence` describes what was actually verified; it is produced at the verification site, never
/// taken from a browser, and its strongest variant ([`Evidence::ConsensusVerified`]) cannot even be
/// constructed outside an authenticated verification path. The achieved tier is
/// `achieved_tier(evidence.kind(), gate.proof_mode, policy)`, which is capped by the evidence
/// ceiling, the mode ceiling and the operator policy. A tier that does not meet the application's
/// `required_tier` — including every `Development` result — issues no session.
pub fn issue_session_with_token(
    reg: &Registry,
    application_id: &str,
    gate_id: &str,
    policy_hash: String,
    authorization_id: &str,
    token: &str,
    evidence: &Evidence,
    policy: &TrustPolicy,
) -> Result<VerifiedSession, String> {
    if authorization_id.is_empty() || token.len() != 64 || !token.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("invalid server-side authorization identity or session token".into());
    }
    require_published_policy_snapshot(reg)?;
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
    // Fail closed on the chain generation BEFORE any tier work: an unknown generation (`0`) or a
    // declared generation below the durable floor (a rollback) authorizes nothing, on production
    // and non-production alike, with no development or testnet bypass. This is orthogonal to, and
    // additive to, the trust-tier gate below.
    let Some(generation) = reg.effective_generation(application_id) else {
        return Err(format!(
            "application {application_id} has no live chain generation (unknown or rolled back); \
             no session issued until an operator migrates it to the current generation"
        ));
    };
    let evidence_kind = evidence.kind();
    // The tier is derived here, from the evidence and the gate's proof machinery — never supplied
    // by the caller as a bare tier. Incompatible evidence, a mode ceiling or the operator policy
    // all pull it down; nothing pulls it up.
    let achieved = achieved_tier(evidence_kind, gate.proof_mode, policy);
    let required = required_tier(app);
    if achieved < required {
        return Err(format!(
            "gate {gate_id}: {evidence_kind} evidence achieves {achieved} trust, but this application \
             requires {required}; no session issued"
        ));
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
    Ok(VerifiedSession {
        token: token.to_ascii_lowercase(),
        authorization_id: Some(authorization_id.to_string()),
        application_id: application_id.to_string(),
        proven_gate: gate_id.to_string(),
        policy_hash,
        granted,
        issued_unix: issued,
        expires_unix: issued + ttl.as_secs(),
        revoked: false,
        test_lane: gate.test_lane,
        trust_tier: achieved,
        evidence_kind,
        chain_generation: generation,
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
    /// The verification strength of the session that was checked. `Development` on any refusal
    /// that happened before a session was found. Server-derived; a relying party may require a
    /// minimum but can never raise it.
    pub trust_tier: TrustTier,
    /// The minimum tier the application's CURRENT policy demands. A relying party compares the two.
    pub required_tier: TrustTier,
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
    // The required tier is a property of the CURRENT application policy, computed here regardless
    // of the session. A relying party reads it to see what the gate demands; it can never be
    // lowered by the session or the client.
    let required = reg.application(application_id).map(required_tier).unwrap_or(TrustTier::Production);
    let refuse = |reason: &str, expires: u64, version: u64, tier: TrustTier| AccessDecision {
        authorized: false, reason: reason.into(), granted: vec![], expires_unix: expires,
        policy_version: version, trust_tier: tier, required_tier: required,
    };

    let Some(session) = sessions.iter().find(|s| s.token == token) else {
        return refuse("unknown session", 0, 0, TrustTier::Development);
    };
    let tier = session.trust_tier;
    if session.revoked {
        return refuse("session revoked", session.expires_unix, 0, tier);
    }
    if session.expires_unix <= now {
        return refuse("session expired", session.expires_unix, 0, tier);
    }
    if session.application_id != application_id {
        return refuse("session belongs to a different application", session.expires_unix, 0, tier);
    }
    let Some(app) = reg.application(application_id) else {
        return refuse("unknown application", session.expires_unix, 0, tier);
    };
    let Some(gate) = app.gate(gate_id) else {
        return refuse("unknown gate", session.expires_unix, 0, tier);
    };
    // A test-lane session can never authorise a production gate, whatever it proves.
    if session.test_lane && !gate.test_lane {
        return refuse("a test session cannot authorise a production gate", session.expires_unix, 0, tier);
    }
    // Fail-closed chain-generation enforcement, evaluated against the CURRENT application and the
    // durable floor on every call. A session only authorizes while its generation is still the
    // live one: an unknown generation (`0`, including a legacy session) authorizes nothing; a
    // reset migration raises the generation so prior-generation sessions stop authorizing at once;
    // and restoring an older configuration cannot help, because the declared generation then falls
    // below the durable floor and `effective_generation` returns `None`.
    match reg.effective_generation(application_id) {
        Some(current) if current == session.chain_generation => {}
        Some(current) => {
            return refuse(
                &format!(
                    "session was issued under chain generation {} but this application now \
                     authorizes under generation {current}; a fresh proof is required",
                    session.chain_generation
                ),
                session.expires_unix, 0, tier,
            );
        }
        None => {
            return refuse(
                "this application has no live chain generation (unknown or rolled back); it \
                 authorizes nothing until an operator migrates it forward",
                session.expires_unix, 0, tier,
            );
        }
    }
    // Fail-closed trust-tier enforcement, evaluated against the CURRENT application policy and not
    // just at issuance. A `Development` session never authorizes; a legacy session (no tier field)
    // loads as `Development` and so is refused here; promoting an application to production
    // immediately refuses any session below `Production`, because `required` is recomputed per call.
    if tier < required {
        return refuse(
            &format!(
                "session trust tier {tier} is below the {required} this application requires; a fresh proof is needed"
            ),
            session.expires_unix, 0, tier,
        );
    }
    // The session is only as valid as the policy it proved under. If the published version moved
    // on, fresh evidence is required: re-verification, not inheritance.
    let version = match reg.current_version(application_id, &session.proven_gate) {
        Some(v) => v,
        None => return refuse("no published policy for the proven gate", session.expires_unix, 0, tier),
    };
    if version.policy_hash != session.policy_hash {
        return refuse(
            &format!(
                "the policy changed (v{} -> v{}): fresh proof required",
                version.version.saturating_sub(1),
                version.version
            ),
            session.expires_unix, version.version, tier,
        );
    }
    // Tier resolution, server-side, from the CURRENT policy — never from the client's claim.
    if !session.granted.contains(&gate_id.to_string()) {
        return AccessDecision {
            authorized: false, reason: "this session does not grant that gate".into(),
            granted: session.granted.clone(), expires_unix: session.expires_unix,
            policy_version: version.version, trust_tier: tier, required_tier: required,
        };
    }
    AccessDecision {
        authorized: true,
        reason: "ok".into(),
        granted: app.granted_by(gate_id),
        expires_unix: session.expires_unix,
        policy_version: version.version,
        trust_tier: tier,
        required_tier: required,
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
    use ghost_gate_core::policy::{AnchorClass, ConsensusAttestation, Freshness, GateTopology, ProofMode};

    /// A stand-in ledger identity for the tests; production uses the deployment's real genesis hash.
    const GENESIS: &str = "00f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

    fn hasher() -> Blake3Hasher {
        Blake3Hasher
    }

    /// The operator opt-in used by tests that exercise the testnet tier.
    fn trusted() -> TrustPolicy {
        TrustPolicy { operator_trusted_indexer: true, max_tier: TrustTier::Production }
    }

    /// Synthetic Production-grade consensus evidence — the only way to reach `Production` before
    /// the sidecar client exists. `ConsensusAttestation::fixture` is test-only.
    fn production_evidence() -> Evidence {
        Evidence::ConsensusVerified(ConsensusAttestation::fixture(
            AnchorClass::IndependentlyAuthenticated, Freshness::Authenticated, "fixture-consensus"))
    }

    /// A consensus gate's own-wallet receipt: reaches OperatorTrustedTestnet, never Production.
    fn wallet_receipt() -> Evidence {
        Evidence::OperatorWalletReceipt { digest: "fixture-receipt".into() }
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
            chain_generation: 1,
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
                policy_hash_version: POLICY_HASH_V1,
                policy_context: None,
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
        let session = issue_session_with_evidence(&reg, "meme", "gold", gold_hash, &mut entropy, &production_evidence(), &trusted()).unwrap();
        assert_eq!(session.granted, vec!["gold", "silver", "bronze"]);
        assert_eq!(session.trust_tier, TrustTier::Production);

        let now = now_unix();
        assert!(check_access(&reg, &[session.clone()], &session.token, "meme", "gold", now).authorized);
        assert!(check_access(&reg, &[session.clone()], &session.token, "meme", "bronze", now).authorized);
        // A lower-tier session does NOT reach up.
        let s2 = issue_session_with_evidence(&reg, "meme", "silver", silver_hash, &mut entropy, &production_evidence(), &trusted()).unwrap();
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
    fn durable_authorization_recovers_one_session_instead_of_minting_two() {
        let dir = std::env::temp_dir().join(format!("gg-session-idempotent-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let paths = StorePaths::new(&dir);
        let reg = registry_with_tiers();
        save_registry(&paths, &reg).unwrap();
        let hash = reg.current_version("meme", "gold").unwrap().policy_hash.clone();
        let mut plane = AccessPlane::new(paths.clone());
        let token = "ab".repeat(32);
        let first = plane.issue_idempotent("meme", "gold", hash.clone(), "auth-1", &token, &production_evidence(), &trusted()).unwrap();
        let recovered = plane.issue_idempotent("meme", "gold", hash, "auth-1", &token, &production_evidence(), &trusted()).unwrap();
        assert_eq!(first.token, token);
        assert_eq!(recovered.token, first.token);
        assert_eq!(load_sessions(&paths).unwrap().len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_policy_change_kills_old_sessions_evidence_even_within_ttl() {
        let reg = registry_with_tiers();
        let app = reg.application("meme").unwrap();
        let gold = app.gate("gold").unwrap();
        let mut entropy = [0u8; 32];
        let session = issue_session_with_evidence(&reg, "meme", "gold", hash_policy(&hasher(), app, gold, 1), &mut entropy, &production_evidence(), &trusted()).unwrap();

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
                policy_hash_version: POLICY_HASH_V1,
                policy_context: None,
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
        let ts = issue_session_with_evidence(&reg, "test", "test-gate", test_hash, &mut e, &wallet_receipt(), &TrustPolicy::default()).unwrap();
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
    fn bindings_contain_only_activatable_enabled_gates() {
        let mut reg = registry_with_tiers();
        let app = reg.applications.first_mut().unwrap();
        let mut draft = gate("draft", 5, false);
        draft.enabled = false;
        draft.proof_mode = ProofMode::Xtm;
        app.gates.push(draft);
        // An enabled CONSENSUS gate with no deployed component is refused outright.
        let mut no_component = gate("ghost", 5, false);
        no_component.component_address = None;
        no_component.proof_mode = ProofMode::Consensus;
        app.gates.push(no_component);
        assert!(app.validate().is_err(), "an enabled consensus gate without a component must be refused");
        app.gates.pop();
        app.validate().unwrap();
        assert!(derive_bindings(&reg).is_err(), "even an inert unpublished draft blocks a live refresh");
    }

    #[test]
    fn draft_authorization_edits_refuse_a_live_bindings_refresh() {
        // `applications` is the administrator's mutable draft workspace.  Until Publish cuts
        // new immutable versions, every authorization-relevant draft must prevent a fresh
        // binding snapshot from replacing the already-served one.
        let reg = registry_with_tiers();
        assert!(derive_bindings(&reg).is_ok());

        let mut cases: Vec<(&str, Box<dyn Fn(&mut Registry)>)> = Vec::new();
        cases.push(("grants", Box::new(|r| r.applications[0].gates[0].grants.clear())));
        cases.push(("ttl", Box::new(|r| r.applications[0].gates[0].session_ttl_override = Some(7_200))));
        cases.push(("scope", Box::new(|r| r.applications[0].gates[0].use_mode = ghost_gate_core::policy::GateUseMode::Both)));
        cases.push(("enablement", Box::new(|r| r.applications[0].gates[0].enabled = false)));
        cases.push(("default ttl", Box::new(|r| r.applications[0].default_session_ttl = 7_200)));
        cases.push(("topology", Box::new(|r| r.applications[0].topology = GateTopology::Independent)));

        for (name, change) in cases {
            let mut draft = reg.clone();
            change(&mut draft);
            assert!(derive_bindings(&draft).is_err(), "unpublished {name} change must not reach the bridge");
            let policy_hash = draft.current_version("meme", "gold").unwrap().policy_hash.clone();
            let refusal = issue_session_with_token(
                &draft,
                "meme",
                "gold",
                policy_hash,
                "draft-eligibility",
                &"11".repeat(32),
                &production_evidence(),
                &trusted(),
            );
            assert!(refusal.is_err(), "unpublished {name} change must also block new session issuance");
        }
    }

    #[test]
    fn credential_gate_without_component_appears_in_bindings() {
        let mut reg = Registry::default();
        reg.credentials.push(cred("admin-1"));
        let mut a = app("cred-app", "admin-1");
        let cred_gate = GatePolicy {
            gate_id: "crypt".into(),
            name: "10 tTARI credential".into(),
            resource_address: "resource_0101010101010101010101010101010101010101010101010101010101010101".into(),
            symbol: "tTARI".into(),
            divisibility: 6,
            threshold_raw: 10_000_000,
            proof_mode: ProofMode::Credential,
            challenge_domain: "cred-app.localhost".into(),
            session_ttl_override: None,
            grants: vec![],
            enabled: true,
            test_lane: false,
            use_mode: Default::default(),
            component_address: None,
        };
        a.gates.push(cred_gate.clone());
        a.validate().unwrap();
        reg.applications.push(a.clone());
        // Publish the credential gate.
        reg.versions.push(PolicyVersion {
            application_id: a.application_id.clone(),
            gate_id: "crypt".into(),
            version: 1,
            policy_hash: hash_policy(&hasher(), &a, &cred_gate, 1),
            policy_hash_version: POLICY_HASH_V1,
            policy_context: None,
            network: ghost_gate_core::network::LOCALNET,
            genesis_hash: GENESIS.to_string(),
            policy: cred_gate.clone(),
            app_revision: 1,
            created_unix: 1,
        });
        let b = derive_bindings(&reg).unwrap();
        assert_eq!(b.gates.len(), 1, "the credential gate must appear in bindings");
        let snap = &b.gates[0];
        assert_eq!(snap.gate_id, "crypt");
        assert_eq!(snap.component_address, "", "credential gate has empty component");
        assert_eq!(snap.proof_mode, "credential");
        assert_eq!(snap.max_trust_tier, "operator-trusted-testnet");
    }

    #[test]
    fn credential_gate_with_component_is_refused_by_validation() {
        let mut reg = Registry::default();
        reg.credentials.push(cred("admin-1"));
        let mut a = app("bad-cred", "admin-1");
        a.gates.push(GatePolicy {
            gate_id: "bad".into(),
            name: "bad".into(),
            resource_address: "resource_abc".into(),
            symbol: "t".into(),
            divisibility: 6,
            threshold_raw: 1,
            proof_mode: ProofMode::Credential,
            challenge_domain: "x.localhost".into(),
            session_ttl_override: None,
            grants: vec![],
            enabled: true,
            test_lane: false,
            use_mode: Default::default(),
            component_address: Some("component_abc".into()),
        });
        assert!(a.validate().is_err(), "a credential gate with a component must be refused");
    }

    #[test]
    fn production_app_refuses_session_below_production_tier() {
        let reg = registry_with_tiers();
        let app = reg.application("meme").unwrap();
        let gold = app.gate("gold").unwrap();
        let gold_hash = hash_policy(&hasher(), app, gold, 1);
        let mut entropy = [0u8; 32];
        // The test registry is production:true. A consensus-mode gate with only an operator wallet
        // receipt achieves OperatorTrustedTestnet, which must be refused for a production app.
        let err = issue_session_with_evidence(
            &reg, "meme", "gold", gold_hash.clone(), &mut entropy, &wallet_receipt(), &trusted(),
        );
        assert!(err.is_err(), "production app must refuse an operator-trusted-testnet session");
        let msg = err.unwrap_err();
        assert!(msg.contains("production") || msg.contains("requires"), "error should explain the tier gap: {msg}");

        // No evidence at all is likewise refused.
        let err2 = issue_session_with_evidence(
            &reg, "meme", "gold", gold_hash, &mut entropy, &Evidence::None, &trusted(),
        );
        assert!(err2.is_err(), "production app must refuse a session with no evidence");
    }

    #[test]
    fn non_production_app_accepts_testnet_tier() {
        let mut reg = registry_with_tiers();
        reg.applications.first_mut().unwrap().production = false;
        let app = reg.application("meme").unwrap();
        let gold = app.gate("gold").unwrap();
        let gold_hash = hash_policy(&hasher(), app, gold, 1);
        let mut entropy = [0u8; 32];
        let session = issue_session_with_evidence(
            &reg, "meme", "gold", gold_hash, &mut entropy, &wallet_receipt(), &trusted(),
        ).unwrap();
        assert_eq!(session.trust_tier, TrustTier::OperatorTrustedTestnet);
    }

    #[test]
    fn credential_mode_caps_tier_at_operator_trusted_testnet() {
        let mut reg = Registry::default();
        reg.credentials.push(cred("admin-1"));
        let mut a = app("cap-test", "admin-1");
        a.production = false;
        a.gates.push(GatePolicy {
            gate_id: "cred".into(),
            name: "cred".into(),
            resource_address: "resource_abc".into(),
            symbol: "t".into(),
            divisibility: 6,
            threshold_raw: 1,
            proof_mode: ProofMode::Credential,
            challenge_domain: "x.localhost".into(),
            session_ttl_override: None,
            grants: vec![],
            enabled: true,
            test_lane: false,
            use_mode: Default::default(),
            component_address: None,
        });
        a.validate().unwrap();
        reg.applications.push(a.clone());
        let g = a.gate("cred").unwrap();
        reg.versions.push(PolicyVersion {
            application_id: a.application_id.clone(),
            gate_id: "cred".into(),
            version: 1,
            policy_hash: hash_policy(&hasher(), &a, g, 1),
            policy_hash_version: POLICY_HASH_V1,
            policy_context: None,
            network: ghost_gate_core::network::LOCALNET,
            genesis_hash: GENESIS.to_string(),
            policy: g.clone(),
            app_revision: 1,
            created_unix: 1,
        });
        let mut entropy = [0u8; 32];
        // Even with independently-authenticated consensus evidence (Production-grade on a consensus
        // gate), credential mode caps the achieved tier at OperatorTrustedTestnet.
        let session = issue_session_with_evidence(
            &reg, "cap-test", "cred", hash_policy(&hasher(), &a, g, 1),
            &mut entropy, &production_evidence(), &trusted(),
        ).unwrap();
        assert_eq!(session.trust_tier, TrustTier::OperatorTrustedTestnet,
            "credential mode must cap the tier at OperatorTrustedTestnet");
        assert_eq!(session.evidence_kind, EvidenceKind::ConsensusIndependentAuthenticatedFreshness);
    }

    #[test]
    fn indexer_assertion_needs_the_operator_opt_in_and_never_reaches_production() {
        // A credential gate on a non-production app, verified only by the indexer's own flag.
        let mut reg = Registry::default();
        reg.credentials.push(cred("admin-1"));
        let mut a = app("idx", "admin-1");
        a.production = false;
        a.gates.push(GatePolicy {
            gate_id: "cred".into(), name: "cred".into(), resource_address: "resource_abc".into(),
            symbol: "t".into(), divisibility: 6, threshold_raw: 1, proof_mode: ProofMode::Credential,
            challenge_domain: "x.localhost".into(), session_ttl_override: None, grants: vec![],
            enabled: true, test_lane: false, use_mode: Default::default(), component_address: None,
        });
        a.validate().unwrap();
        reg.applications.push(a.clone());
        let g = a.gate("cred").unwrap();
        let hash = hash_policy(&hasher(), &a, g, 1);
        reg.versions.push(PolicyVersion {
            application_id: a.application_id.clone(), gate_id: "cred".into(), version: 1,
            policy_hash: hash.clone(), policy_hash_version: POLICY_HASH_V1, policy_context: None, network: ghost_gate_core::network::LOCALNET,
            genesis_hash: GENESIS.to_string(), policy: g.clone(), app_revision: 1, created_unix: 1,
        });
        let indexer = Evidence::IndexerAsserted { digest: "idx".into() };
        let mut e = [0u8; 32];
        // Without the opt-in, indexer-asserted evidence achieves only Development and issues nothing.
        assert!(issue_session_with_evidence(&reg, "idx", "cred", hash.clone(), &mut e, &indexer, &TrustPolicy::default()).is_err(),
            "indexer assertion without the operator opt-in must not authorize");
        // With the opt-in, it reaches OperatorTrustedTestnet on a non-production app.
        let s = issue_session_with_evidence(&reg, "idx", "cred", hash.clone(), &mut e, &indexer, &trusted()).unwrap();
        assert_eq!(s.trust_tier, TrustTier::OperatorTrustedTestnet);
        // The same evidence on a PRODUCTION app never authorizes, opt-in or not.
        reg.applications.first_mut().unwrap().production = true;
        assert!(issue_session_with_evidence(&reg, "idx", "cred", hash, &mut e, &indexer, &trusted()).is_err(),
            "indexer assertion must never authorize a production application");
    }

    #[test]
    fn a_global_tier_ceiling_only_lowers_the_result() {
        let mut reg = registry_with_tiers();
        reg.applications.first_mut().unwrap().production = false;
        let app = reg.application("meme").unwrap();
        let gold = app.gate("gold").unwrap();
        let hash = hash_policy(&hasher(), app, gold, 1);
        let mut e = [0u8; 32];
        // Production-grade evidence, but the operator pins the ceiling to testnet.
        let capped = TrustPolicy { operator_trusted_indexer: true, max_tier: TrustTier::OperatorTrustedTestnet };
        let s = issue_session_with_evidence(&reg, "meme", "gold", hash, &mut e, &production_evidence(), &capped).unwrap();
        assert_eq!(s.trust_tier, TrustTier::OperatorTrustedTestnet, "the ceiling lowered a production result");
    }

    #[test]
    fn promoting_an_app_to_production_refuses_an_existing_testnet_session_at_check_time() {
        let mut reg = registry_with_tiers();
        reg.applications.first_mut().unwrap().production = false;
        let (hash, token) = {
            let app = reg.application("meme").unwrap();
            let gold = app.gate("gold").unwrap();
            (hash_policy(&hasher(), app, gold, 1), String::new())
        };
        let _ = token;
        let mut e = [0u8; 32];
        let session = issue_session_with_evidence(&reg, "meme", "gold", hash, &mut e, &wallet_receipt(), &trusted()).unwrap();
        let now = now_unix();
        // While non-production, the testnet session authorizes.
        assert!(check_access(&reg, &[session.clone()], &session.token, "meme", "gold", now).authorized);
        // Promote the application to production: the SAME session is now below the required tier.
        reg.applications.first_mut().unwrap().production = true;
        let d = check_access(&reg, &[session.clone()], &session.token, "meme", "gold", now);
        assert!(!d.authorized, "promotion to production must refuse a session below Production");
        assert_eq!(d.required_tier, TrustTier::Production);
        assert_eq!(d.trust_tier, TrustTier::OperatorTrustedTestnet);
    }

    #[test]
    fn a_development_or_legacy_session_authorizes_nothing() {
        // A legacy session: no trust_tier field → Development after serde default. Build one by hand.
        let mut reg = registry_with_tiers();
        reg.applications.first_mut().unwrap().production = false; // even the most permissive app
        let app = reg.application("meme").unwrap();
        let gold = app.gate("gold").unwrap();
        let hash = hash_policy(&hasher(), app, gold, 1);
        let now = now_unix();
        let legacy = VerifiedSession {
            token: "legacy-token".into(), authorization_id: None, application_id: "meme".into(),
            proven_gate: "gold".into(), policy_hash: hash, granted: vec!["gold".into(), "silver".into(), "bronze".into()],
            issued_unix: now, expires_unix: now + 3600, revoked: false, test_lane: false,
            trust_tier: TrustTier::Development, evidence_kind: EvidenceKind::None,
            // A live generation, so this test isolates the TIER gate (the generation gate runs
            // first and would otherwise refuse a `0` generation for a different reason).
            chain_generation: 1,
        };
        let d = check_access(&reg, &[legacy.clone()], &legacy.token, "meme", "gold", now);
        assert!(!d.authorized, "a Development/legacy session must never authorize, even on a non-production app");
        assert!(d.reason.contains("trust tier"), "the refusal names the tier gap: {}", d.reason);
        assert_eq!(d.trust_tier, TrustTier::Development);
        // And on a production application the same legacy session is likewise refused.
        reg.applications.first_mut().unwrap().production = true;
        let dp = check_access(&reg, &[legacy.clone()], &legacy.token, "meme", "gold", now);
        assert!(!dp.authorized, "a Development/legacy session must never authorize a production app");
        assert_eq!(dp.required_tier, TrustTier::Production);
    }

    #[test]
    fn session_bounds_match_the_policy_bounds() {
        assert_eq!(CHALLENGE_TTL, std::time::Duration::from_secs(180));
        assert!(MIN_SESSION_TTL <= DEFAULT_SESSION_TTL);
    }

    // ---- Chain-generation / reset enforcement ------------------------------------------------

    fn gen_dir(name: &str) -> StorePaths {
        let dir = std::env::temp_dir().join(format!("gg-gen-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        StorePaths::new(&dir)
    }

    fn session_at(reg: &Registry, generation: u64) -> VerifiedSession {
        let app = reg.application("meme").unwrap();
        let gold = app.gate("gold").unwrap();
        let hash = hash_policy(&hasher(), app, gold, 1);
        let now = now_unix();
        VerifiedSession {
            token: format!("tok-{generation}"), authorization_id: None, application_id: "meme".into(),
            proven_gate: "gold".into(), policy_hash: hash,
            granted: vec!["gold".into(), "silver".into(), "bronze".into()],
            issued_unix: now, expires_unix: now + 3600, revoked: false, test_lane: false,
            trust_tier: TrustTier::Production, evidence_kind: EvidenceKind::IndexerAsserted,
            chain_generation: generation,
        }
    }

    #[test]
    fn an_unknown_generation_authorizes_nothing_on_production_and_nonproduction() {
        let mut reg = registry_with_tiers();
        reg.applications[0].chain_generation = 0; // unknown
        let mut entropy = [0u8; 32];
        let gold_hash = {
            let app = reg.application("meme").unwrap();
            hash_policy(&hasher(), app, app.gate("gold").unwrap(), 1)
        };
        // Issuance refuses outright — no development or testnet bypass.
        assert!(issue_session_with_evidence(&reg, "meme", "gold", gold_hash, &mut entropy, &production_evidence(), &trusted()).is_err());
        // And a hand-built session (as a legacy record with generation 0 would be) is refused at
        // check time on BOTH a production and a non-production application.
        let now = now_unix();
        let s = session_at(&reg, 0);
        for production in [true, false] {
            reg.applications[0].production = production;
            let d = check_access(&reg, &[s.clone()], &s.token, "meme", "gold", now);
            assert!(!d.authorized, "unknown generation must deny (production={production})");
            assert!(d.reason.contains("chain generation"), "reason names the generation gate: {}", d.reason);
        }
    }

    #[test]
    fn a_rolled_back_generation_authorizes_nothing() {
        let mut reg = registry_with_tiers();
        // The durable floor has reached 2, but the application now declares 1 — a restored older
        // configuration. It authorizes nothing until migrated forward again.
        reg.applications[0].chain_generation = 1;
        reg.generation_floor.insert("meme".into(), 2);
        let now = now_unix();
        let s = session_at(&reg, 1);
        let d = check_access(&reg, &[s.clone()], &s.token, "meme", "gold", now);
        assert!(!d.authorized, "a declared generation below the durable floor is a rollback");
        let mut entropy = [0u8; 32];
        let gold_hash = { let app = reg.application("meme").unwrap(); hash_policy(&hasher(), app, app.gate("gold").unwrap(), 1) };
        assert!(issue_session_with_evidence(&reg, "meme", "gold", gold_hash, &mut entropy, &production_evidence(), &trusted()).is_err());
    }

    #[test]
    fn migrating_the_generation_retires_old_sessions_and_rejects_rollback() {
        let paths = gen_dir("migrate");
        let mut reg = registry_with_tiers(); // generation 1, floor 0
        // A live generation-1 session authorizes before the migration.
        let old = session_at(&reg, 1);
        let now = now_unix();
        assert!(check_access(&reg, &[old.clone()], &old.token, "meme", "gold", now).authorized);

        // Migrate forward to generation 2.
        migrate_generation(&paths, &mut reg, "meme", 2, "admin-1").unwrap();
        assert_eq!(reg.generation_floor_of("meme"), 2);
        assert_eq!(reg.application("meme").unwrap().chain_generation, 2);

        // The generation-1 session no longer authorizes — the generation gate refuses it even
        // though its policy hash is unchanged.
        let d = check_access(&reg, &[old.clone()], &old.token, "meme", "gold", now);
        assert!(!d.authorized, "a pre-migration session must be refused after a generation migration");
        assert!(d.reason.contains("generation 2"), "reason names the live generation: {}", d.reason);

        // A fresh generation-2 session authorizes.
        let fresh = session_at(&reg, 2);
        assert!(check_access(&reg, &[fresh.clone()], &fresh.token, "meme", "gold", now).authorized);

        // Rollback and no-op migrations are rejected; only strictly-forward moves are allowed.
        assert!(migrate_generation(&paths, &mut reg, "meme", 1, "admin-1").is_err());
        assert!(migrate_generation(&paths, &mut reg, "meme", 2, "admin-1").is_err());
        assert!(migrate_generation(&paths, &mut reg, "meme", 3, "admin-1").is_ok());

        // The durable ledger survives a reload: restoring an old in-memory registry (floor 0) does
        // not lower the floor, because the floor is read from generations.ndjson, not registry.json.
        let reloaded_floor = load_generation_floor(&paths).unwrap();
        assert_eq!(reloaded_floor.get("meme").copied(), Some(3), "the floor is durable and monotonic");
        let _ = fs::remove_dir_all(&paths.dir);
    }

    #[test]
    fn identical_l1_genesis_network_and_resource_still_fail_closed_across_generations() {
        // The dangerous case: an L2 reset leaves the L1 genesis, the network byte and the native
        // resource address UNCHANGED. Nothing about the gate's content or ledger identity differs
        // — only the declared chain generation. A session from the earlier generation must still
        // be refused, proving reset safety does not rely on any of those three fields changing.
        let paths = gen_dir("identical");
        let mut reg = registry_with_tiers();
        let before = reg.application("meme").unwrap().clone();
        let old = session_at(&reg, 1);

        migrate_generation(&paths, &mut reg, "meme", 2, "admin-1").unwrap();
        let after = reg.application("meme").unwrap();

        // Everything a reset is NOT guaranteed to change is identical across the two generations.
        assert_eq!(before.network, after.network);
        assert_eq!(before.genesis_hash, after.genesis_hash);
        assert_eq!(
            before.gates.iter().map(|g| &g.resource_address).collect::<Vec<_>>(),
            after.gates.iter().map(|g| &g.resource_address).collect::<Vec<_>>(),
            "the native resource address is deterministic and unchanged",
        );
        // Yet the pre-reset session is refused purely on the generation boundary.
        let now = now_unix();
        assert!(!check_access(&reg, &[old.clone()], &old.token, "meme", "gold", now).authorized);
        let _ = fs::remove_dir_all(&paths.dir);
    }

    // ---- Migration crash recovery and ledger integrity ---------------------------------------

    #[test]
    fn a_partial_migration_with_the_floor_ahead_of_the_declared_generation_fails_closed() {
        // Models a crash AFTER the generation floor was persisted (fsync'd) but BEFORE the registry
        // save advanced the declared generation. The floor is 2 while the application still
        // declares 1, so every authorization is refused until the migration is completed.
        let paths = gen_dir("partial");
        let mut reg = registry_with_tiers(); // declared 1, floor 0
        append_generation_activation(&paths, &mut reg, &GenerationActivation {
            application_id: "meme".into(), generation: 2, activated_unix: 1, actor: "op".into(),
        }).unwrap();
        // The registry save did NOT run, so the app still declares generation 1.
        assert_eq!(reg.application("meme").unwrap().chain_generation, 1);
        assert_eq!(reg.generation_floor_of("meme"), 2);
        assert_eq!(reg.effective_generation("meme"), None, "floor ahead of declared denies");
        let now = now_unix();
        let s = session_at(&reg, 1);
        assert!(!check_access(&reg, &[s.clone()], &s.token, "meme", "gold", now).authorized);
        // Issuance is refused too, so no new session is minted in the partial state.
        let mut entropy = [0u8; 32];
        let gold_hash = { let app = reg.application("meme").unwrap(); hash_policy(&hasher(), app, app.gate("gold").unwrap(), 1) };
        assert!(issue_session_with_evidence(&reg, "meme", "gold", gold_hash, &mut entropy, &production_evidence(), &trusted()).is_err());
        let _ = fs::remove_dir_all(&paths.dir);
    }

    #[test]
    fn a_restored_older_registry_cannot_drop_below_the_durable_floor_on_reload() {
        // The durable floor lives in its own append-only ledger, not in registry.json. Persisting a
        // registry that declares the OLD generation and reloading it cannot lower the floor: the
        // reload re-reads the ledger, sees generation 2, and refuses the restored generation-1 app.
        let paths = gen_dir("restore");
        let mut reg = registry_with_tiers(); // declared 1
        append_generation_activation(&paths, &mut reg, &GenerationActivation {
            application_id: "meme".into(), generation: 2, activated_unix: 1, actor: "op".into(),
        }).unwrap();
        // Save a registry that STILL declares generation 1 (the restored older configuration).
        save_registry(&paths, &reg).unwrap();
        let reloaded = load_registry(&paths).unwrap();
        assert_eq!(reloaded.application("meme").unwrap().chain_generation, 1);
        assert_eq!(reloaded.generation_floor_of("meme"), 2, "the floor is re-read from the ledger");
        assert_eq!(reloaded.effective_generation("meme"), None, "the restored older config authorizes nothing");
        let _ = fs::remove_dir_all(&paths.dir);
    }

    #[test]
    fn a_corrupt_or_truncated_generation_ledger_fails_the_whole_load() {
        // A corrupt or partially-written ledger line could hide a high activation, so the load
        // fails closed (the registry refuses to load at all) rather than silently using a lower
        // floor. Recovery is an explicit operator repair, never an automatic downgrade.
        let paths = gen_dir("corrupt");
        let good = serde_json::to_string(&GenerationActivation {
            application_id: "meme".into(), generation: 2, activated_unix: 1, actor: "op".into(),
        }).unwrap();
        fs::write(paths.generations(), format!("{good}\n{{\"application_id\":\"meme\",\"generat")).unwrap();
        assert!(load_generation_floor(&paths).is_err(), "a corrupt/truncated ledger line fails closed");
        assert!(load_registry(&paths).is_err(), "the whole registry load fails closed on a bad ledger");
        let _ = fs::remove_dir_all(&paths.dir);
    }

    #[test]
    fn a_missing_generation_ledger_means_no_floor_documenting_the_fs_limit() {
        // LIMIT OF LOCAL-FS PERSISTENCE: if the ledger file is DELETED, the floor is lost. Rollback
        // protection defends against restoring registry.json / sessions.json alone, not against an
        // adversary who can also delete or rewrite the ledger itself. A remote/authenticated anchor
        // would be required to defend the durable store against tampering with its own files.
        let paths = gen_dir("missing");
        assert_eq!(load_generation_floor(&paths).unwrap().len(), 0);
        let reg = load_registry(&paths).unwrap();
        assert_eq!(reg.generation_floor_of("anything"), 0);
        let _ = fs::remove_dir_all(&paths.dir);
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

    /// Issue a session for an accepted proof and persist it. Returns the grant for the wire. The
    /// trust tier is derived from `evidence` and the gate's proof machinery, never supplied raw.
    pub fn issue(
        &mut self,
        application_id: &str,
        gate_id: &str,
        policy_hash: String,
        evidence: &Evidence,
        policy: &TrustPolicy,
    ) -> Result<AccessGrant, String> {
        let reg = self.registry()?;
        let _lock = StoreLock::acquire(&self.paths)?;
        // Reload under the lock: another process (or our own past self) may have written.
        let mut fresh = load_sessions(&self.paths)?;
        prune_sessions(&mut fresh);
        let mut entropy = [0u8; 32];
        let session = issue_session_with_evidence(&reg, application_id, gate_id, policy_hash, &mut entropy, evidence, policy)?;
        let grant = grant_of(&session);
        fresh.push(session);
        save_sessions(&self.paths, &fresh)?;
        self.cached_sessions = Some((fresh, std::time::SystemTime::now()));
        Ok(grant)
    }

    /// Install or recover one session for a durable replay authorization. This is deliberately
    /// idempotent rather than pretending two separate files form a transaction: a retry passes
    /// the same durable authorization identity and bearer token and recovers the same session.
    /// A recovery NEVER upgrades: it returns the session exactly as it was first issued, whatever
    /// evidence the retry presents.
    pub fn issue_idempotent(
        &mut self,
        application_id: &str,
        gate_id: &str,
        policy_hash: String,
        authorization_id: &str,
        token: &str,
        evidence: &Evidence,
        policy: &TrustPolicy,
    ) -> Result<AccessGrant, String> {
        let reg = self.registry()?;
        let _lock = StoreLock::acquire(&self.paths)?;
        let mut fresh = load_sessions(&self.paths)?;
        prune_sessions(&mut fresh);
        if let Some(existing) = fresh.iter().find(|s| s.authorization_id.as_deref() == Some(authorization_id)) {
            if existing.application_id != application_id || existing.proven_gate != gate_id
                || existing.policy_hash != policy_hash || existing.token != token {
                return Err("authorization identity conflicts with an existing session".into());
            }
            return Ok(grant_of(existing));
        }
        let session = issue_session_with_token(
            &reg, application_id, gate_id, policy_hash, authorization_id, token, evidence, policy,
        )?;
        let grant = grant_of(&session);
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
    pub trust_tier: TrustTier,
    #[serde(default)]
    pub evidence_kind: EvidenceKind,
}

/// The wire grant for a session, carrying its server-derived tier and evidence class verbatim.
fn grant_of(session: &VerifiedSession) -> AccessGrant {
    AccessGrant {
        token: session.token.clone(),
        application_id: session.application_id.clone(),
        proven_gate: session.proven_gate.clone(),
        granted: session.granted.clone(),
        expires_unix: session.expires_unix,
        test_lane: session.test_lane,
        trust_tier: session.trust_tier,
        evidence_kind: session.evidence_kind,
    }
}
