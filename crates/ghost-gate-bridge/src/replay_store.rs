//! Durable, fail-closed replay coordination.
//!
//! `ChallengeBook` is process-local and supplies the full challenge payload while a bridge is
//! alive. It is not evidence of cross-process coordination. This module is the authority for
//! replay decisions when a durable access plane is configured; it never falls back to memory on
//! an I/O or parse error.
//!
//! `FileReplayStore` coordinates independent bridge processes on one local filesystem through a
//! create-new lock and same-directory atomic replacement. It is not a cross-machine coordinator:
//! do not place it on a Windows/WSL shared mount or a network filesystem and call it distributed
//! storage. A hosted deployment needs a single-owner strongly-consistent coordinator.

use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use ghost_gate_core::policy::TrustTier;
use serde::{Deserialize, Serialize};

const STALE_LOCK_AFTER: Duration = Duration::from_secs(30);
const LOCK_ATTEMPTS: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayState { Issued, Submitted, Authorized, Revoked }

/// The only pending proof kind that can currently be reconstructed safely from durable data.
/// An XTM proof also needs its verifier artifact, which is deliberately never serialised here;
/// it therefore remains pending after a restart rather than being guessed or re-submitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingProofKind { OotleTransaction, MinotariXtm }

/// Server-created challenge facts. Every scope field is rechecked on submission; no browser
/// field is sufficient to establish a binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayRecord {
    pub nonce: [u8; 32],
    pub tenant: String,
    pub gate: String,
    pub relying_site: String,
    pub visitor_session: Vec<u8>,
    pub network: u8,
    /// Policy version digest selected by server configuration at issue time. A replacement means
    /// this challenge may never create a session under the newer policy.
    pub policy_hash: Option<String>,
    pub expires_unix: u64,
    pub state: ReplayState,
    /// Server-generated id of the first accepted submission; used for same-visitor retries.
    pub proof_job_id: Option<String>,
    /// The submitted transaction reference, recorded before the browser learns it. It is not
    /// client input and is sufficient to resume Ootle finality polling after a local restart.
    #[serde(default)]
    pub pending_transaction_id: Option<String>,
    /// See [`PendingProofKind`]. Missing fields in pre-recovery records fail closed as unknown.
    #[serde(default)]
    pub pending_proof_kind: Option<PendingProofKind>,
    /// Stable identity of the one authorization this nonce can create.
    pub authorization_id: Option<String>,
    /// Random bearer token held only in server-side storage, reserved before session installation.
    pub access_token: Option<String>,
    /// The trust tier this authorization was granted at. Durable so a restart or retry reinstalls
    /// the SAME tier rather than whatever a later caller supplies. Legacy records load as
    /// `Development` and so can never recover real access.
    #[serde(default)]
    pub trust_tier: TrustTier,
    /// The digest of the verified evidence behind this authorization. A recovery that presents
    /// different evidence is refused rather than silently upgraded. Legacy records have `None`.
    #[serde(default)]
    pub evidence_digest: Option<String>,
    /// The Ootle chain generation this authorization was granted under. A recovery after a reset
    /// migration presents the new generation, which no longer matches, so the retired-generation
    /// authorization is refused rather than restored. Legacy records load as `0`.
    #[serde(default)]
    pub chain_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reservation {
    Reserved(ReplayRecord),
    Pending { proof_job_id: String },
    Authorized(ReplayRecord),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReplayError {
    #[error("GG: durable replay protection is unavailable; refusing proof processing")]
    Unavailable,
    #[error("GG: challenge is unknown, expired, or bound to another visitor/gate/network")]
    BindingMismatch,
    #[error("GG: challenge authorization is already final")]
    Final,
    #[error("GG: recovery evidence does not match the originally authorized evidence")]
    EvidenceMismatch,
    #[error("GG: recovery presents a different chain generation than the one originally authorized")]
    GenerationMismatch,
}

/// Each mutation must be atomic across bridge processes. There is intentionally no operation that
/// releases an ambiguous network result: it stays Submitted until reconciliation.
pub trait ReplayStore: Send {
    fn create(&mut self, record: &ReplayRecord) -> Result<(), ReplayError>;
    fn reserve(&mut self, expected: &ReplayRecord, proof_job_id: &str, now_unix: u64)
        -> Result<Reservation, ReplayError>;
    /// Persist the server-observed transaction reference after submission. If this fails, the
    /// challenge remains reserved and no session may be issued from the in-memory job alone.
    fn record_submission(&mut self, nonce: &[u8; 32], proof_job_id: &str,
        kind: PendingProofKind, transaction_id: &str) -> Result<(), ReplayError>;
    /// Return unresolved durable records for restart recovery. Implementations must not omit a
    /// submitted record merely because it lacks a recoverable transaction reference.
    fn submitted(&mut self) -> Result<Vec<ReplayRecord>, ReplayError>;
    /// Install the one authorization this nonce may create, binding the verified evidence to it.
    /// A retry with the same authorization id must present the same `trust_tier` and
    /// `evidence_digest`, or it is refused: a restart, retry or reconfiguration can never upgrade
    /// an authorization that was already granted.
    fn authorize(&mut self, nonce: &[u8; 32], authorization_id: &str, access_token: &str,
        trust_tier: TrustTier, evidence_digest: &str, chain_generation: u64, now_unix: u64)
        -> Result<ReplayRecord, ReplayError>;
    fn release_refused(&mut self, expected: &ReplayRecord, now_unix: u64) -> Result<(), ReplayError>;
    fn revoke(&mut self, nonce: &[u8; 32]) -> Result<(), ReplayError>;
    fn get(&mut self, nonce: &[u8; 32]) -> Result<ReplayRecord, ReplayError>;
}

/// Explicit fail-closed default. Production code must opt in to a configured durable store.
pub struct UnavailableReplayStore;
impl ReplayStore for UnavailableReplayStore {
    fn create(&mut self, _: &ReplayRecord) -> Result<(), ReplayError> { Err(ReplayError::Unavailable) }
    fn reserve(&mut self, _: &ReplayRecord, _: &str, _: u64) -> Result<Reservation, ReplayError> { Err(ReplayError::Unavailable) }
    fn record_submission(&mut self, _: &[u8; 32], _: &str, _: PendingProofKind, _: &str) -> Result<(), ReplayError> { Err(ReplayError::Unavailable) }
    fn submitted(&mut self) -> Result<Vec<ReplayRecord>, ReplayError> { Err(ReplayError::Unavailable) }
    fn authorize(&mut self, _: &[u8; 32], _: &str, _: &str, _: TrustTier, _: &str, _: u64, _: u64) -> Result<ReplayRecord, ReplayError> { Err(ReplayError::Unavailable) }
    fn release_refused(&mut self, _: &ReplayRecord, _: u64) -> Result<(), ReplayError> { Err(ReplayError::Unavailable) }
    fn revoke(&mut self, _: &[u8; 32]) -> Result<(), ReplayError> { Err(ReplayError::Unavailable) }
    fn get(&mut self, _: &[u8; 32]) -> Result<ReplayRecord, ReplayError> { Err(ReplayError::Unavailable) }
}

/// Test/local-only implementation. It is never selected by bridge startup.
#[derive(Default)]
pub struct MemoryReplayStore { records: HashMap<[u8; 32], ReplayRecord> }
impl MemoryReplayStore { pub fn insert(&mut self, record: ReplayRecord) { self.records.insert(record.nonce, record); } }

fn matches(record: &ReplayRecord, expected: &ReplayRecord, now: u64) -> bool {
    record.expires_unix >= now
        && record.tenant == expected.tenant
        && record.gate == expected.gate
        && record.relying_site == expected.relying_site
        && record.visitor_session == expected.visitor_session
        && record.network == expected.network
        && record.policy_hash == expected.policy_hash
}

fn reserve_record(record: &mut ReplayRecord, expected: &ReplayRecord, job: &str, now: u64)
    -> Result<Reservation, ReplayError>
{
    if !matches(record, expected, now) { return Err(ReplayError::BindingMismatch); }
    match record.state {
        ReplayState::Issued => {
            record.state = ReplayState::Submitted;
            record.proof_job_id = Some(job.to_string());
            Ok(Reservation::Reserved(record.clone()))
        }
        ReplayState::Submitted => record.proof_job_id.clone()
            .map(|proof_job_id| Reservation::Pending { proof_job_id })
            .ok_or(ReplayError::Unavailable),
        ReplayState::Authorized => Ok(Reservation::Authorized(record.clone())),
        ReplayState::Revoked => Err(ReplayError::Final),
    }
}

fn authorize_record(record: &mut ReplayRecord, id: &str, token: &str, tier: TrustTier, digest: &str, generation: u64, now: u64)
    -> Result<ReplayRecord, ReplayError>
{
    if record.expires_unix < now { return Err(ReplayError::BindingMismatch); }
    match record.state {
        ReplayState::Submitted => {
            // A challenge reserved under one generation cannot be authorized under another: a reset
            // migration between challenge issue and proof submission retires the in-flight
            // challenge rather than exchanging it for a new-generation session. (`chain_generation`
            // is deliberately absent from the policy hash, so this is the check that catches it.) A
            // record reserved before this field existed carries `0` and is simply stamped here.
            if record.chain_generation != 0 && record.chain_generation != generation {
                return Err(ReplayError::GenerationMismatch);
            }
            record.state = ReplayState::Authorized;
            record.authorization_id = Some(id.to_string());
            record.access_token = Some(token.to_string());
            record.trust_tier = tier;
            record.evidence_digest = Some(digest.to_string());
            record.chain_generation = generation;
            Ok(record.clone())
        }
        // An idempotent retry must reinstall the SAME authorization: same identity, same tier, same
        // evidence, same chain generation. A mismatch on the evidence or the tier is an upgrade
        // attempt; a mismatch on the generation is a post-reset-migration recovery attempt. Both
        // are refused rather than silently restored.
        ReplayState::Authorized if record.authorization_id.as_deref() == Some(id) => {
            if record.chain_generation != generation {
                return Err(ReplayError::GenerationMismatch);
            }
            if record.trust_tier != tier || record.evidence_digest.as_deref() != Some(digest) {
                return Err(ReplayError::EvidenceMismatch);
            }
            Ok(record.clone())
        }
        ReplayState::Authorized | ReplayState::Revoked | ReplayState::Issued => Err(ReplayError::Final),
    }
}

impl ReplayStore for MemoryReplayStore {
    fn create(&mut self, record: &ReplayRecord) -> Result<(), ReplayError> {
        if self.records.contains_key(&record.nonce) { return Err(ReplayError::Final); }
        self.records.insert(record.nonce, record.clone());
        Ok(())
    }
    fn reserve(&mut self, expected: &ReplayRecord, job: &str, now: u64) -> Result<Reservation, ReplayError> {
        reserve_record(self.records.get_mut(&expected.nonce).ok_or(ReplayError::BindingMismatch)?, expected, job, now)
    }
    fn record_submission(&mut self, nonce: &[u8; 32], job: &str, kind: PendingProofKind, transaction_id: &str) -> Result<(), ReplayError> {
        let record = self.records.get_mut(nonce).ok_or(ReplayError::BindingMismatch)?;
        if record.state != ReplayState::Submitted || record.proof_job_id.as_deref() != Some(job) { return Err(ReplayError::Final); }
        record.pending_proof_kind = Some(kind);
        record.pending_transaction_id = Some(transaction_id.to_string());
        Ok(())
    }
    fn submitted(&mut self) -> Result<Vec<ReplayRecord>, ReplayError> {
        Ok(self.records.values().filter(|record| record.state == ReplayState::Submitted).cloned().collect())
    }
    fn authorize(&mut self, nonce: &[u8; 32], id: &str, token: &str, tier: TrustTier, digest: &str, generation: u64, now: u64) -> Result<ReplayRecord, ReplayError> {
        authorize_record(self.records.get_mut(nonce).ok_or(ReplayError::BindingMismatch)?, id, token, tier, digest, generation, now)
    }
    fn release_refused(&mut self, expected: &ReplayRecord, now: u64) -> Result<(), ReplayError> {
        let record = self.records.get_mut(&expected.nonce).ok_or(ReplayError::BindingMismatch)?;
        if !matches(record, expected, now) || record.state != ReplayState::Submitted { return Err(ReplayError::Final); }
        record.state = ReplayState::Issued;
        record.proof_job_id = None;
        Ok(())
    }
    fn revoke(&mut self, nonce: &[u8; 32]) -> Result<(), ReplayError> {
        let record = self.records.get_mut(nonce).ok_or(ReplayError::BindingMismatch)?;
        record.state = ReplayState::Revoked;
        Ok(())
    }
    fn get(&mut self, nonce: &[u8; 32]) -> Result<ReplayRecord, ReplayError> {
        self.records.get(nonce).cloned().ok_or(ReplayError::BindingMismatch)
    }
}

/// A durable local store. Lock holders only read/write a record; no chain or wallet operation runs
/// under this lock. A stale lock is reclaimed after a bounded lease to recover from a crashed local
/// bridge, at the cost of availability rather than an ambiguous replay decision.
pub struct FileReplayStore { root: PathBuf }
impl FileReplayStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, ReplayError> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|_| ReplayError::Unavailable)?;
        Ok(Self { root })
    }
    fn path(&self, nonce: &[u8; 32]) -> PathBuf { self.root.join(format!("{}.json", hex::encode(nonce))) }
    fn locked<T>(&self, action: impl FnOnce() -> Result<T, ReplayError>) -> Result<T, ReplayError> {
        let lock = self.root.join("replay.lock");
        for attempt in 0..LOCK_ATTEMPTS {
            match OpenOptions::new().write(true).create_new(true).open(&lock) {
                Ok(mut guard) => {
                    let _ = writeln!(guard, "pid={} started_unix={}", std::process::id(), crate::session::now_unix());
                    let _ = guard.sync_all();
                    let result = action();
                    drop(guard);
                    let _ = fs::remove_file(&lock);
                    return result;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let stale = fs::metadata(&lock).and_then(|m| m.modified()).ok()
                        .and_then(|at| SystemTime::now().duration_since(at).ok())
                        .map(|age| age > STALE_LOCK_AFTER).unwrap_or(false);
                    if stale { let _ = fs::remove_file(&lock); continue; }
                    std::thread::sleep(Duration::from_millis(10 + (attempt as u64 % 5) * 5));
                }
                Err(_) => return Err(ReplayError::Unavailable),
            }
        }
        Err(ReplayError::Unavailable)
    }
    fn read(&self, nonce: &[u8; 32]) -> Result<ReplayRecord, ReplayError> {
        serde_json::from_slice(&fs::read(self.path(nonce)).map_err(|_| ReplayError::BindingMismatch)?)
            .map_err(|_| ReplayError::Unavailable)
    }
    fn write(&self, path: &Path, record: &ReplayRecord) -> Result<(), ReplayError> {
        let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
        let data = serde_json::to_vec(record).map_err(|_| ReplayError::Unavailable)?;
        { let mut file = fs::File::create(&tmp).map_err(|_| ReplayError::Unavailable)?;
          file.write_all(&data).and_then(|_| file.sync_all()).map_err(|_| ReplayError::Unavailable)?; }
        fs::rename(&tmp, path).map_err(|_| ReplayError::Unavailable)
    }
}

impl ReplayStore for FileReplayStore {
    fn create(&mut self, record: &ReplayRecord) -> Result<(), ReplayError> {
        self.locked(|| { let path = self.path(&record.nonce); if path.exists() { return Err(ReplayError::Final); } self.write(&path, record) })
    }
    fn reserve(&mut self, expected: &ReplayRecord, job: &str, now: u64) -> Result<Reservation, ReplayError> {
        self.locked(|| { let mut record = self.read(&expected.nonce)?; let result = reserve_record(&mut record, expected, job, now)?;
            if matches!(result, Reservation::Reserved(_)) { self.write(&self.path(&record.nonce), &record)?; } Ok(result) })
    }
    fn record_submission(&mut self, nonce: &[u8; 32], job: &str, kind: PendingProofKind, transaction_id: &str) -> Result<(), ReplayError> {
        self.locked(|| {
            let mut record = self.read(nonce)?;
            if record.state != ReplayState::Submitted || record.proof_job_id.as_deref() != Some(job) { return Err(ReplayError::Final); }
            record.pending_proof_kind = Some(kind);
            record.pending_transaction_id = Some(transaction_id.to_string());
            self.write(&self.path(nonce), &record)
        })
    }
    fn submitted(&mut self) -> Result<Vec<ReplayRecord>, ReplayError> {
        self.locked(|| {
            let mut records = Vec::new();
            for entry in fs::read_dir(&self.root).map_err(|_| ReplayError::Unavailable)? {
                let entry = entry.map_err(|_| ReplayError::Unavailable)?;
                if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") { continue; }
                let record: ReplayRecord = serde_json::from_slice(&fs::read(entry.path()).map_err(|_| ReplayError::Unavailable)?)
                    .map_err(|_| ReplayError::Unavailable)?;
                if record.state == ReplayState::Submitted { records.push(record); }
            }
            Ok(records)
        })
    }
    fn authorize(&mut self, nonce: &[u8; 32], id: &str, token: &str, tier: TrustTier, digest: &str, generation: u64, now: u64) -> Result<ReplayRecord, ReplayError> {
        self.locked(|| { let mut record = self.read(nonce)?; let result = authorize_record(&mut record, id, token, tier, digest, generation, now)?;
            self.write(&self.path(nonce), &record)?; Ok(result) })
    }
    fn release_refused(&mut self, expected: &ReplayRecord, now: u64) -> Result<(), ReplayError> {
        self.locked(|| { let mut record = self.read(&expected.nonce)?;
            if !matches(&record, expected, now) || record.state != ReplayState::Submitted { return Err(ReplayError::Final); }
            record.state = ReplayState::Issued; record.proof_job_id = None; self.write(&self.path(&record.nonce), &record) })
    }
    fn revoke(&mut self, nonce: &[u8; 32]) -> Result<(), ReplayError> {
        self.locked(|| { let mut record = self.read(nonce)?; record.state = ReplayState::Revoked; self.write(&self.path(nonce), &record) })
    }
    fn get(&mut self, nonce: &[u8; 32]) -> Result<ReplayRecord, ReplayError> { self.locked(|| self.read(nonce)) }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record() -> ReplayRecord { ReplayRecord { nonce: [7; 32], tenant: "tenant-a".into(), gate: "gate-a".into(), relying_site: "site-a".into(), visitor_session: vec![1], network: 38, policy_hash: Some("policy-a".into()), expires_unix: 10, state: ReplayState::Issued, proof_job_id: None, pending_transaction_id: None, pending_proof_kind: None, authorization_id: None, access_token: None, trust_tier: TrustTier::default(), evidence_digest: None, chain_generation: 0 } }
    const TTT: TrustTier = TrustTier::OperatorTrustedTestnet;
    const GEN: u64 = 1;

    #[test]
    fn identical_retry_gets_original_job_but_another_visitor_cannot() {
        let mut store = MemoryReplayStore::default(); let record = record(); store.create(&record).unwrap();
        assert!(matches!(store.reserve(&record, "job-1", 1), Ok(Reservation::Reserved(_))));
        assert_eq!(store.reserve(&record, "job-2", 1), Ok(Reservation::Pending { proof_job_id: "job-1".into() }));
        let mut other = record.clone(); other.visitor_session = vec![9];
        assert_eq!(store.reserve(&other, "job-3", 1), Err(ReplayError::BindingMismatch));
    }
    #[test]
    fn authorization_is_idempotent_but_never_mints_a_second_token() {
        let mut store = MemoryReplayStore::default(); let record = record(); store.create(&record).unwrap(); store.reserve(&record, "job-1", 1).unwrap();
        assert_eq!(store.authorize(&record.nonce, "auth-1", "token-1", TTT, "ev-1", GEN, 1).unwrap().access_token.as_deref(), Some("token-1"));
        assert_eq!(store.authorize(&record.nonce, "auth-1", "token-2", TTT, "ev-1", GEN, 1).unwrap().access_token.as_deref(), Some("token-1"));
        assert_eq!(store.authorize(&record.nonce, "auth-2", "token-2", TTT, "ev-1", GEN, 1), Err(ReplayError::Final));
    }
    #[test]
    fn authorization_records_the_tier_and_evidence_and_refuses_an_upgrade_on_retry() {
        let mut store = MemoryReplayStore::default(); let record = record(); store.create(&record).unwrap(); store.reserve(&record, "job-1", 1).unwrap();
        let authed = store.authorize(&record.nonce, "auth-1", "token-1", TTT, "ev-1", GEN, 1).unwrap();
        assert_eq!(authed.trust_tier, TTT);
        assert_eq!(authed.evidence_digest.as_deref(), Some("ev-1"));
        assert_eq!(authed.chain_generation, GEN);
        // Same identity, SAME evidence and tier: idempotent success.
        assert!(store.authorize(&record.nonce, "auth-1", "token-1", TTT, "ev-1", GEN, 1).is_ok());
        // Same identity, a STRONGER tier or different evidence: refused, never upgraded.
        assert_eq!(store.authorize(&record.nonce, "auth-1", "token-1", TrustTier::Production, "ev-1", GEN, 1), Err(ReplayError::EvidenceMismatch));
        assert_eq!(store.authorize(&record.nonce, "auth-1", "token-1", TTT, "ev-2", GEN, 1), Err(ReplayError::EvidenceMismatch));
        assert_eq!(store.get(&record.nonce).unwrap().trust_tier, TTT, "the stored tier is never raised");
    }

    #[test]
    fn a_challenge_reserved_before_a_migration_cannot_be_authorized_after_it() {
        // The challenge is ISSUED (reserved) under generation 1, then the operator migrates to
        // generation 2, then the visitor submits the proof. Authorization must refuse rather than
        // mint a generation-2 session from a generation-1 challenge. This is the end-to-end
        // old-challenge-after-migration case, caught at authorize time.
        let mut store = MemoryReplayStore::default();
        let mut record = record();
        record.chain_generation = 1; // stamped at challenge issue (as the bridge now does)
        store.create(&record).unwrap();
        store.reserve(&record, "job-1", 1).unwrap();
        // Migration happened: the gate binding now reports generation 2.
        assert_eq!(
            store.authorize(&record.nonce, "auth-1", "token-1", TTT, "ev-1", 2, 1),
            Err(ReplayError::GenerationMismatch)
        );
        // No authorization was installed: the record is untouched, so no session can be recovered.
        let after = store.get(&record.nonce).unwrap();
        assert_eq!(after.state, ReplayState::Submitted);
        assert!(after.access_token.is_none(), "no bearer token was minted for the stale challenge");
    }

    #[test]
    fn a_recovery_under_a_different_generation_is_refused() {
        // After a reset migration the bridge presents the NEW generation on recovery. The retired
        // generation's authorization must not be restored, even with the same identity, tier and
        // evidence — that is exactly the old-record-replay-after-migration case.
        let mut store = MemoryReplayStore::default(); let record = record(); store.create(&record).unwrap(); store.reserve(&record, "job-1", 1).unwrap();
        store.authorize(&record.nonce, "auth-1", "token-1", TTT, "ev-1", GEN, 1).unwrap();
        assert_eq!(store.authorize(&record.nonce, "auth-1", "token-1", TTT, "ev-1", GEN + 1, 1), Err(ReplayError::GenerationMismatch));
        assert_eq!(store.get(&record.nonce).unwrap().chain_generation, GEN, "the stored generation is never changed on recovery");
    }
    #[test]
    fn unavailable_storage_fails_closed() { let mut store = UnavailableReplayStore; assert_eq!(store.create(&record()), Err(ReplayError::Unavailable)); assert_eq!(store.reserve(&record(), "job", 1), Err(ReplayError::Unavailable)); }
    #[test]
    fn file_store_survives_reopen_and_coordinates_independent_instances() {
        let root = std::env::temp_dir().join(format!("gg-replay-{}-{}", std::process::id(), crate::session::now_unix())); let mut first = FileReplayStore::open(&root).unwrap(); let mut second = FileReplayStore::open(&root).unwrap(); let record = record();
        first.create(&record).unwrap(); first.reserve(&record, "job-1", 1).unwrap();
        assert_eq!(second.reserve(&record, "job-2", 1), Ok(Reservation::Pending { proof_job_id: "job-1".into() }));
        second.authorize(&record.nonce, "auth-1", "token-1", TTT, "ev-1", GEN, 1).unwrap(); assert_eq!(first.authorize(&record.nonce, "auth-2", "token-2", TTT, "ev-1", GEN, 1), Err(ReplayError::Final)); assert_eq!(first.get(&record.nonce).unwrap().state, ReplayState::Authorized); let _ = fs::remove_dir_all(root);
    }
    #[test]
    fn corrupt_durable_record_fails_closed() {
        let root = std::env::temp_dir().join(format!("gg-replay-corrupt-{}-{}", std::process::id(), crate::session::now_unix())); let mut store = FileReplayStore::open(&root).unwrap(); let record = record(); store.create(&record).unwrap(); fs::write(store.path(&record.nonce), b"not json").unwrap(); assert_eq!(store.get(&record.nonce), Err(ReplayError::Unavailable)); let _ = fs::remove_dir_all(root);
    }
    #[test]
    fn durable_submission_reference_survives_reopen_but_cannot_be_replaced() {
        let root = std::env::temp_dir().join(format!("gg-replay-submission-{}-{}", std::process::id(), crate::session::now_unix()));
        let mut first = FileReplayStore::open(&root).unwrap(); let record = record();
        first.create(&record).unwrap(); first.reserve(&record, "job-1", 1).unwrap();
        first.record_submission(&record.nonce, "job-1", PendingProofKind::OotleTransaction, "tx-1").unwrap();
        let mut second = FileReplayStore::open(&root).unwrap();
        let pending = second.submitted().unwrap(); assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].pending_transaction_id.as_deref(), Some("tx-1"));
        assert_eq!(second.record_submission(&record.nonce, "job-2", PendingProofKind::OotleTransaction, "tx-2"), Err(ReplayError::Final));
        let _ = fs::remove_dir_all(root);
    }
}
