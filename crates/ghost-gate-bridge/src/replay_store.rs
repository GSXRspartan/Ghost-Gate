//! Durable replay-state boundary.
//!
//! `ChallengeBook` is deliberately process-local and is suitable only for the localhost bridge.
//! A hosted verifier must put this trait behind a strongly consistent implementation (for example a
//! single-owner Durable Object). Until one is configured, `UnavailableReplayStore` refuses every
//! mutation rather than pretending that an in-memory mutex coordinates multiple processes.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayState { Issued, Submitted, Authorized, Revoked }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayRecord {
    pub nonce: [u8; 32],
    pub tenant: String,
    pub gate: String,
    pub relying_site: String,
    pub visitor_session: Vec<u8>,
    pub expires_unix: u64,
    pub state: ReplayState,
    pub authorization_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReplayError {
    #[error("GG: durable replay protection is unavailable; refusing proof processing")]
    Unavailable,
    #[error("GG: challenge is unknown, expired, or bound to another visitor/gate")]
    BindingMismatch,
    #[error("GG: challenge submission is already pending")]
    Pending,
    #[error("GG: challenge authorization is already final")]
    Final,
}

/// A storage boundary that must make each transition atomic across verifier instances.
pub trait ReplayStore {
    fn reserve(&mut self, expected: &ReplayRecord, now_unix: u64) -> Result<ReplayRecord, ReplayError>;
    fn authorize(&mut self, nonce: &[u8; 32], authorization_id: &str, now_unix: u64) -> Result<(), ReplayError>;
    fn release_ambiguous(&mut self, nonce: &[u8; 32], now_unix: u64) -> Result<(), ReplayError>;
    fn revoke(&mut self, nonce: &[u8; 32]) -> Result<(), ReplayError>;
}

/// Explicit fail-closed default for a hosted configuration without durable storage.
pub struct UnavailableReplayStore;
impl ReplayStore for UnavailableReplayStore {
    fn reserve(&mut self, _: &ReplayRecord, _: u64) -> Result<ReplayRecord, ReplayError> { Err(ReplayError::Unavailable) }
    fn authorize(&mut self, _: &[u8; 32], _: &str, _: u64) -> Result<(), ReplayError> { Err(ReplayError::Unavailable) }
    fn release_ambiguous(&mut self, _: &[u8; 32], _: u64) -> Result<(), ReplayError> { Err(ReplayError::Unavailable) }
    fn revoke(&mut self, _: &[u8; 32]) -> Result<(), ReplayError> { Err(ReplayError::Unavailable) }
}

/// Test/local implementation. It is intentionally not presented as multi-process durable storage.
#[derive(Default)]
pub struct MemoryReplayStore { records: HashMap<[u8; 32], ReplayRecord> }
impl MemoryReplayStore { pub fn insert(&mut self, record: ReplayRecord) { self.records.insert(record.nonce, record); } }
impl ReplayStore for MemoryReplayStore {
    fn reserve(&mut self, expected: &ReplayRecord, now: u64) -> Result<ReplayRecord, ReplayError> {
        let record = self.records.get_mut(&expected.nonce).ok_or(ReplayError::BindingMismatch)?;
        if record.expires_unix < now || record.tenant != expected.tenant || record.gate != expected.gate || record.relying_site != expected.relying_site || record.visitor_session != expected.visitor_session { return Err(ReplayError::BindingMismatch); }
        match record.state { ReplayState::Issued => { record.state = ReplayState::Submitted; Ok(record.clone()) }, ReplayState::Submitted => Err(ReplayError::Pending), ReplayState::Authorized | ReplayState::Revoked => Err(ReplayError::Final) }
    }
    fn authorize(&mut self, nonce: &[u8; 32], id: &str, now: u64) -> Result<(), ReplayError> {
        let record = self.records.get_mut(nonce).ok_or(ReplayError::BindingMismatch)?;
        if record.expires_unix < now { return Err(ReplayError::BindingMismatch); }
        if record.state != ReplayState::Submitted { return Err(ReplayError::Final); }
        record.state = ReplayState::Authorized; record.authorization_id = Some(id.into()); Ok(())
    }
    fn release_ambiguous(&mut self, _: &[u8; 32], _: u64) -> Result<(), ReplayError> { Err(ReplayError::Unavailable) }
    fn revoke(&mut self, nonce: &[u8; 32]) -> Result<(), ReplayError> { let r=self.records.get_mut(nonce).ok_or(ReplayError::BindingMismatch)?; r.state=ReplayState::Revoked; Ok(()) }
}

#[cfg(test)] mod tests { use super::*;
 fn record() -> ReplayRecord { ReplayRecord { nonce:[7;32],tenant:"a".into(),gate:"g".into(),relying_site:"site".into(),visitor_session:vec![1],expires_unix:10,state:ReplayState::Issued,authorization_id:None } }
 #[test] fn duplicate_reservation_and_authorization_are_atomic_at_the_store_boundary() { let mut s=MemoryReplayStore::default(); let r=record(); s.insert(r.clone()); assert!(s.reserve(&r,1).is_ok()); assert_eq!(s.reserve(&r,1),Err(ReplayError::Pending)); assert!(s.authorize(&r.nonce,"grant",1).is_ok()); assert_eq!(s.authorize(&r.nonce,"grant2",1),Err(ReplayError::Final)); }
 #[test] fn unavailable_storage_fails_closed() { let mut s=UnavailableReplayStore; assert_eq!(s.reserve(&record(),1),Err(ReplayError::Unavailable)); }
}
