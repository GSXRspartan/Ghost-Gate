//! Durable replay-state boundary.
//!
//! `ChallengeBook` is deliberately process-local and is suitable only for the localhost bridge.
//! A hosted verifier must put this trait behind a strongly consistent implementation (for example a
//! single-owner Durable Object). Until one is configured, `UnavailableReplayStore` refuses every
//! mutation rather than pretending that an in-memory mutex coordinates multiple processes.

use std::{collections::HashMap, fs::{self, OpenOptions}, path::{Path, PathBuf}};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayState { Issued, Submitted, Authorized, Revoked }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Local durable store using an exclusive create lock and atomic record replacement.
/// A stale lock after a crash deliberately blocks new decisions until an operator investigates;
/// availability is sacrificed rather than guessing an ambiguous transaction outcome.
pub struct FileReplayStore { root: PathBuf }
impl FileReplayStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, ReplayError> { let root=root.into(); fs::create_dir_all(&root).map_err(|_| ReplayError::Unavailable)?; Ok(Self { root }) }
    fn path(&self, nonce: &[u8;32]) -> PathBuf { self.root.join(format!("{}.json", hex::encode(nonce))) }
    fn locked<T>(&self, action: impl FnOnce() -> Result<T, ReplayError>) -> Result<T, ReplayError> {
        let lock=self.root.join("replay.lock"); let guard=OpenOptions::new().write(true).create_new(true).open(&lock).map_err(|_| ReplayError::Unavailable)?;
        let result=action(); drop(guard); let _=fs::remove_file(lock); result
    }
    pub fn create(&self, record: &ReplayRecord) -> Result<(), ReplayError> { self.locked(|| { let path=self.path(&record.nonce); if path.exists() { return Err(ReplayError::Final); } self.write(&path, record) }) }
    fn read(&self, nonce:&[u8;32]) -> Result<ReplayRecord, ReplayError> { serde_json::from_slice(&fs::read(self.path(nonce)).map_err(|_|ReplayError::BindingMismatch)?).map_err(|_|ReplayError::Unavailable) }
    fn write(&self, path:&Path, record:&ReplayRecord) -> Result<(), ReplayError> { let tmp=path.with_extension("tmp"); fs::write(&tmp,serde_json::to_vec(record).map_err(|_|ReplayError::Unavailable)?).map_err(|_|ReplayError::Unavailable)?; fs::rename(tmp,path).map_err(|_|ReplayError::Unavailable) }
}
impl ReplayStore for FileReplayStore {
 fn reserve(&mut self,e:&ReplayRecord,now:u64)->Result<ReplayRecord,ReplayError>{ self.locked(||{let mut r=self.read(&e.nonce)?; if r.expires_unix<now||r.tenant!=e.tenant||r.gate!=e.gate||r.relying_site!=e.relying_site||r.visitor_session!=e.visitor_session{return Err(ReplayError::BindingMismatch)}; match r.state {ReplayState::Issued=>{r.state=ReplayState::Submitted;self.write(&self.path(&r.nonce),&r)?;Ok(r)},ReplayState::Submitted=>Err(ReplayError::Pending),_=>Err(ReplayError::Final)}}) }
 fn authorize(&mut self,n:&[u8;32],id:&str,now:u64)->Result<(),ReplayError>{self.locked(||{let mut r=self.read(n)?;if r.expires_unix<now{return Err(ReplayError::BindingMismatch)}if r.state!=ReplayState::Submitted{return Err(ReplayError::Final)}r.state=ReplayState::Authorized;r.authorization_id=Some(id.into());self.write(&self.path(n),&r)})}
 fn release_ambiguous(&mut self,_:&[u8;32],_:u64)->Result<(),ReplayError>{Err(ReplayError::Unavailable)}
 fn revoke(&mut self,n:&[u8;32])->Result<(),ReplayError>{self.locked(||{let mut r=self.read(n)?;r.state=ReplayState::Revoked;self.write(&self.path(n),&r)})}
}

#[cfg(test)] mod tests { use super::*;
 fn record() -> ReplayRecord { ReplayRecord { nonce:[7;32],tenant:"a".into(),gate:"g".into(),relying_site:"site".into(),visitor_session:vec![1],expires_unix:10,state:ReplayState::Issued,authorization_id:None } }
 #[test] fn duplicate_reservation_and_authorization_are_atomic_at_the_store_boundary() { let mut s=MemoryReplayStore::default(); let r=record(); s.insert(r.clone()); assert!(s.reserve(&r,1).is_ok()); assert_eq!(s.reserve(&r,1),Err(ReplayError::Pending)); assert!(s.authorize(&r.nonce,"grant",1).is_ok()); assert_eq!(s.authorize(&r.nonce,"grant2",1),Err(ReplayError::Final)); }
 #[test] fn unavailable_storage_fails_closed() { let mut s=UnavailableReplayStore; assert_eq!(s.reserve(&record(),1),Err(ReplayError::Unavailable)); }
 #[test] fn file_store_survives_reopen_and_coordinates_two_instances() { let root=std::env::temp_dir().join(format!("gg-replay-{}",std::process::id())); let mut a=FileReplayStore::open(&root).unwrap(); let mut b=FileReplayStore::open(&root).unwrap(); let r=record(); a.create(&r).unwrap(); a.reserve(&r,1).unwrap(); assert_eq!(b.reserve(&r,1),Err(ReplayError::Pending)); b.authorize(&r.nonce,"grant",1).unwrap(); assert_eq!(a.authorize(&r.nonce,"again",1),Err(ReplayError::Final)); let _=fs::remove_dir_all(root); }
}
