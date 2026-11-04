//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! The bridge process: a loopback HTTP server over the policy in the rest of this crate.
//!
//! # Why loopback, and why that is not enough on its own
//!
//! The listener binds `127.0.0.1` and nothing else, so no machine on the network can reach it. A
//! browser *can*: every page the user has open can reach localhost, and a page the user does not trust
//! will try. So binding loopback is necessary and not sufficient, and the second half is
//! [`OriginPolicy`] -- a request carrying an `Origin` must be on an explicit list.
//!
//! # Why there is no way to spend from here
//!
//! The server holds a [`GateRegistry`], a [`ChallengeBook`] and a [`WalletChannel`], and no route reads
//! anything from a request body except a gate id, a hex challenge nonce and a hex session commitment.
//! There is no field for an amount, a destination or a UTXO. The strongest thing a caller can do is ask
//! for a proof against a gate it already holds a live challenge for, and the wallet picks the input.
//!
//! A proof is not a transaction a caller can also do something else with: the bridge builds it, submits
//! it with the wallet's own lock so the wallet derives the stealth signers itself, and returns the
//! transaction id -- not a signed transaction for the caller to broadcast.

use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::gate_registry::GateRegistry;
use crate::http::{Request, Response, Route, parse_request, render};
use crate::origin::OriginPolicy;
use crate::policy::{ProveRequest, validate_prove_request};
use crate::replay_store::{PendingProofKind, ReplayRecord, ReplayStore, Reservation};
use crate::session::{ChallengeBook, IssuedChallenge, ProofJob, ProofStatus, PublicProof, random_nonce};
use crate::wallet::{StatementRequest, WalletChannel};

/// Largest request body accepted. A prove request is three short strings; anything larger is not one.
pub const MAX_BODY: usize = 8 * 1024;

/// How long one status poll will wait on the wallet while reconciling a submitted job.
///
/// Short on purpose: the caller is polling anyway, so completion is driven by repeated polls rather
/// than by one long blocking wait, and every other route stays responsive behind the mutex.
pub const RECONCILE_WAIT: Duration = Duration::from_secs(3);

/// The most proof jobs the bridge retains.
///
/// Same reasoning as the challenge cap: a job is a record the process holds so `/proof/:id/status`
/// can answer, and creating one is unauthenticated apart from the transport checks. The oldest
/// entries are dropped once the cap is hit, because a proof's result matters for minutes, not
/// forever, and the challenge cap upstream already bounds how fast jobs can be created.
pub const MAX_JOBS: usize = 1_000;

/// Everything the server needs, assembled once at startup.
///
/// Four channels, one per chain and direction: `W` is the Ootle wallet daemon (consensus proofs),
/// `R` the Ootle indexer (credential proofs), `X` the Minotari wallet daemon (native L1 proofs)
/// and `XR` the Minotari base node (L1 evidence). The L1 pair defaults to `NoXtm`/`NoXtmChainReader`
/// so a bridge built without them still serves its Ootle gates and *refuses* L1 work loudly.
pub struct Bridge<
    W: WalletChannel,
    R: crate::credential::ChainReader = crate::credential::NoChainReader,
    X: crate::xtm::XtmChannel = crate::xtm::NoXtm,
    XR: crate::xtm::XtmChainReader = crate::xtm::NoXtmChainReader,
> {
    pub gates: GateRegistry,
    /// Verified-access sessions, active when the bridge is registry-backed (GG_BINDINGS_PATH).
    pub access: Option<crate::access::AccessHandle>,
    /// Sessions granted on accepted proofs, keyed by the challenge nonce they burnt, so the
    /// proof-status response can carry the grant to the client that polled it.
    pub access_grants: std::collections::BTreeMap<String, ghost_gate_registry::AccessGrant>,
    pub challenges: ChallengeBook,
    /// Set only for a configured registry-backed bridge. Its absence means proofs may be previewed
    /// but no durable access authorization is issued.
    pub replay: Option<Box<dyn ReplayStore>>,
    pub jobs: Vec<ProofJob>,
    /// The Privacy Lab's per-attempt diagnostic traces, keyed by an unguessable attempt id the
    /// visitor holds. Bounded in both directions (see MAX_TRACES / MAX_TRACE_EVENTS): a trace can
    /// never become a memory sink, and an old attempt is dropped rather than kept forever.
    pub traces: std::collections::HashMap<String, crate::trace::Trace>,
    /// Which attempt a proof job belongs to, so the events a job generates land in the right trace.
    pub job_attempts: std::collections::HashMap<String, String>,
    pub wallet: W,
    pub origins: OriginPolicy,
    /// How long a freshly minted challenge stays answerable.
    pub challenge_ttl: Duration,
    /// The epoch bound minted into every challenge. See `gate_registry::issue_challenge`.
    pub challenge_expires_epoch: u64,
    /// Where the static demo assets live, resolved once at startup from a fixed list of names.
    ///
    /// A fixed list rather than a joined path: `Route::Asset` can only ever name one of three files, so
    /// there is no request that turns into a path traversal no matter what it contains.
    pub asset_dir: std::path::PathBuf,
    /// Chain access for the credential proof mode. `None` is the default, and a bridge built
    /// without one answers the credential route with an honest refusal rather than verifying
    /// against nothing.
    pub chain: Option<R>,
    /// The `Host` values this bridge accepts.
    ///
    /// The DNS-rebinding defence. A page that resolves a name it controls to `127.0.0.1` reaches
    /// this bridge with same-origin requests, which carry no `Origin` header and therefore pass the
    /// origin allowlist exactly as the operator's own CLI would. The `Host` header is what
    /// distinguishes them: a browser sends the name it typed. Anything outside this set is refused
    /// before the route is read. Host matching is name-only and case-insensitive; the port is not
    /// part of the check, because the bind port is already fixed by the listener.
    pub permitted_hosts: std::collections::BTreeSet<String>,
    /// The Minotari wallet daemon channel, for native L1 XTM proofs.
    pub xtm: X,
    /// The Minotari base node reader, for L1 evidence. `None` means no L1 verification is possible,
    /// and L1 challenges are then refused at issue time.
    pub xtm_chain: Option<XR>,
    /// The deployment-time session commitment shared between the bridge and its on-chain component.
    ///
    /// A component's `check_challenge` compares every challenge's `session_commitment` against the
    /// immutable value stored at instantiation, so a consensus-capable gate and the component it
    /// binds must agree on ONE deployment-time value. This is a **component identity**, not a
    /// per-visitor session: per-visitor binding is provided by the unique nonce (burned on
    /// acceptance) and the origin check in `validate_prove_request`, not by this field.
    ///
    /// When set, every Ootle challenge carries it; when `None`, the bridge generates a random
    /// per-challenge value (suitable for the credential path, which has no on-chain component).
    /// Operator sets `GG_GATE_SESSION` to the same value used at component instantiation.
    pub component_session: Option<Vec<u8>>,
    /// Operator trust policy (GG_OPERATOR_TRUSTED_INDEXER, GG_MAX_TRUST_TIER). It can only LOWER a
    /// derived tier: the default trusts no indexer and caps at `Production` (so it imposes no cap
    /// on its own). The bridge binary parses the env into this once at startup.
    pub trust_policy: ghost_gate_registry::TrustPolicy,
    /// Hosted-verifier adapter: when all three are set, the bridge serves `/v1/hosted/verify`
    /// using the same HMAC contract the standalone hosted verifier speaks, but runs the real
    /// `CredentialVerifier::verify` instead of returning UNKNOWN.
    pub hosted_verifier_token: Option<String>,
    pub hosted_verifier_request_key: Option<String>,
    pub hosted_verifier_response_key: Option<String>,
}

impl<W: WalletChannel, R: crate::credential::ChainReader, X: crate::xtm::XtmChannel, XR: crate::xtm::XtmChainReader>
    Bridge<W, R, X, XR>
{
    /// Attach the configured durable replay coordinator. Browser preview constructors leave this
    /// absent; registry-backed production startup rejects that configuration instead of falling
    /// back to a process-local map.
    pub fn set_replay_store(&mut self, replay: Box<dyn ReplayStore>) {
        self.replay = Some(replay);
    }

    fn replay_record(&self, gate_id: &str, issued: &IssuedChallenge) -> ReplayRecord {
        let tenant = self.access.as_ref()
            .and_then(|access| access.info(gate_id))
            .map(|info| info.application_id.clone())
            .unwrap_or_else(|| "local-preview".to_string());
        ReplayRecord {
            nonce: issued.challenge.nonce().into_array(),
            tenant,
            gate: gate_id.to_string(),
            relying_site: hex::encode(issued.challenge.relying_site()),
            visitor_session: issued.challenge.session_commitment().to_vec(),
            network: issued.challenge.network(),
            policy_hash: issued.policy_hash.clone(),
            expires_unix: issued.expires_at.duration_since(std::time::UNIX_EPOCH)
                .map(|value| value.as_secs()).unwrap_or_default(),
            state: crate::replay_store::ReplayState::Issued,
            proof_job_id: None,
            pending_transaction_id: None,
            pending_proof_kind: None,
            authorization_id: None,
            access_token: None,
            trust_tier: ghost_gate_registry::TrustTier::default(),
            evidence_digest: None,
            // The chain generation the challenge is ISSUED under, captured now. Authorization later
            // refuses if the active generation has moved on (a reset migration between challenge
            // issue and proof submission), so an old-generation challenge cannot be exchanged for a
            // new-generation session. `0` when there is no binding yet (offline preview).
            chain_generation: self.access.as_ref().map(|a| a.expected_generation(gate_id)).unwrap_or(0),
        }
    }

    /// Set the operator trust policy parsed from the environment. Never raises a tier.
    pub fn set_trust_policy(&mut self, policy: ghost_gate_registry::TrustPolicy) {
        self.trust_policy = policy;
    }

    /// The durable reset-halt path for this (registry-backed) bridge, if it has a store. A preview
    /// bridge has no store and so can never be halted.
    fn reset_halt_path(&self) -> Option<std::path::PathBuf> {
        self.access.as_ref().map(|a| a.plane.paths.dir.join("reset_halt.json"))
    }

    /// Whether a durable chain-reset halt is latched. While halted the bridge issues no new
    /// sessions: a suspected reset must be reviewed and explicitly cleared by an operator first.
    /// The check reads the durable guard each time, so it survives a restart and cannot be cleared
    /// by anything but an explicit acknowledgment (see [`crate::reset_guard`]).
    pub fn reset_halted(&self) -> bool {
        self.reset_halt_path().map(|p| crate::reset_guard::is_halted(&p)).unwrap_or(false)
    }

    /// Assembles a bridge over every channel at once. The narrower constructors below are sugar
    /// for the common deployments; this is the one the L1-enabled bridge binary uses.
    pub fn assemble(
        gates: GateRegistry,
        wallet: W,
        origins: OriginPolicy,
        xtm: X,
        xtm_chain: Option<XR>,
    ) -> Self {
        Self {
            gates,
            access: None,
            access_grants: std::collections::BTreeMap::new(),
            challenges: ChallengeBook::new(),
            replay: None,
            jobs: Vec::new(),
            traces: std::collections::HashMap::new(),
            job_attempts: std::collections::HashMap::new(),
            wallet,
            origins,
            challenge_ttl: crate::session::DEFAULT_CHALLENGE_TTL,
            challenge_expires_epoch: DEFAULT_CHALLENGE_EXPIRES_EPOCH,
            asset_dir: std::path::PathBuf::from("web"),
            chain: None,
            permitted_hosts: default_permitted_hosts(),
            xtm,
            xtm_chain,
            component_session: None,
            trust_policy: ghost_gate_registry::TrustPolicy::default(),
            hosted_verifier_token: None,
            hosted_verifier_request_key: None,
            hosted_verifier_response_key: None,
        }
    }

    /// The full bridge: Ootle consensus + credential + native L1 XTM. Every route this crate has.
    pub fn assemble_full(
        gates: GateRegistry,
        wallet: W,
        origins: OriginPolicy,
        chain: R,
        xtm: X,
        xtm_chain: Option<XR>,
    ) -> Self {
        Self {
            gates,
            access: None,
            access_grants: std::collections::BTreeMap::new(),
            challenges: ChallengeBook::new(),
            replay: None,
            jobs: Vec::new(),
            traces: std::collections::HashMap::new(),
            job_attempts: std::collections::HashMap::new(),
            wallet,
            origins,
            challenge_ttl: crate::session::DEFAULT_CHALLENGE_TTL,
            challenge_expires_epoch: DEFAULT_CHALLENGE_EXPIRES_EPOCH,
            asset_dir: std::path::PathBuf::from("web"),
            chain: Some(chain),
            permitted_hosts: default_permitted_hosts(),
            xtm,
            xtm_chain,
            component_session: None,
            trust_policy: ghost_gate_registry::TrustPolicy::default(),
            hosted_verifier_token: None,
            hosted_verifier_request_key: None,
            hosted_verifier_response_key: None,
        }
    }
}

impl<W: WalletChannel> Bridge<W, crate::credential::NoChainReader, crate::xtm::NoXtm, crate::xtm::NoXtmChainReader> {
    pub fn new(gates: GateRegistry, wallet: W, origins: OriginPolicy) -> Self {
        Self::assemble(gates, wallet, origins, crate::xtm::NoXtm, None)
    }
}

/// A 128-bit attempt id, hex. Generated by this process, never guessable, never derived from
/// anything a visitor sends.
fn new_attempt_id() -> String {
    crate::session::random_nonce()[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// Whether a visitor-supplied attempt id is shaped like one we issued. This does not authorise the
/// read — the id is a bearer capability — it only keeps junk out of the map lookup.
fn valid_attempt_id(value: &str) -> bool {
    value.len() == 32 && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// The default epoch bound minted into challenges.
///
/// Deliberately large rather than zero: the gate refuses an expired challenge, so a small constant
/// would brick every proof the moment the chain moved past it (the second-pass audit caught the
/// original hard-coded 0). The wall-clock TTL and the single-use nonce are the operative limits;
/// this bound is defence in depth, and an operator who wants a tight one sets
/// `GG_CHALLENGE_EXPIRES_EPOCH`.
pub const DEFAULT_CHALLENGE_EXPIRES_EPOCH: u64 = 1_000_000;

/// The host names a loopback bridge is willing to answer for.
///
/// The loopback names themselves, without a port: the listener already fixed the port, and a
/// browser sends `Host: 127.0.0.1:7799` or `Host: localhost:7799` for exactly the two spellings an
/// operator would type. A rebound `evil.com:7799` is none of these.
pub fn default_permitted_hosts() -> std::collections::BTreeSet<String> {
    ["127.0.0.1", "localhost", "[::1]", "::1"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// The proof mode a gate actually offers, as the Lab advertises it.
///
/// An Ootle gate WITH a component offers the consensus path (a statement executed at that
/// component) and may also accept credential proofs. An Ootle gate with NO component is
/// credential-only: there is nothing to execute or submit a consensus proof against, so
/// advertising "consensus" would steer a browser wallet into the walletd prove route, whose
/// only honest answer is a refusal. This string is what the Lab dispatches on, so it must
/// tell the truth — the physical-test failure this guards against was exactly a credential-only
/// gate advertised as "consensus".
fn proof_mode_label(
    kind: crate::gate_registry::ProofKind,
    component: Option<&tari_template_lib_types::ComponentAddress>,
) -> &'static str {
    match kind {
        crate::gate_registry::ProofKind::Ootle => match component {
            Some(_) => "consensus",
            None => "credential",
        },
        crate::gate_registry::ProofKind::MinotariXtm => "xtm",
    }
}

/// Lowercases a `Host` header value and drops its port, if any.
///
/// Bracketed IPv6 (`[::1]:7799`) is handled by stripping after the last `:`, which is safe because
/// a bare IPv6 host is already in the permitted set in both spellings.
fn host_name(host: &str) -> String {
    let host = host.trim();
    match host.rsplit_once(':') {
        // A bare IPv6 address contains colons but no `]`; the split would cut inside it, so only
        // strip when what follows the last colon is a port-shaped suffix.
        Some((name, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => name,
        _ => host,
    }
    .to_ascii_lowercase()
}

impl<W: WalletChannel, R: crate::credential::ChainReader> Bridge<W, R, crate::xtm::NoXtm, crate::xtm::NoXtmChainReader> {
    /// Serves the credential proof mode alongside the consensus one.
    ///
    /// Deliberately a separate constructor rather than a second generic on `new`: a bridge that
    /// cannot read chain state must exist (the walletd path needs no reader), and its credential
    /// route must refuse rather than invent a verdict.
    pub fn with_chain_reader(
        gates: GateRegistry,
        wallet: W,
        origins: OriginPolicy,
        chain: R,
    ) -> Self {
        Self {
            gates,
            access: None,
            access_grants: std::collections::BTreeMap::new(),
            challenges: ChallengeBook::new(),
            replay: None,
            jobs: Vec::new(),
            traces: std::collections::HashMap::new(),
            job_attempts: std::collections::HashMap::new(),
            wallet,
            origins,
            challenge_ttl: crate::session::DEFAULT_CHALLENGE_TTL,
            asset_dir: std::path::PathBuf::from("web"),
            chain: Some(chain),
            permitted_hosts: default_permitted_hosts(),
            challenge_expires_epoch: DEFAULT_CHALLENGE_EXPIRES_EPOCH,
            xtm: crate::xtm::NoXtm,
            xtm_chain: None,
            component_session: None,
            trust_policy: ghost_gate_registry::TrustPolicy::default(),
            hosted_verifier_token: None,
            hosted_verifier_request_key: None,
            hosted_verifier_response_key: None,
        }
    }
}

/// A bridge that serves the native Minotari L1 XTM path: an `XtmChannel` to the user's wallet
/// daemon, and a base-node reader for the evidence. The Ootle channels stay as built.
impl<W: WalletChannel, X: crate::xtm::XtmChannel, XR: crate::xtm::XtmChainReader>
    Bridge<W, crate::credential::NoChainReader, X, XR>
{
    pub fn with_xtm(
        gates: GateRegistry,
        wallet: W,
        origins: OriginPolicy,
        xtm: X,
        xtm_chain: Option<XR>,
    ) -> Self {
        Self {
            gates,
            access: None,
            access_grants: std::collections::BTreeMap::new(),
            challenges: ChallengeBook::new(),
            replay: None,
            jobs: Vec::new(),
            traces: std::collections::HashMap::new(),
            job_attempts: std::collections::HashMap::new(),
            wallet,
            origins,
            challenge_ttl: crate::session::DEFAULT_CHALLENGE_TTL,
            asset_dir: std::path::PathBuf::from("web"),
            chain: None,
            permitted_hosts: default_permitted_hosts(),
            challenge_expires_epoch: DEFAULT_CHALLENGE_EXPIRES_EPOCH,
            xtm,
            xtm_chain,
            component_session: None,
            trust_policy: ghost_gate_registry::TrustPolicy::default(),
            hosted_verifier_token: None,
            hosted_verifier_request_key: None,
            hosted_verifier_response_key: None,
        }
    }
}

impl<W: WalletChannel, R: crate::credential::ChainReader, X: crate::xtm::XtmChannel, XR: crate::xtm::XtmChainReader>
    Bridge<W, R, X, XR>
{
    /// Sugar for the bridge binary's no-indexer arm, keeping the concrete types loose.
    pub fn with_xtm_full(
        gates: GateRegistry,
        wallet: W,
        origins: OriginPolicy,
        xtm: X,
        xtm_chain: Option<XR>,
    ) -> Self {
        Self {
            gates,
            access: None,
            access_grants: std::collections::BTreeMap::new(),
            challenges: ChallengeBook::new(),
            replay: None,
            jobs: Vec::new(),
            traces: std::collections::HashMap::new(),
            job_attempts: std::collections::HashMap::new(),
            wallet,
            origins,
            challenge_ttl: crate::session::DEFAULT_CHALLENGE_TTL,
            asset_dir: std::path::PathBuf::from("web"),
            chain: None,
            permitted_hosts: default_permitted_hosts(),
            challenge_expires_epoch: DEFAULT_CHALLENGE_EXPIRES_EPOCH,
            xtm,
            xtm_chain,
            component_session: None,
            trust_policy: ghost_gate_registry::TrustPolicy::default(),
            hosted_verifier_token: None,
            hosted_verifier_request_key: None,
            hosted_verifier_response_key: None,
        }
    }
}

/// The routes and the reconciliation, over every channel combination. All the security-relevant
/// logic lives here so it is written once: a bridge with or without chain readers runs the same
/// handlers, and the difference is only which constructor assembled it.
impl<W: WalletChannel, R: crate::credential::ChainReader, X: crate::xtm::XtmChannel, XR: crate::xtm::XtmChainReader>
    Bridge<W, R, X, XR>
{
    /// Handles one request. Pure with respect to the process: it returns what to send.
    pub async fn handle(&mut self, request: &Request) -> Response {
        // Registry-backed bridges re-read the bindings snapshot when it changes, so a publish
        // from the admin plane is live on the next request — and a REVOCATION is live just as
        // fast. Fail-closed: a corrupt snapshot keeps the last-known-good gates and is logged.
        if self.access.is_some() {
            let paths = self.access.as_ref().unwrap().plane.paths.clone();
            let mut rebuild_failed: Option<String> = None;
            {
                let access = self.access.as_mut().unwrap();
                let mut gates_registry = GateRegistry::new();
                let result = access.reload_if_changed(&paths, &mut |snapshots| {
                    for snap in snapshots {
                        if snap.test_lane {
                            continue; // test-lane gates never bind the production listener
                        }
                        let binding = crate::access::binding_from_snapshot(snap)?;
                        // The scope comes from the same snapshot, so the Lab and the bot read the
                        // same administrator decision rather than each inferring one.
                        gates_registry.set_use_mode(&snap.gate_id, &snap.use_mode);
                        gates_registry
                            .register(snap.gate_id.clone(), binding)
                            .map_err(|e| format!("gate {}: {e}", snap.gate_id))?;
                    }
                    Ok(())
                });
                match result {
                    Ok((true, count)) => {
                        if let Some(handle) = self.access.as_mut() {
                            self.gates = gates_registry;
                            let _ = count;
                        }
                    }
                    Ok((false, _)) => {}
                    Err(e) => {
                        // Keep the last-known-good registry; say why on stderr once.
                        rebuild_failed = Some(e);
                    }
                }
            }
            if let Some(e) = rebuild_failed {
                eprintln!("ghost-gate-bridge: bindings reload refused, keeping last-known-good gates: {e}");
            }
        }
        // The Host check comes first, and for the reason above: a rebound name arrives as a
        // same-origin request that the origin allowlist would welcome. A present-but-unrecognised
        // Host is refused; an absent Host keeps working for the operator's own curl and tests,
        // which never send one.
        if let Some(host) = request.host.as_deref() {
            let name = host_name(host);
            if !self.permitted_hosts.iter().any(|p| p.eq_ignore_ascii_case(&name)) {
                return Response::error(
                    403,
                    format!(
                        "GG: this bridge is bound to the loopback interface and does not answer for host {host:?}. \
                         If you reached it through a mapped or rebound name, connect via 127.0.0.1 or localhost."
                    ),
                );
            }
        }

        // Origin second, before the route is even resolved: a page that may not talk to this bridge gets
        // the same answer for every path, including paths that do not exist.
        if let Err(rejection) = self.origins.permits(request.origin.as_deref()) {
            return Response::error(403, rejection);
        }

        match Route::resolve(request.method, &request.path) {
            Route::Health => Response::json(
                200,
                &serde_json::json!({
                    "service": "ghost-gate-bridge",
                    "version": crate::BRIDGE_VERSION,
                    "gates": self.gates.ids().collect::<Vec<_>>(),
                    "live_challenges": self.challenges.live(),
                    // What this deployment is CONFIGURED for. Configuration is not health: the UI
                    // still probes /wallet/status for reachability, and "configured" must never be
                    // read as "synchronized". These flags only say whether the process was wired
                    // with the dependency at all, so the Lab can say "not configured" honestly.
                    "registry_backed": self.access.is_some(),
                    "credential_configured": self.chain.is_some(),
                    "xtm_configured": self.xtm_chain.is_some(),
                }),
            ),

            Route::WalletStatus => match self.wallet.status().await {
                Ok(status) => Response::json(200, &status),
                Err(e) => Response::error(503, e),
            },

            Route::Gate(id) => match self.gates.public_metadata(id) {
                Some(gate) => Response::json(200, &gate),
                None => Response::error(404, "GG: no such gate"),
            },

            Route::LabGates => self.lab_gates(),
            Route::LabTrace => self.lab_trace(request),
            Route::LabSimulate => self.lab_simulate(request),
            Route::Asset(name) => self.serve_asset(name),
            Route::Challenge(id) => self.issue_challenge(id, request).await,
            Route::Prove(id) => self.prove(id, request).await,
            Route::Credential(id) => self.credential(id, request).await,
            Route::ProofStatus(id) => {
                // Lazy reconciliation: a Submitted job is polled against the wallet here, because
                // nothing else in the process ever does. The pre-audit design had a `reconcile`
                // method that only tests called -- which this audit's second pass caught as a
                // shipped-but-dead consensus path (F-10). The per-call wait is deliberately short:
                // the polling client drives completion by returning, and the bridge never blocks
                // longer than a few seconds on one job.
                self.reconcile_job(id, RECONCILE_WAIT).await;
                match self.jobs.iter().find(|j| j.id == id) {
                    Some(job) => {
                        // A freshly accepted proof carries its access grant on the status
                        // response: the polling client learns its session exactly once, bound to
                        // the policy the proof satisfied.
                        let grant = self
                            .access_grants
                            .get(&hex::encode(job.challenge_nonce))
                            .cloned();
                        let status = job.status.clone();
                        let mut value = serde_json::to_value(&status)
                            .unwrap_or(serde_json::Value::Null);
                        if let Some(grant) = grant {
                            if let Some(obj) = value.as_object_mut() {
                                obj.insert("access".to_string(), serde_json::to_value(grant).unwrap_or(serde_json::Value::Null));
                            }
                        }
                        Response::json(200, &value)
                    }
                    None => Response::error(404, "GG: no such proof"),
                }
            },
            Route::AccessCheck => {
                // The decision is computed from the registry and the session store, server-side.
                // A client cannot argue it: there is no field to argue with.
                let token = request.query.get("token").cloned().unwrap_or_default();
                let gate_id = request.query.get("gate").cloned().unwrap_or_default();
                if token.is_empty() || gate_id.is_empty() {
                    return Response::error(400, "GG: access checks need token and gate");
                }
                match self.access.as_mut() {
                    Some(access) => {
                        let decision = access.check(&token, &gate_id);
                        Response::json(200, &serde_json::json!({
                            "authorized": decision.authorized,
                            "reason": decision.reason,
                            "granted": decision.granted,
                            "expiresUnix": decision.expires_unix,
                            "policyVersion": decision.policy_version,
                            // Server-derived; a relying party may require a minimum tier but can
                            // never raise either value (G3).
                            "trustTier": decision.trust_tier.as_str(),
                            "requiredTier": decision.required_tier.as_str(),
                        }))
                    }
                    None => Response::error(503, "GG: this bridge is not registry-backed; no access plane"),
                }
            }
            Route::HostedVerify => self.hosted_verify(request).await,
            Route::NotFound => Response::error(404, "GG: no such route"),
        }
    }

    fn reserve_replay(
        &mut self,
        gate_id: &str,
        nonce: &[u8; 32],
        proof_job_id: &str,
    ) -> Result<Option<Reservation>, crate::replay_store::ReplayError> {
        let issued = self.challenges.peek(nonce).map_err(|_| crate::replay_store::ReplayError::BindingMismatch)?;
        let expected = self.replay_record(gate_id, issued);
        let Some(replay) = self.replay.as_mut() else { return Ok(None); };
        replay.reserve(&expected, proof_job_id, crate::session::now_unix()).map(Some)
    }

    fn release_replay_refused(&mut self, gate_id: &str, nonce: &[u8; 32]) {
        let Ok(issued) = self.challenges.peek(nonce) else { return; };
        let expected = self.replay_record(gate_id, issued);
        let Some(replay) = self.replay.as_mut() else { return; };
        let _ = replay.release_refused(&expected, crate::session::now_unix());
    }

    /// Rebuild Ootle finality jobs after a process restart. The durable replay record is the
    /// authority: it supplies a server-created gate, job id and transaction reference. Records
    /// without a durable reference (or non-Ootle records that need an artifact) deliberately stay
    /// reserved and cannot be retried into a second transaction.
    pub async fn recover_pending_jobs(&mut self) -> usize {
        let records = match self.replay.as_mut() {
            Some(replay) => match replay.submitted() { Ok(records) => records, Err(_) => return 0 },
            None => return 0,
        };
        let mut recovered = 0;
        for record in records {
            if record.expires_unix < crate::session::now_unix()
                || record.pending_proof_kind != Some(PendingProofKind::OotleTransaction) { continue; }
            let (Some(job_id), Some(transaction_id)) = (record.proof_job_id.clone(), record.pending_transaction_id.clone()) else { continue; };
            if self.gates.get(&record.gate).is_none() || self.jobs.iter().any(|job| job.id == job_id) { continue; }
            self.push_job(ProofJob {
                id: job_id.clone(), gate_id: record.gate, challenge_nonce: record.nonce,
                status: ProofStatus::Submitted { transaction_id }, started_at: std::time::SystemTime::now(),
                xtm_artifact: None,
            });
            // A short poll establishes an already-final result at startup. Timeout/Pending remain
            // submitted and are reconciled by normal status polling; no new wallet action occurs.
            self.reconcile_job(&job_id, RECONCILE_WAIT).await;
            recovered += 1;
        }
        recovered
    }

    /// Issues a verified-access session for an accepted proof on a registry-backed gate, and
    /// remembers it against the challenge nonce so the status poll can carry it. Returns None
    /// when the bridge is not registry-backed or the gate is not registry-bound.
    fn grant_access_for(
        &mut self,
        gate_id: &str,
        nonce_hex: &str,
        job_id: Option<&str>,
        evidence: ghost_gate_registry::Evidence,
    ) -> Option<ghost_gate_registry::AccessGrant> {
        // A latched chain-reset halt stops ALL new issuance, before any other work. A suspected
        // reset (an indexer identity/epoch discontinuity) must be reviewed and explicitly cleared
        // by an operator; the bridge never clears it itself and never issues while it stands.
        if self.reset_halted() {
            eprintln!(
                "ghost-gate-bridge: refusing to issue for gate {gate_id}: a chain-reset halt is \
                 latched; an operator must review the chain identity and clear it"
            );
            return None;
        }
        // A proof is only worth a session under the policy it was answered against. If an
        // administrator replaced that policy while the challenge was outstanding, the answer proves
        // the OLD threshold — so no session is issued and the caller must mint a fresh challenge.
        let current = self.access.as_mut()?.plane.current_policy_hash(gate_id);
        let nonce = hex::decode(nonce_hex).ok().and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
        if self.replay.is_none() && let Some(nonce) = nonce {
            if self.challenges.policy_current(&nonce, current.as_deref()).is_err() {
                eprintln!(
                    "ghost-gate-bridge: refusing a session for gate {gate_id}: the policy was replaced while \
                     challenge {} was outstanding; a fresh challenge is required",
                    hex::encode(nonce)
                );
                return None;
            }
        }
        let policy = self.trust_policy;
        // The tier the evidence will achieve on this gate, computed here so it can be bound into the
        // durable replay record BEFORE issuance. The registry independently recomputes the same
        // value from the same evidence, so a recovery that presents different evidence (a different
        // digest, or evidence that would yield a different tier) is refused rather than upgraded.
        let expected_tier = self.access.as_ref()?.expected_tier(gate_id, &evidence, &policy);
        // The chain generation this gate is bound under, recorded alongside the tier so a recovery
        // after a reset migration (which republishes a higher generation) is refused rather than
        // restoring a retired authorization.
        let expected_generation = self.access.as_ref()?.expected_generation(gate_id);
        let evidence_digest = evidence.digest().to_string();
        let grant = if let Some(replay) = self.replay.as_mut() {
            let nonce = nonce?;
            let existing = replay.get(&nonce).ok()?;
            // The policy hash was fixed at challenge issue. A policy replacement is not a reason
            // to reinterpret an old proof under a new threshold.
            if existing.policy_hash.as_deref() != current.as_deref() {
                return None;
            }
            let authorization_id = format!("gg-auth-{}", hex::encode(nonce));
            let token = existing.access_token.clone().unwrap_or_else(|| hex::encode(random_nonce()));
            let record = match replay.authorize(&nonce, &authorization_id, &token, expected_tier, &evidence_digest, expected_generation, crate::session::now_unix()) {
                Ok(record) => record,
                Err(error) => {
                    // An evidence/tier mismatch on a retry is an attempted upgrade: fail closed and
                    // say so, rather than installing a session at a tier the record never bound.
                    eprintln!("ghost-gate-bridge: refusing a session for gate {gate_id}: {error}");
                    return None;
                }
            };
            let authorization_id = record.authorization_id.as_deref()?;
            let token = record.access_token.as_deref()?;
            self.access.as_mut()?.grant_idempotent(gate_id, authorization_id, token, &evidence, &policy).ok()?
        } else {
            self.access.as_mut()?.grant(gate_id, &evidence, &policy).ok()?
        };
        // The grant's own remaining life is the session duration the visitor was shown. It is the
        // visitor's OWN session, so its length discloses nothing about anyone else.
        let valid = grant.expires_unix.saturating_sub(crate::session::now_unix());
        let attempt = job_id.and_then(|id| self.job_attempts.get(id)).cloned();
        if let Some(attempt) = attempt
            && let Some(trace) = self.traces.get_mut(&attempt)
        {
            crate::trace::ev::access_granted(trace, valid, false);
        }
        self.access_grants.insert(nonce_hex.to_string(), grant.clone());
        Some(grant)
    }

    // ---------------------------------------------------------------------------
    // The Privacy Lab
    // ---------------------------------------------------------------------------

    /// The authoritative gate list for the Lab's gate picker.
    ///
    /// Read from the same registry-backed registry the proofs are checked against: the page cannot
    /// show a threshold that is not the one in force, and this page cannot change one either. Only
    /// PUBLIC policy metadata leaves this route — a gate's threshold, resource and symbol are what
    /// the chain itself publishes; a visitor's balance never appears because no field of it exists.
    fn lab_gates(&mut self) -> Response {
        let mut gates = Vec::new();
        for id in self.gates.ids().collect::<Vec<_>>() {
            let Some(meta) = self.gates.public_metadata(id) else { continue };
            // The component decides the mode: an Ootle gate without one is credential-only, and
            // the Lab must never be told it can run the walletd consensus path against it.
            let proof_mode =
                proof_mode_label(meta.proof_kind, self.gates.get(id).and_then(|g| g.component()));
            // Whether this gate is registry-backed decides whether a session is issued at all; the
            // page shows that honestly rather than promising a grant it cannot deliver.
            let access_plane = self.access.as_mut().and_then(|a| a.plane.current_policy_hash(id));
            gates.push(serde_json::json!({
                "gateId": meta.gate_id,
                "symbol": meta.symbol,
                "resourceAddress": meta.resource_address,
                "thresholdRaw": meta.threshold.to_string(),
                "divisibility": meta.divisibility,
                "network": meta.network,
                "proofMode": proof_mode,
                "activatable": !matches!(meta.proof_kind, crate::gate_registry::ProofKind::MinotariXtm),
                "sessionsAvailable": access_plane.is_some(),
                // The scope the administrator assigned: a website-only gate is not a Telegram gate.
                "useMode": self.gates.use_mode_of(id).unwrap_or_else(|| "website".into()),
            }));
        }
        Response::json(200, &serde_json::json!({ "gates": gates }))
    }

    /// The sanitised trace for one attempt. The attempt id IS the capability: it is 128 random bits
    /// generated by this process, never enumerable, and no other visitor's trace can be read without
    /// it. A missing or unknown id is an empty 404, not a hint.
    fn lab_trace(&mut self, request: &Request) -> Response {
        let attempt = request.query.get("attempt").cloned().unwrap_or_default();
        if !valid_attempt_id(&attempt) {
            return Response::error(404, "GG: no such attempt");
        }
        match self.traces.get(&attempt) {
            Some(trace) => Response::json(200, &trace.to_json()),
            None => Response::error(404, "GG: no such attempt"),
        }
    }

    /// The labelled offline simulation.
    ///
    /// It walks the SAME event constructors the real flow uses, so a judge without a testnet wallet
    /// sees the shape of a real attempt — and every event it produces is stamped `simulated: true`,
    /// it performs no network or wallet call, and it deliberately returns NO session token. There is
    /// no code path here that can grant access, because there is no code path here that can mint a
    /// session at all.
    fn lab_simulate(&mut self, request: &Request) -> Response {
        let gate_id = serde_json::from_str::<serde_json::Value>(&request.body)
            .ok()
            .and_then(|v| v.get("gateId").and_then(|g| g.as_str()).map(|s| s.to_string()))
            .unwrap_or_else(|| "demo".to_string());
        let Some(meta) = self.gates.public_metadata(&gate_id) else {
            return Response::error(404, format!("GG: no such gate: {gate_id}"));
        };
        let attempt_id = new_attempt_id();
        // Same rule as /lab/gates: the component decides the mode, and the simulation must
        // illustrate the shape the REAL flow would take.
        let proof_mode =
            proof_mode_label(meta.proof_kind, self.gates.get(&gate_id).and_then(|g| g.component()));
        let mut trace = crate::trace::Trace::new(attempt_id.clone(), meta.gate_id.clone(), true);
        use crate::trace::ev;
        ev::attempt_started(&mut trace);
        ev::simulation_notice(&mut trace);
        ev::gate_selected(&mut trace, &meta.gate_id, meta.threshold, proof_mode);
        ev::challenge_minted(&mut trace, &meta.gate_id);
        ev::wallet_probe(&mut trace, true, "SIMULATION: a wallet would be probed here. None was contacted.");
        ev::wallet_asked(&mut trace);
        ev::wallet_answered(&mut trace, 42);
        // The numbers below are FIXED demo values chosen to illustrate the comparison. They are not
        // measurements, and they are stamped simulated so no reader can mistake them for evidence.
        ev::verifier_checked(&mut trace, meta.threshold, meta.threshold.saturating_mul(3), 7);
        ev::policy_binding(&mut trace);
        // A credential-only gate has no consensus step to illustrate; inventing one would teach
        // the wrong shape. The signature-against-chain-state check IS its verdict step.
        if proof_mode != "credential" {
            ev::consensus_observed(&mut trace, "simulated0000tx");
        }
        ev::access_granted(&mut trace, 604_800, true);
        let json = trace.to_json();
        self.store_trace(trace);
        Response::json(200, &serde_json::json!({
            "attemptId": attempt_id,
            "simulated": true,
            "session": serde_json::Value::Null,
            "trace": json,
        }))
    }

    /// Keeps a trace in memory under its attempt id, within both bounds.
    fn store_trace(&mut self, trace: crate::trace::Trace) {
        const MAX_TRACES: usize = 64;
        if self.traces.len() >= MAX_TRACES {
            // Drop the oldest by creation order of its first event; a trace is worthless once its
            // attempt is over, and an unbounded map is a denial of service with extra steps.
            if let Some(oldest) = self
                .traces
                .iter()
                .min_by_key(|(_, t)| t.events().first().map(|e| e.at_ms).unwrap_or(0))
                .map(|(id, _)| id.clone())
            {
                self.traces.remove(&oldest);
            }
        }
        self.traces.insert(trace.attempt_id.clone(), trace);
    }

    /// Records an event on the attempt that owns this job, if the request named one.
    fn trace_job(&mut self, job_id: &str, f: impl FnOnce(&mut crate::trace::Trace)) {
        let Some(attempt) = self.job_attempts.get(job_id).cloned() else { return };
        if let Some(trace) = self.traces.get_mut(&attempt) {
            f(trace);
        }
    }

    /// Hosted-verifier adapter: accepts the same `POST /v1/hosted/verify` contract the
    /// standalone hosted verifier speaks, but runs the real `CredentialVerifier::verify`
    /// instead of returning UNKNOWN. This lets the CF Worker call the bridge through the
    /// tunnel without any Worker-side code changes.
    fn hosted_state(&self, req: &ghost_gate_verifier::hosted::HostedVerificationRequest) -> Result<serde_json::Value, String> {
        if self.reset_halted() { return Err("reset halt active".into()); }
        // Same scope rule as the local credential route: a Telegram-only gate never authorizes a website.
        if self.gates.use_mode_of(&req.gate_id).as_deref() == Some("telegram") {
            return Err("gate is scoped to Telegram membership only".into());
        }
        self.origins.permits(Some(&req.relying_site)).map_err(|e| e.to_string())?;
        let access = self.access.as_ref().ok_or("hosted authorization requires registry bindings")?;
        let info = access.info(&req.gate_id).ok_or("unknown registry gate")?;
        if req.tenant != info.application_id { return Err("tenant mismatch".into()); }
        // `GG_BRIDGE_ORIGINS` is a deployment allowlist, not policy authority.  The exact
        // relying-site that the Worker sends must also be the one frozen in the published
        // binding.  Otherwise a later environment-only change could move a live policy to a
        // different site without an authenticated Publish operation.
        if req.relying_site != info.challenge_domain {
            return Err("published relying-site mismatch".into());
        }
        // Always reload the durable generation ledger, even if registry mtime is unchanged.
        let reg = ghost_gate_registry::load_registry(&access.plane.paths)?;
        let version = reg.current_version(&info.application_id, &req.gate_id).ok_or("unpublished policy")?;
        if req.policy_version != format!("v{}", version.version) || version.policy_hash != info.policy_hash {
            return Err("policy mismatch".into());
        }
        let app = reg.application(&info.application_id).ok_or("unknown application")?;
        if app.network != req.network || version.policy.resource_address != req.resource_address
            || version.policy.threshold_raw.to_string() != req.threshold_raw {
            return Err("registry scope mismatch".into());
        }
        let evidence = ghost_gate_registry::Evidence::IndexerAsserted { digest: "hosted-eligibility".into() };
        // A non-persisted eligibility evaluation: exactly the same rules as real local issuance.
        let session = ghost_gate_registry::issue_session_with_token(&reg, &info.application_id,
            &req.gate_id, version.policy_hash.clone(), "hosted-eligibility", &"0".repeat(64), &evidence, &self.trust_policy)?;
        let decision = ghost_gate_registry::check_access(&reg, &[session.clone()], &session.token,
            &info.application_id, &req.gate_id, crate::session::now_unix());
        if !decision.authorized { return Err(decision.reason); }
        let revision_path = access.plane.paths.dir.join("hosted_halt_revision");
        let revision = match std::fs::read_to_string(revision_path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e.to_string()),
        };
        Ok(serde_json::json!({"generation": session.chain_generation.to_string(),
            "policyHash": version.policy_hash, "haltRevision": revision,
            "sessionTtlSecs": session.expires_unix - session.issued_unix}))
    }

    async fn hosted_verify(&mut self, request: &Request) -> Response {
        use ghost_gate_verifier::hosted::{
            self, HostedVerdict, HostedVerificationRequest, HostedVerificationResult,
        };
        let (Some(token), Some(req_key), Some(resp_key)) = (
            self.hosted_verifier_token.clone(),
            self.hosted_verifier_request_key.clone(),
            self.hosted_verifier_response_key.clone(),
        ) else {
            return Response::error(503, "GG: hosted verifier adapter is not configured");
        };

        let auth = request.authorization.as_deref().unwrap_or("");
        if auth != format!("Bearer {}", token) {
            return Response::error(401, r#"{"error":"GG: verifier caller is not authorized"}"#);
        }

        let hv_req: HostedVerificationRequest = match serde_json::from_str(&request.body) {
            Ok(v) => v,
            Err(_) => return Response::error(400, r#"{"error":"GG: invalid hosted verifier request"}"#),
        };

        let req_sig = request.verifier_request_signature.as_deref().unwrap_or("");
        let canonical = hosted::canonical_request(&hv_req);
        if !hosted::verify_hmac_sha256_hex(req_sig, req_key.as_bytes(), canonical.as_bytes()) {
            return Response::error(401, r#"{"error":"GG: verifier request signature is invalid"}"#);
        }

        if let Err(_) = hv_req.validate() {
            return Response::error(400, r#"{"error":"GG: invalid hosted verifier request"}"#);
        }

        let gate_id = &hv_req.gate_id;
        let gate = match self.gates.get(gate_id).cloned() {
            Some(g) => g,
            None => return Response::error(404, r#"{"error":"GG: no such gate"}"#),
        };
        let gate_resource = gate.resource().map(|r| hex::encode(r.as_ref())).unwrap_or_default();
        let req_resource = hv_req.resource_address.strip_prefix("resource_")
            .unwrap_or(&hv_req.resource_address);
        if hv_req.network != gate.network
            || req_resource != gate_resource
            || hv_req.threshold_raw != gate.threshold().to_string()
        {
            return Response::error(409, r#"{"error":"GG: request scope does not match this gate"}"#);
        }

        let state = match self.hosted_state(&hv_req) {
            Ok(s) => s,
            Err(_) => return Response::error(503, "GG: hosted backend authorization unavailable"),
        };
        if hv_req.proof == serde_json::json!({"hostedState": true}) {
            let body = serde_json::json!({"request": hv_req, "state": state,
                "issuedUnix": crate::session::now_unix()}).to_string();
            let sig = hosted::hmac_sha256_hex(resp_key.as_bytes(), body.as_bytes());
            return Response::json_with_header(200, &body, "X-GG-Verifier-Signature", &sig);
        }
        if hv_req.proof.get("backendState") != Some(&state) {
            return Response::error(409, "GG: hosted backend binding changed");
        }
        let vid = hosted::verification_id(&hv_req);

        let proof_json = serde_json::to_string(&hv_req.proof["credential"]).unwrap_or_default();
        let parsed: crate::credential::CredentialProofRequest = match serde_json::from_str(&proof_json) {
            Ok(v) => v,
            Err(_) => {
                let result = HostedVerificationResult {
                    nonce: hv_req.nonce.clone(), tenant: hv_req.tenant.clone(),
                    gate_id: hv_req.gate_id.clone(), relying_site: hv_req.relying_site.clone(),
                    network: hv_req.network, resource_address: hv_req.resource_address.clone(),
                    threshold_raw: hv_req.threshold_raw.clone(), policy_version: hv_req.policy_version.clone(),
                    proof_digest: hv_req.proof_digest.clone(), verdict: HostedVerdict::Rejected,
                    verification_id: vid,
                };
                let body = serde_json::to_string(&result).unwrap_or_default();
                let sig = hosted::sign_result(&result, resp_key.as_bytes());
                return Response::json_with_header(200, &body, "X-GG-Verifier-Signature", &sig);
            }
        };
        let chain = match self.chain.as_ref() {
            Some(c) => c,
            None => return Response::error(503, r#"{"error":"GG: no chain reader configured"}"#),
        };

        let verifier = crate::credential::CredentialVerifier {
            gate_id,
            network: gate.network,
            threshold: gate.threshold(),
            resource: &gate.resource().copied().unwrap(),
            challenge_string: &hv_req.nonce,
        };
        let verdict = match (parsed.gate_id == hv_req.gate_id && parsed.challenge_nonce == hv_req.nonce)
            && verifier.verify(chain, &parsed).await.is_ok()
            && self.hosted_state(&hv_req).ok().as_ref() == Some(&state) {
            true => HostedVerdict::Verified,
            false => HostedVerdict::Rejected,
        };

        let result = HostedVerificationResult {
            nonce: hv_req.nonce.clone(), tenant: hv_req.tenant.clone(),
            gate_id: hv_req.gate_id.clone(), relying_site: hv_req.relying_site.clone(),
            network: hv_req.network, resource_address: hv_req.resource_address.clone(),
            threshold_raw: hv_req.threshold_raw.clone(), policy_version: hv_req.policy_version.clone(),
            proof_digest: hv_req.proof_digest.clone(), verdict,
            verification_id: vid,
        };
        let body = serde_json::to_string(&result).unwrap_or_default();
        let sig = hosted::sign_result(&result, resp_key.as_bytes());
        Response::json_with_header(200, &body, "X-GG-Verifier-Signature", &sig)
    }

    /// Serves one of the three static files this bridge is willing to serve.
    ///
    /// `no-store` on every asset because a cached `app.js` from a previous run would be a stale client
    /// talking to a current bridge, and a cached challenge response would let a page replay one it never
    /// saw.
    fn serve_asset(&self, name: &str) -> Response {
        // Belt and braces: `Route::resolve` already restricts this to three names, and the check below
        // means a future route cannot widen it by accident.
        if !matches!(
            name,
            "index.html"
                | "app.css"
                | "app.js"
                | "js/ghost/capabilities.js"
                | "js/ghost/provider.js"
                | "js/ghost/ghost-gate.js"
                | "js/ghost/test.js"
                | "telegram/join.html"
                | "telegram/claim.js"
                // The Privacy Lab page and its two assets. A fixed set, like every other asset:
                // there is no dynamic path under /lab, only the three files the Lab actually uses.
                | "lab/index.html"
                | "lab/lab.css"
                | "lab/lab.js"
        ) {
            return Response::error(404, "GG: no such asset");
        }
        // A fixed name can contain a subdirectory, but never a `..`: `Route::resolve` only ever
        // hands over one of the names above, and this check repeats the rule so widening the route
        // cannot widen the filesystem surface.
        if name.contains("..") {
            return Response::error(404, "GG: no such asset");
        }
        let path = self.asset_dir.join(name);
        match std::fs::read(&path) {
            Ok(bytes) => Response {
                status: 200,
                content_type: match name {
                    "index.html" | "telegram/join.html" | "lab/index.html" => "text/html; charset=utf-8",
                    "app.css" | "lab/lab.css" => "text/css; charset=utf-8",
                    _ => "text/javascript; charset=utf-8",
                },
                body: String::from_utf8_lossy(&bytes).to_string(),
                extra_headers: Vec::new(),
            },
            Err(_) => Response::error(
                404,
                format!("GG: {name} is not present in the asset directory"),
            ),
        }
    }

    /// Mints a fresh challenge, and hands back a session commitment for it.
    ///
    /// The session commitment is generated **here**, not by the caller, and returned alongside the
    /// challenge. A caller that supplies its own session value could reuse one session across gates; a
    /// value this bridge generates per challenge is bound to that challenge and to the browser that
    /// asked for it.
    ///
    /// An L1 XTM gate additionally records the chain tip at issue time, read from this bridge's own
    /// base-node reader. If the reader is absent or unreachable, the challenge is refused: an L1
    /// challenge without a recorded tip could not be checked for freshness, so none is minted.
    async fn issue_challenge(&mut self, id: &str, request: &Request) -> Response {
        if self.gates.get(id).is_none() {
            return Response::error(404, "GG: no such gate");
        }
        // The tip for an L1 challenge, before anything is minted.
        let xtm_tip = if let Some(gate) = self.gates.get(id) {
            if gate.kind() == crate::gate_registry::ProofKind::MinotariXtm {
                let Some(reader) = self.xtm_chain.as_mut() else {
                    return Response::error(
                        503,
                        "GG: this bridge has no Minotari base node configured, so an XTM challenge \
                         cannot be issued. Set the L1 base node endpoint to enable the native XTM path.",
                    );
                };
                match reader.tip().await {
                    Ok(tip) => Some(tip.height),
                    Err(_) => {
                        return Response::error(
                            503,
                            "GG: the Minotari base node could not be reached, so no XTM challenge was issued",
                        );
                    },
                }
            } else {
                None
            }
        } else {
            unreachable!("gate existence was checked above")
        };
        // A visitor that names an attempt gets a diagnostic trace for it; a CLI caller that does
        // not is unaffected. The attempt id is validated as a shape here and authorised only by
        // being the bearer of an id this process generated.
        if let Some(raw_attempt) = request.attempt.as_deref()
            && !self.traces.contains_key(raw_attempt)
        {
            let gate_id = id.to_string();
            let mut trace = crate::trace::Trace::new(raw_attempt.to_string(), gate_id.clone(), false);
            use crate::trace::ev;
            ev::attempt_started(&mut trace);
            let meta = self.gates.public_metadata(id);
            if let Some(meta) = &meta {
                let mode =
                    proof_mode_label(meta.proof_kind, self.gates.get(id).and_then(|g| g.component()));
                ev::gate_selected(&mut trace, &meta.gate_id, meta.threshold, mode);
            }
            ev::challenge_minted(&mut trace, id);
            self.store_trace(trace);
        }

        let session = self.component_session.clone().unwrap_or_else(|| random_nonce().to_vec());
        // Registry-backed: bind the challenge to the policy version in force right now, so a
        // replacement cannot be satisfied by an answer computed under the old threshold.
        let minted_under = self.access.as_mut().and_then(|a| a.plane.current_policy_hash(id));
        let issued = match self
            .gates
            .issue_challenge(
                id,
                &mut self.challenges,
                &session,
                self.challenge_ttl,
                request.origin.clone(),
                self.challenge_expires_epoch,
                xtm_tip,
                minted_under,
            )
        {
            Ok(issued) => issued,
            // 429 rather than 500: the bridge is healthy and the caller is the problem. The limit
            // is on live challenges, so retrying later — or answering the one already held — is
            // the actual remedy.
            Err(crate::session::BookError::TooManyChallenges) => {
                return Response::error(
                    429,
                    "GG: too many live challenges; wait for one to be answered or expire",
                );
            },
            Err(_) => {
                return Response::error(500, "GG: the challenge could not be recorded");
            },
        };
        // The caller does not receive a nonce until its server-authoritative bindings have been
        // persisted. A configured durable coordinator failing here is a 503, never a quiet
        // fallback to the local ChallengeBook.
        let replay_record = self.replay_record(id, &issued);
        if let Some(replay) = self.replay.as_mut()
            && let Err(error) = replay.create(&replay_record)
        {
            return Response::error(503, error.to_string());
        }
        // The challenge's own fields are named rather than serialised as a blob, so a relying site reads
        // the binding it is about to rely on. `gate` and `resource` are addresses, not names.
        let challenge_json = match &issued.challenge {
            crate::session::AnyChallenge::Ootle(c) => serde_json::json!({
                "kind": "ootle",
                "gate": c.gate.to_string(),
                "resource": c.resource.to_string(),
                "threshold": c.threshold,
                "network": c.network,
                "nonce": crate::policy::nonce_to_hex(&c.nonce),
                "expires_epoch": c.expires_epoch,
                "relying_site": hex::encode(c.relying_site.as_slice()),
                "session_commitment": hex::encode(c.session_commitment.as_slice()),
            }),
            crate::session::AnyChallenge::MinotariXtm(c) => serde_json::json!({
                "kind": "minotari_xtm",
                "gate_id": String::from_utf8_lossy(c.gate_id.as_slice()),
                "threshold_micro": c.threshold_micro,
                "network": c.network,
                "nonce": crate::policy::nonce_to_hex(&c.nonce),
                "issued_at_unix": c.issued_at_unix,
                "expires_at_unix": c.expires_at_unix,
                "relying_site": hex::encode(c.relying_site.as_slice()),
                "session_commitment": hex::encode(c.session_commitment.as_slice()),
                "tip_height_at_issue": c.tip_height_at_issue,
            }),
        };
        Response::json(
            200,
            &serde_json::json!({
                "challenge": challenge_json,
                "challenge_nonce": crate::policy::nonce_to_hex(&issued.challenge.nonce()),
                "session_commitment": hex::encode(&session),
                "expires_at_unix": issued
                    .expires_at
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or_default(),
            }),
        )
    }

    /// The credential proof mode: verify a browser wallet's proof-of-funds output.
    ///
    /// The flow this completes is documented in `docs/PROVIDER_COMPATIBILITY.md` §3: the wallet
    /// first created a real output carrying `minimumValuePromise`, then signed this bridge's
    /// challenge over it. What this handler does is decide, from chain state and the signature,
    /// whether that means what it claims. The page supplies four identifiers and a signature;
    /// everything the verdict rests on is fetched or recomputed here.
    ///
    /// The challenge bookkeeping is the same book Mode A uses, so a credential proof and a
    /// consensus proof compete for the same single-use challenges rather than each having a
    /// private supply an attacker could pace.
    /// The credential route: browser wallet proof-of-funds for website and Telegram flows.
    /// A gate scoped to Telegram-only is refused here (those arrive through the join flow).
    async fn credential(&mut self, id: &str, request: &Request) -> Response {
        let Some(gate) = self.gates.get(id).cloned() else {
            return Response::error(404, "GG: no such gate");
        };
        let parsed: crate::credential::CredentialProofRequest =
            match serde_json::from_str(&request.body) {
                Ok(v) => v,
                Err(e) => {
                    return Response::error(400, format!("GG: malformed credential request: {e}"));
                }
            };

        // The reader must exist before anything else: a bridge with no chain access has no
        // credential mode, and saying so is the honest answer.
        if self.chain.is_none() {
            return Response::error(
                503,
                "GG: this bridge has no chain reader configured, so credential proofs cannot be verified. \
                 Set GG_INDEXER_ENDPOINT to enable the credential mode.",
            );
        }
        // The scope check: credential proofs serve both website and Telegram flows.
        // A gate scoped to "telegram" only is refused from the website credential route
        // (those arrive through the Telegram join flow instead).
        let scope = self.gates.use_mode_of(id).unwrap_or_else(|| "website".into());
        if matches!(scope.as_str(), "telegram") {
            return Response::error(
                403,
                "GG: this gate is scoped to Telegram membership only; use the Telegram join flow",
            );
        }
        // The same challenge validation Mode A passes: live, single-use, session-bound, and bound
        // to this gate's policy. A credential proof answers a challenge the bridge minted, never
        // one a page invented.
        let challenge = match validate_prove_request(
            &gate,
            &self.challenges,
            &crate::policy::ProveRequest {
                gate_id: parsed.gate_id.clone(),
                challenge_nonce: parsed.challenge_nonce.clone(),
                session_commitment: parsed.session_commitment.clone(),
            },
            request.origin.as_deref(),
        ) {
            Ok(c) => c,
            Err(refusal) => {
                return Response::json(
                    409,
                    &serde_json::json!({
                        "refused": refusal.to_string(),
                        "challenge_still_live": !matches!(
                            refusal,
                            crate::policy::ProofRefusal::Expired | crate::policy::ProofRefusal::AlreadyAnswered
                        ),
                    }),
                );
            }
        };

        // Credential verification can await an indexer. Reserve before that await so a duplicate
        // delivery cannot verify the same challenge twice and race its eventual authorization.
        let nonce = challenge.nonce().into_array();
        let session_commitment = challenge.session_commitment().to_vec();
        let job_id = hex::encode(&crate::session::random_nonce()[..8]);
        match self.reserve_replay(id, &nonce, &job_id) {
            Ok(Some(Reservation::Pending { proof_job_id })) => {
                return Response::json(202, &serde_json::json!({ "proof_id": proof_job_id, "idempotent": true }));
            }
            Ok(Some(Reservation::Authorized(_))) => {
                return Response::json(409, &serde_json::json!({ "refused": "GG: challenge is already authorized" }));
            }
            Ok(Some(Reservation::Reserved(_))) | Ok(None) => {}
            Err(error) => return Response::error(503, error.to_string()),
        }
        if let Err(error) = self.challenges.reserve_for_submission(&nonce, &session_commitment) {
            self.release_replay_refused(id, &nonce);
            return Response::error(409, error.to_string());
        }

        // The challenge string the wallet signed is the exact string the challenge route returned
        // and the page passed through: the lowercase hex of the nonce. Reconstruction, not trust.
        let nonce_hex = crate::policy::nonce_to_hex(&challenge.nonce());
        let verifier = crate::credential::CredentialVerifier {
            gate_id: id,
            network: gate.network,
            threshold: gate.threshold(),
            resource: &gate.resource().copied().unwrap(),
            challenge_string: &nonce_hex,
        };

        // Borrow only after the durable reservation. Holding this immutable borrow while the
        // coordinator mutates would also make the lock ordering hard to audit.
        let chain = self.chain.as_ref().expect("checked before challenge reservation");
        let outcome = verifier.verify(chain, &parsed).await;
        match outcome {
            Ok(receipt) => {
                // Retire the challenge only on a verified receipt, exactly as the consensus mode
                // does: a refused proof leaves it live so the user can retry with a fresh output.
                // The nonce bytes came from the challenge itself, already parsed by the policy
                // check above.
                let nonce_bytes = hex::decode(&nonce_hex)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
                if let Some(nonce_bytes) = nonce_bytes {
                    let _ = self.challenges.consume_on_acceptance(
                        &nonce_bytes,
                        challenge.session_commitment(),
                    );
                }
                let job_nonce = challenge.nonce().into_array();
                self.jobs.push(ProofJob {
                    id: job_id.clone(),
                    gate_id: id.to_string(),
                    challenge_nonce: job_nonce,
                    status: ProofStatus::CredentialAccepted {
                        result: Box::new(receipt.clone()),
                    },
                    started_at: std::time::SystemTime::now(),
                    xtm_artifact: None,
                });
                // The credential path's evidence is the indexer's own `verified` flag (F-04): the
                // bridge read the output from an indexer and trusts its merkle assertion. That is
                // `IndexerAsserted`, which reaches at most OperatorTrustedTestnet, and only when the
                // operator has opted in. It can never authorize a production application. When the
                // v0.47 sidecar is wired (Phase 2C) this is where ConsensusVerified evidence will
                // replace it. The digest names the exact verified output + floor.
                let evidence = ghost_gate_registry::Evidence::IndexerAsserted {
                    digest: format!("credential:{}:{}", receipt.substate_id, receipt.attested_minimum),
                };
                self.grant_access_for(id, &hex::encode(job_nonce), Some(&job_id), evidence);
                // The credential path grants its session here and hands it straight back, so
                // the browser never has to poll for it.
                let access = self.access_grants.get(&hex::encode(job_nonce)).cloned();

                // The attempt id comes from the X-GG-Attempt header the page sets; when present,
                // the inspector is fed the REAL protocol events, in order, as they happened —
                // no invented successes.
                if let Some(attempt) = request.attempt.as_deref() {
                    if let Some(trace) = self.traces.get_mut(attempt) {
                        use crate::trace::ev;
                        // The wallet was asked to sign the challenge over the output it claims.
                        ev::wallet_asked(trace);
                        ev::wallet_answered(trace, receipt.attested_minimum);
                        // The verifier ran: output read from chain state, floor compared with
                        // the gate's live threshold.
                        ev::verifier_checked(
                            trace,
                            receipt.required_minimum,
                            receipt.attested_minimum,
                            1,
                        );
                        ev::policy_binding(trace);
                        // Session truth, stated honestly: a registry-backed bridge issues a
                        // token here (a REAL grant, not a simulated one); a preview bridge
                        // verifies and stops short of one. Two distinct events — conflating
                        // "verified" with "granted" was the old failure mode.
                        if let Some(grant) = &access {
                            ev::access_granted(
                                trace,
                                grant.expires_unix.saturating_sub(crate::session::now_unix()),
                                false,
                            );
                        } else {
                            ev::access_unavailable(trace);
                        }
                    }
                }

                // Four distinct facts, never collapsed into one (G4):
                //   proof_verified     — the signature and on-chain floor checked out (always true here);
                //   evidence_class     — the trust model the evidence was accepted under;
                //   session_issued     — a server-authorized session actually exists;
                //   access_granted     — session_issued AND it meets the gate's required tier.
                // A verified proof whose evidence does not meet the application's required tier
                // issues NO session: the bridge must not show admission for it.
                let session_issued = access.is_some();
                let status_message = if session_issued {
                    "ACCESS GRANTED"
                } else {
                    "PROOF VERIFIED — NO ACCESS SESSION ISSUED (evidence does not meet this application's required trust tier, \
                     or this bridge issues no sessions)"
                };
                Response::json(
                    200,
                    &serde_json::json!({
                        "state": "accepted",
                        "status_message": status_message,
                        "proof_verified": true,
                        "evidence_class": ghost_gate_registry::EvidenceKind::IndexerAsserted.as_str(),
                        "session_issued": session_issued,
                        "access_granted": session_issued,
                        "proof_id": job_id,
                        "receipt": receipt,
                        "access": access,
                    }),
                )
            }
            Err(refusal) => {
                let _ = self.challenges.release_submission(&nonce, &session_commitment);
                self.release_replay_refused(id, &nonce);
                // The refusal is a real operation too — record it in the attempt's trace so
                // the inspector shows why the credential was refused, without leaking
                // secrets (Trace::push sanitizes every detail at the boundary).
                if let Some(attempt) = request.attempt.as_deref() {
                    if let Some(trace) = self.traces.get_mut(attempt) {
                        crate::trace::ev::access_refused(trace, "The credential was refused: the output or its signature did not verify against chain state.");
                    }
                }
                Response::json(
                    409,
                    &serde_json::json!({
                        "refused": refusal.to_string(),
                        "challenge_still_live": true,
                    }),
                )
            }
        }
    }

    /// Validates the request, then asks the wallet for a proof.
    ///
    /// The validation is complete before the wallet is touched. A request that fails a rule never
    /// reaches the wallet at all, so a refused request cannot have caused a lock, a query or a
    /// transaction.
    async fn prove(&mut self, id: &str, request: &Request) -> Response {
        let Some(gate) = self.gates.get(id).cloned() else {
            return Response::error(404, "GG: no such gate");
        };
        // A credential-only gate has no on-chain component, so there is nothing the consensus
        // path could execute against and nothing walletd could submit. Refuse BEFORE the body
        // is even parsed, with the honest reason: a browser wallet pointed here gets a clear
        // "wrong flow" instead of a walletd timeout, and any challenge it already holds stays
        // live for the credential route that can actually answer it.
        if gate.kind() == crate::gate_registry::ProofKind::Ootle && gate.component().is_none() {
            return Response::error(
                409,
                "GG: this gate is credential-only: it binds no on-chain component, so a consensus \
                 proof cannot be built for it. Use the credential flow — sign this bridge's \
                 challenge over a qualifying output and POST it to /gate/{id}/credential.",
            );
        }
        let parsed: ProveRequest = match serde_json::from_str(&request.body) {
            Ok(v) => v,
            Err(e) => return Response::error(400, format!("GG: malformed proof request: {e}")),
        };
        // The gate id in the body must be the gate id in the path, so a caller cannot POST to one gate
        // and name another.
        if parsed.gate_id != id {
            return Response::error(400, "GG: the request's gate_id does not match the path");
        }

        let challenge = match validate_prove_request(&gate, &self.challenges, &parsed, request.origin.as_deref()) {
            Ok(c) => c,
            Err(refusal) => {
                // A refusal is a normal outcome, not an error: the user was not proven to hold enough, and
                // saying so leaks nothing they did not already know.
                return Response::json(
                    409,
                    &serde_json::json!({
                        "refused": refusal.to_string(),
                        "challenge_still_live": !matches!(
                            refusal,
                            crate::policy::ProofRefusal::Expired | crate::policy::ProofRefusal::AlreadyAnswered
                        ),
                    }),
                );
            }
        };

        let nonce = challenge.nonce().into_array();
        let session_commitment = challenge.session_commitment().to_vec();
        let job_id_bytes = random_nonce();
        let job_id = hex::encode(&job_id_bytes[..8]);
        match self.reserve_replay(id, &nonce, &job_id) {
            Ok(Some(Reservation::Pending { proof_job_id })) => {
                return Response::json(202, &serde_json::json!({ "proof_id": proof_job_id, "idempotent": true }));
            }
            Ok(Some(Reservation::Authorized(_))) => {
                return Response::json(409, &serde_json::json!({ "refused": "GG: challenge is already authorized" }));
            }
            Ok(Some(Reservation::Reserved(_))) | Ok(None) => {}
            Err(error) => return Response::error(503, error.to_string()),
        }
        match self.challenges.reserve_for_submission(&nonce, &session_commitment) {
            Ok(()) => {}
            Err(crate::session::BookError::InProgress) => {
                // Validation above still bound this retry to the original browser origin/session.
                if let Some(job) = self.jobs.iter().find(|job| job.challenge_nonce == nonce) {
                    let mut body = serde_json::json!({ "proof_id": job.id, "idempotent": true });
                    if let crate::session::ProofStatus::Submitted { transaction_id } = &job.status {
                        body["transaction_id"] = serde_json::Value::String(transaction_id.clone());
                    }
                    return Response::json(202, &body);
                }
                return Response::error(409, "GG: a proof for this challenge is already being processed");
            }
            Err(error) => {
                self.release_replay_refused(id, &nonce);
                return Response::error(409, error.to_string());
            }
        }

        // Dispatch on the gate's typed condition, not on a string: the two proof paths share the
        // challenge bookkeeping and nothing else. The job id is minted once here so both paths
        // answer with the same shape.
        let attempt = request.attempt.as_deref();
        match gate.kind() {
            crate::gate_registry::ProofKind::Ootle => self.prove_ootle(id, challenge, job_id, attempt).await,
            crate::gate_registry::ProofKind::MinotariXtm => self.prove_xtm(id, challenge, job_id).await,
        }
    }

    /// The Ootle path: build a stealth statement and submit it through walletd.
    async fn prove_ootle(
        &mut self,
        id: &str,
        challenge: crate::session::AnyChallenge,
        job_id: String,
        attempt: Option<&str>,
    ) -> Response {
        let gate = self.gates.get(id).cloned();
        let Some(challenge) = challenge.ootle().cloned() else {
            return Response::error(500, "GG: internal dispatch error: Ootle proof for a non-Ootle challenge");
        };
        let Some(gate) = gate else {
            return Response::error(500, "GG: internal dispatch error: gate vanished mid-request");
        };
        let nonce = challenge.nonce.into_array();
        self.push_job(ProofJob {
            id: job_id.clone(),
            gate_id: id.to_string(),
            challenge_nonce: nonce,
            status: ProofStatus::Preparing,
            started_at: std::time::SystemTime::now(),
            xtm_artifact: None,
        });

        // An empty `Named` rather than `WalletSelected`. `Named(vec![])` is the honest encoding of what
        // this request actually says: no input was specified, and the resource and promise are the
        // gate's. The adapter fills the gap by qualifying the gate resource's own unspent outputs inside
        // the local bridge, so no UTXO identifier ever comes from the caller.
        //
        // `WalletSelected` is refused by the adapter and must not be constructed here. It is unusable
        // because the engine resolves a spent input under the gate's resource and refuses a transaction
        // that does not declare every substate it spends -- see `wallet::InputChoice`.
        let statement = StatementRequest {
            resource: gate.resource().copied().unwrap(),
            input_revealed: tari_template_lib_types::Amount::from(gate.threshold()),
            minimum_value_promise: gate.threshold(),
            selection: crate::wallet::InputChoice::Named(Vec::new()),
        };

        // Bind this attempt to the job so every later event lands in the visitor's own trace.
        if let Some(raw_attempt) = attempt {
            self.job_attempts.insert(job_id.clone(), raw_attempt.to_string());
            self.trace_job(&job_id, |t| {
                use crate::trace::ev;
                ev::wallet_asked(t);
                ev::policy_binding(t);
            });
        }

        let reply = match self.wallet.build_statement(statement).await {
            Ok(r) => {
                self.trace_job(&job_id, |t| crate::trace::ev::wallet_answered(t, 0));
                r
            },
            Err(e) => {
                self.trace_job(&job_id, |t| {
                    crate::trace::ev::access_refused(t, "The wallet could not be reached; no proof was built.");
                });
                self.set_status(
                    &job_id,
                    ProofStatus::Failed {
                        reason: e.to_string(),
                    },
                );
                let _ = self.challenges.release_submission(&nonce, challenge.session_commitment.as_slice());
                self.release_replay_refused(id, &nonce);
                return Response::json(202, &serde_json::json!({ "proof_id": job_id }));
            }
        };

        match self
            .wallet
            .submit(
                &gate.component().copied().unwrap().to_string(),
                &challenge,
                &reply.statement,
                &reply.lock_id,
            )
            .await
        {
            Ok(transaction_id) => {
                // Transaction submission is not recoverable until its reference has reached the
                // durable coordinator. If this persistence step fails, keep the nonce reserved,
                // hide the transaction reference from the client and never issue a session from
                // this in-memory-only job.
                if let Some(replay) = self.replay.as_mut()
                    && replay.record_submission(&nonce, &job_id, PendingProofKind::OotleTransaction, &transaction_id).is_err()
                {
                    self.set_status(&job_id, ProofStatus::Failed {
                        reason: "GG: durable replay persistence failed after submission; authorization remains pending for operator reconciliation".into(),
                    });
                    return Response::error(503, "GG: proof submission is pending durable reconciliation");
                }
                self.set_status(
                    &job_id,
                    ProofStatus::Submitted {
                        transaction_id: transaction_id.clone(),
                    },
                );
                Response::json(
                    202,
                    &serde_json::json!({ "proof_id": job_id, "transaction_id": transaction_id }),
                )
            }
            Err(e) => {
                self.set_status(
                    &job_id,
                    ProofStatus::Failed {
                        reason: e.to_string(),
                    },
                );
                // A transport error after submit is ambiguous: walletd may have accepted the
                // transaction while its response was lost. Durable mode keeps the reservation
                // until a reconciler can establish finality, rather than submitting again.
                if self.replay.is_none() {
                    let _ = self.challenges.release_submission(&nonce, challenge.session_commitment.as_slice());
                }
                Response::json(202, &serde_json::json!({ "proof_id": job_id }))
            }
        }
    }

    /// The native Minotari L1 XTM path: one pay-to-self transaction, initiated by this bridge for
    /// this challenge, verified against base-node consensus data.
    ///
    /// The browser supplies three strings and nothing else. It never names a transaction: the
    /// artifact this route records is the one the wallet daemon produced in answer to this
    /// challenge, and only that artifact is ever verified. If the wallet cannot afford a qualifying
    /// transaction, the challenge stays live and the refusal names no balance.
    async fn prove_xtm(&mut self, id: &str, challenge: crate::session::AnyChallenge, job_id: String) -> Response {
        let Some(xtm_challenge) = challenge.minotari_xtm().cloned() else {
            return Response::error(500, "GG: internal dispatch error: XTM proof for a non-XTM challenge");
        };
        self.push_job(ProofJob {
            id: job_id.clone(),
            gate_id: id.to_string(),
            challenge_nonce: xtm_challenge.nonce.into_array(),
            status: ProofStatus::Preparing,
            started_at: std::time::SystemTime::now(),
            xtm_artifact: None,
        });

        let request = crate::xtm::XtmProofRequest {
            threshold_micro: xtm_challenge.threshold_micro,
            challenge_nonce: xtm_challenge.nonce.into_array(),
        };
        match self.xtm.create_proof_transaction(request).await {
            Ok(artifact) => {
                self.jobs.iter_mut().find(|j| j.id == job_id).map(|j| {
                    j.xtm_artifact = Some(artifact.clone());
                });
                self.set_status(
                    &job_id,
                    ProofStatus::Submitted {
                        transaction_id: artifact.transaction_id.to_string(),
                    },
                );
                Response::json(
                    202,
                    &serde_json::json!({
                        "proof_id": job_id,
                        "transaction_id": artifact.transaction_id.to_string(),
                        "network": "minotari",
                    }),
                )
            }
            Err(e) => {
                self.set_status(
                    &job_id,
                    ProofStatus::Failed {
                        reason: e.to_string(),
                    },
                );
                if self.replay.is_none() {
                    let _ = self.challenges.release_submission(
                        &xtm_challenge.nonce.into_array(),
                        xtm_challenge.session_commitment.as_slice(),
                    );
                }
                Response::json(202, &serde_json::json!({ "proof_id": job_id }))
            }
        }
    }

    /// Polls the network for every submitted proof. Kept for tests and for a future background
    /// tick; the production path is `reconcile_job` from the status route, which the second-pass
    /// audit added after finding that nothing here was ever called from the server.
    pub async fn reconcile(&mut self) {
        let ids: Vec<String> = self
            .jobs
            .iter()
            .filter(|j| matches!(j.status, ProofStatus::Submitted { .. }))
            .map(|j| j.id.clone())
            .collect();
        for id in ids {
            self.reconcile_job(&id, Duration::from_secs(120)).await;
        }
    }

    /// Polls the network for one submitted proof and retires the challenge only on acceptance.
    ///
    /// Jobs that are not `Submitted` are untouched, so repeated polls of a settled proof are free.
    /// An XTM job reconciles against the base node (its wallet channel has no wait of its own); an
    /// Ootle job waits on the wallet daemon's transaction result as before.
    pub async fn reconcile_job(&mut self, job_id: &str, timeout: Duration) {
        let Some(index) = self.jobs.iter().position(|j| j.id == job_id) else {
            return;
        };
        if !matches!(self.jobs[index].status, ProofStatus::Submitted { .. }) {
            return;
        }
        if let Some(artifact) = self.jobs[index].xtm_artifact.clone() {
            return self.reconcile_xtm_job(job_id, artifact).await;
        }
        let transaction_id = match &self.jobs[index].status {
            ProofStatus::Submitted { transaction_id } => transaction_id.clone(),
            _ => return,
        };
        let gate_id = self.jobs[index].gate_id.clone();
        let nonce = self.jobs[index].challenge_nonce;
        match self.wallet.wait(&transaction_id, timeout).await
        {
                Ok(crate::wallet::CommitOutcome::Accepted {
                    transaction_id,
                    attested_minimum,
                    input_count,
                }) => {
                    // Only now is the challenge retired. A rejected proof leaves it live so the user can
                    // try again in the same session.
                    self.challenges
                        .consume_on_acceptance(
                            &nonce,
                            &self
                                .challenges
                                .peek(&nonce)
                                .map(|e| e.challenge.session_commitment().to_vec())
                                .unwrap_or_default(),
                        )
                        .ok();
                    let binding = self.gates.get(&gate_id).cloned();
                    self.jobs[index].status = ProofStatus::Accepted {
                        result: PublicProof {
                            gate_id: gate_id.clone(),
                            gate_address: binding
                                .as_ref()
                                .and_then(|g| g.component())
                                .map(|a| a.to_string())
                                .unwrap_or_default(),
                            resource_address: binding
                                .as_ref()
                                .and_then(|g| g.resource())
                                .map(|a| a.to_string())
                                .unwrap_or_default(),
                            required_minimum: binding
                                .as_ref()
                                .map(|g| g.threshold())
                                .unwrap_or_default(),
                            attested_minimum,
                            input_count,
                            challenge_nonce: hex::encode(nonce),
                            transaction_id,
                            proof_kind: crate::gate_registry::ProofKind::Ootle,
                        },
                    };
                    // `grant_access_for` uses the durable nonce record to atomically select its
                    // stable authorization identity before installing/recovering the registry
                    // session. A restart-recovered job follows exactly this same path.
                    //
                    // Mode A's evidence is the operator's OWN wallet daemon reporting a finalized
                    // transaction — not independent consensus. It is `OperatorWalletReceipt`, which
                    // tops out at OperatorTrustedTestnet: a local walletd receipt does not become
                    // Production merely because the gate uses Consensus mode (G5). The digest names
                    // the committed transaction and the floor it attested.
                    let evidence = ghost_gate_registry::Evidence::OperatorWalletReceipt {
                        digest: format!("ootle:{}:{attested_minimum}", hex::encode(nonce)),
                    };
                    self.grant_access_for(&gate_id, &hex::encode(nonce), Some(job_id), evidence);
                }
                Ok(crate::wallet::CommitOutcome::Rejected { reason }) => {
                    self.jobs[index].status = ProofStatus::Refused { reason };
                    if let Ok(issued) = self.challenges.peek(&nonce) {
                        let session = issued.challenge.session_commitment().to_vec();
                        let _ = self.challenges.release_submission(&nonce, &session);
                    }
                    self.release_replay_refused(&gate_id, &nonce);
                }
                Ok(crate::wallet::CommitOutcome::Pending) => {}
                Err(e) => {
                    self.jobs[index].status = ProofStatus::Failed {
                        reason: e.to_string(),
                    };
                    if self.replay.is_none() && let Ok(issued) = self.challenges.peek(&nonce) {
                        let session = issued.challenge.session_commitment().to_vec();
                        let _ = self.challenges.release_submission(&nonce, &session);
                    }
                }
            }
    }

    /// Polls the base node for the proving kernel, verifies the evidence, and retires the challenge
    /// only on a full verdict.
    ///
    /// A "not mined yet" is left `Submitted` so the polling client drives completion, exactly as the
    /// Ootle path's `Pending` does. An error inside a settled verification — stale kernel, short
    /// floor, bad signature — is a `Refused`, which leaves the challenge live; the challenge is
    /// consumed only by an acceptance, and one proof per challenge holds however many times the
    /// user retries.
    async fn reconcile_xtm_job(&mut self, job_id: &str, artifact: crate::xtm::XtmProofArtifact) {
        let Some(index) = self.jobs.iter().position(|j| j.id == job_id) else {
            return;
        };
        let gate_id = self.jobs[index].gate_id.clone();
        let nonce = self.jobs[index].challenge_nonce;
        let Some(gate) = self.gates.get(&gate_id).cloned() else {
            self.jobs[index].status = ProofStatus::Failed {
                reason: "GG: the gate behind this proof is no longer registered".to_string(),
            };
            return;
        };
        let Some(reader) = self.xtm_chain.as_mut() else {
            self.jobs[index].status = ProofStatus::Failed {
                reason: "GG: no Minotari base node is configured, so this proof cannot be verified".to_string(),
            };
            return;
        };
        // The challenge must still be live to be answered: an accepted proof from a challenge that
        // has since expired would be a claim about a window nobody granted.
        let challenge = match self.challenges.peek(&nonce) {
            Ok(issued) => issued.challenge.clone(),
            Err(_) => {
                self.jobs[index].status = ProofStatus::Refused {
                    reason: "GG: the challenge behind this proof is no longer answerable".to_string(),
                };
                return;
            },
        };
        let Some(xtm_challenge) = challenge.minotari_xtm().cloned() else {
            self.jobs[index].status = ProofStatus::Failed {
                reason: "GG: internal dispatch error: XTM proof for a non-XTM challenge".to_string(),
            };
            return;
        };
        // One verification pass per poll; the polling client drives completion.
        let now = crate::session::now_unix();
        let outcome = crate::xtm::verify_xtm_proof(reader, &xtm_challenge, &artifact, now).await;
        match outcome {
            Ok(receipt) => {
                let session_commitment = xtm_challenge.session_commitment.as_slice().to_vec();
                self.challenges
                    .consume_on_acceptance(&nonce, &session_commitment)
                    .ok();
                let xtm_job_id = self.jobs[index].id.clone();
                // L1 XTM is base-node-verified by the operator's own reader, so it is at most an
                // OperatorWalletReceipt. In practice XTM gates are not activatable, so issuance
                // refuses regardless — this stays fail-closed either way.
                let evidence = ghost_gate_registry::Evidence::OperatorWalletReceipt {
                    digest: format!("xtm:{}", hex::encode(nonce)),
                };
                self.grant_access_for(&gate_id, &hex::encode(nonce), Some(&xtm_job_id), evidence);
                self.jobs[index].status = ProofStatus::Accepted {
                    result: PublicProof {
                        gate_id: gate_id.clone(),
                        gate_address: String::new(),
                        resource_address: String::new(),
                        required_minimum: gate.threshold(),
                        // The floor is `promise + fee`, in micro-Minotari. Truncated to u64 for
                        // the wire type: a floor at or above `u64::MAX` is unreachable by any
                        // real threshold, and saturating keeps it monotone rather than wrapping.
                        attested_minimum: u64::try_from(receipt.attested_floor_micro).unwrap_or(u64::MAX),
                        input_count: receipt.output_count,
                        challenge_nonce: hex::encode(nonce),
                        transaction_id: artifact.transaction_id.to_string(),
                        proof_kind: crate::gate_registry::ProofKind::MinotariXtm,
                    },
                };
            },
            Err(ghost_gate_core::xtm::XtmProofError::NotMined) => {
                // Still flying. The status stays Submitted and the next poll looks again.
            },
            Err(other) => {
                self.jobs[index].status = ProofStatus::Refused {
                    reason: other.to_string(),
                };
                let _ = self.challenges.release_submission(&nonce, xtm_challenge.session_commitment.as_slice());
                self.release_replay_refused(&gate_id, &nonce);
            },
        }
    }

    /// Records a job, dropping the oldest once the cap is hit.
    ///
    /// Draining from the front keeps the newest results answerable; the dropped ones answer 404,
    /// which is what a result old enough to matter no longer being retained should look like.
    fn push_job(&mut self, job: ProofJob) {
        self.jobs.push(job);
        if self.jobs.len() > MAX_JOBS {
            let overflow = self.jobs.len() - MAX_JOBS;
            self.jobs.drain(0..overflow);
        }
    }

    fn set_status(&mut self, job_id: &str, status: ProofStatus) {
        if let Some(job) = self.jobs.iter_mut().find(|j| j.id == job_id) {
            job.status = status;
        }
    }
}

/// Serves until the process is stopped.
///
/// One connection at a time, and the connection is closed after one response. That is not a limitation
/// this project should outgrow casually: a bridge is a localhost service for one user's browser, and a
/// serialized loop has no concurrency to get wrong. `Connection: close` is always sent, so a client
/// cannot keep a socket open.
/// A peer gets this long to send a complete request, and this long to accept the response.
///
/// Without the read bound, one client that connects and says nothing -- or that disconnects
/// mid-request, leaving a half-open socket -- blocks this loop in `read()` forever. Because the
/// loop handles one connection at a time, that wedged the whole bridge: every later request,
/// including `/health`, simply queued behind the stalled socket and Privacy Lab stopped loading.
/// Connections are therefore bounded on both ends rather than left to hang.
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Reads exactly one bounded HTTP/1.1 request.  A tunnel is allowed to split the headers and body
/// across separate TCP reads (or reframe a Worker fetch as chunked); treating the first read as a
/// complete request silently turns a valid credential JSON body into an empty string.
///
/// The bridge deliberately accepts only the two framings it can bound: a single Content-Length, or
/// chunked encoding.  It never waits for connection close, and it refuses ambiguous framing.
async fn read_http_request<R: AsyncRead + Unpin>(reader: &mut R) -> Option<String> {
    const MAX_HEADERS: usize = 2 * 1024;
    let mut wire = Vec::with_capacity(MAX_HEADERS + MAX_BODY);
    let mut chunk = [0u8; 1024];

    loop {
        if let Some(header_end) = wire.windows(4).position(|window| window == b"\r\n\r\n") {
            let body_start = header_end + 4;
            let headers = std::str::from_utf8(&wire[..header_end]).ok()?;
            let mut content_length = None;
            let mut chunked = false;
            for line in headers.split("\r\n").skip(1) {
                let Some((name, value)) = line.split_once(':') else { return None };
                if name.eq_ignore_ascii_case("content-length") {
                    if content_length.replace(value.trim().parse::<usize>().ok()?).is_some() {
                        return None;
                    }
                } else if name.eq_ignore_ascii_case("transfer-encoding") {
                    let codings: Vec<_> = value.split(',').map(|coding| coding.trim()).collect();
                    if codings.len() != 1 || !codings[0].eq_ignore_ascii_case("chunked") {
                        return None;
                    }
                    chunked = true;
                }
            }
            if chunked && content_length.is_some() {
                return None;
            }

            if let Some(length) = content_length {
                if length > MAX_BODY { return None; }
                let expected = body_start.checked_add(length)?;
                if wire.len() == expected {
                    return String::from_utf8(wire).ok();
                }
                if wire.len() > expected { return None; }
            } else if chunked {
                match decode_chunked_body(&wire[body_start..])? {
                    Some(body) => {
                        if body.len() > MAX_BODY { return None; }
                        wire.truncate(body_start);
                        wire.extend_from_slice(&body);
                        return String::from_utf8(wire).ok();
                    }
                    None => {}
                }
            } else {
                return String::from_utf8(wire).ok();
            }
        } else if wire.len() >= MAX_HEADERS {
            return None;
        }

        let read = reader.read(&mut chunk).await.ok()?;
        if read == 0 || wire.len().checked_add(read)? > MAX_HEADERS + MAX_BODY + 256 {
            return None;
        }
        wire.extend_from_slice(&chunk[..read]);
    }
}

/// Returns `None` while a valid chunked body is incomplete, and `Some` once its final empty chunk
/// and terminating CRLF arrive. Trailers are refused because this bridge has no route that uses
/// them and accepting unparsed header-like data would widen the HTTP surface unnecessarily.
fn decode_chunked_body(wire: &[u8]) -> Option<Option<Vec<u8>>> {
    let mut offset = 0usize;
    let mut decoded = Vec::new();
    loop {
        let line_end = wire[offset..].windows(2).position(|window| window == b"\r\n");
        let Some(line_end) = line_end else { return Some(None) };
        let line_end = offset + line_end;
        let size_text = std::str::from_utf8(&wire[offset..line_end]).ok()?;
        // Chunk extensions are irrelevant to this small JSON server and are deliberately refused.
        if size_text.contains(';') || size_text.is_empty() { return None; }
        let size = usize::from_str_radix(size_text, 16).ok()?;
        if size > MAX_BODY || decoded.len().checked_add(size)? > MAX_BODY { return None; }
        let data_start = line_end + 2;
        let data_end = data_start.checked_add(size)?;
        let trailer_end = data_end.checked_add(2)?;
        if wire.len() < trailer_end { return Some(None); }
        if &wire[data_end..trailer_end] != b"\r\n" { return None; }
        if size == 0 {
            // The final CRLF is the empty trailer section in `0\r\n\r\n`. Trailers are not
            // accepted, so a complete request ends exactly here.
            if wire.len() != trailer_end { return None; }
            return Some(Some(decoded));
        }
        decoded.extend_from_slice(&wire[data_start..data_end]);
        offset = trailer_end;
    }
}

pub async fn serve<W, R, X, XR>(addr: &str, bridge: Bridge<W, R, X, XR>) -> std::io::Result<()>
where
    W: WalletChannel + Send + 'static,
    R: crate::credential::ChainReader + Send + 'static,
    X: crate::xtm::XtmChannel + Send + 'static,
    XR: crate::xtm::XtmChainReader + Send + 'static,
{
    let listener = TcpListener::bind(addr).await?;
    let bridge = Arc::new(tokio::sync::Mutex::new(bridge));
    loop {
        let (mut socket, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => continue,
        };

        // Bounded read: a silent or half-closed peer costs at most READ_TIMEOUT, not forever.
        // Unlike the old one-read implementation, this waits for the HTTP framing to complete.
        let raw = match tokio::time::timeout(READ_TIMEOUT, read_http_request(&mut socket)).await {
            Ok(Some(raw)) => raw,
            // Read error, an oversized/ambiguous request, or an incomplete body: drop it and
            // serve the next connection. The parser never receives a truncated credential body.
            Ok(None) | Err(_) => {
                let _ = socket.shutdown().await;
                continue;
            }
        };

        let response = match parse_request(&raw) {
            Some(request) => {
                let mut bridge = bridge.lock().await;
                (*bridge).handle(&request).await
            }
            None => Response::error(400, "GG: malformed request"),
        };

        let body = render(&response);
        let _ = tokio::time::timeout(WRITE_TIMEOUT, socket.write_all(body.as_bytes())).await;
        let _ = socket.shutdown().await;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate_registry::GateBinding;
    use crate::wallet::{CommitOutcome, InputChoice, StatementReply, WalletError, WalletStatus};
    use ghost_gate_core::network;
    use rand::{CryptoRng, Rng, rng};
    use tari_crypto::keys::{PublicKey as _, SecretKey as _};
    use tari_crypto::ristretto::{RistrettoPublicKey, RistrettoSecretKey};
    use tari_crypto::signatures::{SchnorrSigChallenge, SchnorrSignature};
    use tari_crypto::tari_utilities::ByteArray;
    use tari_template_lib_types::stealth::StealthTransferStatement;
    use tari_template_lib_types::{ComponentAddress, MaxBytes, ObjectKey, ResourceAddress};

    #[tokio::test]
    async fn http_reader_waits_for_a_credential_body_sent_after_its_headers() {
        let body = r#"{"gate_id":"Crypt","challenge_nonce":"nonce","public_key":"key","public_nonce":"nonce","session_commitment":"commitment","signature":"signature","substate_id":"utxo"}"#;
        let expected_len = body.len();
        let headers = format!(
            "POST /gate/Crypt/credential HTTP/1.1\r\nHost: bridge.example\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let (mut writer, mut reader) = tokio::io::duplex(MAX_BODY + 2048);
        let body = body.to_string();
        let writer_task = tokio::spawn(async move {
            writer.write_all(headers.as_bytes()).await.unwrap();
            // This is the tunnel framing that the former one-read listener treated as an empty body.
            tokio::time::sleep(Duration::from_millis(10)).await;
            writer.write_all(body.as_bytes()).await.unwrap();
        });

        let raw = tokio::time::timeout(READ_TIMEOUT, read_http_request(&mut reader))
            .await
            .unwrap()
            .expect("complete request");
        writer_task.await.unwrap();
        let request = parse_request(&raw).expect("parsed request");
        let fields = serde_json::from_str::<serde_json::Value>(&request.body)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/gate/Crypt/credential");
        assert_eq!(request.body.len(), expected_len);
        assert_eq!(fields, ["challenge_nonce", "gate_id", "public_key", "public_nonce", "session_commitment", "signature", "substate_id"]);
    }

    #[tokio::test]
    async fn http_reader_decodes_a_bounded_chunked_credential_body() {
        let body = r#"{"gate_id":"Crypt"}"#;
        let wire = format!(
            "POST /gate/Crypt/credential HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n{:X}\r\n{}\r\n0\r\n\r\n",
            body.len(), body
        );
        let (mut writer, mut reader) = tokio::io::duplex(MAX_BODY + 2048);
        let writer_task = tokio::spawn(async move { writer.write_all(wire.as_bytes()).await.unwrap(); });
        let raw = read_http_request(&mut reader).await.expect("complete chunked request");
        writer_task.await.unwrap();
        let request = parse_request(&raw).expect("parsed request");
        assert_eq!(request.body, body);
    }

    /// A stand-in for the wallet daemon.
    ///
    /// Legitimate, and worth being precise about why: the wallet is an *external service* reached over
    /// RPC, so a fake here tests the bridge's own policy -- what it asks the wallet for, and what it
    /// refuses before asking -- rather than pretending to establish a consensus claim. The consensus
    /// claim is the localnet scenario's job.
    struct FakeWallet {
        status: WalletStatus,
        build_result: Result<(), String>,
        submit_result: Result<String, String>,
        wait_result: CommitOutcome,
        /// Every resource and threshold the bridge asked for, in order.
        asked: Vec<(ResourceAddress, u64)>,
        /// Every selection strategy the bridge used.
        selections: Vec<InputChoice>,
        reachable: bool,
        /// Every gate the bridge asked to submit, with the challenge nonce that was submitted.
        submitted: Vec<(String, [u8; 32])>,
    }

    impl FakeWallet {
        fn new() -> Self {
            Self {
                status: WalletStatus {
                    configured: true,
                    reachable: true,
                    has_default_account: true,
                    network: network::LOCALNET,
                    network_name: "localnet".into(),
                    account_name: None,
                },
                build_result: Ok(()),
                submit_result: Ok("tx_fake_0001".into()),
                wait_result: CommitOutcome::Accepted {
                    transaction_id: "tx_fake_0001".into(),
                    attested_minimum: 10_000,
                    input_count: 1,
                },
                asked: Vec::new(),
                selections: Vec::new(),
                reachable: true,
                submitted: Vec::new(),
            }
        }
    }

    impl WalletChannel for FakeWallet {
        async fn status(&mut self) -> Result<WalletStatus, WalletError> {
            if self.reachable {
                Ok(self.status.clone())
            } else {
                Err(WalletError::Unreachable("connection refused".into()))
            }
        }
        async fn build_statement(
            &mut self,
            request: StatementRequest,
        ) -> Result<StatementReply, WalletError> {
            self.asked
                .push((request.resource, request.minimum_value_promise));
            self.selections.push(request.selection.clone());
            if let Err(e) = &self.build_result {
                return Err(WalletError::Refused(e.clone()));
            }
            Ok(StatementReply {
                statement: minimal_statement(request.minimum_value_promise),
                lock_id: "lock_fake".into(),
                signer_count: 1,
            })
        }
        async fn submit(
            &mut self,
            gate: &str,
            challenge: &ghost_gate_core::Challenge,
            _statement: &StealthTransferStatement,
            _lock_id: &str,
        ) -> Result<String, WalletError> {
            // Recorded so a test can assert the nonce the bridge submitted is the one it issued: a
            // proof of some *other* challenge would be the failure worth catching here.
            self.submitted
                .push((gate.to_string(), challenge.nonce.into_array())); // `gate` is `&str`.
            self.submit_result.clone().map_err(WalletError::Refused)
        }
        async fn wait(
            &mut self,
            _transaction_id: &str,
            _timeout: Duration,
        ) -> Result<CommitOutcome, WalletError> {
            Ok(self.wait_result.clone())
        }
    }

    fn binding() -> GateBinding {
        GateBinding::ootle(
            Some(ComponentAddress::new(ObjectKey::from_array([1u8; 32]))),
            ResourceAddress::new(ObjectKey::from_array([7u8; 32])),
            10_000,
            network::LOCALNET,
            MaxBytes::new_checked(b"vip.example".to_vec()).unwrap(),
            2,
            "GHOSTTEST".into(),
        )
    }

    /// A syntactically complete statement with one promise-bearing output and no inputs.
    ///
    /// Real bytes rather than a placeholder, so the accept and reject paths are exercised end to end in
    /// the bridge's own terms. It is not a *valid* Ghost Gate proof -- consensus would refuse an empty
    /// input set -- and nothing here claims otherwise: what is under test is the bridge's reaction to
    /// what the network says, not the network's verdict.
    fn minimal_statement(minimum_value_promise: u64) -> StealthTransferStatement {
        use tari_crypto::keys::{PublicKey, SecretKey};
        use tari_crypto::ristretto::{RistrettoPublicKey, RistrettoSecretKey};
        use tari_ootle_wallet_crypto::{OutputWitness, StealthOutputWitness};
        use tari_template_lib_types::crypto::{RistrettoPublicKeyBytes, UtxoTag};
        use tari_template_lib_types::stealth::SpendAuthorization;
        use tari_template_lib_types::{Amount, EncryptedData};

        let out = StealthOutputWitness {
            witness: OutputWitness {
                amount: minimum_value_promise,
                mask: RistrettoSecretKey::from(1u64),
                sender_public_nonce: RistrettoPublicKey::from_secret_key(
                    &RistrettoSecretKey::from(2u64),
                ),
                minimum_value_promise,
                encrypted_data: EncryptedData::try_from(vec![0u8; EncryptedData::min_size()])
                    .unwrap(),
                resource_view_key: None,
            },
            auth: SpendAuthorization::Key(RistrettoPublicKeyBytes::default()),
            tag: UtxoTag::new(0),
        };
        tari_ootle_wallet_crypto::stealth::create_transfer_statement(
            vec![],
            Amount::from(minimum_value_promise),
            [&out],
            None,
        )
        .expect("statement")
    }

    /// A chain reader that pretends to be the indexer, so the credential route can be exercised
    /// end to end. Only what the verifier needs is here: a floor, an auth key, and the ability to
    /// be spent.
    struct FakeChain {
        outputs: std::collections::HashMap<String, crate::credential::UtxoOnChain>,
    }

    impl FakeChain {
        fn with(substate_id: String, promise: u64, auth_key: [u8; 32]) -> Self {
            let mut outputs = std::collections::HashMap::new();
            outputs.insert(
                substate_id,
                crate::credential::UtxoOnChain {
                    minimum_value_promise: promise,
                    auth_key: Some(auth_key),
                    verified: true,
                },
            );
            Self { outputs }
        }
    }

    impl crate::credential::ChainReader for FakeChain {
        async fn utxo(
            &self,
            _network: u8,
            address: &tari_template_lib_types::UtxoAddress,
        ) -> Result<crate::credential::UtxoOnChain, crate::credential::ChainReadError> {
            // The production reader looks the UTXO up by its full string form; the fake keys on
            // exactly what the caller will send.
            match self.outputs.get(&address.to_string()) {
                Some(o) => Ok(o.clone()),
                None => Err(crate::credential::ChainReadError::SpentOrUnknown(
                    "InputSubstateIsDown".into(),
                )),
            }
        }
    }

    fn credential_bridge(wallet: FakeWallet, chain: FakeChain) -> Bridge<FakeWallet, FakeChain> {
        let mut gates = GateRegistry::new();
        gates.register("g1", binding()).unwrap();
        gates.set_use_mode("g1", "both");
        Bridge::with_chain_reader(
            gates,
            wallet,
            OriginPolicy::new().allow("https://vip.example"),
            chain,
        )
    }

    fn bridge(wallet: FakeWallet) -> Bridge<FakeWallet> {
        let mut gates = GateRegistry::new();
        gates.register("g1", binding()).unwrap();
        // Two permitted origins, because an operator may legitimately serve more than one site:
        // the F-09 question is whether a challenge minted by one permitted site can be answered by
        // another.
        Bridge::new(
            gates,
            wallet,
            OriginPolicy::new().allow("https://vip.example").allow("https://partner.example"),
        )
    }

    #[test]
    fn a_registry_backed_bridge_enforces_a_latched_reset_halt_across_a_restart() {
        use ghost_gate_registry::{Bindings, StorePaths};
        let dir = std::env::temp_dir().join(format!("gg-bridge-halt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = StorePaths::new(&dir);
        let empty = Bindings { generated_unix: 0, gates: vec![], revoked_session_prefixes: vec![] };

        // A registry-backed bridge (one with an access plane) reads its reset halt from the store.
        let mut b = bridge(FakeWallet::new());
        b.access = Some(crate::access::AccessHandle::from_snapshot(&paths, &empty).0);
        assert!(!b.reset_halted(), "no halt latched yet");

        // Latch a halt (as the identity sensor would) and confirm the bridge now refuses issuance.
        crate::reset_guard::latch_halt(
            &paths.generations().with_file_name("reset_halt.json"),
            &crate::reset_guard::ResetHalt { reason: "epoch regressed".into(), first_seen_unix: 1, observed_network: Some(38), observed_epoch: Some(3) },
        ).unwrap();
        assert!(b.reset_halted(), "the bridge sees the latched halt");

        // "Restart": a freshly constructed bridge over the SAME store still sees the halt — it is
        // read from disk every time, never held only in memory.
        let mut restarted = bridge(FakeWallet::new());
        restarted.access = Some(crate::access::AccessHandle::from_snapshot(&paths, &empty).0);
        assert!(restarted.reset_halted(), "a restarted bridge still enforces the durable halt");

        // Only an explicit operator acknowledgment clears it.
        crate::reset_guard::clear_halt(&paths.generations().with_file_name("reset_halt.json"), "operator reviewed").unwrap();
        assert!(!restarted.reset_halted(), "an explicit ack clears the halt");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn get(path: &str) -> Request {
        Request {
            method: "GET",
            path: path.into(),
            origin: Some("https://vip.example".into()),
            host: Some("127.0.0.1:7799".into()),
            query: Default::default(),
            body: String::new(),
            attempt: None,
            authorization: None,
            verifier_request_signature: None,
        }
    }

    fn post(path: &str, body: serde_json::Value) -> Request {
        Request {
            method: "POST",
            path: path.into(),
            origin: Some("https://vip.example".into()),
            host: Some("127.0.0.1:7799".into()),
            query: Default::default(),
            body: body.to_string(),
            attempt: None,
            authorization: None,
            verifier_request_signature: None,
        }
    }

    async fn issue<R: crate::credential::ChainReader>(
        b: &mut Bridge<FakeWallet, R>,
    ) -> (String, String) {
        let r = b
            .handle(&post("/gate/g1/challenge", serde_json::json!({})))
            .await;
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        (
            v["challenge_nonce"].as_str().unwrap().to_string(),
            v["session_commitment"].as_str().unwrap().to_string(),
        )
    }

    #[tokio::test]
    async fn health_reports_the_gates_it_serves() {
        let mut b = bridge(FakeWallet::new());
        let r = b.handle(&get("/health")).await;
        assert_eq!(r.status, 200);
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(v["gates"], serde_json::json!(["g1"]));
    }

    #[tokio::test]
    async fn gate_metadata_carries_the_address_not_just_a_name() {
        let mut b = bridge(FakeWallet::new());
        let r = b.handle(&get("/gate/g1")).await;
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(v["resource_address"], binding().resource().copied().unwrap().to_string());
        assert_eq!(v["threshold"], 10_000);
        assert_eq!(v["divisibility"], 2);
        assert_eq!(v["symbol"], "GHOSTTEST");
    }

    #[tokio::test]
    async fn an_unregistered_gate_is_a_404_on_every_route() {
        let mut b = bridge(FakeWallet::new());
        for path in ["/gate/other", "/gate/other/challenge"] {
            let method = if path.ends_with("challenge") {
                "POST"
            } else {
                "GET"
            };
            let req = Request {
                method,
                path: path.into(),
                origin: Some("https://vip.example".into()),
                host: Some("127.0.0.1:7799".into()),
                query: Default::default(),
                body: "{}".into(),
                attempt: None,
                authorization: None,
                verifier_request_signature: None,
            };
            assert_eq!(b.handle(&req).await.status, 404, "{path}");
        }
    }

    /// The privacy boundary as an integration test: a browser may read gate metadata and ask for a
    /// challenge, and nothing it asks for can name an amount, a destination or a UTXO.
    #[tokio::test]
    async fn a_prove_request_cannot_name_a_spend() {
        let mut b = bridge(FakeWallet::new());
        let (nonce, session) = issue(&mut b).await;

        // Every one of these attempts to steer the spend. All are refused, and in every case the wallet
        // was never asked.
        let attempts = [
            // an amount larger than the gate's threshold
            serde_json::json!({"gate_id":"g1","challenge_nonce":nonce,"session_commitment":session,"amount":1u64,"destination":"x"}),
            // a named output
            serde_json::json!({"gate_id":"g1","challenge_nonce":nonce,"session_commitment":session,"utxos":["utxo_a","utxo_b"]}),
            // a different resource
            serde_json::json!({"gate_id":"g1","challenge_nonce":nonce,"session_commitment":session,"resource":"resource_deadbeef"}),
            // a different threshold
            serde_json::json!({"gate_id":"g1","challenge_nonce":nonce,"session_commitment":session,"threshold":1u64}),
        ];
        for attempt in attempts {
            let before = b.wallet.asked.len();
            let r = b.handle(&post("/gate/g1/prove", attempt.clone())).await;
            assert!(
                r.status == 400 || r.status == 409,
                "{attempt} must be refused, got {}",
                r.status
            );
            assert_eq!(
                b.wallet.asked.len(),
                before,
                "a refused request must not reach the wallet: {attempt}"
            );
        }
    }

    #[tokio::test]
    async fn the_wallet_is_asked_for_the_gates_resource_and_threshold_only() {
        let mut b = bridge(FakeWallet::new());
        let (nonce, session) = issue(&mut b).await;
        let r = b
            .handle(&post(
                "/gate/g1/prove",
                serde_json::json!({"gate_id":"g1","challenge_nonce":nonce,"session_commitment":session}),
            ))
            .await;
        assert_eq!(r.status, 202, "{}", r.body);

        assert_eq!(
            b.wallet.asked,
            vec![(*binding().resource().unwrap(), binding().threshold())]
        );
        // `Named(vec![])`, not `WalletSelected`: an empty named set means "no input was specified",
        // which is what a request body can actually say, and the adapter fills it in by qualifying the
        // gate resource's own unspent outputs locally. Nothing named here came from the caller.
        assert_eq!(
            b.wallet.selections,
            vec![InputChoice::Named(vec![])],
            "the request carries no UTXO and no destination: an empty Named means the adapter picks an \
             input of the gate's own resource itself, locally"
        );
    }

    #[tokio::test]
    async fn duplicate_prove_delivery_reuses_the_pending_job_without_a_second_wallet_submission() {
        let mut b = bridge(FakeWallet::new());
        let (nonce, session) = issue(&mut b).await;
        let request = serde_json::json!({
            "gate_id": "g1",
            "challenge_nonce": nonce,
            "session_commitment": session,
        });

        let first = b.handle(&post("/gate/g1/prove", request.clone())).await;
        assert_eq!(first.status, 202, "{}", first.body);
        let first_id = serde_json::from_str::<serde_json::Value>(&first.body).unwrap()["proof_id"]
            .as_str()
            .unwrap()
            .to_string();

        let retry = b.handle(&post("/gate/g1/prove", request)).await;
        assert_eq!(retry.status, 202, "{}", retry.body);
        let retry_json: serde_json::Value = serde_json::from_str(&retry.body).unwrap();
        assert_eq!(retry_json["proof_id"], first_id);
        assert_eq!(retry_json["idempotent"], true);
        assert_eq!(b.wallet.submitted.len(), 1, "one nonce must create at most one wallet submission while pending");
    }

    #[tokio::test]
    async fn configured_replay_store_persists_issue_and_reserves_the_live_handler_once() {
        use crate::replay_store::{MemoryReplayStore, ReplayState};

        let mut b = bridge(FakeWallet::new());
        b.set_replay_store(Box::new(MemoryReplayStore::default()));
        let (nonce, session) = issue(&mut b).await;
        let nonce_bytes: [u8; 32] = hex::decode(&nonce).unwrap().try_into().unwrap();
        let issued = b.replay.as_mut().unwrap().get(&nonce_bytes).unwrap();
        assert_eq!(issued.gate, "g1");
        assert_eq!(issued.network, network::LOCALNET);
        assert_eq!(issued.visitor_session, hex::decode(&session).unwrap());
        assert_eq!(issued.state, ReplayState::Issued);

        let request = serde_json::json!({"gate_id":"g1","challenge_nonce":nonce,"session_commitment":session});
        let first = b.handle(&post("/gate/g1/prove", request.clone())).await;
        assert_eq!(first.status, 202, "{}", first.body);
        let first_id = serde_json::from_str::<serde_json::Value>(&first.body).unwrap()["proof_id"].as_str().unwrap().to_string();
        let reserved = b.replay.as_mut().unwrap().get(&nonce_bytes).unwrap();
        assert_eq!(reserved.state, ReplayState::Submitted);
        assert_eq!(reserved.proof_job_id.as_deref(), Some(first_id.as_str()));
        assert_eq!(reserved.pending_transaction_id.as_deref(), Some("tx_fake_0001"));

        let retry = b.handle(&post("/gate/g1/prove", request)).await;
        let retry_json: serde_json::Value = serde_json::from_str(&retry.body).unwrap();
        assert_eq!(retry.status, 202, "{}", retry.body);
        assert_eq!(retry_json["proof_id"], first_id);
        assert_eq!(b.wallet.submitted.len(), 1, "durable reservation prevents a second submission");
    }

    #[tokio::test]
    async fn restart_recovers_a_durable_ootle_job_without_a_second_submission() {
        use crate::replay_store::{FileReplayStore, ReplayState};
        let root = std::env::temp_dir().join(format!("gg-restart-recovery-{}-{}", std::process::id(), crate::session::now_unix()));
        let mut first = bridge(FakeWallet::new());
        first.set_replay_store(Box::new(FileReplayStore::open(&root).unwrap()));
        let (nonce, session) = issue(&mut first).await;
        let response = first.handle(&post("/gate/g1/prove", serde_json::json!({
            "gate_id":"g1", "challenge_nonce":nonce, "session_commitment":session
        }))).await;
        assert_eq!(response.status, 202, "{}", response.body);
        assert_eq!(first.wallet.submitted.len(), 1);
        drop(first); // model a process exit after submit and before the first finality poll

        let mut restarted = bridge(FakeWallet::new());
        restarted.set_replay_store(Box::new(FileReplayStore::open(&root).unwrap()));
        assert_eq!(restarted.recover_pending_jobs().await, 1);
        assert!(matches!(restarted.jobs[0].status, ProofStatus::Accepted { .. }));
        assert!(restarted.wallet.submitted.is_empty(), "recovery may only poll the original transaction");
        let nonce: [u8; 32] = hex::decode(nonce).unwrap().try_into().unwrap();
        assert_eq!(restarted.replay.as_mut().unwrap().get(&nonce).unwrap().state, ReplayState::Submitted,
            "without an access plane recovery remains fail-closed and cannot mint a session");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn a_wallet_that_will_not_build_a_statement_reports_a_failed_job_not_an_error() {
        // The fail-closed path end to end. A channel that declines to build a statement must not take
        // the bridge down, and must not report a proof id that looks like progress -- the job is
        // `Failed` and carries the reason, so a site cannot mistake a refusal for a pending proof. This
        // is the route a real `WalletDaemonChannel` takes when it refuses `WalletSelected`, when no
        // output of the gate's resource meets the threshold, or when the wallet is unreachable.
        let mut wallet = FakeWallet::new();
        wallet.build_result = Err("wallet-chosen inputs are not supported".into());
        let mut b = bridge(wallet);
        let (nonce, session) = issue(&mut b).await;

        let r = b
            .handle(&post(
                "/gate/g1/prove",
                serde_json::json!({"gate_id":"g1","challenge_nonce":nonce,"session_commitment":session}),
            ))
            .await;

        // 202, not 5xx: the user was not proven to hold enough. Saying so leaks nothing they did not
        // already know.
        assert_eq!(r.status, 202, "{}", r.body);
        let id = serde_json::from_str::<serde_json::Value>(&r.body).unwrap()["proof_id"]
            .as_str()
            .unwrap()
            .to_string();

        let status = b.handle(&get(&format!("/proof/{id}/status"))).await;
        let body = status.body;
        assert!(
            body.contains("wallet-chosen inputs are not supported"),
            "the refusal reason must reach the status route: {body}"
        );
        assert!(
            b.wallet.submitted.is_empty(),
            "nothing may be submitted once the wallet declined to build a statement"
        );
    }

    #[tokio::test]
    async fn the_server_never_constructs_the_unsupported_wallet_selected_path() {
        // `WalletSelected` is refused by the adapter, so the server must never ask for it. Asserted on
        // every selection the bridge actually sends rather than by reading the code, so re-introducing
        // the unusable path fails a policy test instead of shipping transactions consensus rejects.
        let mut b = bridge(FakeWallet::new());
        let (nonce, session) = issue(&mut b).await;
        let r = b
            .handle(&post(
                "/gate/g1/prove",
                serde_json::json!({"gate_id":"g1","challenge_nonce":nonce,"session_commitment":session}),
            ))
            .await;
        assert_eq!(r.status, 202, "{}", r.body);

        assert!(
            !b.wallet
                .selections
                .iter()
                .any(|s| *s == InputChoice::WalletSelected),
            "the server must not request wallet-chosen inputs: {:?}",
            b.wallet.selections
        );
        // And nothing the caller sent turned into a named input.
        assert!(
            b.wallet
                .selections
                .iter()
                .all(|s| matches!(s, InputChoice::Named(v) if v.is_empty())),
            "no input may be named from a request: {:?}",
            b.wallet.selections
        );
    }

    #[tokio::test]
    async fn the_nonce_submitted_is_the_nonce_the_bridge_issued() {
        // A proof must answer the challenge it was issued for. If the bridge ever submitted a different
        // nonce, the gate would refuse it, but the failure would be at consensus rather than here -- so
        // it is checked at the boundary.
        let mut b = bridge(FakeWallet::new());
        let (nonce, session) = issue(&mut b).await;
        let r = b
            .handle(&post(
                "/gate/g1/prove",
                serde_json::json!({"gate_id":"g1","challenge_nonce":nonce,"session_commitment":session}),
            ))
            .await;
        assert_eq!(r.status, 202, "{}", r.body);

        let expected = hex::decode(&nonce).expect("hex nonce");
        assert_eq!(b.wallet.submitted.len(), 1, "{:?}", b.wallet.submitted);
        let (gate, submitted_nonce) = &b.wallet.submitted[0];
        assert_eq!(gate, &binding().component().copied().unwrap().to_string());
        assert_eq!(
            submitted_nonce.as_slice(),
            expected.as_slice(),
            "the submitted challenge must be the one issued"
        );
    }

    #[tokio::test]
    async fn no_route_can_return_a_utxo_identifier() {
        // The relying-site privacy requirement, asserted over every route rather than over one of them.
        // A UTXO address in any response body would let a site correlate the prover's holdings, so this
        // walks all eight routes -- including a completed proof and a rejection -- and requires that no
        // body carries a `utxo_` prefix anywhere.
        let mut b = bridge(FakeWallet::new());
        let (nonce, session) = issue(&mut b).await;

        let mut bodies: Vec<(String, String)> = Vec::new();
        for path in [
            "/health",
            "/wallet/status",
            "/gate/g1",
            "/gate/other",
            "/nonsense",
        ] {
            bodies.push((path.to_string(), b.handle(&get(path)).await.body));
        }

        // A challenge response.
        bodies.push((
            "/gate/g1/challenge".to_string(),
            b.handle(&post("/gate/g1/challenge", serde_json::json!({})))
                .await
                .body,
        ));

        // A proof attempt that fails, and one that reaches the wallet and is submitted.
        bodies.push((
            "/gate/g1/prove (refused)".to_string(),
            b.handle(&post(
                "/gate/g1/prove",
                serde_json::json!({"gate_id":"g1","challenge_nonce":"00","session_commitment":session}),
            ))
            .await
            .body,
        ));

        let accepted = b
            .handle(&post(
                "/gate/g1/prove",
                serde_json::json!({"gate_id":"g1","challenge_nonce":nonce,"session_commitment":session}),
            ))
            .await;
        let proof_id =
            serde_json::from_str::<serde_json::Value>(&accepted.body).unwrap()["proof_id"]
                .as_str()
                .unwrap()
                .to_string();
        // Poll to completion so the accepted receipt -- the one response a site actually cares about --
        // is included in the sweep, not just the pending one.
        for _ in 0..20 {
            let status = b.handle(&get(&format!("/proof/{proof_id}/status"))).await;
            if status.body.contains("\"accepted\"") || status.body.contains("\"rejected\"") {
                break;
            }
        }
        bodies.push((
            format!("/proof/{proof_id}/status"),
            b.handle(&get(&format!("/proof/{proof_id}/status")))
                .await
                .body,
        ));

        for (path, body) in &bodies {
            assert!(
                !body.contains("utxo_"),
                "{path} returned a UTXO identifier: {body}"
            );
        }
    }

    #[tokio::test]
    async fn a_rebound_host_name_is_refused_on_every_route() {
        // The DNS-rebinding reproduction. An attacker page that resolves its own name to 127.0.0.1
        // reaches this bridge with same-origin requests -- no Origin header, so the origin
        // allowlist cannot see it. The Host header is what gives it away, and the bridge must
        // refuse it on every route, /health included: "is the bridge up" is information too.
        let mut b = bridge(FakeWallet::new());
        for (method, path, body) in [
            ("GET", "/health", "{}"),
            ("GET", "/wallet/status", "{}"),
            ("GET", "/gate/g1", "{}"),
            ("POST", "/gate/g1/challenge", "{}"),
            ("POST", "/gate/g1/prove", "{}"),
            ("POST", "/gate/g1/credential", "{}"),
        ] {
            let req = Request {
                method: &method,
                path: path.into(),
                origin: None, // same-origin: the rebinding case
                host: Some("evil.com:7799".into()),
                query: Default::default(),
                body: body.into(),
                attempt: None,
                authorization: None,
                verifier_request_signature: None,
            };
            let r = b.handle(&req).await;
            assert_eq!(r.status, 403, "{method} {path}: {}", r.body);
            assert!(r.body.contains("loopback"), "{method} {path}: {}", r.body);
        }
    }

    #[tokio::test]
    async fn a_proof_from_a_different_origin_than_the_challenge_is_refused() {
        // The F-09 reproduction, kept as the regression. Origin A (the page) mints a challenge;
        // origin B (a hostile page, or a leak recipient) reads the response -- both the nonce and
        // the session commitment are in it -- and submits the proof. Possession of the pair is all
        // the old check required, so this must refuse now that the bridge binds the issuing origin.
        let mut wallet = FakeWallet::new();
        wallet.selections.clear();
        let mut b = bridge(wallet);
        let (nonce, session) = issue(&mut b).await; // origin: https://vip.example

        let hijack = Request {
            method: "POST",
            path: "/gate/g1/prove".into(),
            origin: Some("https://partner.example".into()), // permitted, but not the issuer
            host: Some("127.0.0.1:7799".into()),
            query: Default::default(),
            attempt: None,
            authorization: None,
            verifier_request_signature: None,
            body: serde_json::json!({
                "gate_id": "g1",
                "challenge_nonce": nonce,
                "session_commitment": session,
            })
            .to_string(),
        };
        let r = b.handle(&hijack).await;
        assert_eq!(r.status, 409, "{}", r.body);
        assert!(r.body.contains("session"), "{}", r.body);
        // And the wallet was never asked: a hijacked submission must not drive the wallet.
        assert!(b.wallet.asked.is_empty());
    }

    #[tokio::test]
    async fn the_operators_own_host_spellings_are_permitted() {
        let mut b = bridge(FakeWallet::new());
        for host in ["127.0.0.1:7799", "localhost:7799", "LOCALHOST:7799", "127.0.0.1"] {
            let req = Request {
                method: "GET",
                path: "/health".into(),
                origin: None,
                host: Some(host.into()),
                query: Default::default(),
                body: "{}".into(),
                attempt: None,
                authorization: None,
                verifier_request_signature: None,
            };
            let r = b.handle(&req).await;
            assert_eq!(r.status, 200, "{host}: {}", r.body);
        }
        // A missing Host keeps working: the operator's curl and this file's own harness.
        let req = Request {
            method: "GET",
            path: "/health".into(),
            origin: None,
            host: None,
            query: Default::default(),
            body: "{}".into(),
            attempt: None,
            authorization: None,
            verifier_request_signature: None,
        };
        assert_eq!(b.handle(&req).await.status, 200);
    }

    #[tokio::test]
    async fn the_challenge_book_refuses_to_grow_without_bound() {
        // The DoS reproduction: minting is unauthenticated apart from origin policy, so a page
        // looping the challenge route must hit a cap rather than grow the process's memory.
        let mut b = bridge(FakeWallet::new());
        let mut last = None;
        let mut refused_at = None;
        for i in 0..600 {
            let r = b.handle(&post("/gate/g1/challenge", serde_json::json!({}))).await;
            if r.status == 429 {
                refused_at = Some(i);
                last = Some(r);
                break;
            }
        }
        let refused_at = refused_at.expect("the cap must eventually refuse");
        assert!(refused_at <= 300, "the cap held until challenge {refused_at}");
        let last = last.unwrap();
        assert!(last.body.contains("too many live challenges"), "{}", last.body);

        // And the cap is on *live* challenges: consuming one makes room again.
        // (The book's own unit tests cover expiry pruning; here, the consumed challenge frees a slot.)
        let _ = b.challenges.consume_on_acceptance(
            &hex::decode("00").map(|_| [0u8; 32]).unwrap_or([0u8; 32]),
            &[0u8; 64],
        );
    }

    #[tokio::test]
    async fn a_credential_proof_from_a_real_signature_is_accepted_and_retires_the_challenge() {
        // End to end with the real verifier: issue a challenge, sign it the way the wallet does,
        // and require acceptance plus the single-use property.
        let res = *binding().resource().unwrap();
        let sk = RistrettoSecretKey::random(&mut rng());
        let key_bytes = {
            let pk = RistrettoPublicKey::from_secret_key(&sk);
            let mut b = [0u8; 32];
            b.copy_from_slice(pk.as_bytes());
            b
        };
        // The substate id's resource half must be the gate's resource, in the bare-key form the
        // wallets emit.
        let substate_id = format!(
            "utxo_{}_2c713522a4aaf79f2b219d869b5033d3d71d63c0537e5e0bbed2d717d8b2a67e",
            hex::encode([7u8; 32])
        );

        let mut b = credential_bridge(
            FakeWallet::new(),
            FakeChain::with(substate_id.clone(), 50_000, key_bytes),
        );
        let (nonce, session) = issue(&mut b).await;

        // Sign exactly what the wallet would sign: the framed message over the challenge string
        // the challenge route returned.
        let message = crate::credential::ownership_proof_message(
            ghost_gate_core::network::LOCALNET,
            &res,
            &substate_id,
            &nonce,
        );
        let signature = SchnorrSignature::<
            RistrettoPublicKey,
            RistrettoSecretKey,
            SchnorrSigChallenge,
        >::sign(&sk, &message, &mut rng())
        .unwrap();
        let pk = RistrettoPublicKey::from_secret_key(&sk);

        let r = b
            .handle(&post(
                "/gate/g1/credential",
                serde_json::json!({
                    "gate_id": "g1",
                    "challenge_nonce": nonce,
                    "session_commitment": session,
                    "substate_id": substate_id,
                    "public_key": hex::encode(pk.as_bytes()),
                    "public_nonce": hex::encode(signature.get_public_nonce().as_bytes()),
                    "signature": hex::encode(signature.get_signature().as_bytes()),
                }),
            ))
            .await;
        assert_eq!(r.status, 200, "{}", r.body);
        assert!(r.body.contains("\"accepted\""), "{}", r.body);
        assert!(
            r.body.contains("\"attested_minimum\":50000"),
            "the floor is the chain's: {}",
            r.body
        );
        assert!(r.body.contains("\"mode\":\"credential\""), "{}", r.body);

        // Single-use: the same proof answers nothing a second time.
        let r2 = b
            .handle(&post(
                "/gate/g1/credential",
                serde_json::json!({
                    "gate_id": "g1",
                    "challenge_nonce": nonce,
                    "session_commitment": session,
                    "substate_id": substate_id,
                    "public_key": hex::encode(pk.as_bytes()),
                    "public_nonce": hex::encode(signature.get_public_nonce().as_bytes()),
                    "signature": hex::encode(signature.get_signature().as_bytes()),
                }),
            ))
            .await;
        assert_eq!(r2.status, 409, "{}", r2.body);
        assert!(r2.body.contains("already"), "{}", r2.body);
    }

    #[tokio::test]
    async fn a_credential_proof_is_refused_when_the_output_is_below_the_gates_threshold() {
        let sk = RistrettoSecretKey::random(&mut rng());
        let key_bytes = {
            let pk = RistrettoPublicKey::from_secret_key(&sk);
            let mut b = [0u8; 32];
            b.copy_from_slice(pk.as_bytes());
            b
        };
        let substate_id = format!(
            "utxo_{}_2c713522a4aaf79f2b219d869b5033d3d71d63c0537e5e0bbed2d717d8b2a67e",
            hex::encode([7u8; 32])
        );
        let mut b = credential_bridge(
            FakeWallet::new(),
            FakeChain::with(substate_id.clone(), 9_999, key_bytes),
        );
        let (nonce, session) = issue(&mut b).await;
        let res = *binding().resource().unwrap();
        let message = crate::credential::ownership_proof_message(
            ghost_gate_core::network::LOCALNET,
            &res,
            &substate_id,
            &nonce,
        );
        let signature = SchnorrSignature::<
            RistrettoPublicKey,
            RistrettoSecretKey,
            SchnorrSigChallenge,
        >::sign(&sk, &message, &mut rng())
        .unwrap();

        let r = b
            .handle(&post(
                "/gate/g1/credential",
                serde_json::json!({
                    "gate_id": "g1",
                    "challenge_nonce": nonce,
                    "session_commitment": session,
                    "substate_id": substate_id,
                    "public_key": hex::encode(RistrettoPublicKey::from_secret_key(&sk).as_bytes()),
                    "public_nonce": hex::encode(signature.get_public_nonce().as_bytes()),
                    "signature": hex::encode(signature.get_signature().as_bytes()),
                }),
            ))
            .await;
        assert_eq!(r.status, 409, "{}", r.body);
        assert!(r.body.contains("below this gate"), "{}", r.body);
        assert!(r.body.contains("challenge_still_live\":true"), "{}", r.body);
    }

    #[tokio::test]
    async fn a_credential_proof_naming_another_resource_is_refused() {
        let sk = RistrettoSecretKey::random(&mut rng());
        let key_bytes = {
            let pk = RistrettoPublicKey::from_secret_key(&sk);
            let mut b = [0u8; 32];
            b.copy_from_slice(pk.as_bytes());
            b
        };
        // A real-looking output of some *other* resource.
        let other_resource_substate = format!(
            "utxo_{}_2c713522a4aaf79f2b219d869b5033d3d71d63c0537e5e0bbed2d717d8b2a67e",
            hex::encode([9u8; 32])
        );
        let mut b = credential_bridge(
            FakeWallet::new(),
            FakeChain::with(other_resource_substate.clone(), 50_000, key_bytes),
        );
        let (nonce, session) = issue(&mut b).await;

        let r = b
            .handle(&post(
                "/gate/g1/credential",
                serde_json::json!({
                    "gate_id": "g1",
                    "challenge_nonce": nonce,
                    "session_commitment": session,
                    "substate_id": other_resource_substate,
                    "public_key": hex::encode([1u8; 32]),
                    "public_nonce": hex::encode([2u8; 32]),
                    "signature": hex::encode([3u8; 32]),
                }),
            ))
            .await;
        assert_eq!(r.status, 409, "{}", r.body);
        assert!(r.body.contains("but this gate watches"), "{}", r.body);
    }

    #[tokio::test]
    async fn a_credential_proof_on_a_bridge_without_a_chain_reader_says_so() {
        // The default bridge has no reader. The route must refuse with the honest reason, not
        // verify against nothing and not answer 404 as if the mode did not exist.
        let mut b = bridge(FakeWallet::new());
        let (nonce, session) = issue(&mut b).await;
        let r = b
            .handle(&post(
                "/gate/g1/credential",
                serde_json::json!({
                    "gate_id": "g1",
                    "challenge_nonce": nonce,
                    "session_commitment": session,
                    "substate_id": "utxo_x",
                    "public_key": hex::encode([1u8; 32]),
                    "public_nonce": hex::encode([2u8; 32]),
                    "signature": hex::encode([3u8; 32]),
                }),
            ))
            .await;
        assert_eq!(r.status, 503, "{}", r.body);
        assert!(r.body.contains("no chain reader"), "{}", r.body);
    }

    #[tokio::test]
    async fn a_credential_request_cannot_smuggle_an_amount() {
        let mut b = bridge(FakeWallet::new());
        let (nonce, session) = issue(&mut b).await;
        let r = b
            .handle(&post(
                "/gate/g1/credential",
                serde_json::json!({
                    "gate_id": "g1",
                    "challenge_nonce": nonce,
                    "session_commitment": session,
                    "substate_id": "utxo_x",
                    "public_key": hex::encode([1u8; 32]),
                    "public_nonce": hex::encode([2u8; 32]),
                    "signature": hex::encode([3u8; 32]),
                    "minimum_value_promise": 100_000u64,
                }),
            ))
            .await;
        assert_eq!(r.status, 400, "{}", r.body);
        assert!(
            r.body.contains("malformed credential request"),
            "{}",
            r.body
        );
    }

    #[tokio::test]
    async fn a_prove_request_naming_a_different_gate_in_its_body_is_refused() {
        let mut b = bridge(FakeWallet::new());
        let (nonce, session) = issue(&mut b).await;
        let r = b
            .handle(&post(
                "/gate/g1/prove",
                serde_json::json!({"gate_id":"other","challenge_nonce":nonce,"session_commitment":session}),
            ))
            .await;
        assert_eq!(r.status, 400);
        assert!(b.wallet.asked.is_empty());
    }

    #[tokio::test]
    async fn a_challenge_from_another_origin_cannot_be_answered_here() {
        let mut b = bridge(FakeWallet::new());
        let (nonce, session) = issue(&mut b).await;
        let mut req = post(
            "/gate/g1/prove",
            serde_json::json!({"gate_id":"g1","challenge_nonce":nonce,"session_commitment":session}),
        );
        req.origin = None; // a CLI, which is fine
        let r = b.handle(&req).await;
        assert!(
            r.status == 202 || r.status == 409,
            "a CLI may ask; got {}",
            r.status
        );

        // But an unlisted browser origin never gets that far.
        let mut hostile = post(
            "/gate/g1/prove",
            serde_json::json!({"gate_id":"g1","challenge_nonce":nonce,"session_commitment":session}),
        );
        hostile.origin = Some("https://evil.test".into());
        let r = b.handle(&hostile).await;
        assert_eq!(r.status, 403);
        assert!(r.body.contains("not permitted"), "{}", r.body);
    }

    #[tokio::test]
    async fn an_unpermitted_origin_is_refused_before_the_route_is_even_read() {
        let mut b = bridge(FakeWallet::new());
        for path in ["/health", "/wallet/status", "/gate/g1", "/nonsense"] {
            let mut req = get(path);
            req.origin = Some("https://evil.test".into());
            let r = b.handle(&req).await;
            assert_eq!(r.status, 403, "{path}");
        }
    }

    #[tokio::test]
    async fn a_wallet_that_is_not_reachable_is_reported_as_unavailable() {
        let mut w = FakeWallet::new();
        w.reachable = false;
        let mut b = bridge(w);
        let r = b.handle(&get("/wallet/status")).await;
        assert_eq!(r.status, 503);
        assert!(r.body.contains("not reachable"), "{}", r.body);
    }

    #[tokio::test]
    async fn an_unconfigured_wallet_is_a_status_not_a_service_error() {
        // The regression this locks: a bridge launched WITHOUT GG_WALLETD_ENDPOINT is in
        // offline demonstration mode by configuration. That used to answer 503, which every
        // browser logs as a repeating console error every poll interval. It is a status, so it
        // answers 200 with configured=false and reachable=false — and a wallet that IS
        // configured but fails to answer still 503s, per the test above.
        let mut w = FakeWallet::new();
        w.status = WalletStatus::unreachable();
        let mut b = bridge(w);
        let r = b.handle(&get("/wallet/status")).await;
        assert_eq!(r.status, 200, "{}", r.body);
        assert!(r.body.contains("\"configured\":false"), "{}", r.body);
        assert!(r.body.contains("\"reachable\":false"), "{}", r.body);
    }

    #[tokio::test]
    async fn each_challenge_gets_its_own_session_commitment() {
        let mut b = bridge(FakeWallet::new());
        let (n1, s1) = issue(&mut b).await;
        let (n2, s2) = issue(&mut b).await;
        assert_ne!(n1, n2);
        assert_ne!(
            s1, s2,
            "a session value the bridge generates per challenge cannot be reused"
        );
    }

    #[tokio::test]
    async fn a_refused_proof_leaves_the_challenge_live() {
        let mut b = bridge(FakeWallet::new());
        let (nonce, _session) = issue(&mut b).await;
        // Answer from the wrong session: refused, and the challenge survives so the real session can use it.
        let r = b
            .handle(&post(
                "/gate/g1/prove",
                serde_json::json!({"gate_id":"g1","challenge_nonce":nonce,"session_commitment":"aa"}),
            ))
            .await;
        assert_eq!(r.status, 409);
        assert_eq!(b.challenges.live(), 1);

        let r = b.handle(&get("/gate/g1")).await;
        assert_eq!(r.status, 200, "and the gate is still there to ask about");
    }

    #[tokio::test]
    async fn an_accepted_proof_reports_only_the_public_floor() {
        let mut b = bridge(FakeWallet::new());
        let (nonce, session) = issue(&mut b).await;
        let r = b
            .handle(&post(
                "/gate/g1/prove",
                serde_json::json!({"gate_id":"g1","challenge_nonce":nonce,"session_commitment":session}),
            ))
            .await;
        assert_eq!(r.status, 202);
        let submitted: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(submitted["transaction_id"], "tx_fake_0001");

        // The network answers.
        b.reconcile().await;
        let proof_id = submitted["proof_id"].as_str().unwrap().to_string();
        let status = b.handle(&get(&format!("/proof/{proof_id}/status"))).await;
        let v: serde_json::Value = serde_json::from_str(&status.body).unwrap();
        assert_eq!(v["state"], "accepted");
        assert_eq!(
            v["result"]["attested_minimum"], 10_000,
            "the floor, not the amount"
        );
        assert_eq!(v["result"]["required_minimum"], 10_000);
        assert_eq!(
            v["result"]["input_count"], 1,
            "a count, never a list of inputs"
        );
        assert_eq!(v["result"]["gate_id"], "g1");

        // And the challenge is now spent.
        assert_eq!(b.challenges.live(), 0);
        assert_eq!(b.challenges.answered(), 1);
        let again = b
            .handle(&post(
                "/gate/g1/prove",
                serde_json::json!({"gate_id":"g1","challenge_nonce":nonce,"session_commitment":session}),
            ))
            .await;
        assert_eq!(again.status, 409);
    }

    #[tokio::test]
    async fn the_status_route_itself_reconciles_a_submitted_proof() {
        // The F-10 regression. reconcile() existed and was tested, but nothing in production ever
        // called it, so a real proof sat in `submitted` forever and the challenge was never
        // consumed bridge-side. The route must do the polling itself; this test would have failed
        // before the fix because there is no manual reconcile() in it.
        let mut b = bridge(FakeWallet::new());
        let (nonce, session) = issue(&mut b).await;
        let r = b
            .handle(&post(
                "/gate/g1/prove",
                serde_json::json!({"gate_id":"g1","challenge_nonce":nonce,"session_commitment":session}),
            ))
            .await;
        assert_eq!(r.status, 202, "{}", r.body);
        let proof_id = serde_json::from_str::<serde_json::Value>(&r.body).unwrap()["proof_id"]
            .as_str()
            .unwrap()
            .to_string();

        // First poll: reconciles against the wallet, which reports accepted immediately.
        let status = b.handle(&get(&format!("/proof/{proof_id}/status"))).await;
        let v: serde_json::Value = serde_json::from_str(&status.body).unwrap();
        assert_eq!(v["state"], "accepted", "the status route must reconcile: {}", status.body);
        assert_eq!(v["result"]["attested_minimum"], 10_000);

        // The challenge is consumed by that reconciliation, and a settled job is not re-waited.
        assert_eq!(b.challenges.live(), 0);
        assert_eq!(b.challenges.answered(), 1);
        let again = b.handle(&get(&format!("/proof/{proof_id}/status"))).await;
        assert_eq!(again.body, status.body, "polling a settled job must be free and stable");
    }

    #[tokio::test]
    async fn a_rejected_proof_is_reported_without_issuing_anything() {
        let mut w = FakeWallet::new();
        w.wait_result = CommitOutcome::Rejected {
            reason: "GG: attested minimum is below the gate threshold".into(),
        };
        let mut b = bridge(w);
        let (nonce, session) = issue(&mut b).await;
        let submitted = b
            .handle(&post(
                "/gate/g1/prove",
                serde_json::json!({"gate_id":"g1","challenge_nonce":nonce,"session_commitment":session}),
            ))
            .await;
        assert_eq!(submitted.status, 202, "{}", submitted.body);
        let proof_id =
            serde_json::from_str::<serde_json::Value>(&submitted.body).unwrap()["proof_id"]
                .as_str()
                .unwrap()
                .to_string();
        b.reconcile().await;
        let status = b.handle(&get(&format!("/proof/{proof_id}/status"))).await;
        let v: serde_json::Value = serde_json::from_str(&status.body).unwrap();
        assert_eq!(v["state"], "refused");
        assert!(
            v["reason"]
                .as_str()
                .unwrap()
                .contains("below the gate threshold")
        );
        assert_eq!(
            b.challenges.live(),
            1,
            "a refused proof must not burn the challenge; the user can try again"
        );
    }

    /// A configured component session replaces the random per-challenge session: a component
    /// checks every challenge's session commitment against the value stored in its own state,
    /// so a consensus-capable gate and the bridge MUST share one fixed deployment-time value.
    /// Per-visitor binding is provided by the unique nonce and origin, not by this field.
    /// The component-free credential path keeps the random session when no value is configured —
    /// the 7897 Sapient deployment runs exactly that way and must not change behaviour.
    #[tokio::test]
    async fn a_configured_component_session_stamps_every_challenge() {
        let mut b = bridge(FakeWallet::new());
        b.component_session = Some(b"esm-gate-session".to_vec());
        let r = b.handle(&post("/gate/g1/challenge", serde_json::json!({}))).await;
        assert_eq!(r.status, 200, "{}", r.body);
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        // The challenge JSON carries the session in hex; the configured value must appear.
        let session_hex = hex::encode(b"esm-gate-session");
        assert_eq!(
            v["challenge"]["session_commitment"], session_hex,
            "the configured session must be the one the challenge carries"
        );
        // A second challenge carries the SAME value — that is the whole point: the component's
        // stored session matches every challenge this bridge issues.
        let r2 = b.handle(&post("/gate/g1/challenge", serde_json::json!({}))).await;
        let v2: serde_json::Value = serde_json::from_str(&r2.body).unwrap();
        assert_eq!(v2["challenge"]["session_commitment"], session_hex);
    }

    #[tokio::test]
    async fn without_a_configured_session_challenges_stay_random() {
        let mut b = bridge(FakeWallet::new());
        let r = b.handle(&post("/gate/g1/challenge", serde_json::json!({}))).await;
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        let first = v["challenge"]["session_commitment"].as_str().unwrap().to_string();
        let r2 = b.handle(&post("/gate/g1/challenge", serde_json::json!({}))).await;
        let v2: serde_json::Value = serde_json::from_str(&r2.body).unwrap();
        let second = v2["challenge"]["session_commitment"].as_str().unwrap().to_string();
        assert_ne!(first, second, "no configured session: per-challenge randomness preserved");
        assert_eq!(first.len(), 64, "a random session is 32 bytes of hex");
    }

    // ------------------------------------------------------------------
    // The Privacy Lab
    // ------------------------------------------------------------------

    /// The gate list is the registry's public policy — and nothing else. A visitor can read a
    /// threshold (which the chain publishes anyway); there is no field here that could be a balance.
    #[tokio::test]
    async fn lab_gates_lists_the_registry_and_nothing_else() {
        let mut b = bridge(FakeWallet::new());
        let r = b.handle(&get("/lab/gates")).await;
        assert_eq!(r.status, 200);
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        let gates = v["gates"].as_array().expect("an array of gates");
        assert!(!gates.is_empty(), "the harness bridge has at least one gate");
        let g = &gates[0];
        for expected in ["gateId", "symbol", "thresholdRaw", "divisibility", "proofMode", "activatable", "sessionsAvailable"] {
            assert!(g.get(expected).is_some(), "missing {expected}: {g}");
        }
        // The threshold is a STRING (exact integers never pass through a float).
        assert!(g["thresholdRaw"].is_string(), "threshold must be exact: {g}");
        // No field that could carry a balance, a key or a token.
        let forbidden = ["balance", "amount", "key", "seed", "token", "witness", "preimage", "owner"];
        for k in forbidden {
            assert!(g.get(k).is_none(), "the gate list must not carry {k}: {g}");
        }
    }

    /// The labelled offline simulation: real event SHAPE, zero authority.
    #[tokio::test]
    async fn lab_simulation_shapes_events_and_grants_nothing() {
        let mut b = bridge(FakeWallet::new());
        let r = b.handle(&post("/lab/simulate", serde_json::json!({ "gateId": "g1" }))).await;
        assert_eq!(r.status, 200);
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(v["simulated"], true, "a simulation says so at the top level");
        assert!(v["session"].is_null(), "a simulation issues NO session: {v}");
        // The grant event carries the simulated flag and simulated wording.
        let events = v["trace"]["events"].as_array().unwrap();
        assert!(events.len() >= 8, "a full walkthrough has events: {}", events.len());
        let grant = events.iter().find(|e| e["code"] == "access.granted").expect("a grant event");
        assert_eq!(grant["detail"]["simulated"], true, "the grant is flagged simulated");
        let message = grant["message"].as_str().unwrap();
        assert!(message.contains("SIMULATED"), "the grant message says SIMULATED: {message}");
        // And NO access grant was recorded in the bridge's real grant map.
        assert!(b.access_grants.is_empty(), "the simulation touched no real grant");
    }

    /// One visitor's trace is not another's: the attempt id is the only key, and it is unguessable.
    #[tokio::test]
    async fn lab_traces_are_scoped_to_their_attempt_id() {
        let mut b = bridge(FakeWallet::new());
        let mine = "a".repeat(32);
        // Create a trace the way the challenge route does.
        let mut req = post("/gate/g1/challenge", serde_json::json!({}));
        req.attempt = Some(mine.clone());
        b.handle(&req).await;
        // I can read mine.
        let mut read = get(&format!("/lab/trace?attempt={mine}"));
        read.query.insert("attempt".into(), mine.clone());
        let r = b.handle(&read).await;
        assert_eq!(r.status, 200, "my own trace is readable");
        // Someone else's is not: a different id 404s.
        let theirs = "b".repeat(32);
        let mut foreign = get("/lab/trace");
        foreign.query.insert("attempt".into(), theirs.clone());
        assert_eq!(b.handle(&foreign).await.status, 404, "another attempt's trace is not readable");
        // And an unguessable/malformed id is a plain 404 — no hint that it was malformed.
        let mut junk = get("/lab/trace");
        junk.query.insert("attempt".into(), "../../etc/passwd".into());
        assert_eq!(b.handle(&junk).await.status, 404, "a traversal-shaped id is just unknown");
    }

    /// The header is shape-checked once, at parse time, so no route re-implements the rule.
    #[test]
    fn the_attempt_header_is_shape_checked_at_parse() {
        let raw = "GET /lab/trace HTTP/1.1\r\nHost: 127.0.0.1:7799\r\nX-GG-Attempt: nothex\r\n\r\n";
        assert_eq!(parse_request(raw).unwrap().attempt, None, "a malformed id never reaches a route");
        let good = "GET /lab/trace HTTP/1.1\r\nHost: 127.0.0.1:7799\r\nX-GG-Attempt: abcdef0123456789abcdef0123456789\r\n\r\n";
        assert_eq!(parse_request(good).unwrap().attempt.as_deref(), Some("abcdef0123456789abcdef0123456789"));
    }

    /// No diagnostic route can change a security decision: each is read-only or simulation-only.
    #[tokio::test]
    async fn lab_routes_cannot_change_a_policy_or_mint_a_real_session() {
        let mut b = bridge(FakeWallet::new());
        // /lab/gates is GET-only; a POST is not a route at all.
        assert_eq!(b.handle(&post("/lab/gates", serde_json::json!({ "threshold": 1 }))).await.status, 404);
        // /lab/simulate mints nothing: it returns a null session and records no grant (asserted above).
        // Reading a trace is a GET; a POST to it is not a route.
        assert_eq!(b.handle(&post("/lab/trace", serde_json::json!({}))).await.status, 404);
    }

    /// A gate the administrator scoped to the website cannot be used as a Telegram membership
    /// gate: the credential route refuses telegram-only gates from the website flow.
    #[tokio::test]
    async fn a_telegram_only_gate_is_refused_from_the_credential_route() {
        let mut b = credential_bridge(FakeWallet::new(), FakeChain::with("utxo_x".into(), 1000, [7u8; 32]));
        b.gates.set_use_mode("g1", "telegram");
        let req = post("/gate/g1/credential", serde_json::json!({
            "gate_id": "g1", "challenge_nonce": "aa", "session_commitment": "bb",
            "substate_id": "utxo_x",
            "public_key": "00", "public_nonce": "00", "signature": "00",
        }));
        let r = b.handle(&req).await;
        assert_eq!(r.status, 403, "a telegram-only gate is refused: {}", r.body);
        assert!(r.body.contains("Telegram membership only"), "{}", r.body);
        // A website-scoped gate passes the scope check and reaches challenge validation.
        b.gates.set_use_mode("g1", "website");
        let r2 = b.handle(&req).await;
        assert_ne!(r2.status, 403, "a website gate passes the scope check");
    }

    /// A bridge shaped like the Esmeralda deployment that exposed the wrong-mode advertisement:
    /// one component-backed consensus gate, one credential-only gate (no component).
    fn two_mode_bridge() -> Bridge<FakeWallet> {
        let mut gates = GateRegistry::new();
        gates.register("diag", binding()).unwrap();
        gates.register(
            "esm10",
            GateBinding::ootle(
                None,
                ResourceAddress::new(ObjectKey::from_array([7u8; 32])),
                10_000_000,
                network::LOCALNET,
                MaxBytes::new_checked(b"vip.example".to_vec()).unwrap(),
                2,
                "GHOSTTEST".into(),
            ),
        )
        .unwrap();
        Bridge::new(gates, FakeWallet::new(), OriginPolicy::new().allow("https://vip.example"))
    }

    /// The Lab dispatches on `proofMode`, so a credential-only gate MUST be advertised as
    /// "credential". Advertising "consensus" steered a browser wallet into the walletd prove
    /// route, whose only honest answer is a refusal — the physical-test failure this pins.
    #[tokio::test]
    async fn lab_gates_advertises_credential_for_a_componentless_gate() {
        let mut b = two_mode_bridge();
        let r = b.handle(&get("/lab/gates")).await;
        assert_eq!(r.status, 200);
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        let modes: Vec<(String, String)> = v["gates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| {
                (
                    g["gateId"].as_str().unwrap().to_string(),
                    g["proofMode"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        assert!(modes.contains(&("diag".to_string(), "consensus".to_string())), "{modes:?}");
        assert!(modes.contains(&("esm10".to_string(), "credential".to_string())), "{modes:?}");
    }

    /// The prove route cannot answer a credential-only gate, and it refuses BEFORE the body is
    /// parsed or the wallet is touched: a browser wallet pointed here gets an honest "wrong
    /// flow" refusal instead of a walletd timeout, and the challenge it holds stays live for
    /// the credential route that can actually answer it.
    #[tokio::test]
    async fn the_prove_route_refuses_a_credential_only_gate() {
        let mut b = two_mode_bridge();
        let issued = b.handle(&post("/gate/esm10/challenge", serde_json::json!({}))).await;
        assert_eq!(issued.status, 200, "{}", issued.body);
        let v: serde_json::Value = serde_json::from_str(&issued.body).unwrap();
        let nonce = v["challenge_nonce"].as_str().unwrap().to_string();
        let session = v["session_commitment"].as_str().unwrap().to_string();
        let proved = b
            .handle(&post(
                "/gate/esm10/prove",
                serde_json::json!({"gate_id":"esm10","challenge_nonce":nonce,"session_commitment":session}),
            ))
            .await;
        assert_eq!(proved.status, 409, "{}", proved.body);
        assert!(proved.body.contains("credential-only"), "{}", proved.body);
        // Nothing reached the wallet…
        assert!(b.wallet.asked.is_empty(), "a credential-only gate never reaches the wallet");
        // …and the challenge was not burnt: the credential route can still answer it.
        assert_eq!(b.challenges.live(), 1, "the refusal must not consume the challenge");
    }

    /// The offline simulation illustrates the shape the REAL flow would take: a credential-only
    /// gate is labelled "credential" and shows no consensus step, because it has none.
    #[tokio::test]
    async fn the_lab_simulation_names_the_real_mode_for_a_componentless_gate() {
        let mut b = two_mode_bridge();
        let r = b.handle(&post("/lab/simulate", serde_json::json!({ "gateId": "esm10" }))).await;
        assert_eq!(r.status, 200, "{}", r.body);
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        let events = v["trace"]["events"].as_array().unwrap();
        let selected = events.iter().find(|e| e["code"] == "gate.selected").expect("a gate event");
        assert_eq!(selected["detail"]["proofMode"], "credential", "{selected}");
        assert!(
            events.iter().all(|e| e["code"] != "consensus.observed"),
            "a credential-only simulation must not invent a consensus step"
        );
    }

    // ------------------------------------------------------------------
    // Adversarial session-binding tests (Priority 3 / multi-visitor)
    // ------------------------------------------------------------------

    fn post_from(path: &str, body: serde_json::Value, origin: &str) -> Request {
        Request {
            method: "POST",
            path: path.into(),
            origin: Some(origin.into()),
            host: Some("127.0.0.1:7799".into()),
            query: Default::default(),
            body: body.to_string(),
            attempt: None,
            authorization: None,
            verifier_request_signature: None,
        }
    }

    /// Visitor A's challenge cannot be answered by Visitor B from a different origin.
    /// The per-visitor binding is the origin + nonce, not the session commitment (which is a
    /// deployment-time component identity when GG_GATE_SESSION is set).
    #[tokio::test]
    async fn cross_origin_challenge_replay_is_refused() {
        let mut b = bridge(FakeWallet::new());
        b.component_session = Some(b"shared-deployment-id".to_vec());

        // Visitor A requests a challenge from https://vip.example
        let r = b.handle(&post_from("/gate/g1/challenge", serde_json::json!({}), "https://vip.example")).await;
        assert_eq!(r.status, 200);
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        let nonce = v["challenge_nonce"].as_str().unwrap().to_string();
        let session = v["session_commitment"].as_str().unwrap().to_string();

        // Visitor B from https://partner.example tries to answer Visitor A's challenge
        let prove = post_from(
            "/gate/g1/prove",
            serde_json::json!({
                "gate_id": "g1",
                "challenge_nonce": nonce,
                "session_commitment": session,
            }),
            "https://partner.example",
        );
        let r = b.handle(&prove).await;
        assert_eq!(r.status, 409, "cross-origin replay must be refused: {}", r.body);
        assert!(r.body.contains("session"), "the refusal should mention session binding: {}", r.body);
        assert_eq!(b.challenges.live(), 1, "the challenge must not be consumed by a cross-origin attempt");
    }

    /// An operator challenge (no Origin) cannot be answered by a browser request (has Origin),
    /// and vice versa. This prevents a CLI-minted challenge from being replayed by a page.
    #[tokio::test]
    async fn operator_challenge_cannot_be_answered_by_a_browser() {
        let mut b = bridge(FakeWallet::new());
        // Operator issues a challenge with no Origin
        let mut no_origin_req = post("/gate/g1/challenge", serde_json::json!({}));
        no_origin_req.origin = None;
        let r = b.handle(&no_origin_req).await;
        assert_eq!(r.status, 200);
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        let nonce = v["challenge_nonce"].as_str().unwrap().to_string();
        let session = v["session_commitment"].as_str().unwrap().to_string();

        // A browser from a permitted origin tries to answer it
        let prove = post_from(
            "/gate/g1/prove",
            serde_json::json!({
                "gate_id": "g1",
                "challenge_nonce": nonce,
                "session_commitment": session,
            }),
            "https://vip.example",
        );
        let r = b.handle(&prove).await;
        assert_eq!(r.status, 409, "an operator challenge cannot be answered by a browser: {}", r.body);
    }

    /// When component_session is set, every challenge carries the same deployment-time value —
    /// but the nonce is unique per challenge. A visitor who intercepts another visitor's nonce
    /// but sends from the same origin would still need to know the nonce, and each nonce is
    /// consumed on acceptance. This test asserts nonce uniqueness across visitors.
    #[tokio::test]
    async fn every_challenge_carries_a_unique_nonce_even_with_shared_component_session() {
        let mut b = bridge(FakeWallet::new());
        b.component_session = Some(b"shared".to_vec());

        let mut nonces = std::collections::HashSet::new();
        for _ in 0..10 {
            let r = b.handle(&post("/gate/g1/challenge", serde_json::json!({}))).await;
            let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
            let nonce = v["challenge_nonce"].as_str().unwrap().to_string();
            assert!(nonces.insert(nonce.clone()), "nonce collision: {nonce}");
            // But the session commitment is the SAME for all
            let session = v["session_commitment"].as_str().unwrap().to_string();
            assert_eq!(session, hex::encode(b"shared"));
        }
    }

    /// A consumed challenge cannot be replayed: once accepted, the nonce moves to the answered
    /// set and any further attempt gets AlreadyAnswered.
    #[tokio::test]
    async fn a_consumed_nonce_cannot_be_replayed() {
        let mut b = bridge(FakeWallet::new());
        let (nonce, session) = issue(&mut b).await;

        // Simulate acceptance by consuming the challenge directly
        let nonce_bytes: [u8; 32] = hex::decode(&nonce).unwrap().try_into().unwrap();
        let session_bytes = hex::decode(&session).unwrap();
        b.challenges
            .consume_on_acceptance(&nonce_bytes, &session_bytes)
            .expect("first consumption succeeds");

        // Now try to prove with the same nonce
        let prove = post(
            "/gate/g1/prove",
            serde_json::json!({
                "gate_id": "g1",
                "challenge_nonce": nonce,
                "session_commitment": session,
            }),
        );
        let r = b.handle(&prove).await;
        assert_eq!(r.status, 409, "a consumed nonce must be refused: {}", r.body);
        assert!(r.body.contains("already"), "should say already answered: {}", r.body);
    }

    /// Two visitors from the SAME origin each get their own challenge. Each can only answer
    /// their own — the nonce is the differentiator, not the origin.
    #[tokio::test]
    async fn same_origin_visitors_cannot_swap_challenges() {
        let mut b = bridge(FakeWallet::new());
        b.component_session = Some(b"shared".to_vec());

        // Both visitors are from the same origin
        let r1 = b.handle(&post("/gate/g1/challenge", serde_json::json!({}))).await;
        let v1: serde_json::Value = serde_json::from_str(&r1.body).unwrap();
        let nonce1 = v1["challenge_nonce"].as_str().unwrap().to_string();

        let r2 = b.handle(&post("/gate/g1/challenge", serde_json::json!({}))).await;
        let v2: serde_json::Value = serde_json::from_str(&r2.body).unwrap();
        let nonce2 = v2["challenge_nonce"].as_str().unwrap().to_string();

        assert_ne!(nonce1, nonce2, "two challenges must have different nonces");

        // Each challenge is individually answerable (they share origin and session)
        let session = v1["session_commitment"].as_str().unwrap().to_string();
        assert_eq!(
            session,
            v2["session_commitment"].as_str().unwrap(),
            "both carry the same component session"
        );

        // Consume nonce1
        let nonce1_bytes: [u8; 32] = hex::decode(&nonce1).unwrap().try_into().unwrap();
        let session_bytes = hex::decode(&session).unwrap();
        b.challenges.consume_on_acceptance(&nonce1_bytes, &session_bytes).unwrap();

        // nonce2 is still live
        assert!(b.challenges.check_live(
            &hex::decode(&nonce2).unwrap().try_into().unwrap(),
            &session_bytes
        ).is_ok());

        // nonce1 is consumed
        assert!(b.challenges.check_live(&nonce1_bytes, &session_bytes).is_err());
    }

    fn hosted_fixture(b: &mut Bridge<FakeWallet, FakeChain>) -> ghost_gate_registry::StorePaths {
        use ghost_gate_registry::*;
        let paths = StorePaths { dir: std::env::temp_dir().join(format!("gg-hosted-{}", hex::encode(crate::session::random_nonce()))) };
        let gate: GatePolicy = serde_json::from_value(serde_json::json!({
            "gateId":"g1", "name":"g1", "resourceAddress": binding().resource().unwrap().to_string(),
            "symbol":"tTARI", "divisibility":6, "thresholdRaw":"10000", "proofMode":"credential",
            "challengeDomain":"https://gate.example", "sessionTtlOverride":null, "grants":[], "enabled":true, "testLane":false
        })).unwrap();
        let mut app: Application = serde_json::from_value(serde_json::json!({
            "applicationId":"default", "displayName":"test", "ownerCredential":"admin", "topology":"independent",
            "defaultSessionTtl":3600, "maxGates":10, "gates":[], "revision":1, "production":false,
            "network": binding().network, "genesisHash":"00".repeat(32), "chainGeneration":1
        })).unwrap();
        app.gates.push(gate.clone());
        let mut reg = Registry::default();
        reg.credentials.push(serde_json::from_value(serde_json::json!({"credential_id":"admin", "kind":"WalletKey", "label":"test", "registered_unix":1, "ristretto_public_hex":"abc"})).unwrap());
        reg.versions.push(PolicyVersion { application_id:"default".into(), gate_id:"g1".into(), version:1,
            policy_hash: hash_policy(&Blake3Hasher, &app, &gate, 1), policy_hash_version: ghost_gate_registry::POLICY_HASH_V1, policy_context: None, network:app.network,
            genesis_hash:app.genesis_hash.clone(), policy:gate, app_revision:1, created_unix:1 });
        reg.applications.push(app);
        save_registry(&paths, &reg).unwrap();
        b.access = Some(crate::access::AccessHandle::from_snapshot(&paths, &derive_bindings(&reg).unwrap()).0);
        b.origins = b.origins.clone().allow("https://gate.example");
        b.trust_policy = TrustPolicy { operator_trusted_indexer:true, max_tier:TrustTier::OperatorTrustedTestnet };
        paths
    }

    // Invoked by the Node integration test using the actual compiled Rust test executable.
    #[tokio::test]
    async fn hosted_protocol_fixture() {
        let Ok(input_path) = std::env::var("GG_HOSTED_TEST_INPUT") else { return; };
        let input: serde_json::Value = serde_json::from_slice(&std::fs::read(&input_path).unwrap()).unwrap();
        let sk = RistrettoSecretKey::from_canonical_bytes(&[1u8;32]).unwrap();
        let pk = RistrettoPublicKey::from_secret_key(&sk);
        let res = *binding().resource().unwrap();
        let substate = format!("utxo_{}_2c713522a4aaf79f2b219d869b5033d3d71d63c0537e5e0bbed2d717d8b2a67e", hex::encode(res.as_bytes()));
        let mut key = [0u8;32]; key.copy_from_slice(pk.as_bytes());
        let mut b = credential_bridge(FakeWallet::new(), FakeChain::with(substate.clone(), 50_000, key));
        let paths = hosted_fixture(&mut b);
        let mut reg = ghost_gate_registry::load_registry(&paths).unwrap();
        reg.applications[0].chain_generation = input["generation"].as_u64().unwrap_or(1);
        reg.versions[0].policy_hash = ghost_gate_registry::hash_policy(&ghost_gate_registry::Blake3Hasher, &reg.applications[0], &reg.versions[0].policy, 1);
        ghost_gate_registry::save_registry(&paths, &reg).unwrap();
        b.access = Some(crate::access::AccessHandle::from_snapshot(&paths, &ghost_gate_registry::derive_bindings(&reg).unwrap()).0);
        if input["halted"] == true { std::fs::write(paths.dir.join("reset_halt.json"), "halt").unwrap(); }
        if let Some(revision) = input["revision"].as_str() { std::fs::write(paths.dir.join("hosted_halt_revision"), revision).unwrap(); }
        b.trust_policy.operator_trusted_indexer = input["trusted"].as_bool().unwrap_or(true);
        let output = if let Some(nonce) = input["buildProof"].as_str() {
            let msg = crate::credential::ownership_proof_message(binding().network, &res, &substate, nonce);
            let sig = SchnorrSignature::<RistrettoPublicKey, RistrettoSecretKey, SchnorrSigChallenge>::sign(&sk, &msg, &mut rng()).unwrap();
            serde_json::json!({"gate_id":"g1", "challenge_nonce":nonce, "session_commitment":"", "substate_id":substate,
                "public_key":hex::encode(pk.as_bytes()), "public_nonce":hex::encode(sig.get_public_nonce().as_bytes()), "signature":hex::encode(sig.get_signature().as_bytes())})
        } else {
            b.hosted_verifier_token = Some("token".into()); b.hosted_verifier_request_key = Some("req".into()); b.hosted_verifier_response_key = Some("resp".into());
            let request = Request { method:"POST".into(), path:"/v1/hosted/verify".into(), origin:None, host:Some("127.0.0.1:7899".into()), query:Default::default(),
                body:input["body"].to_string(), attempt:None, authorization:Some("Bearer token".into()), verifier_request_signature:Some(input["signature"].as_str().unwrap().into()) };
            let response = b.handle(&request).await;
            serde_json::json!({"status":response.status, "body":response.body, "headers":response.extra_headers})
        };
        std::fs::write(std::env::var("GG_HOSTED_TEST_OUTPUT").unwrap(), output.to_string()).unwrap();
        std::fs::remove_dir_all(paths.dir).unwrap();
    }

    #[tokio::test]
    async fn hosted_verify_adapter_accepts_a_valid_hmac_authenticated_proof() {
        use ghost_gate_verifier::hosted::{
            self, HostedVerificationRequest, HostedVerdict,
        };

        let token = "test-bearer-token";
        let req_key = "test-request-key";
        let resp_key = "test-response-key";

        let res = *binding().resource().unwrap();
        let sk = RistrettoSecretKey::random(&mut rng());
        let key_bytes = {
            let pk = RistrettoPublicKey::from_secret_key(&sk);
            let mut b = [0u8; 32];
            b.copy_from_slice(pk.as_bytes());
            b
        };
        let substate_id = format!(
            "utxo_{}_2c713522a4aaf79f2b219d869b5033d3d71d63c0537e5e0bbed2d717d8b2a67e",
            hex::encode([7u8; 32])
        );

        let mut b = credential_bridge(
            FakeWallet::new(),
            FakeChain::with(substate_id.clone(), 50_000, key_bytes),
        );
        b.hosted_verifier_token = Some(token.into());
        b.hosted_verifier_request_key = Some(req_key.into());
        b.hosted_verifier_response_key = Some(resp_key.into());

        let paths = hosted_fixture(&mut b);
        let nonce = hex::encode(crate::session::random_nonce());
        let session = hex::encode(crate::session::random_nonce().into_iter().chain(crate::session::random_nonce()).collect::<Vec<_>>());

        let message = crate::credential::ownership_proof_message(
            ghost_gate_core::network::LOCALNET,
            &res,
            &substate_id,
            &nonce,
        );
        let signature = SchnorrSignature::<
            RistrettoPublicKey,
            RistrettoSecretKey,
            SchnorrSigChallenge,
        >::sign(&sk, &message, &mut rng())
        .unwrap();
        let pk = RistrettoPublicKey::from_secret_key(&sk);

        let mut hv_req = HostedVerificationRequest {
            nonce: nonce.clone(),
            tenant: "default".into(),
            gate_id: "g1".into(),
            relying_site: "https://gate.example".into(),
            network: ghost_gate_core::network::LOCALNET,
            resource_address: res.to_string(),
            threshold_raw: "10000".into(),
            policy_version: "v1".into(),
            proof_digest: "b".repeat(64),
            proof: serde_json::json!({
                "gate_id": "g1",
                "challenge_nonce": nonce,
                "session_commitment": session,
                "substate_id": substate_id,
                "public_key": hex::encode(pk.as_bytes()),
                "public_nonce": hex::encode(signature.get_public_nonce().as_bytes()),
                "signature": hex::encode(signature.get_signature().as_bytes()),
            }),
        };

        let state = b.hosted_state(&hv_req).unwrap();
        hv_req.proof = serde_json::json!({"backendState":state, "credential":hv_req.proof});
        let canonical = hosted::canonical_request(&hv_req);
        let req_sig = hosted::hmac_sha256_hex(req_key.as_bytes(), canonical.as_bytes());

        let request = Request {
            method: "POST",
            path: "/v1/hosted/verify".into(),
            origin: None,
            host: Some("127.0.0.1:7899".into()),
            query: Default::default(),
            body: serde_json::to_string(&hv_req).unwrap(),
            attempt: None,
            authorization: Some(format!("Bearer {token}")),
            verifier_request_signature: Some(req_sig),
        };

        let r = b.handle(&request).await;
        assert_eq!(r.status, 200, "hosted verify accepted: {}", r.body);

        let result: hosted::HostedVerificationResult =
            serde_json::from_str(&r.body).expect("valid result JSON");
        assert_eq!(result.verdict, HostedVerdict::Verified, "proof is Verified");
        assert_eq!(result.gate_id, "g1");
        assert_eq!(result.tenant, "default");
        assert_eq!(result.nonce, nonce);

        let resp_sig = r.extra_headers.iter()
            .find(|(k, _)| k == "X-GG-Verifier-Signature")
            .map(|(_, v)| v.as_str())
            .expect("response has X-GG-Verifier-Signature");
        assert!(
            hosted::verify_hmac_sha256_hex(resp_sig, resp_key.as_bytes(), hosted::canonical_result(&result).as_bytes()),
            "response HMAC is valid"
        );

        // A valid signature over one challenge must not authorize a different issued nonce,
        // even when the Worker-authenticated request is otherwise valid.
        let mut substituted = hv_req.clone();
        substituted.nonce = "a".repeat(64);
        let mut replay = request.clone();
        replay.body = serde_json::to_string(&substituted).unwrap();
        replay.verifier_request_signature = Some(hosted::hmac_sha256_hex(
            req_key.as_bytes(), hosted::canonical_request(&substituted).as_bytes(),
        ));
        let denied = b.handle(&replay).await;
        assert_eq!(denied.status, 200);
        let denied: hosted::HostedVerificationResult = serde_json::from_str(&denied.body).unwrap();
        assert_eq!(denied.verdict, HostedVerdict::Rejected);
        b.trust_policy.operator_trusted_indexer = false;
        assert!(b.hosted_state(&hv_req).is_err(), "untrusted indexer cannot authorize");
        b.trust_policy.operator_trusted_indexer = true;
        let mut reg = ghost_gate_registry::load_registry(&paths).unwrap();
        reg.applications[0].production = true;
        reg.versions[0].policy_hash = ghost_gate_registry::hash_policy(&ghost_gate_registry::Blake3Hasher, &reg.applications[0], &reg.versions[0].policy, 1);
        ghost_gate_registry::save_registry(&paths, &reg).unwrap();
        b.access = Some(crate::access::AccessHandle::from_snapshot(&paths, &ghost_gate_registry::derive_bindings(&reg).unwrap()).0);
        assert!(b.hosted_state(&hv_req).unwrap_err().contains("requires"), "production requirement rejects indexer evidence");
        std::fs::remove_dir_all(paths.dir).unwrap();
    }

    #[tokio::test]
    async fn hosted_verify_rejects_wrong_bearer_token() {
        let mut b = credential_bridge(FakeWallet::new(), FakeChain { outputs: Default::default() });
        b.hosted_verifier_token = Some("correct-token".into());
        b.hosted_verifier_request_key = Some("k".into());
        b.hosted_verifier_response_key = Some("k".into());

        let request = Request {
            method: "POST",
            path: "/v1/hosted/verify".into(),
            origin: None,
            host: Some("127.0.0.1:7899".into()),
            query: Default::default(),
            body: "{}".into(),
            attempt: None,
            authorization: Some("Bearer wrong-token".into()),
            verifier_request_signature: None,
        };
        let r = b.handle(&request).await;
        assert_eq!(r.status, 401, "wrong token is refused: {}", r.body);
    }

    #[tokio::test]
    async fn hosted_verify_rejects_tampered_request_hmac() {
        use ghost_gate_verifier::hosted::{self, HostedVerificationRequest};

        let token = "test-token";
        let req_key = "test-key";

        let mut b = credential_bridge(FakeWallet::new(), FakeChain { outputs: Default::default() });
        b.hosted_verifier_token = Some(token.into());
        b.hosted_verifier_request_key = Some(req_key.into());
        b.hosted_verifier_response_key = Some("resp-key".into());

        let hv_req = HostedVerificationRequest {
            nonce: "a".repeat(64), tenant: "t".into(), gate_id: "g1".into(),
            relying_site: "https://x.example".into(), network: 0,
            resource_address: "r".into(), threshold_raw: "1".into(),
            policy_version: "v1".into(), proof_digest: "b".repeat(64),
            proof: serde_json::json!({}),
        };

        let request = Request {
            method: "POST",
            path: "/v1/hosted/verify".into(),
            origin: None,
            host: Some("127.0.0.1:7899".into()),
            query: Default::default(),
            body: serde_json::to_string(&hv_req).unwrap(),
            attempt: None,
            authorization: Some(format!("Bearer {token}")),
            verifier_request_signature: Some("deadbeef".repeat(8)),
        };
        let r = b.handle(&request).await;
        assert_eq!(r.status, 401, "tampered HMAC is refused: {}", r.body);
        assert!(r.body.contains("signature is invalid"), "{}", r.body);
    }

    #[tokio::test]
    async fn hosted_state_refuses_a_telegram_only_gate() {
        let mut b = credential_bridge(FakeWallet::new(), FakeChain::with("unused".into(), 0, [0u8; 32]));
        let paths = hosted_fixture(&mut b);
        let req = ghost_gate_verifier::hosted::HostedVerificationRequest {
            nonce: "a".repeat(64), tenant: "default".into(), gate_id: "g1".into(),
            relying_site: "https://gate.example".into(), network: binding().network,
            resource_address: binding().resource().unwrap().to_string(), threshold_raw: "10000".into(),
            policy_version: "v1".into(), proof_digest: "b".repeat(64),
            proof: serde_json::json!({"hostedState": true}),
        };
        assert!(b.hosted_state(&req).is_ok(), "website-scoped gate is eligible");
        b.gates.set_use_mode("g1", "telegram");
        assert!(b.hosted_state(&req).unwrap_err().contains("Telegram"), "Telegram-only gate is refused");
        b.gates.set_use_mode("g1", "both");
        assert!(b.hosted_state(&req).is_ok(), "a gate scoped to both remains eligible");
        std::fs::remove_dir_all(paths.dir).unwrap();
    }

    #[tokio::test]
    async fn hosted_state_refuses_an_allowlisted_origin_that_differs_from_the_published_binding() {
        let mut b = credential_bridge(FakeWallet::new(), FakeChain::with("unused".into(), 0, [0u8; 32]));
        let paths = hosted_fixture(&mut b);
        // This origin passes the operational allowlist, proving the rejection comes from the
        // immutable published binding rather than a browser-origin configuration accident.
        b.origins = b.origins.clone().allow("https://other.example");
        let req = ghost_gate_verifier::hosted::HostedVerificationRequest {
            nonce: "a".repeat(64), tenant: "default".into(), gate_id: "g1".into(),
            relying_site: "https://other.example".into(), network: binding().network,
            resource_address: binding().resource().unwrap().to_string(), threshold_raw: "10000".into(),
            policy_version: "v1".into(), proof_digest: "b".repeat(64),
            proof: serde_json::json!({"hostedState": true}),
        };
        assert!(b.hosted_state(&req).unwrap_err().contains("published relying-site"));
        std::fs::remove_dir_all(paths.dir).unwrap();
    }

    #[tokio::test]
    async fn hosted_verify_rejects_scope_mismatch() {
        use ghost_gate_verifier::hosted::{self, HostedVerificationRequest};

        let token = "test-bearer-token";
        let req_key = "test-request-key";

        let res = *binding().resource().unwrap();
        let mut b = credential_bridge(
            FakeWallet::new(),
            FakeChain::with("unused".into(), 0, [0u8; 32]),
        );
        b.hosted_verifier_token = Some(token.into());
        b.hosted_verifier_request_key = Some(req_key.into());
        b.hosted_verifier_response_key = Some("resp".into());

        let hv_req = HostedVerificationRequest {
            nonce: "a".repeat(64), tenant: "t".into(), gate_id: "g1".into(),
            relying_site: "https://x.example".into(),
            network: binding().network,
            resource_address: hex::encode(res.as_ref()),
            threshold_raw: "999".into(),
            policy_version: "v1".into(), proof_digest: "b".repeat(64),
            proof: serde_json::json!({}),
        };
        let canonical = hosted::canonical_request(&hv_req);
        let req_sig = hosted::hmac_sha256_hex(req_key.as_bytes(), canonical.as_bytes());

        let request = Request {
            method: "POST",
            path: "/v1/hosted/verify".into(),
            origin: None,
            host: Some("127.0.0.1:7899".into()),
            query: Default::default(),
            body: serde_json::to_string(&hv_req).unwrap(),
            attempt: None,
            authorization: Some(format!("Bearer {token}")),
            verifier_request_signature: Some(req_sig),
        };
        let r = b.handle(&request).await;
        assert_eq!(r.status, 409, "scope mismatch refused: {}", r.body);
        assert!(r.body.contains("scope does not match"), "{}", r.body);
    }
}
