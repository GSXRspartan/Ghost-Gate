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

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::gate_registry::GateRegistry;
use crate::http::{Request, Response, Route, parse_request, render};
use crate::origin::OriginPolicy;
use crate::policy::{ProveRequest, validate_prove_request};
use crate::session::{ChallengeBook, ProofJob, ProofStatus, PublicProof, random_nonce};
use crate::wallet::{StatementRequest, WalletChannel};

/// Largest request body accepted. A prove request is three short strings; anything larger is not one.
pub const MAX_BODY: usize = 8 * 1024;

/// Everything the server needs, assembled once at startup.
pub struct Bridge<
    W: WalletChannel,
    R: crate::credential::ChainReader = crate::credential::NoChainReader,
> {
    pub gates: GateRegistry,
    pub challenges: ChallengeBook,
    pub jobs: Vec<ProofJob>,
    pub wallet: W,
    pub origins: OriginPolicy,
    /// How long a freshly minted challenge stays answerable.
    pub challenge_ttl: Duration,
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
}

impl<W: WalletChannel> Bridge<W, crate::credential::NoChainReader> {
    pub fn new(gates: GateRegistry, wallet: W, origins: OriginPolicy) -> Self {
        Self {
            gates,
            challenges: ChallengeBook::new(),
            jobs: Vec::new(),
            wallet,
            origins,
            challenge_ttl: crate::session::DEFAULT_CHALLENGE_TTL,
            asset_dir: std::path::PathBuf::from("web"),
            chain: None,
            permitted_hosts: default_permitted_hosts(),
        }
    }
}

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

impl<W: WalletChannel, R: crate::credential::ChainReader> Bridge<W, R> {
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
            challenges: ChallengeBook::new(),
            jobs: Vec::new(),
            wallet,
            origins,
            challenge_ttl: crate::session::DEFAULT_CHALLENGE_TTL,
            asset_dir: std::path::PathBuf::from("web"),
            chain: Some(chain),
            permitted_hosts: default_permitted_hosts(),
        }
    }

    /// Handles one request. Pure with respect to the process: it returns what to send.
    pub async fn handle(&mut self, request: &Request) -> Response {
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

            Route::Asset(name) => self.serve_asset(name),
            Route::Challenge(id) => self.issue_challenge(id),
            Route::Prove(id) => self.prove(id, request).await,
            Route::Credential(id) => self.credential(id, request).await,
            Route::ProofStatus(id) => match self.jobs.iter().find(|j| j.id == id) {
                Some(job) => Response::json(200, &job.status),
                None => Response::error(404, "GG: no such proof"),
            },
            Route::NotFound => Response::error(404, "GG: no such route"),
        }
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
                | "vendor/tari-connector.js"
                | "vendor/tari-dapp.d.ts"
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
                    "index.html" => "text/html; charset=utf-8",
                    "app.css" => "text/css; charset=utf-8",
                    // A declaration file is source text, not JavaScript.
                    "vendor/tari-dapp.d.ts" => "text/plain; charset=utf-8",
                    _ => "text/javascript; charset=utf-8",
                },
                body: String::from_utf8_lossy(&bytes).to_string(),
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
    fn issue_challenge(&mut self, id: &str) -> Response {
        if self.gates.get(id).is_none() {
            return Response::error(404, "GG: no such gate");
        }
        let session = random_nonce();
        let issued = match self
            .gates
            .issue_challenge(id, &mut self.challenges, &session, self.challenge_ttl)
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
        // The challenge's own fields are named rather than serialised as a blob, so a relying site reads
        // the binding it is about to rely on. `gate` and `resource` are addresses, not names.
        Response::json(
            200,
            &serde_json::json!({
                "challenge": serde_json::json!({
                    "gate": issued.challenge.gate.to_string(),
                    "resource": issued.challenge.resource.to_string(),
                    "threshold": issued.challenge.threshold,
                    "network": issued.challenge.network,
                    "nonce": crate::policy::nonce_to_hex(&issued.challenge.nonce),
                    "expires_epoch": issued.challenge.expires_epoch,
                    "relying_site": hex::encode(issued.challenge.relying_site.as_slice()),
                    "session_commitment": hex::encode(issued.challenge.session_commitment.as_slice()),
                }),
                "challenge_nonce": crate::policy::nonce_to_hex(&issued.challenge.nonce),
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
        let Some(chain) = self.chain.as_ref() else {
            return Response::error(
                503,
                "GG: this bridge has no chain reader configured, so credential proofs cannot be verified. \
                 Set GG_INDEXER_ENDPOINT to enable the credential mode.",
            );
        };

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

        // The challenge string the wallet signed is the exact string the challenge route returned
        // and the page passed through: the lowercase hex of the nonce. Reconstruction, not trust.
        let nonce_hex = crate::policy::nonce_to_hex(&challenge.nonce);
        let verifier = crate::credential::CredentialVerifier {
            network: gate.network,
            threshold: gate.threshold,
            resource: &gate.resource,
            challenge_string: &nonce_hex,
        };

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
                        challenge.session_commitment.as_slice(),
                    );
                }
                let job_id = hex::encode(&crate::session::random_nonce()[..8]);
                self.jobs.push(ProofJob {
                    id: job_id.clone(),
                    gate_id: id.to_string(),
                    challenge_nonce: challenge.nonce.into_array(),
                    status: ProofStatus::CredentialAccepted {
                        result: Box::new(receipt.clone()),
                    },
                    started_at: std::time::SystemTime::now(),
                });
                Response::json(
                    200,
                    &serde_json::json!({
                        "state": "accepted",
                        "proof_id": job_id,
                        "receipt": receipt,
                    }),
                )
            }
            Err(refusal) => Response::json(
                409,
                &serde_json::json!({
                    "refused": refusal.to_string(),
                    "challenge_still_live": true,
                }),
            ),
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
        let parsed: ProveRequest = match serde_json::from_str(&request.body) {
            Ok(v) => v,
            Err(e) => return Response::error(400, format!("GG: malformed proof request: {e}")),
        };
        // The gate id in the body must be the gate id in the path, so a caller cannot POST to one gate
        // and name another.
        if parsed.gate_id != id {
            return Response::error(400, "GG: the request's gate_id does not match the path");
        }

        let challenge = match validate_prove_request(&gate, &self.challenges, &parsed) {
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

        let job_id_bytes = random_nonce();
        let job_id = hex::encode(&job_id_bytes[..8]);
        let nonce = challenge.nonce.into_array();
        self.jobs.push(ProofJob {
            id: job_id.clone(),
            gate_id: id.to_string(),
            challenge_nonce: nonce,
            status: ProofStatus::Preparing,
            started_at: std::time::SystemTime::now(),
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
            resource: gate.resource,
            input_revealed: tari_template_lib_types::Amount::from(gate.threshold),
            minimum_value_promise: gate.threshold,
            selection: crate::wallet::InputChoice::Named(Vec::new()),
        };

        let reply = match self.wallet.build_statement(statement).await {
            Ok(r) => r,
            Err(e) => {
                self.set_status(
                    &job_id,
                    ProofStatus::Failed {
                        reason: e.to_string(),
                    },
                );
                return Response::json(202, &serde_json::json!({ "proof_id": job_id }));
            }
        };

        match self
            .wallet
            .submit(
                &gate.address.to_string(),
                &challenge,
                &reply.statement,
                &reply.lock_id,
            )
            .await
        {
            Ok(transaction_id) => {
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
                Response::json(202, &serde_json::json!({ "proof_id": job_id }))
            }
        }
    }

    /// Polls the network for a submitted proof and retires the challenge only on acceptance.
    pub async fn reconcile(&mut self) {
        let pending: Vec<(usize, String)> = self
            .jobs
            .iter()
            .enumerate()
            .filter_map(|(i, j)| match &j.status {
                ProofStatus::Submitted { transaction_id } => Some((i, transaction_id.clone())),
                _ => None,
            })
            .collect();

        for (index, transaction_id) in pending {
            let gate_id = self.jobs[index].gate_id.clone();
            let nonce = self.jobs[index].challenge_nonce;
            match self
                .wallet
                .wait(&transaction_id, Duration::from_secs(120))
                .await
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
                                .map(|e| e.challenge.session_commitment.as_slice().to_vec())
                                .unwrap_or_default(),
                        )
                        .ok();
                    let binding = self.gates.get(&gate_id).cloned();
                    self.jobs[index].status = ProofStatus::Accepted {
                        result: PublicProof {
                            gate_id: gate_id.clone(),
                            gate_address: binding
                                .as_ref()
                                .map(|g| g.address.to_string())
                                .unwrap_or_default(),
                            resource_address: binding
                                .as_ref()
                                .map(|g| g.resource.to_string())
                                .unwrap_or_default(),
                            required_minimum: binding
                                .as_ref()
                                .map(|g| g.threshold)
                                .unwrap_or_default(),
                            attested_minimum,
                            input_count,
                            challenge_nonce: hex::encode(nonce),
                            transaction_id,
                        },
                    };
                }
                Ok(crate::wallet::CommitOutcome::Rejected { reason }) => {
                    self.jobs[index].status = ProofStatus::Refused { reason };
                }
                Ok(crate::wallet::CommitOutcome::Pending) => {}
                Err(e) => {
                    self.jobs[index].status = ProofStatus::Failed {
                        reason: e.to_string(),
                    };
                }
            }
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
pub async fn serve<W, R>(addr: &str, bridge: Bridge<W, R>) -> std::io::Result<()>
where
    W: WalletChannel + Send + 'static,
    R: crate::credential::ChainReader + Send + 'static,
{
    let listener = TcpListener::bind(addr).await?;
    let bridge = Arc::new(tokio::sync::Mutex::new(bridge));
    loop {
        let (mut socket, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => continue,
        };

        let mut buf = vec![0u8; MAX_BODY + 2048];
        let read = match socket.read(&mut buf).await {
            Ok(0) => {
                let _ = socket.shutdown().await;
                continue;
            }
            Ok(n) => n,
            Err(_) => {
                let _ = socket.shutdown().await;
                continue;
            }
        };
        let raw = String::from_utf8_lossy(&buf[..read]).to_string();

        let response = match parse_request(&raw) {
            Some(request) => {
                let mut bridge = bridge.lock().await;
                bridge.handle(&request).await
            }
            None => Response::error(400, "GG: malformed request"),
        };

        let _ = socket.write_all(render(&response).as_bytes()).await;
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
                    reachable: true,
                    has_default_account: true,
                    network: network::LOCALNET,
                    network_name: "localnet".into(),
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
        GateBinding {
            address: ComponentAddress::new(ObjectKey::from_array([1u8; 32])),
            resource: ResourceAddress::new(ObjectKey::from_array([7u8; 32])),
            threshold: 10_000,
            network: network::LOCALNET,
            relying_site: MaxBytes::new_checked(b"vip.example".to_vec()).unwrap(),
            divisibility: 2,
            symbol: "GHOSTTEST".into(),
        }
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
            address: &tari_template_lib_types::UtxoAddress,
        ) -> Result<crate::credential::UtxoOnChain, String> {
            // The production reader looks the UTXO up by its full string form; the fake keys on
            // exactly what the caller will send.
            match self.outputs.get(&address.to_string()) {
                Some(o) => Ok(o.clone()),
                None => Err("InputSubstateIsDown".into()),
            }
        }
    }

    fn credential_bridge(wallet: FakeWallet, chain: FakeChain) -> Bridge<FakeWallet, FakeChain> {
        let mut gates = GateRegistry::new();
        gates.register("g1", binding()).unwrap();
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
        Bridge::new(
            gates,
            wallet,
            OriginPolicy::new().allow("https://vip.example"),
        )
    }

    fn get(path: &str) -> Request {
        Request {
            method: "GET",
            path: path.into(),
            origin: Some("https://vip.example".into()),
            host: Some("127.0.0.1:7799".into()),
            body: String::new(),
        }
    }

    fn post(path: &str, body: serde_json::Value) -> Request {
        Request {
            method: "POST",
            path: path.into(),
            origin: Some("https://vip.example".into()),
            host: Some("127.0.0.1:7799".into()),
            body: body.to_string(),
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
        assert_eq!(v["resource_address"], binding().resource.to_string());
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
                body: "{}".into(),
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
            vec![(binding().resource, binding().threshold)]
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
        assert_eq!(gate, &binding().address.to_string());
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
                body: body.into(),
            };
            let r = b.handle(&req).await;
            assert_eq!(r.status, 403, "{method} {path}: {}", r.body);
            assert!(r.body.contains("loopback"), "{method} {path}: {}", r.body);
        }
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
                body: "{}".into(),
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
            body: "{}".into(),
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
        let res = binding().resource;
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
        let res = binding().resource;
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
}
