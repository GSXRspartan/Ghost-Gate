//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! The bridge process.
//!
//! Starts, binds loopback, and refuses to start at all if it cannot do so safely:
//!
//! - it binds `127.0.0.1` and refuses a non-loopback bind address, because a bridge holding a wallet's
//!   consent must not be reachable from the network;
//! - it requires at least one permitted browser origin, because a bridge that permits none is a bridge
//!   no page can use and one that permits everything is the thing this design exists to prevent;
//! - it does not start without a gate to serve.
//!
//! # The wallet
//!
//! If `GG_WALLETD_ENDPOINT` is set, the process connects to that wallet daemon and proofs can be
//! completed. If it is not, the bridge runs with a channel that refuses every wallet operation with an
//! honest reason, and the public routes still work. The difference is stated on stderr at startup rather
//! than left to be discovered by a failed proof.

use std::process::ExitCode;

use ghost_gate_bridge::server::Bridge;
use ghost_gate_bridge::wallet::{
    CommitOutcome, StatementReply, WalletChannel, WalletError, WalletStatus,
};
use ghost_gate_bridge::xtm::{XtmChannel, XtmProofArtifact, XtmProofRequest, XtmWalletStatus};
use ghost_gate_bridge::{GateBinding, GateRegistry, OriginPolicy};
use ghost_gate_walletd::{IndexerChainReader, JsonChainReader};
use tari_template_lib_types::stealth::StealthTransferStatement;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let registry_dir = std::env::var("GG_BINDINGS_PATH").ok();
    if let Some(result) = ghost_gate_bridge::reset_guard::cli(&args, registry_dir.as_deref()) {
        return match result {
            Ok(message) => {
                println!("ghost-gate-bridge: {message}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("ghost-gate-bridge: {e}");
                ExitCode::FAILURE
            }
        };
    }
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ghost-gate-bridge: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut registry = GateRegistry::new();
    for (id, binding) in &config.gates {
        if let Err(e) = registry.register(id.clone(), binding.clone()) {
            eprintln!("ghost-gate-bridge: gate {id}: {e}");
            return ExitCode::FAILURE;
        }
        // Apply the per-gate scope here too: Config::build() records it on its own throwaway
        // registry, but the bridge's runtime registry is built in this loop, so the scope must
        // land here or the env setting silently never reaches the credential route.
        if let Ok(mode) = std::env::var(format!(
            "GG_GATE_USE_{}",
            id.to_uppercase().replace('-', "_")
        )) {
            registry.set_use_mode(id, &mode);
        }
    }

    println!("ghost-gate-bridge listening on {}", config.bind);
    println!("  gate(s): {}", config.gates.len());
    for (id, binding) in &config.gates {
        match binding.kind() {
            ghost_gate_bridge::ProofKind::Ootle => println!(
                "    {id}: [ootle] {} over {} (threshold {}, divisibility {})",
                // A credential-only gate binds no component; the banner says so instead of
                // pretending one exists.
                binding
                    .component()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "<credential-only: no component>".to_string()),
                binding.resource().copied().unwrap(),
                binding.threshold(),
                binding.divisibility
            ),
            ghost_gate_bridge::ProofKind::MinotariXtm => println!(
                "    {id}: [minotari_xtm] threshold {} micro-XTM ({} XTM)",
                binding.threshold(),
                binding.threshold() / 1_000_000
            ),
        }
    }
    println!(
        "  permitted origins: {}",
        config.origins.allowed().collect::<Vec<_>>().join(", ")
    );

    // Connect the wallet before announcing anything, so the startup line below is a report of what is
    // true rather than an intention.
    // The deployment-time session shared by component-backed gates and their on-chain component:
    // a component compares every challenge's session commitment against the value stored at
    // instantiation, so the bridge must stamp the SAME value into its challenges. Read as a
    // UTF-8 string and held only in this process; the operator sets the identical value when
    // instantiating the component.
    let component_session = std::env::var("GG_GATE_SESSION")
        .ok()
        .filter(|v| !v.trim().is_empty());
    if let Some(session) = &component_session {
        println!(
            "  component session: configured ({} bytes) — consensus gates carry the deployment-time identity; per-visitor binding is nonce + origin",
            session.len()
        );
    }
    let mut wallet = match std::env::var("GG_WALLETD_ENDPOINT") {
        Ok(endpoint) if !endpoint.trim().is_empty() => {
            let network = config
                .gates
                .first()
                .map(|(_, b)| b.network)
                .unwrap_or(ghost_gate_core::network::LOCALNET);
            let account_name = std::env::var("GG_WALLETD_ACCOUNT")
                .ok()
                .filter(|v| !v.trim().is_empty());
            match ghost_gate_walletd::WalletDaemonChannel::connect_with_account(
                &endpoint,
                std::env::var("GG_WALLETD_TOKEN")
                    .ok()
                    .filter(|t| !t.trim().is_empty()),
                network,
                fee_ceiling(),
                max_epoch(),
                account_name.clone(),
            ) {
                Ok(mut channel) => {
                    // A `none`-auth-mode walletd still demands a bearer token on account
                    // endpoints. Bootstrap one from the daemon when the operator supplied none;
                    // a daemon that requires real auth rejects this and every account call
                    // then fails closed, so there is no silent bypass either way.
                    let bootstrapped = tokio::runtime::Builder::new_multi_thread()
                        .enable_all()
                        .build()
                        .map(|rt| rt.block_on(channel.bootstrap_local_auth()))
                        .unwrap_or(false);
                    let auth_note = if std::env::var("GG_WALLETD_TOKEN")
                        .ok()
                        .filter(|t| !t.trim().is_empty())
                        .is_some()
                    {
                        "api token from GG_WALLETD_TOKEN"
                    } else if bootstrapped {
                        "local none-mode token bootstrapped"
                    } else {
                        "no token; a daemon requiring auth will refuse account calls"
                    };
                    let acct_note = account_name.as_deref().unwrap_or("default");
                    println!(
                        "  wallet daemon: {endpoint} (network byte {network}, account {acct_note}, {auth_note})"
                    );
                    AnyWallet::Live(channel)
                }
                Err(e) => {
                    // Refusing to start is the honest response: a bridge that has been told where its
                    // wallet is and cannot reach it should not serve proofs that cannot complete.
                    eprintln!("ghost-gate-bridge: cannot connect to the wallet at {endpoint}: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        _ => {
            // Stated plainly rather than discovered later: there is no wallet here, so /wallet/status
            // reports unavailable and a prove request cannot be completed. The gate metadata and
            // challenge routes are live. See docs/GATE4_RESULTS.md.
            eprintln!(
                "  note: GG_WALLETD_ENDPOINT is not set, so no wallet daemon is connected; \
                 /wallet/status will report unavailable and a proof request cannot be completed. \
                 The gate metadata and challenge routes are live."
            );
            AnyWallet::Absent(NoWallet)
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("ghost-gate-bridge: could not start a runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Probed once at startup, so a misconfigured network is visible immediately rather than at the first
    // proof. A failure here is not fatal: the wallet routes report it per-request, and the public routes
    // do not depend on it.
    match runtime.block_on(wallet.status()) {
        Ok(status) => {
            println!(
                "  wallet status: reachable={} default_account={} network={} ({})",
                status.reachable, status.has_default_account, status.network, status.network_name
            );
            let gate_network = config.gates.first().map(|(_, b)| b.network);
            if Some(status.network) != gate_network {
                eprintln!(
                    "  warning: the wallet is on network {} but the gate is bound to a different one; \
                     proofs will be refused until these agree.",
                    status.network
                );
            }
        }
        Err(e) => eprintln!(
            "  warning: the wallet did not answer a status probe ({e}); proofs will fail until it does."
        ),
    }

    // The native Minotari L1 channels. Optional by configuration; when absent, an L1 gate is
    // served for metadata and refused for challenges with an honest message (fail closed).
    let xtm_endpoint = std::env::var("GG_XTM_WALLET_ENDPOINT")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let l1_endpoint = std::env::var("GG_MINOTARI_BASE_NODE_ENDPOINT")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let has_xtm_gate = config
        .gates
        .iter()
        .any(|(_, b)| b.kind() == ghost_gate_bridge::ProofKind::MinotariXtm);

    let mut xtm_channel = AnyXtm::new(xtm_endpoint.clone(), Some(network_byte(&config.gates)));
    #[cfg(feature = "minotari-base-node")]
    let mut xtm_chain = match l1_endpoint {
        Some(endpoint) => match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("runtime: {e}"))
            .and_then(|rt| {
                rt.block_on(
                    ghost_gate_minotari::chain_reader::BaseNodeXtmReader::connect(&endpoint),
                )
                .map_err(|e| e.to_string())
            }) {
            Ok(reader) => {
                println!("  minotari base node: {endpoint} (L1 XTM verification enabled)");
                Some(reader)
            }
            Err(e) => {
                if has_xtm_gate {
                    eprintln!(
                        "ghost-gate-bridge: cannot connect to the Minotari base node at {endpoint}: {e}"
                    );
                    return ExitCode::FAILURE;
                }
                eprintln!(
                    "  note: the Minotari base node at {endpoint} is unreachable ({e}); the L1 path is disabled."
                );
                None
            }
        },
        None => {
            if has_xtm_gate {
                eprintln!(
                    "  note: GG_MINOTARI_BASE_NODE_ENDPOINT is not set, so L1 XTM challenges cannot be issued \
                     or verified; register an Ootle gate or set the endpoint."
                );
            }
            None
        }
    };
    #[cfg(not(feature = "minotari-base-node"))]
    let mut xtm_chain = {
        if l1_endpoint.is_some() && has_xtm_gate {
            eprintln!(
                "ghost-gate-bridge: GG_MINOTARI_BASE_NODE_ENDPOINT is set, but this binary was built without the \
                 minotari-base-node feature; rebuild with --features minotari-base-node"
            );
            return ExitCode::FAILURE;
        }
        if has_xtm_gate {
            eprintln!(
                "  note: live Minotari verification is not compiled in, so L1 XTM challenges cannot be issued or \
                 verified; rebuild with --features minotari-base-node."
            );
        }
        None::<ghost_gate_bridge::xtm::NoXtmChainReader>
    };
    if xtm_endpoint.is_none() && has_xtm_gate {
        eprintln!(
            "  note: GG_XTM_WALLET_ENDPOINT is not set, so no Minotari wallet daemon is connected; \
             XTM proofs will be refused with an honest message."
        );
    }

    // Probed once at startup, so an L1 gate is visible as broken immediately rather than at the
    // first proof.
    if has_xtm_gate {
        match runtime.block_on(xtm_channel.status()) {
            Ok(status) => println!(
                "  minotari wallet: reachable={} network={} spend_key={}",
                status.reachable,
                status.network,
                status.spend_public_key.as_deref().unwrap_or("-")
            ),
            Err(e) => eprintln!(
                "  warning: the Minotari wallet did not answer ({e}); XTM proofs will fail."
            ),
        }
    }

    // The credential mode needs chain reads. Optional by configuration: a bridge pointed only at
    // walletd runs without it, and its credential route says exactly that instead of verifying
    // against nothing.
    //
    // Two arms rather than one because the two bridges are different types (the reader is a type
    // parameter, not a boxed object), and unifying them would need either a second enum or trait
    // objects -- neither worth it for one if/else at startup.
    let indexer = std::env::var("GG_INDEXER_ENDPOINT")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let outcome = match indexer {
        Some(endpoint) => {
            // Which reader? Detect the cohort from the indexer's own /health version: 0.47+
            // answers `state` (the pinned 0.42 client cannot parse that), anything older parses
            // through the pinned client. Wrong-version reads are refused, never degraded.
            let version = runtime
                .block_on(async {
                    reqwest::get(format!("{}/health", endpoint.trim_end_matches('/')))
                        .await
                        .ok()?
                        .json::<serde_json::Value>()
                        .await
                        .ok()?
                        .get("version")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .unwrap_or_default();
            // Versions are "MAJOR.MINOR..." — e.g. "0.47.0" — so the minor carries the cohort
            // bump here (0.x series). Parse the SECOND component, not the first.
            let minor = version
                .split('.')
                .nth(1)
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0);
            // 0.47/0.48 used the transitional JSON value shape. The pinned 0.49 client decodes the
            // current base64-CBOR `Encoded<SubstateValue>` representation itself, so routing 0.49
            // through the legacy JSON field walker would fail closed on every UTXO.
            let json_reader = std::env::var("GG_INDEXER_JSON")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
                || (47..49).contains(&minor);
            if json_reader {
                match JsonChainReader::connect(&endpoint) {
                    Ok(reader) => {
                        println!(
                            "  indexer: {endpoint} (credential mode enabled, dual-shape JSON reader{}",
                            if version.is_empty() {
                                String::new()
                            } else {
                                format!(", indexer {version}")
                            }
                        );
                        let mut bridge = Bridge::assemble_full(
                            registry,
                            wallet,
                            config.origins,
                            reader,
                            xtm_channel,
                            xtm_chain,
                        );
                        bridge.component_session =
                            component_session.clone().map(String::into_bytes);
                        if let Err(e) = attach_access_plane(&mut bridge) {
                            eprintln!("ghost-gate-bridge: {e}");
                            return ExitCode::FAILURE;
                        }
                        configure_tunnel_support(&mut bridge);
                        let recovered = runtime.block_on(bridge.recover_pending_jobs());
                        if recovered > 0 {
                            println!(
                                "  replay recovery: resumed {recovered} durable Ootle finality job(s)"
                            );
                        }
                        runtime.block_on(ghost_gate_bridge::server::serve(&config.bind, bridge))
                    }
                    Err(e) => {
                        eprintln!(
                            "ghost-gate-bridge: cannot connect to the indexer at {endpoint}: {e}"
                        );
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                match IndexerChainReader::connect(&endpoint) {
                    Ok(reader) => {
                        println!("  indexer: {endpoint} (credential mode enabled)");
                        let mut bridge = Bridge::assemble_full(
                            registry,
                            wallet,
                            config.origins,
                            reader,
                            xtm_channel,
                            xtm_chain,
                        );
                        bridge.component_session =
                            component_session.clone().map(String::into_bytes);
                        if let Err(e) = attach_access_plane(&mut bridge) {
                            eprintln!("ghost-gate-bridge: {e}");
                            return ExitCode::FAILURE;
                        }
                        configure_tunnel_support(&mut bridge);
                        let recovered = runtime.block_on(bridge.recover_pending_jobs());
                        if recovered > 0 {
                            println!(
                                "  replay recovery: resumed {recovered} durable Ootle finality job(s)"
                            );
                        }
                        runtime.block_on(ghost_gate_bridge::server::serve(&config.bind, bridge))
                    }
                    Err(e) => {
                        eprintln!(
                            "ghost-gate-bridge: cannot connect to the indexer at {endpoint}: {e}"
                        );
                        return ExitCode::FAILURE;
                    }
                }
            }
        }
        None => {
            eprintln!(
                "  note: GG_INDEXER_ENDPOINT is not set, so the credential proof mode (browser \
                 wallets) is disabled; the consensus mode through walletd is unaffected."
            );
            let mut bridge = Bridge::<
                AnyWallet,
                ghost_gate_bridge::credential::NoChainReader,
                AnyXtm,
                _,
            >::with_xtm_full(
                registry, wallet, config.origins, xtm_channel, xtm_chain
            );
            bridge.component_session = component_session.clone().map(String::into_bytes);
            if let Err(e) = attach_access_plane(&mut bridge) {
                eprintln!("ghost-gate-bridge: {e}");
                return ExitCode::FAILURE;
            }
            configure_tunnel_support(&mut bridge);
            let recovered = runtime.block_on(bridge.recover_pending_jobs());
            if recovered > 0 {
                println!("  replay recovery: resumed {recovered} durable Ootle finality job(s)");
            }
            runtime.block_on(ghost_gate_bridge::server::serve(&config.bind, bridge))
        }
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ghost-gate-bridge: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The fee ceiling offered for a proof transaction.
///
/// An upper bound, not a target: the prover pays the difference back. Sized well above a localnet proof's
/// real cost so a proof is never refused for want of fee headroom, and overridable because a mainnet fee
/// ceiling would not be the same number.
fn fee_ceiling() -> u64 {
    std::env::var("GG_MAX_FEE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000)
}

/// The last epoch in which a proof transaction may be sequenced.
///
/// Clamped to each challenge's own `expires_epoch` before a transaction is built, so this is only ever
/// the outer bound.
fn max_epoch() -> u64 {
    std::env::var("GG_MAX_EPOCH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100)
}

/// Which wallet the bridge is using, chosen once at startup.
///
/// An enum rather than a `Box<dyn WalletChannel>` because `WalletChannel` has native `async fn`
/// methods, which makes it deliberately not object-safe: `Bridge<W>` is generic over `W` precisely so
/// no boxing or `async_trait` is needed. Dispatching on two known variants keeps that property instead
/// of undoing it to hold one runtime choice.
enum AnyWallet {
    /// A connected wallet daemon, in the `ghost-gate-walletd` crate.
    Live(ghost_gate_walletd::WalletDaemonChannel),
    /// No wallet configured.
    Absent(NoWallet),
}

impl WalletChannel for AnyWallet {
    async fn status(&mut self) -> Result<WalletStatus, WalletError> {
        match self {
            Self::Live(w) => w.status().await,
            Self::Absent(w) => w.status().await,
        }
    }
    async fn build_statement(
        &mut self,
        request: ghost_gate_bridge::StatementRequest,
    ) -> Result<StatementReply, WalletError> {
        match self {
            Self::Live(w) => w.build_statement(request).await,
            Self::Absent(w) => w.build_statement(request).await,
        }
    }
    async fn submit(
        &mut self,
        gate: &str,
        challenge: &ghost_gate_core::Challenge,
        statement: &StealthTransferStatement,
        lock_id: &str,
    ) -> Result<String, WalletError> {
        match self {
            Self::Live(w) => w.submit(gate, challenge, statement, lock_id).await,
            Self::Absent(w) => w.submit(gate, challenge, statement, lock_id).await,
        }
    }
    async fn wait(
        &mut self,
        transaction_id: &str,
        timeout: std::time::Duration,
    ) -> Result<CommitOutcome, WalletError> {
        match self {
            Self::Live(w) => w.wait(transaction_id, timeout).await,
            Self::Absent(w) => w.wait(transaction_id, timeout).await,
        }
    }
}

/// A wallet channel that is deliberately not connected.
///
/// Exists so the bridge can start, serve its public routes and refuse the rest with an honest reason,
/// rather than not existing at all. Every method says the same thing, which is the truth: there is no
/// wallet here.
struct NoWallet;

impl WalletChannel for NoWallet {
    async fn status(&mut self) -> Result<WalletStatus, WalletError> {
        // Not configured is a STATUS, not a failure: the bridge was launched without
        // GG_WALLETD_ENDPOINT (offline demonstration mode), which is a configuration the
        // operator chose. Answering 503 here turned a permanent, intentional state into a
        // repeating service error in every browser's console. A wallet that IS configured but
        // fails to answer still errors, and still 503s at the route — that case is unchanged.
        Ok(WalletStatus::unreachable())
    }
    async fn build_statement(
        &mut self,
        _request: ghost_gate_bridge::StatementRequest,
    ) -> Result<StatementReply, WalletError> {
        Err(WalletError::Unreachable(
            "no wallet daemon is connected to this build".into(),
        ))
    }
    async fn submit(
        &mut self,
        _gate: &str,
        _challenge: &ghost_gate_core::Challenge,
        _statement: &StealthTransferStatement,
        _lock_id: &str,
    ) -> Result<String, WalletError> {
        Err(WalletError::Unreachable(
            "no wallet daemon is connected to this build".into(),
        ))
    }
    async fn wait(
        &mut self,
        _transaction_id: &str,
        _timeout: std::time::Duration,
    ) -> Result<CommitOutcome, WalletError> {
        Err(WalletError::Unreachable(
            "no wallet daemon is connected to this build".into(),
        ))
    }
}

/// Startup configuration, read from the environment.
///
/// Environment rather than a config file so that nothing on disk holds a gate's policy, and so an
/// operator can see the whole configuration in the process's own command line.
struct Config {
    bind: String,
    origins: OriginPolicy,
    gates: Vec<(String, GateBinding)>,
}

impl Config {
    fn from_env() -> Result<Self, String> {
        let bind = std::env::var("GG_BRIDGE_BIND").unwrap_or_else(|_| "127.0.0.1:7799".to_string());
        // The one hard requirement on the bind address. Everything else about the address is up to the
        // operator; whether it is loopback is not.
        let host = bind.split(':').next().unwrap_or("");
        if !matches!(host, "127.0.0.1" | "localhost" | "[::1]" | "::1") {
            return Err(format!(
                "GG_BRIDGE_BIND must be a loopback address, got {bind:?}. A bridge holds a wallet's \
                 consent and must not be reachable from the network."
            ));
        }

        let origins_raw = std::env::var("GG_BRIDGE_ORIGINS").map_err(|_| {
            "GG_BRIDGE_ORIGINS must list at least one permitted browser origin".to_string()
        })?;
        let origins: OriginPolicy = origins_raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .fold(OriginPolicy::new(), |p, o| p.allow(o));
        if origins.allowed().next().is_none() {
            return Err("GG_BRIDGE_ORIGINS must list at least one permitted browser origin".into());
        }

        // A registry-backed bridge (GG_BINDINGS_PATH set) takes its gates from the admin plane's
        // authoritative snapshot, so the env var is optional there: the dashboard is the operator's
        // interface, not this variable. Without the registry, the env var remains required —
        // a bridge with no gates at all would be a silent no-op.
        let registry_backed = std::env::var("GG_BINDINGS_PATH")
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        let gates_raw = match std::env::var("GG_BRIDGE_GATES") {
            Ok(v) if !v.trim().is_empty() => v,
            _ if registry_backed => String::new(),
            _ => {
                return Err("GG_BRIDGE_GATES must name at least one gate (id=gate_address:resource:threshold:divisibility),                             or set GG_BINDINGS_PATH to run registry-backed from the admin plane"
                    .into())
            }
        };
        let mut gates = Vec::new();
        for entry in gates_raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            gates.push(parse_gate(entry)?);
        }
        if gates.is_empty() && !registry_backed {
            return Err("GG_BRIDGE_GATES must name at least one gate".into());
        }

        let mut registry = GateRegistry::new();
        for (id, binding) in &gates {
            registry
                .register(id.clone(), binding.clone())
                .map_err(|e| format!("gate {id}: {e}"))?;
            // Per-gate scope: the credential mode (browser wallets + Telegram) only answers for
            // gates the operator explicitly scopes to it. Env form: GG_GATE_USE_<ID>=telegram.
            // Unset means "website" — the safe default that never grants Telegram membership.
            if let Ok(mode) = std::env::var(format!(
                "GG_GATE_USE_{}",
                id.to_uppercase().replace('-', "_")
            )) {
                registry.set_use_mode(id, &mode);
            }
        }

        Ok(Self {
            bind,
            origins,
            gates: gates
                .into_iter()
                .map(|(id, _)| {
                    let b = registry.get(&id).expect("just registered").clone();
                    (id, b)
                })
                .collect(),
        })
    }
}

/// Parses `id=gate_address:resource_address:threshold:divisibility:symbol` for an Ootle gate, or
/// `id=xtm:threshold_micro:symbol` for a native Minotari L1 gate.
///
/// The L1 form's `xtm:` prefix is what makes the two unambiguous. A threshold there is in
/// **micro-Minotari**: `1000000000000` is 1,000,000 XTM. A `1_000_000`-shaped XTM figure with
/// guessed decimal math is exactly the error this format exists to prevent — write base units.
fn parse_gate(entry: &str) -> Result<(String, GateBinding), String> {
    let (id, rest) = entry
        .split_once('=')
        .ok_or_else(|| format!("{entry:?} is missing id="))?;
    if rest.starts_with("xtm:") {
        let parts: Vec<&str> = rest.split(':').collect();
        if parts.len() < 3 {
            return Err(format!("{entry:?} needs id=xtm:threshold_micro:symbol"));
        }
        let threshold_micro: u64 = parts[1]
            .parse()
            .map_err(|e| format!("threshold (micro-Minotari base units): {e}"))?;
        return Ok((
            id.to_string(),
            GateBinding::minotari_xtm(
                threshold_micro,
                std::env::var("GG_MINOTARI_NETWORK")
                    .ok()
                    .and_then(|v| u8::from_str_radix(v.trim_start_matches("0x"), 16).ok())
                    .unwrap_or(ghost_gate_core::network::LOCALNET),
                tari_template_lib_types::MaxBytes::new_checked(b"vip.example".to_vec())
                    .expect("short"),
                parts[2..].join(":"),
            ),
        ));
    }
    let parts: Vec<&str> = rest.split(':').collect();
    if parts.len() < 5 {
        return Err(format!(
            "{entry:?} needs id=gate_address:resource_address:threshold:divisibility:symbol \
             (an empty gate_address registers a credential-only gate)"
        ));
    }
    // An empty gate address registers a credential-only gate: no on-chain component is bound,
    // and the challenge carries the NO_COMPONENT sentinel. The consensus path cannot run on
    // such a gate — which is exactly the point: the credential path verifies against chain
    // state and needs no component at all.
    let component = if parts[0].trim().is_empty() {
        None
    } else {
        if !parts[0].starts_with("component_") {
            return Err(format!(
                "gate address must start with component_ (or be empty for a credential-only gate), got {:?}",
                parts[0]
            ));
        }
        Some(parts[0].parse().map_err(|e| format!("gate address: {e}"))?)
    };
    if !parts[1].starts_with("resource_") {
        return Err(format!(
            "the second field must be a resource ADDRESS starting with resource_, got {:?}. A gate binds \
             to an address, never to a symbol.",
            parts[1]
        ));
    }
    Ok((
        id.to_string(),
        GateBinding::ootle(
            component,
            parts[1]
                .parse()
                .map_err(|e| format!("resource address: {e}"))?,
            parts[2].parse().map_err(|e| format!("threshold: {e}"))?,
            std::env::var("GG_OOTLE_NETWORK")
                .ok()
                .and_then(|v| u8::from_str_radix(v.trim_start_matches("0x"), 16).ok())
                .unwrap_or(ghost_gate_core::network::LOCALNET),
            tari_template_lib_types::MaxBytes::new_checked(b"vip.example".to_vec()).expect("short"),
            parts[3].parse().map_err(|e| format!("divisibility: {e}"))?,
            parts[4..].join(":"),
        ),
    ))
}

/// The network byte the bridge's gates are bound to. XTM gates share the Ootle byte table, so
/// the first gate's byte is the whole story for a single-network deployment; a mixed deployment
/// is refused at parse time before this is ever consulted.
fn network_byte(gates: &[(String, GateBinding)]) -> u8 {
    gates
        .first()
        .map(|(_, b)| b.network)
        .unwrap_or(ghost_gate_core::network::LOCALNET)
}

/// Which Minotari wallet channel the bridge is using, chosen once at startup.
///
/// The same enum-dispatch pattern as [`AnyWallet`]: the `XtmChannel` trait has native `async fn`
/// methods and is deliberately not object-safe.
enum AnyXtm {
    /// A connected proof wallet service (the `ghost-gate-minotari-wallet` binary).
    Live(ghost_gate_minotari::http::HttpXtmChannel),
    /// No Minotari wallet configured: every L1 proof is refused with an honest reason.
    Absent(ghost_gate_bridge::xtm::NoXtm),
}

impl AnyXtm {
    fn new(endpoint: Option<String>, expected_network: Option<u8>) -> Self {
        match endpoint {
            Some(endpoint) => Self::Live(ghost_gate_minotari::http::HttpXtmChannel::new(
                endpoint,
                expected_network,
            )),
            None => Self::Absent(ghost_gate_bridge::xtm::NoXtm),
        }
    }
}

impl XtmChannel for AnyXtm {
    async fn status(&mut self) -> Result<XtmWalletStatus, WalletError> {
        match self {
            Self::Live(w) => w.status().await,
            Self::Absent(w) => w.status().await,
        }
    }

    async fn create_proof_transaction(
        &mut self,
        request: XtmProofRequest,
    ) -> Result<XtmProofArtifact, WalletError> {
        match self {
            Self::Live(w) => w.create_proof_transaction(request).await,
            Self::Absent(w) => w.create_proof_transaction(request).await,
        }
    }

    async fn rebroadcast(&mut self, transaction_id: u64) -> Result<(), WalletError> {
        match self {
            Self::Live(w) => w.rebroadcast(transaction_id).await,
            Self::Absent(w) => w.rebroadcast(transaction_id).await,
        }
    }
}

/// Attaches the verified-access plane when GG_BINDINGS_PATH names the admin registry's data
/// directory. Refuses to start on a corrupt snapshot (fail closed), rebuilds the gate registry
/// from the authoritative snapshot — the admin plane becomes the only source of gate policy —
/// and reports how many gates the registry bound.
///
/// A bridge without GG_BINDINGS_PATH keeps working exactly as before: the env-configured path is
/// not affected by any of this.
fn attach_access_plane<W, R, X, XR>(bridge: &mut Bridge<W, R, X, XR>) -> Result<(), String>
where
    W: ghost_gate_bridge::wallet::WalletChannel,
    R: ghost_gate_bridge::credential::ChainReader,
    X: ghost_gate_bridge::xtm::XtmChannel,
    XR: ghost_gate_bridge::xtm::XtmChainReader,
{
    // The operator trust policy applies to every registry-backed deployment. It can only LOWER a
    // derived tier: GG_OPERATOR_TRUSTED_INDEXER=1 lets the indexer's self-reported `verified` flag
    // support non-production (OperatorTrustedTestnet) sessions, and GG_MAX_TRUST_TIER caps the
    // result. Absent both, credential (indexer-asserted) evidence stays Development and issues no
    // session — fail-closed by default. Production is never reachable from an indexer assertion.
    let trust_policy = ghost_gate_registry::TrustPolicy::parse(
        std::env::var("GG_OPERATOR_TRUSTED_INDEXER").ok().as_deref(),
        std::env::var("GG_MAX_TRUST_TIER").ok().as_deref(),
    );
    bridge.set_trust_policy(trust_policy);
    if trust_policy.operator_trusted_indexer {
        println!(
            "  trust policy: operator vouches for the configured indexer (indexer-asserted evidence may reach operator-trusted-testnet)"
        );
    }

    let Some(dir) = std::env::var("GG_BINDINGS_PATH")
        .ok()
        .filter(|v| !v.trim().is_empty())
    else {
        return Ok(());
    };
    // The env var names the registry's data directory (where bindings.json lives).
    let paths = ghost_gate_registry::StorePaths::new(std::path::Path::new(&dir));
    let snapshot = match ghost_gate_registry::load_bindings(&paths)? {
        Some(s) => s,
        None => {
            return Err(format!(
                "GG_BINDINGS_PATH is set but no bindings file exists at {}",
                paths.bindings().display()
            ));
        }
    };
    let (mut handle, count) =
        ghost_gate_bridge::access::AccessHandle::from_snapshot(&paths, &snapshot);
    let mut registry = GateRegistry::new();
    let mut bound = 0usize;
    for snap in &snapshot.gates {
        // Test-lane gates never bind the production listener: a test session is issued by the
        // bridge only for gates whose access info says test_lane, and this loop keeps even the
        // public challenge routes of a test gate off this process.
        if snap.test_lane {
            continue;
        }
        let binding = ghost_gate_bridge::access::binding_from_snapshot(snap)?;
        registry
            .register(snap.gate_id.clone(), binding)
            .map_err(|e| format!("gate {}: {e}", snap.gate_id))?;
        bound += 1;
    }
    bridge.gates = registry;
    handle
        .plane
        .apply_revocations(&snapshot.revoked_session_prefixes)?;
    bridge.access = Some(handle);
    // Registry-backed bridges issue real access sessions. They must also coordinate replay state
    // durably; selecting MemoryReplayStore here would turn a restart into a second authorization.
    let replay_dir = std::env::var("GG_REPLAY_STORE_PATH")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "GG_BINDINGS_PATH enables real sessions and therefore requires GG_REPLAY_STORE_PATH; refusing a process-local replay fallback".to_string())?;
    let replay = ghost_gate_bridge::replay_store::FileReplayStore::open(&replay_dir)
        .map_err(|error| format!("cannot open durable replay store at {replay_dir:?}: {error}"))?;
    bridge.set_replay_store(Box::new(replay));
    println!(
        "  access plane: registry-backed ({bound} of {count} snapshot gates bound; {} revocation prefixes; durable local replay store configured)",
        snapshot.revoked_session_prefixes.len()
    );
    Ok(())
}

fn configure_tunnel_support<W, R, X, XR>(bridge: &mut Bridge<W, R, X, XR>)
where
    W: ghost_gate_bridge::wallet::WalletChannel,
    R: ghost_gate_bridge::credential::ChainReader,
    X: ghost_gate_bridge::xtm::XtmChannel,
    XR: ghost_gate_bridge::xtm::XtmChainReader,
{
    if let Ok(hosts) = std::env::var("GG_BRIDGE_PERMITTED_HOSTS") {
        for host in hosts.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            bridge.permitted_hosts.insert(host.to_lowercase());
            println!("  permitted host (tunnel): {host}");
        }
    }

    let token = std::env::var("GG_VERIFIER_TOKEN")
        .ok()
        .filter(|v| !v.is_empty());
    let req_key = std::env::var("GG_VERIFIER_REQUEST_KEY")
        .ok()
        .filter(|v| !v.is_empty());
    let resp_key = std::env::var("GG_VERIFIER_RESPONSE_KEY")
        .ok()
        .filter(|v| !v.is_empty());
    if token.is_some() && req_key.is_some() && resp_key.is_some() {
        bridge.hosted_verifier_token = token;
        bridge.hosted_verifier_request_key = req_key;
        bridge.hosted_verifier_response_key = resp_key;
        println!("  hosted verifier adapter: enabled (POST /v1/hosted/verify)");
    }
}
