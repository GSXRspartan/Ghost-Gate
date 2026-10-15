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
use ghost_gate_walletd::IndexerChainReader;
use tari_template_lib_types::stealth::StealthTransferStatement;

fn main() -> ExitCode {
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
    }

    println!("ghost-gate-bridge listening on {}", config.bind);
    println!("  gate(s): {}", config.gates.len());
    for (id, binding) in &config.gates {
        match binding.kind() {
            ghost_gate_bridge::ProofKind::Ootle => println!(
                "    {id}: [ootle] {} over {} (threshold {}, divisibility {})",
                binding.component().copied().unwrap(),
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
    let mut wallet = match std::env::var("GG_WALLETD_ENDPOINT") {
        Ok(endpoint) if !endpoint.trim().is_empty() => {
            let network = config
                .gates
                .first()
                .map(|(_, b)| b.network)
                .unwrap_or(ghost_gate_core::network::LOCALNET);
            match ghost_gate_walletd::WalletDaemonChannel::connect(
                &endpoint,
                std::env::var("GG_WALLETD_TOKEN").ok().filter(|t| !t.trim().is_empty()),
                network,
                fee_ceiling(),
                max_epoch(),
            ) {
                Ok(channel) => {
                    println!("  wallet daemon: {endpoint} (network byte {network})");
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
    let mut xtm_chain = match l1_endpoint {
        Some(endpoint) => match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("runtime: {e}"))
            .and_then(|rt| {
                rt.block_on(ghost_gate_minotari::chain_reader::BaseNodeXtmReader::connect(&endpoint))
                    .map_err(|e| e.to_string())
            }) {
            Ok(reader) => {
                println!("  minotari base node: {endpoint} (L1 XTM verification enabled)");
                Some(reader)
            },
            Err(e) => {
                if has_xtm_gate {
                    eprintln!("ghost-gate-bridge: cannot connect to the Minotari base node at {endpoint}: {e}");
                    return ExitCode::FAILURE;
                }
                eprintln!("  note: the Minotari base node at {endpoint} is unreachable ({e}); the L1 path is disabled.");
                None
            },
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
            Err(e) => eprintln!("  warning: the Minotari wallet did not answer ({e}); XTM proofs will fail."),
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
        Some(endpoint) => match IndexerChainReader::connect(&endpoint) {
            Ok(reader) => {
                println!("  indexer: {endpoint} (credential mode enabled)");
                let bridge = Bridge::assemble_full(registry, wallet, config.origins, reader, xtm_channel, xtm_chain);
                runtime.block_on(ghost_gate_bridge::server::serve(&config.bind, bridge))
            }
            Err(e) => {
                eprintln!("ghost-gate-bridge: cannot connect to the indexer at {endpoint}: {e}");
                return ExitCode::FAILURE;
            }
        },
        None => {
            eprintln!(
                "  note: GG_INDEXER_ENDPOINT is not set, so the credential proof mode (browser \
                 wallets) is disabled; the consensus mode through walletd is unaffected."
            );
            let bridge = Bridge::<AnyWallet, ghost_gate_bridge::credential::NoChainReader, AnyXtm, _>::with_xtm_full(registry, wallet, config.origins, xtm_channel, xtm_chain);
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
        Err(WalletError::Unreachable(
            "no wallet daemon is connected to this build".into(),
        ))
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

        let gates_raw = std::env::var("GG_BRIDGE_GATES")
            .map_err(|_| "GG_BRIDGE_GATES must name at least one gate, as id=gate_address:resource:threshold:divisibility".to_string())?;
        let mut gates = Vec::new();
        for entry in gates_raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            gates.push(parse_gate(entry)?);
        }
        if gates.is_empty() {
            return Err("GG_BRIDGE_GATES must name at least one gate".into());
        }

        let mut registry = GateRegistry::new();
        for (id, binding) in &gates {
            registry
                .register(id.clone(), binding.clone())
                .map_err(|e| format!("gate {id}: {e}"))?;
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
            "{entry:?} needs id=gate_address:resource_address:threshold:divisibility:symbol"
        ));
    }
    if !parts[0].starts_with("component_") {
        return Err(format!(
            "gate address must start with component_, got {:?}",
            parts[0]
        ));
    }
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
            parts[0].parse().map_err(|e| format!("gate address: {e}"))?,
            parts[1].parse().map_err(|e| format!("resource address: {e}"))?,
            parts[2].parse().map_err(|e| format!("threshold: {e}"))?,
            ghost_gate_core::network::LOCALNET,
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
