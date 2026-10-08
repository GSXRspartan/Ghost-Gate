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

use std::process::ExitCode;

use tari_template_lib_types::stealth::StealthTransferStatement;

use ghost_gate_bridge::server::Bridge;
use ghost_gate_bridge::wallet::{
    CommitOutcome, StatementReply, WalletChannel, WalletError, WalletStatus,
};
use ghost_gate_bridge::{GateBinding, GateRegistry, OriginPolicy};

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
        println!(
            "    {id}: {} over {} (threshold {}, divisibility {})",
            binding.address, binding.resource, binding.threshold, binding.divisibility
        );
    }
    println!(
        "  permitted origins: {}",
        config.origins.allowed().collect::<Vec<_>>().join(", ")
    );
    // Stated plainly rather than discovered later: the wallet channel below is not connected to a live
    // walletd, so /wallet/status reports unavailable and a prove request cannot reach a wallet. The
    // policy in front of it is real and tested; the transport is DESIGN_ONLY. See docs/GATE4_RESULTS.md.
    eprintln!(
        "  note: no wallet daemon is connected; /wallet/status will report unavailable and a proof \
         request cannot be completed. The gate metadata and challenge routes are live."
    );

    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("ghost-gate-bridge: could not start a runtime: {e}");
            return ExitCode::FAILURE;
        },
    };

    let bridge = Bridge::new(registry, NoWallet, config.origins);
    match runtime.block_on(ghost_gate_bridge::server::serve(&config.bind, bridge)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ghost-gate-bridge: {e}");
            ExitCode::FAILURE
        },
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
        Err(WalletError::Unreachable("no wallet daemon is connected to this build".into()))
    }
    async fn build_statement(&mut self, _request: ghost_gate_bridge::StatementRequest) -> Result<StatementReply, WalletError> {
        Err(WalletError::Unreachable("no wallet daemon is connected to this build".into()))
    }
    async fn submit(
        &mut self,
        _gate: &str,
        _statement: &StealthTransferStatement,
        _lock_id: &str,
    ) -> Result<String, WalletError> {
        Err(WalletError::Unreachable("no wallet daemon is connected to this build".into()))
    }
    async fn wait(&mut self, _transaction_id: &str, _timeout: std::time::Duration) -> Result<CommitOutcome, WalletError> {
        Err(WalletError::Unreachable("no wallet daemon is connected to this build".into()))
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

        let origins_raw = std::env::var("GG_BRIDGE_ORIGINS")
            .map_err(|_| "GG_BRIDGE_ORIGINS must list at least one permitted browser origin".to_string())?;
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
        for entry in gates_raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
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

/// Parses `id=gate_address:resource_address:threshold:divisibility:symbol`.
///
/// The resource is named by **address**, never by symbol. The symbol is display only and is read last
/// so that a caller cannot accidentally supply a name where an address belongs and have it accepted.
fn parse_gate(entry: &str) -> Result<(String, GateBinding), String> {
    let (id, rest) = entry.split_once('=').ok_or_else(|| format!("{entry:?} is missing id="))?;
    let parts: Vec<&str> = rest.split(':').collect();
    if parts.len() < 5 {
        return Err(format!(
            "{entry:?} needs id=gate_address:resource_address:threshold:divisibility:symbol"
        ));
    }
    if !parts[0].starts_with("component_") {
        return Err(format!("gate address must start with component_, got {:?}", parts[0]));
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
        GateBinding {
            address: parts[0].parse().map_err(|e| format!("gate address: {e}"))?,
            resource: parts[1].parse().map_err(|e| format!("resource address: {e}"))?,
            threshold: parts[2].parse().map_err(|e| format!("threshold: {e}"))?,
            network: ghost_gate_core::network::LOCALNET,
            relying_site: tari_template_lib_types::MaxBytes::new_checked(b"vip.example".to_vec())
                .expect("short"),
            divisibility: parts[3].parse().map_err(|e| format!("divisibility: {e}"))?,
            symbol: parts[4..].join(":"),
        },
    ))
}
