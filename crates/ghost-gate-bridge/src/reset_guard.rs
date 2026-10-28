//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! A durable, latching reset guard.
//!
//! An Ootle L2 testnet reset can leave the L1 genesis, the network byte and even the native
//! resource address unchanged (see `ghost_gate_core::policy::effective_generation`), so the bridge
//! cannot detect a reset from those. What it CAN do is watch the indexer's self-reported identity
//! for a discontinuity and, on a confirmed one, latch a halt that refuses new issuance until an
//! operator has reviewed the situation and migrated the chain generation forward.
//!
//! The indexer's `/identity` report is UNTRUSTED. It is used only in the safe direction: a
//! confirmed discontinuity can STOP issuance, but a "normal" report never establishes trust and
//! never clears a halt. Errors, missing fields and small epoch lag are treated conservatively — as
//! inconclusive — so a transient blip neither latches a false reset nor clears a real one.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// What the bridge observed about the indexer's self-reported identity. Every field is untrusted
/// transport data; `reachable` is false when the probe could not complete at all.
#[derive(Debug, Clone)]
pub struct ObservedIdentity {
    pub reachable: bool,
    pub network_byte: Option<u8>,
    pub sidechain_id: Option<String>,
    pub current_epoch: Option<u64>,
}

/// The identity the operator configured for the live chain generation, plus the freshness policy
/// for epoch regression.
#[derive(Debug, Clone)]
pub struct ExpectedIdentity {
    pub network_byte: u8,
    pub sidechain_id: Option<String>,
    /// The highest epoch previously observed as consistent, if any — the regression baseline.
    pub last_good_epoch: Option<u64>,
    /// How far an observed epoch may fall below `last_good_epoch` and still be treated as node lag
    /// rather than a reset. A reset restarts the epoch counter near zero, so the tell is a large
    /// drop, not a small one.
    pub epoch_lag_tolerance: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainIdentityVerdict {
    /// Observed identity matches expectations. Safe to proceed — but this NEVER clears an existing
    /// halt; only an explicit operator acknowledgment does that.
    Consistent,
    /// A confirmed discontinuity: a reset is suspected. This is the only verdict that latches.
    SuspectedReset { reason: String },
    /// Could not confirm either way (unreachable, missing field, small lag). Conservative: neither
    /// latch a new halt nor clear an existing one.
    Inconclusive { reason: String },
}

/// Compare an observed indexer identity against the operator's expectation. Pure and conservative:
/// only an unambiguous change (network byte or sidechain id) or a large epoch regression is a
/// suspected reset; anything uncertain is inconclusive.
pub fn assess_chain_identity(
    expected: &ExpectedIdentity,
    observed: &ObservedIdentity,
) -> ChainIdentityVerdict {
    if !observed.reachable {
        return ChainIdentityVerdict::Inconclusive { reason: "indexer unreachable".into() };
    }
    match observed.network_byte {
        Some(n) if n != expected.network_byte => {
            return ChainIdentityVerdict::SuspectedReset {
                reason: format!(
                    "indexer network byte 0x{:02x} does not match the expected 0x{:02x}",
                    n, expected.network_byte
                ),
            };
        }
        None => {
            return ChainIdentityVerdict::Inconclusive {
                reason: "indexer reported no network byte".into(),
            };
        }
        _ => {}
    }
    match (&expected.sidechain_id, &observed.sidechain_id) {
        (Some(e), Some(o)) if e != o => {
            return ChainIdentityVerdict::SuspectedReset {
                reason: "indexer sidechain id does not match the expected one".into(),
            };
        }
        // An expected sidechain id with none reported is a conservative "cannot confirm", not proof.
        (Some(_), None) => {
            return ChainIdentityVerdict::Inconclusive {
                reason: "indexer reported no sidechain id".into(),
            };
        }
        _ => {}
    }
    match (expected.last_good_epoch, observed.current_epoch) {
        (Some(last), Some(now)) => {
            // A reset restarts the epoch counter, so an observed epoch far BELOW the last known
            // good one is the tell. A small drop within tolerance is node lag, not a reset.
            if now.saturating_add(expected.epoch_lag_tolerance) < last {
                ChainIdentityVerdict::SuspectedReset {
                    reason: format!(
                        "indexer epoch {now} regressed well below the last observed {last}"
                    ),
                }
            } else {
                ChainIdentityVerdict::Consistent
            }
        }
        (_, None) => ChainIdentityVerdict::Inconclusive {
            reason: "indexer reported no current epoch".into(),
        },
        // No baseline yet: a first observation cannot be a regression.
        (None, Some(_)) => ChainIdentityVerdict::Consistent,
    }
}

/// The durable, latching halt record. Its presence on disk means issuance is halted; it survives a
/// restart because it is a file, and it is removed only by an explicit operator acknowledgment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResetHalt {
    pub reason: String,
    pub first_seen_unix: u64,
    pub observed_network: Option<u8>,
    pub observed_epoch: Option<u64>,
}

/// Read the halt, if any. A corrupt file is treated as a halt with an explanatory reason rather
/// than ignored: an unreadable guard must fail closed, not open.
pub fn load_halt(path: &Path) -> Option<ResetHalt> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice::<ResetHalt>(&bytes) {
        Ok(halt) => Some(halt),
        Err(_) => Some(ResetHalt {
            reason: "the reset-halt file is present but unreadable; refusing to issue".into(),
            first_seen_unix: 0,
            observed_network: None,
            observed_epoch: None,
        }),
    }
}

/// Whether issuance is currently halted.
pub fn is_halted(path: &Path) -> bool {
    path.exists()
}

/// Latch a halt durably. The FIRST observation is preserved: if a halt file already exists it is
/// kept unchanged, so the original evidence survives and a later blip cannot overwrite it. The
/// write is atomic (temp + rename) so a crash cannot leave a torn guard.
pub fn latch_halt(path: &Path, halt: &ResetHalt) -> Result<(), String> {
    if path.exists() {
        return Ok(());
    }
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // Rotate before latching; retain across clear/restart so unobserved halt/recovery retires sessions.
    rotate_hosted_revision(path)?;
    let bytes =
        serde_json::to_vec_pretty(halt).map_err(|e| format!("cannot serialise the reset halt: {e}"))?;
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, &bytes).map_err(|e| format!("cannot write the reset halt: {e}"))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("cannot install the reset halt: {e}"))?;
    Ok(())
}

fn rotate_hosted_revision(path: &Path) -> Result<(), String> {
    let revision = path.with_file_name("hosted_halt_revision");
    let tmp_revision = revision.with_extension("tmp");
    std::fs::write(&tmp_revision, hex::encode(crate::session::random_nonce()))
        .map_err(|e| format!("cannot persist hosted halt revision: {e}"))?;
    std::fs::rename(&tmp_revision, &revision).map_err(|e| e.to_string())?;
    Ok(())
}

/// Clear the halt — only with a non-empty operator acknowledgment. A halt NEVER clears implicitly:
/// not on a restart, and not because the indexer later reports normal values. The operator clears
/// it deliberately after reviewing the configuration (and, normally, migrating the generation).
pub fn clear_halt(path: &Path, operator_ack: &str) -> Result<(), String> {
    if operator_ack.trim().is_empty() {
        return Err("clearing a reset halt requires an explicit operator acknowledgment".into());
    }
    // Also retire decisions overlapping latch_halt's revision write and halt installation.
    if path.exists() { rotate_hosted_revision(path)?; }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("cannot clear the reset halt: {e}")),
    }
}

/// Operator entry point (`ghost-gate-bridge halt <reason>` / `clear-halt <ack>`). Hand-creating or
/// deleting `reset_halt.json` skips the hosted revision rotation, so hosted sessions would survive.
pub fn operator_command(registry_dir: &Path, command: &str, text: &str) -> Result<String, String> {
    let path = registry_dir.join("reset_halt.json");
    match command {
        "halt" if text.trim().is_empty() => Err("halt requires a reason".into()),
        "halt" => latch_halt(&path, &ResetHalt {
            reason: text.trim().to_string(),
            first_seen_unix: crate::session::now_unix(),
            observed_network: None,
            observed_epoch: None,
        })
        .map(|()| format!("reset halt latched at {}", path.display())),
        "clear-halt" => clear_halt(&path, text).map(|()| format!("reset halt cleared at {}", path.display())),
        other => Err(format!("unknown operator command {other}")),
    }
}

/// argv dispatch for the bridge binary. `None` means "not an operator command": start the server.
pub fn cli(args: &[String], registry_dir: Option<&str>) -> Option<Result<String, String>> {
    let command = args.first().filter(|c| matches!(c.as_str(), "halt" | "clear-halt"))?;
    let Some(dir) = registry_dir.filter(|d| !d.trim().is_empty()) else {
        return Some(Err(format!("{command} requires GG_BINDINGS_PATH (the registry data directory)")));
    };
    Some(operator_command(Path::new(dir), command, &args[1..].join(" ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_commands_rotate_the_hosted_revision_on_halt_and_recovery() {
        let dir = std::env::temp_dir().join(format!("gg-halt-cmd-{}", hex::encode(crate::session::random_nonce())));
        std::fs::create_dir_all(&dir).unwrap();
        let revision = || std::fs::read(dir.join("hosted_halt_revision")).ok();
        assert!(operator_command(&dir, "halt", "  ").is_err(), "a halt needs a reason");
        assert!(revision().is_none() && !is_halted(&dir.join("reset_halt.json")));
        operator_command(&dir, "halt", "suspected Esmeralda reset").unwrap();
        assert!(is_halted(&dir.join("reset_halt.json")));
        let latched = revision().expect("halting rotates the hosted revision");
        assert!(operator_command(&dir, "clear-halt", " ").is_err(), "recovery needs an acknowledgment");
        operator_command(&dir, "clear-halt", "operator reviewed").unwrap();
        assert!(!is_halted(&dir.join("reset_halt.json")));
        assert_ne!(revision().unwrap(), latched, "recovery rotates the hosted revision again");
        assert!(operator_command(&dir, "status", "").is_err());

        let argv = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let d = dir.to_str().unwrap();
        assert!(cli(&[], Some(d)).is_none(), "no arguments starts the server");
        assert!(cli(&argv(&["--version"]), Some(d)).is_none(), "other arguments keep the old behaviour");
        assert!(cli(&argv(&["halt", "x"]), None).unwrap().is_err(), "halt needs the registry directory");
        assert!(cli(&argv(&["halt", "x"]), Some(" ")).unwrap().is_err());
        cli(&argv(&["halt", "indexer", "epoch", "regressed"]), Some(d)).unwrap().unwrap();
        assert!(is_halted(&dir.join("reset_halt.json")));
        assert_eq!(load_halt(&dir.join("reset_halt.json")).unwrap().reason, "indexer epoch regressed");
        cli(&argv(&["clear-halt", "reviewed"]), Some(d)).unwrap().unwrap();
        assert!(!is_halted(&dir.join("reset_halt.json")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn expected() -> ExpectedIdentity {
        ExpectedIdentity {
            network_byte: 38, // Esmeralda
            sidechain_id: None,
            last_good_epoch: Some(12_537),
            epoch_lag_tolerance: 5,
        }
    }

    #[test]
    fn a_changed_network_byte_is_a_suspected_reset() {
        let v = assess_chain_identity(
            &expected(),
            &ObservedIdentity { reachable: true, network_byte: Some(37), sidechain_id: None, current_epoch: Some(3) },
        );
        assert!(matches!(v, ChainIdentityVerdict::SuspectedReset { .. }));
    }

    #[test]
    fn a_large_epoch_regression_with_the_same_network_is_a_suspected_reset() {
        // The dangerous case: network byte 38 is UNCHANGED, but the epoch counter restarted.
        let v = assess_chain_identity(
            &expected(),
            &ObservedIdentity { reachable: true, network_byte: Some(38), sidechain_id: None, current_epoch: Some(4) },
        );
        assert!(matches!(v, ChainIdentityVerdict::SuspectedReset { .. }));
    }

    #[test]
    fn small_lag_errors_and_missing_data_are_inconclusive_not_a_reset() {
        // A small drop within tolerance is node lag.
        assert_eq!(
            assess_chain_identity(&expected(), &ObservedIdentity { reachable: true, network_byte: Some(38), sidechain_id: None, current_epoch: Some(12_535) }),
            ChainIdentityVerdict::Consistent
        );
        // Unreachable / missing epoch never latch.
        assert!(matches!(
            assess_chain_identity(&expected(), &ObservedIdentity { reachable: false, network_byte: None, sidechain_id: None, current_epoch: None }),
            ChainIdentityVerdict::Inconclusive { .. }
        ));
        assert!(matches!(
            assess_chain_identity(&expected(), &ObservedIdentity { reachable: true, network_byte: Some(38), sidechain_id: None, current_epoch: None }),
            ChainIdentityVerdict::Inconclusive { .. }
        ));
    }

    #[test]
    fn a_latched_halt_survives_reload_and_only_an_explicit_ack_clears_it() {
        let dir = std::env::temp_dir().join(format!("gg-halt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("reset_halt.json");

        assert!(!is_halted(&path));
        let halt = ResetHalt { reason: "epoch regressed".into(), first_seen_unix: 100, observed_network: Some(38), observed_epoch: Some(4) };
        latch_halt(&path, &halt).unwrap();
        assert!(is_halted(&path));

        // "Restart": a fresh read still sees the halt, with the original evidence.
        assert_eq!(load_halt(&path).unwrap(), halt);

        // A later latch with different evidence does NOT overwrite the first observation.
        latch_halt(&path, &ResetHalt { reason: "something else".into(), first_seen_unix: 200, observed_network: Some(38), observed_epoch: Some(9) }).unwrap();
        assert_eq!(load_halt(&path).unwrap(), halt, "the first observation is preserved");

        // A normal indexer report does not clear it; only an explicit ack does. An empty ack fails.
        assert!(clear_halt(&path, "   ").is_err());
        assert!(is_halted(&path));
        let before = std::fs::read(path.with_file_name("hosted_halt_revision")).unwrap();
        clear_halt(&path, "operator reviewed and migrated to generation 2").unwrap();
        let after = std::fs::read(path.with_file_name("hosted_halt_revision")).unwrap();
        assert_ne!(before, after, "recovery retires decisions overlapping halt activation");
        assert!(!is_halted(&path));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
