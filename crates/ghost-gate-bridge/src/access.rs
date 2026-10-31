//! The bridge side of verified access: read the registry's bindings snapshot, rebuild the gate
//! registry when it changes, issue sessions on accepted proofs, answer /access/check entirely
//! server-side, and honour revocations.
//!
//! Fail-closed rules:
//! - A corrupt bindings file never replaces a working registry: the last-known-good gates keep
//!   serving and the parse error is logged once.
//! - A session is bound to the policy hash it was proved under. A published replacement invalidates
//!   it: fresh evidence required, no grandfathering.
//! - A test-lane session can never authorise a production gate, whatever it proves.

use ghost_gate_core::policy::ProofMode;
use ghost_gate_registry::{AccessDecision, AccessGrant, AccessPlane, Bindings, Evidence, GateBindingSnapshot, TrustPolicy};

/// What the bridge needs to know about one bound gate, derived from the snapshot. Tier grants
/// come from the policy, resolved server-side — never from anything a browser says.
#[derive(Debug, Clone)]
pub struct GateAccessInfo {
    pub application_id: String,
    /// The immutable relying-site identity frozen with the published policy. Hosted requests
    /// must match this value as well as the deployment origin allowlist; an environment change
    /// must not silently retarget a published gate to a different website.
    pub challenge_domain: String,
    pub policy_hash: String,
    pub policy_version: u64,
    pub session_ttl_secs: u64,
    pub test_lane: bool,
    pub grants: Vec<String>,
    /// The gate's proof machinery, recovered from the snapshot. The bridge uses it only to sanity
    /// the evidence it already holds; the registry remains the authority on the issued tier.
    pub proof_mode: ProofMode,
    /// The Ootle chain generation this gate's binding was published under. Bound into the replay
    /// record so a recovery after a reset migration (which republishes with a higher generation)
    /// cannot restore a retired-generation authorization. `0` means an unmigrated binding.
    pub chain_generation: u64,
}

/// Where the bridge's gates came from when it is registry-backed.
pub struct AccessHandle {
    pub plane: AccessPlane,
    /// gate_id -> access info, from the snapshot.
    pub index: std::collections::BTreeMap<String, GateAccessInfo>,
    /// The bindings mtime this index was built from.
    pub bindings_mtime: Option<std::time::SystemTime>,
}

impl AccessHandle {
    /// Build from the current snapshot. `None` when no snapshot exists yet.
    pub fn from_snapshot(paths: &ghost_gate_registry::StorePaths, snapshot: &Bindings) -> (Self, usize) {
        let mut index = std::collections::BTreeMap::new();
        for g in &snapshot.gates {
            index.insert(
                g.gate_id.clone(),
                GateAccessInfo {
                    application_id: g.application_id.clone(),
                    challenge_domain: g.challenge_domain.clone(),
                    policy_hash: g.policy_hash.clone(),
                    policy_version: g.policy_version,
                    session_ttl_secs: g.session_ttl_secs,
                    test_lane: g.test_lane,
                    grants: g.grants.clone(),
                    // A snapshot written before this field (or with an unknown label) falls back to
                    // Credential, the mode whose ceiling is lowest among the activatable modes, so
                    // an unparseable snapshot can never over-grant.
                    proof_mode: ProofMode::from_label(&g.proof_mode).unwrap_or(ProofMode::Credential),
                    chain_generation: g.chain_generation,
                },
            );
        }
        let mtime = std::fs::metadata(paths.bindings()).and_then(|m| m.modified()).ok();
        (
            Self {
                plane: AccessPlane::new(paths.clone()),
                index,
                bindings_mtime: mtime,
            },
            snapshot.gates.len(),
        )
    }

    /// Re-read the bindings file when it changed, rebuilding the gate registry and the access
    /// index. Returns (reloaded, gate_count). On a parse failure the LAST-KNOWN-GOOD state is
    /// kept — the caller logs and continues.
    pub fn reload_if_changed(
        &mut self,
        paths: &ghost_gate_registry::StorePaths,
        rebuild: &mut dyn FnMut(&[GateBindingSnapshot]) -> Result<(), String>,
    ) -> Result<(bool, usize), String> {
        let mtime = std::fs::metadata(paths.bindings()).and_then(|m| m.modified()).ok();
        if mtime == self.bindings_mtime {
            return Ok((false, self.index.len()));
        }
        let Some(snapshot) = ghost_gate_registry::load_bindings(paths)? else {
            return Ok((false, self.index.len()));
        };
        rebuild(&snapshot.gates)?;
        let (handle, count) = Self::from_snapshot(paths, &snapshot);
        self.index = handle.index;
        self.bindings_mtime = handle.bindings_mtime;
        // Revocations ride the snapshot; apply them to the persisted sessions.
        let revoked = self.plane.apply_revocations(&snapshot.revoked_session_prefixes)?;
        let _ = revoked;
        Ok((true, count))
    }

    /// The access info for a gate, if this bridge serves it from the registry.
    pub fn info(&self, gate_id: &str) -> Option<&GateAccessInfo> {
        self.index.get(gate_id)
    }

    /// Issue a session for an accepted proof. `evidence` is what the bridge actually verified; the
    /// registry derives the trust tier from it and the gate's proof machinery, and refuses when the
    /// tier does not meet the application's requirement.
    pub fn grant(&mut self, gate_id: &str, evidence: &Evidence, policy: &TrustPolicy) -> Result<AccessGrant, String> {
        let info = self
            .index
            .get(gate_id)
            .ok_or_else(|| format!("gate {gate_id} is not registry-bound"))?
            .clone();
        self.plane.issue(&info.application_id, gate_id, info.policy_hash, evidence, policy)
    }

    /// Recover the one access session attached to a durable replay authorization. The browser
    /// never supplies either value: both are generated and persisted by the bridge replay store.
    pub fn grant_idempotent(
        &mut self,
        gate_id: &str,
        authorization_id: &str,
        token: &str,
        evidence: &Evidence,
        policy: &TrustPolicy,
    ) -> Result<AccessGrant, String> {
        let info = self
            .index
            .get(gate_id)
            .ok_or_else(|| format!("gate {gate_id} is not registry-bound"))?
            .clone();
        self.plane.issue_idempotent(
            &info.application_id,
            gate_id,
            info.policy_hash,
            authorization_id,
            token,
            evidence,
            policy,
        )
    }

    /// The trust tier the bridge expects for `evidence` on this gate. Used to bind the tier into the
    /// durable replay record before issuance; the registry independently recomputes the same value.
    pub fn expected_tier(&self, gate_id: &str, evidence: &Evidence, policy: &TrustPolicy) -> ghost_gate_registry::TrustTier {
        match self.index.get(gate_id) {
            Some(info) => ghost_gate_registry::achieved_tier(evidence.kind(), info.proof_mode, policy),
            None => ghost_gate_registry::TrustTier::Development,
        }
    }

    /// The chain generation this gate's binding was published under, bound into the replay record
    /// so a cross-generation recovery is refused. An unknown gate yields `0` (no live generation).
    pub fn expected_generation(&self, gate_id: &str) -> u64 {
        self.index.get(gate_id).map(|info| info.chain_generation).unwrap_or(0)
    }

    /// The full server-side access decision.
    pub fn check(&mut self, token: &str, gate_id: &str) -> AccessDecision {
        let Some(info) = self.index.get(gate_id).cloned() else {
            return AccessDecision {
                authorized: false,
                reason: "unknown gate".into(),
                granted: vec![],
                expires_unix: 0,
                policy_version: 0,
                trust_tier: ghost_gate_registry::TrustTier::Development,
                required_tier: ghost_gate_registry::TrustTier::Production,
            };
        };
        match self.plane.check(token, &info.application_id, gate_id) {
            Ok(d) => d,
            Err(e) => AccessDecision {
                authorized: false,
                reason: e,
                granted: vec![],
                expires_unix: 0,
                policy_version: 0,
                trust_tier: ghost_gate_registry::TrustTier::Development,
                required_tier: ghost_gate_registry::TrustTier::Production,
            },
        }
    }
}

/// Build the engine's GateBinding from a registry snapshot entry. The snapshot is authoritative:
/// the bridge never learns a gate's threshold, resource or component from a browser.
pub fn binding_from_snapshot(
    snap: &GateBindingSnapshot,
) -> Result<crate::gate_registry::GateBinding, String> {
    use ghost_gate_core::network;
    use tari_template_lib_types::ResourceAddress;
    // The cohort and genesis identity come from the registry, never from this process's defaults:
    // a bridge that silently served a localnet gate as if it were a mainnet one would be the one
    // bug that makes every other check meaningless. An unknown cohort or a missing genesis is
    // refused, not defaulted.
    if !network::is_known(snap.network) {
        return Err(format!("gate {}: network byte 0x{:02x} is not a known cohort", snap.gate_id, snap.network));
    }
    if snap.genesis_hash.trim().is_empty() {
        return Err(format!("gate {}: the snapshot carries no genesis identity", snap.gate_id));
    }
    if let Ok(expected) = std::env::var("GG_BRIDGE_NETWORK") {
        let expected_byte = parse_network_byte(&expected)
            .ok_or_else(|| format!("GG_BRIDGE_NETWORK {expected:?} is not a cohort name or hex byte"))?;
        if expected_byte != snap.network {
            return Err(format!(
                "gate {}: the snapshot is for network 0x{:02x} but this bridge serves 0x{:02x} — refusing to bind a gate from another ledger",
                snap.gate_id, snap.network, expected_byte
            ));
        }
    }
    // An empty component address means the snapshot declares a credential-only gate: no on-chain
    // component exists, so nothing is bound. Anything else must parse as a real address.
    let component = if snap.component_address.trim().is_empty() {
        None
    } else {
        Some(try_parse_address(&snap.component_address, "component")?)
    };
    let resource: ResourceAddress = try_parse_address(&snap.resource_address, "resource")?;
    Ok(crate::gate_registry::GateBinding::ootle(
        component,
        resource,
        u64::try_from(snap.threshold_raw).map_err(|_| "threshold exceeds u64 for the engine binding")?,
        snap.network,
        challenge_domain_bytes(&snap.challenge_domain)?,
        snap.divisibility,
        snap.symbol.clone(),
    ))
}

/// "localnet", "0x10" or "16" -> the cohort byte.
fn parse_network_byte(raw: &str) -> Option<u8> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "mainnet" => Some(ghost_gate_core::network::MAINNET),
        "stagenet" => Some(ghost_gate_core::network::STAGENET),
        "nextnet" => Some(ghost_gate_core::network::NEXTNET),
        "localnet" => Some(ghost_gate_core::network::LOCALNET),
        "igor" => Some(ghost_gate_core::network::IGOR),
        "esmeralda" => Some(ghost_gate_core::network::ESMERALDA),
        other => u8::from_str_radix(other.strip_prefix("0x").unwrap_or(other), 16).ok(),
    }
}

/// The template address types may not implement FromStr; they construct from a string via their
/// own conversion. Try the available paths and refuse loudly when none apply.
fn try_parse_address<T>(addr: &str, kind: &str) -> Result<T, String>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    T::from_str(addr).map_err(|e| format!("{kind} address {addr:?}: {e}"))
}

fn challenge_domain_bytes(domain: &str) -> Result<tari_template_lib_types::MaxBytes<64>, String> {
    tari_template_lib_types::MaxBytes::new_checked(domain.as_bytes().to_vec())
        .ok_or_else(|| format!("challenge domain {domain:?} exceeds 64 bytes"))
}
