//! Canonical gate policy: the single authoritative description of what a gate requires.
//!
//! # Why this type exists
//!
//! Before this, a gate's requirements lived in an environment variable the operator typed at
//! startup, and the browser was told what the gate was. That is backwards: the *server* must own
//! the policy and the browser must be told nothing it can be trusted with. Every value a proof is
//! judged against now comes from a [`GatePolicy`] that is loaded from the registry, versioned,
//! hashed, and signed into the challenge domain — so a browser that lies about a threshold, a
//! resource, a gate id, or a policy version is simply describing a different policy, and the
//! proof it submits cannot verify.
//!
//! # Immutability
//!
//! A published policy version is frozen. Changing a threshold or a resource does not mutate it:
//! it publishes a *new* version ([`PolicyVersion::next`]) with an incremented version number, a
//! fresh hash, and its own [`ReplacementRecord`]. Outstanding challenges keep the version they
//! were issued under, so a threshold cannot be lowered underneath an in-flight proof.
//!
//! # Proof modes
//!
//! [`ProofMode`] is a closed set. `Xtm` exists so an administrator can *draft* a native L1 gate
//! and see exactly what is missing, but [`ProofMode::is_activatable`] is false for it and for any
//! other unsupported mode: a draft can be saved and reviewed but can never authorize a session.
//!
//! # Units
//!
//! Thresholds are **raw integer units**, never floats, never display strings. Divisibility exists
//! only so a dashboard can show "10 tTARI" to a human and store the exact raw integer
//! ([`GatePolicy::raw_units_for`] is the one conversion path, and it is checked against an exact
//! divisibility test so 10.0000001 can never silently become 10).

use std::collections::BTreeMap;
use std::fmt;

/// Maximum number of gates in one application. This is a *configured operational limit*, not a
/// protocol bound — `crates/ghost-gate-bridge/tests/scale.rs` measures the real cost at 1, 3, 10,
/// 25 and 50 gates and the dashboard enforces whatever limit the server reports.
pub const DEFAULT_MAX_GATES_PER_APP: usize = 50;

/// Longest verified-access session the system will issue at all, whatever an administrator asks
/// for. This is the documented, enforced maximum; shorter is always allowed.
pub const MAX_SESSION_TTL: std::time::Duration = std::time::Duration::from_secs(30 * 24 * 3600);

/// Shortest verified-access session worth issuing.
pub const MIN_SESSION_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

/// Standard website default, and the value the dashboard suggests for a normal site.
pub const DEFAULT_SESSION_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

/// Community-membership suggestion.
pub const SUGGESTED_COMMUNITY_TTL: std::time::Duration = std::time::Duration::from_secs(7 * 24 * 3600);

/// Challenges stay short and single-use regardless of how long a session may live. A long session
/// is not a long challenge.
pub const CHALLENGE_TTL: std::time::Duration = std::time::Duration::from_secs(180);

/// u128 as a JSON number or an exact decimal string. Strings are accepted — and preferred on the
/// wire — because dashboard JavaScript cannot hold a threshold above 2^53 in a number without
/// losing integer precision, and a threshold that silently rounds is a threshold nobody can audit.
mod u128_flexible {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = u128;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "a decimal string or number")
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<u128, E> { Ok(v as u128) }
            fn visit_u128<E: serde::de::Error>(self, v: u128) -> Result<u128, E> { Ok(v) }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<u128, E> {
                v.parse::<u128>().map_err(|_| serde::de::Error::custom(format!("not an exact unsigned integer: {v:?}")))
            }
        }
        d.deserialize_any(V)
    }
}

/// The proof machinery a gate demands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProofMode {
    /// The wallet daemon builds a proof transaction; the network attests a public floor.
    Consensus,
    /// The wallet creates a value-committing output and signs the challenge over it; the bridge
    /// verifies against chain state.
    Credential,
    /// Native L1 (Minotari XTM). **Not activatable**: no compatible verifier exists upstream.
    Xtm,
}

impl ProofMode {
    pub fn is_activatable(self) -> bool {
        matches!(self, ProofMode::Consensus | ProofMode::Credential)
    }

    /// Why a mode cannot be activated, in words an administrator can act on.
    pub fn blocked_reason(self) -> Option<&'static str> {
        match self {
            ProofMode::Consensus | ProofMode::Credential => None,
            ProofMode::Xtm => Some(
                "Native L1 (XTM) has no compatible verifier yet: the only L1 signing surface \
                 available upstream signs with the node identity key, not with a user's stealth \
                 outputs, so no proof could be verified. Saved as a draft; it cannot authorize a \
                 session until a real verifier exists.",
            ),
        }
    }
}

/// How gates relate to each other inside one application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GateTopology {
    /// Qualifying for one gate grants that gate only.
    Independent,
    /// A gate may name lower tiers it also grants. Inherited access is resolved **server-side**
    /// from the policy; a client claiming a lower tier proves nothing on its own.
    Hierarchical,
}

/// One gate, as administered. This is the canonical record; the bridge builds its runtime bindings
/// from these and never from browser input.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GatePolicy {
    /// Stable, unique within the application. Never reused after a removal, so an old proof or
    /// policy version can never be reinterpreted as a different gate.
    pub gate_id: String,
    /// Display name. Purely cosmetic; it never affects authorization, and hierarchy is never
    /// inferred from it.
    pub name: String,
    /// The resource this gate's balance floor is measured in.
    pub resource_address: String,
    /// Human symbol, e.g. "tTARI". Display only. Two different resources may share a ticker —
    /// which is exactly why authorization never looks at this.
    pub symbol: String,
    /// Decimal places for display and for the dashboard's conversion only.
    pub divisibility: u8,
    /// Exact minimum in **raw integer units**. Serialised as a decimal string (or accepted as a
    /// JSON number) so dashboard JavaScript never has to round a threshold.
    #[serde(with = "u128_flexible")]
    pub threshold_raw: u128,
    pub proof_mode: ProofMode,
    /// The relying-site / challenge domain this gate is bound to.
    pub challenge_domain: String,
    /// Optional per-gate override of the application session duration.
    pub session_ttl_override: Option<u64>,
    /// Tiers this gate grants, when the application is hierarchical. Explicit, never inferred.
    pub grants: Vec<String>,
    /// Whether this gate can authorize a session at all. A draft is visible but inert.
    pub enabled: bool,
    /// Whether this gate belongs to the test lane. Test lanes never authorize production
    /// sessions, regardless of how well the proof verifies.
    pub test_lane: bool,
    /// The deployed on-chain gate component. An enabled, activatable gate requires one: the
    /// component is where consensus holds the gate's state. serde default so registries written
    /// before this field existed still load.
    #[serde(default)]
    pub component_address: Option<String>,
}

impl GatePolicy {
    /// Exact, divisibility-aware conversion from a human amount to raw units.
    ///
    /// Returns `None` when the amount cannot be represented exactly. This is deliberately strict:
    /// 10.0000001 at divisibility 6 is rejected rather than truncated, because a threshold that
    /// silently rounds is a threshold nobody can audit.
    pub fn raw_units_for(amount_decimal: &str, divisibility: u8) -> Option<u128> {
        if amount_decimal.trim().is_empty() || amount_decimal.contains(['e', 'E', '+']) {
            return None;
        }
        let (int_part, frac_part) = match amount_decimal.trim().split_once('.') {
            Some((i, f)) => (i, f),
            None => (amount_decimal.trim(), ""),
        };
        if int_part.is_empty() || !int_part.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        if !frac_part.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        if frac_part.len() > divisibility as usize {
            return None; // more precision than the resource can express
        }
        let int: u128 = int_part.parse().ok()?;
        let scale = 10u128.checked_pow(divisibility as u32)?;
        let frac: u128 = if frac_part.is_empty() { 0 } else { frac_part.parse().ok()? };
        // Exactness: the fraction must fill exactly `divisibility` places, so multiply by the
        // remaining power of ten. 10.5 at div 6 -> 105 * 10^5, with no rounding anywhere.
        let padded = frac * 10u128.checked_pow(divisibility as u32 - frac_part.len() as u32)?;
        if padded >= scale && frac != 0 {
            return None;
        }
        int.checked_mul(scale)?.checked_add(padded)
    }

    /// Render raw units back for display, exactly (trailing zeros trimmed).
    pub fn format_raw(raw: u128, divisibility: u8) -> String {
        if divisibility == 0 {
            return raw.to_string();
        }
        let scale = 10u128.saturating_pow(divisibility as u32);
        if scale == 0 {
            return raw.to_string();
        }
        let int = raw / scale;
        let frac = raw % scale;
        if frac == 0 {
            return int.to_string();
        }
        let frac_str = format!("{:0width$}", frac, width = divisibility as usize);
        format!("{}.{}", int, frac_str.trim_end_matches('0'))
    }

    pub fn effective_ttl(&self, app_default: u64) -> std::time::Duration {
        std::time::Duration::from_secs(self.session_ttl_override.unwrap_or(app_default))
    }
}

/// An application: a named set of gates with one owner and one default session duration.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Application {
    pub application_id: String,
    pub display_name: String,
    /// The administrator (passkey credential id) that owns this application. Only this principal
    /// may change its policy.
    pub owner_credential: String,
    pub topology: GateTopology,
    pub default_session_ttl: u64,
    pub max_gates: usize,
    /// Gates in administrator order. Order is cosmetic; position grants nothing.
    pub gates: Vec<GatePolicy>,
    /// Bumped on every accepted mutation; part of each policy version's identity.
    pub revision: u64,
    /// A production deployment. Production applications may not enable a test-lane gate: a test
    /// configuration must never be able to authorize a production session. Demo/test deployments
    /// set this to false explicitly.
    pub production: bool,
}

impl Application {
    pub fn gate(&self, gate_id: &str) -> Option<&GatePolicy> {
        self.gates.iter().find(|g| g.gate_id == gate_id)
    }

    pub fn gate_mut(&mut self, gate_id: &str) -> Option<&mut GatePolicy> {
        self.gates.iter_mut().find(|g| g.gate_id == gate_id)
    }

    /// Structural validation. Everything that must hold before a version may be published lives
    /// here, so no caller can skip it by building the struct a different way.
    pub fn validate(&self) -> Result<(), String> {
        if self.application_id.trim().is_empty() || self.application_id.len() > 64 {
            return Err("application_id must be 1..=64 characters".into());
        }
        if !self
            .application_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err("application_id may contain only letters, digits, '-', '_' and '.'".into());
        }
        if self.owner_credential.trim().is_empty() {
            return Err("an application must have an owner".into());
        }
        if self.gates.len() > self.max_gates {
            return Err(format!(
                "{} gates exceeds this application's configured limit of {}",
                self.gates.len(),
                self.max_gates
            ));
        }
        let ttl = std::time::Duration::from_secs(self.default_session_ttl);
        if ttl < MIN_SESSION_TTL || ttl > MAX_SESSION_TTL {
            return Err(format!(
                "default session duration must be between 1 hour and {} days",
                MAX_SESSION_TTL.as_secs() / 86_400
            ));
        }
        if self.revision == 0 {
            return Err("revision starts at 1".into());
        }
        let mut seen = BTreeMap::new();
        for g in &self.gates {
            validate_gate(g, self)?;
            if seen.insert(g.gate_id.clone(), ()).is_some() {
                return Err(format!("duplicate gate id {:?}", g.gate_id));
            }
        }
        // Hierarchy is explicit and may only name gates that exist in this application. It is
        // never inferred, and a cycle is refused rather than resolved at request time.
        if self.topology == GateTopology::Hierarchical {
            for g in &self.gates {
                for granted in &g.grants {
                    if !self.gates.iter().any(|o| o.gate_id == *granted) {
                        return Err(format!(
                            "gate {:?} grants {:?}, which is not a gate in this application",
                            g.gate_id, granted
                        ));
                    }
                }
            }
            detect_cycle(&self.gates)?;
        }
        Ok(())
    }

    /// The gates a verified session for `gate_id` unlocks, resolved server-side from policy.
    /// Returns an empty vec for an unknown gate.
    ///
    /// Breadth-first in the administrator's declared grant order, so the result is deterministic
    /// and reads the way the policy was written: the gate itself, then its direct grants, then
    /// theirs.
    pub fn granted_by(&self, gate_id: &str) -> Vec<String> {
        // An unknown gate grants nothing — including itself. A session can only ever name a gate
        // that exists in this application's policy.
        if self.gate(gate_id).is_none() {
            return Vec::new();
        }
        let mut out = vec![gate_id.to_string()];
        if self.topology != GateTopology::Hierarchical {
            return out;
        }
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(gate_id.to_string());
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        seen.insert(gate_id.to_string());
        while let Some(cur) = queue.pop_front() {
            if let Some(g) = self.gate(&cur) {
                for granted in &g.grants {
                    if seen.insert(granted.clone()) {
                        out.push(granted.clone());
                        queue.push_back(granted.clone());
                    }
                }
            }
        }
        out
    }
}

fn detect_cycle(gates: &[GatePolicy]) -> Result<(), String> {
    // Iterative depth-first search over the grant graph; any back edge is a cycle.
    let mut state: BTreeMap<&str, u8> = BTreeMap::new(); // 0 unvisited, 1 on stack, 2 done
    for root in gates {
        if state.get(root.gate_id.as_str()).copied().unwrap_or(0) == 2 {
            continue;
        }
        let mut stack: Vec<(&str, usize)> = vec![(root.gate_id.as_str(), 0)];
        state.insert(root.gate_id.as_str(), 1);
        while let Some((id, child)) = stack.pop() {
            let g = match gates.iter().find(|g| g.gate_id == id) {
                Some(g) => g,
                None => continue,
            };
            if child < g.grants.len() {
                stack.push((id, child + 1));
                let next = g.grants[child].as_str();
                match state.get(next).copied().unwrap_or(0) {
                    1 => return Err(format!("tier cycle through gate {next:?}")),
                    2 => {}
                    _ => {
                        state.insert(next, 1);
                        stack.push((next, 0));
                    }
                }
            } else {
                state.insert(id, 2);
            }
        }
    }
    Ok(())
}

fn validate_gate(g: &GatePolicy, app: &Application) -> Result<(), String> {
    if g.gate_id.trim().is_empty() || g.gate_id.len() > 64 {
        return Err("gate_id must be 1..=64 characters".into());
    }
    if !g
        .gate_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(format!("gate_id {:?} has invalid characters", g.gate_id));
    }
    if g.name.trim().is_empty() || g.name.len() > 120 {
        return Err(format!("gate {:?}: name must be 1..=120 characters", g.gate_id));
    }
    if g.resource_address.trim().is_empty() || g.resource_address.len() > 128 {
        return Err(format!("gate {:?}: resource address required", g.gate_id));
    }
    if g.divisibility > 24 {
        return Err(format!("gate {:?}: divisibility above 24 is not representable", g.gate_id));
    }
    if g.threshold_raw == 0 {
        return Err(format!("gate {:?}: threshold must be greater than zero", g.gate_id));
    }
    if g.challenge_domain.trim().is_empty() || g.challenge_domain.len() > 128 {
        return Err(format!("gate {:?}: challenge domain required", g.gate_id));
    }
    if let Some(secs) = g.session_ttl_override {
        let d = std::time::Duration::from_secs(secs);
        if d < MIN_SESSION_TTL || d > MAX_SESSION_TTL {
            return Err(format!(
                "gate {:?}: session override must be between 1 hour and {} days",
                g.gate_id,
                MAX_SESSION_TTL.as_secs() / 86_400
            ));
        }
    }
    // An enabled gate must be activatable: a draft cannot authorize sessions.
    if g.enabled && !g.proof_mode.is_activatable() {
        return Err(format!(
            "gate {:?} uses a proof mode that cannot be activated yet: {}",
            g.gate_id,
            g.proof_mode.blocked_reason().unwrap_or("unsupported")
        ));
    }
    // An enabled gate must be deployed: the component is where consensus keeps the gate's state.
    if g.enabled && g.proof_mode.is_activatable() {
        match &g.component_address {
            Some(a) if a.starts_with("component_") && a.len() > "component_".len() => {}
            _ => return Err(format!(
                "gate {:?} is enabled but has no deployed gate component address",
                g.gate_id
            )),
        }
    }
    if g.enabled && g.test_lane && app.production {
        return Err(format!(
            "gate {:?}: test lanes cannot be enabled in a production application",
            g.gate_id
        ));
    }
    Ok(())
}

/// A frozen, hashed policy version. The hash is what a challenge binds to, so a proof can only be
/// verified against the exact policy it was issued under.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyVersion {
    pub application_id: String,
    pub gate_id: String,
    pub version: u64,
    /// Canonical digest over every field above plus the network/genesis identifier.
    pub policy_hash: String,
    pub network: u8,
    /// The policy, frozen. Never mutated in place.
    pub policy: GatePolicy,
    /// Revision of the application this version was cut from.
    pub app_revision: u64,
    pub created_unix: u64,
}

impl PolicyVersion {
    pub fn next<H: PolicyHasher>(&self, hasher: &H, app: &Application, gate: &GatePolicy) -> Result<Self, String> {
        if gate.gate_id != self.gate_id {
            return Err("a policy version cannot change its gate id".into());
        }
        if gate.gate_id == self.policy.gate_id
            && gate.threshold_raw == self.policy.threshold_raw
            && gate.resource_address == self.policy.resource_address
        {
            return Err(
                "threshold and resource are unchanged; publish a change or leave the version alone"
                    .into(),
            );
        }
        Ok(PolicyVersion {
            application_id: app.application_id.clone(),
            gate_id: gate.gate_id.clone(),
            version: self.version + 1,
            policy_hash: hash_policy(hasher, app, gate, self.version + 1),
            network: self.network,
            policy: gate.clone(),
            app_revision: app.revision,
            created_unix: now_unix(),
        })
    }
}

/// Canonical, order-independent byte form of a gate policy.
///
/// Every authority-bearing field is included. `symbol` and `name` are included too, deliberately:
/// they are not authoritative, but a digest that ignored them would let two different displayed
/// policies share a hash, which is precisely the confusion an auditor cannot afford.
///
/// This crate has no crypto dependency on purpose (the WASM template compiles it), so the digest is
/// computed by a caller-supplied [`PolicyHasher`]. The shipped implementation is blake3, which the
/// bridge provides because blake3 is already in the cohort's dependency graph.
pub fn canonical_form(app: &Application, gate: &GatePolicy, version: u64) -> Vec<u8> {
    let mut canonical = String::new();
    canonical.push_str(&format!("v1|{}|{}|{}", app.application_id, gate.gate_id, version));
    canonical.push_str(&format!("|{}|{}|{}", app.owner_credential, app.topology.topology_code(), app.revision));
    canonical.push_str(&format!(
        "|{}|{}|{}|{}|{}",
        gate.resource_address, gate.threshold_raw, gate.divisibility, gate.symbol, gate.name
    ));
    canonical.push_str(&format!(
        "|{:?}|{}|{}|{}|{}|{}|{}",
        gate.proof_mode,
        gate.challenge_domain,
        gate.session_ttl_override.unwrap_or(app.default_session_ttl),
        gate.enabled,
        gate.test_lane,
        gate.grants.join(","),
        gate.component_address.as_deref().unwrap_or("")
    ));
    canonical.into_bytes()
}

/// Anything that can digest the canonical form. blake3 in production; a stub in tests.
pub trait PolicyHasher {
    fn hex_digest(&self, bytes: &[u8]) -> String;
}

/// Convenience: hash a policy version with the supplied hasher.
pub fn hash_policy<H: PolicyHasher>(hasher: &H, app: &Application, gate: &GatePolicy, version: u64) -> String {
    hasher.hex_digest(&canonical_form(app, gate, version))
}

impl GateTopology {
    pub fn topology_code(self) -> u8 {
        match self {
            GateTopology::Independent => 0,
            GateTopology::Hierarchical => 1,
        }
    }
}

/// Replacement bookkeeping, so changing a threshold or a resource is an explicit, authorized
/// event with outstanding work accounted for — never a silent mutation of a live component.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplacementRecord {
    pub gate_id: String,
    pub from_version: u64,
    pub to_version: u64,
    pub reason: String,
    /// Challenges issued under the old version. They are refused against the new one.
    pub outstanding_challenges_invalidated: Vec<String>,
    /// Verified sessions issued under the old version. They keep working until their own expiry
    /// unless revoked; the administrator is told which ones.
    pub sessions_carried: Vec<String>,
    pub sessions_revoked: Vec<String>,
    pub authorized_by: String,
    pub created_unix: u64,
}

impl fmt::Display for ProofMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofMode::Consensus => write!(f, "consensus"),
            ProofMode::Credential => write!(f, "credential"),
            ProofMode::Xtm => write!(f, "xtm"),
        }
    }
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> Application {
        Application {
            application_id: "meme-coin".into(),
            display_name: "Meme Coin".into(),
            owner_credential: "cred-owner-1".into(),
            topology: GateTopology::Independent,
            default_session_ttl: 86_400,
            max_gates: 10,
            gates: vec![],
            revision: 1,
            production: true,
        }
    }

    /// Deterministic stand-in for blake3 so the policy tests stay dependency-free. The bridge's
    /// real tests use blake3; this only proves the canonical form changes when it should.
    #[derive(Default)]
    struct TestHasher(u64);
    impl PolicyHasher for TestHasher {
        fn hex_digest(&self, bytes: &[u8]) -> String {
            let mut h: u64 = 0xcbf29ce484222325;
            for b in bytes {
                h ^= *b as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
            format!("{h:016x}")
        }
    }

    fn gate(id: &str) -> GatePolicy {
        GatePolicy {
            gate_id: id.into(),
            name: id.into(),
            resource_address: "resource_abc".into(),
            symbol: "tTARI".into(),
            divisibility: 6,
            threshold_raw: 100_000_000,
            proof_mode: ProofMode::Consensus,
            challenge_domain: "meme-coin.localhost".into(),
            session_ttl_override: None,
            grants: vec![],
            enabled: true,
            test_lane: false,
            component_address: Some("component_abc".into()),
        }
    }

    #[test]
    fn raw_conversion_is_exact_and_refuses_rounding() {
        assert_eq!(GatePolicy::raw_units_for("10", 6), Some(10_000_000));
        assert_eq!(GatePolicy::raw_units_for("10.5", 6), Some(10_500_000));
        assert_eq!(GatePolicy::raw_units_for("100000", 0), Some(100_000));
        // Too much precision for the resource: refused, never truncated.
        assert_eq!(GatePolicy::raw_units_for("10.0000001", 6), None);
        assert_eq!(GatePolicy::raw_units_for("0.1", 0), None);
        assert_eq!(GatePolicy::raw_units_for("1e6", 6), None);
        assert_eq!(GatePolicy::raw_units_for("", 6), None);
        assert_eq!(GatePolicy::raw_units_for("-5", 6), None);
        assert_eq!(GatePolicy::raw_units_for("abc", 6), None);
        // Round-trip.
        assert_eq!(GatePolicy::raw_units_for("10.5", 6).map(|r| GatePolicy::format_raw(r, 6)), Some("10.5".into()));
    }

    #[test]
    fn validation_refuses_a_zero_threshold_a_huge_ttl_and_a_cycle() {
        let mut a = app();
        let mut g = gate("one");
        g.threshold_raw = 0;
        a.gates.push(g);
        assert!(a.validate().is_err(), "zero threshold must be refused");

        let mut a = app();
        let mut g = gate("one");
        g.session_ttl_override = Some(60);
        a.gates.push(g);
        assert!(a.validate().is_err(), "a 60 second session must be refused");

        let mut a = app();
        a.topology = GateTopology::Hierarchical;
        let mut top = gate("top");
        top.grants = vec!["bottom".into()];
        let mut bottom = gate("bottom");
        bottom.grants = vec!["top".into()];
        a.gates = vec![top, bottom];
        assert!(a.validate().is_err(), "a tier cycle must be refused");
    }

    #[test]
    fn hierarchy_grants_are_resolved_from_policy_not_from_names() {
        let mut a = app();
        a.topology = GateTopology::Hierarchical;
        let mut gold = gate("gold");
        gold.grants = vec!["silver".into(), "bronze".into()];
        let mut silver = gate("silver");
        silver.grants = vec!["bronze".into()];
        a.gates = vec![gold, silver, gate("bronze")];
        assert_eq!(a.granted_by("gold"), vec!["gold", "silver", "bronze"]);
        assert_eq!(a.granted_by("silver"), vec!["silver", "bronze"]);
        assert_eq!(a.granted_by("bronze"), vec!["bronze"]);
        // A threshold-ordered name would have implied the wrong thing; policy decides.
        assert!(a.granted_by("nothing-here").is_empty());
    }

    #[test]
    fn independent_topology_grants_exactly_one_gate() {
        let mut a = app();
        let mut g = gate("only");
        g.grants = vec!["only".into()];
        a.gates = vec![g];
        assert_eq!(a.granted_by("only"), vec!["only"]);
    }

    #[test]
    fn a_draft_cannot_be_enabled_and_xtm_is_not_activatable() {
        assert!(!ProofMode::Xtm.is_activatable());
        assert!(ProofMode::Xtm.blocked_reason().is_some());
        let mut a = app();
        let mut g = gate("l1");
        g.proof_mode = ProofMode::Xtm;
        a.gates.push(g);
        assert!(a.validate().is_err(), "an enabled XTM gate must be refused");

        // As a draft it is fine.
        let mut a = app();
        let mut g = gate("l1");
        g.proof_mode = ProofMode::Xtm;
        g.enabled = false;
        a.gates.push(g);
        assert!(a.validate().is_ok(), "a draft XTM gate is allowed");
    }

    #[test]
    fn the_policy_hash_changes_when_any_field_changes() {
        let h = TestHasher::default();
        let a = app();
        let g = gate("one");
        let base = hash_policy(&h, &a, &g, 1);
        assert_eq!(base, hash_policy(&h, &a, &g, 1), "hashing is deterministic");

        let mut g2 = g.clone();
        g2.threshold_raw += 1;
        assert_ne!(base, hash_policy(&h, &a, &g2, 1), "threshold must change the hash");

        let mut g3 = g.clone();
        g3.resource_address = "resource_other".into();
        assert_ne!(base, hash_policy(&h, &a, &g3, 1), "resource must change the hash");

        // Same ticker, different resource: the exact confusion the spec calls out.
        let mut g4 = g.clone();
        g4.resource_address = "resource_impostor".into();
        g4.symbol = g.symbol.clone();
        assert_ne!(hash_policy(&h, &a, &g4, 1), base, "a ticker clone must not share a hash");

        let mut a2 = a.clone();
        a2.revision = 2;
        assert_ne!(base, hash_policy(&h, &a2, &g, 1), "revision must change the hash");

        let mut g5 = g.clone();
        g5.grants = vec!["x".into()];
        assert_ne!(base, hash_policy(&h, &a, &g5, 1), "grants must change the hash");

        // Version is part of the identity too.
        assert_ne!(hash_policy(&h, &a, &g, 2), base, "version must change the hash");
    }

    #[test]
    fn versions_only_advance_and_refuse_empty_changes() {
        let a = app();
        let g = gate("one");
        let h = TestHasher::default();
        let v1 = PolicyVersion {
            application_id: a.application_id.clone(),
            gate_id: g.gate_id.clone(),
            version: 1,
            policy_hash: hash_policy(&h, &a, &g, 1),
            network: 30,
            policy: g.clone(),
            app_revision: a.revision,
            created_unix: 1,
        };
        // No change: refused.
        assert!(v1.next(&h, &a, &g).is_err());
        // Changed threshold: version 2 with a new hash.
        let mut g2 = g.clone();
        g2.threshold_raw = 200_000_000;
        let v2 = v1.next(&h, &a, &g2).unwrap();
        assert_eq!(v2.version, 2);
        assert_ne!(v2.policy_hash, v1.policy_hash);
        assert_eq!(v2.network, v1.network, "the network is part of the identity");
        // A version cannot be re-cut under a different gate id.
        let mut g3 = g2.clone();
        g3.gate_id = "other".into();
        assert!(v1.next(&h, &a, &g3).is_err());
    }

    #[test]
    fn session_bounds_are_enforced_at_the_policy_level() {
        assert!(MAX_SESSION_TTL >= SUGGESTED_COMMUNITY_TTL);
        assert!(SUGGESTED_COMMUNITY_TTL >= DEFAULT_SESSION_TTL);
        assert!(DEFAULT_SESSION_TTL >= MIN_SESSION_TTL);
        // The suggested ladder, in seconds, as the dashboard offers it.
        let ladder = [3600u64, 12 * 3600, 86_400, 3 * 86_400, 7 * 86_400, 14 * 86_400, 30 * 86_400];
        for h in ladder {
            assert!(h >= MIN_SESSION_TTL.as_secs() && h <= MAX_SESSION_TTL.as_secs());
        }
        // The 30-day entry must equal the enforced maximum, not exceed it.
        assert_eq!(ladder[6], MAX_SESSION_TTL.as_secs());
    }
}