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
    use serde::{Deserializer, Serializer};
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
    /// Native L1 (Minotari XTM). **Not activatable**: the available browser provider is Ootle
    /// L2-only and no supported API yields independently verifiable live L1 output evidence.
    Xtm,
}

impl ProofMode {
    pub fn is_activatable(self) -> bool {
        matches!(self, ProofMode::Consensus | ProofMode::Credential)
    }

    /// Parse the stable label produced by [`fmt::Display`]. Used by the bridge to recover the mode
    /// from a bindings snapshot without a second serde round trip.
    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "consensus" => Some(ProofMode::Consensus),
            "credential" => Some(ProofMode::Credential),
            "xtm" => Some(ProofMode::Xtm),
            _ => None,
        }
    }

    /// Why a mode cannot be activated, in words an administrator can act on.
    pub fn blocked_reason(self) -> Option<&'static str> {
        match self {
            ProofMode::Consensus | ProofMode::Credential => None,
            ProofMode::Xtm => Some(
                "Native L1 (XTM) is blocked for production: Tari Universe's window.tari provider \
                 is Ootle L2-only, while the available Minotari wallet signing surface does not \
                 provide an independently verifiable proof of a user's currently unspent outputs. \
                 Saved as a draft; it cannot authorize a session until that proof API exists.",
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
    /// Where this gate may be used. serde default so registries written before this field existed
    /// still load, defaulting to the website (the ordinary case).
    ///
    /// A gate is a policy about a TOKEN, not about one front door. An administrator may want the
    /// same threshold enforced on the website but NOT used to mint Telegram invites (or the other
    /// way round); this is where that choice is recorded, in the versioned policy, so the bridge
    /// and the bot read the same answer.
    #[serde(default)]
    pub use_mode: GateUseMode,
}

/// Which surfaces a gate is allowed to authorize. Not a hierarchy: `Both` means both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GateUseMode {
    /// The website (the Privacy Lab and any relying site). The default.
    #[default]
    Website,
    /// Telegram membership only.
    Telegram,
    /// Both surfaces.
    Both,
}

impl GateUseMode {
    pub fn as_str(self) -> &'static str {
        match self {
            GateUseMode::Website => "website",
            GateUseMode::Telegram => "telegram",
            GateUseMode::Both => "both",
        }
    }

    /// Whether this gate may authorize the given surface.
    pub fn allows(self, telegram: bool) -> bool {
        match self {
            GateUseMode::Website => !telegram,
            GateUseMode::Telegram => telegram,
            GateUseMode::Both => true,
        }
    }
}

/// How strong the verification evidence behind an authorization actually is.
///
/// Computed **server-side only**, never from anything a browser supplies. A session, receipt, or
/// bindings snapshot records its tier at issuance time, and no code path may silently upgrade a
/// weaker verdict. A `production: true` application refuses to issue a session below `Production`.
///
/// The tier is orthogonal to `test_lane`: a test-lane session on a testnet deployment may be
/// `OperatorTrustedTestnet`, but it still cannot authorize a production gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TrustTier {
    /// No chain reader, no anchor, fixture data, or unknown/failed verdict. Never authorizes
    /// real access — development and testing only.
    Development,
    /// Credential mode with an operator-controlled indexer, or consensus mode with a
    /// release-bootstrap anchor under explicit operator opt-in. The indexer's `verified` flag
    /// is accepted as evidence but labeled honestly: the operator trusts the indexer, and
    /// downstream consumers see that.
    OperatorTrustedTestnet,
    /// Consensus mode backed by an independently-authenticated, network-bound validator-set
    /// root with satisfied freshness. This is the only tier that may authorize production
    /// sessions in a `production: true` application.
    Production,
}

impl TrustTier {
    pub fn as_str(self) -> &'static str {
        match self {
            TrustTier::Development => "development",
            TrustTier::OperatorTrustedTestnet => "operator-trusted-testnet",
            TrustTier::Production => "production",
        }
    }

    /// Whether this tier is strong enough to authorize a session in a production application.
    pub fn permits_production(self) -> bool {
        matches!(self, TrustTier::Production)
    }
}

impl Default for TrustTier {
    fn default() -> Self {
        TrustTier::Development
    }
}

impl fmt::Display for TrustTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ProofMode {
    /// The highest trust tier this proof mode can ever reach, regardless of evidence quality.
    /// Credential mode tops out at OperatorTrustedTestnet because the indexer's `verified`
    /// flag is not independently verifiable (F-04). Consensus can reach Production with an
    /// authenticated anchor.
    pub fn max_trust_tier(self) -> TrustTier {
        match self {
            ProofMode::Consensus => TrustTier::Production,
            ProofMode::Credential => TrustTier::OperatorTrustedTestnet,
            ProofMode::Xtm => TrustTier::Development,
        }
    }
}

/// The kind of evidence a session rests on, recorded with the session and the replay record.
///
/// This is a *summary*, not a capability: nothing accepts an `EvidenceKind` to issue a session.
/// Issuance takes an [`Evidence`], whose strongest variant cannot be constructed outside a
/// verification path. Legacy records without this field load as `None` and never authorize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EvidenceKind {
    #[default]
    None,
    /// Chain data read from an indexer whose own `verified` flag is the only assurance (F-04).
    IndexerAsserted,
    /// The operator's own wallet daemon reported a finalized transaction.
    OperatorWalletReceipt,
    /// Pinned-anchor consensus verification rooted in the operator-approved release bootstrap.
    ConsensusReleaseBootstrap,
    /// Independently anchored consensus verification whose freshness is only relative to the
    /// verifier's own latest handover.
    ConsensusIndependentRelativeFreshness,
    /// Independently anchored consensus verification with authenticated current-state freshness.
    ConsensusIndependentAuthenticatedFreshness,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EvidenceKind::None => "none",
            EvidenceKind::IndexerAsserted => "indexer-asserted",
            EvidenceKind::OperatorWalletReceipt => "operator-wallet-receipt",
            EvidenceKind::ConsensusReleaseBootstrap => "consensus-release-bootstrap",
            EvidenceKind::ConsensusIndependentRelativeFreshness => "consensus-independent-relative-freshness",
            EvidenceKind::ConsensusIndependentAuthenticatedFreshness => "consensus-independent-authenticated-freshness",
        }
    }

    /// The strongest tier this kind of evidence can support under `policy`.
    pub fn ceiling(self, policy: &TrustPolicy) -> TrustTier {
        let tier = match self {
            EvidenceKind::None => TrustTier::Development,
            EvidenceKind::IndexerAsserted if policy.operator_trusted_indexer => TrustTier::OperatorTrustedTestnet,
            EvidenceKind::IndexerAsserted => TrustTier::Development,
            EvidenceKind::OperatorWalletReceipt
            | EvidenceKind::ConsensusReleaseBootstrap
            | EvidenceKind::ConsensusIndependentRelativeFreshness => TrustTier::OperatorTrustedTestnet,
            EvidenceKind::ConsensusIndependentAuthenticatedFreshness => TrustTier::Production,
        };
        tier.min(policy.max_tier)
    }

    /// Whether this evidence can be produced by a gate's proof machinery at all. A wallet receipt
    /// is not credential evidence and an indexer read is not a consensus-mode receipt.
    pub fn compatible_with(self, mode: ProofMode) -> bool {
        match self {
            EvidenceKind::None => false,
            EvidenceKind::IndexerAsserted => mode == ProofMode::Credential,
            EvidenceKind::OperatorWalletReceipt => mode == ProofMode::Consensus,
            EvidenceKind::ConsensusReleaseBootstrap
            | EvidenceKind::ConsensusIndependentRelativeFreshness
            | EvidenceKind::ConsensusIndependentAuthenticatedFreshness => {
                matches!(mode, ProofMode::Consensus | ProofMode::Credential)
            }
        }
    }
}

impl fmt::Display for EvidenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorClass {
    ReleaseBootstrap,
    IndependentlyAuthenticated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    RelativeOnly,
    Authenticated,
}

/// Consensus evidence attested by the pinned-anchor verifier.
///
/// The fields are private and this build has no public constructor: the only producer will be the
/// authenticated sidecar client, which does not exist yet. Until it does, `Production` is
/// unreachable outside test fixtures. There is deliberately no `Deserialize`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusAttestation {
    anchor: AnchorClass,
    freshness: Freshness,
    digest: String,
}

impl ConsensusAttestation {
    pub fn anchor(&self) -> AnchorClass {
        self.anchor
    }

    pub fn freshness(&self) -> Freshness {
        self.freshness
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn fixture(anchor: AnchorClass, freshness: Freshness, digest: impl Into<String>) -> Self {
        Self { anchor, freshness, digest: digest.into() }
    }
}

/// The evidence a verification path hands to session issuance. The digest identifies the exact
/// verified evidence so a recovery can prove it is re-installing the same authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evidence {
    None,
    IndexerAsserted { digest: String },
    OperatorWalletReceipt { digest: String },
    ConsensusVerified(ConsensusAttestation),
}

impl Evidence {
    pub fn kind(&self) -> EvidenceKind {
        match self {
            Evidence::None => EvidenceKind::None,
            Evidence::IndexerAsserted { .. } => EvidenceKind::IndexerAsserted,
            Evidence::OperatorWalletReceipt { .. } => EvidenceKind::OperatorWalletReceipt,
            Evidence::ConsensusVerified(a) => match (a.anchor, a.freshness) {
                (AnchorClass::ReleaseBootstrap, _) => EvidenceKind::ConsensusReleaseBootstrap,
                (AnchorClass::IndependentlyAuthenticated, Freshness::RelativeOnly) => {
                    EvidenceKind::ConsensusIndependentRelativeFreshness
                }
                (AnchorClass::IndependentlyAuthenticated, Freshness::Authenticated) => {
                    EvidenceKind::ConsensusIndependentAuthenticatedFreshness
                }
            },
        }
    }

    pub fn digest(&self) -> &str {
        match self {
            Evidence::None => "",
            Evidence::IndexerAsserted { digest } | Evidence::OperatorWalletReceipt { digest } => digest,
            Evidence::ConsensusVerified(a) => &a.digest,
        }
    }
}

/// Operator configuration that can only *lower* what evidence achieves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustPolicy {
    /// `GG_OPERATOR_TRUSTED_INDEXER=1`: the operator vouches for the indexer it configured, so
    /// indexer-asserted chain data may support non-production sessions.
    pub operator_trusted_indexer: bool,
    /// `GG_MAX_TRUST_TIER`: a global ceiling.
    pub max_tier: TrustTier,
}

impl Default for TrustPolicy {
    fn default() -> Self {
        Self { operator_trusted_indexer: false, max_tier: TrustTier::Production }
    }
}

impl TrustPolicy {
    /// Parses the two operator settings. Only the exact value `1` opts in; an unrecognised
    /// ceiling fails closed to `Development` rather than being ignored.
    pub fn parse(operator_trusted_indexer: Option<&str>, max_tier: Option<&str>) -> Self {
        let max_tier = match max_tier.map(str::trim) {
            None | Some("") => TrustTier::Production,
            Some("production") => TrustTier::Production,
            Some("operator-trusted-testnet") => TrustTier::OperatorTrustedTestnet,
            Some(_) => TrustTier::Development,
        };
        Self { operator_trusted_indexer: operator_trusted_indexer.map(str::trim) == Some("1"), max_tier }
    }
}

/// The minimum tier the application's CURRENT policy demands. `Development` never qualifies.
pub fn required_tier(app: &Application) -> TrustTier {
    if app.production { TrustTier::Production } else { TrustTier::OperatorTrustedTestnet }
}

/// The tier evidence of `kind` actually achieves on a gate of `mode`: the evidence ceiling, capped
/// by the mode's maximum and the operator policy. Incompatible evidence achieves `Development`.
pub fn achieved_tier(kind: EvidenceKind, mode: ProofMode, policy: &TrustPolicy) -> TrustTier {
    if !kind.compatible_with(mode) {
        return TrustTier::Development;
    }
    kind.ceiling(policy).min(mode.max_trust_tier())
}

/// The chain generation an application may currently authorize under, or `None` when it may
/// authorize nothing. This is the single fail-closed rule for reset enforcement, shared by
/// issuance, the access check and the bridge so none of them can disagree:
///
/// - `declared == 0` (unknown) authorizes nothing — on production AND non-production apps, with no
///   development or testnet bypass. A legacy application, session or record loads as `0`.
/// - `declared < floor` is a generation *rollback*: an older configuration was restored after a
///   newer generation was activated. It authorizes nothing until migrated forward again. The floor
///   is a durable, monotonic high-water mark that a config/policy/session restore cannot lower.
/// - otherwise the live generation is `declared` (`== floor` in steady state).
pub fn effective_generation(declared: u64, floor: u64) -> Option<u64> {
    if declared == 0 || declared < floor {
        return None;
    }
    Some(declared)
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
    /// The network cohort this application is bound to (see `core::network`). It is part of every
    /// policy digest and travels into the bridge bindings: a gate proven on one cohort must never
    /// be served as if it were the same gate on another. Unknown cohorts are refused.
    pub network: u8,
    /// The chain's genesis identity (hex). Genesis plus network byte is what makes "the same
    /// resource address" mean the same thing — two networks can both host address 0x..., so a
    /// digest that binds only the network byte would treat unrelated ledgers as one. Required: an
    /// application without a genesis identity is refused at validation.
    pub genesis_hash: String,
    /// The Ootle chain *generation* this application authorizes under. An L2 testnet reset can
    /// leave the L1 genesis, the network byte and even the native resource address unchanged while
    /// re-genesising the L2 — so `genesis_hash` and `network` cannot detect it. This is an
    /// operator-declared, review-gated generation counter: `0` means "unknown" and authorizes
    /// NOTHING (production or not), and it may only ever be raised, through the migrate operation,
    /// past the durable generation floor. It is deliberately NOT part of the policy digest: it is
    /// an orthogonal authorization dimension, not a property of a gate's frozen content.
    #[serde(default)]
    pub chain_generation: u64,
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
        if !crate::network::is_known(self.network) {
            return Err(format!(
                "network byte 0x{:02x} is not a known cohort (mainnet, stagenet, nextnet, localnet, igor, esmeralda)",
                self.network
            ));
        }
        let genesis = self.genesis_hash.trim();
        if genesis.is_empty() || genesis.len() > 128 || !genesis.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("genesis_hash must be 1..=128 hex characters — it is what distinguishes two ledgers that reuse the same addresses".into());
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
    validate_challenge_domain(&g.challenge_domain)
        .map_err(|reason| format!("gate {:?}: {reason}", g.gate_id))?;
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
    // Consensus gates require a deployed component: the component is where consensus keeps the
    // gate's state. Credential gates are component-free by protocol: the bridge verifies an
    // on-chain output + ownership signature entirely off-chain.
    if g.enabled && g.proof_mode == ProofMode::Consensus {
        match &g.component_address {
            Some(a) if a.starts_with("component_") && a.len() > "component_".len() => {}
            _ => return Err(format!(
                "gate {:?} is enabled consensus gate but has no deployed gate component address",
                g.gate_id
            )),
        }
    }
    // A credential gate must NOT have a component address: it would be unused and misleading.
    if g.enabled && g.proof_mode == ProofMode::Credential && g.component_address.is_some() {
        let addr = g.component_address.as_deref().unwrap_or("");
        if !addr.trim().is_empty() {
            return Err(format!(
                "gate {:?} is a credential gate and must not have a component address \
                 (credential verification is off-chain)",
                g.gate_id
            ));
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

/// Validate the immutable relying-site identity carried by a gate policy.
///
/// Existing private/local deployments use an opaque `*.localhost` value. Hosted gates instead
/// need the complete, canonical HTTPS origin the browser will report. Keeping those forms
/// explicit prevents an `http` URL, path, credential, or arbitrary hostname from being published
/// as a challenge-binding identity.
pub fn validate_challenge_domain(value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > 128 || value != value.trim() {
        return Err("challenge domain required".into());
    }
    if !value.contains("://") {
        let local = value.to_ascii_lowercase();
        if (local == "localhost" || local.ends_with(".localhost"))
            && valid_challenge_hostname(value)
        {
            return Ok(());
        }
        return Err("challenge domain must be a *.localhost local identity or an exact HTTPS origin".into());
    }
    let Some(authority) = value.strip_prefix("https://") else {
        return Err("hosted relying-site must be an HTTPS origin".into());
    };
    if authority.is_empty()
        || authority != authority.to_ascii_lowercase()
        || authority.bytes().any(|byte| byte.is_ascii_whitespace())
        || authority.contains(['/', '?', '#', '@'])
    {
        return Err("hosted relying-site must be an exact lowercase HTTPS origin without path, credentials, query, or fragment".into());
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if !valid_challenge_hostname(host) {
        return Err("hosted relying-site has an invalid hostname".into());
    }
    if let Some(port) = port {
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit())
            || (port.len() > 1 && port.starts_with('0'))
            || port.parse::<u16>().ok().filter(|port| *port != 0 && *port != 443).is_none()
        {
            return Err("hosted relying-site has an invalid or non-canonical port".into());
        }
    }
    Ok(())
}

fn valid_challenge_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
        && host.split('.').all(|label| !label.is_empty() && !label.starts_with('-') && !label.ends_with('-'))
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
    /// The canonical policy-hash format used for `policy_hash`.  Registries written before
    /// policy-hash v2 used v1, which deliberately remains verifiable so an upgrade cannot
    /// reinterpret an already-published policy.  A subsequent explicit Publish migrates it to
    /// v2.
    #[serde(default = "default_policy_hash_version")]
    pub policy_hash_version: u8,
    /// The application-level authorization context frozen with a v2 policy.  Gate policies alone
    /// cannot reproduce topology, default TTL, or production trust requirements after an
    /// administrator starts a new draft.  Legacy v1 records intentionally have no context and
    /// require an explicit re-publish before those application fields may be edited.
    #[serde(default)]
    pub policy_context: Option<PublishedApplicationContext>,
    /// The ledger this version was frozen for: the cohort byte plus the genesis identity. Frozen
    /// with the policy so a later re-point of the application cannot silently reinterpret it.
    pub network: u8,
    pub genesis_hash: String,
    /// The policy, frozen. Never mutated in place.
    pub policy: GatePolicy,
    /// Revision of the application this version was cut from.
    pub app_revision: u64,
    pub created_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishedApplicationContext {
    pub owner_credential: String,
    pub topology: GateTopology,
    pub default_session_ttl: u64,
    pub production: bool,
    pub network: u8,
    pub genesis_hash: String,
}

impl PublishedApplicationContext {
    pub fn from_application(app: &Application) -> Self {
        Self {
            owner_credential: app.owner_credential.clone(),
            topology: app.topology,
            default_session_ttl: app.default_session_ttl,
            production: app.production,
            network: app.network,
            genesis_hash: app.genesis_hash.clone(),
        }
    }

    /// Reconstruct just the application fields consumed by policy canonicalization.  Gates and
    /// bookkeeping remain from `current` because they are deliberately outside that digest.
    pub fn apply_to(&self, current: &Application) -> Application {
        let mut frozen = current.clone();
        frozen.owner_credential = self.owner_credential.clone();
        frozen.topology = self.topology;
        frozen.default_session_ttl = self.default_session_ttl;
        frozen.production = self.production;
        frozen.network = self.network;
        frozen.genesis_hash = self.genesis_hash.clone();
        frozen
    }
}

pub const POLICY_HASH_V1: u8 = 1;
pub const POLICY_HASH_V2: u8 = 2;

fn default_policy_hash_version() -> u8 {
    POLICY_HASH_V1
}

impl PolicyVersion {
    pub fn next<H: PolicyHasher>(&self, hasher: &H, app: &Application, gate: &GatePolicy) -> Result<Self, String> {
        if gate.gate_id != self.gate_id {
            return Err("a policy version cannot change its gate id".into());
        }
        let next_hash = hash_policy_versioned(
            hasher,
            app,
            gate,
            self.version + 1,
            POLICY_HASH_V2,
        )?;
        // A deliberate re-publish of a legacy v1 policy is a migration, even if its visible
        // resource and threshold did not change.  v2 binds the missing authority fields.
        if self.policy_hash_version == POLICY_HASH_V2
            && self.policy == *gate
            && self.policy_context.as_ref() == Some(&PublishedApplicationContext::from_application(app))
        {
            return Err(
                "policy is unchanged; publish a change or leave the version alone"
                    .into(),
            );
        }
        Ok(PolicyVersion {
            application_id: app.application_id.clone(),
            gate_id: gate.gate_id.clone(),
            version: self.version + 1,
            policy_hash: next_hash,
            policy_hash_version: POLICY_HASH_V2,
            policy_context: Some(PublishedApplicationContext::from_application(app)),
            network: self.network,
            genesis_hash: self.genesis_hash.clone(),
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
    // The application's revision is deliberately EXCLUDED: it is bookkeeping that moves on every
    // edit, while a policy version's digest must stay stable for exactly as long as that version
    // is the published truth. What IS included is everything that changes what the policy MEANS:
    // the owner (who may re-publish), the topology (how tiers resolve) and every gate field.
    canonical.push_str(&format!("|{}|{}|{}", app.owner_credential, app.topology.topology_code(), app.network));
    canonical.push_str(&format!("|{}", app.genesis_hash));
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

/// Canonical policy-hash v2.  This deliberately does not change [`canonical_form`]: existing
/// v1 policy hashes must continue to mean exactly what they meant when they were signed and
/// published.  New publications bind every runtime authorization setting omitted by v1,
/// including the surface (`use_mode`) and application production/trust requirement.
pub fn canonical_form_v2(app: &Application, gate: &GatePolicy, version: u64) -> Vec<u8> {
    let mut canonical = String::new();
    canonical.push_str(&format!("v2|{}|{}|{}", app.application_id, gate.gate_id, version));
    canonical.push_str(&format!(
        "|{}|{}|{}|{}|{}|{}",
        app.owner_credential,
        app.topology.topology_code(),
        app.network,
        app.genesis_hash,
        app.production,
        app.default_session_ttl,
    ));
    canonical.push_str(&format!(
        "|{}|{}|{}|{}|{}",
        gate.resource_address, gate.threshold_raw, gate.divisibility, gate.symbol, gate.name
    ));
    canonical.push_str(&format!(
        "|{:?}|{}|{}|{}|{}|{}|{}|{}",
        gate.proof_mode,
        gate.challenge_domain,
        gate.session_ttl_override.unwrap_or(app.default_session_ttl),
        gate.enabled,
        gate.test_lane,
        gate.grants.join(","),
        gate.component_address.as_deref().unwrap_or(""),
        gate.use_mode.as_str(),
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

/// Hash a policy using its recorded canonicalization version. Unknown versions are never
/// best-effort decoded: callers must fail closed rather than silently weaken a future format.
pub fn hash_policy_versioned<H: PolicyHasher>(
    hasher: &H,
    app: &Application,
    gate: &GatePolicy,
    version: u64,
    policy_hash_version: u8,
) -> Result<String, String> {
    match policy_hash_version {
        POLICY_HASH_V1 => Ok(hash_policy(hasher, app, gate, version)),
        POLICY_HASH_V2 => Ok(hasher.hex_digest(&canonical_form_v2(app, gate, version))),
        other => Err(format!("unsupported policy hash version {other}")),
    }
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
            network: crate::network::LOCALNET,
            genesis_hash: "00f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0".into(),
            chain_generation: 1,
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
            use_mode: Default::default(),
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
    fn challenge_domain_keeps_local_identities_and_requires_exact_https_for_hosted() {
        assert!(validate_challenge_domain("Crypt.localhost").is_ok(), "the existing local identity remains valid");
        assert!(validate_challenge_domain("https://ghost-gate-staging.gsxrspartan.workers.dev").is_ok());

        for invalid in [
            "http://ghost-gate-staging.gsxrspartan.workers.dev",
            "https://ghost-gate-staging.gsxrspartan.workers.dev/verify",
            "https://admin@ghost-gate-staging.gsxrspartan.workers.dev",
            "https://ghost-gate-staging.gsxrspartan.workers.dev:443",
            "https://ghost-gate-staging.gsxrspartan.workers.dev:0001",
            "ghost-gate-staging.gsxrspartan.workers.dev",
            "not a domain.localhost",
        ] {
            assert!(validate_challenge_domain(invalid).is_err(), "{invalid:?} must fail closed");
        }
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

        // The revision is bookkeeping, NOT identity: a version's digest has to stay stable while
        // that version is the published truth, so unrelated edits elsewhere in the application must
        // not move it. (An earlier build included the revision and refused to load its own registry
        // the moment an operator wired tiers on an already-published application.)
        let mut a2 = a.clone();
        a2.revision = 99;
        assert_eq!(base, hash_policy(&h, &a2, &g, 1), "the revision must NOT move a published digest");

        // The ledger identity is identity, though: a gate on another cohort, or on another chain
        // that reuses the same addresses, is a different gate and must never share a digest.
        let mut other_net = a.clone();
        other_net.network = crate::network::STAGENET;
        assert_ne!(base, hash_policy(&h, &other_net, &g, 1), "the cohort must change the hash");
        let mut other_genesis = a.clone();
        other_genesis.genesis_hash = "deadbeef".into();
        assert_ne!(base, hash_policy(&h, &other_genesis, &g, 1), "the genesis identity must change the hash");
        // Ownership and topology decide what the policy means, so they stay in.
        let mut other_owner = a.clone();
        other_owner.owner_credential = "someone-else".into();
        assert_ne!(base, hash_policy(&h, &other_owner, &g, 1), "the owner must change the hash");
        let mut other_topology = a.clone();
        other_topology.topology = match a.topology {
            GateTopology::Independent => GateTopology::Hierarchical,
            GateTopology::Hierarchical => GateTopology::Independent,
        };
        assert_ne!(base, hash_policy(&h, &other_topology, &g, 1), "the topology must change the hash");

        let mut g5 = g.clone();
        g5.grants = vec!["x".into()];
        assert_ne!(base, hash_policy(&h, &a, &g5, 1), "grants must change the hash");

        // Version is part of the identity too.
        assert_ne!(hash_policy(&h, &a, &g, 2), base, "version must change the hash");

        let v2 = hash_policy_versioned(&h, &a, &g, 1, POLICY_HASH_V2).unwrap();
        let mut other_scope = g.clone();
        other_scope.use_mode = GateUseMode::Both;
        assert_ne!(v2, hash_policy_versioned(&h, &a, &other_scope, 1, POLICY_HASH_V2).unwrap(), "v2 must bind the allowed surface");
        let mut production = a.clone();
        production.production = !production.production;
        assert_ne!(v2, hash_policy_versioned(&h, &production, &g, 1, POLICY_HASH_V2).unwrap(), "v2 must bind the required trust tier");
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
            policy_hash_version: POLICY_HASH_V1,
            policy_context: None,
            network: crate::network::LOCALNET,
            genesis_hash: a.genesis_hash.clone(),
            policy: g.clone(),
            app_revision: a.revision,
            created_unix: 1,
        };
        // Re-publishing a v1 policy deliberately migrates it to v2, even without a visible
        // policy change.  The stored v1 hash remains verifiable; it is never reinterpreted.
        let migrated = v1.next(&h, &a, &g).unwrap();
        assert_eq!(migrated.policy_hash_version, POLICY_HASH_V2);
        assert!(migrated.next(&h, &a, &g).is_err(), "an unchanged v2 policy is not re-cut");
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
    fn credential_gate_without_component_is_valid() {
        let mut a = app();
        let mut g = gate("cred");
        g.proof_mode = ProofMode::Credential;
        g.component_address = None;
        a.gates.push(g);
        assert!(a.validate().is_ok(), "a credential gate without a component must be accepted");
    }

    #[test]
    fn credential_gate_with_component_is_refused() {
        let mut a = app();
        let mut g = gate("cred");
        g.proof_mode = ProofMode::Credential;
        g.component_address = Some("component_abc".into());
        a.gates.push(g);
        assert!(a.validate().is_err(), "a credential gate with a component must be refused");
    }

    #[test]
    fn consensus_gate_without_component_is_refused() {
        let mut a = app();
        let mut g = gate("cons");
        g.proof_mode = ProofMode::Consensus;
        g.component_address = None;
        a.gates.push(g);
        assert!(a.validate().is_err(), "a consensus gate without a component must be refused");
    }

    #[test]
    fn consensus_gate_with_component_is_valid() {
        let mut a = app();
        let g = gate("cons"); // default: Consensus + component_abc
        a.gates.push(g);
        assert!(a.validate().is_ok(), "a consensus gate with a valid component must be accepted");
    }

    #[test]
    fn trust_tier_ordering_and_properties() {
        assert!(TrustTier::Development < TrustTier::OperatorTrustedTestnet);
        assert!(TrustTier::OperatorTrustedTestnet < TrustTier::Production);
        assert!(!TrustTier::Development.permits_production());
        assert!(!TrustTier::OperatorTrustedTestnet.permits_production());
        assert!(TrustTier::Production.permits_production());
        assert_eq!(TrustTier::default(), TrustTier::Development);
    }

    #[test]
    fn proof_mode_max_trust_tier() {
        assert_eq!(ProofMode::Consensus.max_trust_tier(), TrustTier::Production);
        assert_eq!(ProofMode::Credential.max_trust_tier(), TrustTier::OperatorTrustedTestnet);
        assert_eq!(ProofMode::Xtm.max_trust_tier(), TrustTier::Development);
    }

    #[test]
    fn trust_tier_display_and_as_str() {
        assert_eq!(TrustTier::Development.as_str(), "development");
        assert_eq!(TrustTier::OperatorTrustedTestnet.as_str(), "operator-trusted-testnet");
        assert_eq!(TrustTier::Production.as_str(), "production");
        assert_eq!(format!("{}", TrustTier::Development), "development");
        assert_eq!(format!("{}", TrustTier::Production), "production");
    }

    fn opted_in() -> TrustPolicy {
        TrustPolicy { operator_trusted_indexer: true, max_tier: TrustTier::Production }
    }

    #[test]
    fn evidence_classification_table() {
        let p = opted_in();
        let independent_fresh = Evidence::ConsensusVerified(ConsensusAttestation::fixture(
            AnchorClass::IndependentlyAuthenticated, Freshness::Authenticated, "d"));
        let independent_stale = Evidence::ConsensusVerified(ConsensusAttestation::fixture(
            AnchorClass::IndependentlyAuthenticated, Freshness::RelativeOnly, "d"));
        let release_fresh = Evidence::ConsensusVerified(ConsensusAttestation::fixture(
            AnchorClass::ReleaseBootstrap, Freshness::Authenticated, "d"));
        let wallet = Evidence::OperatorWalletReceipt { digest: "d".into() };
        let indexer = Evidence::IndexerAsserted { digest: "d".into() };

        assert_eq!(Evidence::None.kind().ceiling(&p), TrustTier::Development);
        assert_eq!(indexer.kind().ceiling(&p), TrustTier::OperatorTrustedTestnet);
        assert_eq!(indexer.kind().ceiling(&TrustPolicy::default()), TrustTier::Development,
            "indexer assertions need the explicit operator opt-in");
        assert_eq!(wallet.kind().ceiling(&p), TrustTier::OperatorTrustedTestnet);
        assert_eq!(release_fresh.kind().ceiling(&p), TrustTier::OperatorTrustedTestnet,
            "a release-bootstrap anchor never reaches production, whatever its freshness");
        assert_eq!(independent_stale.kind().ceiling(&p), TrustTier::OperatorTrustedTestnet);
        assert_eq!(independent_fresh.kind().ceiling(&p), TrustTier::Production);
    }

    #[test]
    fn a_consensus_mode_gate_does_not_make_a_wallet_receipt_production() {
        let p = opted_in();
        assert_eq!(ProofMode::Consensus.max_trust_tier(), TrustTier::Production, "the mode's ceiling");
        assert_eq!(achieved_tier(EvidenceKind::OperatorWalletReceipt, ProofMode::Consensus, &p),
            TrustTier::OperatorTrustedTestnet, "the achieved tier comes from the evidence");
        assert_eq!(achieved_tier(EvidenceKind::ConsensusIndependentAuthenticatedFreshness, ProofMode::Credential, &p),
            TrustTier::OperatorTrustedTestnet, "credential mode stays capped by its own ceiling");
    }

    #[test]
    fn evidence_from_the_wrong_proof_machinery_achieves_nothing() {
        let p = opted_in();
        assert_eq!(achieved_tier(EvidenceKind::IndexerAsserted, ProofMode::Consensus, &p), TrustTier::Development);
        assert_eq!(achieved_tier(EvidenceKind::OperatorWalletReceipt, ProofMode::Credential, &p), TrustTier::Development);
        assert_eq!(achieved_tier(EvidenceKind::ConsensusIndependentAuthenticatedFreshness, ProofMode::Xtm, &p), TrustTier::Development);
        assert_eq!(achieved_tier(EvidenceKind::None, ProofMode::Consensus, &p), TrustTier::Development);
    }

    #[test]
    fn the_operator_ceiling_only_lowers() {
        let fresh = EvidenceKind::ConsensusIndependentAuthenticatedFreshness;
        let capped = TrustPolicy::parse(Some("1"), Some("operator-trusted-testnet"));
        assert_eq!(fresh.ceiling(&capped), TrustTier::OperatorTrustedTestnet);
        assert_eq!(EvidenceKind::None.ceiling(&TrustPolicy::parse(None, Some("production"))), TrustTier::Development,
            "a high ceiling never raises weak evidence");
        assert_eq!(TrustPolicy::parse(None, Some("unlimited")).max_tier, TrustTier::Development,
            "an unrecognised ceiling fails closed");
        assert_eq!(TrustPolicy::parse(None, None).max_tier, TrustTier::Production);
        assert!(!TrustPolicy::parse(Some("true"), None).operator_trusted_indexer, "only the exact value 1 opts in");
        assert!(TrustPolicy::parse(Some("1"), None).operator_trusted_indexer);
    }

    #[test]
    fn the_required_tier_follows_the_current_application_policy() {
        let mut a = app();
        a.production = false;
        assert_eq!(required_tier(&a), TrustTier::OperatorTrustedTestnet);
        a.production = true;
        assert_eq!(required_tier(&a), TrustTier::Production);
        assert!(required_tier(&a) > TrustTier::Development);
    }

    #[test]
    fn legacy_records_load_as_no_evidence() {
        assert_eq!(EvidenceKind::default(), EvidenceKind::None);
        assert_eq!(Evidence::None.digest(), "");
    }

    #[test]
    fn an_unknown_or_rolled_back_generation_authorizes_nothing() {
        // 0 is "unknown" — no development or testnet bypass, on any application.
        assert_eq!(effective_generation(0, 0), None);
        assert_eq!(effective_generation(0, 5), None);
        // A declared generation below the durable floor is a rollback: a restored older config.
        assert_eq!(effective_generation(1, 2), None);
        assert_eq!(effective_generation(4, 5), None);
        // Steady state: declared == floor, and a freshly migrated generation.
        assert_eq!(effective_generation(1, 1), Some(1));
        assert_eq!(effective_generation(5, 5), Some(5));
        // declared may sit at the floor; it can never be raised above it except by migration,
        // which raises the floor in the same operation, so declared > floor is never a steady
        // state — but if observed it is still the live generation (the floor only ever lags up).
        assert_eq!(effective_generation(6, 5), Some(6));
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
