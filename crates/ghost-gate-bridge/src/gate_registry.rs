//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! The gates this bridge serves.
//!
//! A gate is registered by the operator of the relying site, not by a caller. That is the whole
//! security boundary for configuration: a browser can ask about a registered gate and can ask for a
//! challenge against one, but it cannot introduce a gate, move a threshold, or point the bridge at a
//! different resource.
//!
//! # Why the binding is stored and not recomputed
//!
//! A gate's resource, threshold, network and relying-site identity are read **from the gate itself on
//! chain**, once, at registration. Every later request is checked against that stored binding rather
//! than against whatever the caller says. A compromised or stale front end therefore cannot talk the
//! bridge into a different answer: the worst it can do is ask a question the gate was already
//! registered to answer.
//!
//! `challenge.resource`, `challenge.threshold` and `challenge.network` are checked against this binding
//! on every proof request, so a challenge minted elsewhere -- or edited in transit -- does not become a
//! proof here.

use ghost_gate_core::xtm::XtmChallenge;
use ghost_gate_core::network;
use tari_template_lib_types::{ComponentAddress, Hash32 as TemplateHash32, MaxBytes, ObjectKey, ResourceAddress};

use crate::session::{AnyChallenge, ChallengeBook, IssuedChallenge};

/// Which proof machinery a gate requires.
///
/// A deliberate type, not a string comparison. The bridge dispatches on it, the challenge records
/// it, and a proof produced by one machinery can never answer a gate of the other: the challenge
/// types differ, the verification differs, and everything downstream of this enum is typed to
/// match. This is the property `docs/THREAT_MODEL.md` §3 leans on: cross-network substitution is
/// refused by construction, not by convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofKind {
    /// The Ootle stealth-fungible path: a consensus-committed statement at a gate component.
    Ootle,
    /// The native Minotari L1 path: a pay-to-self transaction with a consensus-enforced minimum
    /// value promise, verified against base-node data.
    MinotariXtm,
}

/// The typed condition a gate watches.
///
/// The Ootle condition names the on-chain gate component and the resource the threshold is
/// denominated in; the L1 condition is a native-XTM threshold only — XTM has no resource address
/// and no component, and inventing one would invite exactly the substitution the type exists to
/// prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateCondition {
    /// An Ootle gate. `component` is the on-chain gate template the **consensus** path executes
    /// `prove_access` against; the **credential** path never calls it, so credential-only gates
    /// may register with `component: None` — the challenge then binds to the zero component
    /// address ([`NO_COMPONENT`]) as an explicit "no component exists" sentinel, and the
    /// resource, threshold and network remain the authoritative policy. A `Some` component means
    /// the consensus path may also run against it; it does not mean the component is deployed on
    /// the gate's network.
    Ootle {
        /// The on-chain gate component, when the consensus path is intended.
        component: Option<ComponentAddress>,
        /// The resource the threshold is denominated in. Authority.
        resource: ResourceAddress,
        /// The raw threshold, in the resource's smallest unit.
        threshold: u64,
    },
    MinotariXtm {
        /// The threshold in micro-Minotari (base units; 1 XTM = 1,000,000 micro).
        threshold_micro: u64,
    },
}

/// The challenge-gate sentinel for a credential-only Ootle gate: the all-zero component address.
///
/// Credential-only gates have no on-chain component to execute, but the core `Challenge` type
/// always carries a gate address because the consensus path compares it against the executing
/// component. Binding the sentinel keeps that type honest: it is deterministic (both minter and
/// validator map "no component" to the same bytes), and it can only be minted by a
/// credential-only bridge gate — a real component gate carries its own address, so a sentinel
/// challenge can never authorize a component gate and vice versa.
pub const NO_COMPONENT: ComponentAddress = ComponentAddress::new(ObjectKey::from_array([0u8; 32]));

impl GateCondition {
    pub fn threshold(&self) -> u64 {
        match self {
            Self::Ootle { threshold, .. } => *threshold,
            Self::MinotariXtm { threshold_micro } => *threshold_micro,
        }
    }

    pub fn kind(&self) -> ProofKind {
        match self {
            Self::Ootle { .. } => ProofKind::Ootle,
            Self::MinotariXtm { .. } => ProofKind::MinotariXtm,
        }
    }
}

/// Everything a registered gate is, as the bridge understands it.
///
/// The condition's addresses are the asset's identity. `symbol` is display only and is never
/// compared, never matched, and never returned as authority: it is carried so a UI can render
/// something a person can read, and a caller cannot change it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateBinding {
    /// What the gate requires, typed by proof machinery.
    pub condition: GateCondition,
    /// The network byte the gate is bound to. The same table serves both networks.
    pub network: u8,
    /// Opaque relying-site identity the gate compares. Opaque here too.
    pub relying_site: MaxBytes<64>,
    /// Decimal places, for display only. Read from the gate at registration; no rule uses it.
    pub divisibility: u8,
    /// Display name for a UI. Never authority.
    pub symbol: String,
}

impl GateBinding {
    /// An Ootle gate, the original shape.
    pub fn ootle(
        component: Option<ComponentAddress>,
        resource: ResourceAddress,
        threshold: u64,
        network: u8,
        relying_site: MaxBytes<64>,
        divisibility: u8,
        symbol: String,
    ) -> Self {
        Self {
            condition: GateCondition::Ootle { component, resource, threshold },
            network,
            relying_site,
            divisibility,
            symbol,
        }
    }

    /// A native Minotari L1 XTM gate.
    pub fn minotari_xtm(threshold_micro: u64, network: u8, relying_site: MaxBytes<64>, symbol: String) -> Self {
        Self {
            condition: GateCondition::MinotariXtm { threshold_micro },
            network,
            // An L1 amount has six decimal places, always: 1 XTM = 10^6 micro. Display only.
            divisibility: ghost_gate_core::xtm::MICRO_PER_XTM.ilog10() as u8,
            symbol,
            relying_site,
        }
    }

    pub fn threshold(&self) -> u64 {
        self.condition.threshold()
    }

    pub fn kind(&self) -> ProofKind {
        self.condition.kind()
    }

    /// The gate component's address, for the Ootle kinds. `None` on L1, which has no component.
    /// For an Ootle credential-only gate this is `None` too: no component was bound.
    pub fn component(&self) -> Option<&ComponentAddress> {
        match &self.condition {
            GateCondition::Ootle { component, .. } => component.as_ref(),
            GateCondition::MinotariXtm { .. } => None,
        }
    }

    /// The resource the threshold is denominated in, for the Ootle kinds.
    pub fn resource(&self) -> Option<&ResourceAddress> {
        match &self.condition {
            GateCondition::Ootle { resource, .. } => Some(resource),
            GateCondition::MinotariXtm { .. } => None,
        }
    }
}

/// Why a gate could not be registered.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GateRegistrationError {
    #[error("GG: a gate with id {0} is already registered")]
    DuplicateGate(String),
    #[error("GG: threshold must be positive")]
    ZeroThreshold,
    #[error("GG: {network_byte:#04x} is not an Ootle cohort byte")]
    UnknownNetwork { network_byte: u8 },
    #[error("GG: a gate's relying site identity must not be empty")]
    EmptyRelyingSite,
}

/// The gates this bridge serves, keyed by the opaque id a browser is allowed to name.
#[derive(Debug, Clone, Default)]
pub struct GateRegistry {
    gates: std::collections::BTreeMap<String, GateBinding>,
    /// The administrator's scope per gate id (website / telegram / both), from the registry
    /// snapshot. Kept beside the binding so the Lab and the bot read the SAME answer.
    use_modes: std::collections::BTreeMap<String, String>,
}

impl GateRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a gate under `id`, reading its policy from what the caller resolved on chain.
    ///
    /// The caller is an operator with chain access, so `binding` is trusted here; everything after
    /// this call is checked against it.
    /// Records the administrator's scope for a gate. Called from the snapshot reload, never by a
    /// caller that could invent one.
    pub fn set_use_mode(&mut self, id: &str, mode: &str) {
        self.use_modes.insert(id.to_string(), mode.to_string());
    }

    /// The scope recorded for a gate, defaulting to `website` when unknown (the conservative default:
    /// a gate with no recorded scope authorizes the website, never Telegram by accident).
    pub fn use_mode_of(&self, id: &str) -> Option<String> {
        Some(self.use_modes.get(id).cloned().unwrap_or_else(|| "website".into()))
    }

    pub fn register(
        &mut self,
        id: impl Into<String>,
        binding: GateBinding,
    ) -> Result<(), GateRegistrationError> {
        let id = id.into();
        if self.gates.contains_key(&id) {
            return Err(GateRegistrationError::DuplicateGate(id));
        }
        if binding.threshold() == 0 {
            return Err(GateRegistrationError::ZeroThreshold);
        }
        if !network::is_known(binding.network) {
            return Err(GateRegistrationError::UnknownNetwork {
                network_byte: binding.network,
            });
        }
        if binding.relying_site.is_empty() {
            return Err(GateRegistrationError::EmptyRelyingSite);
        }
        self.gates.insert(id, binding);
        Ok(())
    }

    /// The gate registered under `id`.
    pub fn get(&self, id: &str) -> Option<&GateBinding> {
        self.gates.get(id)
    }

    /// Every registered id, for a site that wants to list what it operates.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.gates.keys().map(String::as_str)
    }

    /// Public metadata for `id`, as a browser is allowed to see it.
    ///
    /// Deliberately includes the resource **address** and not just a name: a site that renders a
    /// threshold needs to name the asset it is rendering for, and the address is the only thing that
    /// identifies it. Includes the raw threshold *and* the divisibility so the browser can format it
    /// itself and a mismatch is detectable rather than silently rounded.
    pub fn public_metadata(&self, id: &str) -> Option<PublicGate> {
        self.gates.get(id).map(|g| PublicGate {
            gate_id: id.to_string(),
            gate_address: g.component().map(|a| a.to_string()).unwrap_or_default(),
            resource_address: g.resource().map(|a| a.to_string()).unwrap_or_default(),
            threshold: g.threshold(),
            network: g.network,
            divisibility: g.divisibility,
            symbol: g.symbol.clone(),
            proof_kind: g.kind(),
        })
    }

    /// Mints a fresh, single-use challenge for the gate registered under `id`.
    ///
    /// The nonce comes from the OS RNG. It is public by construction: the prover has to publish it in
    /// the transaction, so it is a single-use token and not a secret, and its unpredictability is what
    /// makes "one challenge, one session" mean something.
    /// `Err(BookError::TooManyChallenges)` is a caller problem and reaches the route as a 429; the
    /// other `Err` cases (unknown gate, bad session encoding) are operator problems and reach it
    /// as a 500. Collapsing them into one `Option` would have turned the DoS cap into a generic
    /// "internal error", which is how a real limit hides.
    ///
    /// For an L1 XTM gate the challenge also records `tip_height_at_issue`, read from the chain
    /// reader the caller passes; `None` for that reader is a refusal — an L1 challenge minted
    /// without chain access could not be checked for freshness, so it is not minted at all.
    pub fn issue_challenge(
        &self,
        id: &str,
        book: &mut ChallengeBook,
        session_commitment: &[u8],
        expires_in: std::time::Duration,
        issued_to_origin: Option<String>,
        expires_epoch: u64,
        xtm_tip_height: Option<u64>,
        policy_hash: Option<String>,
    ) -> Result<IssuedChallenge, crate::session::BookError> {
        let gate = self.gates.get(id).ok_or(crate::session::BookError::Unknown)?;
        let session = max_bytes(session_commitment).ok_or(crate::session::BookError::Unknown)?;
        let now = std::time::SystemTime::now();
        let challenge = match &gate.condition {
            crate::gate_registry::GateCondition::Ootle { component, resource, threshold } => {
                // The core Challenge always carries a gate address because the consensus path
                // compares it against the executing component. A credential-only gate has no
                // component to execute, so the challenge binds to the zero address instead:
                // an explicit, deterministic "no component" sentinel. The resource, threshold,
                // network and nonce still bind the signature to this gate's policy, and the
                // zero sentinel can only be minted by a credential-only bridge gate — a real
                // component gate carries its own address, so the two never collide.
                AnyChallenge::Ootle(ghost_gate_core::Challenge {
                    gate: component.unwrap_or(NO_COMPONENT),
                    resource: *resource,
                    threshold: *threshold,
                    network: gate.network,
                    nonce: TemplateHash32::from_array(crate::session::random_nonce()),
                    // The epoch bound is defence in depth; the wall-clock TTL above is the operative
                    // liveness limit and the nonce burn is the single-use guarantee. The second-pass audit
                    // caught the hard-coded 0: on any chain at epoch > 0 the gate would refuse every
                    // bridge-minted challenge, which is fail-closed but functionally dead.
                    expires_epoch,
                    relying_site: gate.relying_site.clone(),
                    session_commitment: session.clone(),
                })
            },
            crate::gate_registry::GateCondition::MinotariXtm { threshold_micro } => {
                let tip_height = xtm_tip_height.ok_or(crate::session::BookError::Unknown)?;
                let issued_at = now
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or_default();
                AnyChallenge::MinotariXtm(XtmChallenge {
                    gate_id: max_bytes(id.as_bytes()).ok_or(crate::session::BookError::Unknown)?,
                    threshold_micro: *threshold_micro,
                    network: gate.network,
                    nonce: TemplateHash32::from_array(crate::session::random_nonce()),
                    issued_at_unix: issued_at,
                    expires_at_unix: issued_at + expires_in.as_secs(),
                    relying_site: gate.relying_site.clone(),
                    session_commitment: session.clone(),
                    tip_height_at_issue: tip_height,
                })
            },
        };
        book.insert_bound(challenge.clone(), expires_in, issued_to_origin.clone(), policy_hash.clone())?;
        Ok(IssuedChallenge {
            challenge,
            expires_at: now + expires_in,
            issued_to_origin,
            policy_hash,
            state: crate::session::ChallengeState::Issued,
        })
    }
}

/// The metadata a browser may read about a gate.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicGate {
    pub gate_id: String,
    /// The gate component's address, empty on an L1 gate (which has no component).
    pub gate_address: String,
    /// The resource address, empty on an L1 gate (native XTM has no resource address).
    pub resource_address: String,
    pub threshold: u64,
    pub network: u8,
    pub divisibility: u8,
    pub symbol: String,
    /// Which proof machinery this gate requires. Typed, and the browser renders it; it decides
    /// nothing.
    pub proof_kind: ProofKind,
}

/// Copies a session commitment into the bounded form the challenge carries.
///
/// `None` for anything over the limit, which the caller turns into "no challenge issued". A session
/// commitment that does not fit is refused rather than truncated: truncating two different sessions to
/// the same prefix would bind a proof to the wrong one.
fn max_bytes(value: &[u8]) -> Option<MaxBytes<64>> {
    MaxBytes::new_checked(value.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tari_template_lib_types::ObjectKey;

    const NETWORK: u8 = network::LOCALNET;

    fn binding() -> GateBinding {
        GateBinding::ootle(
            Some(ComponentAddress::new(ObjectKey::from_array([1u8; 32]))),
            ResourceAddress::new(ObjectKey::from_array([7u8; 32])),
            1_000_000,
            NETWORK,
            MaxBytes::new_checked(b"vip.example".to_vec()).unwrap(),
            2,
            "GHOSTTEST".to_string(),
        )
    }

    /// The million-XTM gate, as the final gate is configured: native L1, threshold in base units.
    fn xtm_binding() -> GateBinding {
        GateBinding::minotari_xtm(
            ghost_gate_core::xtm::MICRO_PER_XTM * 1_000_000,
            NETWORK,
            MaxBytes::new_checked(b"vip.example".to_vec()).unwrap(),
            "XTM".to_string(),
        )
    }

    fn registry() -> GateRegistry {
        let mut r = GateRegistry::new();
        r.register("g1", binding()).unwrap();
        r
    }

    #[test]
    fn a_registered_gate_is_readable_by_id() {
        let r = registry();
        let meta = r.public_metadata("g1").expect("registered");
        assert_eq!(meta.threshold, 1_000_000);
        assert_eq!(meta.divisibility, 2);
        assert_eq!(meta.symbol, "GHOSTTEST");
        assert_eq!(meta.resource_address, binding().resource().copied().unwrap().to_string());
        assert_eq!(r.ids().collect::<Vec<_>>(), vec!["g1"]);
    }

    #[test]
    fn an_unregistered_gate_is_invisible() {
        let r = registry();
        assert!(r.public_metadata("nope").is_none());
        assert!(r.get("nope").is_none());
    }

    #[test]
    fn registering_the_same_id_twice_is_refused() {
        let mut r = registry();
        assert_eq!(
            r.register("g1", binding()),
            Err(GateRegistrationError::DuplicateGate("g1".into()))
        );
    }

    #[test]
    fn a_zero_threshold_gate_is_refused() {
        let mut r = GateRegistry::new();
        let b = GateBinding::ootle(
            Some(*binding().component().unwrap()),
            *binding().resource().unwrap(),
            0,
            NETWORK,
            MaxBytes::new_checked(b"vip.example".to_vec()).unwrap(),
            2,
            "GHOSTTEST".to_string(),
        );
        assert_eq!(
            r.register("bad", b),
            Err(GateRegistrationError::ZeroThreshold)
        );
    }

    #[test]
    fn a_zero_threshold_xtm_gate_is_refused() {
        let mut r = GateRegistry::new();
        assert_eq!(
            r.register("bad", GateBinding::minotari_xtm(0, NETWORK, MaxBytes::new_checked(b"vip.example".to_vec()).unwrap(), "XTM".into())),
            Err(GateRegistrationError::ZeroThreshold)
        );
    }

    #[test]
    fn a_gate_on_an_unknown_cohort_byte_is_refused() {
        let mut r = GateRegistry::new();
        let mut b = binding();
        b.network = 0x03;
        assert_eq!(
            r.register("bad", b),
            Err(GateRegistrationError::UnknownNetwork { network_byte: 0x03 })
        );
    }

    #[test]
    fn an_xtm_gate_records_its_typed_condition() {
        let mut r = GateRegistry::new();
        r.register("otherside", xtm_binding()).unwrap();
        let meta = r.public_metadata("otherside").unwrap();
        assert_eq!(meta.proof_kind, ProofKind::MinotariXtm);
        assert_eq!(meta.threshold, ghost_gate_core::xtm::MICRO_PER_XTM * 1_000_000);
        assert_eq!(meta.symbol, "XTM");
        assert_eq!(meta.divisibility, 6);
        assert!(meta.gate_address.is_empty(), "an L1 gate has no component");
        assert!(meta.resource_address.is_empty(), "native XTM has no resource address");
    }

    #[test]
    fn an_ootle_gate_records_its_typed_condition() {
        let r = registry();
        assert_eq!(r.public_metadata("g1").unwrap().proof_kind, ProofKind::Ootle);
    }

    #[test]
    fn two_fresh_challenges_differ() {
        let r = registry();
        let mut book = ChallengeBook::new();
        let a = r
            .issue_challenge("g1", &mut book, b"s", std::time::Duration::from_secs(60), None, 1_000, None, None)
            .unwrap();
        let b = r
            .issue_challenge("g1", &mut book, b"s", std::time::Duration::from_secs(60), None, 1_000, None, None)
            .unwrap();
        assert_ne!(
            a.challenge.nonce(), b.challenge.nonce(),
            "each challenge needs its own nonce"
        );
        assert_eq!(a.challenge.ootle_gate(), Some(*binding().component().unwrap()));
        assert_eq!(a.challenge.ootle_resource(), Some(*binding().resource().unwrap()));
        assert_eq!(a.challenge.threshold(), binding().threshold());
        assert_eq!(a.challenge.network(), binding().network);
    }

    #[test]
    fn a_challenge_cannot_be_issued_for_an_unregistered_gate() {
        let r = registry();
        let mut book = ChallengeBook::new();
        assert!(
            matches!(
                r.issue_challenge("nope", &mut book, b"s", std::time::Duration::from_secs(60), None, 1_000, None, None),
                Err(crate::session::BookError::Unknown)
            ),
            "an unregistered gate is an operator error, distinct from a saturated book"
        );
        assert_eq!(book.live(), 0, "and nothing is left behind in the book");
    }

    #[test]
    fn an_xtm_challenge_cannot_be_issued_without_a_chain_reader() {
        // Fail closed: without a tip height there is no freshness check, so there is no challenge.
        let r = registry();
        let mut r2 = GateRegistry::new();
        r2.register("otherside", xtm_binding()).unwrap();
        let mut book = ChallengeBook::new();
        assert!(
            matches!(
                r2.issue_challenge("otherside", &mut book, b"s", std::time::Duration::from_secs(60), None, 1_000, None, None),
                Err(crate::session::BookError::Unknown)
            ),
            "an XTM challenge without chain access is refused, not minted unchecked"
        );
        assert_eq!(book.live(), 0);
    }

    #[test]
    fn an_xtm_challenge_records_the_tip_it_was_issued_at() {
        let mut r = GateRegistry::new();
        r.register("otherside", xtm_binding()).unwrap();
        let mut book = ChallengeBook::new();
        let issued = r
            .issue_challenge("otherside", &mut book, b"s", std::time::Duration::from_secs(60), None, 1_000, Some(77), None)
            .unwrap();
        match &issued.challenge {
            AnyChallenge::MinotariXtm(x) => {
                assert_eq!(x.tip_height_at_issue, 77);
                assert_eq!(x.threshold_micro, ghost_gate_core::xtm::MICRO_PER_XTM * 1_000_000);
                assert!(x.expires_at_unix > x.issued_at_unix);
            },
            other => panic!("expected an XTM challenge, got {other:?}"),
        }
    }
}
