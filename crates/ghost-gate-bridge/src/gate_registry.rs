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

use ghost_gate_core::{Challenge, network};
use tari_template_lib_types::{ComponentAddress, Hash32, MaxBytes, ResourceAddress};

use crate::session::{ChallengeBook, IssuedChallenge};

/// Everything a registered gate is, as the bridge understands it.
///
/// The resource address is the asset's identity. `symbol` is display only and is never compared, never
/// matched, and never returned as authority: it is carried so a UI can render something a person can
/// read, and a caller cannot change it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateBinding {
    /// The gate component's address on chain.
    pub address: ComponentAddress,
    /// The resource the threshold is denominated in. Authority.
    pub resource: ResourceAddress,
    /// The raw threshold, in the resource's smallest unit.
    pub threshold: u64,
    /// The Ootle cohort byte the gate is bound to.
    pub network: u8,
    /// Opaque relying-site identity the gate compares. Opaque here too.
    pub relying_site: MaxBytes<64>,
    /// Decimal places, for display only. Read from the gate at registration; no rule uses it.
    pub divisibility: u8,
    /// Display name for a UI. Never authority.
    pub symbol: String,
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
}

impl GateRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a gate under `id`, reading its policy from what the caller resolved on chain.
    ///
    /// The caller is an operator with chain access, so `binding` is trusted here; everything after
    /// this call is checked against it.
    pub fn register(
        &mut self,
        id: impl Into<String>,
        binding: GateBinding,
    ) -> Result<(), GateRegistrationError> {
        let id = id.into();
        if self.gates.contains_key(&id) {
            return Err(GateRegistrationError::DuplicateGate(id));
        }
        if binding.threshold == 0 {
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
            gate_address: g.address.to_string(),
            resource_address: g.resource.to_string(),
            threshold: g.threshold,
            network: g.network,
            divisibility: g.divisibility,
            symbol: g.symbol.clone(),
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
    pub fn issue_challenge(
        &self,
        id: &str,
        book: &mut ChallengeBook,
        session_commitment: &[u8],
        expires_in: std::time::Duration,
        issued_to_origin: Option<String>,
        expires_epoch: u64,
    ) -> Result<IssuedChallenge, crate::session::BookError> {
        let gate = self.gates.get(id).ok_or(crate::session::BookError::Unknown)?;
        let challenge = Challenge {
            gate: gate.address,
            resource: gate.resource,
            threshold: gate.threshold,
            network: gate.network,
            nonce: Hash32::from_array(crate::session::random_nonce()),
            // The epoch bound is defence in depth; the wall-clock TTL above is the operative
            // liveness limit and the nonce burn is the single-use guarantee. The second-pass audit
            // caught the hard-coded 0: on any chain at epoch > 0 the gate would refuse every
            // bridge-minted challenge, which is fail-closed but functionally dead.
            expires_epoch,
            relying_site: gate.relying_site.clone(),
            session_commitment: max_bytes(session_commitment).ok_or(crate::session::BookError::Unknown)?,
        };
        book.insert(challenge.clone(), expires_in, issued_to_origin.clone())?;
        Ok(IssuedChallenge {
            challenge,
            expires_at: std::time::SystemTime::now() + expires_in,
            issued_to_origin,
        })
    }
}

/// The metadata a browser may read about a gate.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicGate {
    pub gate_id: String,
    pub gate_address: String,
    pub resource_address: String,
    pub threshold: u64,
    pub network: u8,
    pub divisibility: u8,
    pub symbol: String,
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
        GateBinding {
            address: ComponentAddress::new(ObjectKey::from_array([1u8; 32])),
            resource: ResourceAddress::new(ObjectKey::from_array([7u8; 32])),
            threshold: 1_000_000,
            network: NETWORK,
            relying_site: MaxBytes::new_checked(b"vip.example".to_vec()).unwrap(),
            divisibility: 2,
            symbol: "GHOSTTEST".to_string(),
        }
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
        assert_eq!(meta.resource_address, binding().resource.to_string());
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
        let mut b = binding();
        b.threshold = 0;
        assert_eq!(
            r.register("bad", b),
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
    fn two_fresh_challenges_differ() {
        let r = registry();
        let mut book = ChallengeBook::new();
        let a = r
            .issue_challenge("g1", &mut book, b"s", std::time::Duration::from_secs(60), None, 1_000)
            .unwrap();
        let b = r
            .issue_challenge("g1", &mut book, b"s", std::time::Duration::from_secs(60), None, 1_000)
            .unwrap();
        assert_ne!(
            a.challenge.nonce, b.challenge.nonce,
            "each challenge needs its own nonce"
        );
        assert_eq!(a.challenge.gate, binding().address);
        assert_eq!(a.challenge.resource, binding().resource);
        assert_eq!(a.challenge.threshold, binding().threshold);
        assert_eq!(a.challenge.network, binding().network);
    }

    #[test]
    fn a_challenge_cannot_be_issued_for_an_unregistered_gate() {
        let r = registry();
        let mut book = ChallengeBook::new();
        assert!(
            matches!(
                r.issue_challenge("nope", &mut book, b"s", std::time::Duration::from_secs(60), None, 1_000),
                Err(crate::session::BookError::Unknown)
            ),
            "an unregistered gate is an operator error, distinct from a saturated book"
        );
        assert_eq!(book.live(), 0, "and nothing is left behind in the book");
    }
}
