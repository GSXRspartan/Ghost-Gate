//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! The validation every proof request passes.
//!
//! This module holds the bridge's security policy and nothing else: no I/O, no clock of its own, no
//! wallet. That is deliberate. Every rule a caller could try to get past is a pure function of
//! (registered gate, caller-supplied challenge, session commitment), so the whole boundary can be
//! exercised in unit tests without a node, a wallet or a network.
//!
//! # The rules, and what each is for
//!
//! 1. **The gate must be registered.** A caller cannot introduce a gate.
//! 2. **The challenge must be one this bridge minted, still live, and not already answered.** A caller
//!    cannot present a challenge from elsewhere, an old one, or a second answer to the same one.
//! 3. **The challenge must name the registered gate, resource, threshold and network.** A caller cannot
//!    move a threshold or change the asset.
//! 4. **The challenge must belong to the session presenting it.** A proof captured in one browser
//!    session cannot be redeemed in another.
//!
//! Note what is *absent*: no amount, no resource, no UTXO, no recipient. A caller cannot ask this
//! bridge to spend anything at all — the wallet picks the qualifying input, inside the gate's own
//! resource, and the caller cannot influence which.

use serde::{Deserialize, Serialize};
use tari_template_lib_types::Hash32;

use crate::gate_registry::GateBinding;
use crate::session::{BookError, ChallengeBook};

/// What a browser asks for when it wants to prove access.
///
/// `deny_unknown_fields` is load-bearing rather than tidy. Without it, serde drops a field it does not
/// know and the request proceeds -- so a caller that sends `amount`, `resource` or `utxos` believing it
/// is steering the spend would get a `202` and no indication that its input was ignored. Refusing the
/// request is the only honest answer: it cannot be satisfied, and saying so is better than accepting it
/// silently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProveRequest {
    /// The gate id, as the browser was told by `GET /gate/:id`.
    pub gate_id: String,
    /// The challenge the bridge returned from `POST /gate/:id/challenge`, hex-encoded.
    pub challenge_nonce: String,
    /// The session commitment the browser received when that challenge was issued.
    pub session_commitment: String,
}

/// Why a proof request was refused before anything was built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProofRefusal {
    #[error("GG: no such gate")]
    UnknownGate,
    #[error("GG: challenge is malformed")]
    MalformedChallenge,
    #[error("GG: challenge is not one this bridge issued")]
    UnknownChallenge,
    #[error("GG: challenge has expired; request a fresh one")]
    Expired,
    #[error("GG: challenge has already been answered")]
    AlreadyAnswered,
    #[error("GG: challenge belongs to a different browser session")]
    SessionMismatch,
    #[error("GG: the gate policy was replaced while this challenge was outstanding; request a fresh one")]
    PolicyReplaced,
    #[error("GG: challenge names a different gate than the one requested")]
    GateMismatch,
    #[error("GG: challenge names a different resource than the gate's policy")]
    ResourceMismatch,
    #[error("GG: challenge threshold does not match the gate's policy")]
    ThresholdMismatch,
    #[error("GG: challenge names a different network than the gate's policy")]
    NetworkMismatch,
    #[error("GG: challenge names a different relying site than the gate's policy")]
    RelyingSiteMismatch,
    #[error("GG: this challenge's proof machinery does not match the gate's")]
    KindMismatch,
}

impl From<BookError> for ProofRefusal {
    fn from(e: BookError) -> Self {
        match e {
            BookError::Unknown => Self::UnknownChallenge,
            BookError::Expired => Self::Expired,
            BookError::Consumed => Self::AlreadyAnswered,
            BookError::SessionMismatch => Self::SessionMismatch,
            BookError::InProgress => Self::AlreadyAnswered,
            BookError::Superseded => Self::PolicyReplaced,
            // A saturated book is not a property of *this* challenge; it surfaces on issue, never
            // on validate. Mapped here so the conversion stays total.
            BookError::TooManyChallenges => Self::UnknownChallenge,
        }
    }
}

/// Validates a proof request against the registered gate and the bridge's own challenge book.
///
/// Returns the challenge the bridge will answer, or the reason it will not. On success the challenge
/// is still **live**: it is retired only after the network accepts the proof, so a user who was turned
/// away can try again in the same session.
pub fn validate_prove_request(
    gate: &GateBinding,
    book: &ChallengeBook,
    request: &ProveRequest,
    caller_origin: Option<&str>,
) -> Result<crate::session::AnyChallenge, ProofRefusal> {
    let nonce = parse_nonce(&request.challenge_nonce)?;
    let session = parse_session(&request.session_commitment)?;

    // Liveness and single-use first: there is no point comparing a challenge that was never ours, or
    // one that has already been spent, against the gate's policy.
    // A submitted challenge still needs full origin/session/policy validation for an idempotent
    // retry. Only `reserve_for_submission` decides whether a new proof job may be created.
    book.check_current(&nonce, &session)?;

    let issued = book.peek(&nonce).map_err(ProofRefusal::from)?;

    // The session binding is enforced against the *issuer*, not just the submitted value. The
    // session commitment travels inside the challenge response, so possession of the pair proves
    // nothing about who is presenting it; the issuing origin is the part of the binding a reader
    // cannot forge. Operator callers (no Origin) may only answer operator challenges.
    let same_origin = match (issued.issued_to_origin.as_deref(), caller_origin) {
        (None, None) => true,
        (Some(issuer), Some(caller)) => crate::origin::normalise(issuer) == crate::origin::normalise(caller),
        _ => false,
    };
    if !same_origin {
        return Err(ProofRefusal::SessionMismatch);
    }

    let issued = issued.challenge.clone();

    // The machinery must match before any field is compared: an Ootle challenge can never answer an
    // XTM gate and vice versa, whatever its fields say.
    match (&gate.condition, &issued) {
        (
            crate::gate_registry::GateCondition::Ootle { .. },
            crate::session::AnyChallenge::Ootle(_),
        )
        | (
            crate::gate_registry::GateCondition::MinotariXtm { .. },
            crate::session::AnyChallenge::MinotariXtm(_),
        ) => {},
        _ => return Err(ProofRefusal::KindMismatch),
    }

    // Ootle-only bindings. A credential-only gate has no component to compare, so the challenge's
    // gate address is checked against the zero sentinel instead: the same deterministic value the
    // challenge minted, so the binding holds without an on-chain component.
    if issued.ootle().is_some() {
        if issued.ootle_gate() != Some(gate.component().copied().unwrap_or(crate::gate_registry::NO_COMPONENT)) {
            return Err(ProofRefusal::GateMismatch);
        }
        if issued.ootle_resource() != gate.resource().copied() {
            return Err(ProofRefusal::ResourceMismatch);
        }
    }
    if issued.threshold() != gate.threshold() {
        return Err(ProofRefusal::ThresholdMismatch);
    }
    if issued.network() != gate.network {
        return Err(ProofRefusal::NetworkMismatch);
    }
    if issued.relying_site() != gate.relying_site.as_slice() {
        return Err(ProofRefusal::RelyingSiteMismatch);
    }

    Ok(issued)
}

/// The comparison every challenge field makes, stated once.
fn parse_nonce(hex: &str) -> Result<[u8; 32], ProofRefusal> {
    let bytes = hex::decode(hex.trim()).map_err(|_| ProofRefusal::MalformedChallenge)?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| ProofRefusal::MalformedChallenge)
}

fn parse_session(hex: &str) -> Result<Vec<u8>, ProofRefusal> {
    hex::decode(hex.trim()).map_err(|_| ProofRefusal::MalformedChallenge)
}

/// The nonce as the gate and a relying site exchange it: hex, lowercase.
pub fn nonce_to_hex(nonce: &Hash32) -> String {
    hex::encode(nonce.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate_registry::GateBinding;
    use crate::session::{ChallengeBook, IssuedChallenge};
    use std::time::Duration;
    use tari_template_lib_types::{ComponentAddress, MaxBytes, ObjectKey, ResourceAddress};

    const NETWORK: u8 = ghost_gate_core::network::LOCALNET;

    fn binding() -> GateBinding {
        GateBinding::ootle(
            Some(ComponentAddress::new(ObjectKey::from_array([1u8; 32]))),
            ResourceAddress::new(ObjectKey::from_array([7u8; 32])),
            10_000,
            NETWORK,
            MaxBytes::new_checked(b"vip.example".to_vec()).unwrap(),
            6,
            "GHOSTTEST".into(),
        )
    }

    fn challenge(nonce: u8) -> crate::session::AnyChallenge {
        crate::session::AnyChallenge::Ootle(ghost_gate_core::Challenge {
            gate: *binding().component().unwrap(),
            resource: *binding().resource().unwrap(),
            threshold: binding().threshold(),
            network: NETWORK,
            nonce: Hash32::from_array([nonce; 32]),
            expires_epoch: 1_000,
            relying_site: binding().relying_site.clone(),
            session_commitment: MaxBytes::new_checked(b"aa".to_vec()).unwrap(),
        })
    }

    fn request(nonce: u8) -> ProveRequest {
        ProveRequest {
            gate_id: "g1".into(),
            challenge_nonce: hex::encode([nonce; 32]),
            session_commitment: hex::encode(b"aa"),
        }
    }

    fn book(nonce: u8) -> ChallengeBook {
        let mut b = ChallengeBook::new();
        b.insert(challenge(nonce), Duration::from_secs(60), None).unwrap();
        b
    }

    #[test]
    fn a_request_for_a_gate_the_bridge_serves_is_accepted() {
        let book = book(1);
        let issued = validate_prove_request(&binding(), &book, &request(1), None).expect("accepted");
        assert_eq!(issued.nonce().into_array(), [1u8; 32]);
    }

    #[test]
    fn a_challenge_this_bridge_never_issued_is_refused() {
        // Correct shape, correct session, but nonce 9 was never inserted.
        assert_eq!(
            validate_prove_request(&binding(), &book(1), &request(9), None).unwrap_err(),
            ProofRefusal::UnknownChallenge
        );
    }

    #[test]
    fn a_challenge_from_another_session_is_refused() {
        let mut req = request(1);
        req.session_commitment = hex::encode(b"bb");
        assert_eq!(
            validate_prove_request(&binding(), &book(1), &req, None).unwrap_err(),
            ProofRefusal::SessionMismatch
        );
    }

    #[test]
    fn an_already_answered_challenge_is_refused() {
        let mut book = book(1);
        book.consume_on_acceptance(&[1u8; 32], b"aa").unwrap();
        assert_eq!(
            validate_prove_request(&binding(), &book, &request(1), None).unwrap_err(),
            ProofRefusal::AlreadyAnswered
        );
    }

    #[test]
    fn an_expired_challenge_is_refused() {
        let mut book = ChallengeBook::new();
        book.insert(challenge(1), Duration::from_millis(1), None).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(
            validate_prove_request(&binding(), &book, &request(1), None).unwrap_err(),
            ProofRefusal::Expired
        );
    }

    /// The interesting one: a bridge that has issued a genuine challenge, for a genuine gate, must
    /// still refuse it once the gate's own policy has moved. A site lowering a threshold is exactly the
    /// case where a stale challenge must not be redeemable at the new, lower bar.
    #[test]
    fn a_challenge_is_refused_once_the_gates_policy_moved() {
        // Each mutation starts again from the registered binding, so a field is changed in isolation
        // and one mismatch cannot mask the next.
        let base = binding();
        let mut gate = base.clone();
        gate.condition = crate::gate_registry::GateCondition::Ootle {
            component: Some(ComponentAddress::new(ObjectKey::from_array([2u8; 32]))),
            resource: *base.resource().unwrap(),
            threshold: base.threshold(),
        };
        assert_eq!(
            validate_prove_request(&gate, &book(1), &request(1), None).unwrap_err(),
            ProofRefusal::GateMismatch
        );

        let mut gate = base.clone();
        gate.condition = crate::gate_registry::GateCondition::Ootle {
            component: Some(*base.component().unwrap()),
            resource: ResourceAddress::new(ObjectKey::from_array([8u8; 32])),
            threshold: base.threshold(),
        };
        assert_eq!(
            validate_prove_request(&gate, &book(1), &request(1), None).unwrap_err(),
            ProofRefusal::ResourceMismatch
        );

        let mut gate = base.clone();
        gate.condition = crate::gate_registry::GateCondition::Ootle {
            component: Some(*base.component().unwrap()),
            resource: *base.resource().unwrap(),
            threshold: 1,
        };
        assert_eq!(
            validate_prove_request(&gate, &book(1), &request(1), None).unwrap_err(),
            ProofRefusal::ThresholdMismatch
        );

        let mut gate = base.clone();
        gate.network = ghost_gate_core::network::ESMERALDA;
        assert_eq!(
            validate_prove_request(&gate, &book(1), &request(1), None).unwrap_err(),
            ProofRefusal::NetworkMismatch
        );

        let mut gate = base.clone();
        gate.relying_site = MaxBytes::new_checked(b"evil.example".to_vec()).unwrap();
        assert_eq!(
            validate_prove_request(&gate, &book(1), &request(1), None).unwrap_err(),
            ProofRefusal::RelyingSiteMismatch
        );
    }

    /// The cross-machinery substitution: an Ootle challenge presented to an XTM gate, and an XTM
    /// challenge presented to an Ootle gate. Neither is a threshold comparison — it is a type error,
    /// refused before any field is read.
    #[test]
    fn an_ootle_challenge_cannot_answer_an_xtm_gate() {
        use crate::gate_registry::{GateBinding, GateCondition};
        let xtm_gate = GateBinding::minotari_xtm(
            10_000,
            NETWORK,
            MaxBytes::new_checked(b"vip.example".to_vec()).unwrap(),
            "XTM".into(),
        );
        assert_eq!(
            validate_prove_request(&xtm_gate, &book(1), &request(1), None).unwrap_err(),
            ProofRefusal::KindMismatch
        );

        let mut xtm_book = ChallengeBook::new();
        xtm_book
            .insert(
                crate::session::AnyChallenge::MinotariXtm(ghost_gate_core::xtm::XtmChallenge {
                    gate_id: MaxBytes::new_checked(b"g1".to_vec()).unwrap(),
                    threshold_micro: 10_000,
                    network: NETWORK,
                    nonce: Hash32::from_array([1u8; 32]),
                    issued_at_unix: 0,
                    expires_at_unix: u64::MAX,
                    relying_site: MaxBytes::new_checked(b"vip.example".to_vec()).unwrap(),
                    session_commitment: MaxBytes::new_checked(b"aa".to_vec()).unwrap(),
                    tip_height_at_issue: 0,
                }),
                Duration::from_secs(60),
                None,
            )
            .unwrap();
        assert_eq!(
            validate_prove_request(&binding(), &xtm_book, &request(1), None).unwrap_err(),
            ProofRefusal::KindMismatch
        );
    }

    /// The credential-only case the refactor exists for: a gate with no on-chain component binds
    /// its challenge to the zero sentinel, and a proof answering that challenge validates. The
    /// resource, threshold, network, relying site and session must still be enforced — dropping
    /// the component must not drop any other binding.
    #[test]
    fn a_component_free_credential_gate_accepts_its_own_zero_sentinel_challenge() {
        let credential_gate = {
            let mut g = binding();
            g.condition = crate::gate_registry::GateCondition::Ootle {
                component: None,
                resource: *binding().resource().unwrap(),
                threshold: binding().threshold(),
            };
            g
        };
        // A credential-only book holds the zero-sentinel challenge this gate mints.
        const ZERO: ComponentAddress = ComponentAddress::new(ObjectKey::from_array([0u8; 32]));
        let mut zero_book = ChallengeBook::new();
        zero_book
            .insert(
                crate::session::AnyChallenge::Ootle(ghost_gate_core::Challenge {
                    gate: ZERO,
                    resource: *credential_gate.resource().unwrap(),
                    threshold: credential_gate.threshold(),
                    network: NETWORK,
                    nonce: Hash32::from_array([1u8; 32]),
                    expires_epoch: 1_000,
                    relying_site: credential_gate.relying_site.clone(),
                    session_commitment: MaxBytes::new_checked(b"aa".to_vec()).unwrap(),
                }),
                Duration::from_secs(60),
                None,
            )
            .unwrap();
        // The whole policy must still bind: every field matches, so the credential proof proceeds.
        assert_eq!(
            validate_prove_request(&credential_gate, &zero_book, &request(1), None),
            Ok(crate::session::AnyChallenge::Ootle(ghost_gate_core::Challenge {
                gate: ZERO,
                resource: *credential_gate.resource().unwrap(),
                threshold: credential_gate.threshold(),
                network: NETWORK,
                nonce: Hash32::from_array([1u8; 32]),
                expires_epoch: 1_000,
                relying_site: credential_gate.relying_site.clone(),
                session_commitment: MaxBytes::new_checked(b"aa".to_vec()).unwrap(),
            }))
        );
    }

    /// The sentinel collision guard: the zero "no component" address must never let a
    /// credential-only challenge authorize a component-bound gate, or vice versa. The sentinel is
    /// deterministic, so if either direction accepted, a credential proof would silently mint
    /// access to a consensus gate (or the reverse) with no on-chain evidence at all.
    #[test]
    fn the_zero_sentinel_cannot_substitute_for_a_real_component_gate() {
        const ZERO: ComponentAddress = ComponentAddress::new(ObjectKey::from_array([0u8; 32]));
        // Direction 1: a credential-only gate's zero-sentinel challenge presented to a
        // component-bound gate. The real component differs from the sentinel -> GateMismatch.
        let mut sentinel_book = ChallengeBook::new();
        sentinel_book
            .insert(
                crate::session::AnyChallenge::Ootle(ghost_gate_core::Challenge {
                    gate: ZERO,
                    resource: *binding().resource().unwrap(),
                    threshold: binding().threshold(),
                    network: NETWORK,
                    nonce: Hash32::from_array([1u8; 32]),
                    expires_epoch: 1_000,
                    relying_site: binding().relying_site.clone(),
                    session_commitment: MaxBytes::new_checked(b"aa".to_vec()).unwrap(),
                }),
                Duration::from_secs(60),
                None,
            )
            .unwrap();
        assert_eq!(
            validate_prove_request(&binding(), &sentinel_book, &request(1), None).unwrap_err(),
            ProofRefusal::GateMismatch
        );
        // Direction 2: a component-bound challenge presented to a credential-only gate. The
        // credential gate binds nothing, so the real component address also mismatches.
        let credential_gate = {
            let mut g = binding();
            g.condition = crate::gate_registry::GateCondition::Ootle {
                component: None,
                resource: *binding().resource().unwrap(),
                threshold: binding().threshold(),
            };
            g
        };
        assert_eq!(
            validate_prove_request(&credential_gate, &book(1), &request(1), None).unwrap_err(),
            ProofRefusal::GateMismatch
        );
    }

    #[test]
    fn a_malformed_nonce_is_refused_without_panicking() {
        for bad in ["", "zz", "00", &"ab".repeat(33)] {
            let mut req = request(1);
            req.challenge_nonce = bad.to_string();
            assert_eq!(
                validate_prove_request(&binding(), &book(1), &req, None).unwrap_err(),
                ProofRefusal::MalformedChallenge,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn validation_does_not_consume_the_challenge() {
        // A user declined once must be able to try again in the same session.
        let book = book(1);
        for _ in 0..3 {
            assert!(validate_prove_request(&binding(), &book, &request(1), None).is_ok());
        }
        assert_eq!(book.live(), 1);
        assert_eq!(book.answered(), 0);
    }

    #[test]
    fn an_unknown_field_is_refused_rather_than_ignored() {
        // A caller who sends `amount` and gets a 202 would reasonably believe they had asked for an
        // amount. Silence would be the worst possible answer.
        for extra in [
            r#""amount":1"#,
            r#""resource":"resource_deadbeef""#,
            r#""utxos":["utxo_a"]"#,
            r#""destination":"x""#,
            r#""minimum_value_promise":1"#,
        ] {
            let body = format!(
                r#"{{"gate_id":"g1","challenge_nonce":"{}",other}}"#,
                "ff".repeat(32)
            );
            let body = body.replacen("{}", &"ff".repeat(32), 1).replacen(
                ",other",
                &format!(",{extra}"),
                1,
            );
            assert!(
                serde_json::from_str::<ProveRequest>(&body).is_err(),
                "{extra} must not be accepted"
            );
        }
    }

    #[test]
    fn a_request_carries_no_spendable_parameters() {
        // The shape of the request is itself a security property: there is nowhere to put a resource, an
        // amount, a UTXO or a recipient, so there is nothing to validate away.
        let json = serde_json::to_string(&ProveRequest {
            gate_id: "g1".into(),
            challenge_nonce: "ff".into(),
            session_commitment: "aa".into(),
        })
        .unwrap();
        assert_eq!(
            json, r#"{"gate_id":"g1","challenge_nonce":"ff","session_commitment":"aa"}"#,
            "the prove request must serialise to exactly these three fields"
        );
    }

    #[test]
    fn an_issued_challenge_carries_the_gate_policy_not_the_callers() {
        let issued = IssuedChallenge {
            policy_hash: None,
            challenge: challenge(3),
            expires_at: std::time::SystemTime::now(),
            issued_to_origin: None,
            state: crate::session::ChallengeState::Issued,
        };
        let gate = binding();
        assert_eq!(issued.challenge.ootle_resource(), Some(*gate.resource().unwrap()));
        assert_eq!(issued.challenge.threshold(), gate.threshold());
        assert_eq!(issued.challenge.network(), gate.network);
        assert_eq!(
            issued.challenge.relying_site(),
            gate.relying_site.as_slice()
        );
    }

    // ------------------------------------------------------------------
    // Adversarial: cross-visitor session binding
    // ------------------------------------------------------------------

    /// A challenge issued to one origin cannot be proved from another. This is the per-visitor
    /// binding that prevents cross-site challenge replay, independent of the session commitment
    /// (which may be a shared deployment-time value for consensus gates).
    #[test]
    fn a_challenge_issued_to_one_origin_cannot_be_answered_from_another() {
        let mut book = ChallengeBook::new();
        book.insert(challenge(1), Duration::from_secs(60), Some("https://site-a.example".into())).unwrap();
        assert_eq!(
            validate_prove_request(&binding(), &book, &request(1), Some("https://site-b.example")).unwrap_err(),
            ProofRefusal::SessionMismatch,
            "a challenge minted for site-a must not be answerable from site-b"
        );
        assert!(validate_prove_request(&binding(), &book, &request(1), Some("https://site-a.example")).is_ok());
    }

    /// An operator (no-Origin) challenge cannot be answered by a browser (has Origin).
    #[test]
    fn an_operator_challenge_cannot_be_answered_by_a_browser_origin() {
        let mut book = ChallengeBook::new();
        book.insert(challenge(1), Duration::from_secs(60), None).unwrap();
        assert_eq!(
            validate_prove_request(&binding(), &book, &request(1), Some("https://vip.example")).unwrap_err(),
            ProofRefusal::SessionMismatch,
        );
        assert!(validate_prove_request(&binding(), &book, &request(1), None).is_ok());
    }

    /// A browser challenge cannot be answered by a no-origin operator caller.
    #[test]
    fn a_browser_challenge_cannot_be_answered_by_an_operator() {
        let mut book = ChallengeBook::new();
        book.insert(challenge(1), Duration::from_secs(60), Some("https://vip.example".into())).unwrap();
        assert_eq!(
            validate_prove_request(&binding(), &book, &request(1), None).unwrap_err(),
            ProofRefusal::SessionMismatch,
        );
    }
}
