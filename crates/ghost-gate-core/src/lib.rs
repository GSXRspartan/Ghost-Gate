//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! Ghost Gate's consensus-visible proof-qualification rules.
//!
//! This crate holds every rule that decides whether a stealth transfer statement counts as a
//! Ghost Gate proof. It is deliberately free of engine and wallet dependencies: the on-chain
//! template and the off-chain verifier both compile the *same* function, so a relying site can
//! never disagree with consensus about what a valid proof looks like.
//!
//! What is proven: the statement carries at least one live, unspent, key-path-authorised stealth
//! output whose public `minimum_value_promise` is at least the gate threshold, and the hidden value
//! behind that commitment is proven to lie in `[minimum_value_promise, 2^64)` by the aggregated
//! bulletproof. That is a proof of control of *at least* X, never of an exact amount.
//!
//! What is NOT proven, and cannot be: that the qualifying output belongs to the prover. A stealth
//! output is spendable by whoever holds its spend key, and only the creator learns that key. The
//! gate can require the output be *key-spendable*; it cannot require it be *the caller's*. See
//! `docs/PRIVACY_MODEL.md`.

#![deny(unsafe_code)]

use minicbor::{CborLen, Decode, Encode};
use tari_template_lib_types::{
    ComponentAddress, Hash32, MaxBytes, ResourceAddress,
    stealth::{SpendAuthorization, StealthTransferStatement, StealthUnspentOutput},
};

use crate::binding_hash::BindingHash;

/// Short mark for the product, used in events and receipts.
pub const MARK: &str = "GG";

/// Domain separator for any Ghost Gate binding hash.
///
/// Bound into every challenge commitment so a value produced for Ghost Gate can never be replayed
/// into another protocol, and vice versa.
pub const GHOST_GATE_DOMAIN: &[u8] = b"tari.ghost_gate.v1";

/// Longest accepted relying-site identifier, in bytes.
pub const MAX_RELYING_SITE_LEN: usize = 64;

/// Longest accepted session commitment, in bytes.
pub const MAX_SESSION_COMMITMENT_LEN: usize = 64;

/// Network byte identifying Tari's live testnet cohort.
///
/// Ootle's `Network` enum starts at `Esmeralda = 0` for mainnet and continues through the testnet
/// cohorts; `Next` is the value a freshly built transaction carries and is what a template sees for
/// a transaction that has not been pinned to a specific cohort. Recorded rather than assumed: a
/// template has no host call that reports the network, so the network binding is enforced by the
/// validator admitting the transaction at all, and by this constant only checking that the prover
/// and the gate agree. See `docs/V042_SOURCE_TRACE.md`, finding 31.
pub const NETWORK_BYTE: u8 = 0;

/// The relying site's one-shot challenge.
///
/// Issued by the relying site, bound into the transaction carrying the proof, and burned on use. It
/// carries no identifying information: no IP, no account, no user id. `nonce` is what makes each
/// challenge single-use and `expires_epoch` bounds how long a prover may take to answer.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, CborLen)]
pub struct Challenge {
    /// The Ghost Gate component this challenge was issued for, so it cannot be moved between gates.
    #[n(0)]
    pub gate: ComponentAddress,
    /// The resource the threshold is denominated in.
    #[n(1)]
    pub resource: ResourceAddress,
    /// The threshold, in the resource's smallest unit, the proof must meet.
    #[n(2)]
    pub threshold: u64,
    /// Chain identity the challenge is valid on.
    #[n(3)]
    pub network: u8,
    /// Cryptographically random single-use value.
    #[n(4)]
    pub nonce: Hash32,
    /// Last epoch in which the challenge may be answered.
    #[n(5)]
    pub expires_epoch: u64,
    /// Opaque identifier of the relying site, so a proof for site A cannot be redeemed at site B.
    #[n(6)]
    pub relying_site: MaxBytes<MAX_RELYING_SITE_LEN>,
    /// Opaque browser-session commitment, so a proof cannot be lifted into another browser session.
    #[n(7)]
    pub session_commitment: MaxBytes<MAX_SESSION_COMMITMENT_LEN>,
}

impl Challenge {
    /// The digest a prover commits to when building the proof transaction.
    ///
    /// Every field participates, so a proof built for one challenge cannot satisfy another. This is
    /// a binding device, not an authentication token: the single-use guarantee is the nonce being
    /// burned in gate state, which is consensus data.
    pub fn commitment(&self) -> Hash32 {
        let mut hasher = BindingHash::new(GHOST_GATE_DOMAIN);
        hasher.update(self.gate.as_object_key().array());
        hasher.update(self.resource.as_object_key().array());
        hasher.update(&self.threshold.to_le_bytes());
        hasher.update(&[self.network]);
        hasher.update(self.nonce.as_slice());
        hasher.update(&self.expires_epoch.to_le_bytes());
        hasher.update(self.relying_site.as_slice());
        hasher.update(self.session_commitment.as_slice());
        hasher.finish()
    }
}

/// A gate's immutable policy, fixed at construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, CborLen)]
pub struct GatePolicy {
    /// The resource the threshold is denominated in.
    #[n(0)]
    pub resource: ResourceAddress,
    /// The minimum hidden value, in the resource's smallest unit, a proof must carry.
    #[n(1)]
    pub threshold: u64,
    /// Whether the gate is currently accepting proofs.
    #[n(2)]
    pub open: bool,
}

/// Everything a gate learned from a single accepted proof.
///
/// Contains no value, no address and no identity. A receipt is safe to hand to an indexer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, CborLen)]
pub struct ProofReceipt {
    /// The qualifying output's public lower bound. Public by construction: the bulletproof commits
    /// to it.
    #[n(0)]
    pub attested_minimum: u64,
    /// Number of live inputs the proof consumed.
    #[n(1)]
    pub input_count: u32,
    /// The challenge nonce burned by this proof.
    #[n(2)]
    pub challenge_nonce: Hash32,
}

/// Why a statement was refused as a Ghost Gate proof.
///
/// Every variant is a consensus rule. The template panics with `reason()`, which the engine surfaces
/// as the transaction's rejection reason, so a refused proof is legible to the prover and to the
/// relying site without either re-implementing the rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateError {
    /// The gate is not accepting proofs.
    GateClosed,
    /// The challenge names a different gate.
    WrongGate,
    /// The challenge names a different resource than the gate's policy.
    WrongResource,
    /// The challenge's threshold does not match the gate's threshold.
    ThresholdMismatch,
    /// The challenge names a different network.
    NetworkMismatch,
    /// The challenge names a different relying site.
    RelyingSiteMismatch,
    /// The challenge names a different browser session.
    SessionMismatch,
    /// The challenge's expiry has passed.
    ChallengeExpired,
    /// The statement spends no stealth inputs, so it proves control of nothing live.
    NoStealthInputs,
    /// A spent input is not authorised by the key path, so ordinary wallet ownership is not what is
    /// being exercised.
    NonKeyPathInput,
    /// The statement reveals an input amount in cleartext, which defeats the point of the gate.
    RevealedInput,
    /// The statement creates a revealed output, which publishes an exact amount.
    RevealedOutput,
    /// The statement creates no stealth output, so there is nothing to attest to.
    NoStealthOutputs,
    /// The statement creates more than one stealth output, so "the qualifying output" is ambiguous.
    TooManyOutputs,
    /// The qualifying output's `minimum_value_promise` is below the gate threshold.
    BelowThreshold { attested: u64, required: u64 },
    /// The qualifying output is not key-spendable, so the funds would be locked in a condition tree
    /// rather than held by the prover.
    NotKeySpendable,
    /// The statement carries no balance proof, so value conservation is unproven.
    MissingBalanceProof,
    /// The challenge nonce has already been burnt by an earlier proof.
    ChallengeAlreadyUsed,
}

impl GateError {
    /// A stable, human-readable reason, used as the template's panic message.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::GateClosed => "GG: gate is not accepting proofs",
            Self::WrongGate => "GG: challenge is for a different gate",
            Self::WrongResource => "GG: challenge resource does not match gate policy",
            Self::ThresholdMismatch => "GG: challenge threshold does not match gate policy",
            Self::NetworkMismatch => "GG: challenge network does not match this chain",
            Self::RelyingSiteMismatch => "GG: challenge is for a different relying site",
            Self::SessionMismatch => "GG: challenge is for a different browser session",
            Self::ChallengeExpired => "GG: challenge has expired",
            Self::NoStealthInputs => "GG: proof must spend at least one live stealth input",
            Self::NonKeyPathInput => "GG: every input must be authorised by the key path",
            Self::RevealedInput => "GG: proof must not reveal an input amount",
            Self::RevealedOutput => "GG: proof must not reveal an output amount",
            Self::NoStealthOutputs => "GG: proof must create exactly one stealth output",
            Self::TooManyOutputs => "GG: proof must create exactly one stealth output",
            Self::BelowThreshold { .. } => "GG: attested minimum is below the gate threshold",
            Self::NotKeySpendable => "GG: qualifying output must be key-spendable",
            Self::MissingBalanceProof => "GG: proof must carry a balance proof",
            Self::ChallengeAlreadyUsed => "GG: challenge nonce has already been used",
        }
    }
}

impl core::fmt::Display for GateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BelowThreshold { attested, required } => {
                write!(f, "{} (attested {attested}, required {required})", self.reason())
            },
            other => f.write_str(other.reason()),
        }
    }
}

/// The single stealth output a Ghost Gate proof must create.
///
/// Exactly one, so "the qualifying output" is never ambiguous: there is no ordering to argue about
/// and no way to smuggle value past the check in a second output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QualifyingOutput<'a> {
    pub output: &'a StealthUnspentOutput,
}

impl QualifyingOutput<'_> {
    /// The output's public lower bound on its hidden value.
    pub fn attested_minimum(&self) -> u64 {
        self.output.output.minimum_value_promise
    }
}

/// The challenge context a gate checks a proof against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateContext<'a> {
    /// The gate component being executed.
    pub self_address: ComponentAddress,
    /// The consensus epoch the transaction is executing in.
    pub current_epoch: u64,
    /// The network byte the challenge must carry.
    pub current_network: u8,
    /// The relying-site identifier configured at gate construction.
    pub relying_site: &'a [u8],
    /// The browser-session commitment configured at gate construction.
    pub session_commitment: &'a [u8],
}

/// Validates `challenge` against `policy` and the execution context.
///
/// Checked before the statement is even inspected, so a challenge from the wrong gate, the wrong
/// site or the wrong network costs the validator nothing beyond a comparison.
pub fn check_challenge(
    policy: &GatePolicy,
    challenge: &Challenge,
    ctx: &GateContext<'_>,
    already_used: bool,
) -> Result<(), GateError> {
    if !policy.open {
        return Err(GateError::GateClosed);
    }
    if challenge.gate != ctx.self_address {
        return Err(GateError::WrongGate);
    }
    if challenge.resource != policy.resource {
        return Err(GateError::WrongResource);
    }
    if challenge.threshold != policy.threshold {
        return Err(GateError::ThresholdMismatch);
    }
    if challenge.network != ctx.current_network {
        return Err(GateError::NetworkMismatch);
    }
    if challenge.relying_site.as_slice() != ctx.relying_site {
        return Err(GateError::RelyingSiteMismatch);
    }
    if challenge.session_commitment.as_slice() != ctx.session_commitment {
        return Err(GateError::SessionMismatch);
    }
    if ctx.current_epoch > challenge.expires_epoch {
        return Err(GateError::ChallengeExpired);
    }
    if already_used {
        return Err(GateError::ChallengeAlreadyUsed);
    }
    Ok(())
}

/// Identifies the one stealth output that satisfies `policy.threshold` in `statement`.
///
/// Refuses anything ambiguous rather than guessing. A statement with two outputs is refused, not
/// resolved, because "which one was the proof" would otherwise have two answers and no consensus
/// rule to pick between them.
pub fn find_qualifying_output<'a>(
    policy: &GatePolicy,
    statement: &'a StealthTransferStatement,
) -> Result<QualifyingOutput<'a>, GateError> {
    let outputs = &statement.outputs_statement.outputs;

    if statement.inputs_statement.inputs.is_empty() {
        return Err(GateError::NoStealthInputs);
    }
    if statement
        .inputs_statement
        .inputs
        .iter()
        .any(|input| !input.witness.is_key_path())
    {
        return Err(GateError::NonKeyPathInput);
    }
    if !statement.inputs_statement.revealed_amount.is_zero() {
        return Err(GateError::RevealedInput);
    }
    if statement.outputs_statement.revealed_output.is_some() {
        return Err(GateError::RevealedOutput);
    }
    if outputs.is_empty() {
        return Err(GateError::NoStealthOutputs);
    }
    if outputs.len() > 1 {
        return Err(GateError::TooManyOutputs);
    }
    if statement.balance_proof.is_none() {
        return Err(GateError::MissingBalanceProof);
    }

    let output = &outputs[0];

    // Key-spendable, not locked in a condition tree. A script-only output would satisfy the
    // threshold while parking the funds behind a predicate, which is not what "you control enough
    // right now" means, and it would leave a public beacon attached to the funds.
    if output.auth.spend_key().is_none() {
        return Err(GateError::NotKeySpendable);
    }

    let attested = output.output.minimum_value_promise;
    if attested < policy.threshold {
        return Err(GateError::BelowThreshold {
            attested,
            required: policy.threshold,
        });
    }

    Ok(QualifyingOutput { output })
}

/// Full qualification: challenge context first, then the statement's shape.
pub fn qualify(
    policy: &GatePolicy,
    challenge: &Challenge,
    statement: &StealthTransferStatement,
    ctx: &GateContext<'_>,
    already_used: bool,
) -> Result<ProofReceipt, GateError> {
    check_challenge(policy, challenge, ctx, already_used)?;

    let qualifying = find_qualifying_output(policy, statement)?;

    Ok(ProofReceipt {
        attested_minimum: qualifying.attested_minimum(),
        input_count: statement.inputs_statement.inputs.len() as u32,
        challenge_nonce: challenge.nonce,
    })
}

/// Whether `auth` is spendable through the key path, i.e. by proving ownership of a key.
pub fn is_key_spendable(auth: &SpendAuthorization) -> bool {
    auth.spend_key().is_some()
}

/// Domain-separated 32-byte binding hash for the consensus path.
///
/// FNV-1a widened to 32 bytes: **not** collision resistant, and deliberately named so nobody
/// mistakes it for SHA-256. A template has no business pulling in a hash crate it does not need, and
/// this digest is not a security boundary — it binds public, already-committed fields. The
/// single-use guarantee is the nonce being burned in gate state. Replacing this with SHA-256 is a
/// tracked hardening item in `docs/THREAT_MODEL.md`.
pub mod binding_hash {
    use tari_template_lib_types::Hash32;

    const FNV_OFFSET: u128 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u128 = 0x0000_0000_0100_0000_0000_0000_0000_013b;

    /// FNV-1a 128-bit, widened to 32 bytes. NOT collision resistant.
    pub struct BindingHash {
        state: u128,
    }

    impl BindingHash {
        pub fn new(domain: &[u8]) -> Self {
            let mut state = FNV_OFFSET;
            for byte in domain {
                state ^= u128::from(*byte);
                state = state.wrapping_mul(FNV_PRIME);
            }
            Self { state }
        }

        pub fn update(&mut self, data: &[u8]) {
            for byte in data {
                self.state ^= u128::from(*byte);
                self.state = self.state.wrapping_mul(FNV_PRIME);
            }
        }

        pub fn finish(self) -> Hash32 {
            let mut out = [0u8; 32];
            out[..16].copy_from_slice(&self.state.to_be_bytes());
            out[16..].copy_from_slice(&self.state.rotate_left(64).to_be_bytes());
            Hash32::from_array(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tari_template_lib_types::ObjectKey;

    const RESOURCE: ResourceAddress = ResourceAddress::new(ObjectKey::from_array([7u8; ObjectKey::LENGTH]));

    fn challenge() -> Challenge {
        Challenge {
            gate: ComponentAddress::new(ObjectKey::from_array([1u8; ObjectKey::LENGTH])),
            resource: RESOURCE,
            threshold: 10_000,
            network: NETWORK_BYTE,
            nonce: Hash32::zero(),
            expires_epoch: 100,
            relying_site: MaxBytes::new_checked(b"vip.example".to_vec()).unwrap(),
            session_commitment: MaxBytes::new_checked(b"session-1".to_vec()).unwrap(),
        }
    }

    fn policy() -> GatePolicy {
        GatePolicy {
            resource: RESOURCE,
            threshold: 10_000,
            open: true,
        }
    }

    fn ctx() -> GateContext<'static> {
        GateContext {
            self_address: ComponentAddress::new(ObjectKey::from_array([1u8; ObjectKey::LENGTH])),
            current_epoch: 1,
            current_network: NETWORK_BYTE,
            relying_site: b"vip.example",
            session_commitment: b"session-1",
        }
    }

    #[test]
    fn challenge_commitment_is_deterministic() {
        assert_eq!(challenge().commitment(), challenge().commitment());
    }

    #[test]
    fn commitment_covers_every_challenge_field() {
        let base = challenge().commitment();

        let mut mutated = challenge();
        mutated.nonce = Hash32::from_array([9u8; 32]);
        assert_ne!(base, mutated.commitment(), "nonce");

        let mut mutated = challenge();
        mutated.gate = ComponentAddress::new(ObjectKey::from_array([3u8; ObjectKey::LENGTH]));
        assert_ne!(base, mutated.commitment(), "gate");

        let mut mutated = challenge();
        mutated.resource = ResourceAddress::new(ObjectKey::from_array([4u8; ObjectKey::LENGTH]));
        assert_ne!(base, mutated.commitment(), "resource");

        let mut mutated = challenge();
        mutated.threshold = 10_001;
        assert_ne!(base, mutated.commitment(), "threshold");

        let mut mutated = challenge();
        mutated.network = NETWORK_BYTE.wrapping_add(1);
        assert_ne!(base, mutated.commitment(), "network");

        let mut mutated = challenge();
        mutated.expires_epoch = 101;
        assert_ne!(base, mutated.commitment(), "expiry");

        let mut mutated = challenge();
        mutated.relying_site = MaxBytes::new_checked(b"other.example".to_vec()).unwrap();
        assert_ne!(base, mutated.commitment(), "relying site");

        let mut mutated = challenge();
        mutated.session_commitment = MaxBytes::new_checked(b"session-2".to_vec()).unwrap();
        assert_ne!(base, mutated.commitment(), "session");
    }

    #[test]
    fn a_matching_challenge_passes() {
        assert_eq!(check_challenge(&policy(), &challenge(), &ctx(), false), Ok(()));
    }

    #[test]
    fn threshold_below_gate_is_refused() {
        let mut challenge = challenge();
        challenge.threshold = 9_999;
        assert_eq!(
            check_challenge(&policy(), &challenge, &ctx(), false),
            Err(GateError::ThresholdMismatch)
        );
    }

    #[test]
    fn expired_challenge_is_refused() {
        let mut ctx = ctx();
        ctx.current_epoch = 101;
        assert_eq!(
            check_challenge(&policy(), &challenge(), &ctx, false),
            Err(GateError::ChallengeExpired)
        );
    }

    #[test]
    fn challenge_expiring_this_epoch_is_still_valid() {
        let mut challenge = challenge();
        challenge.expires_epoch = 1;
        assert_eq!(check_challenge(&policy(), &challenge, &ctx(), false), Ok(()));
    }

    #[test]
    fn wrong_relying_site_is_refused() {
        let mut ctx = ctx();
        ctx.relying_site = b"evil.example";
        assert_eq!(
            check_challenge(&policy(), &challenge(), &ctx, false),
            Err(GateError::RelyingSiteMismatch)
        );
    }

    #[test]
    fn wrong_session_is_refused() {
        let mut ctx = ctx();
        ctx.session_commitment = b"session-9";
        assert_eq!(
            check_challenge(&policy(), &challenge(), &ctx, false),
            Err(GateError::SessionMismatch)
        );
    }

    #[test]
    fn wrong_network_is_refused() {
        let mut ctx = ctx();
        ctx.current_network = NETWORK_BYTE.wrapping_add(1);
        assert_eq!(
            check_challenge(&policy(), &challenge(), &ctx, false),
            Err(GateError::NetworkMismatch)
        );
    }

    #[test]
    fn wrong_gate_is_refused() {
        let mut ctx = ctx();
        ctx.self_address = ComponentAddress::new(ObjectKey::from_array([3u8; ObjectKey::LENGTH]));
        assert_eq!(
            check_challenge(&policy(), &challenge(), &ctx, false),
            Err(GateError::WrongGate)
        );
    }

    #[test]
    fn closed_gate_refuses_everything() {
        let mut closed = policy();
        closed.open = false;
        assert_eq!(
            check_challenge(&closed, &challenge(), &ctx(), false),
            Err(GateError::GateClosed)
        );
    }

    #[test]
    fn used_challenge_is_refused() {
        assert_eq!(
            check_challenge(&policy(), &challenge(), &ctx(), true),
            Err(GateError::ChallengeAlreadyUsed)
        );
    }

    #[test]
    fn below_threshold_message_names_both_numbers() {
        let text = GateError::BelowThreshold {
            attested: 4_000,
            required: 10_000,
        }
        .to_string();
        assert!(text.contains("4000"), "{text}");
        assert!(text.contains("10000"), "{text}");
    }
}