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
//! # Which resources a gate can watch
//!
//! Any **stealth fungible** Ootle resource, identified by its resource address. tTARI is one
//! instance of that class, not a special case: the gate never reads a token symbol, a token name or a
//! divisibility, and a resource created by any user works exactly as native tTARI does. What the gate
//! requires is the property that produces the proof -- a per-output hidden value with a public lower
//! bound -- and that exists only for [`ResourceClass::StealthFungible`]. Public and confidential
//! fungible resources and non-fungibles are refused at construction, by name.
//!
//! # What is NOT proven, and cannot be: that the qualifying output belongs to the prover. A stealth
//! output is spendable by whoever holds its spend key, and only the creator learns that key. The
//! gate can require the output be *key-spendable*; it cannot require it be *the caller's*. See
//! `docs/PRIVACY_MODEL.md`.

#![deny(unsafe_code)]

use minicbor::{CborLen, Decode, Encode};
pub use tari_template_lib_types::Hash32;
use tari_template_lib_types::{
    ComponentAddress, MaxBytes, ResourceAddress,
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

/// Domain separator for the L1 XTM challenge's binding hash.
///
/// Deliberately distinct from [`GHOST_GATE_DOMAIN`]: an Ootle challenge's commitment must not be
/// interchangeable with an L1 one, even though both hash over similar fields.
pub const XTM_DOMAIN: &[u8] = b"tari.ghost_gate.xtm.v1";

/// Longest accepted relying-site identifier, in bytes.
pub const MAX_RELYING_SITE_LEN: usize = 64;

/// Longest accepted session commitment, in bytes.
pub const MAX_SESSION_COMMITMENT_LEN: usize = 64;

/// The Ootle network byte for each cohort.
///
/// Transcribed from `ootle_network::Network` (`#[repr(u8)]`, `as_byte()` is `self as u8`) in the
/// pinned v0.42.0 cohort, `crates/ootle_network/src/lib.rs`. Deliberately spelled out rather than
/// taken from the crate: this crate compiles to WASM inside a template, and a *named* constant is
/// checked by a reader against the enum, where a bare `0` is not.
///
/// ```text
/// MainNet    = 0x00        StageNet   = 0x01        NextNet = 0x02
/// LocalNet   = 0x10        Igor       = 0x24        Esmeralda = 0x26
/// ```
pub mod network {
    pub const MAINNET: u8 = 0x00;
    pub const STAGENET: u8 = 0x01;
    pub const NEXTNET: u8 = 0x02;
    pub const LOCALNET: u8 = 0x10;
    pub const IGOR: u8 = 0x24;
    /// The current public testnet cohort, and the SDK's `#[default]`.
    pub const ESMERALDA: u8 = 0x26;

    /// Every cohort byte Ghost Gate will accept as a plausible network binding.
    ///
    /// An unrecognised byte is still comparable -- the gate stores whatever the deploying site chose
    /// -- so this is a sanity list for callers, not a gate rule.
    pub const ALL: [u8; 6] = [MAINNET, STAGENET, NEXTNET, LOCALNET, IGOR, ESMERALDA];

    /// Whether `byte` names a cohort in [`ALL`].
    pub const fn is_known(byte: u8) -> bool {
        byte == MAINNET || byte == STAGENET || byte == NEXTNET || byte == LOCALNET || byte == IGOR ||
            byte == ESMERALDA
    }
}

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

/// The class of an Ootle resource, as a gate needs to reason about it.
///
/// Ghost Gate's guarantee is produced by a stealth bulletproof over
/// `[minimum_value_promise, 2^64)`. Only a **stealth** resource has such a proof to produce, so
/// only a stealth resource can be denominated in a threshold. The other three classes are named
/// here so a gate can refuse them *at construction* with a specific reason rather than accept a
/// configuration that can never be satisfied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceClass {
    /// Balance is public. A threshold can be proven with a plain balance check, but the balance
    /// would be visible, which is the opposite of the product.
    PublicFungible,
    /// Balance is hidden inside vaults, revealed per-output with its own proof. Not a stealth
    /// output: there is no per-output `minimum_value_promise` to pin a floor to.
    ConfidentialFungible,
    /// Individually identifiable and indivisible. There is no amount to threshold.
    NonFungible,
    /// Per-output hidden value with a public `minimum_value_promise` and an aggregated bulletproof.
    /// The only class Ghost Gate supports.
    StealthFungible,
}

impl ResourceClass {
    /// Whether Ghost Gate can prove a threshold in this class.
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::StealthFungible)
    }

    /// A short, stable name for the class, used in refusal messages.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PublicFungible => "public fungible",
            Self::ConfidentialFungible => "confidential fungible",
            Self::NonFungible => "non-fungible",
            Self::StealthFungible => "stealth fungible",
        }
    }
}

/// What a gate records about the resource it watches, read from chain at construction.
///
/// `divisibility` is **presentation only**. It is recorded so a relying site can render
/// `1,000,000 GHOSTTEST` instead of `1000000`, and it never enters a comparison. The consensus
/// comparison is `attested_minimum >= threshold` on raw units, which is correct for a divisibility
/// of 0 and of 18 alike. Keeping the two apart is what stops a rounding error in a UI from becoming
/// a gate that accepts the wrong amount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceProfile {
    /// Which class of resource this is.
    pub class: ResourceClass,
    /// Decimal places the resource's smallest unit is divisible into. Display only.
    pub divisibility: u8,
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
    /// Chain identity this gate is bound to.
    ///
    /// Per-gate rather than a compile-time constant, because the same template is published on every
    /// cohort: a gate deployed on LocalNet must bind to LocalNet and a gate deployed on Esmeralda to
    /// Esmeralda, and one baked-in byte cannot be both.
    ///
    /// What this still does **not** prove: a template has no host call that reports the network, so
    /// this is a self-consistency check between the deploying site and the prover's challenge, not
    /// an attestation of which chain executed. The real network binding is that the validator
    /// admitted the transaction at all. See `docs/V042_SOURCE_TRACE.md`, finding 31.
    #[n(3)]
    pub network: u8,
}

/// Everything a gate is configured with at construction.
///
/// The generalized constructor shape. A gate binds to a *resource address* and a *threshold*, not to
/// a token: the resource address is the security identity, and the symbol and name beside it are
/// presentation the gate never reads. Amounts are `u64` in the resource's own smallest unit -- never
/// floating point, because a threshold that has been through a float is not a threshold any more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateParams {
    /// The resource the threshold is denominated in. Authority, not a display string.
    pub resource: ResourceAddress,
    /// The minimum hidden value, in the resource's smallest unit, a proof must carry.
    pub threshold: u64,
    /// Opaque relying-site identity. The gate only compares it.
    pub relying_site: MaxBytes<MAX_RELYING_SITE_LEN>,
    /// Opaque browser-session commitment. The gate only compares it.
    pub session_commitment: MaxBytes<MAX_SESSION_COMMITMENT_LEN>,
    /// Chain identity this gate is bound to. See [`network`] for the byte values.
    pub network: u8,
}

impl GateParams {
    /// Validates the configuration and produces the policy to store.
    ///
    /// The two refusals here are the ones that would otherwise produce a gate that looks deployed
    /// and can never do anything useful:
    /// - a threshold of zero, which every statement trivially clears;
    /// - a resource class with no per-output `minimum_value_promise`, which has no proof to verify.
    pub fn into_policy(self, profile: &ResourceProfile) -> Result<GatePolicy, GateError> {
        if self.threshold == 0 {
            return Err(GateError::ThresholdNotPositive);
        }
        if !profile.class.is_supported() {
            return Err(GateError::UnsupportedResource {
                class: profile.class,
            });
        }
        Ok(GatePolicy {
            resource: self.resource,
            threshold: self.threshold,
            open: true,
            network: self.network,
        })
    }
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
    /// The gate was configured with a threshold of zero.
    ThresholdNotPositive,
    /// The gate was configured over a resource class with no per-output minimum value promise.
    UnsupportedResource { class: ResourceClass },
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
            Self::ThresholdNotPositive => "GG: threshold must be positive",
            Self::UnsupportedResource { .. } => "GG: a gate can only be denominated in a stealth fungible resource",
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
            Self::UnsupportedResource { class } => {
                write!(f, "{} (resource class: {})", self.reason(), class.as_str())
            },
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
    if challenge.network != policy.network {
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
pub mod xtm {
    //! Native Minotari L1 XTM proving: the challenge type and the provable-floor arithmetic.
    //!
    //! # How an L1 threshold is proven, precisely
    //!
    //! A Minotari confidential output publicly commits to a minimum value: `minimum_value_promise`
    //! (`MicroMinotari`) is a consensus field of `TransactionOutput`, part of the output's hash, and
    //! enforced by the bulletproof proving the hidden value lies in `[promise, 2^64)`. That alone
    //! proves an output *held* value at mining time, not that the prover still controls it, and not
    //! that the output is fresh. Three more pieces make it a Ghost Gate proof:
    //!
    //! 1. **The kernel fee.** A pay-to-self transaction's inputs minus its outputs equal the fee, so
    //!    `output_value >= promise` and `inputs <= balance` together give
    //!    `promise + fee <= balance_before`. The proof condition is therefore
    //!    `promise + kernel_fee >= threshold`, which reads both figures off consensus data (the
    //!    output and the kernel, both on chain) and is exact at the boundary: a wallet whose entire
    //!    spendable balance is exactly the threshold can promise `threshold - fee` on the output and
    //!    still prove the threshold. No fee headroom is demanded of the user.
    //! 2. **A spend-key signature over the challenge nonce.** The proving wallet signs the
    //!    challenge's 32-byte nonce with the qualifying output's script key; the bridge verifies
    //!    that signature against the script public key read **from the mined output on chain**. The
    //!    nonce is unknowable before the bridge issues the challenge, so no historical transaction
    //!    and no third party's transaction can be presented in its place: whoever answers must have
    //!    held the output's spend key at answer time.
    //! 3. **Freshness from chain state.** The kernel must be mined in a block above the tip height
    //!    recorded when the challenge was issued, with a block timestamp not earlier than the
    //!    challenge's issue time (small slack for miner clock jitter). A transaction created or
    //!    mined before the challenge existed is refused.
    //!
    //! What the bridge itself contributes: it initiates the transaction for each challenge and
    //! records the kernel signature it expects, so a browser can never nominate a transaction. The
    //! spend-key signature then makes that initiation belt-and-braces rather than load-bearing.
    //!
    //! # Units
    //!
    //! One XTM is 1,000,000 micro-Minotari (`tari_transaction_components::tari_amount`: `uT = 1`,
    //! `T = 1_000_000`). All arithmetic here is integer base units; there is no floating point and
    //! no display-figure rounding anywhere near a comparison.

    use minicbor::{CborLen, Decode, Encode};
    use tari_template_lib_types::{Hash32, MaxBytes};

    use crate::binding_hash::BindingHash;

    /// Micro-Minotari per XTM, from `tari_amount.rs`: `1 * T == 1_000_000 * uT`.
    pub const MICRO_PER_XTM: u64 = 1_000_000;

    /// Checked `micro_xtm -> u128` conversion for XTM display figures.
    ///
    /// Returns `None` when the XTM figure does not fit in base units — i.e. only when the caller
    /// tried to express a number the chain cannot hold. Never rounds.
    pub const fn xtm_to_micro(xtm: u64) -> Option<u128> {
        // u128::MAX / MICRO_PER_XTM >> u64::MAX, so no u64 XTM value can overflow this.
        Some(xtm as u128 * MICRO_PER_XTM as u128)
    }

    /// Longest accepted gate identifier, in bytes, matching the challenge's other string bounds.
    pub const MAX_GATE_ID_LEN: usize = crate::MAX_RELYING_SITE_LEN;

    /// How far behind a challenge's issue time a mining block's timestamp may fall and still count
    /// as fresh, in seconds. Miners may timestamp a block up to the median-time rule behind their
    /// wall clock; this slack absorbs that jitter without opening the door to pre-challenge
    /// transactions, which the height check rejects outright.
    pub const FRESHNESS_TIMESTAMP_SLACK_SECS: u64 = 120;

    /// The L1 XTM challenge: the relying site's one-shot question about native XTM.
    ///
    /// Same shape as [`crate::Challenge`] but for the base layer: there is no Ootle component or
    /// resource to name, so the gate is identified by its registered id, the threshold is in
    /// micro-Minotari, and expiry is wall clock (the L1 chain has no Ghost Gate template to compare
    /// epochs against). `tip_height_at_issue` is the base-layer tip when the challenge was minted;
    /// a qualifying kernel must be mined above that height, which is what makes a pre-existing
    /// transaction unusable.
    #[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, CborLen)]
    pub struct XtmChallenge {
        /// The bridge-registered gate id, so a challenge minted for one gate cannot answer another.
        #[n(0)]
        pub gate_id: MaxBytes<MAX_GATE_ID_LEN>,
        /// The threshold in micro-Minotari (base units; 1 XTM = [`MICRO_PER_XTM`] micro).
        #[n(1)]
        pub threshold_micro: u64,
        /// The Minotari network byte (same table as the Ootle cohorts: LocalNet 0x10, Esmeralda 0x26…).
        #[n(2)]
        pub network: u8,
        /// Cryptographically random single-use value. What the spend key signs.
        #[n(3)]
        pub nonce: Hash32,
        /// When the challenge was minted (Unix seconds). The freshness check reads it.
        #[n(4)]
        pub issued_at_unix: u64,
        /// Last second at which the challenge may be answered.
        #[n(5)]
        pub expires_at_unix: u64,
        /// Opaque relying-site identity, as on the Ootle challenge.
        #[n(6)]
        pub relying_site: MaxBytes<64>,
        /// Opaque browser-session commitment, as on the Ootle challenge.
        #[n(7)]
        pub session_commitment: MaxBytes<64>,
        /// The base-layer tip height when the challenge was minted. A qualifying kernel must be
        /// mined strictly above this, so a transaction that already existed is not fresh.
        #[n(8)]
        pub tip_height_at_issue: u64,
    }

    impl XtmChallenge {
        /// The digest binding every field of the challenge. Same role and same caveats as the
        /// Ootle challenge's commitment: a binding device, not the single-use mechanism.
        pub fn commitment(&self) -> Hash32 {
            let mut hasher = BindingHash::new(crate::XTM_DOMAIN);
            hasher.update(self.gate_id.as_slice());
            hasher.update(&self.threshold_micro.to_le_bytes());
            hasher.update(&[self.network]);
            hasher.update(self.nonce.as_slice());
            hasher.update(&self.issued_at_unix.to_le_bytes());
            hasher.update(&self.expires_at_unix.to_le_bytes());
            hasher.update(self.relying_site.as_slice());
            hasher.update(self.session_commitment.as_slice());
            hasher.update(&self.tip_height_at_issue.to_le_bytes());
            hasher.finish()
        }

        /// Whether this challenge has passed its expiry second.
        ///
        /// `now` is the caller's clock. The boundary is exclusive: a challenge expires *after* its
        /// last second, mirroring the Ootle challenge's inclusive epoch handling.
        pub fn is_expired(&self, now_unix: u64) -> bool {
            now_unix > self.expires_at_unix
        }
    }

    /// Why an L1 proof was refused. Every variant is a rule, as on the Ootle side: a stable reason
    /// string, a plain enum, no error-crate dependency — this crate compiles to WASM inside a
    /// template too.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum XtmProofError {
        /// The proving transaction was never mined within the verification window.
        NotMined,
        /// The proving kernel was mined below the challenge's tip height, so it is not fresh.
        StaleKernel,
        /// The proving block's timestamp predates the challenge.
        BlockPredatesChallenge,
        /// The wallet or chain is on a different network than the challenge names.
        NetworkMismatch,
        /// The qualifying output's promised floor plus the kernel fee is below the threshold.
        BelowThreshold,
        /// The spend-key signature over the challenge does not verify against the mined output.
        BadSpendSignature,
        /// The wallet could not construct a qualifying transaction at all.
        CannotConstruct,
        /// Arithmetic overflow computing the provable floor.
        Overflow,
    }

    impl XtmProofError {
        /// A stable, human-readable reason, mirroring `GateError::reason`.
        pub const fn reason(self) -> &'static str {
            match self {
                Self::NotMined => "GG: the proving transaction was never mined within the verification window",
                Self::StaleKernel => "GG: the proving kernel was mined below the challenge's tip height, so it is not fresh",
                Self::BlockPredatesChallenge => "GG: the proving block predates the challenge",
                Self::NetworkMismatch => "GG: the proving transaction is not on this challenge's network",
                Self::BelowThreshold => "GG: the promised floor plus the kernel fee is below the threshold",
                Self::BadSpendSignature => "GG: the spend-key signature over the challenge does not verify against the mined output",
                Self::CannotConstruct => "GG: the wallet could not construct a qualifying transaction",
                Self::Overflow => "GG: arithmetic overflow computing the provable floor",
            }
        }
    }

    impl core::fmt::Display for XtmProofError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str(self.reason())
        }
    }

    /// The provable floor a mined pay-to-self transaction establishes, in micro-Minotari.
    ///
    /// `minimum_value_promise` is the qualifying output's public floor and `kernel_fee` is the fee
    /// the transaction paid; inputs cover `output + fee`, so the wallet's balance before the
    /// transaction was at least `promise + fee`. The sum is computed in `u128`, where two `u64`s
    /// can never overflow, so the arithmetic is total and there is no error case to mis-handle.
    pub const fn provable_floor(minimum_value_promise_micro: u64, kernel_fee_micro: u64) -> u128 {
        minimum_value_promise_micro as u128 + kernel_fee_micro as u128
    }

    /// Whether the provable floor meets the threshold. The one L1 threshold comparison.
    pub fn floor_meets_threshold(floor_micro: u128, threshold_micro: u64) -> bool {
        floor_micro >= u128::from(threshold_micro)
    }

    /// The receipt an L1 proof leaves behind. Public, minimal, same discipline as
    /// [`crate::ProofReceipt`]: a floor, a count and the challenge nonce. No balance, no address.
    #[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, CborLen)]
    pub struct XtmProofReceipt {
        /// The floor the chain data proved: `minimum_value_promise + kernel fee`, micro-Minotari.
        /// A lower bound on what the wallet controlled; never the wallet's balance.
        #[n(0)]
        pub attested_floor_micro: u128,
        /// How many outputs the proving transaction carried (1 is the norm: the promised output;
        /// a self-transfer may also carry change, which is not part of the proof).
        #[n(1)]
        pub output_count: u32,
        /// The challenge nonce this proof consumed.
        #[n(2)]
        pub challenge_nonce: Hash32,
        /// Height of the block the proving kernel was mined into.
        #[n(3)]
        pub mined_height: u64,
    }
}

pub mod policy;

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

    /// The cohort these tests pretend to run on. Any cohort works, because the point of the tests is
    /// that the gate compares the challenge against *its own* configured byte.
    const NETWORK: u8 = network::LOCALNET;

    fn challenge() -> Challenge {
        Challenge {
            gate: ComponentAddress::new(ObjectKey::from_array([1u8; ObjectKey::LENGTH])),
            resource: RESOURCE,
            threshold: 10_000,
            network: NETWORK,
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
            network: NETWORK,
        }
    }

    fn ctx() -> GateContext<'static> {
        GateContext {
            self_address: ComponentAddress::new(ObjectKey::from_array([1u8; ObjectKey::LENGTH])),
            current_epoch: 1,
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
        mutated.network = NETWORK.wrapping_add(1);
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
        // The gate is bound to the network it was deployed for, so a challenge minted for another
        // cohort cannot be redeemed here.
        let mut policy = policy();
        policy.network = network::LOCALNET;
        let mut challenge = challenge();
        challenge.network = network::ESMERALDA;
        assert_eq!(
            check_challenge(&policy, &challenge, &ctx(), false),
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

    // -----------------------------------------------------------------------------------------
    // General resources
    // -----------------------------------------------------------------------------------------

    fn params() -> GateParams {
        GateParams {
            resource: RESOURCE,
            threshold: 10_000,
            relying_site: MaxBytes::new_checked(b"vip.example".to_vec()).unwrap(),
            session_commitment: MaxBytes::new_checked(b"session-1".to_vec()).unwrap(),
            network: NETWORK,
        }
    }

    fn profile(class: ResourceClass, divisibility: u8) -> ResourceProfile {
        ResourceProfile { class, divisibility }
    }

    #[test]
    fn only_the_stealth_fungible_class_is_supported() {
        assert!(ResourceClass::StealthFungible.is_supported());
        assert!(!ResourceClass::PublicFungible.is_supported());
        assert!(!ResourceClass::ConfidentialFungible.is_supported());
        assert!(!ResourceClass::NonFungible.is_supported());
    }

    #[test]
    fn any_stealth_fungible_resource_can_back_a_gate() {
        // Divisibility is a presentation property. Three resources with three different
        // divisibilities produce three identical gates, because nothing in the comparison uses it.
        for divisibility in [0u8, 2, 6, 18] {
            let policy = params()
                .into_policy(&profile(ResourceClass::StealthFungible, divisibility))
                .expect("a stealth fungible resource is supported at any divisibility");
            assert_eq!(policy.threshold, 10_000);
        }
    }

    #[test]
    fn an_unsupported_resource_class_is_refused_at_construction() {
        for class in [
            ResourceClass::PublicFungible,
            ResourceClass::ConfidentialFungible,
            ResourceClass::NonFungible,
        ] {
            assert_eq!(
                params().into_policy(&profile(class, 6)),
                Err(GateError::UnsupportedResource { class }),
                "{} must not be able to back a gate",
                class.as_str()
            );
        }
    }

    #[test]
    fn a_zero_threshold_is_refused() {
        let mut params = params();
        params.threshold = 0;
        assert_eq!(
            params.into_policy(&profile(ResourceClass::StealthFungible, 6)),
            Err(GateError::ThresholdNotPositive)
        );
    }

    #[test]
    fn the_policy_records_the_network_it_was_built_for() {
        let policy = GateParams { network: network::ESMERALDA, ..params() }
            .into_policy(&profile(ResourceClass::StealthFungible, 6))
            .expect("supported resource");
        assert_eq!(policy.network, network::ESMERALDA);

        // And a gate built for one cohort refuses another cohort's challenge.
        let mut challenge = challenge();
        challenge.network = network::LOCALNET;
        assert_eq!(
            check_challenge(&policy, &challenge, &ctx(), false),
            Err(GateError::NetworkMismatch)
        );
    }

    #[test]
    fn the_unsupported_class_refusal_names_the_class() {
        let text = GateError::UnsupportedResource {
            class: ResourceClass::NonFungible,
        }
        .to_string();
        assert!(text.contains("non-fungible"), "{text}");
        assert!(text.contains("stealth fungible"), "{text}");
    }

    #[test]
    fn the_cohort_bytes_match_the_ootle_network_enum() {
        // Transcribed from ootle_network::Network in the pinned cohort. If the cohort ever renumbers,
        // this is the line that tells us rather than the one that silently ships.
        assert_eq!(network::MAINNET, 0x00);
        assert_eq!(network::STAGENET, 0x01);
        assert_eq!(network::NEXTNET, 0x02);
        assert_eq!(network::LOCALNET, 0x10);
        assert_eq!(network::IGOR, 0x24);
        assert_eq!(network::ESMERALDA, 0x26);
        assert!(network::is_known(network::ESMERALDA));
        assert!(!network::is_known(0x03));
        // Distinct, so `wrong_network_is_refused` cannot accidentally pass on equal bytes.
        assert_ne!(network::ESMERALDA, network::LOCALNET);
    }
}
#[cfg(test)]
mod xtm_tests {
    use super::*;

    /// 1 XTM is 1,000,000 micro-Minotari, from `tari_amount.rs` (`1 * T == 1_000_000 * uT`).
    #[test]
    fn the_base_unit_conversion_is_canonical() {
        assert_eq!(xtm::MICRO_PER_XTM, 1_000_000);
        assert_eq!(xtm::xtm_to_micro(1), Some(1_000_000));
        assert_eq!(xtm::xtm_to_micro(u64::MAX), Some(u64::MAX as u128 * 1_000_000));
    }

    fn xtm_challenge(nonce: [u8; 32]) -> xtm::XtmChallenge {
        xtm::XtmChallenge {
            gate_id: MaxBytes::new_checked(b"otherside".to_vec()).unwrap(),
            threshold_micro: xtm::MICRO_PER_XTM * 1_000_000,
            network: network::LOCALNET,
            nonce: Hash32::from_array(nonce),
            issued_at_unix: 1_000,
            expires_at_unix: 1_180,
            relying_site: MaxBytes::new_checked(b"vip.example".to_vec()).unwrap(),
            session_commitment: MaxBytes::new_checked(b"session-1".to_vec()).unwrap(),
            tip_height_at_issue: 42,
        }
    }

    /// The binding: every field participates, so changing any one of them changes the commitment.
    /// This is what makes an XTM challenge for one gate/session unusable at another.
    #[test]
    fn every_xtm_challenge_field_participates_in_the_commitment() {
        let base = xtm_challenge([1u8; 32]);
        let base_commitment = base.commitment();

        let mut c = base.clone();
        c.gate_id = MaxBytes::new_checked(b"othergate".to_vec()).unwrap();
        assert_ne!(c.commitment(), base_commitment);

        let mut c = base.clone();
        c.threshold_micro += 1;
        assert_ne!(c.commitment(), base_commitment);

        let mut c = base.clone();
        c.network = network::ESMERALDA;
        assert_ne!(c.commitment(), base_commitment);

        let mut c = base.clone();
        c.nonce = Hash32::from_array([2u8; 32]);
        assert_ne!(c.commitment(), base_commitment);

        let mut c = base.clone();
        c.issued_at_unix += 1;
        assert_ne!(c.commitment(), base_commitment);

        let mut c = base.clone();
        c.expires_at_unix += 1;
        assert_ne!(c.commitment(), base_commitment);

        let mut c = base.clone();
        c.relying_site = MaxBytes::new_checked(b"evil.example".to_vec()).unwrap();
        assert_ne!(c.commitment(), base_commitment);

        let mut c = base.clone();
        c.session_commitment = MaxBytes::new_checked(b"session-2".to_vec()).unwrap();
        assert_ne!(c.commitment(), base_commitment);

        let mut c = base.clone();
        c.tip_height_at_issue += 1;
        assert_ne!(c.commitment(), base_commitment);
    }

    /// The two domains are distinct: an Ootle challenge's commitment is never an XTM one's, so a
    /// value bound in one cannot be presented as bound in the other.
    #[test]
    fn the_xtm_domain_is_distinct_from_the_ootle_domain() {
        assert_ne!(XTM_DOMAIN, GHOST_GATE_DOMAIN);
        let xtm_c = xtm_challenge([1u8; 32]);
        let ootle_c = Challenge {
            gate: ComponentAddress::new(tari_template_lib_types::ObjectKey::from_array([1u8; 32])),
            resource: ResourceAddress::new(tari_template_lib_types::ObjectKey::from_array([7u8; 32])),
            threshold: 10_000,
            network: network::LOCALNET,
            nonce: Hash32::from_array([1u8; 32]),
            expires_epoch: 100,
            relying_site: MaxBytes::new_checked(b"vip.example".to_vec()).unwrap(),
            session_commitment: MaxBytes::new_checked(b"session-1".to_vec()).unwrap(),
        };
        assert_ne!(xtm_c.commitment(), ootle_c.commitment());
    }

    #[test]
    fn expiry_is_exclusive_on_the_last_second() {
        let c = xtm_challenge([1u8; 32]);
        assert!(!c.is_expired(c.expires_at_unix), "the last second is still answerable");
        assert!(c.is_expired(c.expires_at_unix + 1));
    }

    /// The fee relation, at and around the million-XTM boundary. The four cases the fee-boundary
    /// section of the task demands, in base units, with checked arithmetic throughout.
    #[test]
    fn the_provable_floor_arithmetic_is_exact_at_the_boundary() {
        // Exactly at threshold: output promises threshold minus the fee, and the sum meets it.
        let threshold = xtm::MICRO_PER_XTM as u128 * 1_000_000; // 1,000,000 XTM
        let floor = xtm::provable_floor((threshold - 1) as u64, 1);
        assert!(xtm::floor_meets_threshold(floor, threshold as u64));

        // One micro short is refused.
        let floor = xtm::provable_floor((threshold - 2) as u64, 1);
        assert!(!xtm::floor_meets_threshold(floor, threshold as u64));

        // Comfortably above.
        let floor = xtm::provable_floor(u64::try_from(threshold).unwrap(), 0);
        assert!(xtm::floor_meets_threshold(floor, u64::try_from(threshold).unwrap()));

        // A fee at u64::MAX cannot overflow the u128 sum: the arithmetic is total.
        let floor = xtm::provable_floor(u64::MAX, u64::MAX);
        assert_eq!(floor, u64::MAX as u128 * 2);
    }

    #[test]
    fn the_xtm_receipt_carries_a_floor_not_a_balance() {
        // Structurally: the type has these three fields and nothing that could hold a balance,
        // an address or a key. The receipt is CBOR-decodable by the wallet's proof readback, and
        // its wire form is checked here so a new field is a visible change.
        let receipt = xtm::XtmProofReceipt {
            attested_floor_micro: 1_000_000_000_000,
            output_count: 1,
            challenge_nonce: Hash32::from_array([5u8; 32]),
            mined_height: 77,
        };
        let bytes = minicbor::to_vec(&receipt).unwrap();
        let back: xtm::XtmProofReceipt = minicbor::decode(&bytes).unwrap();
        assert_eq!(back, receipt);
        assert_eq!(back.attested_floor_micro, 1_000_000_000_000);
        assert_eq!(back.output_count, 1);
    }
}
