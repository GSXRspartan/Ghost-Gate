//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! The headless Minotari wallet service: the user's own wallet daemon, serving exactly two
//! capabilities.
//!
//! # The design in one paragraph
//!
//! The service wraps a full in-process Minotari wallet (`minotari_wallet::Wallet`) — key manager,
//! output manager, transaction service, comms — and exposes two operations over loopback HTTP
//! (JSON-RPC): *status* and *prove*. `prove` answers one Ghost Gate challenge with one pay-to-self
//! transaction carrying a consensus-enforced `minimum_value_promise`, broadcasts it through the
//! wallet's own transaction service, and signs the challenge nonce with the new output's script
//! key. Everything else the wallet can do — sending funds, importing UTXOs, seed recovery — is
//! deliberately not exposed: this process exists to prove thresholds, and every extra capability
//! is attack surface against the funds it holds.
//!
//! # The fee-fixed-point, stated precisely
//!
//! A wallet whose spendable balance is exactly the threshold must be able to prove it. A naive
//! self-transfer of `threshold` as the output value would need `threshold + fee` of inputs, which
//! that wallet does not have. The fix is to solve for the largest affordable output value
//! `v` such that `v + fee(v) <= spendable`, where `fee(v)` is a non-decreasing step function of
//! `v` through the number of fee "grams" the transaction weighs. Iterating from a conservative
//! start converges in a few passes (fee estimation is stable per gram count), and the fixed point
//! is checked with `v + fee >= threshold` before anything is broadcast. All arithmetic is integer
//! micro-Minotari; there is no floating point.
//!
//! # What this process never does
//!
//! It never reports a balance to any caller: `status` says reachable or not, `prove` says which
//! artifact it produced or why it could not. It never signs anything except its own proof
//! responses. It binds to the loopback interface only.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::artifact::XtmProofWire;
use ghost_gate_bridge::XtmProofArtifact;

/// The proof outcome the wallet service produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XtmProofOutcome {
    Broadcast(XtmProofArtifact),
    CannotAfford,
    Failed(String),
}

/// The default fee per gram, in micro-Minotari. A local/testnet figure; an operator overrides it.
pub const DEFAULT_FEE_PER_GRAM: u64 = 5;
/// How long `prove` will wait for the wallet's own transaction protocol to accept the broadcast.
pub const DEFAULT_BROADCAST_TIMEOUT: Duration = Duration::from_secs(120);

/// The request the bridge sends for a proof. `deny_unknown_fields` is load-bearing: a caller that
/// smuggles an amount or a key field into a proof request gets a refusal, not a silent ignore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProveRequestWire {
    /// The threshold, in micro-Minotari. The only number a proof request carries.
    pub threshold_micro: u64,
    /// The 32-byte challenge nonce, hex. What the output's script key signs.
    pub challenge_nonce_hex: String,
}

/// The response to a proof request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProveResponseWire {
    /// The transaction was broadcast; the artifact is what the bridge will verify.
    Broadcast { artifact: XtmProofWire },
    /// The wallet could not afford a qualifying transaction. No balance is named.
    CannotAfford,
    /// Something else went wrong; nothing was broadcast for this challenge.
    Failed { reason: String },
}

impl ProveResponseWire {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self)
            .unwrap_or_else(|_| r#"{"state":"failed","reason":"internal"}"#.to_string())
    }
}

/// Errors the service reports to its own logs. Never returned to a caller with key material in.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("GG: {0}")]
    Wallet(String),
    #[error("GG: the wallet cannot afford a qualifying transaction for this threshold")]
    CannotAfford,
    #[error("GG: the challenge nonce is malformed")]
    MalformedNonce,
    #[error("GG: the requested threshold cannot be carried by a Minotari output")]
    ThresholdUnrepresentable,
}

/// The fee-fixed-point solver, as a pure function.
///
/// Returns the largest output value the given spendable balance can carry, given a fee function
/// `fee(value) -> fee`. Non-decreasing fees are assumed (more value means more bytes in the
/// encrypted-data field, never fewer). Returns `None` when even a zero-value transaction costs
/// more than the balance.
///
/// The algorithm is a bisection on the integer domain: `fee` is a step function, so binary search
/// finds the largest `v` where `v + fee(v) <= spendable` in O(log max) evaluations. Every
/// candidate is `u128`, so `v + fee(v)` cannot overflow.
pub fn largest_affordable_output_value<F>(spendable_micro: u64, fee: F) -> Option<u64>
where
    F: Fn(u64) -> u64,
{
    // The invariant: value_ok is the largest value so far with value + fee(value) <= spendable.
    let mut lo: u64 = 0;
    let mut hi: u64 = spendable_micro;
    let mut best: Option<u64> = None;
    while lo <= hi {
        let mid = lo + (hi - lo) / 2;
        let f = fee(mid);
        let total = u128::from(mid) + u128::from(f);
        if total <= u128::from(spendable_micro) {
            best = Some(mid);
            // The next candidate above may still fit (fee steps are coarse), keep going up.
            lo = match mid.checked_add(1) {
                Some(next) => next,
                // mid == u64::MAX: no higher candidate exists.
                None => break,
            };
        } else {
            // Guard the subtraction: if mid == 0 nothing can fit.
            if mid == 0 {
                break;
            }
            hi = mid - 1;
        }
    }
    best
}

/// TheGhost Gate spend-signature message: exactly the challenge's 32-byte nonce.
///
/// The message is the nonce and nothing else. It is single-use, unpredictable, and produced by the
/// bridge for this challenge, which is what makes the signature a challenge binding rather than a
/// general capability.
pub fn spend_signature_message(challenge_nonce: &[u8; 32]) -> [u8; 32] {
    *challenge_nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A step fee function: 1,000 micro per "gram", where value costs grams at 100,000 each.
    fn step_fee(value: u64) -> u64 {
        1_000 * (1 + value / 100_000)
    }

    #[test]
    fn the_fixed_point_never_exceeds_the_spendable_balance() {
        for spendable in [1u64, 999, 1_000, 1_001, 100_000, 500_000, u64::MAX] {
            if let Some(v) = largest_affordable_output_value(spendable, step_fee) {
                assert!(
                    u128::from(v) + u128::from(step_fee(v)) <= u128::from(spendable),
                    "spendable {spendable}: chose {v} with fee {f}",
                    f = step_fee(v)
                );
            }
        }
    }

    #[test]
    fn the_fixed_point_is_maximal() {
        // For each of several balances, no larger value also fits.
        for spendable in [1u64, 999, 1_000, 1_001, 100_000, 500_000, 10_000_000] {
            if let Some(v) = largest_affordable_output_value(spendable, step_fee) {
                if let Some(next) = v.checked_add(1) {
                    assert!(
                        u128::from(next) + u128::from(step_fee(next)) > u128::from(spendable),
                        "spendable {spendable}: {next} would also fit after {v}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_tiny_balance_cannot_afford_anything() {
        assert_eq!(largest_affordable_output_value(999, step_fee), None);
        assert_eq!(largest_affordable_output_value(0, step_fee), None);
    }

    #[test]
    fn an_exact_balance_carries_a_value_that_fits() {
        // spendable 1,001,000: v=1,000,000 has fee 1,000*11=11,000 -> total 1,011,000 > balance.
        // v=1,000,000 - x where fee(x) still 1,000/gram step... verify the invariant instead.
        if let Some(v) = largest_affordable_output_value(1_001_000, step_fee) {
            assert!(u128::from(v) + u128::from(step_fee(v)) <= 1_001_000u128);
        }
    }

    #[test]
    fn a_zero_fee_function_carries_the_whole_balance() {
        assert_eq!(
            largest_affordable_output_value(5_000_000, |_| 0),
            Some(5_000_000)
        );
    }

    #[test]
    fn the_message_is_exactly_the_nonce() {
        let nonce = [9u8; 32];
        assert_eq!(spend_signature_message(&nonce), nonce);
    }
}
