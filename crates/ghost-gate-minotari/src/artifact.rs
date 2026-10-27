//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! The proof artifact's wire form, shared between the wallet service and the bridge.
//!
//! Everything in [`XtmProofWire`] is public on chain or is a signature the wallet made over the
//! challenge: a kernel excess signature, an output hash and a spend-key signature. Nothing here
//! can disclose a balance, a value or a key: the output *value* is not in the artifact at all,
//! because the verifier reads the floor from the mined output's `minimum_value_promise`.

use crate::service::XtmProofOutcome;
use ghost_gate_bridge::XtmProofArtifact;
use serde::{Deserialize, Serialize};

/// The artifact, in wire form. Every field is hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XtmProofWire {
    /// The wallet's own transaction id.
    pub transaction_id: u64,
    /// The kernel's excess signature, 64 bytes hex (public nonce || scalar).
    pub kernel_excess_sig_hex: String,
    /// The qualifying output's hash, 32 bytes hex.
    pub output_hash_hex: String,
    /// The spend-key signature over the challenge nonce, 64 bytes hex (public nonce || scalar).
    pub spend_signature_hex: String,
}

impl XtmProofWire {
    pub fn from_artifact(artifact: &XtmProofArtifact) -> Self {
        Self {
            transaction_id: artifact.transaction_id,
            kernel_excess_sig_hex: hex::encode(artifact.kernel_excess_sig),
            output_hash_hex: hex::encode(artifact.output_hash),
            spend_signature_hex: hex::encode(artifact.spend_signature),
        }
    }

    /// Decodes back into the bridge's artifact type. Hex and length errors are refusals, not panics.
    pub fn to_artifact(&self) -> Result<XtmProofArtifact, String> {
        let kernel = hex::decode(&self.kernel_excess_sig_hex).map_err(|e| e.to_string())?;
        let output = hex::decode(&self.output_hash_hex).map_err(|e| e.to_string())?;
        let spend = hex::decode(&self.spend_signature_hex).map_err(|e| e.to_string())?;
        if kernel.len() != 64 || output.len() != 32 || spend.len() != 64 {
            return Err("GG: malformed proof artifact lengths".to_string());
        }
        let mut kernel_excess_sig = [0u8; 64];
        kernel_excess_sig.copy_from_slice(&kernel);
        let mut output_hash = [0u8; 32];
        output_hash.copy_from_slice(&output);
        let mut spend_signature = [0u8; 64];
        spend_signature.copy_from_slice(&spend);
        Ok(XtmProofArtifact {
            transaction_id: self.transaction_id,
            kernel_excess_sig,
            output_hash,
            spend_signature,
        })
    }
}

/// The final outcome of a proof, as the wallet service's binary reports it for an operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum XtmProofOutcomeWire {
    Broadcast { artifact: XtmProofWire },
    CannotAfford,
    Failed { reason: String },
}

impl From<XtmProofOutcome> for XtmProofOutcomeWire {
    fn from(o: XtmProofOutcome) -> Self {
        match o {
            XtmProofOutcome::Broadcast(a) => Self::Broadcast {
                artifact: XtmProofWire::from_artifact(&a),
            },
            XtmProofOutcome::CannotAfford => Self::CannotAfford,
            XtmProofOutcome::Failed(reason) => Self::Failed { reason },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_artifact_round_trips_through_its_wire_form() {
        let artifact = XtmProofArtifact {
            transaction_id: 42,
            kernel_excess_sig: [1u8; 64],
            output_hash: [2u8; 32],
            spend_signature: [3u8; 64],
        };
        let wire = XtmProofWire::from_artifact(&artifact);
        let back = wire.to_artifact().unwrap();
        assert_eq!(back, artifact);
    }

    #[test]
    fn malformed_lengths_are_refused_not_panicked() {
        let wire = XtmProofWire {
            transaction_id: 1,
            kernel_excess_sig_hex: hex::encode([1u8; 63]),
            output_hash_hex: hex::encode([2u8; 32]),
            spend_signature_hex: hex::encode([3u8; 64]),
        };
        assert!(wire.to_artifact().is_err());
        let wire = XtmProofWire {
            transaction_id: 1,
            kernel_excess_sig_hex: "zz".to_string(),
            output_hash_hex: hex::encode([2u8; 32]),
            spend_signature_hex: hex::encode([3u8; 64]),
        };
        assert!(wire.to_artifact().is_err());
    }

    #[test]
    fn the_wire_form_carries_no_value_and_no_key() {
        let artifact = XtmProofArtifact {
            transaction_id: 1,
            kernel_excess_sig: [1u8; 64],
            output_hash: [2u8; 32],
            spend_signature: [3u8; 64],
        };
        let json = serde_json::to_string(&XtmProofWire::from_artifact(&artifact)).unwrap();
        assert!(
            !json.contains("value") && !json.contains("amount") && !json.contains("mask"),
            "{json}"
        );
    }
}
