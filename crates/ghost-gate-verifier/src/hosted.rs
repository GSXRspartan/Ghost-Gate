//! Authenticated hosted-verifier wire contract.
//!
//! The Cloudflare Worker owns replay and browser sessions. This module is deliberately narrower:
//! it validates the server-created binding and signs an outcome. Until a real chain reader and
//! finality verifier are attached, [`verify_fail_closed`] only returns `UNKNOWN`; it never turns a
//! fixture, an ownership signature, or client balance metadata into `VERIFIED`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostedVerificationRequest {
    pub nonce: String,
    pub tenant: String,
    pub gate_id: String,
    pub relying_site: String,
    pub network: u8,
    pub resource_address: String,
    pub threshold_raw: String,
    pub policy_version: String,
    pub proof_digest: String,
    /// Opaque browser evidence. It is intentionally not interpreted by this fail-closed adapter.
    pub proof: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HostedVerdict { Verified, Rejected, Pending, Unknown }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostedVerificationResult {
    pub nonce: String,
    pub tenant: String,
    pub gate_id: String,
    pub relying_site: String,
    pub network: u8,
    pub resource_address: String,
    pub threshold_raw: String,
    pub policy_version: String,
    pub proof_digest: String,
    pub verdict: HostedVerdict,
    pub verification_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostedContractError {
    #[error("GG: hosted verification request has an invalid binding")]
    InvalidBinding,
}

impl HostedVerificationRequest {
    /// Reject malformed or oversized client evidence before any chain adapter is considered.
    pub fn validate(&self) -> Result<(), HostedContractError> {
        let hex64 = |value: &str| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
        if !hex64(&self.nonce) || !hex64(&self.proof_digest)
            || self.tenant.is_empty() || self.gate_id.is_empty() || self.relying_site.is_empty()
            || self.resource_address.is_empty() || self.threshold_raw.is_empty() || self.policy_version.is_empty()
            || self.tenant.len() > 256 || self.gate_id.len() > 256 || self.relying_site.len() > 512
            || self.resource_address.len() > 512 || self.threshold_raw.len() > 64 || self.policy_version.len() > 256
        { return Err(HostedContractError::InvalidBinding); }
        Ok(())
    }
}

/// Current production-safe verifier behavior: do not claim eligibility without a deployed,
/// independently configured chain/finality adapter. The randomly generated verification identity
/// makes an old signed outcome non-substitutable for a newly submitted proof job.
pub fn verify_fail_closed(request: &HostedVerificationRequest, verification_id: String)
    -> Result<HostedVerificationResult, HostedContractError>
{
    request.validate()?;
    Ok(HostedVerificationResult {
        nonce: request.nonce.clone(), tenant: request.tenant.clone(), gate_id: request.gate_id.clone(),
        relying_site: request.relying_site.clone(), network: request.network,
        resource_address: request.resource_address.clone(), threshold_raw: request.threshold_raw.clone(),
        policy_version: request.policy_version.clone(), proof_digest: request.proof_digest.clone(),
        verdict: HostedVerdict::Unknown, verification_id,
    })
}

/// Canonical JSON exactly matching the Worker: object keys are lexicographically sorted and every
/// string is encoded through `serde_json`, so HMACs cover all scope fields and the verdict.
pub fn canonical_result(result: &HostedVerificationResult) -> String {
    let mut fields = BTreeMap::<&str, serde_json::Value>::new();
    fields.insert("gateId", result.gate_id.clone().into());
    fields.insert("network", result.network.into());
    fields.insert("nonce", result.nonce.clone().into());
    fields.insert("policyVersion", result.policy_version.clone().into());
    fields.insert("proofDigest", result.proof_digest.clone().into());
    fields.insert("relyingSite", result.relying_site.clone().into());
    fields.insert("resourceAddress", result.resource_address.clone().into());
    fields.insert("tenant", result.tenant.clone().into());
    fields.insert("thresholdRaw", result.threshold_raw.clone().into());
    fields.insert("verificationId", result.verification_id.clone().into());
    fields.insert("verdict", serde_json::to_value(&result.verdict).expect("enum serialises"));
    serde_json::to_string(&fields).expect("canonical fields serialise")
}

/// HMAC-SHA-256 without a new cryptographic dependency. The key and message are server-only;
/// callers expose only the final hex signature in `X-GG-Verifier-Signature`.
pub fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    const BLOCK: usize = 64;
    let mut normalized = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        normalized[..digest.len()].copy_from_slice(&digest);
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(normalized.map(|byte| byte ^ 0x36));
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(normalized.map(|byte| byte ^ 0x5c));
    outer.update(inner);
    hex::encode(outer.finalize())
}

pub fn sign_result(result: &HostedVerificationResult, key: &[u8]) -> String {
    hmac_sha256_hex(key, canonical_result(result).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> HostedVerificationRequest {
        HostedVerificationRequest {
            nonce: "a".repeat(64), tenant: "tenant-a".into(), gate_id: "esm10".into(),
            relying_site: "https://gate.example".into(), network: 38, resource_address: "resource_test".into(),
            threshold_raw: "10000000".into(), policy_version: "v1".into(), proof_digest: "b".repeat(64), proof: serde_json::json!({"untrusted":true}),
        }
    }

    #[test]
    fn hosted_adapter_cannot_claim_a_fixture_is_verified() {
        let result = verify_fail_closed(&request(), "c".repeat(32)).unwrap();
        assert_eq!(result.verdict, HostedVerdict::Unknown);
        assert_eq!(result.network, 38);
    }

    #[test]
    fn signature_covers_scope_and_verdict() {
        let mut result = verify_fail_closed(&request(), "c".repeat(32)).unwrap();
        let signature = sign_result(&result, b"test-key");
        result.tenant = "other-tenant".into();
        assert_ne!(signature, sign_result(&result, b"test-key"));
        result.tenant = "tenant-a".into(); result.verdict = HostedVerdict::Verified;
        assert_ne!(signature, sign_result(&result, b"test-key"));
    }

    #[test]
    fn canonical_json_matches_the_worker_key_order() {
        let result = verify_fail_closed(&request(), "c".repeat(32)).unwrap();
        assert_eq!(canonical_result(&result), format!(
            "{{\"gateId\":\"esm10\",\"network\":38,\"nonce\":\"{}\",\"policyVersion\":\"v1\",\"proofDigest\":\"{}\",\"relyingSite\":\"https://gate.example\",\"resourceAddress\":\"resource_test\",\"tenant\":\"tenant-a\",\"thresholdRaw\":\"10000000\",\"verdict\":\"UNKNOWN\",\"verificationId\":\"{}\"}}",
            "a".repeat(64), "b".repeat(64), "c".repeat(32)
        ));
    }

    #[test]
    fn malformed_nonce_is_refused_before_signing() {
        let mut request = request(); request.nonce = "not-a-nonce".into();
        assert_eq!(verify_fail_closed(&request, "c".repeat(32)), Err(HostedContractError::InvalidBinding));
    }
}
