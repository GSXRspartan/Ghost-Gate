use std::path::PathBuf;

use serde::{Deserialize, Serialize};

const NATIVE_TARI_RESOURCE: &str =
    "resource_0101010101010101010101010101010101010101010101010101010101010101";
const ESMERALDA_POLICY_HASH: &str =
    "13af3169aefb313f355368c5b9131d512d86048ab700d850024c79ddb680b74f";
const MAX_EVIDENCE_AGE_EPOCHS: u64 = 2;

#[derive(Debug, Clone, Deserialize, Serialize)]
struct VerifiedEvidence {
    gate_id: String,
    network: u8,
    policy_hash: String,
    output_id: String,
    resource_address: String,
    commitment_hex: String,
    minimum_value_promise: u64,
    frozen: bool,
    state: String,
    anchor_epoch: u64,
    anchor_height: u64,
    current_epoch: u64,
    evidence_age_epochs: u64,
    challenge_hex: String,
    relying_origin: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct GatePolicy {
    gate_id: String,
    network: u8,
    policy_hash: String,
    resource_address: String,
    threshold_raw: u64,
    relying_site: String,
    telegram_scope: bool,
    challenge_hex: String,
}

#[derive(Debug, Clone, Serialize)]
struct AdapterVerdict {
    outcome: &'static str,
    authorized: bool,
    session: Option<String>,
    reason: Option<String>,
    provenance: &'static str,
}

fn evaluate(evidence: &VerifiedEvidence, policy: &GatePolicy) -> AdapterVerdict {
    let refuse = |reason: &str| AdapterVerdict {
        outcome: "refused",
        authorized: false,
        session: None,
        reason: Some(reason.to_string()),
        provenance: "authenticated_consensus_evidence",
    };
    if evidence.network != 0 {
        return refuse("evidence is not on mainnet");
    }
    if policy.network != 0 {
        return refuse("policy is not a mainnet policy");
    }
    if policy.policy_hash == ESMERALDA_POLICY_HASH {
        return refuse("Esmeralda policy hash cannot bind a mainnet gate");
    }
    if evidence.gate_id != policy.gate_id {
        return refuse("gate id mismatch");
    }
    if evidence.policy_hash != policy.policy_hash {
        return refuse("policy hash mismatch");
    }
    if evidence.resource_address != policy.resource_address || policy.resource_address != NATIVE_TARI_RESOURCE {
        return refuse("resource mismatch");
    }
    if evidence.state != "Up" {
        return refuse("output is not authenticated Up");
    }
    if evidence.frozen {
        return refuse("output is frozen");
    }
    if evidence.minimum_value_promise < policy.threshold_raw {
        return refuse("minimum value promise below policy threshold");
    }
    if evidence.current_epoch.saturating_sub(evidence.anchor_epoch) > MAX_EVIDENCE_AGE_EPOCHS
        || evidence.evidence_age_epochs > MAX_EVIDENCE_AGE_EPOCHS
    {
        return refuse("authenticated evidence is stale");
    }
    if evidence.challenge_hex != policy.challenge_hex {
        return refuse("challenge mismatch");
    }
    if evidence.relying_origin != policy.relying_site {
        return refuse("relying origin mismatch");
    }
    if !policy.telegram_scope {
        return refuse("gate is not scoped to Telegram admission");
    }
    AdapterVerdict {
        outcome: "cryptographically_eligible_test_only",
        authorized: false,
        session: None,
        reason: None,
        provenance: "authenticated_consensus_evidence",
    }
}

#[cfg(test)]
fn sample_evidence(promise: u64) -> VerifiedEvidence {
    VerifiedEvidence {
        gate_id: "Crypt".into(),
        network: 0,
        policy_hash: "b1".repeat(32),
        output_id: "utxo_0101…a664f".into(),
        resource_address: NATIVE_TARI_RESOURCE.into(),
        commitment_hex: "a8cbdc65…e52a664f".into(),
        minimum_value_promise: promise,
        frozen: false,
        state: "Up".into(),
        anchor_epoch: 39274,
        anchor_height: 21,
        current_epoch: 39274,
        evidence_age_epochs: 0,
        challenge_hex: "07".repeat(32),
        relying_origin: "https://ghostgate.boo".into(),
    }
}

#[cfg(test)]
fn sample_policy(threshold: u64) -> GatePolicy {
    GatePolicy {
        gate_id: "Crypt".into(),
        network: 0,
        policy_hash: "b1".repeat(32),
        resource_address: NATIVE_TARI_RESOURCE.into(),
        threshold_raw: threshold,
        relying_site: "https://ghostgate.boo".into(),
        telegram_scope: true,
        challenge_hex: "07".repeat(32),
    }
}

#[test]
fn adapter_never_authorizes_and_enforces_policy_binding() {
    let poor = evaluate(&sample_evidence(11_000_000), &sample_policy(100_000_000));
    assert_eq!(poor.outcome, "refused");
    assert!(!poor.authorized);
    assert!(poor.session.is_none());

    let good = evaluate(&sample_evidence(100_000_000), &sample_policy(100_000_000));
    assert_eq!(good.outcome, "cryptographically_eligible_test_only");
    assert!(!good.authorized, "adapter must never authorize");
    assert!(good.session.is_none(), "adapter must never mint a session");

    let mut esm = sample_policy(100_000_000);
    esm.policy_hash = ESMERALDA_POLICY_HASH.into();
    assert_eq!(evaluate(&sample_evidence(100_000_000), &esm).outcome, "refused");

    let mut wrong_net = sample_evidence(100_000_000);
    wrong_net.network = 0x26;
    assert_eq!(evaluate(&wrong_net, &sample_policy(100_000_000)).outcome, "refused");

    let mut frozen = sample_evidence(100_000_000);
    frozen.frozen = true;
    assert_eq!(evaluate(&frozen, &sample_policy(100_000_000)).outcome, "refused");

    let mut stale = sample_evidence(100_000_000);
    stale.anchor_epoch = 39270;
    stale.evidence_age_epochs = 4;
    assert_eq!(evaluate(&stale, &sample_policy(100_000_000)).outcome, "refused");

    let mut wrong_challenge = sample_evidence(100_000_000);
    wrong_challenge.challenge_hex = "08".repeat(32);
    assert_eq!(evaluate(&wrong_challenge, &sample_policy(100_000_000)).outcome, "refused");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<PathBuf> = std::env::args().skip(1).map(PathBuf::from).collect();
    if args.len() != 2 {
        return Err("usage: adapter <evidence.json> <policy.json>".into());
    }
    let evidence: VerifiedEvidence = serde_json::from_slice(&std::fs::read(&args[0])?)?;
    let policy: GatePolicy = serde_json::from_slice(&std::fs::read(&args[1])?)?;
    let verdict = evaluate(&evidence, &policy);
    println!("{}", serde_json::to_string_pretty(&verdict)?);
    Ok(())
}
