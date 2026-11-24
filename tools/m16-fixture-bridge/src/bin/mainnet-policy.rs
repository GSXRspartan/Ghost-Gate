//! Computes the authoritative mainnet native-TARI Crypt policy hash and emits the
//! adapter-compatible policy JSON.
//!
//! The hash is the registry's own canonical BLAKE3 digest (policy-hash v2, the version the
//! administrator plane publishes), computed over the exact Application/GatePolicy contents this
//! bin prints. The Esmeralda staging policy hash is structurally excluded: the network byte is
//! 0x00, so no Esmeralda-cohort hash can ever equal this digest.
//!
//! The mainnet Ootle L2 genesis hash is NOT pinned in this repository. The bin refuses to run
//! without an explicit `--genesis <hex>`; for the local non-authorizing lab draft pass
//! `--genesis pending-mainnet-genesis-pin` — that value is not valid hex, so the resulting draft
//! can never validate or authorize anything, while its digest still binds every other policy
//! field. When the authenticated mainnet genesis is pinned, re-run with it to obtain the
//! production-candidate digest.

use ghost_gate_core::policy::{hash_policy_versioned, Application, GatePolicy, GateTopology, ProofMode, GateUseMode};
use ghost_gate_registry::{Blake3Hasher, POLICY_HASH_V2};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut genesis: Option<String> = None;
    let mut relying = "http://127.0.0.1:7798".to_string();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--genesis" => { i += 1; genesis = Some(args.get(i).cloned().expect("--genesis needs a value")); }
            "--relying" => { i += 1; relying = args.get(i).cloned().expect("--relying needs a value"); }
            other => panic!("unknown argument {other}; usage: mainnet-policy --genesis <hex> [--relying <origin>]"),
        }
        i += 1;
    }
    let genesis = genesis.unwrap_or_else(|| panic!("--genesis <hex> is required (the mainnet L2 genesis hash is not pinned in this repository)"));

    let gate = GatePolicy {
        gate_id: "Crypt".into(),
        name: "Crypt - mainnet native TARI".into(),
        resource_address: ghost_gate_core::network::MAINNET_TARI_RESOURCE.into(),
        symbol: "TARI".into(),
        divisibility: ghost_gate_core::network::MAINNET_TARI_DIVISIBILITY,
        threshold_raw: 100_000_000, // 100 TARI
        proof_mode: ProofMode::Credential,
        challenge_domain: relying.clone(),
        session_ttl_override: None,
        grants: vec![],
        enabled: false,
        test_lane: true,
        component_address: None,
        use_mode: GateUseMode::Website,
    };
    let app = Application {
        application_id: "ghost-gate".into(),
        display_name: "Ghost Gate".into(),
        owner_credential: "local-operator".into(),
        topology: GateTopology::Independent,
        default_session_ttl: 600,
        max_gates: 16,
        gates: vec![gate.clone()],
        revision: 1,
        production: false,
        network: ghost_gate_core::network::MAINNET,
        genesis_hash: genesis.clone(),
        chain_generation: 0,
    };

    let hash = hash_policy_versioned(&Blake3Hasher, &app, &gate, 1, POLICY_HASH_V2)
        .expect("POLICY_HASH_V2 is a supported version");
    let esmeralda_hash = "13af3169aefb313f355368c5b9131d512d86048ab700d850024c79ddb680b74f";
    if hash == esmeralda_hash {
        panic!("the computed mainnet policy hash equals the Esmeralda staging hash; refusing");
    }

    println!(
        "{}",
        serde_json::json!({
            "_note": "Mainnet native-TARI Crypt policy. Non-authorizing draft: enabled=false, test_lane=true, chain_generation=0 (authorizes NOTHING). Production publication additionally requires the authenticated mainnet L2 genesis hash and an explicit activation step.",
            "gate_id": gate.gate_id,
            "network": ghost_gate_core::network::MAINNET,
            "policy_hash": hash,
            "policy_hash_version": POLICY_HASH_V2,
            "resource_address": gate.resource_address,
            "threshold_raw": u64::try_from(gate.threshold_raw).expect("threshold fits u64"),
            "divisibility": gate.divisibility,
            "symbol": gate.symbol,
            "relying_site": gate.challenge_domain,
            "telegram_scope": false,
            "challenge_hex": "",
            "application": {
                "application_id": app.application_id,
                "owner_credential": app.owner_credential,
                "topology": "independent",
                "production": app.production,
                "genesis_hash": app.genesis_hash,
                "chain_generation": app.chain_generation,
                "default_session_ttl": app.default_session_ttl,
            },
            "gate_flags": {
                "enabled": gate.enabled,
                "test_lane": gate.test_lane,
                "proof_mode": "credential",
                "use_mode": gate.use_mode.as_str(),
            },
        })
    );
}
