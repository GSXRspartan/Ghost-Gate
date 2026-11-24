use std::time::Duration;

use anyhow::anyhow;
use ghost_gate_bridge::{
    authorization_coordinator::AuthorizationCoordinator,
    bot_session_interface::BotGatePolicy,
    credential::{ChainReader, UtxoOnChain},
    server::{Bridge, serve},
    wallet::{CommitOutcome, StatementReply, StatementRequest, WalletChannel, WalletError, WalletStatus},
    GateBinding, GateRegistry, OriginPolicy,
};
use ghost_gate_core::Challenge;
use serde_json::Value;
use tari_template_lib_types::{MaxBytes, UtxoAddress, stealth::StealthTransferStatement};

const RESOURCE: &str = "resource_0101010101010101010101010101010101010101010101010101010101010101";

struct NoWallet;

#[allow(async_fn_in_trait)]
impl WalletChannel for NoWallet {
    async fn status(&mut self) -> Result<WalletStatus, WalletError> {
        Ok(WalletStatus::unreachable())
    }
    async fn build_statement(&mut self, _request: StatementRequest) -> Result<StatementReply, WalletError> {
        Err(WalletError::CannotConstructProof)
    }
    async fn submit(
        &mut self,
        _gate: &str,
        _challenge: &Challenge,
        _statement: &StealthTransferStatement,
        _lock_id: &str,
    ) -> Result<String, WalletError> {
        Err(WalletError::CannotConstructProof)
    }
    async fn wait(
        &mut self,
        _transaction_id: &str,
        _timeout: Duration,
    ) -> Result<CommitOutcome, WalletError> {
        Ok(CommitOutcome::Pending)
    }
}

struct JsonChainReader {
    endpoint: String,
    client: reqwest::Client,
}

impl JsonChainReader {
    fn connect(endpoint: &str) -> anyhow::Result<Self> {
        let endpoint = endpoint.trim_end_matches('/').to_string();
        let client = reqwest::Client::builder()
            .user_agent("ghost-gate-m16-verifier/0.1")
            .build()?;
        Ok(Self { endpoint, client })
    }
}

impl ChainReader for JsonChainReader {
    async fn utxo(&self, address: &UtxoAddress) -> Result<UtxoOnChain, String> {
        let url = format!("{}/substates/{}", self.endpoint, address);
        let resp = self.client.get(&url).send().await.map_err(|e| format!("indexer unreachable: {e}"))?;
        let status = resp.status();
        let body: Value = resp.json().await.map_err(|e| format!("unreadable body: {e}"))?;

        if let Some(cbor_blob) = body.pointer("/state/up/substate").and_then(|v| v.as_str()) {
            let verified = body.get("verified").and_then(|v| v.as_bool()).unwrap_or(false);
            return read_utxo_cbor(cbor_blob, address, verified);
        }
        let v047_up = body.pointer("/state/up/substate/Utxo").filter(|v| v.is_object());
        let v042 = body.get("substate").and_then(|s| s.get("Utxo")).filter(|v| v.is_object());
        let is_v047 = v047_up.is_some() || body.get("substate").is_none();
        if v047_up.is_none() && is_v047 {
            if body.pointer("/state/down").is_some() {
                return Err(format!("{address} is DOWN on the indexer"));
            }
            if status.as_u16() == 404 {
                return Err(format!("{address} is unknown to this indexer"));
            }
            return Err(format!("{address}: unexpected indexer response HTTP {status}"));
        }
        let utxo = v047_up.or(v042).ok_or_else(|| format!("{address}: not a UTXO"))?;
        let verified = body.get("verified").and_then(|v| v.as_bool()).unwrap_or(false);
        let output = utxo.get("output").ok_or_else(|| format!("{address}: no output body"))?;
        let promise = output
            .get("output")
            .and_then(|o| o.get("minimum_value_promise"))
            .or_else(|| output.get("minimum_value_promise"))
            .and_then(|v| v.as_u64())
            .ok_or_else(|| format!("{address}: no minimum_value_promise"))?;
        let auth_key = output
            .get("auth")
            .and_then(|a| a.get("Key"))
            .and_then(|k| k.as_str())
            .and_then(|s| {
                let mut out = [0u8; 32];
                hex::decode_to_slice(s.trim_start_matches("0x"), &mut out).ok()?;
                Some(out)
            });
        let is_frozen = utxo.get("is_frozen").and_then(|v| v.as_bool()).unwrap_or(false);
        Ok(UtxoOnChain { minimum_value_promise: promise, verified, auth_key, is_frozen })
    }
}

fn read_utxo_cbor(blob: &str, address: &UtxoAddress, verified: bool) -> Result<UtxoOnChain, String> {
    use ghost_gate_cbor::{CborValue, decode_committed_base64, Limits};
    let bad = |what: String| format!("{address}: not a Utxo substate: {what}");
    let committed = decode_committed_base64(blob, Limits::default())
        .map_err(|e| format!("{address}: CBOR decode failed: {e}"))?;
    let top = committed.value().as_array().map_err(|e| bad(format!("top level: {e}")))?;
    if top.len() != 2 || top[0].as_u64().map_err(|e| bad(e.to_string()))? != 8 {
        return Err(bad("expected Utxo variant 8".into()));
    }
    let wrapper = top[1].as_array().map_err(|e| bad(format!("payload: {e}")))?;
    let utxo = wrapper.first().and_then(|v| v.as_array().ok()).ok_or_else(|| bad("Utxo struct".into()))?;
    if utxo.len() != 2 {
        return Err(bad("burnt or unknown Utxo shape".into()));
    }
    let is_frozen = utxo[1].as_bool().map_err(|e| bad(format!("is_frozen: {e}")))?;
    let out = utxo[0].as_array().map_err(|e| bad(format!("UtxoOutput: {e}")))?;
    if out.len() != 3 {
        return Err(bad("UtxoOutput field count".into()));
    }
    let body = out[0].as_array().map_err(|e| bad(format!("OutputBody: {e}")))?;
    if !(3..=4).contains(&body.len()) {
        return Err(bad("OutputBody field count".into()));
    }
    let nonce = body[0].as_bytes().map_err(|e| bad(format!("nonce: {e}")))?;
    if nonce.len() != 32 {
        return Err(bad("nonce length".into()));
    }
    let encrypted = body[1].as_bytes().map_err(|e| bad(format!("encrypted_data: {e}")))?;
    if !(80..=335).contains(&encrypted.len()) {
        return Err(bad("encrypted_data length".into()));
    }
    let minimum_value_promise = body[2].as_u64().map_err(|e| bad(format!("promise: {e}")))?;
    let auth = out[1].as_array().map_err(|e| bad(format!("auth: {e}")))?;
    if auth.len() != 2 {
        return Err(bad("auth field count".into()));
    }
    let variant = auth[0].as_u64().map_err(|e| bad(format!("auth variant: {e}")))?;
    let fields = auth[1].as_array().map_err(|e| bad(format!("auth fields: {e}")))?;
    let key32 = |v: &CborValue| -> Result<[u8; 32], String> {
        let b = v.as_bytes().map_err(|e| bad(format!("key: {e}")))?;
        let mut k = [0u8; 32];
        if b.len() != 32 { return Err(bad("key length".into())); }
        k.copy_from_slice(b);
        Ok(k)
    };
    let auth_key = match (variant, fields.len()) {
        (0, 1) => Some(key32(&fields[0])?),
        (1, 1) => { key32(&fields[0])?; None }
        (2, 2) => { key32(&fields[0])?; key32(&fields[1])?; Some(key32(&fields[0])?) }
        _ => return Err(bad("unsupported auth shape".into())),
    };
    Ok(UtxoOnChain { minimum_value_promise, verified, auth_key, is_frozen })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let bind = std::env::var("GG_BRIDGE_BIND").unwrap_or_else(|_| "127.0.0.1:7799".into());
    let origins_raw = std::env::var("GG_BRIDGE_ORIGINS").unwrap_or_else(|_| "http://127.0.0.1:7799".into());
    let relying = std::env::var("GG_BRIDGE_RELYING_SITE").unwrap_or_else(|_| "http://127.0.0.1:7799".into());
    let indexer = std::env::var("GG_INDEXER_ENDPOINT")
        .unwrap_or_else(|_| "https://esme-indexer-a.ootle.tari.com/".into());
    let threshold: u64 = std::env::var("GG_GATE_THRESHOLD")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(100_000_000);
    // The served gate is env-configurable so the same binary can host the local mainnet L2 lab
    // without touching the Esmeralda M16 fixture defaults.
    let gate_id = std::env::var("GG_GATE_ID").unwrap_or_else(|_| "esme".into());
    let network = u8::from_str_radix(
        std::env::var("GG_GATE_NETWORK_HEX").unwrap_or_else(|_| "26".into()).trim_start_matches("0x"),
        16,
    )?;
    let symbol = std::env::var("GG_GATE_SYMBOL").unwrap_or_else(|_| "tTARI".into());
    let divisibility: u8 = std::env::var("GG_GATE_DIVISIBILITY")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(6);

    let mut registry = GateRegistry::new();
    registry.register(
        gate_id.clone(),
        GateBinding::ootle(
            None,
            RESOURCE.parse()?,
            threshold,
            network,
            MaxBytes::new_checked(relying.as_bytes().to_vec())
                .ok_or_else(|| anyhow!("relying site too long"))?,
            divisibility,
            symbol,
        ),
    )?;

    // Experimental GGBP-1 v3 L1 tXTM test gate. Opt-in, Esmeralda L1 only, never authorizing:
    // the routes it enables return labelled test verdicts with authorized=false and no session.
    // The gate registers into the registry BEFORE the bridge consumes it.
    let ggbp1_enabled = std::env::var("GG_GGBP1_TEST")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let ggbp1_gate_id = std::env::var("GG_GGBP1_GATE_ID").unwrap_or_else(|_| "ggbp1xtm".into());
    if ggbp1_enabled {
        let ggbp1_threshold: u64 = std::env::var("GG_GGBP1_THRESHOLD_MICRO")
            .ok().and_then(|v| v.parse().ok()).unwrap_or(1_000_000);
        registry.register(
            ggbp1_gate_id.clone(),
            GateBinding::minotari_xtm(
                ggbp1_threshold,
                ghost_gate_ggbp1::ESMERALDA_NETWORK,
                MaxBytes::new_checked(relying.as_bytes().to_vec())
                    .ok_or_else(|| anyhow!("relying site too long"))?,
                "tXTM".into(),
            ),
        )?;
    }

    let origins = origins_raw.split(',').map(str::trim).filter(|s| !s.is_empty())
        .fold(OriginPolicy::new(), |p, o| p.allow(o));
    let chain = JsonChainReader::connect(&indexer)?;
    let mut bridge = Bridge::with_chain_reader(registry, NoWallet, origins, chain);

    if ggbp1_enabled {
        bridge.ggbp1_test = Some(std::sync::Arc::new(
            ghost_gate_ggbp1::Ggbp1TestServer::new_without_chain(
                ghost_gate_ggbp1::ESMERALDA_NETWORK,
                ghost_gate_ggbp1::ESMERALDA_GENESIS_HASH,
            ),
        ));
        println!("  experimental GGBP-1 v3 test gate {ggbp1_gate_id}: enabled (cryptography only; chain evidence not configured; never grants access)");
    }

    // The bot admission path is wired only when the operator explicitly configured a bot key
    // (the M16 Esmeralda fixture does). A bridge launched without one — the mainnet L2 lab —
    // refuses every bot route instead of advertising a fixture policy.
    if std::env::var("GG_BOT_KEY").is_ok() {
        let key_hex = std::env::var("GG_BOT_KEY").unwrap();
        let key_bytes = hex::decode(key_hex.trim())?;
        let bot_key: [u8; 32] = key_bytes.as_slice().try_into()?;
        let db_dir = std::env::var("GG_BOT_AUTH_DB_DIR")
            .unwrap_or_else(|_| std::env::temp_dir().join("gg-m16-auth-db").to_string_lossy().into_owned());
        std::fs::create_dir_all(&db_dir)?;
        let db_path = std::path::Path::new(&db_dir).join("authorization.sqlite");
        let mut db = AuthorizationCoordinator::create_new(&db_path)
            .or_else(|_| AuthorizationCoordinator::open_existing(&db_path))?;
        db.initialize_bot_event_store()?;
        bridge.bot_key = Some(bot_key);
        bridge.bot_authorizations = Some(db);
        bridge.bot_gate_policy = Some(BotGatePolicy {
            gate_id: std::env::var("GG_BOT_GATE_ID").unwrap_or_else(|_| gate_id.clone()),
            policy_hash: std::env::var("GG_BOT_POLICY_HASH")
                .unwrap_or_else(|_| "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface".into()),
            network,
            resource: RESOURCE.into(),
            threshold,
            telegram_chat_id: std::env::var("GG_BOT_CHAT_ID").ok().and_then(|v| v.parse().ok()).unwrap_or(-1001234567890),
        });
    }

    println!("M16 fixture bridge on http://{bind}/lab");
    println!("  gate {gate_id} network 0x{network:02x} threshold {threshold} indexer {indexer}");
    serve(&bind, bridge).await?;
    Ok(())
}
