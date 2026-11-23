//! Local, non-authorizing GGBP-1 v3 test bridge.
//!
//! This is a test harness, not a production bridge. It runs the real `ghost-gate-bridge` HTTP
//! server with a no-op wallet, no chain reader, no XTM channel, and an in-memory GGBP-1 test
//! server. It exists so the Privacy Lab can be exercised against a real Tari Universe wallet
//! without building the full Minotari/walletd stack.
//!
//! It registers:
//!   * `xtmtest` — an Esmeralda L1 XTM gate for GGBP-1 v3;
//!   * `crypttest` — a credential-only tTARI gate for confirming the ordinary gate metadata and
//!     challenge route still work.
//!
//! Neither gate can authorize. GGBP-1 verdicts are always `authorized: false` and
//! `crypttest` has no chain reader, so its credential verify route returns 503.

use std::sync::Arc;
use std::time::Duration;

use ghost_gate_bridge::gate_registry::{GateBinding, GateRegistry};
use ghost_gate_bridge::origin::OriginPolicy;
use ghost_gate_bridge::server::{Bridge, serve};
use ghost_gate_bridge::wallet::{
    CommitOutcome, StatementReply, StatementRequest, WalletChannel, WalletError, WalletStatus,
};
use ghost_gate_ggbp1::{
    ESMERALDA_GENESIS_HASH, ESMERALDA_NETWORK, Ggbp1TestServer,
};
use tari_template_lib_types::stealth::StealthTransferStatement;
use tari_template_lib_types::{MaxBytes, ResourceAddress};

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
        _challenge: &ghost_gate_core::Challenge,
        _statement: &StealthTransferStatement,
        _lock_id: &str,
    ) -> Result<String, WalletError> {
        Err(WalletError::CannotConstructProof)
    }

    async fn wait(&mut self, _transaction_id: &str, _timeout: Duration) -> Result<CommitOutcome, WalletError> {
        Ok(CommitOutcome::Pending)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind = std::env::var("GG_BRIDGE_BIND").unwrap_or_else(|_| "127.0.0.1:7799".to_string());
    let origins_raw = std::env::var("GG_BRIDGE_ORIGINS")
        .unwrap_or_else(|_| "http://127.0.0.1:7799".to_string());
    let relying_site = std::env::var("GG_BRIDGE_RELYING_SITE")
        .unwrap_or_else(|_| "http://127.0.0.1:7799".to_string());
    let threshold = std::env::var("GG_GGBP1_THRESHOLD")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1_000_000);

    let origins = origins_raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .fold(OriginPolicy::new(), |policy, origin| policy.allow(origin));
    if origins.allowed().next().is_none() {
        return Err("GG_BRIDGE_ORIGINS must list at least one permitted browser origin".into());
    }

    let relying = MaxBytes::new_checked(relying_site.as_bytes().to_vec())
        .ok_or("GG_BRIDGE_RELYING_SITE exceeds 64 bytes")?;

    let mut registry = GateRegistry::new();
    registry.register(
        "xtmtest".to_string(),
        GateBinding::minotari_xtm(threshold, ESMERALDA_NETWORK, relying.clone(), "tXTM".to_string()),
    )?;
    // The published Esmeralda tTARI Crypt gate shape: 100 tTARI, divisibility 6, network 38,
    // credential-only. The resource is the published `resource_0101...` fixture; the relying site
    // is the local origin so the local bridge can mint challenges for it. This is the real gate
    // shape, not a dummy: it exercises the ordinary Ootle challenge route. A full credential proof
    // still needs a chain reader and is honestly 503 on this test bridge.
    let crypt_resource: ResourceAddress = format!("resource_{}", "01".repeat(32)).parse()?;
    registry.register(
        "Crypt".to_string(),
        GateBinding::ootle(
            None,
            crypt_resource,
            100_000_000,
            38,
            relying,
            6,
            "tTARI".to_string(),
        ),
    )?;

    let mut bridge = Bridge::new(registry, NoWallet, origins);
    bridge.ggbp1_test = Some(Arc::new(Ggbp1TestServer::new_without_chain(
        ESMERALDA_NETWORK,
        ESMERALDA_GENESIS_HASH,
    )));

    println!("GGBP-1 test bridge listening on http://{bind}/lab");
    println!("  xtmtest: Esmeralda XTM gate, threshold {threshold} micro-XTM, GGBP-1 v3 test only");
    println!("  Crypt: Esmeralda tTARI gate, 100 tTARI, credential-only (no chain reader; verify returns 503)");
    println!("  authorized=false and session=null on every GGBP-1 verdict");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(serve(&bind, bridge))?;
    Ok(())
}