//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! Deploys Ghost Gate's templates, resource and gates to a running localnet, through
//! Ghost Gate's own MVP-patched walletd.
//!
//! One command provisions a fresh walletd + localnet demonstration environment:
//!
//! ```text
//! deploy_vault                                  # publish templates, mint the resource, deploy the gates
//! ```
//!
//! The steps mirror the `@ghost_gate` cucumber scenario exactly — the flow the localnet evidence
//! was gathered against — driven here over the real walletd JSON-RPC instead of in-process:
//!
//! 1. publish the faucet and gate templates (dry-run for the fee, then publish);
//! 2. build the mint statement (wallet-side, `FromBucket`: no inputs, the whole supply revealed
//!    into stealth outputs owned by this wallet);
//! 3. call `faucet.new(symbol, divisibility, supply, mint)` — which creates the stealth resource
//!    and funds this wallet with it;
//! 4. deploy the demo gates over that resource at their thresholds;
//! 5. print the bridge configuration line, ready to paste.
//!
//! Everything is idempotent-friendly: existing templates are detected and reused, and each step is
//! a separate transaction, so a failed step loses nothing but its own fee.

use tari_ootle_transaction::{Epoch, TransactionBuilder, args};
use tari_ootle_walletd_client::permissions::Permission;
use tari_ootle_walletd_client::WalletDaemonClient;
use tari_ootle_walletd_client::types::{
    AccountsCreateStealthTransferStatementRequest, AuthCredentials, AuthLoginRequest,
    InputSelection, PublishTemplateRequest, TransactionSubmitRequest, TransactionWaitResultRequest,
    TransferStatementRequest,
};
use tari_ootle_wallet_sdk::apis::stealth_transfer::TransferOutput;
use tari_ootle_wallet_sdk::crypto::pay_to::PayTo;
use tari_template_lib_types::{
    Amount, ComponentAddress, MaxBytes, TemplateAddress,
};
use tari_engine_types::substate::{SubstateDiff, SubstateId};
use tari_ootle_wallet_sdk::models::Account;

const MAX_FEE_HEADROOM: u64 = 5_000_000;
/// The gate's relying-site identifier and session binding for this deployment.
const RELYING_SITE: &[u8] = b"vip.example";
const SESSION: &[u8] = b"haunted-vault";
const NETWORK: u8 = 0x10; // localnet

/// The demo gates this deployer creates: an id and its raw threshold. A production
/// deployment takes these from the administrator's registry instead — the deployer only proves
/// that the template, the resource and the component exist on chain.
const DOORS: &[(&str, u64)] = &[("crypt", 100_000), ("vault", 500_000), ("abyss", 2_000_000)];

/// The final gate: native Minotari L1 XTM, one million whole XTM. Configured in *base units*
/// (micro-Minotari): 1,000,000 XTM × 1,000,000 micro. Deployed by the operator's bridge config,
/// not here — the L1 gate has no Ootle component — but the figure is recorded so the printed
/// bridge line and the docs agree.
pub const MILLION_XTM_THRESHOLD_MICRO: u64 = 1_000_000 * 1_000_000;

struct Ctx {
    client: WalletDaemonClient,
    account: Account,
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn main() {
    let code = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("runtime").block_on(run());
    std::process::exit(code);
}

async fn run() -> i32 {
    let endpoint = env_or("GG_WALLETD_ENDPOINT", "http://127.0.0.1:18130/json_rpc");
    let symbol = env_or("GG_VAULT_SYMBOL", "GHOST");
    let divisibility: u8 = env_or("GG_VAULT_DIVISIBILITY", "6").parse().unwrap_or(6);
    let supply: u64 = env_or("GG_VAULT_SUPPLY", "10_000_000".replace('_', "").as_str()).parse().unwrap_or(10_000_000);

    // The deploy tool authenticates like the bridge: an API key when the wallet requires one.
    // Without an operator-supplied token it bootstraps one from the daemon itself — the walletd
    // answers `auth.request` (credentials `None`) with a JWT, which every account endpoint
    // demands even when the daemon runs in `none` auth mode.
    let supplied_token = std::env::var("GG_WALLETD_TOKEN").ok().filter(|t| !t.trim().is_empty()).is_some();
    let mut client = match WalletDaemonClient::connect(
        &endpoint,
        std::env::var("GG_WALLETD_TOKEN").ok().filter(|t| !t.trim().is_empty()).map(zeroize::Zeroizing::new),
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("deploy_vault: cannot connect to walletd at {endpoint}: {e}");
            return 1;
        },
    };
    if !supplied_token {
        match client
            .auth_request(&AuthLoginRequest {
                permissions: vec![Permission::Admin],
                credentials: AuthCredentials::None,
            })
            .await
        {
            Ok(resp) => {
                client.set_auth_token(resp.token);
            },
            Err(e) => {
                eprintln!(
                    "deploy_vault: cannot authenticate against {endpoint} ({e}); \
                     set GG_WALLETD_TOKEN to the wallet API key and try again"
                );
                return 1;
            },
        }
    }

    let mut ctx = match bootstrap_account(client).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("deploy_vault: {e}");
            return 1;
        },
    };

    // 1. Templates. Publishing is idempotent by content: a re-publish of the same WASM is a fee
    //    paid for nothing, so existing addresses are reused when present.
    let faucet_wasm = match load_wasm("ghost_gate_faucet") {
        Ok(w) => w,
        Err(e) => {
            eprintln!("deploy_vault: {e}");
            return 1;
        },
    };
    let gate_wasm = match load_wasm("ghost_gate") {
        Ok(w) => w,
        Err(e) => {
            eprintln!("deploy_vault: {e}");
            return 1;
        },
    };

    let faucet_addr = match publish_template(&mut ctx, faucet_wasm, "GhostGateFaucet").await {
        Ok(a) => a,
        Err(e) => {
            eprintln!("deploy_vault: publishing the faucet template: {e}");
            return 1;
        },
    };
    let gate_template = match publish_template(&mut ctx, gate_wasm, "GhostGate").await {
        Ok(a) => a,
        Err(e) => {
            eprintln!("deploy_vault: publishing the gate template: {e}");
            return 1;
        },
    };

    // 2-3. The resource, minted through the faucet with a wallet-built statement.
    let (resource, _faucet) = match mint_resource(&mut ctx, faucet_addr, &symbol, divisibility, supply).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("deploy_vault: creating the resource: {e}");
            return 1;
        },
    };

    // 4. The three gates.
    let mut gates: Vec<(String, ComponentAddress)> = Vec::new();
    for (gate_id, threshold) in DOORS {
        match deploy_gate(&mut ctx, gate_template, resource, *threshold).await {
            Ok(addr) => gates.push((gate_id.to_string(), addr)),
            Err(e) => {
                eprintln!("deploy_vault: deploying gate {gate_id}: {e}");
                return 1;
            },
        }
    }

    // 5. The bridge configuration, ready to paste.
    let gates_env = gates
        .iter()
        .map(|(id, addr)| format!("{id}={addr}:{resource}:{thr}:{divisibility}:{symbol}", thr = {
            DOORS.iter().find(|(g, _)| g == id).map(|(_, t)| t).unwrap_or(&0)
        }))
        .collect::<Vec<_>>()
        .join(",");
    println!();
    println!("deploy_vault: done.");
    println!("  faucet:   {faucet_addr}");
    println!("  gate template: {gate_template}");
    println!("  resource: {resource} ({symbol}, divisibility {divisibility}, supply {supply})");
    for (id, addr) in &gates {
        println!("  gate {id}: {addr}");
    }
    println!();
    println!("  Restart the bridge service with:");
    println!("    GG_BRIDGE_GATES='{gates_env}' \\");
    println!("    GG_WALLETD_ENDPOINT='{endpoint}' \\");
    println!("    <your bridge-service command>");
    0
}

/// Ensures the wallet has a default account with an owner key, failing with an honest message when
/// the wallet was never initialised.
async fn bootstrap_account(mut client: WalletDaemonClient) -> Result<Ctx, String> {
    let account = client
        .accounts_get_default()
        .await
        .map_err(|e| format!("the wallet has no default account yet ({e}); open the wallet's web UI once so it creates its keys, or run the create-key flow, and try again"))?
        .account;
    if account.owner_key_id.is_none() {
        return Err("the default account has no owner key; this wallet cannot sign".into());
    }
    Ok(Ctx { client, account })
}

/// The templates build for wasm32 in their own cargo workspaces; the built .wasm is expected at
/// `target/wasm32-unknown-unknown/release/<name>.wasm`, produced by its template workspace.
fn load_wasm(name: &str) -> Result<Vec<u8>, String> {
    // The artifact name follows the package name (hyphens to underscores), and the template may
    // pin its own target-dir via .cargo/config.toml (target/default/).
    let pkg = match name {
        "ghost_gate" => "ghost_gate_template",
        other => other,
    };
    let candidates = [
        format!("../../templates/{name}/target/default/wasm32-unknown-unknown/release/{pkg}.wasm"),
        format!("../../templates/{name}/target/wasm32-unknown-unknown/release/{pkg}.wasm"),
    ];
    for path in &candidates {
        if let Ok(bytes) = std::fs::read(path) {
            return Ok(bytes);
        }
    }
    Err(format!(
        "no compiled template found for {name} (tried {}); build the matching template workspace first",
        candidates.join(", ")
    ))
}

/// Publishes one template: dry-run to learn the fee, then publish with headroom.
async fn publish_template(ctx: &mut Ctx, wasm: Vec<u8>, name: &str) -> Result<TemplateAddress, String> {
    let dry = ctx
        .client
        .publish_template(PublishTemplateRequest {
            binary: wasm.clone(),
            fee_account: Some(tari_ootle_walletd_client::ComponentAddressOrName::ComponentAddress(
                ctx.account.component_address,
            )),
            max_fee: MAX_FEE_HEADROOM,
            detect_inputs: true,
            dry_run: true,
            metadata: None,
        })
        .await
        .map_err(|e| format!("the dry run failed: {e}"))?;
    let required = dry.dry_run_fee.ok_or("the dry run returned no fee")?;
    let max_fee = required.saturating_add(required / 10 + 1).min(MAX_FEE_HEADROOM);
    println!("publishing {name}: estimated fee {required}, cap {max_fee}");

    let response = ctx
        .client
        .publish_template(PublishTemplateRequest {
            binary: wasm,
            fee_account: Some(tari_ootle_walletd_client::ComponentAddressOrName::ComponentAddress(
                ctx.account.component_address,
            )),
            max_fee,
            detect_inputs: true,
            dry_run: false,
            metadata: None,
        })
        .await
        .map_err(|e| format!("publish failed: {e}"))?;
    let finalize = wait(ctx, response.transaction_id, name).await?;
    let template = finalize
        .result
        .any_accept()
        .and_then(|diff| {
            diff.up_iter().find_map(|(id, _)| match id {
                SubstateId::Template(t) => Some(t),
                _ => None,
            })
        })
        .ok_or_else(|| "the publish committed no template substate".to_string())?;
    // The substate id's template address is a hash; convert the way the harness does.
    let hash = template.as_hash();
    let template = TemplateAddress::try_from_slice(hash.as_ref())
        .map_err(|e| format!("template address conversion: {e}"))?;
    println!("  {name} published at {template}");
    Ok(template)
}

/// Creates the faucet component and its stealth resource, then funds this wallet from the faucet.
///
/// Two transactions, exactly as the `@ghost_gate` scenario does it, and the reason is a real
/// constraint: a stealth output's tag is derived by its sender from the resource address, so the
/// wallet cannot build a funding output until the resource is on chain. The resource is created
/// first (no statement needed — the faucet's `new_resource` mints the revealed supply into its own
/// vault), and the wallet then builds a `FromBucket` statement against that resource — the revealed
/// amount comes from the faucet's minted supply, the stealth output is encrypted to the wallet's
/// own view key — and `faucet.mint` turns it into a UTXO the wallet can legitimately spend later.
async fn mint_resource(
    ctx: &mut Ctx,
    faucet_template: TemplateAddress,
    symbol: &str,
    divisibility: u8,
    supply: u64,
) -> Result<(tari_template_lib_types::ResourceAddress, ComponentAddress), String> {
    use tari_template_lib_types::stealth::StealthTransferStatement;

    // Step 1: the faucet component + the resource, in one call_function.
    let account = ctx.account.component_address;
    let transaction = TransactionBuilder::new(NETWORK, Epoch(1_000_000))
        .with_nonce(rand::random())
        .pay_fee_from_component(account, MAX_FEE_HEADROOM)
        .call_function(
            faucet_template,
            "new_resource",
            args![symbol.to_string(), divisibility, Amount::from(supply)],
        )
        .add_input(account)
        .build_unsigned();

    let owner = ctx.account.owner_key_id.clone().ok_or("no owner key")?;
    let submitted = ctx
        .client
        .submit_transaction(TransactionSubmitRequest {
            transaction,
            seal_signer: owner,
            other_signers: vec![],
            signatures: vec![],
            detect_inputs: true,
            detect_inputs_use_unversioned: true,
            lock_ids: vec![],
        })
        .await
        .map_err(|e| format!("submit failed: {e}"))?;
    let finalize = wait(ctx, submitted.transaction_id, "the faucet").await?;
    let accept = finalize.result.any_accept().ok_or("the faucet deployment was not accepted")?;
    let faucet = accept
        .up_iter()
        .find_map(|(id, _)| match id {
            SubstateId::Component(c) => Some(*c),
            _ => None,
        })
        .ok_or_else(|| "the deployment committed no faucet component".to_string())?;
    let resource = accept
        .up_iter()
        .find_map(|(id, _)| id.as_resource_address())
        .ok_or_else(|| "the deployment committed no resource".to_string())?;
    println!("  faucet component {faucet}, resource {resource}");

    // Step 2: the wallet funds itself from the faucet's supply, wallet-built statement.
    let wallet_addr = ctx.client.accounts_get_default().await.map_err(|e| e.to_string())?.address;
    let statement = ctx
        .client
        .accounts_create_stealth_transfer_statement(AccountsCreateStealthTransferStatementRequest {
            requests: vec![TransferStatementRequest {
                sender_account: tari_ootle_walletd_client::ComponentAddressOrName::ComponentAddress(account),
                resource_address: resource,
                // Nothing is spent from the account: the value comes from the faucet's minted
                // supply, revealed in. `FromBucket` is the handler's name for exactly that.
                input_selection: InputSelection::FromBucket {
                    revealed_amount: Amount::from(supply),
                },
                outputs: vec![TransferOutput {
                    address: wallet_addr,
                    revealed_amount: Amount::zero(),
                    blinded_amount: supply,
                    memo: None,
                    pay_to: PayTo::StealthPublicKey,
                    // A funding output promises nothing: the gate proof is what promises.
                    minimum_value_promise: 0,
                }],
            }],
        })
        .await
        .map_err(|e| format!("the wallet would not build the funding statement: {e}"))?;
    let statement: StealthTransferStatement = statement
        .statements
        .into_iter()
        .next()
        .ok_or("the wallet built no statement")?;

    // FromBucket spends no inputs, so there is nothing to release; the lock simply expires.
    let transaction = TransactionBuilder::new(NETWORK, Epoch(1_000_000))
        .with_nonce(rand::random())
        .pay_fee_from_component(account, MAX_FEE_HEADROOM)
        .call_method(faucet, "mint", args![statement])
        .add_input(account)
        .add_input(faucet)
        .build_unsigned();

    let owner = ctx.account.owner_key_id.clone().ok_or("no owner key")?;
    let submitted = ctx
        .client
        .submit_transaction(TransactionSubmitRequest {
            transaction,
            seal_signer: owner,
            other_signers: vec![],
            signatures: vec![],
            detect_inputs: true,
            detect_inputs_use_unversioned: true,
            lock_ids: vec![],
        })
        .await
        .map_err(|e| format!("submit failed: {e}"))?;
    wait(ctx, submitted.transaction_id, "the funding").await?;
    println!("  wallet funded with {supply} {symbol}");
    Ok((resource, faucet))
}

/// Deploys one gate component over `resource` at `threshold`.
async fn deploy_gate(
    ctx: &mut Ctx,
    template: TemplateAddress,
    resource: tari_template_lib_types::ResourceAddress,
    threshold: u64,
) -> Result<ComponentAddress, String> {
    let account = ctx.account.component_address;
    let transaction = TransactionBuilder::new(NETWORK, Epoch(1_000_000))
        .with_nonce(rand::random())
        .pay_fee_from_component(account, MAX_FEE_HEADROOM)
        .allocate_component_address("gate_deploy")
        .call_function(
            template,
            "new",
            args![
                Workspace("gate_deploy"),
                resource,
                threshold,
                site_bytes(),
                session_bytes(),
                NETWORK,
            ],
        )
        .add_input(account)
        .build_unsigned();

    let owner = ctx.account.owner_key_id.clone().ok_or("no owner key")?;
    let submitted = ctx
        .client
        .submit_transaction(TransactionSubmitRequest {
            transaction,
            seal_signer: owner,
            other_signers: vec![],
            signatures: vec![],
            detect_inputs: true,
            detect_inputs_use_unversioned: true,
            lock_ids: vec![],
        })
        .await
        .map_err(|e| format!("submit failed: {e}"))?;
    let finalize = wait(ctx, submitted.transaction_id, "the gate").await?;
    let gate = finalize
        .result
        .any_accept()
        .and_then(|diff: &SubstateDiff| {
            diff.up_iter().find_map(|(id, _)| match id {
                SubstateId::Component(c) => Some(*c),
                _ => None,
            })
        })
        .ok_or_else(|| "the deployment committed no component".to_string())?;
    println!("  gate deployed at {gate} (threshold {threshold})");
    Ok(gate)
}

async fn wait(
    ctx: &mut Ctx,
    transaction_id: tari_ootle_transaction::TransactionId,
    what: &str,
) -> Result<tari_engine_types::commit_result::FinalizeResult, String> {
    let waited = ctx
        .client
        .wait_transaction_result(TransactionWaitResultRequest {
            transaction_id,
            timeout_secs: Some(300),
        })
        .await
        .map_err(|e| format!("waiting for {what}: {e}"))?;
    if waited.timed_out {
        return Err(format!("{what} timed out"));
    }
    let finalize = waited
        .result
        .ok_or_else(|| format!("{what} finished with {:?}", waited.status))?;
    if let Some(reason) = finalize.result.any_reject() {
        return Err(format!("{what} was rejected: {reason:?}"));
    }
    Ok(finalize)
}



fn site_bytes() -> MaxBytes<64> {
    MaxBytes::new_checked(RELYING_SITE.to_vec()).expect("short")
}

fn session_bytes() -> MaxBytes<64> {
    MaxBytes::new_checked(SESSION.to_vec()).expect("short")
}
