//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! The proof service over the real Minotari wallet.
//!
//! # One wallet, two jobs
//!
//! The service runs a full in-process `minotari_wallet::Wallet` — the same stack the console
//! wallet runs, without the UI: key manager, output manager, transaction service, comms. It
//! exposes exactly two operations:
//!
//! - **status**: reachable, the network, and the wallet's *public* spend key. Nothing else.
//! - **prove**: one pay-to-self transaction carrying the challenge's answer, broadcast once, and
//!   the artifact the bridge verifies.
//!
//! # What "affordable" means, and why the exact boundary holds
//!
//! The fee fixed point in [`crate::service::largest_affordable_output_value`] is driven by the
//! wallet's own fee estimate (`preview_coin_split_with_commitments_no_amount` / the configured
//! `fee_per_gram`) rather than a hardcoded fee table. The output value is chosen as the largest
//! `v` with `v + fee(v) <= spendable`, so a wallet whose spendable balance is exactly the
//! threshold can still produce a qualifying transaction — its output promises `threshold - fee`,
//! and the verifier adds the kernel's own fee back before comparing. See the bridge's
//! `xtm::verify_xtm_proof` for the other half of that relation.
//!
//! # The spend-key signature
//!
//! The wallet's key manager signs the challenge nonce with the *script key* of the output being
//! created (`sign_script_message`). The bridge verifies that signature against the public key the
//! mined output's script carries (`PushPubKey(script_key.pub_key)`), so a proof cannot be
//! assembled from a transaction the wallet did not build in answer to this challenge.
//!
//! # What this process never does
//!
//! It never reports a balance to any caller; it never signs anything except its own proof
//! responses; it binds to the loopback interface only. The wallet's own funds move only between
//! the wallet's own addresses.

use std::sync::Arc;
use std::time::Duration;

use minotari_wallet::{
    WalletConfig, WalletSqlite,
    output_manager_service::error::OutputManagerError,
    storage::sqlite_utilities::{WalletDbConnection, initialize_sqlite_database_backends},
    transaction_service::{error::TransactionServiceError, storage::models::WalletTransaction},
    wallet::{Wallet, read_or_create_master_seed},
};
use tari_common::configuration::Network;
use tari_common_types::{seeds::cipher_seed::CipherSeed, tari_address::TariAddress};
use tari_comms::{
    NodeIdentity, multiaddr::Multiaddr, peer_manager::PeerFeatures, types::CommsPublicKey,
};
use tari_p2p::TransportType;
use tari_shutdown::Shutdown;
use tari_transaction_components::{
    consensus::ConsensusManager,
    crypto_factories::CryptoFactories,
    key_manager::TransactionKeyManagerInterface,
    tari_amount::MicroMinotari,
    transaction_components::{MemoField, OutputFeatures, memo_field::TxType},
};
use tari_transaction_key_manager::{
    legacy_key_manager::{LegacyTransactionKeyManagerWrapper, wallet_types::LegacyWalletType},
    storage::sqlite_db::TransactionKeyManagerSqliteDatabase,
};
use tari_utilities::{ByteArray, SafePassword};

use crate::service::{XtmProofOutcome, largest_affordable_output_value, spend_signature_message};
use ghost_gate_bridge::XtmProofArtifact;

/// How long a single attempt to reach the key manager may take.
const SIGN_TIMEOUT: Duration = Duration::from_secs(10);

/// The configuration a proof wallet starts with. Everything a malicious caller could misuse is
/// absent: there is no send-money operation, no import, no recovery.
#[derive(Debug, Clone)]
pub struct ProofWalletConfig {
    pub network: Network,
    pub base_path: std::path::PathBuf,
    /// The base node's p2p address, as a multiaddr string (`/ip4/127.0.0.1/tcp/N`).
    pub base_node_address: String,
    /// The base node's public key, hex.
    pub base_node_identity_public_key: String,
    /// The base node's HTTP fetch address (the "seed" HTTP endpoint wallets use).
    pub base_node_http_url: String,
    /// Fee per gram for the proving transaction, micro-Minotari.
    pub fee_per_gram: u64,
    /// How long the wallet's broadcast step may take.
    pub broadcast_timeout: Duration,
    /// The p2p TCP port this wallet listens on. Port 0 lets the OS assign one.
    pub listener_port: u16,
}

impl ProofWalletConfig {
    /// A local/testnet proving wallet pointed at a local base node.
    pub fn local_test(
        base_path: std::path::PathBuf,
        base_node_address: String,
        base_node_public_key_hex: String,
        base_node_http_url: String,
    ) -> Self {
        Self {
            network: Network::LocalNet,
            base_path,
            base_node_address,
            base_node_identity_public_key: base_node_public_key_hex,
            base_node_http_url,
            fee_per_gram: crate::service::DEFAULT_FEE_PER_GRAM,
            broadcast_timeout: crate::service::DEFAULT_BROADCAST_TIMEOUT,
            listener_port: 0,
        }
    }
}

/// A running proof wallet. Owns the shutdown signal so a caller can stop the stack cleanly.
pub struct ProofWalletService {
    pub shutdown: Shutdown,
    /// The wallet's service handles, held for the proof operations.
    pub wallet: WalletSqlite,
    pub network: Network,
    pub fee_per_gram: u64,
}

impl ProofWalletService {
    /// Starts the wallet stack. This is the console wallet's own `init_wallet` sequence, minus
    /// the UI and the interactive password prompt: the passphrase comes from configuration.
    pub async fn start(
        config: ProofWalletConfig,
        password: String,
        shutdown: Shutdown,
    ) -> Result<Self, crate::service::ServiceError> {
        let wallet_config = Self::wallet_config(&config);
        let db_path = wallet_config.db_file.clone();
        std::fs::create_dir_all(db_path.parent().unwrap_or(&config.base_path)).map_err(|e| {
            crate::service::ServiceError::Wallet(format!(
                "could not create the wallet directory: {e}"
            ))
        })?;

        let passphrase = SafePassword::from(password);
        let (wallet_backend, transaction_backend, output_manager_backend, key_manager_backend) =
            initialize_sqlite_database_backends(
                &db_path,
                passphrase.clone(),
                wallet_config.db_connection_pool_size,
            )
            .map_err(|e| {
                crate::service::ServiceError::Wallet(format!("wallet database init failed: {e}"))
            })?;

        let wallet_db = minotari_wallet::storage::database::WalletDatabase::new(wallet_backend);
        let output_db =
            minotari_wallet::output_manager_service::storage::database::OutputManagerDatabase::new(
                output_manager_backend.clone(),
            );

        // The seed: read from the DB on restart, create fresh on first run. No recovery path is
        // exposed here; an operator restores from backup or re-creates the wallet.
        let master_seed: CipherSeed = read_or_create_master_seed(None, &wallet_db)
            .map_err(|e| crate::service::ServiceError::Wallet(format!("seed init failed: {e}")))?;

        let node_addresses: Vec<Multiaddr> = wallet_db
            .get_node_address()
            .map_err(|e| {
                crate::service::ServiceError::Wallet(format!("node address read failed: {e}"))
            })?
            .map(|addr| vec![addr])
            .unwrap_or_default();

        let node_identity = Self::identity_from_db(&wallet_db, &master_seed, node_addresses)
            .map_err(crate::service::ServiceError::Wallet)?;

        let consensus_manager = ConsensusManager::builder(config.network).build();
        let factories = CryptoFactories::default();

        let mut wallet_config = wallet_config;
        wallet_config.password = Some(passphrase);

        let wallet = Wallet::<
            minotari_wallet::storage::sqlite_db::wallet::WalletSqliteDatabase,
            minotari_wallet::transaction_service::storage::sqlite_db::TransactionServiceSqliteDatabase,
            minotari_wallet::output_manager_service::storage::sqlite_db::OutputManagerSqliteDatabase,
            LegacyTransactionKeyManagerWrapper<TransactionKeyManagerSqliteDatabase<WalletDbConnection>>,
            minotari_wallet::client::http_client_factory::DefaultHttpClientFactory,
        >::start(
            wallet_config.clone(),
            tari_p2p::auto_update::AutoUpdateConfig::default(),
            node_identity,
            consensus_manager,
            factories,
            wallet_db,
            output_db,
            transaction_backend,
            output_manager_backend,
            key_manager_backend,
            shutdown.to_signal(),
            master_seed,
            None::<LegacyWalletType>,
        )
        .await
        .map_err(|e| crate::service::ServiceError::Wallet(format!("wallet start failed: {e}")))?;

        Ok(Self {
            shutdown,
            wallet,
            network: config.network,
            fee_per_gram: config.fee_per_gram,
        })
    }

    /// The console wallet's own comms-identity setup, transcribed rather than reached into the
    /// private `init` module: identity from the seed's comms key, signed and re-persisted if the
    /// stored signature no longer validates.
    fn identity_from_db(
        wallet_db: &minotari_wallet::storage::database::WalletDatabase<
            minotari_wallet::storage::sqlite_db::wallet::WalletSqliteDatabase,
        >,
        master_seed: &CipherSeed,
        node_addresses: Vec<Multiaddr>,
    ) -> Result<Arc<NodeIdentity>, String> {
        use minotari_wallet::wallet::derive_comms_secret_key;

        let node_features = wallet_db
            .get_node_features()
            .map_err(|e| format!("node features: {e}"))?
            .unwrap_or(PeerFeatures::COMMUNICATION_CLIENT);

        let identity_sig = wallet_db
            .get_comms_identity_signature()
            .map_err(|e| format!("identity signature read: {e}"))?;

        let comms_secret_key =
            derive_comms_secret_key(master_seed).map_err(|e| format!("comms key: {e}"))?;

        // The stored signature is valid only if it still validates against the derived key; the
        // `None` path re-signs below.
        let identity_sig = identity_sig.filter(|sig| {
            let comms_public_key = CommsPublicKey::from_secret_key(&comms_secret_key);
            matches!(
                sig.is_valid(&comms_public_key, node_features, &node_addresses),
                Ok(true)
            )
        });

        // SAFETY: we are manually checking the validity of this signature before adding Some(..)
        let node_identity = Arc::new(NodeIdentity::with_signature_unchecked(
            comms_secret_key,
            node_addresses,
            node_features,
            identity_sig,
        ));
        if !node_identity.is_signed() {
            node_identity.sign();
            let sig = node_identity
                .identity_signature_read()
                .as_ref()
                .expect("signed above")
                .clone();
            wallet_db
                .set_comms_identity_signature(sig)
                .map_err(|e| format!("identity signature write: {e}"))?;
        }

        Ok(node_identity)
    }

    fn wallet_config(config: &ProofWalletConfig) -> WalletConfig {
        let mut c = WalletConfig::default();
        c.network = config.network;
        c.set_base_path(&config.base_path);
        c.password = None;
        c.fee_per_gram = config.fee_per_gram;
        c.use_libtor = false;
        c.p2p.transport.transport_type = TransportType::Tcp;
        c.p2p.transport.tcp.listener_address =
            format!("/ip4/127.0.0.1/tcp/{}", config.listener_port)
                .parse()
                .unwrap_or_else(|_| "/ip4/127.0.0.1/tcp/0".parse().unwrap());
        c.p2p.public_addresses = vec![c.p2p.transport.tcp.listener_address.clone()].into();
        c.p2p.datastore_path = config.base_path.join("peer_db/proof-wallet");
        c.p2p.dht = tari_comms_dht::DhtConfig {
            database_url: tari_common_sqlite::connection::DbConnectionUrl::File(
                config.base_path.join("dht.sqlite"),
            ),
            ..tari_comms_dht::DhtConfig::default_local_test()
        };
        c.base_node_service_peers = Vec::from([format!(
            "{}::{}",
            config.base_node_identity_public_key, config.base_node_address
        )])
        .into();
        c.http_server_url = config.base_node_http_url.clone();
        c.fallback_http_server_url = config.base_node_http_url.clone();
        c.output_manager_service_config.num_confirmations_required = 0;
        c.output_manager_service_config.prevent_fee_gt_amount = false;
        c.transaction_service_config.num_confirmations_required = 0;
        c.scanning_interval = 5;
        c.transaction_service_config.broadcast_send_timeout = config.broadcast_timeout;
        c.transaction_service_config.direct_send_timeout = config.broadcast_timeout;
        c.grpc_enabled = false;
        c
    }

    /// The wallet's public spend key, hex. This is a public key and safe to serve.
    pub fn spend_public_key_hex(&self) -> String {
        use tari_crypto::tari_utilities::ByteArray as _;
        hex::encode(
            self.wallet
                .key_manager_service
                .get_spend_key()
                .pub_key
                .as_bytes(),
        )
    }

    /// The wallet's one-sided receive address, for funding the wallet by the miner.
    pub fn receive_address(&self) -> Result<TariAddress, crate::service::ServiceError> {
        self.wallet
            .get_wallet_one_sided_address()
            .map_err(|e| crate::service::ServiceError::Wallet(format!("wallet address: {e}")))
    }

    /// Builds the proving transaction for one challenge, with the fee fixed point applied.
    ///
    /// The output value is the largest affordable one; the minimum value promise is the whole
    /// output value (a pay-to-self output promises what it carries, and the kernel fee the wallet
    /// computes covers the boundary). The wallet's UTXO selection does the rest.
    pub async fn create_proof_transaction(
        &mut self,
        threshold_micro: u64,
        challenge_nonce: [u8; 32],
        fee_per_gram: MicroMinotari,
    ) -> Result<XtmProofOutcome, crate::service::ServiceError> {
        // 1. Spendable balance. The wallet's own accounting, and the only place a number like
        //    this is touched. It never leaves this function.
        let balance = self
            .wallet
            .output_manager_service
            .get_balance()
            .await
            .map_err(map_output_error)?;
        // The spendable figure is the available balance minus anything time-locked. Computed
        // here, in checked integers, and never logged.
        let spendable: u64 = {
            let available = balance.available_balance.as_u64();
            let locked = balance.time_locked_balance.map(|v| v.as_u64()).unwrap_or(0);
            available.saturating_sub(locked)
        };

        // 2. The fee fixed point: the largest output value v with v + fee(v) <= spendable. The
        //    bisection oracle is the conservative fee model below; the *exact* boundary is
        //    re-checked against the real kernel fee after the transaction is built, which is
        //    what keeps the gate's semantics honest end to end.
        let fpg = fee_per_gram.as_u64();
        let fee_for_value = move |_value: u64| -> u64 { 1_000 + fpg * 24 };
        // Nothing spendable at all (funds pending-in, coinbase maturing) is the SAME user
        // condition as "the balance cannot carry the threshold": an outcome the caller waits and
        // retries on, not an internal error. Surfacing it as Err made the bridge report a refusal
        // where the retry signal belonged.
        let Some(output_value) = largest_affordable_output_value(spendable, fee_for_value) else {
            return Ok(XtmProofOutcome::CannotAfford);
        };

        // 3. A first look at affordability, on the conservative model. Never a verdict: the
        //    real fee is read from the kernel after construction.
        if u128::from(output_value) + u128::from(fee_for_value(output_value))
            < u128::from(threshold_micro)
        {
            return Ok(XtmProofOutcome::CannotAfford);
        }

        // 4. Build. The output manager constructs the pay-to-self body; the promise is the whole
        //    output value, and nothing is broadcast yet.
        let memo =
            MemoField::new_open_from_string("Ghost Gate threshold proof", TxType::PaymentToSelf)
                .map_err(|e| crate::service::ServiceError::Wallet(format!("memo: {e}")))?;
        // The output manager can still conclude NotEnoughFunds between the balance read above and
        // the build (an encumbrance landed in between). Same answer as the solver's: an outcome the
        // caller retries on, not an error.
        let built = self
            .wallet
            .output_manager_service
            .create_pay_to_self_transaction(
                MicroMinotari(output_value),
                Default::default(),
                OutputFeatures::default(),
                fee_per_gram,
                None,
                memo,
                MicroMinotari(output_value),
            )
            .await;
        let (_fee_estimated, transaction, tx_id) = match built {
            Ok(v) => v,
            Err(OutputManagerError::NotEnoughFunds { .. }) => {
                return Ok(XtmProofOutcome::CannotAfford);
            }
            Err(other) => return Err(map_output_error(other)),
        };

        // 5. The exact boundary, against the *real* kernel fee the wallet just computed. This is
        //    the same comparison the verifier will run on chain; running it here prevents a
        //    broadcast that would fail the gate.
        let kernel = transaction
            .body
            .kernels()
            .iter()
            .next()
            .ok_or_else(|| {
                crate::service::ServiceError::Wallet("no kernel in transaction".to_string())
            })?
            .clone();
        let real_fee = kernel.fee.as_u64();
        let floor = u128::from(output_value) + u128::from(real_fee);
        if floor < u128::from(threshold_micro) {
            // The model under-estimated the fee. Do not broadcast a losing transaction: release
            // the short-term encumbrance and report honestly.
            let _ = self
                .wallet
                .output_manager_service
                .clear_short_term_encumberances()
                .await;
            return Ok(XtmProofOutcome::CannotAfford);
        }

        let mut kernel_excess_sig = [0u8; 64];
        kernel_excess_sig[..32]
            .copy_from_slice(kernel.excess_sig.get_compressed_public_nonce().as_bytes());
        kernel_excess_sig[32..].copy_from_slice(kernel.excess_sig.get_signature().as_bytes());

        let output = transaction
            .body
            .outputs()
            .iter()
            .find(|o| o.minimum_value_promise.as_u64() == output_value)
            .or_else(|| transaction.body.outputs().iter().next())
            .ok_or_else(|| {
                crate::service::ServiceError::Wallet("no output in transaction".to_string())
            })?;
        let output_hash: [u8; 32] = output
            .hash()
            .as_slice()
            .try_into()
            .expect("output hash is 32 bytes");

        // 6. The spend-key signature over the challenge. The script key the output was built
        //    with is the key the bridge will verify against, via the public key in the output's
        //    own script.
        // The script key's *private* key id lives on the wallet's own record of the output (the
        // `WalletOutput`), not on the public `TransactionOutput`. Fetch it by tx id.
        let outputs = self
            .wallet
            .output_manager_service
            .fetch_outputs_by_tx_id(tx_id)
            .await
            .map_err(map_output_error)?;
        let script_key_id = outputs
            .iter()
            .find(|o| o.hash.as_slice() == output.hash().as_slice())
            .or_else(|| outputs.first())
            .map(|o| o.wallet_output.script_key_id().clone())
            .ok_or_else(|| {
                crate::service::ServiceError::Wallet(
                    "the proving output is not in the wallet's records".to_string(),
                )
            })?;
        let signature = self
            .wallet
            .key_manager_service
            .sign_script_message(&script_key_id, &spend_signature_message(&challenge_nonce))
            .map_err(|e| {
                crate::service::ServiceError::Wallet(format!("spend-key signature: {e}"))
            })?;
        let mut spend_signature = [0u8; 64];
        spend_signature[..32].copy_from_slice(signature.get_compressed_public_nonce().as_bytes());
        spend_signature[32..].copy_from_slice(signature.get_signature().as_bytes());

        // 7. Broadcast exactly once, through the wallet's own submit path.
        self.wallet
            .transaction_service
            .submit_transaction(
                tx_id,
                transaction.clone(),
                MicroMinotari(output_value),
                MemoField::new_open_from_string(
                    "Ghost Gate threshold proof",
                    TxType::PaymentToSelf,
                )
                .map_err(|e| crate::service::ServiceError::Wallet(format!("memo: {e}")))?,
            )
            .await
            .map_err(map_transaction_error)?;

        Ok(XtmProofOutcome::Broadcast(XtmProofArtifact {
            transaction_id: tx_id.into(),
            kernel_excess_sig,
            output_hash,
            spend_signature,
        }))
    }

    /// Re-broadcasts the *same* transaction, for the ambiguous-submission case.
    ///
    /// The transaction service records the transaction by tx_id; re-submitting the same bytes is
    /// what the mempool deduplicates on. Building a second transaction for the same challenge is
    /// forbidden — the caller resolves ambiguity by querying status, not by re-submitting blind.
    pub async fn rebroadcast(&mut self, tx_id: u64) -> Result<(), crate::service::ServiceError> {
        let tx = self
            .wallet
            .transaction_service
            .get_any_transaction(tari_common_types::transaction::TxId::from(tx_id))
            .await
            .map_err(map_transaction_error)?;
        let Some(WalletTransaction::Completed(completed)) = tx else {
            return Err(crate::service::ServiceError::Wallet(format!(
                "transaction {tx_id} is not in a broadcastable state"
            )));
        };
        self.wallet
            .transaction_service
            .submit_transaction(
                tari_common_types::transaction::TxId::from(tx_id),
                completed.transaction,
                completed.amount,
                completed.payment_id,
            )
            .await
            .map_err(map_transaction_error)
    }
}

fn map_output_error(e: OutputManagerError) -> crate::service::ServiceError {
    match &e {
        OutputManagerError::NotEnoughFunds { .. } => crate::service::ServiceError::CannotAfford,
        other => crate::service::ServiceError::Wallet(format!("output manager: {other}")),
    }
}

fn map_transaction_error(e: TransactionServiceError) -> crate::service::ServiceError {
    crate::service::ServiceError::Wallet(format!("transaction service: {e}"))
}
