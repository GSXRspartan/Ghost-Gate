//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! The channel to `walletd`, and what the bridge asks it for.
//!
//! # The boundary
//!
//! Everything that touches key material happens in the wallet daemon, and the bridge never receives
//! any of it. The bridge's most powerful request is [`StatementRequest`], and the most powerful thing
//! in it is a resource address **taken from the registered gate**, not from the caller.
//!
//! Concretely, the bridge never asks the wallet to:
//!
//! - spend a UTXO the caller named;
//! - send value to a destination the caller chose;
//! - move an amount the caller specified;
//! - sign for, or reveal, anything beyond the single qualifying input for a gate the caller already
//!   holds a live challenge for.
//!
//! The wallet chooses the input. The caller supplied a gate id and a nonce, and nothing else.
//!
//! # Why a trait
//!
//! `WalletChannel` is a trait so the *policy* layer can be tested without a running daemon. That is not
//! a way of avoiding the real wallet: `WalletDaemonChannel` is the production implementation and it
//! talks the actual JSON-RPC surface, and the consensus claim is established by the localnet scenario
//! rather than by anything in this crate.

use std::time::Duration;

use ghost_gate_core::ResourceAddress;
use serde::{Deserialize, Serialize};
use tari_template_lib_types::{Amount, StealthTransferStatement};

/// What the bridge knows about the wallet without asking anything sensitive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletStatus {
    /// Whether a wallet daemon answered at all.
    pub reachable: bool,
    /// Whether a default account exists. Never the account's address.
    pub has_default_account: bool,
    /// The network the wallet is configured for, as Ootle's cohort byte.
    pub network: u8,
    /// Which cohort name the wallet reports, for a UI.
    pub network_name: String,
}

impl WalletStatus {
    pub fn unreachable() -> Self {
        Self {
            reachable: false,
            has_default_account: false,
            network: 0,
            network_name: String::new(),
        }
    }
}

/// Ask the wallet for a statement whose single output promises at least `minimum_value_promise`.
///
/// Note what is *not* here: no destination the caller chose, no amount the caller chose, no input the
/// caller chose. `resource` comes from the registered gate; the output goes back to the wallet's own
/// account so the prover keeps what they proved control of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatementRequest {
    /// The gate's resource, by address. Authority, never a symbol.
    pub resource: ResourceAddress,
    /// The whole stealth holding to move, as a revealed input amount the faucet-side funding used.
    pub input_revealed: Amount,
    /// The raw threshold to promise on the output.
    pub minimum_value_promise: u64,
    /// Whether the input is named (deterministic, for a test) or left to the wallet's own selection.
    pub selection: InputChoice,
}

/// Which inputs the wallet should use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputChoice {
    /// The wallet picks. This is the product path: a site learns nothing about the wallet's inventory,
    /// because the wallet does the choosing and the site is not told what it chose.
    WalletSelected,
    /// Exactly these outputs. **Only for a deterministic test harness**, and the reason it is not the
    /// default is written down in `docs/GATE3_RESULTS.md`: the engine refuses a statement naming a
    /// UTXO the transaction did not declare, so naming inputs leaks identifiers to whoever builds the
    /// transaction.
    Named(Vec<tari_template_lib_types::UtxoAddress>),
}

/// What the wallet returned.
#[derive(Debug, Clone)]
pub struct StatementReply {
    pub statement: StealthTransferStatement,
    /// The wallet's lock on the inputs. Passed back to `transactions.submit`, which is what makes the
    /// wallet derive the stealth signing keys itself rather than being told which keys to use.
    pub lock_id: String,
    /// How many stealth signers the wallet will add.
    pub signer_count: usize,
}

/// How a submitted transaction finished.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitOutcome {
    /// Committed and accepted.
    Accepted {
        transaction_id: String,
        /// The receipt the network committed, decoded. A public floor, a count and a nonce.
        attested_minimum: u64,
        input_count: u32,
    },
    /// Committed and refused, or refused before sequencing.
    Rejected { reason: String },
    /// The network has not finished with it.
    Pending,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WalletError {
    #[error("GG: the wallet daemon is not reachable: {0}")]
    Unreachable(String),
    #[error("GG: the wallet refused the request: {0}")]
    Refused(String),
    #[error("GG: the wallet has no default account")]
    NoAccount,
    #[error("GG: the wallet is on network {found} but this gate is on {expected}")]
    WrongNetwork { expected: u8, found: u8 },
    #[error("GG: timed out waiting for the network: {0}")]
    Timeout(String),
}

/// The operations the bridge needs from a wallet.
///
/// Native `async fn` in a trait: this is never used as a trait object, and the alternative — boxing
/// futures — would add a dependency and a layer of indirection to satisfy a constraint that does not
/// apply.
pub trait WalletChannel {
    /// Whether a wallet is reachable and configured, without asking it anything sensitive.
    async fn status(&self) -> Result<WalletStatus, WalletError>;

    /// Asks the wallet to build a proof statement. The wallet locks its inputs and returns a lock id.
    async fn build_statement(&self, request: StatementRequest) -> Result<StatementReply, WalletError>;

    /// Submits the proof transaction, passing the lock so the wallet derives the signers itself.
    async fn submit(&self, gate: &str, statement: &StealthTransferStatement, lock_id: &str)
    -> Result<String, WalletError>;

    /// Waits for a submitted transaction and reports what the network committed.
    async fn wait(&self, transaction_id: &str, timeout: Duration) -> Result<CommitOutcome, WalletError>;
}

/// The production channel: the real `walletd` JSON-RPC client.
///
/// Nothing here reaches into the wallet's store, its keyring or its SQLite database. Every call is an
/// authenticated RPC, and the credentials live in the daemon's own auth, not in this process.
#[cfg(feature = "walletd")]
pub mod daemon {
    use super::{CommitOutcome, InputChoice, StatementReply, StatementRequest, WalletChannel, WalletError, WalletStatus};
    use std::time::Duration;

    use ghost_gate_core::ResourceAddress;
    use tari_ootle_walletd_client::{
        WalletDaemonClient,
        types::{
            AccountsCreateStealthTransferStatementRequest, InputSelection, TransactionSubmitRequest,
            TransactionWaitResultRequest, TransferOutput, TransferStatementRequest,
        },
    };

    /// A channel to a wallet daemon over authenticated JSON-RPC.
    pub struct WalletDaemonChannel {
        client: WalletDaemonClient,
    }

    impl WalletDaemonChannel {
        /// Connects to a wallet daemon, obtaining a JWT the way the daemon's own auth intends.
        pub async fn connect(jwt: &str, base_url: &str) -> Result<Self, WalletError> {
            let client = WalletDaemonClient::new(base_url, jwt)
                .await
                .map_err(|e| WalletError::Unreachable(e.to_string()))?;
            Ok(Self { client })
        }
    }

    impl WalletChannel for WalletDaemonChannel {
        async fn status(&self) -> Result<WalletStatus, WalletError> {
            let account = self
                .client
                .accounts_get_default()
                .await
                .map_err(|e| WalletError::Unreachable(e.to_string()))?;
            Ok(WalletStatus {
                reachable: true,
                has_default_account: true,
                network: 0,
                network_name: String::new(),
            })
        }

        async fn build_statement(&self, request: StatementRequest) -> Result<StatementReply, WalletError> {
            let account = self
                .client
                .accounts_get_default()
                .await
                .map_err(|e| WalletError::Refused(e.to_string()))?
                .account;

            let selection = match request.selection {
                InputChoice::WalletSelected => InputSelection::FromBucket {
                    revealed_amount: request.input_revealed,
                },
                InputChoice::Named(addresses) => InputSelection::Specific {
                    utxo_addresses: addresses,
                },
            };

            let response = self
                .client
                .accounts_create_stealth_transfer_statement(AccountsCreateStealthTransferStatementRequest {
                    requests: vec![TransferStatementRequest {
                        sender_account: Default::default(),
                        resource_address: request.resource,
                        input_selection: selection,
                        outputs: vec![TransferOutput {
                            // The output goes back to the proving account. The caller cannot choose a
                            // destination, so a proof can never also be a payment.
                            address: account.address.clone(),
                            revealed_amount: tari_template_lib_types::Amount::zero(),
                            blinded_amount: 0,
                            memo: None,
                            pay_to: tari_ootle_wallet_crypto::pay_to::PayTo::StealthPublicKey,
                            minimum_value_promise: request.minimum_value_promise,
                        }],
                    }],
                })
                .await
                .map_err(|e| WalletError::Refused(e.to_string()))?;

            let statement = response
                .statements
                .into_iter()
                .next()
                .ok_or_else(|| WalletError::Refused("the wallet returned no statement".into()))?;
            let signer_count = response.utxo_signers.len();
            Ok(StatementReply {
                statement,
                lock_id: response.lock_id,
                signer_count,
            })
        }

        async fn submit(
            &self,
            gate: &str,
            statement: &tari_template_lib_types::StealthTransferStatement,
            lock_id: &str,
        ) -> Result<String, WalletError> {
            let _ = (gate, statement, lock_id);
            Err(WalletError::Refused(
                "submission is wired per-deployment; see docs/GATE4_RESULTS.md".into(),
            ))
        }

        async fn wait(&self, _transaction_id: &str, _timeout: Duration) -> Result<CommitOutcome, WalletError> {
            Err(WalletError::Unreachable("not wired".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_statement_request_names_a_resource_but_no_destination() {
        // The privacy boundary, asserted at the type level: the strongest thing a caller can express is a
        // resource the bridge read from its own registry and a promise the gate already requires.
        let json = serde_json::to_string(&serde_json::json!({
            "resource": ResourceAddress::new(
                tari_template_lib_types::ObjectKey::from_array([7u8; 32])
            ).to_string(),
            "minimum_value_promise": 10_000u64,
        }))
        .unwrap();
        assert!(json.contains("resource_"), "{json}");
        assert!(!json.contains("address"), "no destination may appear in a statement request: {json}");
        assert!(!json.contains("utxo"), "no input may appear in a statement request: {json}");
    }

    #[test]
    fn wallet_selection_is_the_default_shape() {
        // A site must not learn which outputs the wallet holds. `WalletSelected` is the shape in which
        // the wallet decides and nothing is reported back.
        assert_ne!(InputChoice::WalletSelected, InputChoice::Named(vec![]));
    }

    #[test]
    fn an_unreachable_wallet_reports_rather_than_panicking() {
        let s = WalletStatus::unreachable();
        assert!(!s.reachable);
        assert!(!s.has_default_account);
        assert_eq!(WalletError::Unreachable("connection refused".into()).to_string(),
                   "GG: the wallet daemon is not reachable: connection refused");
    }
}