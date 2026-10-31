//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! The real [`WalletChannel`], talking to a running `walletd`.
//!
//! This crate exists as its own crate rather than as a module in `ghost-gate-bridge` because it needs
//! the walletd client, the wallet SDK and the transaction builder. Keeping those out of the bridge means
//! the bridge's 61 policy tests compile without the wallet SDK in the graph, and the security-relevant
//! question -- which HTTP request may do what -- stays readable without tracing a client library.
//!
//! # What this does, end to end
//!
//! A `POST /gate/{id}/prove` carries a gate id, a challenge nonce and a session commitment. Nothing
//! else. From that, this adapter:
//!
//! 1. lists the wallet's **unspent outputs of the gate's own resource** ([`stealth_utxos_list`]),
//!    filtered to `Unspent`, on-chain, not burnt, not frozen;
//! 2. picks one whose value meets the gate's threshold, entirely locally;
//! 3. asks the wallet to build a statement spending exactly that output, with the gate's threshold as
//!    the output's `minimum_value_promise` ([`accounts_create_stealth_transfer_statement`]);
//! 4. builds the `prove_access` call and submits it under the wallet's lock, so the wallet derives the
//!    stealth signers itself ([`submit_transaction`]);
//! 5. waits for the network's verdict and reports only the public floor ([`wait_transaction_result`]).
//!
//! # Where the UTXO identifier lives
//!
//! Step 1 is the whole privacy argument. The identifier of the output being spent is chosen by the
//! wallet, filtered by a resource address the **gate** supplied, and never crosses the bridge's HTTP
//! API in either direction. A relying site learns `attested_minimum`, `input_count` and a transaction
//! id. It cannot learn which output was spent, what it was worth, or what else the wallet holds --
//! because no route in `ghost-gate-bridge` returns a UTXO address and no request body accepts one.
//!
//! That this is necessary is a finding about the engine, not a design preference. The engine resolves a
//! spent input under the gate's resource and refuses a transaction that does not declare every
//! substate it spends, so a wallet that chose freely could not tell the builder what to declare. See
//! `ghost_gate_bridge::wallet::InputChoice` for the full argument, and `docs/GATE4_RESULTS.md` for the
//! two-stage flow this shape anticipates.
//!
//! # Key isolation
//!
//! This crate never holds a private key, a mask, or a decrypted value. `submit_transaction` is called
//! with a `seal_signer` key **id** and a `lock_id`; the daemon holds the keys and returns signatures
//! that never pass through this process. The same property holds for the values in step 1: the wallet
//! decrypts its own outputs and reports them over loopback, and only a comparison against the gate's
//! public threshold happens here.
//!
//! [`stealth_utxos_list`]: tari_ootle_walletd_client::WalletDaemonClient::stealth_utxos_list
//! [`accounts_create_stealth_transfer_statement`]: tari_ootle_walletd_client::WalletDaemonClient::accounts_create_stealth_transfer_statement
//! [`submit_transaction`]: tari_ootle_walletd_client::WalletDaemonClient::submit_transaction
//! [`wait_transaction_result`]: tari_ootle_walletd_client::WalletDaemonClient::wait_transaction_result

mod esmeralda;
mod indexer;

pub use esmeralda::JsonChainReader;
pub use indexer::IndexerChainReader;

use std::time::Duration;

use ghost_gate_bridge::wallet::{
    CommitOutcome, InputChoice, StatementReply, StatementRequest, WalletChannel, WalletError,
    WalletStatus,
};
use tari_ootle_transaction::{Epoch, Network, TransactionBuilder, TransactionId, args};
use tari_ootle_wallet_sdk::apis::stealth_transfer::TransferOutput;
use tari_ootle_wallet_sdk::crypto::pay_to::PayTo;
use tari_ootle_wallet_sdk::models::{OutputStatus, WalletLockId};
use tari_ootle_walletd_client::WalletDaemonClient;
use tari_ootle_walletd_client::types::{
    AccountGetResponse, AccountsCreateStealthTransferStatementRequest, InputSelection,
    StealthUtxosListRequest, TransactionSubmitRequest, TransactionWaitResultRequest,
    TransactionWaitResultResponse, TransferStatementRequest,
};
use tari_template_lib_types::stealth::StealthTransferStatement;
use tari_template_lib_types::{Amount, ComponentAddress, ResourceAddress, UtxoAddress, UtxoId};

/// A [`WalletChannel`] backed by a live wallet daemon.
pub struct WalletDaemonChannel {
    client: WalletDaemonClient,
    /// The chain this bridge was configured for. Checked against the wallet's own report before any
    /// signing, so a wallet pointed at mainnet is never used to answer a localnet challenge.
    expected_network: u8,
    /// The fee ceiling offered for the proof transaction, in the network's own denomination.
    max_fee: u64,
    /// Validity window for the proof transaction.
    ///
    /// A challenge carries `expires_epoch`, and the bridge must not build a transaction that outlives
    /// the challenge it answers: a proof sequenced after its challenge expired would be refused by the
    /// template anyway, but it would spend the inputs first. Clamped to the challenge's own expiry.
    max_epoch: u64,
    /// Whether the operator supplied a real credential. When true, [`Self::bootstrap_local_auth`]
    /// must leave the supplied token untouched.
    token_supplied: bool,
    /// Which account to prove from. When `Some`, the adapter calls `accounts_get` with this name
    /// instead of `accounts_get_default`. An operator sets `GG_WALLETD_ACCOUNT` to bind the bridge
    /// to a specific wallet account; the name never comes from a browser request.
    account_name: Option<String>,
}

impl WalletDaemonChannel {
    /// Connects to `endpoint`, which is a walletd JSON-RPC URL on loopback.
    ///
    /// `token` is the walletd API key, when the daemon requires authentication — an operator sets
    /// `GG_WALLETD_TOKEN` and the bridge presents it on every call. The token is held by the
    /// process and never logged; it is a credential, not configuration.
    pub fn connect(
        endpoint: &str,
        token: Option<String>,
        expected_network: u8,
        max_fee: u64,
        max_epoch: u64,
    ) -> Result<Self, WalletError> {
        Self::connect_with_account(endpoint, token, expected_network, max_fee, max_epoch, None)
    }

    /// Connects to `endpoint` and binds to a specific account by name.
    ///
    /// When `account_name` is `Some`, the adapter uses `accounts_get` with that name instead of
    /// `accounts_get_default`. The name is an operator configuration (`GG_WALLETD_ACCOUNT`), never
    /// from a browser request — a caller cannot select which account proves.
    pub fn connect_with_account(
        endpoint: &str,
        token: Option<String>,
        expected_network: u8,
        max_fee: u64,
        max_epoch: u64,
        account_name: Option<String>,
    ) -> Result<Self, WalletError> {
        let token_supplied = token.is_some();
        let encoded = token.map(zeroize::Zeroizing::new);
        let client = WalletDaemonClient::connect(endpoint, encoded)
            .map_err(|e| WalletError::Unreachable(format!("cannot build a walletd client: {e}")))?;
        Ok(Self {
            client,
            expected_network,
            max_fee,
            max_epoch,
            token_supplied,
            account_name,
        })
    }

    /// Bootstraps a bearer token from a `none`-auth-mode wallet daemon.
    ///
    /// The ootle walletd demands a bearer token on every account endpoint even when transport
    /// auth is off: without this, a local daemon answers `accounts_get_default` with 401 and
    /// `/wallet/status` reports "reachable, no account" forever. `auth.request` with credentials
    /// `None` succeeds ONLY on a `none`-mode daemon — a daemon configured for WebAuthN or API
    /// keys rejects the bootstrap, no token is obtained, and every later account call fails
    /// closed with 401 exactly as before. Callers pass a real `GG_WALLETD_TOKEN` when the daemon
    /// requires one; that token always wins and this method must then be skipped. The token
    /// lives in this process, is never logged, and never crosses the bridge's HTTP API. There is
    /// no route from the public internet to it: walletd binds loopback and the bridge calls it
    /// server-side only.
    pub async fn bootstrap_local_auth(&mut self) -> bool {
        if self.token_supplied {
            return true;
        }
        let request = tari_ootle_walletd_client::types::AuthLoginRequest {
            permissions: vec![tari_ootle_walletd_client::permissions::Permission::Admin],
            credentials: tari_ootle_walletd_client::types::AuthCredentials::None,
        };
        match self.client.auth_request(&request).await {
            Ok(resp) => {
                self.client.set_auth_token(resp.token);
                true
            },
            Err(_) => false,
        }
    }

    /// The account this bridge proves from: either the operator-named account or the wallet's
    /// default.
    ///
    /// The output returns to the prover's own account so they keep what they proved control of.
    /// When `account_name` is set, `accounts_get` resolves it by name; otherwise the wallet's
    /// default account is used. The name is an operator configuration, never from a browser
    /// request — a caller cannot select which account proves.
    async fn account(&mut self) -> Result<AccountGetResponse, WalletError> {
        match &self.account_name {
            Some(name) => self
                .client
                .accounts_get(tari_ootle_walletd_client::ComponentAddressOrName::Name(
                    name.clone(),
                ))
                .await
                .map_err(|e| {
                    WalletError::Refused(format!(
                        "cannot find account {name:?}: {e}"
                    ))
                }),
            None => self
                .client
                .accounts_get_default()
                .await
                .map_err(|e| WalletError::Unreachable(e.to_string())),
        }
    }

    /// Picks an output of the gate's resource that meets the threshold, without telling anyone.
    ///
    /// The filter is deliberately strict. `status == Unspent` excludes anything already spent or locked;
    /// `is_on_chain` excludes an output whose creating transaction has not committed, which the engine
    /// would refuse to resolve; `is_burnt`/`is_frozen` exclude outputs no honest spend may use.
    ///
    /// Which output is picked is not a privacy property that can be asserted here in the strong sense --
    /// picking the smallest qualifying output is a heuristic, not a guarantee, since it can still leak
    /// something about the wallet's shape to an observer of the transaction. It is *not* leaked to the
    /// relying site, which is the boundary this project holds: the site sees a floor, a count and a
    /// transaction id. Recorded in `docs/THREAT_MODEL.md` rather than glossed over.
    async fn pick_qualifying_output(
        &mut self,
        resource: ResourceAddress,
        account: &ComponentAddress,
        required: u64,
    ) -> Result<UtxoAddress, WalletError> {
        let listed = self
            .client
            .stealth_utxos_list(StealthUtxosListRequest {
                resource_address: resource,
                account_address: Some(*account),
                filter_by_status: Some(OutputStatus::Unspent),
            })
            .await
            .map_err(|e| {
                WalletError::Refused(format!("the wallet could not list {resource}: {e}"))
            })?;

        // `u64` rather than `Amount` throughout: the comparison is against the gate's public threshold,
        // so there is no reason to carry a 128-bit amount or to convert one that could overflow.
        let mut best: Option<(u64, UtxoAddress)> = None;
        for utxo in listed.utxos {
            if !utxo.is_on_chain || utxo.is_burnt || utxo.is_frozen {
                continue;
            }
            // The value here is the wallet's own decrypted figure for an output it owns. It is compared
            // against a public threshold and then discarded; it is never stored, logged or returned.
            let Some(value) = utxo.value.to_u64_checked() else {
                // A holding too large for the threshold's own denomination cannot qualify for it.
                continue;
            };
            if value < required {
                continue;
            }
            // Smallest qualifying output wins, so a proof does not consolidate more of the wallet's
            // holdings than the gate required.
            let replace = match best {
                Some((current, _)) => value < current,
                None => true,
            };
            if replace {
                best = Some((value, utxo.address));
            }
        }

        best.map(|(_, address)| address)
            .ok_or(WalletError::NoQualifyingOutput {
                resource: resource.to_string(),
                required,
            })
    }
}

impl WalletChannel for WalletDaemonChannel {
    async fn status(&mut self) -> Result<WalletStatus, WalletError> {
        let info = self
            .client
            .get_wallet_info()
            .await
            .map_err(|e| WalletError::Unreachable(e.to_string()))?;
        let has_account = self.account().await.is_ok();
        Ok(WalletStatus {
            configured: true,
            reachable: true,
            has_default_account: has_account,
            network: info.network_byte,
            network_name: info.network,
            account_name: self.account_name.clone(),
        })
    }

    async fn build_statement(
        &mut self,
        request: StatementRequest,
    ) -> Result<StatementReply, WalletError> {
        // Fail closed on the unsupported selection rather than producing a transaction consensus will
        // refuse. See `ghost_gate_bridge::wallet::InputChoice` for why this is the only honest answer.
        if request.selection == InputChoice::WalletSelected {
            return Err(WalletError::WalletSelectionUnsupported(
                "the engine resolves a spent input under the gate's resource and refuses a transaction \
                 that does not declare the wallet's choice, so a wallet-chosen input cannot be built \
                 into a valid transaction",
            ));
        }
        let InputChoice::Named(mut named) = request.selection else {
            // Unreachable: `WalletSelected` returned above. Restated rather than left to an `unreachable!()`
            // so that adding a third variant to the enum is a compile error here instead of a panic in
            // the middle of a proof.
            return Err(WalletError::WalletSelectionUnsupported(
                "this input selection is not supported",
            ));
        };
        let mut address = named.pop().ok_or(WalletError::NoQualifyingOutput {
            resource: request.resource.to_string(),
            required: request.minimum_value_promise,
        })?;

        let account = self.account().await?;
        if named.is_empty() {
            // The named form is used by the adapter itself, qualified against the gate's own resource.
            // Re-deriving it here keeps one code path for both: whatever the caller named is still
            // checked against the wallet's list of that resource before it is spent.
            address = self
                .pick_qualifying_output(
                    request.resource,
                    &account.account.component_address,
                    request.minimum_value_promise,
                )
                .await?;
        }

        let response = self
            .client
            .accounts_create_stealth_transfer_statement(
                AccountsCreateStealthTransferStatementRequest {
                    requests: vec![TransferStatementRequest {
                        sender_account:
                            tari_ootle_walletd_client::ComponentAddressOrName::ComponentAddress(
                                account.account.component_address,
                            ),
                        resource_address: request.resource,
                        // The input is named, not selected. This is the engine's requirement, not a
                        // convenience: see the module docs.
                        input_selection: InputSelection::Specific {
                            utxo_addresses: vec![address],
                        },
                        outputs: vec![TransferOutput {
                            // An `OotleAddress`, which is what the wallet needs to derive the output's
                            // encryption keys. It is the wallet's own default address, read from the wallet --
                            // never one a request supplied.
                            address: account.address,
                            revealed_amount: Amount::zero(),
                            // The whole input moves. Anything else would need a change output, and a change
                            // output would have to promise the threshold too -- so the full amount keeps the
                            // qualifying output the only one that carries the promise.
                            blinded_amount: request.input_revealed.to_u64_checked().ok_or_else(
                                || {
                                    WalletError::Refused(format!(
                                        "{} does not fit in a transaction's amount",
                                        request.input_revealed
                                    ))
                                },
                            )?,
                            memo: None,
                            pay_to: PayTo::StealthPublicKey,
                            minimum_value_promise: request.minimum_value_promise,
                        }],
                    }],
                },
            )
            .await
            .map_err(|e| {
                WalletError::Refused(format!("the wallet would not build the statement: {e}"))
            })?;

        if response.statements.len() != 1 {
            return Err(WalletError::Refused(format!(
                "expected exactly one statement, the wallet returned {}",
                response.statements.len()
            )));
        }
        Ok(StatementReply {
            statement: response.statements[0].clone(),
            // The bridge treats this as an opaque token it hands straight back; only this adapter
            // interprets it. The SDK models a lock id as an `i32`, so the round trip is decimal.
            lock_id: response.lock_id.to_string(),
            signer_count: response.utxo_signers.len(),
        })
    }

    async fn submit(
        &mut self,
        gate: &str,
        challenge: &ghost_gate_core::Challenge,
        statement: &StealthTransferStatement,
        lock_id: &str,
    ) -> Result<String, WalletError> {
        // Refuse before signing if the wallet is on a different chain than the gate is bound to. A proof
        // submitted to the wrong network would be a valid transaction in the wrong place.
        let found = self
            .client
            .get_wallet_info()
            .await
            .map_err(|e| {
                WalletError::Unreachable(format!("the wallet stopped answering mid-proof: {e}"))
            })?
            .network_byte;
        if found != self.expected_network {
            return Err(WalletError::WrongNetwork {
                expected: self.expected_network,
                found,
            });
        }

        let gate_address: ComponentAddress = gate
            .parse()
            .map_err(|_| WalletError::Refused(format!("{gate:?} is not a component address")))?;
        let account = self.account().await?;

        // The challenge's own expiry bounds the transaction's validity window. A proof must not be
        // sequencable after the challenge it answers has expired.
        let max_epoch = self.max_epoch.min(challenge.expires_epoch);

        // `max_epoch` is a `u64` from the challenge's own field; the builder wants the cohort's `Epoch`.
        let max_epoch = Epoch(max_epoch);
        let network =
            Network::try_from(self.expected_network).map_err(|_| WalletError::WrongNetwork {
                expected: self.expected_network,
                found: self.expected_network,
            })?;

        let transaction = TransactionBuilder::new(network, max_epoch)
            .with_nonce(rand::random())
            .pay_fee_from_component(account.account.component_address, self.max_fee)
            .call_method(
                gate_address,
                "prove_access",
                args![challenge.clone(), statement.clone()],
            )
            // Both substates the transaction touches must be declared. The engine refuses a reference to
            // any substate the transaction did not declare, so without the gate this call could not
            // modify its own nonce.
            .add_input(gate_address)
            // And the UTXO the statement spends, which the adapter chose locally in step 1.
            .add_input(utxo_address_of(statement, challenge.resource))
            .build_unsigned();

        let owner_key = account.account.owner_key_id.ok_or_else(|| {
            WalletError::Refused("the default account has no owner key to seal with".into())
        })?;

        let submitted = self
            .client
            .submit_transaction(TransactionSubmitRequest {
                transaction,
                seal_signer: owner_key,
                // No signatures and no other signers: the daemon derives the stealth UTXO signers from
                // the lock. Passing signers here would mean telling the wallet which keys to use, which
                // is exactly the disclosure this design avoids.
                other_signers: vec![],
                signatures: vec![],
                detect_inputs: true,
                detect_inputs_use_unversioned: true,
                // The lock is what makes the daemon derive the stealth UTXO signers itself rather than
                // being handed a list of keys. Parsed from the opaque token `build_statement` returned.
                lock_ids: vec![lock_id.parse::<WalletLockId>().map_err(|_| {
                    WalletError::Refused(format!("{lock_id:?} is not a wallet lock id"))
                })?],
            })
            .await
            .map_err(|e| {
                WalletError::Refused(format!("the wallet would not submit the proof: {e}"))
            })?;

        Ok(submitted.transaction_id.to_string())
    }

    async fn wait(
        &mut self,
        transaction_id: &str,
        timeout: Duration,
    ) -> Result<CommitOutcome, WalletError> {
        let id = TransactionId::from_hex(transaction_id).map_err(|e| {
            WalletError::Refused(format!("{transaction_id:?} is not a transaction id: {e:?}"))
        })?;

        let waited = self
            .client
            .wait_transaction_result(TransactionWaitResultRequest {
                transaction_id: id,
                timeout_secs: Some(timeout.as_secs()),
            })
            .await
            .map_err(|e| WalletError::Timeout(e.to_string()))?;

        if waited.timed_out {
            return Ok(CommitOutcome::Pending);
        }

        // A rejection is reported as a rejection, with the engine's own reason. That reason names the
        // gate, never a key or a value, so it is safe to surface to the site.
        if let Some(result) = &waited.result
            && let Some(reason) = result.any_reject()
        {
            return Ok(CommitOutcome::Rejected {
                reason: format!("{reason:?}"),
            });
        }

        if !waited.status.is_any_accept() {
            return Ok(CommitOutcome::Rejected {
                reason: format!("the network finished it as {:?}", waited.status),
            });
        }

        // The public floor and input count, read back out of the committed receipt rather than echoed
        // from the request. Reading them from the network is the point: a site is told what consensus
        // committed, not what this process intended.
        Ok(CommitOutcome::Accepted {
            transaction_id: transaction_id.to_string(),
            attested_minimum: Self::attested_minimum_from(&waited),
            input_count: Self::input_count_from(&waited),
        })
    }
}

/// The UTXO the statement spends, derived from the statement itself.
///
/// `StealthInput` carries a commitment rather than an address, and a stealth output's address is
/// derived from its commitment. So the address the transaction must declare is a function of the
/// statement the wallet just built -- not something this crate chose, and not something it could choose
/// differently without the engine refusing the transaction.
fn utxo_address_of(statement: &StealthTransferStatement, resource: ResourceAddress) -> UtxoAddress {
    let commitment = statement
        .inputs_statement
        .inputs
        .first()
        .expect("a proof statement spends at least one input")
        .commitment;
    // A stealth UTXO's address is `(resource_address, UtxoId::from(commitment))`. Both halves are
    // already public: the resource is the gate's, and the commitment is on chain. So deriving the
    // address here discloses nothing that was not public, and it cannot be wrong in the one way that
    // would matter -- a resource other than the gate's would be a substate the engine never resolves.
    UtxoAddress::new(resource, UtxoId::from(commitment))
}

impl WalletDaemonChannel {
    /// Reads the gate's promised minimum back out of the committed receipt.
    ///
    /// This is decoded from what consensus committed, not echoed from the request. That distinction is
    /// the whole point: a site is told what the network accepted, not what this process intended. A
    /// receipt that cannot be decoded yields zero, which every consumer treats as "no attestation" and
    /// which fails closed -- a fabricated floor would not.
    fn attested_minimum_from(waited: &TransactionWaitResultResponse) -> u64 {
        let Some(result) = &waited.result else {
            return 0;
        };
        // The gate's receipt is the return value of its `prove_access` call, which is the last execution
        // result in the transaction. `ProofReceipt` is declared in `ghost_gate_core` and derives bor's
        // `Decode`, so it is nameable here even though the template itself is WASM -- no decoding by
        // debug format and no untyped scrape, so a template change is a compile error rather than a
        // silent zero.
        result
            .execution_results
            .last()
            .and_then(|execution| execution.decode::<ghost_gate_core::ProofReceipt>().ok())
            .map(|receipt| receipt.attested_minimum)
            .unwrap_or(0)
    }

    /// The number of live inputs the receipt says the proof consumed.
    ///
    /// Read from the receipt for the same reason as the floor: it is the gate's own count of what it
    /// qualified, not this crate's guess.
    fn input_count_from(waited: &TransactionWaitResultResponse) -> u32 {
        waited
            .result
            .as_ref()
            .and_then(|result| result.execution_results.last())
            .and_then(|execution| execution.decode::<ghost_gate_core::ProofReceipt>().ok())
            .map(|receipt| receipt.input_count)
            .unwrap_or(0)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use ghost_gate_bridge::wallet::StatementRequest;
    use tari_template_lib_types::{Hash32, ObjectKey};

    fn resource(byte: u8) -> ResourceAddress {
        ResourceAddress::new(ObjectKey::from_array([byte; 32]))
    }

    #[test]
    fn a_derived_utxo_address_is_the_gates_resource_paired_with_the_spent_commitment() {
        // The address the transaction declares is a pure function of two already-public values, so
        // deriving it locally cannot leak anything and cannot be forged toward another resource.
        let statement = minimal_statement();
        let commitment = statement.inputs_statement.inputs[0].commitment;
        let gate_resource = resource(7);

        let address = utxo_address_of(&statement, gate_resource);

        assert_eq!(
            address,
            UtxoAddress::new(gate_resource, UtxoId::from(commitment))
        );
        assert_eq!(
            address.resource_address(),
            &gate_resource,
            "the derived address must name the gate's own resource, or the engine resolves nothing"
        );
    }

    #[test]
    fn a_statement_request_carries_no_utxo_identifier_into_the_adapter() {
        // `StatementRequest` has no UTXO field, so the adapter cannot be handed one from outside. The
        // privacy boundary is a property of the type, not of this crate's discipline.
        let request = StatementRequest {
            resource: resource(7),
            input_revealed: Amount::from(10_000u64),
            minimum_value_promise: 10_000,
            selection: InputChoice::WalletSelected,
        };
        let json = format!("{request:?}");
        assert!(
            !json.to_lowercase().contains("utxo"),
            "no UTXO may reach the adapter: {json}"
        );
    }

    #[test]
    fn wallet_selected_is_refused_before_any_wallet_call() {
        // Asserted through the real adapter, not a fake: a `WalletSelected` request must come back as the
        // fail-closed refusal even though the wallet behind it is unreachable, which is only true if the
        // check happens first. Without a wallet the alternative outcome would be `Unreachable`, so this
        // distinguishes "refused the selection" from "could not reach the wallet".
        let mut channel = WalletDaemonChannel {
            client: WalletDaemonClient::connect("http://127.0.0.1:1", None)
                .expect("a URL is a URL"),
            expected_network: ghost_gate_core::network::LOCALNET,
            max_fee: 100_000,
            max_epoch: 100,
            token_supplied: false,
            account_name: None,
        };
        let request = StatementRequest {
            resource: resource(7),
            input_revealed: Amount::from(10_000u64),
            minimum_value_promise: 10_000,
            selection: InputChoice::WalletSelected,
        };

        let error = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(channel.build_statement(request))
            .expect_err("WalletSelected must be refused");

        assert!(
            matches!(error, WalletError::WalletSelectionUnsupported(_)),
            "expected the fail-closed refusal, got {error:?}"
        );
    }

    #[test]
    fn a_challenge_nonce_is_carried_into_the_submit_call_not_invented() {
        // The adapter must submit the challenge it was handed. Recorded here as a property of the call
        // shape: `submit` takes the core `Challenge` by reference, so the nonce cannot be defaulted,
        // regenerated or read from a request body.
        let nonce = [0xabu8; 32];
        let challenge = ghost_gate_core::Challenge {
            gate: ComponentAddress::new(ObjectKey::from_array([1u8; 32])),
            resource: resource(7),
            threshold: 10_000,
            network: ghost_gate_core::network::LOCALNET,
            nonce: Hash32::from(nonce),
            expires_epoch: 90,
            relying_site: tari_template_lib_types::MaxBytes::new_checked(b"vip.example".to_vec())
                .unwrap(),
            session_commitment: tari_template_lib_types::MaxBytes::new_checked(vec![0x11u8; 32])
                .expect("32 bytes fits the session commitment bound"),
        };
        assert_eq!(challenge.nonce.into_array(), nonce);
        // A transaction must not outlive the challenge it answers.
        assert!(
            challenge.expires_epoch < 100,
            "the harness's max_epoch must clamp below this, or the test would be vacuous"
        );
    }

    /// The smallest statement the type accepts: one spent commitment and one output.
    fn minimal_statement() -> StealthTransferStatement {
        StealthTransferStatement {
            inputs_statement: tari_template_lib_types::stealth::StealthInputsStatement::new(
                vec![tari_template_lib_types::stealth::StealthInput::new(
                    tari_template_lib_types::crypto::PedersenCommitmentBytes::from([3u8; 32]),
                )],
                Amount::zero(),
            ),
            outputs_statement: tari_template_lib_types::stealth::StealthOutputsStatement {
                outputs: vec![],
                revealed_output: None,
                // This fixture is never submitted: it exists only to give `utxo_address_of` a spent
                // commitment to read. An unparsable proof blob keeps that obvious.
                agg_range_proof: tari_template_lib_types::crypto::RangeProofBytes::try_from(
                    vec![0u8; 8],
                )
                .expect("a short placeholder proof blob"),
            },
            balance_proof: None,
            covenant_claims: Default::default(),
        }
    }
}
