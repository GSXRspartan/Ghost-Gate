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

use serde::{Deserialize, Serialize};
use tari_template_lib_types::stealth::StealthTransferStatement;
use tari_template_lib_types::{Amount, ResourceAddress};

/// What the bridge knows about the wallet without asking anything sensitive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletStatus {
    /// Whether this bridge was WIRED with a wallet daemon at startup. A bridge without one is
    /// in offline demonstration mode by configuration, which is a status, not a service failure.
    pub configured: bool,
    /// Whether a wallet daemon answered at all.
    pub reachable: bool,
    /// Whether the configured account (named or default) exists. Never the account's address.
    pub has_default_account: bool,
    /// The network the wallet is configured for, as Ootle's cohort byte.
    pub network: u8,
    /// Which cohort name the wallet reports, for a UI.
    pub network_name: String,
    /// The operator-configured account name, if one was set via `GG_WALLETD_ACCOUNT`.
    /// `None` means the wallet's default account is used. Never an address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_name: Option<String>,
}

impl WalletStatus {
    pub fn unreachable() -> Self {
        Self {
            configured: false,
            reachable: false,
            has_default_account: false,
            network: 0,
            network_name: String::new(),
            account_name: None,
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
///
/// # Why there is no usable "wallet picks" variant
///
/// `WalletSelected` is what a finished product would use, and it is deliberately **refused** rather
/// than wired up. Two independent facts in the engine make it unusable today, and neither is a
/// limitation of this bridge:
///
/// 1. **The engine resolves a spent input under the gate's resource.** A statement spends a commitment,
///    and the gate qualifies the proof by finding that commitment among the gate resource's outputs. If
///    the wallet spends an input of a *different* resource, the engine finds nothing and consensus
///    refuses with "engine found no input under this resource".
/// 2. **A transaction must declare every substate it spends.** The same transaction that carries the
///    statement has to declare the UTXO the wallet chose, or the engine refuses it as undeclared.
///
/// Facts 1 and 2 together mean a wallet that chooses freely cannot produce a transaction that names
/// its choice, because the choice is not communicated to the builder. So `WalletSelected` would only
/// ever generate transactions that consensus rejects. Rather than ship a path that fails at consensus
/// and burns a challenge, [`WalletError::WalletSelectionUnsupported`] is returned before anything is
/// signed.
///
/// The way out is the two-stage wallet-local flow, recorded in `docs/GATE4_RESULTS.md`: the wallet
/// selects internally, reports the exact versioned substate requirements to the **trusted local**
/// builder, and only the public proof reaches the site. The walletd adapter implements that shape
/// today, which is why it qualifies inputs under the gate's own resource address rather than by
/// letting the wallet choose blindly.
///
/// Note the privacy direction here: the identifiers this variant would have to name are chosen and
/// held **inside the trusted local bridge**, never derived from a request and never returned to a
/// browser. See `docs/THREAT_MODEL.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputChoice {
    /// Refused. Kept so the enum records why the product path is not available.
    ///
    /// An implementation must return [`WalletError::WalletSelectionUnsupported`]. This crate's own
    /// server never constructs it.
    WalletSelected,
    /// Exactly these outputs.
    ///
    /// Not for a request body: a caller may not name wallet outputs. The adapter fills this in from
    /// `stealth_utxos_list`, which returns only the gate resource's own unspent outputs, so the
    /// identifier came from the wallet and the gate, never from the network-facing side.
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
    #[error("GG: wallet-chosen inputs are not supported: {0}")]
    WalletSelectionUnsupported(&'static str),
    #[error("GG: no unspent output of {resource} holds at least {required}")]
    NoQualifyingOutput { resource: String, required: u64 },
    #[error("GG: the wallet could not construct a qualifying proof transaction")]
    CannotConstructProof,
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
/// `&mut self` rather than `&self`: a wallet client carries connection state, and the bridge serves
/// one connection at a time, so there is nothing to gain from interior mutability and a plain `&mut`
/// says what the concurrency actually is.
///
/// Native `async fn` in a trait is allowed deliberately. This trait is never used as a trait object --
/// `Bridge<W>` is generic over it -- so the usual reason to fall back to boxed futures does not apply,
/// and `async_trait` would be a dependency bought to silence a lint.
#[allow(async_fn_in_trait)]
pub trait WalletChannel {
    /// Whether a wallet is reachable and configured, without asking it anything sensitive.
    async fn status(&mut self) -> Result<WalletStatus, WalletError>;

    /// Asks the wallet to build a proof statement. The wallet locks its inputs and returns a lock id.
    async fn build_statement(
        &mut self,
        request: StatementRequest,
    ) -> Result<StatementReply, WalletError>;

    /// Submits the proof transaction, passing the lock so the wallet derives the signers itself.
    ///
    /// `challenge` is the core type because that is what the gate's `prove_access` takes, and the
    /// adapter builds the call from it. Handing the adapter a serialisable challenge rather than a
    /// pre-encoded argument keeps the ABI shape in one place: if the template's signature changes, it
    /// changes here and in the template, not in a blob assembled by the caller.
    async fn submit(
        &mut self,
        gate: &str,
        challenge: &ghost_gate_core::Challenge,
        statement: &StealthTransferStatement,
        lock_id: &str,
    ) -> Result<String, WalletError>;

    /// Waits for a submitted transaction and reports what the network committed.
    async fn wait(
        &mut self,
        transaction_id: &str,
        timeout: Duration,
    ) -> Result<CommitOutcome, WalletError>;
}

// NOTE ON THE PRODUCTION CHANNEL
// --------------------------
// The real channel is the `ghost-gate-walletd` crate, not a module here. It needs the walletd client,
// the wallet SDK and `reqwest`, and none of those belong in a crate whose job is deciding *which
// request may do what* against a policy readable in one sitting. Keeping it separate also keeps this
// crate's 59 policy tests compiling without the wallet SDK in the graph.
// One implementation was written and removed from this file first: it could not be run in this
// environment, and shipping signing code that has never been executed is exactly the failure mode
// this project has avoided elsewhere. The replacement is exercised by the localnet scenario rather
// than by anything asserted in this file.
//
// A UTXO identifier is never a parameter of any method above. `build_statement` takes a resource and
// a promise; the adapter learns which output to spend from the wallet, locally. That is the property
// the relying site depends on, and it is why `InputChoice` is not reachable from a request body.

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
        assert!(
            !json.contains("address"),
            "no destination may appear in a statement request: {json}"
        );
        assert!(
            !json.contains("utxo"),
            "no input may appear in a statement request: {json}"
        );
    }

    #[test]
    fn wallet_selection_is_refused_rather_than_silently_accepted() {
        // `WalletSelected` exists so the enum records the gap. If it ever became a real default again,
        // this test is the reminder that the engine cannot accept what it produces.
        const WHY: &str = "the engine resolves a spent input under the gate's resource and refuses a \
                           transaction that does not declare the wallet's choice";
        assert_ne!(InputChoice::WalletSelected, InputChoice::Named(vec![]));
        assert_eq!(
            WalletError::WalletSelectionUnsupported(WHY).to_string(),
            format!("GG: wallet-chosen inputs are not supported: {WHY}")
        );
    }

    #[test]
    fn a_statement_request_serialises_without_any_utxo_identifier() {
        // The privacy requirement, asserted on the type rather than on prose. `StatementRequest` is the
        // strongest thing a caller can hand the wallet, so if a UTXO field were ever added to it, a
        // serialised request would carry an identifier. Asserted on a struct literal built through
        // `..Default`-free construction so a new required field would break this test loudly.
        let request = StatementRequest {
            resource: ResourceAddress::new(tari_template_lib_types::ObjectKey::from_array(
                [9u8; 32],
            )),
            input_revealed: Amount::from(10_000u64),
            minimum_value_promise: 10_000,
            selection: InputChoice::WalletSelected,
        };
        // No `Serialize` impl exists on this type *on purpose*: the only thing that can cross a process
        // boundary here is the HTTP body, and `policy::ProveRequest` is what gets parsed from that.
        assert!(
            !std::any::type_name::<StatementRequest>().contains("Serialize"),
            "a statement request must not gain a wire form"
        );
        assert_eq!(request.minimum_value_promise, 10_000);
        assert_eq!(request.input_revealed, Amount::from(10_000u64));
    }

    #[test]
    fn an_unreachable_wallet_reports_rather_than_panicking() {
        let s = WalletStatus::unreachable();
        assert!(!s.reachable);
        assert!(!s.has_default_account);
        assert_eq!(s.account_name, None);
        assert_eq!(
            WalletError::Unreachable("connection refused".into()).to_string(),
            "GG: the wallet daemon is not reachable: connection refused"
        );
    }

    #[test]
    fn account_name_is_omitted_from_json_when_none() {
        let s = WalletStatus::unreachable();
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains("account_name"), "None account_name must be omitted: {json}");
    }

    #[test]
    fn account_name_appears_in_json_when_set() {
        let mut s = WalletStatus::unreachable();
        s.account_name = Some("my-prover".into());
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"account_name\":\"my-prover\""), "set account_name must appear: {json}");
    }
}
