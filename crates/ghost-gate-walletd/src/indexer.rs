//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! Chain reads for the bridge's credential proof mode.
//!
//! The relying site must fetch the proof output itself. A page-supplied substate could claim any
//! floor and any key, so `IndexerChainReader` is the only production path between the verifier and
//! chain state: it wraps the cohort's indexer REST client and reduces each UTXO to the three
//! public facts verification needs — the floor, the spend-authorisation key, and the knowledge
//! that the output still exists unspent.
//!
//! What is deliberately not here: any balance read, any wallet-scoped query, any view-key use. The
//! indexer answers public questions about public substates; a verifier that asked for more than
//! [`UtxoOnChain`] carries would be a verifier holding data it does not need.

use ghost_gate_bridge::credential::{ChainReader, UtxoOnChain};
use tari_engine_types::substate::SubstateValue;
use tari_indexer_client::rest_api_client::IndexerRestApiClient;
use tari_template_lib_types::UtxoAddress;

/// Reads UTXOs from an indexer over REST.
pub struct IndexerChainReader {
    client: IndexerRestApiClient,
}

impl IndexerChainReader {
    pub fn connect(
        endpoint: &str,
    ) -> Result<Self, ghost_gate_bridge::credential::CredentialRefusal> {
        let client = IndexerRestApiClient::connect(endpoint).map_err(|e| {
            ghost_gate_bridge::credential::CredentialRefusal::Chain(format!(
                "cannot build an indexer client for {endpoint}: {e}"
            ))
        })?;
        Ok(Self { client })
    }
}

impl ChainReader for IndexerChainReader {
    /// The indexer's semantics do the unspent check: a spent UTXO is answered with
    /// `InputSubstateIsDown`, which surfaces as the `Err` the verifier treats as "no longer
    /// unspent". A successful lookup is by definition the current, still-UP record.
    async fn utxo(&self, address: &UtxoAddress) -> Result<UtxoOnChain, String> {
        let response = self
            .client
            .get_substate(
                &tari_engine_types::substate::SubstateId::Utxo(address.clone()),
                tari_indexer_client::types::GetSubstateRequest {
                    version: None,
                    local_search_only: false,
                    include_proof: false,
                },
            )
            .await
            .map_err(|e| format!("{e}"))?;

        let verified = response.verified;
        let encoded = response
            .into_substate_value()
            .ok_or_else(|| format!("{} is no longer an unspent substate", address))?;
        let substate = encoded
            .decode()
            .map_err(|e| format!("{} returned invalid CBOR: {e}", address))?;
        let SubstateValue::Utxo(utxo) = &substate else {
            return Err(format!("{} is not a UTXO substate", address));
        };
        let Some(output) = &utxo.output else {
            return Err(format!("{} has no output body", address));
        };
        Ok(UtxoOnChain {
            minimum_value_promise: output.output.minimum_value_promise,
            // The indexer's own merkle-verification statement, carried through untouched. A
            // `false` here refuses at the verifier, by design.
            verified,
            auth_key: output.auth.spend_key().map(|k| {
                let mut out = [0u8; 32];
                out.copy_from_slice(k.as_bytes());
                out
            }),
        })
    }
}
