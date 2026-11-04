//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! Proven chain reads for the bridge's credential proof mode.
//!
//! Ootle 0.49 serves [`GetSubstateResponse`] as a JSON envelope whose committed value is
//! base64-encoded CBOR at `state.up.substate`. The envelope's `proof` binds that exact CBOR value,
//! substate id and version to the anchor's state root. This reader uses the upstream response type
//! and proof verifier; it never treats an HTTP 200 or the indexer's `verified` boolean alone as a
//! sufficient credential.

use ghost_gate_bridge::credential::{ChainReadError, ChainReader, UtxoOnChain};
use ootle_network::Network;
use tari_engine_types::substate::{SubstateId, SubstateValue};
use tari_indexer_client::{
    error::IndexerRestClientError,
    rest_api_client::IndexerRestApiClient,
    types::{GetSubstateRequest, GetSubstateResponse, SubstateState},
};
use tari_ootle_common_types::{Epoch, NumPreshards};
use tari_ootle_storage::{
    TrustedStateRoot, consensus_models::CommittedBlockProof,
    verify_substate_value_proof_against_root,
};
use tari_template_lib_types::UtxoAddress;

/// Reads and verifies UTXOs from an indexer over REST.
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
    async fn utxo(
        &self,
        network_byte: u8,
        address: &UtxoAddress,
    ) -> Result<UtxoOnChain, ChainReadError> {
        let network = Network::try_from(network_byte).map_err(|e| {
            ChainReadError::InvalidProof(format!(
                "gate network byte {network_byte} is not an Ootle network: {e}"
            ))
        })?;
        let substate_id = SubstateId::Utxo(address.clone());
        let response = self
            .client
            .get_substate(
                &substate_id,
                GetSubstateRequest {
                    version: None,
                    local_search_only: false,
                    // Required: the bridge validates the current committed value proof below.
                    include_proof: true,
                },
            )
            .await
            .map_err(|error| classify_client_error(address, error))?;

        // Read the same indexer's current network identity after the proof. A transition that races
        // these calls can only refuse: a stale or future anchor is never accepted for authorization.
        let network_info = self
            .client
            .get_network_info()
            .await
            .map_err(|error| classify_client_error(address, error))?;
        if network_info.network_byte != network_byte || network_info.network != network {
            return Err(ChainReadError::InvalidProof(format!(
                "{address}: indexer network is {} ({:#04x}), gate requires {} ({network_byte:#04x})",
                network_info.network, network_info.network_byte, network
            )));
        }

        decode_proven_utxo(
            network,
            network_info.epoch,
            NumPreshards::current(),
            address,
            response,
        )
    }
}

fn classify_client_error(address: &UtxoAddress, error: IndexerRestClientError) -> ChainReadError {
    match error {
        IndexerRestClientError::ErrorResponse { ref source, .. }
            if source.status() == Some(reqwest::StatusCode::NOT_FOUND) =>
        {
            ChainReadError::SpentOrUnknown(format!("{address} is absent or no longer unspent"))
        }
        IndexerRestClientError::DeserializeResponse { .. }
        | IndexerRestClientError::InvalidResponse { .. }
        | IndexerRestClientError::ResponseTooLarge { .. } => {
            ChainReadError::UnsupportedResponse(format!("{address}: {error}"))
        }
        _ => ChainReadError::Transport(format!("{address}: {error}")),
    }
}

/// Reduces the exact upstream 0.49 response type to the facts credential verification needs.
///
/// The indexer's `verified` flag remains a required committee-verification assertion. In addition,
/// Ghost Gate independently checks that the commit-proof header matches the public anchor and that
/// the value proof includes this exact `(UTXO id, version, decoded CBOR value)` under that root.
fn decode_proven_utxo(
    network: Network,
    current_epoch: Epoch,
    num_preshards: NumPreshards,
    address: &UtxoAddress,
    response: GetSubstateResponse,
) -> Result<UtxoOnChain, ChainReadError> {
    let GetSubstateResponse {
        version,
        state,
        verified,
        proof,
    } = response;

    let encoded = match state {
        SubstateState::Up { substate } => substate,
        SubstateState::Down {} => {
            return Err(ChainReadError::SpentOrUnknown(format!(
                "{address} is DOWN on the indexer (spent or destroyed)"
            )));
        }
    };
    let substate = encoded.decode().map_err(|error| {
        ChainReadError::UnsupportedResponse(format!(
            "{address}: state.up.substate is not valid base64-CBOR SubstateValue: {error}"
        ))
    })?;

    // A false assertion is handled by CredentialVerifier as UnverifiedChainData. A true assertion
    // without the proof it asserts is malformed and must not reach that branch.
    if verified {
        let proof = proof.as_ref().ok_or_else(|| {
            ChainReadError::InvalidProof(format!(
                "{address}: verified response omitted its substate proof"
            ))
        })?;
        verify_proof_envelope(
            network,
            current_epoch,
            num_preshards,
            address,
            version,
            &substate,
            proof,
        )?;
    }

    let SubstateValue::Utxo(utxo) = &substate else {
        return Err(ChainReadError::UnsupportedResponse(format!(
            "{address}: committed value is not a UTXO substate"
        )));
    };
    let Some(output) = &utxo.output else {
        return Err(ChainReadError::SpentOrUnknown(format!(
            "{address} has no live output body"
        )));
    };
    Ok(UtxoOnChain {
        minimum_value_promise: output.output.minimum_value_promise,
        verified,
        auth_key: output.auth.spend_key().map(|key| {
            let mut out = [0u8; 32];
            out.copy_from_slice(key.as_bytes());
            out
        }),
    })
}

fn verify_proof_envelope(
    network: Network,
    current_epoch: Epoch,
    num_preshards: NumPreshards,
    address: &UtxoAddress,
    version: tari_engine_types::SubstateVersion,
    value: &SubstateValue,
    proof: &tari_indexer_client::types::SubstateProof,
) -> Result<(), ChainReadError> {
    let committed = CommittedBlockProof::from_bytes(&proof.commit_proof).map_err(|error| {
        ChainReadError::InvalidProof(format!("{address}: invalid commit proof: {error}"))
    })?;
    let anchor = &proof.anchor;
    let header_network = committed.proof().header.network;
    let anchor_matches_header = committed.epoch() == anchor.epoch
        && committed.height().as_u64() == anchor.height
        && committed.shard_group().ok() == Some(anchor.shard_group)
        && committed.block_id().as_slice() == anchor.block_id.as_slice()
        && committed.state_merkle_root().as_slice() == anchor.state_merkle_root.as_slice();
    if header_network != network.as_byte() || !anchor_matches_header {
        return Err(ChainReadError::InvalidProof(format!(
            "{address}: proof anchor does not match its commit-proof header or network"
        )));
    }
    if anchor.epoch != current_epoch {
        return Err(ChainReadError::InvalidProof(format!(
            "{address}: proof anchor epoch {} is not the indexer's current epoch {}",
            anchor.epoch, current_epoch
        )));
    }

    let trusted_root = TrustedStateRoot {
        epoch: anchor.epoch,
        shard_group: anchor.shard_group,
        root: committed.state_merkle_root(),
    };
    verify_substate_value_proof_against_root(
        &proof.value_proof,
        &SubstateId::Utxo(address.clone()),
        version,
        Some(value),
        network,
        num_preshards,
        proof.value_hash_epoch,
        &trusted_root,
    )
    .map_err(|error| {
        ChainReadError::InvalidProof(format!(
            "{address}: committed value proof does not verify: {error}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    use ghost_gate_bridge::credential::{
        ChainReader, CredentialProofRequest, CredentialRefusal, CredentialVerifier, OwnershipProof,
    };
    use tari_engine_types::{
        Utxo, UtxoOutput, crypto::OutputBody, encoded::Encoded, substate::SubstateValue,
    };
    use tari_indexer_client::types::{GetSubstateResponse, SubstateProofAnchor, SubstateState};
    use tari_ootle_light_client::test_fixtures::{
        NETWORK, NUM_PRESHARDS, ValidatorSetFixture, substate_proof,
    };
    use tari_template_lib_types::{
        EncryptedData, ResourceAddress,
        crypto::{RistrettoPublicKeyBytes, UtxoTag},
        stealth::SpendAuthorization,
    };

    const FLOOR: u64 = 100_000_000;

    fn address(resource_byte: u8, id_byte: u8) -> UtxoAddress {
        UtxoAddress::from_str(&format!(
            "utxo_{}_{}",
            hex::encode([resource_byte; 32]),
            hex::encode([id_byte; 32])
        ))
        .unwrap()
    }

    fn value(floor: u64) -> SubstateValue {
        SubstateValue::Utxo(Utxo::new(UtxoOutput {
            output: OutputBody {
                public_nonce: RistrettoPublicKeyBytes::zero(),
                encrypted_data: EncryptedData::try_from(vec![0; EncryptedData::min_size()])
                    .unwrap(),
                minimum_value_promise: floor,
                viewable_balance: None,
            },
            auth: SpendAuthorization::Key(RistrettoPublicKeyBytes::zero()),
            tag: UtxoTag::new(0),
        }))
    }

    fn response(address: &UtxoAddress, floor: u64) -> GetSubstateResponse {
        let value = value(floor);
        let id = SubstateId::Utxo(address.clone());
        let set = ValidatorSetFixture::new(41);
        let mut proof = substate_proof(&set, &id, tari_engine_types::SubstateVersion::ZERO, &value);
        let committed = CommittedBlockProof::from_bytes(&proof.commit_proof).unwrap();
        proof.anchor = SubstateProofAnchor {
            epoch: committed.epoch(),
            shard_group: committed.shard_group().unwrap(),
            height: committed.height().as_u64(),
            block_id: committed.block_id().into_array().into(),
            state_merkle_root: committed.state_merkle_root().into_array().into(),
        };
        GetSubstateResponse {
            version: tari_engine_types::SubstateVersion::ZERO,
            state: SubstateState::Up {
                substate: Encoded::encode(&value).unwrap(),
            },
            verified: true,
            proof: Some(proof),
        }
    }

    fn decode(
        address: &UtxoAddress,
        response: GetSubstateResponse,
    ) -> Result<UtxoOnChain, ChainReadError> {
        // Serialize and deserialize through JSON so the test exercises the live base64-CBOR wire
        // shape, not merely the in-memory Rust structs.
        let wire = serde_json::to_vec(&response).unwrap();
        let served: GetSubstateResponse = serde_json::from_slice(&wire).unwrap();
        decode_proven_utxo(
            NETWORK,
            served.proof.as_ref().unwrap().anchor.epoch,
            NUM_PRESHARDS,
            address,
            served,
        )
    }

    #[test]
    fn live_0491_shape_decodes_base64_cbor_and_verifies_the_committed_utxo() {
        let address = address(1, 7);
        let decoded = decode(&address, response(&address, FLOOR)).unwrap();
        assert_eq!(decoded.minimum_value_promise, FLOOR);
        assert!(decoded.verified);
        assert_eq!(decoded.auth_key, Some([0; 32]));
    }

    struct ResponseReader {
        response: GetSubstateResponse,
    }

    impl ChainReader for ResponseReader {
        async fn utxo(
            &self,
            _network: u8,
            address: &UtxoAddress,
        ) -> Result<UtxoOnChain, ChainReadError> {
            decode(address, self.response.clone())
        }
    }

    #[tokio::test]
    async fn live_shape_below_threshold_is_refused_as_threshold_not_schema() {
        let address = address(1, 7);
        let resource =
            ResourceAddress::from_str(&format!("resource_{}", hex::encode([1; 32]))).unwrap();
        let reader = ResponseReader {
            response: response(&address, FLOOR - 1),
        };
        let verifier = CredentialVerifier {
            gate_id: "g",
            network: NETWORK.as_byte(),
            threshold: FLOOR,
            resource: &resource,
            challenge_string: "aa",
        };
        let request = CredentialProofRequest {
            gate_id: "g".into(),
            challenge_nonce: "aa".into(),
            session_commitment: "00".repeat(32),
            substate_id: address.to_string(),
            ownership: OwnershipProof {
                public_key: String::new(),
                public_nonce: "00".repeat(32),
                signature: "00".repeat(32),
            },
        };
        match verifier.verify(&reader, &request).await {
            Err(CredentialRefusal::BelowThreshold { attested, required }) => {
                assert_eq!(attested, FLOOR - 1);
                assert_eq!(required, FLOOR);
            }
            other => panic!("expected BelowThreshold, got {other:?}"),
        }
    }

    #[test]
    fn down_output_is_distinct_from_schema_failure() {
        let address = address(1, 7);
        let mut response = response(&address, FLOOR);
        response.state = SubstateState::Down {};
        assert!(matches!(
            decode(&address, response),
            Err(ChainReadError::SpentOrUnknown(_))
        ));
    }

    #[test]
    fn malformed_proof_envelope_fails_closed() {
        let legacy = serde_json::json!({
            "state": { "up": { "substate": { "Utxo": {} } } },
            "verified": true
        });
        assert!(serde_json::from_value::<GetSubstateResponse>(legacy).is_err());
    }

    #[test]
    fn altered_state_merkle_root_is_an_invalid_proof() {
        let address = address(1, 7);
        let mut response = response(&address, FLOOR);
        response.proof.as_mut().unwrap().anchor.state_merkle_root = [9; 32].into();
        assert!(matches!(
            decode(&address, response),
            Err(ChainReadError::InvalidProof(_))
        ));
    }

    #[test]
    fn altered_utxo_identity_is_an_invalid_proof() {
        let original = address(1, 7);
        let altered = address(1, 8);
        assert!(matches!(
            decode(&altered, response(&original, FLOOR)),
            Err(ChainReadError::InvalidProof(_))
        ));
    }

    #[test]
    fn altered_resource_is_an_invalid_proof() {
        let original = address(1, 7);
        let altered = address(2, 7);
        assert!(matches!(
            decode(&altered, response(&original, FLOOR)),
            Err(ChainReadError::InvalidProof(_))
        ));
    }

    #[test]
    fn malformed_encoded_committed_value_fails_closed() {
        let address = address(1, 7);
        let mut response = response(&address, FLOOR);
        response.state = SubstateState::Up {
            substate: Encoded::from_bytes(vec![0xff, 0x00]),
        };
        assert!(matches!(
            decode(&address, response),
            Err(ChainReadError::UnsupportedResponse(_))
        ));
    }

    #[test]
    fn legacy_json_value_shape_cannot_deserialize_as_049() {
        let legacy = serde_json::json!({
            "version": 0,
            "state": { "up": { "substate": { "Utxo": { "output": {} } } } },
            "verified": true,
            "proof": null
        });
        assert!(serde_json::from_value::<GetSubstateResponse>(legacy).is_err());
    }
}
