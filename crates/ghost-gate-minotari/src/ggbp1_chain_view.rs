//! Read-only GGBP-1 ChainView backed by the pinned Minotari base-node gRPC client.
//!
//! `SearchUtxos` establishes the output's best-chain block inclusion from a commitment and
//! `FetchMatchingUtxos` establishes its current UTXO presence by output hash. The base-node gRPC
//! service does not return a transferable inclusion proof or response authentication. This adapter
//! therefore emits *untrusted* RPC assertions only; it cannot produce a positive experimental
//! verification result. A future connector must authenticate the transport or verify an
//! operator-controlled pin before it may emit trusted evidence.

use async_trait::async_trait;
use minotari_node_grpc_client::grpc::{
    Empty as ProtoEmpty, FetchMatchingUtxosRequest, GetBlocksRequest, HistoricalBlock,
    SearchUtxosRequest, base_node_client::BaseNodeClient,
};
use tari_crypto::ristretto::{RistrettoPublicKey, pedersen::PedersenCommitment};
use tari_script::TariScript;
use tari_utilities::ByteArray;
use tokio::sync::Mutex;

use crate::{
    ggbp1::SyntheticStandardOutput,
    ggbp1_experiment::{
        Ggbp1ChainSnapshot, Ggbp1ChainView, Ggbp1ChainViewError, Ggbp1EvidenceSource,
        Ggbp1ObservedOutput,
    },
};

/// A read-only diagnostic client for an arbitrary base-node endpoint. It does not start,
/// configure, or synchronize a node, and its RPC observations are never a trusted verifier input.
pub struct BaseNodeGgbp1ChainView {
    client: Mutex<BaseNodeClient<tonic::transport::Channel>>,
}

impl BaseNodeGgbp1ChainView {
    pub async fn connect_untrusted_for_diagnostics(
        endpoint: &str,
    ) -> Result<Self, Ggbp1ChainViewError> {
        let client = BaseNodeClient::connect(endpoint.to_string())
            .await
            .map_err(|error| Ggbp1ChainViewError(format!("base-node connect: {error}")))?;
        Ok(Self {
            client: Mutex::new(client),
        })
    }
}

#[async_trait]
impl Ggbp1ChainView for BaseNodeGgbp1ChainView {
    async fn snapshot(&self) -> Result<Ggbp1ChainSnapshot, Ggbp1ChainViewError> {
        let mut client = self.client.lock().await;
        let tip = client
            .get_tip_info(ProtoEmpty {})
            .await
            .map_err(|error| Ggbp1ChainViewError(format!("get_tip_info: {error}")))?
            .into_inner();
        let metadata = tip
            .metadata
            .ok_or_else(|| Ggbp1ChainViewError("get_tip_info omitted metadata".to_string()))?;
        let tip_hash = array_32(&metadata.best_block_hash, "tip hash")?;
        let version = client
            .get_version(ProtoEmpty {})
            .await
            .map_err(|error| Ggbp1ChainViewError(format!("get_version: {error}")))?
            .into_inner();
        let network = u8::try_from(version.network).map_err(|_| {
            Ggbp1ChainViewError("node network does not fit GGBP-1 network byte".to_string())
        })?;
        let genesis = block_at_height(&mut client, 0).await?.ok_or_else(|| {
            Ggbp1ChainViewError("the node cannot return the genesis block".to_string())
        })?;
        let genesis_hash = block_header(&genesis)
            .and_then(|header| array_32(&header.hash, "genesis hash").ok())
            .ok_or_else(|| {
                Ggbp1ChainViewError("genesis block omits a valid header hash".to_string())
            })?;

        // BaseNodeState::LISTENING is value 5 in the pinned generated protobuf. We retain the
        // numeric comparison so this module does not import a generated enum name that has changed
        // across Tari releases; the source-backed version contract is documented above.
        Ok(Ggbp1ChainSnapshot {
            source: Ggbp1EvidenceSource::UntrustedBaseNodeRpc,
            network,
            genesis_hash,
            tip_height: metadata.best_block_height,
            tip_hash,
            tip_timestamp_unix_seconds: metadata.timestamp,
            is_synced: tip.initial_sync_achieved
                && tip.base_node_state == 5
                && !tip.failed_checkpoints,
        })
    }

    async fn output(
        &self,
        expected: &SyntheticStandardOutput,
    ) -> Result<Option<Ggbp1ObservedOutput>, Ggbp1ChainViewError> {
        let mut client = self.client.lock().await;
        let mut block_stream = client
            .search_utxos(SearchUtxosRequest {
                commitments: vec![expected.commitment.as_bytes().to_vec()],
            })
            .await
            .map_err(|error| Ggbp1ChainViewError(format!("search_utxos: {error}")))?
            .into_inner();

        let mut inclusion = None;
        while let Some(block) = block_stream
            .message()
            .await
            .map_err(|error| Ggbp1ChainViewError(format!("search_utxos stream: {error}")))?
        {
            if let Some(output) = find_output(&block, expected)? {
                inclusion = Some((block, output));
                break;
            }
        }
        let Some((block, output)) = inclusion else {
            return Ok(None);
        };
        let header = block_header(&block)
            .ok_or_else(|| Ggbp1ChainViewError("included block has no header".to_string()))?;
        let mined_block_hash = array_32(&header.hash, "mined block hash")?;
        let features = output
            .features
            .as_ref()
            .ok_or_else(|| Ggbp1ChainViewError("included output has no features".to_string()))?;
        let commitment =
            PedersenCommitment::from_canonical_bytes(&output.commitment).map_err(|_| {
                Ggbp1ChainViewError("included output has invalid commitment bytes".to_string())
            })?;
        let script = TariScript::from_bytes(&output.script)
            .map_err(|error| Ggbp1ChainViewError(format!("included output script: {error}")))?;
        let script_public_key = push_pubkey_script_key(&output.script)?;
        let is_unspent = current_utxo_presence(&mut client, expected.output_hash).await?;

        Ok(Some(Ggbp1ObservedOutput {
            output_hash: expected.output_hash,
            commitment,
            script,
            script_public_key,
            mined_height: header.height,
            mined_block_hash,
            confirmations: block.confirmations,
            maturity_height: features.maturity,
            output_version: output.version,
            output_type: features.output_type,
            range_proof_type: features.range_proof_type,
            // The raw RPC output contains covenant bytes but this adapter has no reviewed
            // canonical covenant parser. It also lacks the wallet-local script lock height.
            // Returning `None` is deliberate: the verifier refuses incomplete evidence.
            covenant_is_supported: None,
            effective_lock_height: None,
            is_unspent,
            // `SearchUtxos` is defined against the node's current best chain. The verifier protects
            // the remaining node-trust and reorg race with its before/after tip snapshots.
            is_in_best_chain: true,
        }))
    }
}

async fn block_at_height(
    client: &mut BaseNodeClient<tonic::transport::Channel>,
    height: u64,
) -> Result<Option<HistoricalBlock>, Ggbp1ChainViewError> {
    let mut stream = client
        .get_blocks(GetBlocksRequest {
            heights: vec![height],
        })
        .await
        .map_err(|error| Ggbp1ChainViewError(format!("get_blocks: {error}")))?
        .into_inner();
    stream
        .message()
        .await
        .map_err(|error| Ggbp1ChainViewError(format!("get_blocks stream: {error}")))
}

async fn current_utxo_presence(
    client: &mut BaseNodeClient<tonic::transport::Channel>,
    output_hash: [u8; 32],
) -> Result<bool, Ggbp1ChainViewError> {
    let mut stream = client
        .fetch_matching_utxos(FetchMatchingUtxosRequest {
            hashes: vec![output_hash.to_vec()],
        })
        .await
        .map_err(|error| Ggbp1ChainViewError(format!("fetch_matching_utxos: {error}")))?
        .into_inner();
    while let Some(response) = stream
        .message()
        .await
        .map_err(|error| Ggbp1ChainViewError(format!("fetch_matching_utxos stream: {error}")))?
    {
        if let Some(output) = response.output {
            if output.hash.as_slice() == output_hash {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn find_output(
    block: &HistoricalBlock,
    expected: &SyntheticStandardOutput,
) -> Result<Option<minotari_node_grpc_client::grpc::TransactionOutput>, Ggbp1ChainViewError> {
    let Some(body) = block.block.as_ref().and_then(|block| block.body.as_ref()) else {
        return Err(Ggbp1ChainViewError(
            "search_utxos returned a block without a body".to_string(),
        ));
    };
    for output in &body.outputs {
        if output.hash.as_slice() == expected.output_hash
            && output.commitment.as_slice() == expected.commitment.as_bytes()
        {
            return Ok(Some(output.clone()));
        }
    }
    Ok(None)
}

fn block_header(block: &HistoricalBlock) -> Option<&minotari_node_grpc_client::grpc::BlockHeader> {
    block.block.as_ref()?.header.as_ref()
}

fn array_32(bytes: &[u8], field: &str) -> Result<[u8; 32], Ggbp1ChainViewError> {
    bytes
        .try_into()
        .map_err(|_| Ggbp1ChainViewError(format!("{field} must be 32 bytes")))
}

fn push_pubkey_script_key(script: &[u8]) -> Result<RistrettoPublicKey, Ggbp1ChainViewError> {
    // `PushPubKey` is opcode 0x7e followed directly by the 32-byte compressed Ristretto key in
    // the pinned tari_script 6.0.1-pre.2 codec. Other scripts cannot be used by this prototype.
    if script.len() != 33 || script[0] != 0x7e {
        return Err(Ggbp1ChainViewError(
            "output does not use the supported standard PushPubKey script".to_string(),
        ));
    }
    RistrettoPublicKey::from_canonical_bytes(&script[1..])
        .map_err(|_| Ggbp1ChainViewError("PushPubKey has invalid public-key bytes".to_string()))
}
