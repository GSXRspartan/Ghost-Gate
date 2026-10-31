//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! The base-node reader: the L1 evidence, straight from consensus data.
//!
//! Every answer is read from a real Minotari base node over gRPC and reduced to the fields the
//! verdict needs. A node that cannot be reached is a transport error, never a verdict; a node
//! that answers "unknown kernel" is `Ok(None)`, which the verifier treats as "not mined yet".

use minotari_node_grpc_client::grpc::{
    Empty as ProtoEmpty, FetchMatchingUtxosRequest, SearchKernelsRequest,
    Signature as ProtoSignature, SubmitTransactionRequest, SubmitTransactionResponse, Transaction,
    base_node_client::BaseNodeClient,
};

use ghost_gate_bridge::xtm::{MinedKernel, XtmChainError, XtmChainReader, XtmMinedOutput, XtmTip};

/// A connected base node.
pub struct BaseNodeXtmReader {
    client: BaseNodeClient<tonic::transport::Channel>,
}

impl BaseNodeXtmReader {
    /// Connects to `http://host:port`. The address is loopback in every supported deployment;
    /// nothing here enforces that, because the *bridge* enforces what it talks to.
    pub async fn connect(endpoint: &str) -> Result<Self, XtmChainError> {
        let client = BaseNodeClient::connect(endpoint.to_string())
            .await
            .map_err(|e| XtmChainError(format!("base node connect: {e}")))?;
        Ok(Self { client })
    }

    /// The tip's height, for challenge minting.
    pub async fn tip_height(&mut self) -> Result<u64, XtmChainError> {
        Ok(self.tip().await?.height)
    }

    /// Submits a full transaction to the mempool. Returns the node's own verdict word.
    pub async fn submit_transaction(
        &mut self,
        transaction: Transaction,
    ) -> Result<String, XtmChainError> {
        let response: SubmitTransactionResponse = self
            .client
            .submit_transaction(SubmitTransactionRequest {
                transaction: Some(transaction),
            })
            .await
            .map_err(|e| XtmChainError(format!("submit: {e}")))?
            .into_inner();
        let result = response.result;
        Ok(match result {
            0 => "NONE".to_string(),
            1 => "ACCEPTED".to_string(),
            2 => "NOT_PROCESSABLE_AT_THIS_TIME".to_string(),
            3 => "ALREADY_MINED".to_string(),
            4 => "REJECTED".to_string(),
            other => format!("UNKNOWN({other})"),
        })
    }
}

/// The kernel search: how a broadcast transaction's *status* is resolved without resubmitting.
///
/// A transaction is identified by its kernel's excess signature (public nonce + scalar), which is
/// unique per transaction and is exactly what the proof artifact carries.
async fn find_kernel_block(
    client: &mut BaseNodeClient<tonic::transport::Channel>,
    excess_sig: &[u8; 64],
) -> Result<Option<minotari_node_grpc_client::grpc::HistoricalBlock>, XtmChainError> {
    let mut public_nonce = Vec::from(&excess_sig[..32]);
    let signature = Vec::from(&excess_sig[32..]);
    let mut stream = client
        .search_kernels(SearchKernelsRequest {
            signatures: vec![ProtoSignature {
                public_nonce: public_nonce.clone(),
                signature,
            }],
        })
        .await
        .map_err(|e| XtmChainError(format!("search_kernels: {e}")))?
        .into_inner();
    let _ = public_nonce.pop();
    // The first block that reports the kernel is the canonical answer: SearchKernels returns the
    // block the kernel was mined into on this node's best chain.
    match stream.message().await {
        Ok(Some(block)) => Ok(Some(block)),
        Ok(None) => Ok(None),
        Err(e) => Err(XtmChainError(format!("search_kernels stream: {e}"))),
    }
}

fn reduce_block(block: &minotari_node_grpc_client::grpc::HistoricalBlock) -> Option<MinedKernel> {
    let block = block.block.as_ref()?;
    let header = block.header.as_ref()?;
    let kernel = block.body.as_ref()?.kernels.iter().next()?;
    Some(MinedKernel {
        block_height: header.height,
        block_timestamp_unix: header.timestamp,
        kernel_fee_micro: kernel.fee,
        outputs: block
            .body
            .as_ref()?
            .outputs
            .iter()
            .map(|o| {
                let hash: [u8; 32] = o
                    .hash
                    .iter()
                    .copied()
                    .collect::<Vec<u8>>()
                    .try_into()
                    .unwrap_or([0u8; 32]);
                // The script is read for a single PushPubKey opcode: the standard pay-to-self
                // shape. Anything else reports None, which the verdict refuses.
                let script_public_key = read_push_pubkey(&o.script);
                XtmMinedOutput {
                    output_hash: hash,
                    minimum_value_promise_micro: o.minimum_value_promise,
                    script_public_key,
                }
            })
            .collect(),
    })
}

/// Reads a `PushPubKey(k)` script: one byte of opcode (0x73 = PushPubKey per `op_codes.rs`),
/// then the length, then the 32-byte key. Anything else is `None`.
fn read_push_pubkey(script: &[u8]) -> Option<[u8; 32]> {
    // PushPubKey = 0x7e, serialised as the opcode byte then the 32-byte key: no length prefix.
    // (`tari_script-6.0.1-pre.2/src/op_codes.rs:108`); the key is `p.deref().as_bytes()`.
    if script.len() == 33 && script[0] == 0x7e {
        let mut key = [0u8; 32];
        key.copy_from_slice(&script[1..]);
        Some(key)
    } else {
        None
    }
}

impl XtmChainReader for BaseNodeXtmReader {
    async fn tip(&mut self) -> Result<XtmTip, XtmChainError> {
        let response = self
            .client
            .get_tip_info(ProtoEmpty {})
            .await
            .map_err(|e| XtmChainError(format!("tip: {e}")))?
            .into_inner();
        let metadata = response.metadata.unwrap_or_default();
        Ok(XtmTip {
            height: metadata.best_block_height,
            timestamp_unix: metadata.timestamp,
        })
    }

    async fn kernel_block(
        &mut self,
        excess_sig: &[u8; 64],
    ) -> Result<Option<MinedKernel>, XtmChainError> {
        let _ = ProtoEmpty {};
        match find_kernel_block(&mut self.client, excess_sig).await? {
            Some(block) => Ok(reduce_block(&block)),
            None => Ok(None),
        }
    }

    async fn output_is_unspent(&mut self, output_hash: &[u8; 32]) -> Result<bool, XtmChainError> {
        let mut stream = self
            .client
            .fetch_matching_utxos(FetchMatchingUtxosRequest {
                hashes: vec![Vec::from(output_hash)],
            })
            .await
            .map_err(|e| XtmChainError(format!("fetch_matching_utxos: {e}")))?
            .into_inner();
        match stream.message().await {
            Ok(Some(response)) => Ok(response.output.is_some()),
            Ok(None) => Ok(false),
            Err(e) => Err(XtmChainError(format!("fetch_matching_utxos stream: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The script reader is consensus-facing; these pin the exact byte shapes.
    #[test]
    fn a_push_pubkey_script_reads_its_key() {
        let mut script = vec![0x7eu8];
        script.extend_from_slice(&[9u8; 32]);
        assert_eq!(read_push_pubkey(&script), Some([9u8; 32]));
    }

    #[test]
    fn any_other_script_is_none() {
        assert_eq!(read_push_pubkey(&[]), None);
        assert_eq!(read_push_pubkey(&[0x7e]), None);
        assert_eq!(read_push_pubkey(&vec![0x7eu8, 0, 0, 1]), None);
    }
}
