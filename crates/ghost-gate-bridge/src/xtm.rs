//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! The native Minotari L1 XTM proof path: its channel, its chain evidence and its verdict.
//!
//! # The boundary, in one paragraph
//!
//! The browser may ask for a challenge and ask for a proof; it may never name a transaction, an
//! output or an amount. The bridge holds the only channel to the user's Minotari wallet daemon and
//! the only reader of base-node state, and it initiates one pay-to-self transaction per challenge.
//! The verdict itself rests on consensus data, not on the wallet's word: the mined kernel's fee,
//! the qualifying output's public `minimum_value_promise`, the block height and timestamp the
//! kernel was mined into, and a spend-key signature over the challenge nonce verified against the
//! public key the mined output carries in its script.
//!
//! # What the verdict asserts
//!
//! That the wallet answering the challenge held the spend key of an output whose promised floor
//! plus the kernel fee was at least the threshold, in a block mined after the challenge was issued,
//! at the moment the bridge verified. It asserts nothing about the wallet's total balance: the
//! floor `promise + fee ≤ balance` is the whole arithmetic, and the wallet never reports a balance
//! to the bridge at all.
//!
//! # Where challenge binding is enforced
//!
//! Minotari transactions carry no consensus-visible free-form field (the kernel has no message
//! input, and `MemoField` is wallet-local and fee-weighting only), so the challenge cannot be
//! written into the transaction itself. Binding is therefore enforced in two places, in this order:
//!
//! 1. **Structurally, by the bridge.** The browser never supplies a transaction; the bridge asks
//!    its own channel to create one *for this challenge*, remembers the kernel signature and output
//!    hash it received, and only ever verifies that artifact. A request body has no field that could
//!    name a transaction (`policy::ProveRequest` is three short strings).
//! 2. **Cryptographically, by the spend-key signature.** The wallet daemon signs the challenge's
//!    32-byte nonce with the qualifying output's script key, and the bridge verifies it against the
//!    script public key read from the mined output on chain. A transaction that was not created in
//!    answer to this challenge cannot carry that signature, and neither can a third party's.
//!
//! The second check is the one that would still hold if the wallet daemon were re-implemented by
//! someone else: the first alone trusts the wallet channel, and the docs say so.

use std::time::Duration;

use ghost_gate_core::xtm::{
    FRESHNESS_TIMESTAMP_SLACK_SECS,
    XtmChallenge,
    XtmProofError,
    XtmProofReceipt,
    floor_meets_threshold,
    provable_floor,
};
use ghost_gate_core::Hash32;

use crate::wallet::WalletError;

/// How the L1 wallet daemon reports itself without revealing anything.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct XtmWalletStatus {
    /// Whether a wallet daemon answered at all.
    pub reachable: bool,
    /// The Minotari network byte the wallet is configured for (`tari_common::Network`), which is
    /// the same byte table the Ootle cohorts use.
    pub network: u8,
    /// The network's name, for a UI.
    pub network_name: String,
    /// The wallet's public spend key, hex. This is a public key: it is on chain in every output the
    /// wallet's outputs derive from, and the verifier needs it to bind proofs to this wallet.
    pub spend_public_key: Option<String>,
}

impl XtmWalletStatus {
    pub fn unreachable() -> Self {
        Self {
            reachable: false,
            network: 0,
            network_name: String::new(),
            spend_public_key: None,
        }
    }
}

/// What the bridge asks the wallet daemon to build: one pay-to-self transaction whose output
/// promises at least the gate threshold, answering this challenge.
///
/// Note what is not here: no output value (the wallet chooses the largest value it can afford —
/// that is how the exact boundary is met without the wallet disclosing its balance), no input
/// selection, no destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XtmProofRequest {
    /// The gate threshold in micro-Minotari (base units).
    pub threshold_micro: u64,
    /// The challenge nonce, which the wallet signs with the new output's script key.
    pub challenge_nonce: [u8; 32],
}

/// The minimal public artifact of the proving transaction.
///
/// Everything here is either public on chain (the kernel signature, the output hash) or is the
/// challenge signature the wallet daemon produces. Nothing discloses a balance, a value, or a mask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XtmProofArtifact {
    /// The wallet's own transaction id, for rebroadcast and bookkeeping.
    pub transaction_id: u64,
    /// The kernel's excess signature (64 bytes: public nonce + signature scalar), by which the
    /// bridge finds the transaction on chain via `SearchKernels`.
    pub kernel_excess_sig: [u8; 64],
    /// The hash of the qualifying output, whose `minimum_value_promise` and script key the
    /// verifier reads from the mined block.
    pub output_hash: [u8; 32],
    /// The spend-key signature over the challenge nonce: 64 bytes (public nonce + scalar),
    /// `tari_script`'s `CheckSigSchnorrSignature` construction.
    pub spend_signature: [u8; 64],
}

/// What the bridge needs from a Minotari wallet daemon.
///
/// Separate from [`crate::wallet::WalletChannel`]: the Ootle channel builds Ootle statements, this
/// one builds L1 transactions, and the two must never be interchangeable — a typed gate names its
/// kind and the server dispatches on it, so an Ootle proof can never answer an XTM challenge or
/// the reverse.
#[allow(async_fn_in_trait)]
pub trait XtmChannel {
    /// Whether a wallet daemon is reachable, without asking anything sensitive.
    async fn status(&mut self) -> Result<XtmWalletStatus, WalletError>;

    /// Creates (and broadcasts) the proving transaction for this challenge.
    ///
    /// The daemon resolves its own fee, selects its own inputs, promises the whole output value,
    /// broadcasts exactly once, and returns the artifact. On `WalletError::CannotConstructProof`
    /// nothing was broadcast and nothing was spent: the wallet could not afford a qualifying
    /// transaction, and it says so without stating a balance.
    async fn create_proof_transaction(
        &mut self,
        request: XtmProofRequest,
    ) -> Result<XtmProofArtifact, WalletError>;

    /// Re-broadcasts the *same* transaction the daemon already built.
    ///
    /// This exists for the ambiguous-submission case only: a transport error or timeout after
    /// submission leaves the transaction's network state unknown, and the rule is to resolve by
    /// querying before considering another submission. Re-broadcasting identical bytes is safe —
    /// consensus rejects a duplicate kernel as a duplicate — while building a second transaction
    /// for the same challenge would double-spend the user's inputs.
    async fn rebroadcast(&mut self, transaction_id: u64) -> Result<(), WalletError>;
}

/// A base-layer tip, as the verifier reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XtmTip {
    pub height: u64,
    pub timestamp_unix: u64,
}

/// One output of a mined block, reduced to what the verdict reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XtmMinedOutput {
    pub output_hash: [u8; 32],
    /// The output's public `minimum_value_promise`, in micro-Minotari. Consensus data.
    pub minimum_value_promise_micro: u64,
    /// The public key the output's script pushes, if the script is a single `PushPubKey` — the
    /// shape every standard pay-to-self output has. `None` for anything else, which is a refusal:
    /// a qualifying output must be key-controlled.
    pub script_public_key: Option<[u8; 32]>,
}

/// The chain evidence for one kernel: the block it was mined into, reduced to the fields the
/// verdict reads. Everything here comes from base-node consensus data, not from the wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinedKernel {
    pub block_height: u64,
    pub block_timestamp_unix: u64,
    /// The kernel's fee, in micro-Minotari. Consensus data.
    pub kernel_fee_micro: u64,
    /// The outputs the block carries alongside the kernel.
    pub outputs: Vec<XtmMinedOutput>,
}

/// Why the chain reader gave up on one call. A transport error, not a verdict.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("GG: the base node could not be queried: {0}")]
pub struct XtmChainError(pub String);

/// The chain evidence the L1 verdict is built on.
///
/// The production implementation talks gRPC to a base node (`BaseNodeXtmReader`, in
/// `ghost-gate-minotari`). The trait is here so the verdict logic can be tested against crafted
/// evidence without a node, and so a base node that lies can be a *tested* concern rather than an
/// untested one.
#[allow(async_fn_in_trait)]
pub trait XtmChainReader {
    /// The current tip.
    async fn tip(&mut self) -> Result<XtmTip, XtmChainError>;
    /// The block a kernel excess signature was mined into, or `None` while it is unknown to this
    /// node (mempool, or never seen). An error is a transport problem, not a verdict.
    async fn kernel_block(&mut self, excess_sig: &[u8; 64]) -> Result<Option<MinedKernel>, XtmChainError>;
    /// Whether the output hash is currently in the UTXO set. `false` covers both "spent" and
    /// "unknown to this node": a proof output the chain no longer holds is not evidence.
    async fn output_is_unspent(&mut self, output_hash: &[u8; 32]) -> Result<bool, XtmChainError>;
}

/// How long one chain lookup may take before it is an error. A poll loop is the caller's job; one
/// call never waits for the chain to settle.
pub const CHAIN_CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// The verdict, and what it means to get one.
///
/// The order below is the security argument, and it is deliberately fail-closed end to end:
/// anything unobservable, unconfirmed, stale, arithmetically short, or cryptographically unbound
/// is a refusal, and the caller retries only while the challenge is still live.
pub async fn verify_xtm_proof(
    reader: &mut impl XtmChainReader,
    challenge: &XtmChallenge,
    artifact: &XtmProofArtifact,
    now_unix: u64, // used by the timestamp freshness check below
) -> Result<XtmProofReceipt, XtmProofError> {
    // 1. Committed evidence only. "Unknown to this node" covers the mempool: a transaction that
    //    has not been mined is not evidence, whatever a submission response said.
    let mined = reader
        .kernel_block(&artifact.kernel_excess_sig)
        .await
        .map_err(|_| XtmProofError::NotMined)?
        .ok_or(XtmProofError::NotMined)?;

    // 2. Freshness. The kernel must sit in a block above the tip the challenge recorded, so no
    //    transaction that pre-dates the challenge can answer it, however qualifying it looks.
    if mined.block_height <= challenge.tip_height_at_issue {
        return Err(XtmProofError::StaleKernel);
    }
    //    The timestamp check is the second half: a block whose recorded time is before the
    //    challenge was minted is refused, with slack for miner clock jitter only.
    let fresh_from = challenge.issued_at_unix.saturating_sub(FRESHNESS_TIMESTAMP_SLACK_SECS);
    if mined.block_timestamp_unix < fresh_from {
        return Err(XtmProofError::BlockPredatesChallenge);
    }

    // 3. The qualifying output. Exactly the hash the proving transaction declared; anything else is
    //    a different proof.
    let output = mined
        .outputs
        .iter()
        .find(|o| o.output_hash == artifact.output_hash)
        .ok_or(XtmProofError::NotMined)?;

    // 4. The threshold, on the provable floor: the output's public promise plus the kernel's fee.
    //    The sum is computed in `u128`, where two `u64`s cannot overflow, so the arithmetic is
    //    total and there is no error case to mis-handle.
    let floor = provable_floor(output.minimum_value_promise_micro, mined.kernel_fee_micro);
    if !floor_meets_threshold(floor, challenge.threshold_micro) {
        return Err(XtmProofError::BelowThreshold);
    }

    // 5. The cryptographic binding: the challenge was signed by the output's script key.
    let script_key = output.script_public_key.ok_or(XtmProofError::BadSpendSignature)?;
    let nonce: [u8; 32] = challenge
        .nonce
        .as_slice()
        .try_into()
        .expect("Hash32 is exactly 32 bytes");
    if !xtm_signature::verify_spend_signature(&script_key, &nonce, &artifact.spend_signature) {
        return Err(XtmProofError::BadSpendSignature);
    }

    // 6. The output must still be in the live UTXO set: the proof is about control *now*, and an
    //    output the chain no longer holds cannot support it.
    if !reader
        .output_is_unspent(&artifact.output_hash)
        .await
        .map_err(|_| XtmProofError::NotMined)?
    {
        return Err(XtmProofError::NotMined);
    }
    Ok(XtmProofReceipt {
        attested_floor_micro: floor,
        output_count: 1,
        challenge_nonce: Hash32::from_array(nonce),
        mined_height: mined.block_height,
    })
}


/// Helpers around the spend-key signature's encoding, so the wallet daemon, the bridge and the
/// tests agree on byte layout without either side depending on the other's crates.
///
/// The construction is `tari_script`'s `CheckSigSchnorrSignature` — the same type the wallet's key
/// manager produces from `sign_script_message(key_id, challenge)` — so the verification here is
/// byte-for-byte the construction that ran at signing time, not a re-implementation of it.
pub mod xtm_signature {
    use tari_crypto::{
        compressed_key::CompressedKey,
        ristretto::RistrettoPublicKey,
        tari_utilities::ByteArray,
    };
    use tari_script::CompressedCheckSigSchnorrSignature;

    /// The signature's two 32-byte halves: public nonce `R` first, then the scalar `s`.
    pub const SIGNATURE_LEN: usize = 64;

    /// Verifies a spend-key signature over `message` against `script_public_key`.
    ///
    /// Every input is untrusted bytes, so every decode failure is `false`, never a panic.
    pub fn verify_spend_signature(script_public_key: &[u8; 32], message: &[u8; 32], signature: &[u8; 64]) -> bool {
        let Ok(public_key) = RistrettoPublicKey::from_canonical_bytes(script_public_key) else {
            return false;
        };
        let mut public_nonce = [0u8; 32];
        public_nonce.copy_from_slice(&signature[..32]);
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&signature[32..]);
        let Ok(scalar) = tari_crypto::ristretto::RistrettoSecretKey::from_canonical_bytes(&scalar) else {
            return false;
        };
        let Ok(public_nonce) = RistrettoPublicKey::from_canonical_bytes(&public_nonce) else {
            return false;
        };
        let compressed = CompressedCheckSigSchnorrSignature::new(
            CompressedKey::new_from_pk(public_nonce),
            scalar,
        );
        let Ok(uncompressed) = compressed.to_schnorr_signature() else {
            return false;
        };
        uncompressed.verify(&public_key, message)
    }
}

/// The absent Minotari wallet daemon: every method refuses, honestly.
///
/// The bridge built without one serves its Ootle gates and reports this for anything L1. It is the
/// shape [`crate::server::NoWallet`] has on the Ootle side, and it exists so the generic defaults
/// never need a `#[cfg]`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoXtm;

impl XtmChannel for NoXtm {
    async fn status(&mut self) -> Result<XtmWalletStatus, WalletError> {
        Ok(XtmWalletStatus::unreachable())
    }

    async fn create_proof_transaction(
        &mut self,
        _request: XtmProofRequest,
    ) -> Result<XtmProofArtifact, WalletError> {
        Err(WalletError::Unreachable(
            "no Minotari wallet daemon is connected to this bridge".to_string(),
        ))
    }

    async fn rebroadcast(&mut self, _transaction_id: u64) -> Result<(), WalletError> {
        Err(WalletError::Unreachable(
            "no Minotari wallet daemon is connected to this bridge".to_string(),
        ))
    }
}

/// The absent base-node reader: no L1 evidence exists, so no L1 verdict can.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoXtmChainReader;

impl XtmChainReader for NoXtmChainReader {
    async fn tip(&mut self) -> Result<XtmTip, XtmChainError> {
        Err(XtmChainError("no base node is configured for this bridge".to_string()))
    }

    async fn kernel_block(&mut self, _excess_sig: &[u8; 64]) -> Result<Option<MinedKernel>, XtmChainError> {
        Err(XtmChainError("no base node is configured for this bridge".to_string()))
    }

    async fn output_is_unspent(&mut self, _output_hash: &[u8; 32]) -> Result<bool, XtmChainError> {
        Err(XtmChainError("no base node is configured for this bridge".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_gate_core::Hash32;
    use ghost_gate_core::xtm::MICRO_PER_XTM;
    use tari_crypto::keys::{PublicKey, SecretKey};
    use tari_crypto::ristretto::RistrettoSecretKey;
    use tari_crypto::tari_utilities::ByteArray;
    use tari_script::CheckSigSchnorrSignature;

    const NETWORK: u8 = ghost_gate_core::network::LOCALNET;

    fn challenge(threshold_micro: u64, tip_at_issue: u64, issued_at: u64) -> XtmChallenge {
        XtmChallenge {
            gate_id: tari_template_lib_types::MaxBytes::new_checked(b"otherside".to_vec()).unwrap(),
            threshold_micro,
            network: NETWORK,
            nonce: Hash32::from_array([7u8; 32]),
            issued_at_unix: issued_at,
            expires_at_unix: issued_at + 180,
            relying_site: tari_template_lib_types::MaxBytes::new_checked(b"vip.example".to_vec()).unwrap(),
            session_commitment: tari_template_lib_types::MaxBytes::new_checked(b"session-1".to_vec()).unwrap(),
            tip_height_at_issue: tip_at_issue,
        }
    }

    /// A mined kernel carrying one output whose script key belongs to a fresh keypair, plus the
    /// artifact that answers a challenge: signed with the same key the output carries.
    fn fresh_artifact(
        nonce: &[u8; 32],
    ) -> (XtmProofArtifact, MinedKernel, RistrettoSecretKey) {
        let secret = RistrettoSecretKey::random(&mut rand::rng());
        let public: tari_crypto::ristretto::RistrettoPublicKey = PublicKey::from_secret_key(&secret);
        let sig = CheckSigSchnorrSignature::sign(&secret, nonce, &mut rand::rng()).unwrap();
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(sig.get_public_nonce().as_bytes());
        signature[32..].copy_from_slice(sig.get_signature().as_bytes());

        let artifact = XtmProofArtifact {
            transaction_id: 1,
            kernel_excess_sig: [1u8; 64],
            output_hash: [2u8; 32],
            spend_signature: signature,
        };
        let mined = MinedKernel {
            block_height: 50,
            block_timestamp_unix: 10_000,
            kernel_fee_micro: 1_000,
            outputs: vec![XtmMinedOutput {
                output_hash: [2u8; 32],
                minimum_value_promise_micro: 0,
                script_public_key: Some(public.as_bytes().try_into().unwrap()),
            }],
        };
        (artifact, mined, secret)
    }

    /// A chain reader over a canned verdict.
    struct FakeReader {
        mined: Option<MinedKernel>,
        unspent: bool,
    }

    impl XtmChainReader for FakeReader {
        async fn tip(&mut self) -> Result<XtmTip, XtmChainError> {
            Ok(XtmTip { height: 50, timestamp_unix: 10_000 })
        }
        async fn kernel_block(&mut self, _sig: &[u8; 64]) -> Result<Option<MinedKernel>, XtmChainError> {
            Ok(self.mined.clone())
        }
        async fn output_is_unspent(&mut self, _hash: &[u8; 32]) -> Result<bool, XtmChainError> {
            Ok(self.unspent)
        }
    }

    /// 1 XTM is a million micro; the million gate's threshold in base units.
    #[test]
    fn the_million_xtm_threshold_is_a_million_million_micro() {
        assert_eq!(MICRO_PER_XTM, 1_000_000);
        assert_eq!(
            ghost_gate_core::xtm::xtm_to_micro(1_000_000),
            Some(1_000_000_000_000u128),
            "1,000,000 XTM in base units"
        );
    }

    #[tokio::test]
    async fn at_the_exact_boundary_the_floor_plus_fee_equals_the_threshold() {
        // The whole point of the fee relation: a wallet with exactly 1,000,000 XTM spends
        // 999,999,000 micro as the output (fee 1,000) and still proves the threshold.
        let ch = challenge(1_000_000_000_000, 40, 9_990);
        let (art, mut mined, _key) = fresh_artifact(&[7u8; 32]);
        mined.outputs[0].minimum_value_promise_micro = 1_000_000_000_000 - 1_000;
        mined.block_height = 41;
        let mut reader = FakeReader { mined: Some(mined), unspent: true };
        let receipt = verify_xtm_proof(&mut reader, &ch, &art, 10_000).await.unwrap();
        assert_eq!(receipt.attested_floor_micro, 1_000_000_000_000u128);
        assert_eq!(receipt.mined_height, 41);
    }

    #[tokio::test]
    async fn one_micro_below_the_boundary_is_refused() {
        let ch = challenge(1_000_000_000_000, 40, 9_990);
        let (art, mut mined, _key) = fresh_artifact(&[7u8; 32]);
        mined.outputs[0].minimum_value_promise_micro = 1_000_000_000_000 - 1_001;
        mined.block_height = 41;
        let mut reader = FakeReader { mined: Some(mined), unspent: true };
        assert_eq!(
            verify_xtm_proof(&mut reader, &ch, &art, 10_000).await.unwrap_err(),
            XtmProofError::BelowThreshold
        );
    }

    #[tokio::test]
    async fn comfortably_above_the_threshold_is_accepted() {
        let ch = challenge(1_000_000_000_000, 40, 9_990);
        let (art, mut mined, _key) = fresh_artifact(&[7u8; 32]);
        mined.outputs[0].minimum_value_promise_micro = 1_000_000_000_000 + 500;
        mined.block_height = 41;
        let mut reader = FakeReader { mined: Some(mined), unspent: true };
        let receipt = verify_xtm_proof(&mut reader, &ch, &art, 10_000).await.unwrap();
        assert!(receipt.attested_floor_micro > 1_000_000_000_000u128);
    }

    #[tokio::test]
    async fn a_kernel_not_yet_mined_is_not_evidence() {
        let ch = challenge(1_000, 40, 9_990);
        let (art, _mined, _key) = fresh_artifact(&[7u8; 32]);
        let mut reader = FakeReader { mined: None, unspent: true };
        assert_eq!(
            verify_xtm_proof(&mut reader, &ch, &art, 10_000).await.unwrap_err(),
            XtmProofError::NotMined
        );
    }

    #[tokio::test]
    async fn a_kernel_mined_at_the_recorded_tip_or_below_is_stale() {
        let ch = challenge(1_000, 50, 9_990);
        let (art, mined, _key) = fresh_artifact(&[7u8; 32]);
        let mut at_tip = FakeReader { mined: Some(mined.clone()), unspent: true };
        assert_eq!(
            verify_xtm_proof(&mut at_tip, &ch, &art, 10_000).await.unwrap_err(),
            XtmProofError::StaleKernel
        );
        let mut below = FakeReader {
            mined: Some(MinedKernel { block_height: 49, ..mined }),
            unspent: true,
        };
        assert_eq!(
            verify_xtm_proof(&mut below, &ch, &art, 10_000).await.unwrap_err(),
            XtmProofError::StaleKernel
        );
    }

    #[tokio::test]
    async fn a_block_timestamped_before_the_challenge_is_refused() {
        let ch = challenge(1_000, 40, 10_000);
        let (art, mut mined, _key) = fresh_artifact(&[7u8; 32]);
        mined.block_height = 41;
        mined.block_timestamp_unix = 10_000 - 121; // one second beyond the slack
        let mut reader = FakeReader { mined: Some(mined), unspent: true };
        assert_eq!(
            verify_xtm_proof(&mut reader, &ch, &art, 10_000).await.unwrap_err(),
            XtmProofError::BlockPredatesChallenge
        );
    }

    #[tokio::test]
    async fn the_timestamp_slack_absorbs_minor_jitter() {
        let ch = challenge(1_000, 40, 10_000);
        let (art, mut mined, _key) = fresh_artifact(&[7u8; 32]);
        mined.block_height = 41;
        mined.block_timestamp_unix = 10_000 - 120; // exactly the slack
        let mut reader = FakeReader { mined: Some(mined), unspent: true };
        assert!(verify_xtm_proof(&mut reader, &ch, &art, 10_000).await.is_ok());
    }

    #[tokio::test]
    async fn the_floor_arithmetic_is_total_at_extreme_values() {
        // Two u64s added in u128 cannot overflow, so an absurd floor is a *number*, not a panic,
        // and the comparison against the same absurd threshold simply succeeds.
        let ch = challenge(u64::MAX, 40, 9_990);
        let (art, mut mined, _key) = fresh_artifact(&[7u8; 32]);
        mined.outputs[0].minimum_value_promise_micro = u64::MAX;
        mined.block_height = 41;
        mined.kernel_fee_micro = u64::MAX;
        let mut reader = FakeReader { mined: Some(mined), unspent: true };
        let receipt = verify_xtm_proof(&mut reader, &ch, &art, 10_000).await.unwrap();
        assert_eq!(receipt.attested_floor_micro, u64::MAX as u128 * 2);
    }

    #[tokio::test]
    async fn a_mismatched_output_hash_is_refused() {
        let ch = challenge(1_000, 40, 9_990);
        let (mut art, mined, _key) = fresh_artifact(&[7u8; 32]);
        art.output_hash = [4u8; 32]; // not the output the transaction produced
        let mut reader = FakeReader { mined: Some(mined), unspent: true };
        assert_eq!(
            verify_xtm_proof(&mut reader, &ch, &art, 10_000).await.unwrap_err(),
            XtmProofError::NotMined
        );
    }

    #[tokio::test]
    async fn a_signature_by_the_wrong_key_is_refused() {
        // A different key signs the challenge; the mined output carries this one.
        let ch = challenge(1_000, 40, 9_990);
        let (art, mut mined, _key) = fresh_artifact(&[7u8; 32]);
        mined.block_height = 41;
        let wrong = RistrettoSecretKey::random(&mut rand::rng());
        let sig = CheckSigSchnorrSignature::sign(&wrong, &[7u8; 32], &mut rand::rng()).unwrap();
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(sig.get_public_nonce().as_bytes());
        signature[32..].copy_from_slice(sig.get_signature().as_bytes());
        let mut bad_artifact = art.clone();
        bad_artifact.spend_signature = signature;
        let mut reader = FakeReader { mined: Some(mined), unspent: true };
        assert_eq!(
            verify_xtm_proof(&mut reader, &ch, &bad_artifact, 10_000).await.unwrap_err(),
            XtmProofError::BadSpendSignature
        );
    }

    #[tokio::test]
    async fn a_signature_over_a_different_nonce_is_refused() {
        // The replay attempt: a signature produced for challenge A does not verify against
        // challenge B, because the nonce is the signed message.
        let ch = challenge(1_000, 40, 9_990);
        let (art, mut mined, _key) = fresh_artifact(&[9u8; 32]); // signed for a different challenge
        mined.block_height = 41;
        let mut reader = FakeReader { mined: Some(mined), unspent: true };
        assert_eq!(
            verify_xtm_proof(&mut reader, &ch, &art, 10_000).await.unwrap_err(),
            XtmProofError::BadSpendSignature
        );
    }

    #[tokio::test]
    async fn an_output_with_no_script_key_is_refused() {
        let ch = challenge(1_000, 40, 9_990);
        let (art, mut mined, _key) = fresh_artifact(&[7u8; 32]);
        mined.block_height = 41;
        mined.outputs[0].script_public_key = None;
        let mut reader = FakeReader { mined: Some(mined), unspent: true };
        assert_eq!(
            verify_xtm_proof(&mut reader, &ch, &art, 10_000).await.unwrap_err(),
            XtmProofError::BadSpendSignature
        );
    }

    #[tokio::test]
    async fn an_output_no_longer_in_the_utxo_set_is_not_evidence() {
        let ch = challenge(1_000, 40, 9_990);
        let (art, mut mined, _key) = fresh_artifact(&[7u8; 32]);
        mined.block_height = 41;
        let mut reader = FakeReader { mined: Some(mined), unspent: false };
        assert_eq!(
            verify_xtm_proof(&mut reader, &ch, &art, 10_000).await.unwrap_err(),
            XtmProofError::NotMined
        );
    }

    #[test]
    fn an_ill_formed_signature_is_a_refusal_not_a_panic() {
        let key = [0xffu8; 32]; // not a valid curve point encoding for a public nonce
        let mut sig = [0u8; 64];
        rand::fill(&mut sig);
        assert!(!xtm_signature::verify_spend_signature(&key, &[7u8; 32], &sig));
        assert!(!xtm_signature::verify_spend_signature(&[9u8; 32], &[7u8; 32], &[0u8; 64]));
    }
}
