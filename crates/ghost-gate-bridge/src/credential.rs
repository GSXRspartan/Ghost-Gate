//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! The credential proof mode (Mode B), and what the bridge verifies rather than trusts.
//!
//! Mode B is the browser-provider path. A wallet first creates a **real** on-chain output whose
//! range proof publicly commits `value >= minimumValuePromise`, then signs a challenge the site
//! generated over that output. This module is the verifier half: it decides, from chain state and
//! a signature, whether a credential proof means what it claims — trusting nothing the page
//! supplied except the identifiers needed to name things.
//!
//! # What is verified, in order
//!
//! 1. **Challenge binding** — the same book Mode A uses: the challenge is live, belongs to this
//!    gate, and matches the session commitment. A credential proof cannot outlive its challenge.
//! 2. **Chain state, fetched by the bridge** — the substate is read from the indexer here, never
//!    accepted from the page. A page-supplied substate could say anything.
//! 3. **The output is still unspent.** A spent output destroys the proof; the indexer answers a
//!    lookup for a spent UTXO with an error, which is refused.
//! 4. **The floor is real and sufficient** — `minimum_value_promise` is read off the chain
//!    object and must be at least the gate's threshold. The value the page echoed is ignored.
//! 5. **The signature verifies against the output's own on-chain key** — standard Tari Schnorr over
//!    the domain-tagged message in [`ownership_proof_message`], checked against `auth.Key` from the
//!    substate. The `publicKey` the page supplies is **never** the verification key: anyone can
//!    self-report a key, and the docs say the same thing.
//!
//! Only after all five does the challenge retire and a receipt exist.
//!
//! # What this mode is — and is deliberately allowed to be
//!
//! Unlike Mode A, the site ends up holding the output's identifier, the floor is public and
//! permanent for as long as the output exists, and reusing one output across sessions links them.
//! Those properties are inherent to the mechanism and are surfaced to the user in the UI rather
//! than softened here. This module does not pretend otherwise; it also does not let the two modes
//! blur: a credential receipt is a different type from a consensus [`PublicProof`], and records
//! which mode produced it.

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use tari_crypto::hash_domain;
use tari_crypto::hashing::DomainSeparatedHasher;

use tari_crypto::ristretto::{RistrettoPublicKey, RistrettoSecretKey};
use tari_crypto::signatures::{SchnorrSigChallenge, SchnorrSignature};
// `tari_crypto` re-exports `tari_utilities`, so the byte-conversion trait arrives from there --
// same path the cohort's own wallet crypto uses.
use tari_crypto::tari_utilities::ByteArray;
use tari_template_lib_types::crypto::RistrettoPublicKeyBytes;
use tari_template_lib_types::{ResourceAddress, UtxoAddress};

// -------------------------------------------------------------------------------------------
// The ownership-proof message, byte for byte
// -------------------------------------------------------------------------------------------

/// The domain the wallet's own SDK signs under, reproduced exactly.
///
/// The JS reference builds its tag as `${domain}.v${version}.${variant}` with `version = 1` and
/// `variant = "v1"`, so the effective tag is this string **with the doubled suffix**:
/// `com.tari.paylink.ownership_proof.v1.v1`. The doubled suffix is reproduced by
/// `OwnershipProofDomain::domain_separation_tag("v1")`; a reader who "fixes" it will produce
/// messages no wallet will ever sign, which the vectors below will catch.
pub const OWNERSHIP_PROOF_DOMAIN: &str = "com.tari.paylink.ownership_proof";
pub const OWNERSHIP_PROOF_VERSION: u8 = 1;
/// The label `new_with_label` is called with. "v1" is what the reference uses; not a choice.
pub const OWNERSHIP_PROOF_LABEL: &str = "v1";

hash_domain!(
    OwnershipProofDomain,
    OWNERSHIP_PROOF_DOMAIN,
    OWNERSHIP_PROOF_VERSION
);

/// The bytes the wallet signs for [`tari_signOwnershipChallenge`].
///
/// Framing (confirmed against the reference verifier, not inferred): Blake2b-512 over
/// length-prefixed chunks — `[u64 LE length, bytes]` — in this order:
///
/// 1. the domain tag `com.tari.paylink.ownership_proof.v1.v1`;
/// 2. one raw byte, the Ootle network byte;
/// 3. the resource address, as the **UTF-8 bytes of its string form** (`resource_<hex>`), not
///    decoded bytes;
/// 4. the substate id, likewise as the UTF-8 bytes of the string the wallet was given
///    (`utxo_<resource>_<commitment>`);
/// 5. the challenge, as the UTF-8 bytes of the exact string the site handed the wallet — for this
///    bridge that is the lowercase hex of the nonce, because that is the string the challenge
///    route returned and the page passed through unchanged.
///
/// The last point is why the challenge string is a parameter rather than reconstructed here: the
/// message binds *the bytes that were signed*, and only the caller knows which representation the
/// wallet actually received.
pub fn ownership_proof_message(
    network: u8,
    resource: &ResourceAddress,
    substate_id: &str,
    challenge_string: &str,
) -> [u8; 64] {
    let digest = DomainSeparatedHasher::<
        blake2::Blake2b<blake2::digest::consts::U64>,
        OwnershipProofDomain,
    >::new_with_label(OWNERSHIP_PROOF_LABEL)
    .chain([network])
    .chain(resource.to_string())
    .chain(substate_id)
    .chain(challenge_string)
    .finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(digest.as_ref());
    out
}

// -------------------------------------------------------------------------------------------
// What the page may send
// -------------------------------------------------------------------------------------------

/// The three fields of a provider ownership proof, as Tari's documented dApp contract declares them.
///
/// `public_key` is present because the provider returns it, but it is **carried for logging only**
/// and is never a verification key: see [`CredentialDecision::ForgedKey`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipProof {
    #[serde(default)]
    pub public_key: String,
    pub public_nonce: String,
    pub signature: String,
}

/// A credential-proof submission. Exactly these fields, like [`crate::policy::ProveRequest`]:
/// there is no field an amount, a destination or a chosen UTXO could travel in.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialProofRequest {
    pub gate_id: String,
    /// Lowercase hex of the challenge nonce, as the challenge route issued it.
    pub challenge_nonce: String,
    /// Lowercase hex of the session commitment, as the challenge route issued it.
    pub session_commitment: String,
    /// The proof output's substate id, `utxo_<resource>_<commitment>`.
    pub substate_id: String,
    #[serde(flatten)]
    pub ownership: OwnershipProof,
}

// -------------------------------------------------------------------------------------------
// What the chain says
// -------------------------------------------------------------------------------------------

/// The parts of an on-chain UTXO this verifier needs, and nothing else.
///
/// No value, no mask, no encrypted data: the floor is public, the key is public, and everything
/// else about the output is none of the bridge's business.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoOnChain {
    pub minimum_value_promise: u64,
    /// The one-time key authorising a key-path spend, when the auth path is a key path.
    pub auth_key: Option<[u8; 32]>,
    /// Whether the indexer's answer was itself verified against the shard group committee by
    /// merkle proof.
    ///
    /// `false` means the value was served unverified — which is exactly the case where a malicious
    /// or compromised indexer could hand the relying site a fabricated floor or key for an output
    /// that does not exist, or a stale value for one that was spent. An access decision built on
    /// unverified chain data is not a decision the bridge is willing to make, so the verifier
    /// refuses these. The cost is real and documented: on networks with substate proofs disabled,
    /// or in the window after an epoch change when no committee member can supply a proof yet,
    /// credential proofs are unavailable. Fail-closed is the correct trade for an authorisation
    /// path; the consensus mode does not depend on the indexer at all.
    pub verified: bool,
}

/// Reads chain state, so the verifier can be tested without an indexer.
///
/// Native `async fn` in a trait, like [`crate::wallet::WalletChannel`]: never used as a trait
/// object, and `Bridge` is generic over it for the same reason.
#[allow(async_fn_in_trait)]
pub trait ChainReader {
    /// The current state of one UTXO, or an error when it is spent, unknown, or unreachable.
    ///
    /// The error case is load-bearing: the cohort's indexer answers a lookup for a spent UTXO with
    /// `InputSubstateIsDown`, so "error" is precisely how "no longer unspent" reaches this module.
    async fn utxo(&self, address: &UtxoAddress) -> Result<UtxoOnChain, String>;
}

/// The no-reader default. A bridge built without a chain reader refuses credential proofs with an
/// honest reason rather than verifying against nothing.
pub struct NoChainReader;

impl ChainReader for NoChainReader {
    async fn utxo(&self, _address: &UtxoAddress) -> Result<UtxoOnChain, String> {
        Err("no chain reader is configured on this bridge".into())
    }
}

// -------------------------------------------------------------------------------------------
// The verifier
// -------------------------------------------------------------------------------------------

/// Why a credential proof was refused. Every variant is a fact a user or site can act on, and none
/// of them leaks a balance: the only quantities named are public ones.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredentialRefusal {
    #[error("GG: the substate id is not a UTXO of this network: {0}")]
    NotAUtxo(String),
    #[error("GG: the proof output is spent or unknown: {0}")]
    Unspent(String),
    #[error("GG: the proof output belongs to {found}, but this gate watches {expected}")]
    WrongResource { expected: String, found: String },
    #[error("GG: the output's on-chain floor is {attested}, below this gate's {required}")]
    BelowThreshold { attested: u64, required: u64 },
    #[error(
        "GG: the output's spend authorisation is not a key path, so ownership cannot be proven"
    )]
    NotKeySpendable,
    #[error("GG: the indexer answered without a merkle-verified value; credential proofs refuse unverified chain data")]
    UnverifiedChainData,
    #[error("GG: the ownership signature does not verify against the output's on-chain key")]
    ForgedKey,
    #[error("GG: malformed ownership proof: {0}")]
    Malformed(String),
    #[error("GG: {0}")]
    Chain(String),
}

/// What a verified credential proof attests. Deliberately a different type from the consensus
/// [`crate::session::PublicProof`]: a credential receipt names the output it stands on, which is
/// the property that makes it Mode B.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialReceipt {
    /// Which gate verified this. A downstream consumer (the Telegram bot or Privacy Lab) must check the
    /// receipt names the gate it cares about — a receipt is evidence about one gate, not a
    /// general-purpose pass, and this field is what makes that check possible.
    pub gate_id: String,
    pub attested_minimum: u64,
    /// The threshold the verifying gate required, in the resource's smallest unit. A receipt must
    /// record what was asked, not just what was shown: the relying site compares floor ≥
    /// required against the gate's policy in force, and the frontend renders both sides of that
    /// comparison from this receipt alone.
    pub required_minimum: u64,
    /// The output the proof stands on. Public by construction in this mode; documented as the
    /// linkability cost in `docs/PROVIDER_COMPATIBILITY.md` §3.
    pub substate_id: String,
    pub mode: &'static str,
}

/// Verifies one credential proof against chain state and a challenge the bridge itself minted.
///
/// `expected` is everything the bridge knows from its own book: the gate's policy, the network the
/// gate is bound to, and the challenge the page claims to be answering.
pub struct CredentialVerifier<'a> {
    /// The gate this verification is for, recorded into the receipt.
    pub gate_id: &'a str,
    pub network: u8,
    pub threshold: u64,
    pub resource: &'a ResourceAddress,
    /// The challenge string exactly as the wallet received it.
    pub challenge_string: &'a str,
}

impl CredentialVerifier<'_> {
    pub async fn verify(
        &self,
        reader: &impl ChainReader,
        request: &CredentialProofRequest,
    ) -> Result<CredentialReceipt, CredentialRefusal> {
        let address = UtxoAddress::from_str(&request.substate_id)
            .map_err(|e| CredentialRefusal::NotAUtxo(format!("{e}")))?;
        if address.resource_address() != self.resource {
            return Err(CredentialRefusal::WrongResource {
                expected: self.resource.to_string(),
                found: address.resource_address().to_string(),
            });
        }

        // Chain state, read here. A spent output refuses here: the indexer errors on a DOWN
        // substate, and that error is exactly the "no longer unspent" signal.
        let on_chain = reader
            .utxo(&address)
            .await
            .map_err(CredentialRefusal::Unspent)?;

        // Indexer trust, stated as a rule: the floor and the key come from a remote service. When
        // that service cannot prove its answer (merkle verification against the committee), the
        // answer is not evidence and the proof is refused. See `UtxoOnChain::verified`.
        if !on_chain.verified {
            return Err(CredentialRefusal::UnverifiedChainData);
        }

        if on_chain.minimum_value_promise < self.threshold {
            return Err(CredentialRefusal::BelowThreshold {
                attested: on_chain.minimum_value_promise,
                required: self.threshold,
            });
        }
        let Some(auth_key) = on_chain.auth_key else {
            return Err(CredentialRefusal::NotKeySpendable);
        };

        self.verify_signature(&request.ownership, &auth_key, &request.substate_id)?;

        Ok(CredentialReceipt {
            gate_id: self.gate_id.to_string(),
            attested_minimum: on_chain.minimum_value_promise,
            required_minimum: self.threshold,
            substate_id: request.substate_id.clone(),
            mode: "credential",
        })
    }

    /// The signature check, isolated so its failure mode is explicit.
    ///
    /// The verification key is the **on-chain** `auth.Key`; the page-supplied `public_key` is never
    /// consulted. A signature over a key the page chose would let anyone claim anyone's output,
    /// which is the exact attack the provider docs warn about.
    fn verify_signature(
        &self,
        proof: &OwnershipProof,
        auth_key: &[u8; 32],
        substate_id: &str,
    ) -> Result<(), CredentialRefusal> {
        let message = ownership_proof_message(
            self.network,
            self.resource,
            substate_id,
            self.challenge_string,
        );

        let key = RistrettoPublicKey::from_canonical_bytes(auth_key).map_err(|_| {
            CredentialRefusal::Malformed("the on-chain auth key is not a valid public key".into())
        })?;
        let nonce = hex::decode(&proof.public_nonce)
            .ok()
            .and_then(|b| RistrettoPublicKey::from_canonical_bytes(&b).ok())
            .ok_or_else(|| {
                CredentialRefusal::Malformed("public_nonce is not a hex public key".into())
            })?;
        let scalar_bytes = hex::decode(&proof.signature)
            .ok()
            .filter(|b| b.len() == 32)
            .ok_or_else(|| CredentialRefusal::Malformed("signature is not 32 hex bytes".into()))?;
        let scalar = RistrettoSecretKey::from_canonical_bytes(&scalar_bytes)
            .map_err(|_| CredentialRefusal::Malformed("signature is not a valid scalar".into()))?;

        let signature =
            SchnorrSignature::<RistrettoPublicKey, RistrettoSecretKey, SchnorrSigChallenge>::new(
                nonce, scalar,
            );
        // The message here is the digest the wallet signed; `verify` derives the Schnorr challenge
        // from it under `com.tari.schnorr_signature.v1.challenge`, the same construction on both
        // sides of the wire.
        if !signature.verify(&key, message) {
            return Err(CredentialRefusal::ForgedKey);
        }
        Ok(())
    }
}

/// The public key a provider reported, decoded — for the log line a user might want, never for
/// verification. Separated out so nothing can accidentally verify against it.
pub fn reported_key_is_the_auth_key(proof: &OwnershipProof, auth_key: &[u8; 32]) -> bool {
    hex::decode(&proof.public_key)
        .ok()
        .filter(|b| b.len() == 32)
        .is_some_and(|b| b.as_slice() == auth_key)
}

/// The byte type the chain stores, re-exported for the production reader's signature.
pub type AuthKeyBytes = RistrettoPublicKeyBytes;

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rng;
    use tari_crypto::keys::{PublicKey as _, SecretKey as _};
    use tari_crypto::tari_utilities::ByteArray as _;

    const NETWORK: u8 = 0x10; // localnet

    struct FixedReader {
        promise: u64,
        auth_key: Option<[u8; 32]>,
        error: Option<String>,
        verified: bool,
    }

    impl FixedReader {
        fn ok(promise: u64, auth_key: [u8; 32]) -> Self {
            Self {
                verified: true,
                promise,
                auth_key: Some(auth_key),
                error: None,
            }
        }
    }

    impl ChainReader for FixedReader {
        async fn utxo(&self, _address: &UtxoAddress) -> Result<UtxoOnChain, String> {
            if let Some(e) = &self.error {
                return Err(e.clone());
            }
            Ok(UtxoOnChain {
                minimum_value_promise: self.promise,
                auth_key: self.auth_key,
                verified: self.verified,
            })
        }
    }

    fn resource(byte: u8) -> ResourceAddress {
        ResourceAddress::new(tari_template_lib_types::ObjectKey::from_array([byte; 32]))
    }

    fn substate_id(res: &ResourceAddress) -> String {
        // The string form the wallets produce and the page passes through: the resource enters as
        // its bare object key, without the `resource_` prefix — `utxo_{resource}_{id}` is what
        // `UtxoAddress::from_str` parses. Only the resource half is checked against the gate; the
        // id half is arbitrary here.
        format!(
            "utxo_{}_2c713522a4aaf79f2b219d869b5033d3d71d63c0537e5e0bbed2d717d8b2a67e",
            res.as_object_key()
        )
    }

    /// A submission signed by the holder of `secret`, exactly as the wallet would produce it: the
    /// signature's nonce is fresh, the reported key is the secret's public key, and the message is
    /// the framed one.
    fn request(
        res: &ResourceAddress,
        challenge: &str,
        secret: &RistrettoSecretKey,
    ) -> CredentialProofRequest {
        let message = ownership_proof_message(NETWORK, res, &substate_id(res), challenge);
        let signature = SchnorrSignature::<
            RistrettoPublicKey,
            RistrettoSecretKey,
            SchnorrSigChallenge,
        >::sign(secret, &message, &mut rng())
        .unwrap();
        let key = RistrettoPublicKey::from_secret_key(secret);
        CredentialProofRequest {
            gate_id: "g1".into(),
            challenge_nonce: challenge.into(),
            session_commitment: "11".repeat(32),
            substate_id: substate_id(res),
            ownership: OwnershipProof {
                public_key: hex::encode(key.as_bytes()),
                public_nonce: hex::encode(signature.get_public_nonce().as_bytes()),
                signature: hex::encode(signature.get_signature().as_bytes()),
            },
        }
    }

    fn verifier<'a>(
        res: &'a ResourceAddress,
        threshold: u64,
        challenge: &'a str,
    ) -> CredentialVerifier<'a> {
        CredentialVerifier {
            gate_id: "g1",
            network: NETWORK,
            threshold,
            resource: res,
            challenge_string: challenge,
        }
    }

    async fn verify_with(
        reader: &FixedReader,
        v: &CredentialVerifier<'_>,
        req: &CredentialProofRequest,
    ) {
        let _ = v.verify(reader, req).await;
    }

    /// `ByteArray::as_bytes` returns a slice; the verifier's `UtxoOnChain` carries an array.
    fn key_bytes(pk: &RistrettoPublicKey) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(pk.as_bytes());
        out
    }

    fn keypair() -> (RistrettoSecretKey, RistrettoPublicKey) {
        let k = RistrettoSecretKey::random(&mut rng());
        let p = RistrettoPublicKey::from_secret_key(&k);
        (k, p)
    }

    #[tokio::test]
    async fn a_true_credential_proof_is_accepted_with_the_chain_floor() {
        let res = resource(7);
        let (sk, pk) = keypair();
        let req = request(&res, "9d69d80b", &sk);
        let reader = FixedReader::ok(50_000, key_bytes(&pk));
        let v = verifier(&res, 10_000, "9d69d80b");

        let receipt = v
            .verify(&reader, &req)
            .await
            .expect("a true proof verifies");
        assert_eq!(
            receipt.attested_minimum, 50_000,
            "the floor is the chain's, not the request's echo"
        );
        assert_eq!(receipt.mode, "credential");
        assert!(receipt.substate_id.contains("utxo_"));
        let _ = sk;
    }

    #[tokio::test]
    async fn a_signature_over_a_self_reported_key_is_refused() {
        // The page's publicKey is a different key from the on-chain auth key. Verification must
        // bind to the chain key, so this refuses even though the signature is internally valid.
        let res = resource(7);
        let (sk1, pk1) = keypair();
        let (sk2, pk2) = keypair();
        let req = request(&res, "9d69d80b", &sk1);
        // The chain holds pk2's key; the page reported pk1.
        let reader = FixedReader::ok(50_000, key_bytes(&pk2));
        let v = verifier(&res, 10_000, "9d69d80b");

        let err = v
            .verify(&reader, &req)
            .await
            .expect_err("a forged key must refuse");
        assert!(matches!(err, CredentialRefusal::ForgedKey), "{err}");
    }

    #[tokio::test]
    async fn a_proof_for_a_different_challenge_string_is_refused() {
        let res = resource(7);
        let (sk, pk) = keypair();
        // Signed over challenge A; verified against challenge B.
        let req = request(
            &res,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &sk,
        );
        let reader = FixedReader::ok(50_000, key_bytes(&pk));
        let v = verifier(
            &res,
            10_000,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );

        let err = v
            .verify(&reader, &req)
            .await
            .expect_err("a replayed signature must refuse");
        assert!(matches!(err, CredentialRefusal::ForgedKey), "{err}");
    }

    #[tokio::test]
    async fn a_proof_signed_for_another_network_is_refused() {
        // The network byte is part of the signed message, so a proof minted on one chain is not a
        // proof on another. The verifier hashes with the GATE's network; a wallet that signed for
        // a different cohort produced different bytes, and the signature check refuses.
        let res = resource(7);
        let (sk, pk) = keypair();
        // Signed with mainnet's byte; verified against localnet's.
        let message = ownership_proof_message(0x00, &res, &substate_id(&res), "9d69d80b");
        let signature = SchnorrSignature::<RistrettoPublicKey, RistrettoSecretKey, SchnorrSigChallenge>::sign(
            &sk, &message, &mut rng(),
        )
        .unwrap();
        let req = CredentialProofRequest {
            gate_id: "g1".into(),
            challenge_nonce: "9d69d80b".into(),
            session_commitment: "11".repeat(32),
            substate_id: substate_id(&res),
            ownership: OwnershipProof {
                public_key: hex::encode(RistrettoPublicKey::from_secret_key(&sk).as_bytes()),
                public_nonce: hex::encode(signature.get_public_nonce().as_bytes()),
                signature: hex::encode(signature.get_signature().as_bytes()),
            },
        };
        let reader = FixedReader::ok(50_000, key_bytes(&pk));
        let v = verifier(&res, 10_000, "9d69d80b");

        let err = v.verify(&reader, &req).await.expect_err("a cross-network proof must refuse");
        assert!(matches!(err, CredentialRefusal::ForgedKey), "{err}");
    }

    #[tokio::test]
    async fn the_receipt_names_the_gate_that_verified_it() {
        // Downstream consumers (the Telegram bot or Privacy Lab) must be able to check a receipt is for
        // the gate they care about; this is the field that makes that possible.
        let res = resource(7);
        let (sk, pk) = keypair();
        let req = request(&res, "9d69d80b", &sk);
        let reader = FixedReader::ok(50_000, key_bytes(&pk));
        let v = verifier(&res, 10_000, "9d69d80b");

        let receipt = v.verify(&reader, &req).await.expect("a true proof verifies");
        assert_eq!(receipt.gate_id, "g1");
    }

    #[tokio::test]
    async fn a_proof_for_a_different_resource_is_refused_before_the_chain_is_read() {
        let gate_resource = resource(7);
        let other = resource(9);
        let (sk, pk) = keypair();
        let req = request(&other, "9d69d80b", &sk);
        let reader = FixedReader::ok(50_000, key_bytes(&pk));
        let v = verifier(&gate_resource, 10_000, "9d69d80b");

        let err = v
            .verify(&reader, &req)
            .await
            .expect_err("a cross-resource proof must refuse");
        assert!(
            matches!(err, CredentialRefusal::WrongResource { .. }),
            "the resource check must run first: {err}"
        );
        assert!(
            format!("{err}").contains(&gate_resource.to_string()),
            "the refusal names both resources: {err}"
        );
    }

    #[tokio::test]
    async fn a_spent_output_is_refused_with_the_reader_error() {
        let res = resource(7);
        let (sk, pk) = keypair();
        let req = request(&res, "9d69d80b", &sk);
        let reader = FixedReader {
            promise: 50_000,
            auth_key: Some(key_bytes(&pk)),
            error: Some("InputSubstateIsDown".into()),
            verified: true,
        };
        let v = verifier(&res, 10_000, "9d69d80b");

        let err = v
            .verify(&reader, &req)
            .await
            .expect_err("a spent output must refuse");
        assert!(matches!(err, CredentialRefusal::Unspent(_)), "{err}");
        assert!(
            format!("{err}").contains("spent"),
            "the refusal says what happened: {err}"
        );
    }

    #[tokio::test]
    async fn a_floor_below_the_threshold_is_refused_from_chain_state() {
        let res = resource(7);
        let (sk, pk) = keypair();
        let req = request(&res, "9d69d80b", &sk);
        // The chain's promise is real but small; whatever the page claimed is ignored.
        let reader = FixedReader::ok(9_999, key_bytes(&pk));
        let v = verifier(&res, 10_000, "9d69d80b");

        let err = v
            .verify(&reader, &req)
            .await
            .expect_err("a sub-threshold floor must refuse");
        assert!(
            matches!(
                err,
                CredentialRefusal::BelowThreshold {
                    attested: 9_999,
                    required: 10_000
                }
            ),
            "{err}"
        );
    }

    #[tokio::test]
    async fn an_output_with_a_script_auth_path_is_refused() {
        let res = resource(7);
        let (sk, pk) = keypair();
        let req = request(&res, "9d69d80b", &sk);
        // `auth_key: None` is what a script-only auth path reads as: no key, so no ownership
        // proof can bind to this output.
        let reader = FixedReader { promise: 50_000, auth_key: None, error: None, verified: true };
        let v = verifier(&res, 10_000, "9d69d80b");

        let err = v
            .verify(&reader, &req)
            .await
            .expect_err("a script-only output must refuse");
        assert!(matches!(err, CredentialRefusal::NotKeySpendable), "{err}");
    }

    #[tokio::test]
    async fn malformed_signature_material_is_refused_as_malformed_not_forged() {
        let res = resource(7);
        let (sk, pk) = keypair();
        let mut req = request(&res, "9d69d80b", &sk);
        req.ownership.signature = "zz".into();
        let reader = FixedReader::ok(50_000, key_bytes(&pk));
        let v = verifier(&res, 10_000, "9d69d80b");

        let err = v
            .verify(&reader, &req)
            .await
            .expect_err("garbage must refuse");
        assert!(matches!(err, CredentialRefusal::Malformed(_)), "{err}");
    }

    #[tokio::test]
    async fn an_unverified_indexer_answer_is_refused_even_when_everything_else_matches() {
        // A compromised indexer could fabricate a floor and a key for an output that does not
        // exist, or serve a stale record for one that was spent. The merkle-verified flag is the
        // indexer's own statement that it did neither; without it there is no evidence, and an
        // authorisation decision is not made on no evidence.
        let res = resource(7);
        let (sk, pk) = keypair();
        let req = request(&res, "9d69d80b", &sk);
        let reader = FixedReader {
            promise: 50_000,
            auth_key: Some(key_bytes(&pk)),
            error: None,
            verified: false,
        };
        let v = verifier(&res, 10_000, "9d69d80b");

        let err = v.verify(&reader, &req).await.expect_err("unverified chain data must refuse");
        assert!(matches!(err, CredentialRefusal::UnverifiedChainData), "{err}");
    }

    #[tokio::test]
    async fn a_bridge_without_a_chain_reader_refuses_rather_than_verifying_nothing() {
        let res = resource(7);
        let (sk, pk) = keypair();
        let req = request(&res, "9d69d80b", &sk);
        let reader = NoChainReader;
        let v = verifier(&res, 10_000, "9d69d80b");

        let err = v
            .verify(&reader, &req)
            .await
            .expect_err("no reader, no verdict");
        assert!(matches!(err, CredentialRefusal::Unspent(_)), "{err}");
        assert!(format!("{err}").contains("no chain reader"), "{err}");
    }

    #[test]
    fn the_message_framing_is_length_prefixed_over_the_exact_strings() {
        // The property that makes this interoperate: chunk 0 is the doubled-suffix domain tag, and
        // the resource/substate/challenge enter as their UTF-8 *string* bytes. Asserted against a
        // hand-built expected value so a framing change here is caught even without a wallet.
        let res = resource(7);
        let tag = "com.tari.paylink.ownership_proof.v1.v1";
        let mut expected: Vec<u8> = Vec::new();
        let mut chunk = |out: &mut Vec<u8>, data: &[u8]| {
            out.extend_from_slice(&(data.len() as u64).to_le_bytes());
            out.extend_from_slice(data);
        };
        chunk(&mut expected, tag.as_bytes());
        chunk(&mut expected, &[NETWORK]);
        chunk(&mut expected, res.to_string().as_bytes());
        chunk(&mut expected, "utxo_x".as_bytes());
        chunk(&mut expected, "challenge-1".as_bytes());

        let got = ownership_proof_message(NETWORK, &res, "utxo_x", "challenge-1");
        // The digest is over exactly the byte stream above; hash it with the same fixed-size
        // hasher the production code uses, fed by hand rather than by the helper, so the two
        // constructions cannot share a bug.
        use blake2::digest::Digest;
        let mut hasher = blake2::Blake2b::<blake2::digest::consts::U64>::new();
        hasher.update(&expected);
        let want = hasher.finalize();
        assert_eq!(
            got.as_slice(),
            want.as_slice(),
            "the framing must match a direct hash of the chunk stream"
        );
    }

    #[test]
    fn a_request_body_cannot_carry_an_amount_or_a_destination() {
        // The same wire discipline as ProveRequest: unknown fields are refused, so no proof
        // submission can smuggle in an amount, a recipient, or a chosen UTXO.
        let json = serde_json::json!({
            "gate_id": "g1",
            "challenge_nonce": "9d69d80b",
            "session_commitment": "11",
            "substate_id": "utxo_x",
            "public_key": "aa",
            "public_nonce": "bb",
            "signature": "cc",
            "amount": 100_000u64,
        });
        let parsed: Result<CredentialProofRequest, _> = serde_json::from_value(json);
        assert!(
            parsed.is_err(),
            "an amount field must be refused, got {parsed:?}"
        );
    }

    #[tokio::test]
    async fn the_reported_key_may_be_logged_but_is_never_the_verifier() {
        // Documents the rule in code: when the reported key differs from the chain key, the proof
        // refuses (ForgedKey above); when it matches, `reported_key_is_the_auth_key` is available
        // for logs. The verification path takes `auth_key` directly and never this helper.
        let res = resource(7);
        let (sk, pk) = keypair();
        let req = request(&res, "9d69d80b", &sk);
        let on_chain = key_bytes(&pk);
        assert!(reported_key_is_the_auth_key(&req.ownership, &on_chain));
        let (sk2, pk2) = keypair();
        assert!(!reported_key_is_the_auth_key(
            &req.ownership,
            &key_bytes(&pk2)
        ));
    }

    #[tokio::test]
    async fn verify_and_log_are_separate_calls_so_the_key_cannot_be_swapped_back_in() {
        // The full path a real submission takes, with the reported key deliberately wrong: the
        // verifier ignores it. The test that proves the rule is therefore the inverse of the
        // obvious one: a *lying* reported key still verifies, because the verdict never read it --
        // and a signature actually made by another key refuses (see the self-reported-key test
        // above). Both halves together are the property the docs' "never against publicKey at
        // face value" warning asks for.
        let res = resource(7);
        let (sk, pk) = keypair();
        let (_sk2, pk2) = keypair();
        let mut req = request(&res, "9d69d80b", &sk);
        req.ownership.public_key = hex::encode(pk2.as_bytes()); // lie about who we are
        let reader = FixedReader::ok(50_000, key_bytes(&pk));
        let v = verifier(&res, 10_000, "9d69d80b");
        let receipt = v.verify(&reader, &req).await.expect(
            "a lying reported key must not change the verdict: verification binds to the chain key",
        );
        assert_eq!(receipt.attested_minimum, 50_000);
    }
}
