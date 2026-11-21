//! Ghost Gate's canonical 223-byte GGBP-1 v3 challenge codec.
//!
//! The wallet-facing challenge is exactly the fixed prefix of
//! [`Ggbp1Challenge::canonical_message`](crate::v3::Ggbp1Challenge::canonical_message):
//! it names the network, genesis, origin, gate, configuration version, subject, threshold,
//! nonce, expiry and commitment-generator fingerprint, and stops before the output count and
//! the wallet-selected output hashes. The wallet appends those when it signs.

use sha2::{Digest, Sha256};
use tari_crypto::ristretto::RistrettoPublicKey;
use tari_utilities::ByteArray;
use thiserror::Error;

use crate::v3::{GGBP1_EXPERIMENTAL_VERSION, Ggbp1Challenge, expected_commitment_generator_fingerprint};

/// MainNet's GGBP-1 network byte.
pub const MAINNET_NETWORK: u8 = 0x00;
/// Esmeralda's GGBP-1 network byte. GGBP-1 v3 is live only on Esmeralda.
pub const ESMERALDA_NETWORK: u8 = 0x26;
/// Esmeralda genesis hash, as published by the wallet's `GGBP1_GENESIS_HASH` table.
pub const ESMERALDA_GENESIS_HASH: [u8; 32] = [
    0x3c, 0x36, 0x81, 0xad, 0x31, 0x8e, 0xb5, 0x4c, 0xa3, 0xf3, 0xe8, 0xae, 0xd7, 0x9d, 0x3d, 0x20,
    0x7d, 0x94, 0xa5, 0x29, 0x1a, 0xec, 0x84, 0xba, 0x1a, 0x0b, 0x62, 0x86, 0x33, 0xdb, 0x36, 0x21,
];

/// The fixed challenge length the wallet validates before it will sign.
pub const CHALLENGE_BYTES: usize = 223;
const CHALLENGE_MAGIC: &[u8; 5] = b"GGBP1";

/// Why a 223-byte challenge was refused.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChallengeError {
    #[error("challenge must be exactly {CHALLENGE_BYTES} bytes")]
    WrongLength,
    #[error("challenge magic is not GGBP1")]
    WrongMagic,
    #[error("unsupported GGBP-1 challenge version")]
    UnsupportedVersion,
    #[error("challenge threshold must be nonzero")]
    ZeroThreshold,
    #[error("challenge subject key is invalid")]
    InvalidSubjectKey,
    #[error("challenge subject key is the identity point")]
    IdentitySubjectKey,
    #[error("challenge commitment-generator fingerprint is not the supported Tari generator set")]
    CommitmentGeneratorMismatch,
}

/// Encodes the fixed 223-byte challenge the wallet receives.
pub fn encode_challenge(challenge: &Ggbp1Challenge) -> Result<[u8; CHALLENGE_BYTES], ChallengeError> {
    validate_challenge_fields(challenge)?;
    let mut bytes = [0u8; CHALLENGE_BYTES];
    let mut cursor = 0usize;
    bytes[cursor..cursor + 5].copy_from_slice(CHALLENGE_MAGIC);
    cursor += 5;
    bytes[cursor] = GGBP1_EXPERIMENTAL_VERSION;
    cursor += 1;
    bytes[cursor] = challenge.network;
    cursor += 1;
    bytes[cursor..cursor + 32].copy_from_slice(&challenge.genesis_hash);
    cursor += 32;
    bytes[cursor..cursor + 32].copy_from_slice(&challenge.origin_hash);
    cursor += 32;
    bytes[cursor..cursor + 16].copy_from_slice(&challenge.gate_id);
    cursor += 16;
    bytes[cursor..cursor + 8].copy_from_slice(&challenge.gate_configuration_version.to_le_bytes());
    cursor += 8;
    bytes[cursor..cursor + 16].copy_from_slice(&challenge.subject_id);
    cursor += 16;
    bytes[cursor..cursor + 32].copy_from_slice(challenge.subject_authentication_public_key.as_bytes());
    cursor += 32;
    bytes[cursor..cursor + 8].copy_from_slice(&challenge.threshold_micro_xtm.to_le_bytes());
    cursor += 8;
    bytes[cursor..cursor + 32].copy_from_slice(&challenge.nonce);
    cursor += 32;
    bytes[cursor..cursor + 8].copy_from_slice(&challenge.expires_at_unix_seconds.to_le_bytes());
    cursor += 8;
    bytes[cursor..cursor + 32].copy_from_slice(&challenge.commitment_generator_fingerprint);
    cursor += 32;
    debug_assert_eq!(cursor, CHALLENGE_BYTES);
    Ok(bytes)
}

/// Parses exactly one 223-byte challenge. Trailing bytes are refused: the wallet does the same,
/// so a server that accepted a longer buffer would be reading a different message than the signer.
pub fn decode_challenge(bytes: &[u8]) -> Result<Ggbp1Challenge, ChallengeError> {
    if bytes.len() != CHALLENGE_BYTES {
        return Err(ChallengeError::WrongLength);
    }
    let mut cursor = 0usize;
    if &bytes[cursor..cursor + 5] != CHALLENGE_MAGIC {
        return Err(ChallengeError::WrongMagic);
    }
    cursor += 5;
    if bytes[cursor] != GGBP1_EXPERIMENTAL_VERSION {
        return Err(ChallengeError::UnsupportedVersion);
    }
    cursor += 1;
    let network = bytes[cursor];
    cursor += 1;
    let genesis_hash = take_array::<32>(bytes, &mut cursor);
    let origin_hash = take_array::<32>(bytes, &mut cursor);
    let gate_id = take_array::<16>(bytes, &mut cursor);
    let gate_configuration_version = u64::from_le_bytes(take_array::<8>(bytes, &mut cursor));
    let subject_id = take_array::<16>(bytes, &mut cursor);
    let subject_authentication_public_key = RistrettoPublicKey::from_canonical_bytes(&take_array::<32>(bytes, &mut cursor))
        .map_err(|_| ChallengeError::InvalidSubjectKey)?;
    let threshold_micro_xtm = u64::from_le_bytes(take_array::<8>(bytes, &mut cursor));
    let nonce = take_array::<32>(bytes, &mut cursor);
    let expires_at_unix_seconds = u64::from_le_bytes(take_array::<8>(bytes, &mut cursor));
    let commitment_generator_fingerprint = take_array::<32>(bytes, &mut cursor);
    debug_assert_eq!(cursor, CHALLENGE_BYTES);

    let challenge = Ggbp1Challenge {
        network,
        genesis_hash,
        origin_hash,
        gate_id,
        gate_configuration_version,
        subject_id,
        subject_authentication_public_key,
        threshold_micro_xtm,
        nonce,
        expires_at_unix_seconds,
        commitment_generator_fingerprint,
    };
    validate_challenge_fields(&challenge)?;
    Ok(challenge)
}

/// The deterministic 16-byte gate identity carried in a GGBP-1 challenge.
///
/// The wallet treats this field as opaque; Ghost Gate derives it from the registered gate id
/// under a fixed domain so the same gate always produces the same bytes and a caller cannot
/// substitute a different gate's identity.
pub fn gate_id_bytes(gate_id: &str) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(b"ghost-gate.ggbp1.gate-id.v1");
    hasher.update(gate_id.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes
}

/// A stable configuration version for a gate's threshold and network.
///
/// The value is informational to the wallet and authoritative only to Ghost Gate. Deriving it
/// from the registered policy means a threshold change produces a different challenge version,
/// so an outstanding proof cannot be replayed against a replaced policy.
pub fn gate_configuration_version(gate_id: &str, threshold_micro_xtm: u64, network: u8) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"ghost-gate.ggbp1.gate-configuration-version.v1");
    hasher.update(gate_id.as_bytes());
    hasher.update(threshold_micro_xtm.to_le_bytes());
    hasher.update([network]);
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("sha256 prefix is 8 bytes"))
}

fn validate_challenge_fields(challenge: &Ggbp1Challenge) -> Result<(), ChallengeError> {
    if challenge.threshold_micro_xtm == 0 {
        return Err(ChallengeError::ZeroThreshold);
    }
    if challenge.subject_authentication_public_key == RistrettoPublicKey::default() {
        return Err(ChallengeError::IdentitySubjectKey);
    }
    if challenge.commitment_generator_fingerprint != expected_commitment_generator_fingerprint() {
        return Err(ChallengeError::CommitmentGeneratorMismatch);
    }
    Ok(())
}

fn take_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> [u8; N] {
    let mut value = [0u8; N];
    value.copy_from_slice(&bytes[*cursor..*cursor + N]);
    *cursor += N;
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use tari_crypto::{keys::PublicKey, ristretto::RistrettoSecretKey};

    fn challenge() -> Ggbp1Challenge {
        let secret = RistrettoSecretKey::from(7u64);
        Ggbp1Challenge {
            network: ESMERALDA_NETWORK,
            genesis_hash: ESMERALDA_GENESIS_HASH,
            origin_hash: [2u8; 32],
            gate_id: gate_id_bytes("xtmtest"),
            gate_configuration_version: gate_configuration_version("xtmtest", 1_000_000, ESMERALDA_NETWORK),
            subject_id: [3u8; 16],
            subject_authentication_public_key: RistrettoPublicKey::from_secret_key(&secret),
            threshold_micro_xtm: 1_000_000,
            nonce: [4u8; 32],
            expires_at_unix_seconds: 1_800_000_000,
            commitment_generator_fingerprint: expected_commitment_generator_fingerprint(),
        }
    }

    #[test]
    fn challenge_is_exactly_223_bytes_and_round_trips() {
        let original = challenge();
        let encoded = encode_challenge(&original).unwrap();
        assert_eq!(encoded.len(), CHALLENGE_BYTES);
        assert_eq!(&encoded[..6], b"GGBP1\x03");
        let decoded = decode_challenge(&encoded).unwrap();
        assert_eq!(decoded, original);
        // The 223-byte challenge is the fixed prefix of the signed canonical message.
        let canonical = original.canonical_message(&[[9u8; 32]]).unwrap();
        assert_eq!(&canonical[..CHALLENGE_BYTES], encoded);
    }

    #[test]
    fn a_short_long_or_retagged_challenge_is_refused() {
        let encoded = encode_challenge(&challenge()).unwrap();
        assert_eq!(decode_challenge(&encoded[..CHALLENGE_BYTES - 1]).unwrap_err(), ChallengeError::WrongLength);
        let mut longer = encoded.to_vec();
        longer.push(0);
        assert_eq!(decode_challenge(&longer).unwrap_err(), ChallengeError::WrongLength);
        let mut wrong_version = encoded;
        wrong_version[5] = 2;
        assert_eq!(decode_challenge(&wrong_version).unwrap_err(), ChallengeError::UnsupportedVersion);
    }

    #[test]
    fn zero_threshold_and_identity_subject_are_refused() {
        let mut zero = challenge();
        zero.threshold_micro_xtm = 0;
        assert_eq!(encode_challenge(&zero).unwrap_err(), ChallengeError::ZeroThreshold);
        let mut identity = challenge();
        identity.subject_authentication_public_key = RistrettoPublicKey::default();
        assert_eq!(encode_challenge(&identity).unwrap_err(), ChallengeError::IdentitySubjectKey);
    }

    #[test]
    fn gate_identity_and_configuration_version_are_deterministic() {
        assert_eq!(gate_id_bytes("xtmtest"), gate_id_bytes("xtmtest"));
        assert_ne!(gate_id_bytes("xtmtest"), gate_id_bytes("xtmtest2"));
        assert_ne!(
            gate_configuration_version("xtmtest", 1, ESMERALDA_NETWORK),
            gate_configuration_version("xtmtest", 2, ESMERALDA_NETWORK)
        );
    }
}
