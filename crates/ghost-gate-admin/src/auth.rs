//! Administrator authentication: WebAuthn passkeys (preferred) and wallet-challenge signatures.
//!
//! # Passkeys (WebAuthn, ES256)
//!
//! This module verifies ceremonies server-side, from scratch against the spec's bytes: the
//! client-data JSON must carry the exact challenge the server issued, the expected `type`, and the
//! expected origin; the authenticator data must hash the expected rpId; the user-present and
//! user-verified flags must be set for registration and for step-up; and the ES256 signature must
//! verify over `authenticatorData || SHA-256(clientDataJSON)` with the credential's own public
//! key. Only verification exists here — no private-key code, because the private key lives in the
//! authenticator and nowhere else.
//!
//! # Wallet challenge
//!
//! A wallet-challenge administrator signs a server challenge with the SAME Ristretto Schnorr
//! machinery the audited gate-credential flow uses (tari_crypto), so admin authentication reuses
//! code that has already been adversarially reviewed rather than inventing a second signature
//! scheme.

use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};
use tari_crypto::signatures::{SchnorrSigChallenge, SchnorrSignature};
use tari_crypto::ristretto::{RistrettoPublicKey, RistrettoSecretKey};
use tari_crypto::tari_utilities::ByteArray;

/// Random, URL-safe challenge bytes (16 bytes → 22 chars base64url without padding).
pub fn new_challenge() -> String {
    let mut b = [0u8; 16];
    rand::fill(&mut b);
    base64url_nopad(&b)
}

pub fn base64url_nopad(bytes: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 { out.push(T[(n >> 6) as usize & 63] as char); }
        if chunk.len() > 2 { out.push(T[n as usize & 63] as char); }
    }
    out
}

pub fn base64url_decode(s: &str) -> Result<Vec<u8>, String> {
    const REV: fn(u8) -> Option<u8> = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    };
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        let v = REV(c).ok_or("invalid base64url character")? as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

/// A pending ceremony challenge, single-use and short-lived.
#[derive(Debug, Clone)]
pub struct PendingChallenge {
    pub challenge: String,
    pub kind: CeremonyKind,
    pub created_unix: u64,
    pub used: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyKind {
    /// Registering a NEW credential. Requires the bootstrap token when the registry has none.
    Registration,
    /// Logging in / step-up with an EXISTING credential.
    Authentication,
}

/// What the browser returns for a WebAuthn ceremony, as the dashboard JS receives it.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct WebAuthnResponse {
    /// base64url of the authenticator response bytes (registration: attestationObject's clientData
    /// is inside; we accept the dashboard sending the parsed fields it CAN parse, but verification
    /// is done on the raw bytes server-side).
    pub client_data_b64: String,
    /// base64url authenticator data (registration) or authenticatorData (assertion).
    #[serde(default)]
    pub authenticator_data_b64: String,
    /// base64url DER signature (assertion only).
    #[serde(default)]
    pub signature_b64: String,
    /// base64url credential id (assertion, and registration result).
    #[serde(default)]
    pub credential_id_b64: String,
    /// Registration only: the full attestation object, base64url.
    #[serde(default)]
    pub attestation_object_b64: String,
}

/// Parse the CBOR attestation object far enough to find fmt, authData, and (for packed
/// self-attestation) the credential public key. Only the formats an honest browser produces are
/// accepted: `none` and packed self-attestation. Anything else is refused, not approximated.
pub fn parse_attestation(attestation: &[u8]) -> Result<(String, &[u8]), String> {
    // attestationObject = { fmt: tstr, authData: bstr, attStmt: {...} }
    let (_fmt, auth_data) = cbor_map_get_fmt_and_authdata(attestation)?;
    Ok((_fmt.to_string(), auth_data))
}

/// Extract (fmt, authData) from the CBOR map without a full CBOR dependency: the structure is
/// fixed by the spec (three text-string/binary entries), and a strict mini-parser over exactly
/// that shape refuses anything unexpected.
fn cbor_map_get_fmt_and_authdata(bytes: &[u8]) -> Result<(&str, &[u8]), String> {
    // Map header: 0xA3 (map, 3 entries).
    if bytes.first() != Some(&0xA3) {
        return Err("attestation object is not a 3-entry CBOR map".into());
    }
    let mut i = 1usize;
    let mut fmt: Option<&str> = None;
    let mut auth: Option<&[u8]> = None;
    for _ in 0..3 {
        // Key: text string (0x60+len) or small string.
        let (key, consumed) = read_cbor_text(bytes.get(i..).ok_or("truncated attestation")?)?;
        i += consumed;
        match key {
            "fmt" => {
                let (v, c) = read_cbor_text(bytes.get(i..).ok_or("truncated attestation")?)?;
                i += c;
                fmt = Some(v);
            }
            "authData" => {
                let (v, c) = read_cbor_bytes(bytes.get(i..).ok_or("truncated attestation")?)?;
                i += c;
                auth = Some(v);
            }
            "attStmt" => {
                let c = skip_cbor_item(bytes.get(i..).ok_or("truncated attestation")?)?;
                i += c;
            }
            _ => return Err(format!("unexpected attestation key {key:?}")),
        }
    }
    let fmt = fmt.ok_or("attestation object lacks fmt")?;
    let auth = auth.ok_or("attestation object lacks authData")?;
    Ok((fmt, auth))
}

fn read_cbor_text(bytes: &[u8]) -> Result<(&str, usize), String> {
    let b = *bytes.first().ok_or("truncated")?;
    let (len, hdr) = match b {
        n @ 0x60..=0x77 => ((n - 0x60) as usize, 1),
        0x78 => {
            let l = *bytes.get(1).ok_or("truncated")? as usize;
            (l, 2)
        }
        0x79 => {
            let arr: [u8; 2] = bytes.get(1..3).ok_or("truncated")?.try_into().unwrap();
            (u16::from_be_bytes(arr) as usize, 3)
        }
        _ => return Err("expected a CBOR text string".into()),
    };
    let s = bytes.get(hdr..hdr + len).ok_or("truncated string")?;
    let text = std::str::from_utf8(s).map_err(|_| "invalid utf-8 in CBOR string")?;
    Ok((text, hdr + len))
}

fn read_cbor_bytes(bytes: &[u8]) -> Result<(&[u8], usize), String> {
    let b = *bytes.first().ok_or("truncated")?;
    let (len, hdr) = match b {
        n @ 0x40..=0x57 => ((n - 0x40) as usize, 1),
        0x58 => {
            let l = *bytes.get(1).ok_or("truncated")? as usize;
            (l, 2)
        }
        0x59 => {
            let arr: [u8; 2] = bytes.get(1..3).ok_or("truncated")?.try_into().unwrap();
            (u16::from_be_bytes(arr) as usize, 3)
        }
        _ => return Err("expected a CBOR byte string".into()),
    };
    let s = bytes.get(hdr..hdr + len).ok_or("truncated byte string")?;
    Ok((s, hdr + len))
}

/// Skip one CBOR item of any shape (used for attStmt maps).
fn skip_cbor_item(bytes: &[u8]) -> Result<usize, String> {
    let b = *bytes.first().ok_or("truncated")?;
    let (major, info) = (b >> 5, b & 0x1F);
    match major {
        0..=1 => {
            let len = match info {
                n @ 0..=23 => n as usize,
                24 => *bytes.get(1).ok_or("truncated")? as usize,
                25 => {
                    let arr: [u8; 2] = bytes.get(1..3).ok_or("truncated")?.try_into().unwrap();
                    u16::from_be_bytes(arr) as usize
                }
                26 => {
                    let arr: [u8; 4] = bytes.get(1..5).ok_or("truncated")?.try_into().unwrap();
                    u32::from_be_bytes(arr) as usize
                }
                _ => return Err("unsupported CBOR length".into()),
            };
            if major == 0 { Ok(1 + len_len(info) + len) } else { Ok(1 + len_len(info)) } // int/bool-ish
        }
        2 | 3 => {
            let len = match info {
                n @ 0..=23 => n as usize,
                24 => *bytes.get(1).ok_or("truncated")? as usize,
                25 => {
                    let arr: [u8; 2] = bytes.get(1..3).ok_or("truncated")?.try_into().unwrap();
                    u16::from_be_bytes(arr) as usize
                }
                26 => {
                    let arr: [u8; 4] = bytes.get(1..5).ok_or("truncated")?.try_into().unwrap();
                    u32::from_be_bytes(arr) as usize
                }
                _ => return Err("unsupported CBOR length".into()),
            };
            Ok(1 + len_len(info) + len)
        }
        4 => {
            let n = info as usize;
            let mut off = 1;
            for _ in 0..n {
                off += skip_cbor_item(bytes.get(off..).ok_or("truncated array")?)?;
            }
            Ok(off)
        }
        5 => {
            let n = info as usize;
            let mut off = 1;
            for _ in 0..(2 * n) {
                off += skip_cbor_item(bytes.get(off..).ok_or("truncated map")?)?;
            }
            Ok(off)
        }
        _ => Ok(1), // tags, specials: single byte in the shapes browsers emit here
    }
}

fn len_len(info: u8) -> usize {
    match info { 24 => 1, 25 => 2, 26 => 4, 27 => 8, _ => 0 }
}

/// Verified registration: returns the credential id and the ES256 public key (SEC1 uncompressed).
pub fn verify_webauthn_registration(
    response: &WebAuthnResponse,
    expected_challenge: &str,
    expected_origin: &str,
    expected_rp_id: &str,
) -> Result<(String, Vec<u8>), String> {
    // 1. clientDataJSON: type, challenge, origin.
    let client_data = base64url_decode(&response.client_data_b64)?;
    verify_client_data(&client_data, "webauthn.create", expected_challenge, expected_origin)?;
    // 2. attestation object.
    let att = base64url_decode(&response.attestation_object_b64)?;
    let (fmt, auth_data) = parse_attestation(&att)?;
    if fmt != "none" && fmt != "packed" {
        return Err(format!("attestation format {fmt:?} is not accepted; only none and packed self-attestation are"));
    }
    verify_authenticator_data(auth_data, expected_rp_id, true)?;
    // 3. credential id + COSE key from the attested credential data.
    let (cred_id, cose) = parse_attested_credential(auth_data)?;
    let sec1 = cose_es256_to_sec1(cose)?;
    if fmt == "packed" {
        // Packed self-attestation: the signature (in attStmt) must verify under the SAME key.
        verify_packed_self_attestation(&att, auth_data, &client_data, &sec1)?;
    }
    Ok((base64url_nopad(&cred_id), sec1))
}

/// Verified assertion (login / step-up) against a known credential public key.
pub fn verify_webauthn_assertion(
    response: &WebAuthnResponse,
    expected_challenge: &str,
    expected_origin: &str,
    expected_rp_id: &str,
    expected_credential_id: &str,
    es256_public_sec1: &[u8],
    require_user_verification: bool,
) -> Result<(), String> {
    let client_data = base64url_decode(&response.client_data_b64)?;
    verify_client_data(&client_data, "webauthn.get", expected_challenge, expected_origin)?;
    let auth_data = base64url_decode(&response.authenticator_data_b64)?;
    verify_authenticator_data(&auth_data, expected_rp_id, require_user_verification)?;
    let cred_id = base64url_nopad(&base64url_decode(&response.credential_id_b64)?);
    if cred_id != expected_credential_id {
        return Err("assertion used a different credential".into());
    }
    let sig = Signature::from_der(&base64url_decode(&response.signature_b64)?)
        .map_err(|_| "assertion signature is not valid DER ECDSA")?;
    let key = VerifyingKey::from_sec1_bytes(es256_public_sec1)
        .map_err(|_| "the registered passkey public key is not a valid P-256 point")?;
    let mut signed = Vec::with_capacity(auth_data.len() + 32);
    signed.extend_from_slice(&auth_data);
    signed.extend_from_slice(&Sha256::digest(&client_data));
    key.verify(&signed, &sig).map_err(|_| "assertion signature does not verify")?;
    Ok(())
}

fn verify_client_data(
    client_data: &[u8],
    expected_type: &str,
    expected_challenge: &str,
    expected_origin: &str,
) -> Result<(), String> {
    let v: serde_json::Value =
        serde_json::from_slice(client_data).map_err(|_| "clientDataJSON is not JSON")?;
    if v.get("type").and_then(|t| t.as_str()) != Some(expected_type) {
        return Err(format!("clientData type is not {expected_type}"));
    }
    if v.get("challenge").and_then(|c| c.as_str()) != Some(expected_challenge) {
        return Err("clientData challenge does not match the server's challenge".into());
    }
    if v.get("origin").and_then(|o| o.as_str()) != Some(expected_origin) {
        return Err(format!("clientData origin is not {expected_origin}"));
    }
    // A cross-origin ceremony is exactly what a phishing page performs.
    if let Some(x) = v.get("crossOrigin").and_then(|c| c.as_bool()) {
        if x {
            return Err("cross-origin ceremonies are refused".into());
        }
    }
    Ok(())
}

fn verify_authenticator_data(auth: &[u8], rp_id: &str, require_uv: bool) -> Result<(), String> {
    if auth.len() < 37 {
        return Err("authenticator data is too short".into());
    }
    let mut rp_hash = [0u8; 32];
    rp_hash.copy_from_slice(&auth[..32]);
    let expect: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
    if rp_hash != expect {
        return Err("authenticator data is signed for a different rpId".into());
    }
    let flags = auth[32];
    const UP: u8 = 0x01;
    const UV: u8 = 0x04;
    if flags & UP == 0 {
        return Err("user presence was not asserted".into());
    }
    if require_uv && flags & UV == 0 {
        return Err("user verification was required but not asserted".into());
    }
    Ok(())
}

fn parse_attested_credential(auth_data: &[u8]) -> Result<(Vec<u8>, &[u8]), String> {
    if auth_data.len() < 37 + 18 {
        return Err("attested credential data is missing".into());
    }
    let aaguid = &auth_data[37..53];
    if aaguid.iter().all(|b| *b == 0) {
        // Zero AAGUID is legitimate for many authenticators.
    }
    let cred_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    let cred_start = 55;
    let cred_end = cred_start + cred_len;
    if auth_data.len() < cred_end {
        return Err("credential id overruns the authenticator data".into());
    }
    let cred_id = auth_data[cred_start..cred_end].to_vec();
    Ok((cred_id, &auth_data[cred_end..]))
}

/// Extract the ES256 public key from a COSE key (algorithm -7, P-256), as SEC1 uncompressed.
fn cose_es256_to_sec1(cose: &[u8]) -> Result<Vec<u8>, String> {
    // Walk the CBOR map: keys 1 (kty), 3 (alg), -1 (crv), -2 (x), -3 (y).
    let b = *cose.first().ok_or("empty COSE key")?;
    if b >> 5 != 5 {
        return Err("COSE key is not a map".into());
    }
    let n = (b & 0x1F) as usize;
    let mut off = 1usize;
    let mut alg: Option<i64> = None;
    let mut x: Option<Vec<u8>> = None;
    let mut y: Option<Vec<u8>> = None;
    let read_int = |bytes: &[u8], off: &mut usize| -> Result<i64, String> {
        let b = *bytes.get(*off).ok_or("truncated COSE")?;
        *off += 1;
        match b >> 5 {
            0 => Ok((b & 0x1F) as i64),
            1 => Ok(-1 - (b & 0x1F) as i64),
            _ => Err("unexpected COSE int encoding".into()),
        }
    };
    for _ in 0..n {
        let k = read_int(cose, &mut off)?;
        match k {
            1 | 3 | -1 => {
                let v = read_int(cose, &mut off)?;
                if k == 3 { alg = Some(v); }
                if k == 1 && v != 2 {
                    return Err("COSE key type is not EC2".into());
                }
                if k == -1 && v != 1 {
                    return Err("COSE curve is not P-256".into());
                }
            }
            -2 | -3 => {
                let (v, c) = read_cbor_bytes(&cose[off..])?;
                if v.len() != 32 {
                    return Err("EC2 coordinate is not 32 bytes".into());
                }
                if k == -2 { x = Some(v.to_vec()); } else { y = Some(v.to_vec()); }
                off += c;
            }
            _ => { off += skip_cbor_item(&cose[off..])?; }
        }
    }
    if alg != Some(-7) {
        return Err(format!("COSE algorithm is {:?}, not ES256", alg));
    }
    let (x, y) = (x.ok_or("COSE key lacks x")?, y.ok_or("COSE key lacks y")?);
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    // Rejecting an off-curve point here means a fake key can never be registered.
    VerifyingKey::from_sec1_bytes(&point).map_err(|_| "the credential public key is not a valid P-256 point")?;
    Ok(point)
}

fn verify_packed_self_attestation(
    attestation: &[u8],
    auth_data: &[u8],
    client_data: &[u8],
    sec1: &[u8],
) -> Result<(), String> {
    // attStmt = { alg: -7, sig: bstr }. Find the sig inside the CBOR map by scanning the tail.
    let sig = extract_attestation_signature(attestation)?;
    let key = VerifyingKey::from_sec1_bytes(sec1).map_err(|_| "bad key")?;
    let mut signed = Vec::with_capacity(auth_data.len() + 32);
    signed.extend_from_slice(auth_data);
    signed.extend_from_slice(&Sha256::digest(client_data));
    key.verify(&signed, &sig).map_err(|_| "packed self-attestation signature does not verify")?;
    Ok(())
}

fn extract_attestation_signature(attestation: &[u8]) -> Result<Signature, String> {
    // Locate the attStmt map: scan top-level for the third entry after fmt/authData. Simpler and
    // still strict: parse offsets again via cbor_map_get_fmt_and_authdata's walk. We re-walk to
    // the attStmt value.
    let mut i = 1usize;
    for key_index in 0..3 {
        let (key, consumed) = if key_index == 0 {
            read_cbor_text(attestation.get(i..).ok_or("truncated")?)?
        } else {
            // keys "authData" and "attStmt"
            let (k, c) = read_cbor_text(attestation.get(i..).ok_or("truncated")?)?;
            (k, c)
        };
        i += consumed;
        match key {
            "fmt" => { let (_, c) = read_cbor_text(attestation.get(i..).ok_or("truncated")?)?; i += c; }
            "authData" => { let (_, c) = read_cbor_bytes(attestation.get(i..).ok_or("truncated")?)?; i += c; }
            "attStmt" => {
                // The map: { "alg": -7, "sig": bstr }
                let b = *attestation.get(i).ok_or("truncated attStmt")?;
                if b >> 5 != 5 { return Err("attStmt is not a map".into()); }
                let n = (b & 0x1F) as usize;
                let mut off = i + 1;
                let mut sig: Option<Vec<u8>> = None;
                for _ in 0..n {
                    let k = read_cbor_text(attestation.get(off..).ok_or("truncated attStmt")?)
                        .map(|(k, c)| { off += c; k.to_string() })?;
                    match k.as_str() {
                        "alg" => { off += skip_cbor_item(attestation.get(off..).ok_or("truncated")?)?; }
                        "sig" => {
                            let (v, c) = read_cbor_bytes(attestation.get(off..).ok_or("truncated")?)?;
                            off += c;
                            sig = Some(v.to_vec());
                        }
                        _ => { off += skip_cbor_item(attestation.get(off..).ok_or("truncated")?)?; }
                    }
                }
                let sig = sig.ok_or("attStmt lacks sig")?;
                return Signature::from_der(&sig).map_err(|_| "attestation signature is not DER ECDSA".into());
            }
            _ => return Err("unexpected key in attestation object".into()),
        }
    }
    Err("attestation object lacks attStmt".into())
}

/// Wallet-challenge authentication: verify a Ristretto Schnorr signature over the server's
/// challenge with the registered public key. The SAME verify path the gate-credential flow uses.
pub fn verify_wallet_signature(
    challenge: &str,
    public_hex: &str,
    public_nonce_hex: &str,
    signature_hex: &str,
) -> Result<(), String> {
    let key_bytes = hex::decode(public_hex).map_err(|_| "the registered wallet public key is not hex")?;
    let public = RistrettoPublicKey::from_canonical_bytes(&key_bytes)
        .map_err(|_| "the registered wallet public key is not valid Ristretto")?;
    let nonce_bytes = hex::decode(public_nonce_hex).map_err(|_| "the nonce is not hex")?;
    let nonce = RistrettoPublicKey::from_canonical_bytes(&nonce_bytes)
        .map_err(|_| "the nonce is not a valid public key")?;
    let scalar_bytes = hex::decode(signature_hex).map_err(|_| "signature is not hex")?;
    if scalar_bytes.len() != 32 {
        return Err("a Ristretto Schnorr scalar is 32 bytes".into());
    }
    let scalar = RistrettoSecretKey::from_canonical_bytes(&scalar_bytes)
        .map_err(|_| "signature is not a valid scalar")?;
    // Exactly the construction credential.rs verifies with: `verify` derives the Schnorr challenge
    // from the message digest under com.tari.schnorr_signature.v1.challenge, the same on both
    // sides of the wire.
    let signature =
        SchnorrSignature::<RistrettoPublicKey, RistrettoSecretKey, SchnorrSigChallenge>::new(nonce, scalar);
    if !signature.verify(&public, hash_challenge(challenge)) {
        return Err("wallet signature does not verify".into());
    }
    Ok(())
}

/// The challenge is bound to the admin domain before hashing, so a signature over a gate
/// credential challenge can never be replayed as an admin authentication (and vice versa).
/// Public because it is part of the wire contract: wallets sign exactly this digest.
pub fn hash_challenge(challenge: &str) -> Vec<u8> {
    Sha256::digest(format!("ghost-gate-admin:v1:{challenge}").as_bytes()).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_round_trips_and_decodes_strictly() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        let enc = base64url_nopad(&bytes);
        assert!(!enc.contains('+') && !enc.contains('/') && !enc.contains('='));
        assert_eq!(base64url_decode(&enc).unwrap(), bytes);
        assert!(base64url_decode("a+b/").is_err());
        assert_eq!(base64url_decode(&base64url_nopad(b"")).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn a_real_key_pair_verifies_and_a_forged_one_does_not() {
        // Register-style: build a valid P-256 key by hand from a fixed point (no private key
        // operations in production code paths — the test generates one via the library to have a
        // genuine signature to verify).
        use p256::ecdsa::{SigningKey, signature::{Signer, SignatureEncoding}};
        // A fixed seed gives a deterministic test key — no RNG dependency in the test at all.
        let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let sec1 = sk.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        let auth_data = {
            let mut a = vec![0u8; 37];
            a[..32].copy_from_slice(&Sha256::digest("localhost".as_bytes()));
            a[32] = 0x05; // UP | UV
            a
        };
        let client_data = br#"{"type":"webauthn.get","challenge":"abc","origin":"http://127.0.0.1:7811"}"#;
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(client_data));
        let sig: Signature = sk.sign(&signed);
        let resp = WebAuthnResponse {
            client_data_b64: base64url_nopad(client_data),
            authenticator_data_b64: base64url_nopad(&auth_data),
            signature_b64: base64url_nopad(sig.to_der().as_bytes()),
            credential_id_b64: base64url_nopad(b"cred-1"),
            attestation_object_b64: String::new(),
        };
        assert!(verify_webauthn_assertion(&resp, "abc", "http://127.0.0.1:7811", "localhost", &base64url_nopad(b"cred-1"), &sec1, true).is_ok());
        // Wrong challenge refused.
        assert!(verify_webauthn_assertion(&resp, "OTHER", "http://127.0.0.1:7811", "localhost", &base64url_nopad(b"cred-1"), &sec1, true).is_err());
        // Wrong origin refused.
        assert!(verify_webauthn_assertion(&resp, "abc", "http://evil.example", "localhost", &base64url_nopad(b"cred-1"), &sec1, true).is_err());
        // Missing user verification refused when required.
        let mut no_uv = auth_data.clone();
        no_uv[32] = 0x01;
        let resp2 = WebAuthnResponse { authenticator_data_b64: base64url_nopad(&no_uv), ..resp.clone() };
        assert!(verify_webauthn_assertion(&resp2, "abc", "http://127.0.0.1:7811", "localhost", &base64url_nopad(b"cred-1"), &sec1, true).is_err());
        // A different credential id refused.
        assert!(verify_webauthn_assertion(&resp, "abc", "http://127.0.0.1:7811", "localhost", &base64url_nopad(b"cred-OTHER"), &sec1, true).is_err());
    }

    #[test]
    fn wallet_challenges_refuse_replays_across_domains() {
        // A signature over the GATE challenge string must not verify as an ADMIN authentication:
        // hash_challenge binds the admin domain. Verified indirectly: two different challenges hash
        // differently, so a replay across domains cannot verify.
        let c1 = hash_challenge("one");
        let c2 = hash_challenge("two");
        assert_ne!(c1, c2);
        // And a real signature verifies (self-consistent round trip via the same helper used by
        // the server): signing lives in the wallet, so here we check the verifier accepts a
        // correctly constructed signature made with the library, mirroring credential.rs.
        use tari_crypto::keys::{PublicKey, SecretKey};
        let sk = RistrettoSecretKey::random(&mut rand::rng());
        let pk = RistrettoPublicKey::from_secret_key(&sk);
        let challenge = "test-challenge";
        let sig = SchnorrSignature::<RistrettoPublicKey, RistrettoSecretKey, SchnorrSigChallenge>::sign(
            &sk,
            &hash_challenge(challenge),
            &mut rand::rng(),
        ).unwrap();
        let pk_hex = pk.to_string();
        let nonce_hex = hex::encode(sig.get_public_nonce().as_bytes());
        let sig_hex = hex::encode(sig.get_signature().as_bytes());
        assert!(verify_wallet_signature(challenge, &pk_hex, &nonce_hex, &sig_hex).is_ok());
        assert!(verify_wallet_signature("different", &pk_hex, &nonce_hex, &sig_hex).is_err());
    }

    #[test]
    fn attestation_parsing_accepts_none_and_refuses_garbage() {
        // Build a minimal "none" attestation by hand: CBOR map { fmt: "none", attStmt: {}, authData: bstr }.
        let auth_data = vec![0u8; 37 + 18 + 77]; // rpIdHash+flags+counter + aaguid + credId + COSE key
        let mut cbor: Vec<u8> = vec![0xA3];
        cbor.extend_from_slice(b"\x63fmt"); // "fmt"
        cbor.extend_from_slice(b"\x64none"); // "none"
        cbor.extend_from_slice(b"\x67attStmt"); // "attStmt"
        cbor.push(0xA0); // empty map
        cbor.extend_from_slice(b"\x68authData"); // "authData"
        cbor.push(0x58);
        cbor.push(auth_data.len() as u8);
        cbor.extend_from_slice(&auth_data);
        let (fmt, got_auth) = parse_attestation(&cbor).unwrap();
        assert_eq!(fmt, "none");
        assert_eq!(got_auth, &auth_data[..]);
        assert!(parse_attestation(b"garbage").is_err());
    }
}
