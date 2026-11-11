//   Copyright 2026 Ghost Gate contributors
//   SPDX-License-Identifier: MIT

//! M8 test-only binary: generate Ristretto keypairs and sign ownership-proof messages.
//!
//! Used exclusively by the M8 end-to-end test scripts to sign wallet challenges without a real
//! Tari wallet daemon. Never connects to any wallet, indexer, bridge, or Telegram. Outputs JSON
//! only; never writes files or modifies state.
//!
//! # Commands
//!
//! **gen-keypair**
//! ```text
//! gg-test-signer gen-keypair
//! ```
//! Outputs `{"secret_key":"<64-hex>","public_key":"<64-hex>"}`.
//! The `public_key` bytes (32 bytes, Ristretto255) match what the bridge's `FixtureChainReader`
//! expects as `auth_key` in `GG_FIXTURE_UTXO`.
//!
//! **sign**
//! ```text
//! gg-test-signer sign <network_hex> <resource_addr> <substate_id> <challenge_string> <secret_key_hex>
//! ```
//! Signs `ownership_proof_message(network, resource, substate_id, challenge_string)` with the
//! Ristretto secret key and outputs `{"public_key":"<hex>","public_nonce":"<hex>","signature":"<hex>"}`.
//! These fields map directly to `CredentialProofRequest::ownership` (flattened).

use std::process::ExitCode;
use std::str::FromStr;

use ghost_gate_bridge::ownership_proof_message;
use tari_crypto::keys::{PublicKey, SecretKey};
use tari_crypto::ristretto::{RistrettoPublicKey, RistrettoSecretKey};
use tari_crypto::signatures::{SchnorrSigChallenge, SchnorrSignature};
use tari_crypto::tari_utilities::ByteArray;
use tari_template_lib_types::ResourceAddress;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("gen-keypair") => match do_gen_keypair() {
            Ok(json) => { println!("{json}"); ExitCode::SUCCESS }
            Err(e) => { eprintln!("gg-test-signer gen-keypair: {e}"); ExitCode::FAILURE }
        },
        Some("sign") => {
            if args.len() != 6 {
                eprintln!(
                    "usage: gg-test-signer sign <network_hex> <resource_addr> <substate_id> <challenge_string> <secret_key_hex>"
                );
                return ExitCode::FAILURE;
            }
            match do_sign(&args[1], &args[2], &args[3], &args[4], &args[5]) {
                Ok(json) => { println!("{json}"); ExitCode::SUCCESS }
                Err(e) => { eprintln!("gg-test-signer sign: {e}"); ExitCode::FAILURE }
            }
        }
        _ => {
            eprintln!("usage: gg-test-signer <gen-keypair | sign>");
            ExitCode::FAILURE
        }
    }
}

fn do_gen_keypair() -> Result<String, String> {
    let mut rng = rand::rng();
    let secret = RistrettoSecretKey::random(&mut rng);
    let public = RistrettoPublicKey::from_secret_key(&secret);
    Ok(format!(
        r#"{{"secret_key":"{}","public_key":"{}"}}"#,
        hex::encode(secret.as_bytes()),
        hex::encode(public.as_bytes()),
    ))
}

fn do_sign(
    network_hex: &str,
    resource_str: &str,
    substate_id: &str,
    challenge_string: &str,
    sk_hex: &str,
) -> Result<String, String> {
    let network = parse_network(network_hex)?;
    let resource = ResourceAddress::from_str(resource_str)
        .map_err(|e| format!("bad resource address: {e}"))?;
    let sk_bytes = hex::decode(sk_hex).map_err(|e| format!("bad secret key hex: {e}"))?;
    let secret = RistrettoSecretKey::from_canonical_bytes(&sk_bytes)
        .map_err(|_| "secret key bytes are not a valid Ristretto scalar".to_string())?;

    let message = ownership_proof_message(network, &resource, substate_id, challenge_string);
    let mut rng = rand::rng();
    let sig = SchnorrSignature::<RistrettoPublicKey, RistrettoSecretKey, SchnorrSigChallenge>::sign(
        &secret,
        &message,
        &mut rng,
    )
    .map_err(|e| format!("sign failed: {e}"))?;
    let public = RistrettoPublicKey::from_secret_key(&secret);

    Ok(format!(
        r#"{{"public_key":"{}","public_nonce":"{}","signature":"{}"}}"#,
        hex::encode(public.as_bytes()),
        hex::encode(sig.get_public_nonce().as_bytes()),
        hex::encode(sig.get_signature().as_bytes()),
    ))
}

fn parse_network(s: &str) -> Result<u8, String> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u8::from_str_radix(hex, 16).map_err(|e| format!("bad network hex {s:?}: {e}"))
    } else {
        s.parse::<u8>().map_err(|e| format!("bad network byte {s:?}: {e}"))
    }
}
