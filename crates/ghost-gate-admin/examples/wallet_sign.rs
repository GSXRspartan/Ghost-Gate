//! Signs an admin challenge with a Ristretto wallet key — the operator tool for wallet-key
//! administration. The SECRET key never leaves this process; the server only ever sees the public
//! key, the nonce and the signature, and verifies them with the audited Schnorr machinery.
//!
//! Usage:
//!   wallet_sign --generate                 # prints secret_key=<hex>; store it safely
//!   wallet_sign <secret_key_hex> <challenge>
//! Prints: publicKey, publicNonce, signature (one per line, key=value).

use tari_crypto::keys::{PublicKey, SecretKey};
use tari_crypto::ristretto::{RistrettoPublicKey, RistrettoSecretKey};
use tari_crypto::signatures::{SchnorrSigChallenge, SchnorrSignature};
use tari_crypto::tari_utilities::ByteArray;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && args[1] == "--generate" {
        let secret = RistrettoSecretKey::random(&mut rand::rng());
        println!("secret_key={}", hex::encode(secret.as_bytes()));
        return;
    }
    if args.len() != 3 {
        eprintln!("usage: wallet_sign --generate   |   wallet_sign <secret_key_hex> <challenge>");
        std::process::exit(2);
    }
    let secret_bytes = hex::decode(&args[1]).expect("secret key must be hex");
    let secret = RistrettoSecretKey::from_canonical_bytes(&secret_bytes)
        .expect("secret key must be a valid Ristretto scalar (use --generate to mint one)");
    let public = RistrettoPublicKey::from_secret_key(&secret);
    let challenge = &args[2];
    let sig = SchnorrSignature::<RistrettoPublicKey, RistrettoSecretKey, SchnorrSigChallenge>::sign(
        &secret,
        ghost_gate_admin::auth::hash_challenge(challenge),
        &mut rand::rng(),
    )
    .expect("signing cannot fail with a valid key");
    println!("publicKey={}", public.to_string());
    println!("publicNonce={}", sig.get_public_nonce().to_string());
    println!("signature={}", hex::encode(sig.get_signature().as_bytes()));
}
