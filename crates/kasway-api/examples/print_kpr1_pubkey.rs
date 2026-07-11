//! Print the KPR-1 signing public key for the configured seed, as SPKI PEM.
//!
//! Wallets pin this key at build time (e.g. the extension's
//! VITE_KPR1_TRUSTED_KEYS_JSON). Uses the same AppConfig env handling as the
//! server, so run it with the same environment.
//!
//! Usage: cargo run -p kasway-api --example print_kpr1_pubkey

use base64::Engine;
use ed25519_dalek::SigningKey;

fn main() {
    let config = kasway_api::state::AppConfig::from_env();
    let key = SigningKey::from_bytes(&config.kpr1.signing_seed);
    let public = key.verifying_key().to_bytes();

    // SPKI DER for ed25519: fixed 12-byte header + 32-byte raw key.
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(&public);
    let b64 = base64::engine::general_purpose::STANDARD.encode(&der);

    let hex: String = public.iter().map(|b| format!("{b:02x}")).collect();
    println!("keyId: {}", config.kpr1.signing_key_id);
    println!("publicKeyHex: {hex}");
    println!("-----BEGIN PUBLIC KEY-----");
    for chunk in b64.as_bytes().chunks(64) {
        println!("{}", String::from_utf8_lossy(chunk));
    }
    println!("-----END PUBLIC KEY-----");
}
