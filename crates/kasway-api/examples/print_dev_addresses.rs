//! Print the deterministic TN10 dev identities used to seed a local environment.
//!
//! The default `KASWAY_PLATFORM_FEE_ADDRESS` in `state.rs` is a placeholder that
//! is not a decodable Kaspa address, so covenant finalize fails on it. These are
//! real schnorr P2PK addresses derived from fixed dev secrets — deterministic so
//! the merchant/arbiter keys stay available for release + dispute flows.
//!
//! DEV ONLY: the secrets are printed because they are hardcoded here in the
//! clear. Never point these at real funds.
//!
//! Usage: cargo run -p kasway-api --example print_dev_addresses

use kasway_covenant::{network_prefix, KeeperKey};

/// Fixed dev secrets — arbitrary, non-zero, and public by design.
const DEV_KEYS: [(&str, [u8; 32]); 4] = [
    ("merchant", [0x11; 32]),
    ("platform_fee", [0x22; 32]),
    ("arbiter", [0x33; 32]),
    // The keeper pays the on-chain fee for release/refund txs from its OWN utxos,
    // so unlike the others this address must actually hold TN10 funds.
    ("keeper_fee", [0x44; 32]),
];

fn main() {
    let prefix = network_prefix("tn10").expect("tn10 prefix");
    for (role, secret) in DEV_KEYS {
        let key = KeeperKey::from_secret_bytes(&secret).expect("valid dev secret");
        let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        println!("{role}:");
        println!("  address: {}", key.address(prefix));
        println!("  secret:  {hex}");
    }
}
