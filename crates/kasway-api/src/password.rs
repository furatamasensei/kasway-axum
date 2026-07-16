//! Password hashing. Adonis uses `hash.use('scrypt')`; we use the RustCrypto
//! scrypt PHC implementation. Self-consistent (hash on register, verify on
//! login) — the new database has no Adonis-minted hashes to interoperate with.

use scrypt::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use scrypt::Scrypt;

pub fn hash_password(plain: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Scrypt
        .hash_password(plain.as_bytes(), &salt)
        .expect("hash password")
        .to_string()
}

pub fn verify_password(plain: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Scrypt.verify_password(plain.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}
