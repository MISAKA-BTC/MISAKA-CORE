//! Key derivation utilities for account creation.

use sha3::{Sha3_256, Digest};
use hkdf::Hkdf;

/// Derive an ML-DSA-65 seed from a master seed and account index.
pub fn derive_signing_seed(master_seed: &[u8], account_index: u32) -> [u8; 32] {
    let hk = Hkdf::<Sha3_256>::new(Some(b"MISAKA:signing:v1"), master_seed);
    let mut okm = [0u8; 32];
    let info = format!("account:{}", account_index);
    hk.expand(info.as_bytes(), &mut okm).expect("valid length");
    okm
}

/// Derive an ML-KEM-768 seed from a master seed and account index.
pub fn derive_view_seed(master_seed: &[u8], account_index: u32) -> [u8; 32] {
    let hk = Hkdf::<Sha3_256>::new(Some(b"MISAKA:view:v1"), master_seed);
    let mut okm = [0u8; 32];
    let info = format!("view:{}", account_index);
    hk.expand(info.as_bytes(), &mut okm).expect("valid length");
    okm
}

/// Generate a mnemonic seed from entropy.
pub fn entropy_to_seed(entropy: &[u8], passphrase: &str) -> [u8; 64] {
    let hk = Hkdf::<Sha3_256>::new(Some(passphrase.as_bytes()), entropy);
    let mut seed = [0u8; 64];
    hk.expand(b"MISAKA:mnemonic:seed:v1", &mut seed).expect("valid length");
    seed
}

/// Derive a sub-key for encryption purposes.
pub fn derive_encryption_key(master_seed: &[u8], purpose: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha3_256>::new(Some(b"MISAKA:encrypt:v1"), master_seed);
    let mut okm = [0u8; 32];
    hk.expand(purpose.as_bytes(), &mut okm).expect("valid length");
    okm
}
