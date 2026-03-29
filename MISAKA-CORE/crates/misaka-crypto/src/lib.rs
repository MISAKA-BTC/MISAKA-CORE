//! MISAKA Validator Signature: ML-DSA-65 Only (Post-Quantum).
//!
//! # Security Policy
//!
//! ECC (Ed25519, ECDSA, secp256k1) is COMPLETELY EXCLUDED.
//! All validator signatures use ML-DSA-65 (FIPS 204 / Dilithium3).
//!
//! # Domain Separation
//!
//! All signatures are computed over:
//! `SHA3-256("MISAKA-PQ-SIG:v2:" || message)`

pub mod hash;
pub mod addresses;
pub mod hashes;
pub mod keystore;
pub mod signature;
pub mod validator_sig;

pub use hash::sha3_256;
pub use keystore::{
    decrypt_keystore, encrypt_keystore, is_plaintext_keyfile, load_keystore, save_keystore,
    EncryptedKeystore, KeystoreError, KEYSTORE_VERSION,
};
pub use validator_sig::{
    generate_validator_keypair, validator_sign, validator_verify, ValidatorKeypair,
    ValidatorPqPublicKey, ValidatorPqSecretKey, ValidatorPqSignature,
};
pub mod key_manager;
pub mod schnorr_pq;
pub mod merkle;
pub mod commitment;
pub mod randomness;
pub mod kdf;
