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

pub mod validator_sig;
pub mod hash;

pub use validator_sig::{
    ValidatorKeypair, ValidatorPqPublicKey, ValidatorPqSecretKey, ValidatorPqSignature,
    validator_sign, validator_verify, generate_validator_keypair,
};
pub use hash::sha3_256;
