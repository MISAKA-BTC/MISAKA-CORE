//! MISAKA Hybrid Signature: Ed25519 + ML-DSA-65.
//!
//! # Security Policy
//!
//! **Both** signatures must verify for the signature to be valid.
//! This provides security against both classical and quantum attackers:
//! - If ECC breaks (quantum): ML-DSA still holds
//! - If lattice breaks (unlikely): Ed25519 still holds
//!
//! # Domain Separation
//!
//! All signatures are computed over:
//! `SHA3-256("MISAKA-HYBRID-SIG:v1:" || message)`

pub mod hybrid;
pub mod hash;

pub use hybrid::{
    HybridKeypair, HybridPublicKey, HybridSecretKey, HybridSignature,
    hybrid_sign, hybrid_verify, generate_hybrid_keypair,
};
pub use hash::sha3_256;
