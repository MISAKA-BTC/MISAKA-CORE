//! MISAKA PQC — Post-Quantum Cryptographic Primitives
//!
//! v1.0: ML-DSA-65 signing + ML-KEM-768 key encapsulation only.
//! Shielded/Q-DAG-CT modules removed. See docs/whitepaper_errata.md.

pub mod canonical_ki;
pub mod error;
pub mod key_derivation;
pub mod pq_kem;
pub mod pq_sign;

// Phase 2c-B D5d: domains.rs deleted — domain separation moved upstream.
// Phase 2c-B D4a: ring re-exports deleted (legacy ring functions, LegacyProofData, Poly)
// Retained: canonical_spend_id (ML-DSA key management), SpendingKeypair (wallet key management)
pub use canonical_ki::canonical_spend_id;
pub use error::CryptoError;
pub use key_derivation::SpendingKeypair;
pub use pq_kem::{
    MlKemCiphertext, MlKemKeypair, MlKemPublicKey, MlKemSecretKey, MlKemSharedSecret,
};
pub use pq_sign::{
    ml_dsa_sign_raw, ml_dsa_verify_raw, MlDsaKeypair, MlDsaPublicKey, MlDsaSecretKey,
    MlDsaSignature,
};
