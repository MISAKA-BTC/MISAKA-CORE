//! Cryptographic error types for the PQC layer.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("ML-DSA keygen failed")]
    MlDsaKeygenFailed,

    #[error("ML-DSA signature verification failed")]
    MlDsaVerifyFailed,

    #[error("ML-DSA invalid public key length: expected 1952, got {0}")]
    MlDsaInvalidPkLen(usize),

    #[error("ML-DSA invalid secret key length: expected 4032, got {0}")]
    MlDsaInvalidSkLen(usize),

    #[error("ML-DSA invalid signature length: expected 3309, got {0}")]
    MlDsaInvalidSigLen(usize),

    #[error("ML-KEM keygen failed")]
    MlKemKeygenFailed,

    #[error("ML-KEM encapsulation failed")]
    MlKemEncapsulateFailed,

    #[error("ML-KEM decapsulation failed")]
    MlKemDecapsulateFailed,

    #[error("ML-KEM invalid public key length: expected 1184, got {0}")]
    MlKemInvalidPkLen(usize),

    #[error("ML-KEM invalid secret key length: expected 2400, got {0}")]
    MlKemInvalidSkLen(usize),

    #[error("ML-KEM invalid ciphertext length: expected 1088, got {0}")]
    MlKemInvalidCtLen(usize),

    #[error("ML-DSA signature invalid: {0}")]
    ProofInvalid(String),

    #[error("ring: duplicate key image")]
    DuplicateKeyImage,

    #[error("invalid seed length: expected {expected}, got {got}")]
    InvalidSeedLength { expected: usize, got: usize },

    #[error("internal cryptographic error: {0}")]
    Internal(&'static str),
}
