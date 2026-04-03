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

    #[error("stealth: domain separation tag mismatch")]
    StealthDomainMismatch,

    #[error("stealth: HMAC verification failed — output not for this recipient")]
    StealthHmacMismatch,

    #[error("stealth: encrypted payload too short (need ≥{min}, got {got})")]
    StealthPayloadTooShort { min: usize, got: usize },

    #[error("stealth: output index out of range")]
    StealthIndexOutOfRange,

    #[error("output recovery: no matching outputs found")]
    NoMatchingOutputs,

    #[error("lattice ZKP proof invalid: {0}")]
    ProofInvalid(String),

    #[error("ring: duplicate key image")]
    DuplicateKeyImage,

    #[error("invalid seed length: expected {expected}, got {got}")]
    InvalidSeedLength { expected: usize, got: usize },

    #[error("ZKP verification incomplete")]
    IncompleteVerification,
}
