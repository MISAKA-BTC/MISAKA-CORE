//! Ring Signature Abstraction — trait-based interface for LRS / ChipmunkRing switching.
//!
//! This module defines the `RingScheme` trait that both the legacy LRS and the new
//! ChipmunkRing implementations must satisfy. The trait cleanly separates:
//!
//! 1. **Ring signature** (anonymity among ring members)
//! 2. **Key image** (linkability / double-spend detection)
//! 3. **Key image proof** (proof of correct KI derivation)
//!
//! This separation is critical because ChipmunkRing does not natively include
//! key images — MISAKA adds a linkability layer on top.

use crate::error::CryptoError;
use serde::{Serialize, Deserialize};

// ─── Core Trait ─────────────────────────────────────────────

/// Ring signature scheme interface.
///
/// Implementors: `LrsScheme` (legacy v1), `ChipmunkScheme` (v2).
pub trait RingScheme: Send + Sync {
    /// Public key type for ring members.
    type PublicKey: Clone + Send + Sync;
    /// Secret key type for the real signer.
    type SecretKey: Send + Sync;
    /// Ring signature output.
    type Signature: Clone + Send + Sync;
    /// Key image proof type.
    type KiProof: Clone + Send + Sync;

    /// Scheme identifier string (for serialization versioning).
    fn scheme_id(&self) -> &'static str;

    // ─── Key Management ─────────────────────────────────

    /// Derive a public key from a secret key.
    fn derive_pubkey(&self, sk: &Self::SecretKey) -> Self::PublicKey;

    /// Compute deterministic key image from secret key.
    /// Must be the same regardless of which ring the key appears in.
    fn compute_key_image(&self, sk: &Self::SecretKey) -> [u8; 32];

    // ─── Ring Signature ─────────────────────────────────

    /// Sign a message with a ring of public keys.
    ///
    /// - `ring_pubkeys`: all ring member public keys (includes signer)
    /// - `signer_index`: position of the real signer in the ring
    /// - `sk`: the real signer's secret key
    /// - `message`: the 32-byte signing digest
    fn ring_sign(
        &self,
        ring_pubkeys: &[Self::PublicKey],
        signer_index: usize,
        sk: &Self::SecretKey,
        message: &[u8; 32],
    ) -> Result<Self::Signature, CryptoError>;

    /// Verify a ring signature.
    fn ring_verify(
        &self,
        ring_pubkeys: &[Self::PublicKey],
        message: &[u8; 32],
        signature: &Self::Signature,
    ) -> Result<(), CryptoError>;

    // ─── Key Image Proof ────────────────────────────────

    /// Generate a proof that the key image was correctly derived.
    fn prove_key_image(
        &self,
        sk: &Self::SecretKey,
        pk: &Self::PublicKey,
        key_image: &[u8; 32],
    ) -> Result<Self::KiProof, CryptoError>;

    /// Verify a key image correctness proof.
    fn verify_key_image_proof(
        &self,
        pk: &Self::PublicKey,
        key_image: &[u8; 32],
        proof: &Self::KiProof,
    ) -> Result<(), CryptoError>;

    // ─── Serialization ──────────────────────────────────

    /// Serialize a signature to bytes.
    fn signature_to_bytes(&self, sig: &Self::Signature) -> Vec<u8>;

    /// Deserialize a signature from bytes.
    fn signature_from_bytes(&self, data: &[u8], ring_size: usize) -> Result<Self::Signature, CryptoError>;

    /// Serialize a public key to bytes.
    fn pubkey_to_bytes(&self, pk: &Self::PublicKey) -> Vec<u8>;

    /// Deserialize a public key from bytes.
    fn pubkey_from_bytes(&self, data: &[u8]) -> Result<Self::PublicKey, CryptoError>;

    /// Serialize a KI proof to bytes.
    fn ki_proof_to_bytes(&self, proof: &Self::KiProof) -> Vec<u8>;

    /// Deserialize a KI proof from bytes.
    fn ki_proof_from_bytes(&self, data: &[u8]) -> Result<Self::KiProof, CryptoError>;

    // ─── Parameters ─────────────────────────────────────

    /// Minimum ring size for this scheme.
    fn min_ring_size(&self) -> usize;

    /// Maximum ring size for this scheme.
    fn max_ring_size(&self) -> usize;
}

// ─── Batch Verification (future) ────────────────────────────

/// Optional batch verification support.
/// Implementations can override for performance.
pub trait BatchVerifiable: RingScheme {
    /// Verify multiple ring signatures in a batch.
    /// Default: verify sequentially.
    fn batch_verify(
        &self,
        items: &[(Vec<Self::PublicKey>, [u8; 32], Self::Signature)],
    ) -> Result<(), CryptoError> {
        for (pks, msg, sig) in items {
            self.ring_verify(pks, msg, sig)?;
        }
        Ok(())
    }
}

// ─── Scheme Version Tag ─────────────────────────────────────

/// Ring signature scheme version (embedded in TX).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RingSchemeVersion {
    /// Legacy LRS (Lyubashevsky Σ-protocol over R_q).
    LrsV1 = 0x01,
    /// ChipmunkRing + MISAKA linkability layer.
    ChipmunkV1 = 0x02,
}

impl RingSchemeVersion {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::LrsV1),
            0x02 => Some(Self::ChipmunkV1),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl std::fmt::Display for RingSchemeVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LrsV1 => write!(f, "LRS-v1"),
            Self::ChipmunkV1 => write!(f, "Chipmunk-v1"),
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheme_version_roundtrip() {
        assert_eq!(RingSchemeVersion::from_u8(0x01), Some(RingSchemeVersion::LrsV1));
        assert_eq!(RingSchemeVersion::from_u8(0x02), Some(RingSchemeVersion::ChipmunkV1));
        assert_eq!(RingSchemeVersion::from_u8(0xFF), None);
    }

    #[test]
    fn test_scheme_version_to_u8() {
        assert_eq!(RingSchemeVersion::LrsV1.to_u8(), 0x01);
        assert_eq!(RingSchemeVersion::ChipmunkV1.to_u8(), 0x02);
    }
}
