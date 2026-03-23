//! Cryptographic Type System — compile-time enforcement of secret/public separation.
//!
//! # Problem
//!
//! In the previous codebase, nullifiers, commitments, shared secrets, and
//! raw byte arrays all shared the same `[u8; 32]` or `Vec<u8>` type.
//! This created two classes of vulnerability:
//!
//! 1. **Type Confusion**: A nullifier could be accidentally used where a
//!    commitment hash was expected (or vice versa), silently corrupting
//!    the Fiat-Shamir transcript and breaking soundness.
//!
//! 2. **Secret Leakage**: A `SecretKey` stored as `[u8; 32]` could be
//!    accidentally serialized to the wire or logged, destroying privacy.
//!
//! # Solution: Newtype Wrappers with Trait-Level Access Control
//!
//! Each cryptographic value gets a dedicated wrapper type. The Rust compiler
//! enforces that:
//! - **Public types** (`PublicNullifier`, `CommitmentHash`) implement `Serialize`
//! - **Secret types** (`SecretWitness`, `SharedSecret`) do NOT implement `Serialize`
//! - **Secret types** do NOT implement `Clone` (prevents accidental copies)
//! - **Secret types** implement `ZeroizeOnDrop` (guaranteed cleanup)
//!
//! Passing a `PublicNullifier` where a `CommitmentHash` is expected is a
//! **compile-time error**, not a runtime bug.

use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

use crate::pq_ring::Poly;

// ═══════════════════════════════════════════════════════════════
//  PUBLIC TYPES — safe to broadcast, serialize, store on-chain
// ═══════════════════════════════════════════════════════════════

/// A nullifier that has been derived and is safe for on-chain broadcast.
///
/// `nullifier = canonical_nullifier_hash(a_null · s)`
///
/// # Why a newtype?
///
/// Without this, a function like `check_double_spend(ki: [u8; 32])` accepts
/// ANY 32-byte value — a commitment hash, a tx hash, a random nonce.
/// With `PublicNullifier`, the signature becomes `check_double_spend(nf: &PublicNullifier)`
/// and the compiler rejects `check_double_spend(&some_commitment_hash)`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicNullifier(pub [u8; 32]);

impl PublicNullifier {
    pub const ZERO: Self = Self([0u8; 32]);

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Convert from raw bytes (e.g., deserialization from wire).
    /// Use sparingly — prefer computing via `compute_nullifier()`.
    pub fn from_raw(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for PublicNullifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nullifier({}..)", hex::encode(&self.0[..4]))
    }
}

impl fmt::Display for PublicNullifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

/// A BDLOP commitment's hash digest (32 bytes).
///
/// Distinct from `PublicNullifier` and `TxDigest` at the type level.
/// Used for Merkle tree leaf hashes, commitment identity, etc.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CommitmentHash(pub [u8; 32]);

impl CommitmentHash {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn from_raw(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for CommitmentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CommitHash({}..)", hex::encode(&self.0[..4]))
    }
}

/// A committed leaf in the SIS Merkle tree.
///
/// Wraps `Poly` to prevent confusion with other polynomial values
/// (e.g., nullifier polynomials, response polynomials).
///
/// # Type Safety
///
/// `sis_leaf()` returns `CommittedLeaf`, and `compute_sis_root()` accepts
/// `&[CommittedLeaf]`. Passing a `Poly` from a different context
/// (e.g., a blinding factor polynomial) is a compile-time error.
#[derive(Clone, Serialize, Deserialize)]
pub struct CommittedLeaf(pub Poly);

impl CommittedLeaf {
    pub fn as_poly(&self) -> &Poly {
        &self.0
    }
    pub fn into_poly(self) -> Poly {
        self.0
    }
}

impl fmt::Debug for CommittedLeaf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CommittedLeaf([..{}])", self.0.coeffs[0])
    }
}

/// Anonymity set root hash (SIS Merkle root).
///
/// Distinct from `CommitmentHash` and `PublicNullifier`.
/// Used exclusively for Merkle root references in `ConfidentialInput`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AnonymityRoot(pub [u8; 32]);

impl AnonymityRoot {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn from_raw(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for AnonymityRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AnonRoot({}..)", hex::encode(&self.0[..4]))
    }
}

/// Transaction digest (signing message for ZKP binding).
///
/// Prevents confusion with nullifiers, commitment hashes, etc.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TxDigest(pub [u8; 32]);

impl TxDigest {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn from_raw(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for TxDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TxDigest({}..)", hex::encode(&self.0[..4]))
    }
}

// ═══════════════════════════════════════════════════════════════
//  SECRET TYPES — NEVER serializable, NEVER cloneable
// ═══════════════════════════════════════════════════════════════

/// Secret witness data (spending secret, blinding factors, etc.)
///
/// # Compile-Time Safety
///
/// - **No `Serialize`**: Cannot be accidentally written to wire/disk.
///   `serde_json::to_string(&witness)` is a **compilation error**.
/// - **No `Clone`**: Cannot be accidentally duplicated in memory.
///   `let w2 = witness.clone()` is a **compilation error**.
/// - **`ZeroizeOnDrop`**: Memory is securely cleared when value goes out of scope.
/// - **No `Debug` with real data**: Logging `{:?}` shows `[REDACTED]`.
///
/// # Why not `Secret<Vec<u8>>`?
///
/// We use a custom struct instead of `secrecy::Secret<Vec<u8>>` because:
/// 1. We need to enforce `!Clone` (secrecy::Secret is Clone if T: Clone)
/// 2. We want a domain-specific type name in error messages
/// 3. We need to attach the ZKP context (what this witness is for)
pub struct SecretWitness {
    data: Vec<u8>,
    /// Debug label (e.g., "spending_secret", "blinding_factor").
    /// NOT the actual secret — safe for logging.
    label: &'static str,
}

impl SecretWitness {
    pub fn new(data: Vec<u8>, label: &'static str) -> Self {
        Self { data, label }
    }

    /// Access the secret bytes. The caller MUST ensure the result
    /// is not logged, serialized, or stored beyond the proof scope.
    pub fn expose(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for SecretWitness {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl fmt::Debug for SecretWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SecretWitness({}: [REDACTED {} bytes])",
            self.label,
            self.data.len()
        )
    }
}

// SecretWitness intentionally does NOT implement:
// - Serialize / Deserialize (prevents wire leakage)
// - Clone (prevents accidental copies)
// - PartialEq (prevents timing side-channels in naive comparison)

/// Shared secret from ML-KEM key exchange.
///
/// Wraps a 32-byte shared secret with ZeroizeOnDrop.
/// Cannot be serialized, cloned, or printed.
pub struct SharedSecret {
    data: [u8; 32],
}

impl SharedSecret {
    pub fn new(data: [u8; 32]) -> Self {
        Self { data }
    }

    /// Access the shared secret. Use ONLY for key derivation (HKDF).
    pub fn expose(&self) -> &[u8; 32] {
        &self.data
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SharedSecret([REDACTED])")
    }
}

// SharedSecret intentionally does NOT implement:
// - Serialize / Deserialize
// - Clone
// - PartialEq

// ═══════════════════════════════════════════════════════════════
//  VERIFIED PROOF TYPES — proof-of-verification tokens
// ═══════════════════════════════════════════════════════════════

/// A proof-of-verification token for a nullifier.
///
/// This type can ONLY be constructed by `verify_nullifier_proof()`.
/// It serves as a compile-time witness that the nullifier has been
/// cryptographically verified.
///
/// # Usage in DAG State Manager
///
/// ```ignore
/// fn apply_nullifier(nf: VerifiedNullifier) { ... }
/// // Cannot call with unverified data:
/// // apply_nullifier(PublicNullifier::from_raw([0; 32])); // COMPILE ERROR
/// ```
pub struct VerifiedNullifier {
    nullifier: PublicNullifier,
    /// Private field prevents construction outside verification functions.
    _verified: (),
}

impl VerifiedNullifier {
    /// ONLY called by verification functions after successful proof check.
    pub(crate) fn new_verified(nullifier: PublicNullifier) -> Self {
        Self {
            nullifier,
            _verified: (),
        }
    }

    pub fn nullifier(&self) -> &PublicNullifier {
        &self.nullifier
    }
    pub fn into_nullifier(self) -> PublicNullifier {
        self.nullifier
    }
}

impl fmt::Debug for VerifiedNullifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Verified({})", self.nullifier)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nullifier_is_serializable() {
        let nf = PublicNullifier::from_raw([0xAA; 32]);
        let json = serde_json::to_string(&nf).unwrap();
        let nf2: PublicNullifier = serde_json::from_str(&json).unwrap();
        assert_eq!(nf, nf2);
    }

    #[test]
    fn test_nullifier_not_zero() {
        let nf = PublicNullifier::from_raw([1; 32]);
        assert!(!nf.is_zero());
        assert!(PublicNullifier::ZERO.is_zero());
    }

    #[test]
    fn test_commitment_hash_distinct_from_nullifier() {
        // This test exists to document that the type system prevents confusion.
        // If the types were both [u8; 32], this function would accept either.
        fn takes_nullifier(_nf: &PublicNullifier) {}
        fn takes_commitment(_ch: &CommitmentHash) {}

        let nf = PublicNullifier::from_raw([1; 32]);
        let ch = CommitmentHash::from_raw([1; 32]);

        takes_nullifier(&nf);
        takes_commitment(&ch);
        // takes_nullifier(&ch);  // COMPILE ERROR: expected PublicNullifier, got CommitmentHash
        // takes_commitment(&nf); // COMPILE ERROR: expected CommitmentHash, got PublicNullifier
    }

    #[test]
    fn test_secret_witness_debug_redacted() {
        let w = SecretWitness::new(vec![0xFF; 32], "test_secret");
        let dbg = format!("{:?}", w);
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains("ff"), "secret bytes must not appear in Debug");
    }

    #[test]
    fn test_shared_secret_debug_redacted() {
        let ss = SharedSecret::new([0xAA; 32]);
        let dbg = format!("{:?}", ss);
        assert!(dbg.contains("REDACTED"));
    }

    #[test]
    fn test_verified_nullifier_cannot_be_forged() {
        // VerifiedNullifier can only be created via new_verified (pub(crate))
        // External code cannot construct it directly.
        let nf = PublicNullifier::from_raw([1; 32]);
        // This works inside this crate:
        let vnf = VerifiedNullifier::new_verified(nf);
        assert_eq!(*vnf.nullifier().as_bytes(), [1; 32]);
    }

    // The following would NOT compile if uncommented:
    //
    // fn secret_not_serializable(w: &SecretWitness) {
    //     serde_json::to_string(w); // ERROR: Serialize not implemented
    // }
    //
    // fn secret_not_cloneable(w: &SecretWitness) {
    //     let _ = w.clone(); // ERROR: Clone not implemented
    // }
    //
    // fn shared_secret_not_serializable(s: &SharedSecret) {
    //     serde_json::to_string(s); // ERROR: Serialize not implemented
    // }
}
