//! STARK-based Zero-Knowledge Proof (Post-Quantum).
//!
//! # ⚠ STUB IMPLEMENTATION — NOT A REAL STARK PROVER/VERIFIER
//!
//! This module provides a hash-commitment interface that mimics STARK proof
//! structure for API stability. It provides ZERO soundness — any party
//! knowing the constraint values can forge a "proof".
//!
//! ## Production Safety
//!
//! This entire module is gated behind `#[cfg(feature = "stark-stub")] // DEV-ONLY: Stub ZK verifier — blocked in release builds`.
//! Production builds MUST NOT enable this feature.
//! The functions `stark_prove` and `stark_verify` are NOT available
//! in default builds.
//!
//! ## Future
//!
//! Production integration will replace this with a real STARK prover/verifier
//! (e.g., winterfell, risc0).

#![cfg(feature = "stark-stub")]

use crate::error::CryptoError;
use crate::secret::{ct_eq, ct_eq_32};
use serde::{Deserialize, Serialize};
use sha3::{Digest as Sha3Digest, Sha3_256};

// ─── Constants ───────────────────────────────────────────────

/// STARK proof version tag.
pub const STARK_PROOF_VERSION: u8 = 0x01;

/// Minimum proof size (hash chain commitment, 2 Merkle paths).
pub const MIN_STARK_PROOF_SIZE: usize = 256;

/// Security parameter: number of FRI query rounds (λ=128 target).
pub const STARK_SECURITY_BITS: usize = 128;

/// Domain separation for STARK proof generation.
const DST_STARK: &[u8] = b"MISAKA_STARK:v1:";

// ─── Types ───────────────────────────────────────────────────

/// Transaction constraint set for STARK proving.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxConstraints {
    /// Canonical transaction digest this proof is bound to.
    pub tx_digest: [u8; 32],
    /// Total input amount (must equal outputs + fee).
    pub sum_inputs: u64,
    /// Total output amount.
    pub sum_outputs: u64,
    /// Transaction fee.
    pub fee: u64,
    /// Number of outputs (for range proof).
    pub num_outputs: usize,
    /// Output amounts (for individual range proofs).
    pub output_amounts: Vec<u64>,
    /// Key images (for correctness proofs).
    pub key_images: Vec<[u8; 32]>,
}

impl TxConstraints {
    /// Validate constraint consistency (pre-proving check).
    pub fn validate(&self) -> Result<(), CryptoError> {
        // Balance conservation
        if self.sum_inputs
            != self
                .sum_outputs
                .checked_add(self.fee)
                .ok_or(CryptoError::ProofInvalid("amount overflow".into()))?
        {
            return Err(CryptoError::ProofInvalid(format!(
                "balance mismatch: {} != {} + {}",
                self.sum_inputs, self.sum_outputs, self.fee
            )));
        }
        // Output count consistency
        if self.output_amounts.len() != self.num_outputs {
            return Err(CryptoError::ProofInvalid(
                "output count mismatch".into(),
            ));
        }
        // Output sum consistency
        let actual_sum: u64 = self.output_amounts.iter().sum();
        if actual_sum != self.sum_outputs {
            return Err(CryptoError::ProofInvalid(
                "output sum mismatch".into(),
            ));
        }
        Ok(())
    }

    /// Compute constraint digest for STARK input.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(DST_STARK);
        h.update(&self.tx_digest);
        h.update(&self.sum_inputs.to_le_bytes());
        h.update(&self.sum_outputs.to_le_bytes());
        h.update(&self.fee.to_le_bytes());
        h.update(&(self.num_outputs as u32).to_le_bytes());
        for amt in &self.output_amounts {
            h.update(&amt.to_le_bytes());
        }
        for ki in &self.key_images {
            h.update(ki);
        }
        h.finalize().into()
    }
}

/// STARK proof (opaque bytes + metadata).
///
/// In production, this wraps a proper STARK proof from winterfell/risc0.
/// Currently a placeholder that uses hash commitments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarkProof {
    /// Proof version.
    pub version: u8,
    /// Constraint digest being proven.
    pub constraint_digest: [u8; 32],
    /// Proof bytes (opaque).
    pub proof_data: Vec<u8>,
    /// Number of FRI query rounds.
    pub query_rounds: u32,
}

impl StarkProof {
    /// Wire size in bytes.
    pub fn wire_size(&self) -> usize {
        1 + 32 + 4 + 4 + self.proof_data.len()
    }

    /// Compact binary encoding for carrying the proof over tx/RPC boundaries.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.wire_size());
        buf.push(self.version);
        buf.extend_from_slice(&self.constraint_digest);
        buf.extend_from_slice(&self.query_rounds.to_le_bytes());
        buf.extend_from_slice(&(self.proof_data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.proof_data);
        buf
    }

    /// Decode a proof produced by `to_bytes()`.
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() < 1 + 32 + 4 + 4 {
            return Err(CryptoError::ProofInvalid(
                "STARK proof bytes too short".into(),
            ));
        }

        let version = data[0];
        let mut constraint_digest = [0u8; 32];
        constraint_digest.copy_from_slice(&data[1..33]);
        let query_rounds =
            u32::from_le_bytes(data[33..37].try_into().map_err(|_| {
                CryptoError::ProofInvalid("invalid STARK query_rounds".into())
            })?);
        let proof_len =
            u32::from_le_bytes(data[37..41].try_into().map_err(|_| {
                CryptoError::ProofInvalid("invalid STARK proof length".into())
            })?) as usize;
        if data.len() != 41 + proof_len {
            return Err(CryptoError::ProofInvalid(format!(
                "STARK proof length mismatch: header says {} but wire is {}",
                proof_len,
                data.len().saturating_sub(41),
            )));
        }

        Ok(Self {
            version,
            constraint_digest,
            query_rounds,
            proof_data: data[41..].to_vec(),
        })
    }
}

// ─── Prover (stub) ───────────────────────────────────────────

/// Generate a STARK proof for transaction constraints.
///
/// # ⚠ STUB IMPLEMENTATION
///
/// This generates a hash-based commitment proof, NOT a real STARK proof.
/// Production integration will replace this with a proper STARK prover.
pub fn stark_prove(constraints: &TxConstraints) -> Result<StarkProof, CryptoError> {
    constraints.validate()?;

    let constraint_digest = constraints.digest();

    // Stub proof: hash chain commitment
    // In production: FRI-based polynomial commitment over AIR trace
    let mut proof_data = Vec::with_capacity(256);

    // Commitment 1: balance conservation witness
    let mut h1 = Sha3_256::new();
    h1.update(b"MISAKA_STARK:balance:");
    h1.update(&constraint_digest);
    let balance_commit: [u8; 32] = h1.finalize().into();
    proof_data.extend_from_slice(&balance_commit);

    // Commitment 2: range proof witnesses (one per output)
    for (i, amt) in constraints.output_amounts.iter().enumerate() {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA_STARK:range:");
        h.update(&constraint_digest);
        h.update(&(i as u32).to_le_bytes());
        h.update(&amt.to_le_bytes());
        let range_commit: [u8; 32] = h.finalize().into();
        proof_data.extend_from_slice(&range_commit);
    }

    // Commitment 3: key image witnesses
    for ki in &constraints.key_images {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA_STARK:ki:");
        h.update(&constraint_digest);
        h.update(ki);
        let ki_commit: [u8; 32] = h.finalize().into();
        proof_data.extend_from_slice(&ki_commit);
    }

    // FRI simulation: additional random oracle queries
    let query_rounds = STARK_SECURITY_BITS as u32;
    for round in 0..8u32 {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA_STARK:fri:");
        h.update(&constraint_digest);
        h.update(&round.to_le_bytes());
        let fri_commit: [u8; 32] = h.finalize().into();
        proof_data.extend_from_slice(&fri_commit);
    }

    Ok(StarkProof {
        version: STARK_PROOF_VERSION,
        constraint_digest,
        proof_data,
        query_rounds,
    })
}

// ─── Verifier (stub) ─────────────────────────────────────────

/// Verify a STARK proof against transaction constraints.
///
/// # ⚠ STUB IMPLEMENTATION
///
/// This verifies the hash-based commitment proof.
/// Production will verify proper STARK proofs (FRI verification).
pub fn stark_verify(constraints: &TxConstraints, proof: &StarkProof) -> Result<(), CryptoError> {
    // Version check
    if proof.version != STARK_PROOF_VERSION {
        return Err(CryptoError::ProofInvalid(format!(
            "unsupported STARK proof version: 0x{:02x}",
            proof.version
        )));
    }

    // Validate constraints
    constraints.validate()?;

    // Verify constraint digest match
    let expected_digest = constraints.digest();
    if !ct_eq_32(&proof.constraint_digest, &expected_digest) {
        return Err(CryptoError::ProofInvalid(
            "STARK constraint digest mismatch".into(),
        ));
    }

    // Verify proof data minimum size
    let expected_min_size = 32 // balance commitment
        + constraints.num_outputs * 32 // range commitments
        + constraints.key_images.len() * 32 // KI commitments
        + 8 * 32; // FRI rounds
    if proof.proof_data.len() < expected_min_size {
        return Err(CryptoError::ProofInvalid(format!(
            "STARK proof too short: {} < {}",
            proof.proof_data.len(),
            expected_min_size
        )));
    }

    // Verify balance commitment
    let mut h1 = Sha3_256::new();
    h1.update(b"MISAKA_STARK:balance:");
    h1.update(&expected_digest);
    let expected_balance: [u8; 32] = h1.finalize().into();
    if !ct_eq(&proof.proof_data[..32], &expected_balance) {
        return Err(CryptoError::ProofInvalid(
            "STARK balance commitment mismatch".into(),
        ));
    }

    // Verify range commitments
    let mut offset = 32;
    for (i, amt) in constraints.output_amounts.iter().enumerate() {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA_STARK:range:");
        h.update(&expected_digest);
        h.update(&(i as u32).to_le_bytes());
        h.update(&amt.to_le_bytes());
        let expected: [u8; 32] = h.finalize().into();
        if !ct_eq(&proof.proof_data[offset..offset + 32], &expected) {
            return Err(CryptoError::ProofInvalid(format!(
                "STARK range commitment mismatch at output {}",
                i
            )));
        }
        offset += 32;
    }

    // Verify KI commitments
    for ki in &constraints.key_images {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA_STARK:ki:");
        h.update(&expected_digest);
        h.update(ki);
        let expected: [u8; 32] = h.finalize().into();
        if !ct_eq(&proof.proof_data[offset..offset + 32], &expected) {
            return Err(CryptoError::ProofInvalid(
                "STARK key image commitment mismatch".into(),
            ));
        }
        offset += 32;
    }

    Ok(())
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_constraints() -> TxConstraints {
        TxConstraints {
            tx_digest: [0x11; 32],
            sum_inputs: 10000,
            sum_outputs: 9900,
            fee: 100,
            num_outputs: 2,
            output_amounts: vec![5000, 4900],
            key_images: vec![[0xAA; 32], [0xBB; 32]],
        }
    }

    #[test]
    fn test_constraints_validate_ok() {
        make_test_constraints().validate().unwrap();
    }

    #[test]
    fn test_constraints_validate_balance_mismatch() {
        let mut c = make_test_constraints();
        c.fee = 200; // now sum_inputs != sum_outputs + fee
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_constraints_validate_output_count_mismatch() {
        let mut c = make_test_constraints();
        c.num_outputs = 3; // doesn't match output_amounts.len()
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_constraints_digest_deterministic() {
        let c = make_test_constraints();
        assert_eq!(c.digest(), c.digest());
    }

    #[test]
    fn test_constraints_digest_changes_on_input() {
        let c1 = make_test_constraints();
        let mut c2 = make_test_constraints();
        c2.sum_inputs = 20000;
        c2.sum_outputs = 19900;
        assert_ne!(c1.digest(), c2.digest());
    }

    #[test]
    fn test_stark_prove_verify_roundtrip() {
        let c = make_test_constraints();
        let proof = stark_prove(&c).unwrap();
        stark_verify(&c, &proof).unwrap();
    }

    #[test]
    fn test_stark_verify_wrong_constraints() {
        let c1 = make_test_constraints();
        let proof = stark_prove(&c1).unwrap();

        let mut c2 = make_test_constraints();
        c2.output_amounts = vec![4000, 5900]; // different distribution
        assert!(stark_verify(&c2, &proof).is_err());
    }

    #[test]
    fn test_stark_verify_tampered_proof() {
        let c = make_test_constraints();
        let mut proof = stark_prove(&c).unwrap();
        proof.proof_data[0] ^= 0xFF;
        assert!(stark_verify(&c, &proof).is_err());
    }

    #[test]
    fn test_stark_verify_wrong_version() {
        let c = make_test_constraints();
        let mut proof = stark_prove(&c).unwrap();
        proof.version = 0xFF;
        assert!(stark_verify(&c, &proof).is_err());
    }

    #[test]
    fn test_stark_prove_invalid_constraints() {
        let mut c = make_test_constraints();
        c.fee = 999; // balance mismatch
        assert!(stark_prove(&c).is_err());
    }

    #[test]
    fn test_stark_proof_wire_size() {
        let c = make_test_constraints();
        let proof = stark_prove(&c).unwrap();
        assert!(proof.wire_size() > 0);
        assert_eq!(proof.wire_size(), proof.to_bytes().len());
        assert_eq!(proof.version, STARK_PROOF_VERSION);
    }

    #[test]
    fn test_stark_proof_bytes_roundtrip() {
        let c = make_test_constraints();
        let proof = stark_prove(&c).unwrap();
        let decoded = StarkProof::from_bytes(&proof.to_bytes()).unwrap();
        assert_eq!(decoded.version, proof.version);
        assert_eq!(decoded.constraint_digest, proof.constraint_digest);
        assert_eq!(decoded.query_rounds, proof.query_rounds);
        assert_eq!(decoded.proof_data, proof.proof_data);
    }

    #[test]
    fn test_stark_single_output() {
        let c = TxConstraints {
            tx_digest: [0x22; 32],
            sum_inputs: 1000,
            sum_outputs: 990,
            fee: 10,
            num_outputs: 1,
            output_amounts: vec![990],
            key_images: vec![[0xCC; 32]],
        };
        let proof = stark_prove(&c).unwrap();
        stark_verify(&c, &proof).unwrap();
    }
}
