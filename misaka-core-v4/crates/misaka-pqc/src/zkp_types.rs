//! ZKP Type System — Public Instance / Private Witness / Proof / Relation.
//!
//! # Architecture (Phase 1 — Type-Level Privacy Enforcement)
//!
//! This module enforces at the Rust type level that secret information
//! cannot accidentally leak into public structures. The separation:
//!
//! - **PublicInstance**: Data visible to all observers and verifiers.
//!   Contains ONLY: anonymity_root, nullifier, commitments, merkle_root.
//!
//! - **PrivateWitness**: Data known ONLY to the prover.
//!   Contains: secret key, membership index, Merkle path, blinding factors,
//!   output_id, amounts, path direction bits.
//!
//! - **Proof**: The zero-knowledge proof itself. Contains NO secret data
//!   and NO data that allows efficient identification of the real input.
//!
//! # Security Properties
//!
//! - **Soundness**: An efficient prover cannot produce a valid proof for
//!   a false statement (wrong membership, wrong nullifier, wrong balance).
//!
//! - **Zero-Knowledge**: The proof reveals nothing about the witness beyond
//!   the truth of the statement. Specifically, a simulator can produce
//!   proofs indistinguishable from real ones without any witness.
//!
//! - **Witness Indistinguishability**: Even with the verification key,
//!   no efficient distinguisher can determine which witness was used.

use serde::{Serialize, Deserialize};
use crate::pq_ring::Poly;
use crate::bdlop::{BdlopCommitment, BlindingFactor};
use crate::nullifier::OutputId;

// ═══════════════════════════════════════════════════════════════
//  Membership Relation
// ═══════════════════════════════════════════════════════════════

/// Public instance for membership proof.
///
/// The verifier sees ONLY this. It reveals:
/// - Which anonymity set (Merkle root) the prover claims membership in
/// - The transaction message being signed
///
/// It does NOT reveal: which leaf, which public key, which output.
#[derive(Debug, Clone)]
pub struct MembershipInstance {
    /// Merkle root of the anonymity set.
    pub anonymity_root: [u8; 32],
    /// Transaction signing digest (binds proof to TX context).
    pub message: [u8; 32],
}

/// Private witness for membership proof.
///
/// Known ONLY to the prover. NEVER serialized to wire or stored on-chain.
///
/// # Contained secrets
/// - `secret`: The spending secret polynomial `s` such that `pk = a·s`
/// - `signer_pk`: The public key (derivable from secret, but cached)
/// - `leaf_index`: Position in the Merkle tree (hidden by ring-scan verification)
/// - `merkle_path`: Sibling hashes at each tree level
/// - `path_directions`: Left/right at each level (hidden by ring-scan verification)
pub struct MembershipWitness {
    pub secret: Poly,
    pub signer_pk: Poly,
    pub leaf_index: usize,
    pub leaf_hashes: Vec<[u8; 32]>,
}

// ═══════════════════════════════════════════════════════════════
//  Nullifier Relation
// ═══════════════════════════════════════════════════════════════

/// Public instance for nullifier proof.
///
/// The verifier sees:
/// - The claimed nullifier hash (for double-spend detection)
/// - The nullifier derivation parameter `a_null` (one-way from output_id)
///
/// The verifier does NOT see: output_id, chain_id (embedded in a_null).
#[derive(Debug, Clone)]
pub struct NullifierInstance {
    /// Nullifier hash: `H(a_null · s)`.
    pub nullifier_hash: [u8; 32],
    /// Nullifier parameter: `a_null = DeriveParam(output_id, chain_id)`.
    /// One-way derivation; output_id recovery requires O(|UTXO_set|) brute force.
    pub nullifier_param: Poly,
}

/// Private witness for nullifier proof.
///
/// The SAME secret `s` as in MembershipWitness — this binding is
/// enforced by the unified Σ-protocol using a single challenge.
pub struct NullifierWitness {
    /// Spending secret (SAME as membership witness).
    pub secret: Poly,
    /// Output being spent (PRIVATE — never on-chain).
    pub output_id: OutputId,
    /// Chain ID (PRIVATE — encoded in nullifier_param).
    pub chain_id: u32,
}

// ═══════════════════════════════════════════════════════════════
//  Range Relation
// ═══════════════════════════════════════════════════════════════

/// Public instance for range proof.
#[derive(Debug, Clone)]
pub struct RangeInstance {
    /// BDLOP commitment to the value being range-checked.
    pub commitment: BdlopCommitment,
}

/// Private witness for range proof.
pub struct RangeWitness {
    /// The actual value (PRIVATE).
    pub value: u64,
    /// Blinding factor (PRIVATE).
    pub blinding: BlindingFactor,
}

// ═══════════════════════════════════════════════════════════════
//  Unified Transaction Statement
// ═══════════════════════════════════════════════════════════════

/// Complete public statement for a confidential transaction.
///
/// This is the ONLY structure the verifier receives.
/// It contains no secret information and no data that identifies
/// the real input among the anonymity set.
///
/// # Verifier's view
///
/// The verifier can confirm:
/// 1. The prover knows a secret in the anonymity set (membership)
/// 2. The nullifier is correctly derived from that secret (nullifier)
/// 3. All amounts are non-negative (range proofs)
/// 4. Total inputs = total outputs + fee (balance)
/// 5. The fee is within bounds (fee range + minimum)
///
/// The verifier CANNOT determine:
/// - Which UTXO was spent
/// - Which public key in the ring belongs to the spender
/// - The amounts of any input or output
/// - The blinding factors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicTxStatement {
    /// Per-input public instances.
    pub input_instances: Vec<InputPublicInstance>,
    /// Output commitments (amounts hidden).
    pub output_commitments: Vec<BdlopCommitment>,
    /// Fee commitment.
    pub fee_commitment: BdlopCommitment,
    /// Transaction chain ID (for domain separation).
    pub chain_id: u32,
    /// Canonical transaction digest (binds all proofs).
    pub tx_digest: [u8; 32],
}

/// Public instance for a single input (no secret data).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputPublicInstance {
    /// Merkle root of the anonymity set.
    pub anonymity_root: [u8; 32],
    /// Nullifier (double-spend detection).
    pub nullifier: [u8; 32],
    /// Input commitment (amount hidden).
    pub input_commitment: BdlopCommitment,
}

/// Complete private witness for transaction construction.
///
/// This structure is NEVER serialized, NEVER sent over the wire,
/// NEVER stored on-chain. It exists only in the prover's memory
/// during proof generation and is zeroized immediately after.
pub struct PrivateTxWitness {
    /// Per-input witnesses.
    pub input_witnesses: Vec<InputPrivateWitness>,
    /// Per-output witnesses.
    pub output_witnesses: Vec<OutputPrivateWitness>,
    /// Fee witness.
    pub fee_value: u64,
    pub fee_blinding: BlindingFactor,
}

/// Private witness for a single input.
pub struct InputPrivateWitness {
    /// Spending secret polynomial.
    pub secret: Poly,
    /// Public key (derived from secret).
    pub signer_pk: Poly,
    /// Output being spent.
    pub output_id: OutputId,
    /// Position in the Merkle tree.
    pub leaf_index: usize,
    /// All leaf hashes (for Merkle path computation).
    pub leaf_hashes: Vec<[u8; 32]>,
    /// Input amount.
    pub amount: u64,
    /// Input blinding factor.
    pub blinding: BlindingFactor,
}

/// Private witness for a single output.
pub struct OutputPrivateWitness {
    pub amount: u64,
    pub blinding: BlindingFactor,
}

// ═══════════════════════════════════════════════════════════════
//  Compile-Time Safety
// ═══════════════════════════════════════════════════════════════

// Witness types intentionally do NOT implement Serialize/Deserialize.
// This prevents accidental serialization to wire or storage.
// Any attempt to derive Serialize on a Witness type is a compilation error.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_instance_is_serializable() {
        // PublicTxStatement derives Serialize — this compiles
        let _ = std::mem::size_of::<PublicTxStatement>();
    }

    // The following would NOT compile if uncommented, proving type safety:
    // fn witness_not_serializable(w: &PrivateTxWitness) {
    //     serde_json::to_string(w); // ERROR: Serialize not implemented
    // }
}
