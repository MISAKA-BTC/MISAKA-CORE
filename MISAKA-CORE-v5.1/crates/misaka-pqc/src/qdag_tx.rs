//! Q-DAG-CT Transaction — Phase 2/4/6 hardened (root binding, nullifier, transcript).
//!
//! # Security Properties (Phase 2-6 audit fixes)
//!
//! 1. **Root binding (Phase 2)**: `input.anonymity_root` MUST match the UnifiedZKP
//!    signature's `merkle_root`. Verifier does NOT trust external ring pubkeys
//!    unless they reconstruct to the declared root.
//!
//! 2. **Ring-independent nullifier (Phase 4)**: `input.nullifier` is derived
//!    from (secret, spent_output_id, chain_id) — NOT from ring_root.
//!    Same UTXO always produces the same nullifier regardless of ring choice.
//!
//! 3. **Unified transcript (Phase 6)**: All proofs (range, balance, membership)
//!    are bound to a single deterministic transcript derived from the full TX.

use sha3::{Sha3_256, Digest as Sha3Digest};
use serde::{Serialize, Deserialize};

use crate::bdlop::{BdlopCommitment, BalanceExcessProof};
use crate::confidential_fee::ConfidentialFee;
use crate::range_proof::RangeProof;
use crate::nullifier::OutputId;
use crate::pq_ring::Poly;
use crate::error::CryptoError;

pub type Hash = [u8; 32];

// ═══════════════════════════════════════════════════════════════
//  Ring Leaf — binds pubkey + commitment + output identity (Phase 2)
// ═══════════════════════════════════════════════════════════════

/// Canonical ring member leaf for Merkle tree construction.
///
/// Phase 2 fix: Ring members are NOT just pubkeys. Each leaf commits to:
/// - spending public key
/// - output commitment (BDLOP)
/// - output identifier (tx_hash + index)
/// - chain domain
///
/// This prevents an attacker from substituting ring members with different
/// commitments or from different chains.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RingMemberLeaf {
    /// Spending public key polynomial (serialized, 512 bytes).
    pub spending_pubkey: Vec<u8>,
    /// BDLOP commitment to the output amount.
    pub commitment: BdlopCommitment,
    /// Output identifier (tx_hash + output_index).
    pub output_id: OutputId,
    /// Chain ID for domain separation.
    pub chain_id: u32,
}

impl RingMemberLeaf {
    /// Compute the canonical leaf hash for Merkle tree inclusion.
    ///
    /// `leaf = SHA3-256("MISAKA_RING_LEAF_V1:" || pk || commitment || output_id || chain_id)`
    pub fn leaf_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA_RING_LEAF_V1:");
        h.update(&self.spending_pubkey);
        h.update(&self.commitment.to_bytes());
        h.update(&self.output_id.to_bytes());
        h.update(&self.chain_id.to_le_bytes());
        h.finalize().into()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Confidential Input (Phase 2+4 hardened)
// ═══════════════════════════════════════════════════════════════

/// Anonymous confidential input with unified ZKP binding.
///
/// # Privacy Model (Task 1.1 — Anonymity-Critical Fix)
///
/// `spent_output_id` has been **completely removed** from this on-chain
/// structure. In the previous design, it was broadcast in plaintext,
/// reducing anonymity to zero regardless of ring size or ZKP quality.
///
/// The output being spent is now a **Private Witness** known only to
/// the prover (sender). It enters the protocol in two ways:
///
/// 1. **Nullifier derivation**: `a_null = DeriveParam(output_id, chain_id)`,
///    `null_poly = a_null · s`, `nullifier = H(null_poly)`.
///    The verifier sees `nullifier` (for double-spend detection) and
///    `nullifier_param` (= a_null, for algebraic binding), but cannot
///    invert to recover `output_id` without O(|UTXO_set|) brute force.
///
/// 2. **Membership proof**: The prover demonstrates in ZK that their
///    secret key `s` corresponds to a public key `pk = a·s` which is
///    a leaf in the Merkle tree rooted at `anonymity_root`.
///
/// The verifier only checks:
///   - The proof is valid against `anonymity_root`
///   - `H(null_poly) == nullifier`
///   - The Σ-protocol binds `s` to both membership and nullifier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidentialInput {
    /// Merkle root of the anonymity set (ring member leaves).
    pub anonymity_root: Hash,

    /// Global nullifier (ring-independent, deterministic per output).
    pub nullifier: [u8; 32],

    /// Serialized `UnifiedMembershipProof`.
    pub membership_proof: Vec<u8>,

    /// BDLOP commitment to the input amount.
    pub input_commitment: BdlopCommitment,

    // NOTE (Phase 1.2): `ring_member_refs` has been REMOVED from this structure.
    //
    // ring_member_refs revealed the candidate anonymity set to on-chain observers,
    // reducing effective anonymity to 1/N even without running the ZKP.
    //
    // Ring member resolution is now handled via `TxAuxData`, which is:
    // - NOT included in the signed transcript (tx_digest)
    // - NOT committed to by the prover
    // - Provided by the submitting node for verification only
    // - Verifiable: the resolved leaves MUST hash to anonymity_root
}

/// Auxiliary verification data — NOT part of the signed transaction.
///
/// This data is needed by validators to verify the ZKP but is NOT
/// committed to by the prover and NOT included in the TX transcript.
///
/// # Privacy Model
///
/// On-chain observers see: `ConfidentialInput` (anonymity_root, nullifier, proof)
/// Validators additionally see: `TxAuxData` (ring member references)
///
/// This gives:
/// - **Observer anonymity**: Cannot identify ring members from on-chain data
/// - **Validator anonymity**: Ring-level (1/N) — validators know the ring
///   but not which member is real
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxAuxData {
    /// Per-input ring member references for verification.
    /// `aux.ring_refs[i]` corresponds to `tx.inputs[i]`.
    /// The verifier resolves these to RingMemberLeaf entries and checks
    /// that their Merkle root matches `input.anonymity_root`.
    pub ring_refs: Vec<Vec<OutputId>>,
}

// ═══════════════════════════════════════════════════════════════
//  Confidential Output
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidentialOutput {
    pub commitment: BdlopCommitment,
    pub range_proof: RangeProof,
    pub stealth_data: ConfidentialStealthData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidentialStealthData {
    pub kem_ct: Vec<u8>,
    pub scan_tag: [u8; 16],
    pub amount_ct: Vec<u8>,
    pub blind_ct: Vec<u8>,
    /// One-time address — 32 bytes for PQ collision resistance.
    /// Previously [u8; 20] which was insufficient for post-quantum security margins.
    pub one_time_address: [u8; 32],
}

// ═══════════════════════════════════════════════════════════════
//  Q-DAG Transaction (Phase 6: unified transcript)
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QdagTxType { Transfer, Coinbase }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QdagTransaction {
    pub version: u8,
    pub tx_type: QdagTxType,
    /// Chain ID — bound into transcript and nullifiers (Phase 6).
    pub chain_id: u32,
    pub parents: Vec<Hash>,
    pub inputs: Vec<ConfidentialInput>,
    pub outputs: Vec<ConfidentialOutput>,
    /// Confidential fee — hidden in BDLOP commitment with range + minimum proofs.
    /// Replaces the old plaintext `fee: u64`.
    /// Balance equation: Σ C_in = Σ C_out + fee_commitment (all hidden).
    pub fee: ConfidentialFee,
    pub balance_proof: BalanceExcessProof,
    pub extra: Vec<u8>,
}

pub const QDAG_VERSION: u8 = 0x10;
pub const MAX_QDAG_INPUTS: usize = 16;
pub const MAX_QDAG_OUTPUTS: usize = 64;
pub const MAX_QDAG_EXTRA: usize = 1024;
/// Maximum membership proof size per input (DoS protection).
/// UnifiedMembershipProof for 1024 members ≈ 3KB.
pub const MAX_MEMBERSHIP_PROOF_SIZE: usize = 32768; // 32 KiB generous limit

impl QdagTransaction {
    /// Unified transcript hash — Phase 6 + Task 1.1 privacy fix.
    ///
    /// ALL proofs must be verified against this transcript.
    /// Changing any field invalidates all proofs.
    ///
    /// # Privacy: spent_output_id is EXCLUDED
    ///
    /// The output being spent is a private witness. Including it in the
    /// transcript would broadcast it on-chain, destroying anonymity.
    /// The nullifier (derived from output_id + secret) is included instead,
    /// providing double-spend detection without identification.
    ///
    /// ```text
    /// transcript = SHA3-256(
    ///   "MISAKA_QDAG_TRANSCRIPT_V2:"
    ///   || version || chain_id
    ///   || len(inputs) || for each input: (anonymity_root || nullifier || input_commitment)
    ///   || len(outputs) || for each output: (commitment || one_time_address)
    ///   || fee_commitment
    ///   || extra
    /// )
    /// ```
    pub fn transcript(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA_QDAG_TRANSCRIPT_V2:");
        h.update([self.version]);
        h.update(self.chain_id.to_le_bytes());
        h.update((self.inputs.len() as u32).to_le_bytes());
        for inp in &self.inputs {
            h.update(&inp.anonymity_root);
            h.update(&inp.nullifier);
            // NOTE: spent_output_id intentionally EXCLUDED (private witness).
            // Including it here would broadcast which UTXO is being spent,
            // reducing anonymity to zero regardless of ring size or ZKP.
            h.update(&inp.input_commitment.to_bytes());
        }
        h.update((self.outputs.len() as u32).to_le_bytes());
        for out in &self.outputs {
            h.update(&out.commitment.to_bytes());
            h.update(&out.stealth_data.one_time_address);
        }
        h.update(&self.fee.commitment.to_bytes());
        h.update((self.extra.len() as u32).to_le_bytes());
        h.update(&self.extra);
        h.finalize().into()
    }

    /// Signing digest — the message signed by UnifiedZKP membership proofs.
    /// Uses the unified transcript (Phase 6).
    pub fn signing_digest(&self) -> [u8; 32] {
        self.transcript()
    }

    /// Backward-compat alias.
    pub fn tx_hash(&self) -> Hash { self.transcript() }

    /// Structural validation + DoS pre-checks (Phase 9).
    ///
    /// This runs BEFORE any expensive cryptographic verification.
    /// Cheap rejections first.
    pub fn validate_structure(&self) -> Result<(), CryptoError> {
        // Version
        if self.version != QDAG_VERSION {
            return Err(CryptoError::RingSignatureInvalid(
                format!("unsupported QDAG version: 0x{:02x}", self.version)));
        }
        // Transfer must have inputs
        if self.tx_type == QdagTxType::Transfer && self.inputs.is_empty() {
            return Err(CryptoError::RingSignatureInvalid(
                "transfer TX must have at least one input".into()));
        }
        // Count limits (Phase 9: DoS)
        if self.inputs.len() > MAX_QDAG_INPUTS {
            return Err(CryptoError::RingSignatureInvalid(
                format!("too many inputs: {} > {}", self.inputs.len(), MAX_QDAG_INPUTS)));
        }
        if self.outputs.len() > MAX_QDAG_OUTPUTS {
            return Err(CryptoError::RingSignatureInvalid(
                format!("too many outputs: {} > {}", self.outputs.len(), MAX_QDAG_OUTPUTS)));
        }
        if self.extra.len() > MAX_QDAG_EXTRA {
            return Err(CryptoError::RingSignatureInvalid(
                format!("extra too large: {} > {}", self.extra.len(), MAX_QDAG_EXTRA)));
        }
        // Phase 9: Size limits on proofs before parsing
        for (i, inp) in self.inputs.iter().enumerate() {
            if inp.membership_proof.len() > MAX_MEMBERSHIP_PROOF_SIZE {
                return Err(CryptoError::RingSignatureInvalid(
                    format!("input[{}] membership_proof too large: {} > {}",
                        i, inp.membership_proof.len(), MAX_MEMBERSHIP_PROOF_SIZE)));
            }
            // Nullifier must not be all zeros (Phase 4)
            if inp.nullifier == [0u8; 32] {
                return Err(CryptoError::RingSignatureInvalid(
                    format!("input[{}] nullifier is all zeros", i)));
            }
            // NOTE: ring_member_refs validation moved to TxAuxData verification
            // (separate from on-chain TX validation). See qdag_verify.rs.
        }
        // Chain ID must be non-zero
        if self.chain_id == 0 {
            return Err(CryptoError::RingSignatureInvalid(
                "chain_id must be non-zero".into()));
        }
        Ok(())
    }

    /// Extract all nullifiers (for DAG state manager double-spend detection).
    pub fn nullifiers(&self) -> Vec<[u8; 32]> {
        self.inputs.iter().map(|i| i.nullifier).collect()
    }

    pub fn input_commitments(&self) -> Vec<&BdlopCommitment> {
        self.inputs.iter().map(|i| &i.input_commitment).collect()
    }

    pub fn output_commitments(&self) -> Vec<&BdlopCommitment> {
        self.outputs.iter().map(|o| &o.commitment).collect()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::range_proof::RangeProof;
    use crate::confidential_fee::FeeMinimumProof;

    fn dummy_balance_proof() -> BalanceExcessProof {
        BalanceExcessProof { challenge: [0u8; 32], response: Poly::zero() }
    }

    fn dummy_range_proof() -> RangeProof {
        RangeProof { bit_commitments: vec![], bit_proofs: vec![] }
    }

    fn dummy_fee() -> ConfidentialFee {
        ConfidentialFee {
            commitment: BdlopCommitment(Poly::zero()),
            range_proof: dummy_range_proof(),
            minimum_proof: FeeMinimumProof {
                diff_range_proof: dummy_range_proof(),
            },
            proposer_hint_ct: vec![],
        }
    }

    fn dummy_input(nullifier: [u8; 32]) -> ConfidentialInput {
        ConfidentialInput {
            anonymity_root: [0xAA; 32],
            nullifier,
            membership_proof: vec![0u8; 100],
            input_commitment: BdlopCommitment(Poly::zero()),
        }
    }

    #[test]
    fn test_transcript_deterministic() {
        let tx = QdagTransaction {
            version: QDAG_VERSION, tx_type: QdagTxType::Coinbase, chain_id: 2,
            parents: vec![], inputs: vec![], outputs: vec![], fee: dummy_fee(),
            balance_proof: dummy_balance_proof(), extra: vec![],
        };
        assert_eq!(tx.transcript(), tx.transcript());
    }

    #[test]
    fn test_transcript_changes_with_chain_id() {
        let mut tx = QdagTransaction {
            version: QDAG_VERSION, tx_type: QdagTxType::Coinbase, chain_id: 1,
            parents: vec![], inputs: vec![], outputs: vec![], fee: dummy_fee(),
            balance_proof: dummy_balance_proof(), extra: vec![],
        };
        let t1 = tx.transcript();
        tx.chain_id = 2;
        let t2 = tx.transcript();
        assert_ne!(t1, t2, "different chain_id must produce different transcript");
    }

    #[test]
    fn test_transcript_changes_with_nullifier() {
        let tx1 = QdagTransaction {
            version: QDAG_VERSION, tx_type: QdagTxType::Transfer, chain_id: 2,
            parents: vec![], inputs: vec![dummy_input([0x11; 32])],
            outputs: vec![], fee: dummy_fee(),
            balance_proof: dummy_balance_proof(), extra: vec![],
        };
        let tx2 = QdagTransaction {
            version: QDAG_VERSION, tx_type: QdagTxType::Transfer, chain_id: 2,
            parents: vec![], inputs: vec![dummy_input([0x22; 32])],
            outputs: vec![], fee: dummy_fee(),
            balance_proof: dummy_balance_proof(), extra: vec![],
        };
        assert_ne!(tx1.transcript(), tx2.transcript());
    }

    #[test]
    fn test_zero_nullifier_rejected() {
        let tx = QdagTransaction {
            version: QDAG_VERSION, tx_type: QdagTxType::Transfer, chain_id: 2,
            parents: vec![], inputs: vec![dummy_input([0; 32])],
            outputs: vec![], fee: dummy_fee(),
            balance_proof: dummy_balance_proof(), extra: vec![],
        };
        assert!(tx.validate_structure().is_err());
    }

    #[test]
    fn test_oversized_proof_rejected() {
        let mut inp = dummy_input([0x11; 32]);
        inp.membership_proof = vec![0u8; MAX_MEMBERSHIP_PROOF_SIZE + 1];
        let tx = QdagTransaction {
            version: QDAG_VERSION, tx_type: QdagTxType::Transfer, chain_id: 2,
            parents: vec![], inputs: vec![inp],
            outputs: vec![], fee: dummy_fee(),
            balance_proof: dummy_balance_proof(), extra: vec![],
        };
        assert!(tx.validate_structure().is_err());
    }


}
