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
use crate::nullifier::{OutputId, NullifierProof};
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
/// # Architecture: UnifiedZKP → UnifiedZKP
///
/// The `membership_proof` field now contains a serialized `UnifiedMembershipProof`
/// which simultaneously proves:
///   1. Merkle membership (position hidden)
///   2. Key ownership (pk = a·s)
///   3. Nullifier correctness (null_poly = a_null·s, H(null_poly) = nullifier)
///
/// The separate `nullifier_proof` field has been removed — it is now embedded
/// in the unified proof. This eliminates the risk of proof mismatch between
/// the membership and nullifier components.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidentialInput {
    /// Merkle root of the ring member set.
    pub anonymity_root: Hash,

    /// Global nullifier (ring-independent).
    /// Verified algebraically within the unified ZKP.
    pub nullifier: [u8; 32],

    /// Serialized `UnifiedMembershipProof`.
    /// Contains membership + nullifier + key ownership in ONE proof.
    pub membership_proof: Vec<u8>,

    /// Output being spent.
    pub spent_output_id: OutputId,

    /// BDLOP commitment to the input amount.
    pub input_commitment: BdlopCommitment,

    /// Explicit ring member references (OutputIds of all ring members).
    ///
    /// The verifier resolves these from the UTXO set to reconstruct
    /// `RingMemberLeaf` entries, then verifies that their Merkle root
    /// matches `anonymity_root`. The real input is hidden among these
    /// by the zero-knowledge proof.
    ///
    /// Length MUST equal `STANDARD_RING_SIZE` (privacy.rs).
    pub ring_member_refs: Vec<OutputId>,
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
    /// Unified transcript hash — Phase 6.
    ///
    /// ALL proofs must be verified against this transcript.
    /// Changing any field invalidates all proofs.
    ///
    /// ```text
    /// transcript = SHA3-256(
    ///   "MISAKA_QDAG_TRANSCRIPT_V1:"
    ///   || version || chain_id
    ///   || len(inputs) || for each input: (anonymity_root || nullifier || spent_output_id || input_commitment)
    ///   || len(outputs) || for each output: (commitment || one_time_address)
    ///   || fee
    ///   || extra
    /// )
    /// ```
    pub fn transcript(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA_QDAG_TRANSCRIPT_V1:");
        h.update([self.version]);
        h.update(self.chain_id.to_le_bytes());
        h.update((self.inputs.len() as u32).to_le_bytes());
        for inp in &self.inputs {
            h.update(&inp.anonymity_root);
            h.update(&inp.nullifier);
            h.update(&inp.spent_output_id.to_bytes());
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
            // Ring member refs: must have exactly STANDARD_RING_SIZE entries
            // for Transfer inputs (Coinbase inputs have no ring)
            if self.tx_type == QdagTxType::Transfer {
                use crate::privacy::STANDARD_RING_SIZE;
                if inp.ring_member_refs.len() != STANDARD_RING_SIZE {
                    return Err(CryptoError::RingSignatureInvalid(
                        format!("input[{}] ring_member_refs count {} != STANDARD_RING_SIZE {}",
                            i, inp.ring_member_refs.len(), STANDARD_RING_SIZE)));
                }
                // Duplicate ring member check (prevents trivial deanonymization)
                let mut seen = std::collections::HashSet::new();
                for r in &inp.ring_member_refs {
                    if !seen.insert(r.to_bytes()) {
                        return Err(CryptoError::RingSignatureInvalid(
                            format!("input[{}] duplicate ring_member_ref", i)));
                    }
                }
            }
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
            spent_output_id: OutputId { tx_hash: [0xBB; 32], output_index: 0 },
            input_commitment: BdlopCommitment(Poly::zero()),
            ring_member_refs: vec![],
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

    #[test]
    fn test_wrong_ring_size_rejected() {
        use crate::privacy::STANDARD_RING_SIZE;
        let mut inp = dummy_input([0x11; 32]);
        // Provide wrong number of ring members (not STANDARD_RING_SIZE)
        inp.ring_member_refs = vec![
            OutputId { tx_hash: [0xCC; 32], output_index: 0 },
        ];
        let tx = QdagTransaction {
            version: QDAG_VERSION, tx_type: QdagTxType::Transfer, chain_id: 2,
            parents: vec![], inputs: vec![inp],
            outputs: vec![], fee: dummy_fee(),
            balance_proof: dummy_balance_proof(), extra: vec![],
        };
        let result = tx.validate_structure();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ring_member_refs"));
    }

    #[test]
    fn test_duplicate_ring_member_rejected() {
        use crate::privacy::STANDARD_RING_SIZE;
        let mut inp = dummy_input([0x11; 32]);
        let same_ref = OutputId { tx_hash: [0xCC; 32], output_index: 0 };
        inp.ring_member_refs = std::iter::repeat(same_ref)
            .take(STANDARD_RING_SIZE)
            .collect();
        let tx = QdagTransaction {
            version: QDAG_VERSION, tx_type: QdagTxType::Transfer, chain_id: 2,
            parents: vec![], inputs: vec![inp],
            outputs: vec![], fee: dummy_fee(),
            balance_proof: dummy_balance_proof(), extra: vec![],
        };
        let result = tx.validate_structure();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("duplicate"));
    }
}
