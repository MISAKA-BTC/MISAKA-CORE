//! Q-DAG-CT Verification Engine — Unified ZKP native (LogRing removed).
//!
//! # Verification Pipeline (cheapest rejections first)
//!
//! ```text
//! QdagTransaction
//!   ├─→ 0. DoS pre-check: sizes, counts, version (FREE)
//!   ├─→ 1. Root binding: recomputed root == declared root (CHEAP)
//!   ├─→ 2. Chain ID consistency in ring leaves (CHEAP)
//!   ├─→ 3. Unified ZKP verification per input:
//!   │      - Σ-protocol (key ownership)
//!   │      - Nullifier algebraic binding
//!   │      - OR-proof consistency (MODERATE-EXPENSIVE)
//!   ├─→ 4. Range proofs per output (EXPENSIVE, parallelizable)
//!   ├─→ 5. Confidential fee verification (EXPENSIVE)
//!   ├─→ 6. Balance proof: Σ C_in = Σ C_out + C_fee (EXPENSIVE)
//!   └─→ 7. Nullifier uniqueness: DAG state manager (SEQUENTIAL, external)
//! ```

use misaka_pqc::bdlop::{BdlopCrs, BdlopCommitment, verify_balance_with_excess};
use misaka_pqc::range_proof::verify_range;
use misaka_pqc::unified_zkp::{
    UnifiedMembershipProof, unified_verify, compute_merkle_root,
};
use misaka_pqc::pq_ring::{Poly, derive_public_param, DEFAULT_A_SEED};
use misaka_pqc::qdag_tx::{QdagTransaction, QdagTxType, RingMemberLeaf};
use misaka_pqc::error::CryptoError;

/// Verification result.
#[derive(Debug)]
pub enum QdagVerifyResult {
    Valid,
    StructuralError(String),
    RootBindingFailed { input_index: usize, reason: String },
    ZkpFailed { input_index: usize, reason: String },
    RangeProofFailed { output_index: usize, reason: String },
    FeeFailed(String),
    BalanceProofFailed(String),
}

impl QdagVerifyResult {
    pub fn is_valid(&self) -> bool { matches!(self, Self::Valid) }
    pub fn error_message(&self) -> Option<String> {
        match self {
            Self::Valid => None,
            Self::StructuralError(s) => Some(format!("structural: {s}")),
            Self::RootBindingFailed { input_index, reason } =>
                Some(format!("root[{input_index}]: {reason}")),
            Self::ZkpFailed { input_index, reason } =>
                Some(format!("zkp[{input_index}]: {reason}")),
            Self::RangeProofFailed { output_index, reason } =>
                Some(format!("range[{output_index}]: {reason}")),
            Self::FeeFailed(s) => Some(format!("fee: {s}")),
            Self::BalanceProofFailed(s) => Some(format!("balance: {s}")),
        }
    }
}

/// Verify all cryptographic proofs in a Q-DAG-CT transaction.
///
/// Ring leaves are provided by the caller (resolved from the anonymity set).
/// This function verifies root binding, then delegates to `unified_verify`.
pub fn verify_qdag_tx(
    tx: &QdagTransaction,
    crs: &BdlopCrs,
    ring_leaves_per_input: &[Vec<RingMemberLeaf>],
) -> QdagVerifyResult {
    // ── 0. Structural + DoS ──
    if let Err(e) = tx.validate_structure() {
        return QdagVerifyResult::StructuralError(e.to_string());
    }
    if tx.tx_type == QdagTxType::Coinbase {
        return QdagVerifyResult::Valid;
    }
    if ring_leaves_per_input.len() != tx.inputs.len() {
        return QdagVerifyResult::StructuralError(
            format!("ring_leaves count {} != input count {}",
                ring_leaves_per_input.len(), tx.inputs.len()));
    }

    let a = derive_public_param(&DEFAULT_A_SEED);
    let digest = tx.signing_digest();

    for (i, input) in tx.inputs.iter().enumerate() {
        let leaves = &ring_leaves_per_input[i];

        // ── 1. Root binding ──
        let leaf_hashes: Vec<[u8; 32]> = leaves.iter().map(|l| l.leaf_hash()).collect();
        let recomputed_root = match compute_merkle_root(&leaf_hashes) {
            Ok(r) => r,
            Err(e) => return QdagVerifyResult::RootBindingFailed {
                input_index: i, reason: format!("merkle root: {e}"),
            },
        };
        if recomputed_root != input.anonymity_root {
            return QdagVerifyResult::RootBindingFailed {
                input_index: i,
                reason: format!("recomputed root != declared root"),
            };
        }

        // ── 2. Chain ID consistency ──
        for (j, leaf) in leaves.iter().enumerate() {
            if leaf.chain_id != tx.chain_id {
                return QdagVerifyResult::RootBindingFailed {
                    input_index: i,
                    reason: format!("leaf[{j}] chain_id {} != tx {}", leaf.chain_id, tx.chain_id),
                };
            }
        }

        // ── 3. Parse and verify Unified ZKP ──
        let proof = match UnifiedMembershipProof::from_bytes(&input.membership_proof) {
            Ok(p) => p,
            Err(e) => return QdagVerifyResult::ZkpFailed {
                input_index: i, reason: format!("parse: {e}"),
            },
        };

        // Verify root in proof matches declared root
        if proof.merkle_root != input.anonymity_root {
            return QdagVerifyResult::ZkpFailed {
                input_index: i,
                reason: "proof.merkle_root != input.anonymity_root".into(),
            };
        }

        // Verify output_id in proof matches input's spent_output_id
        if proof.output_id != input.spent_output_id {
            return QdagVerifyResult::ZkpFailed {
                input_index: i,
                reason: "proof.output_id != input.spent_output_id".into(),
            };
        }

        // Verify chain_id in proof
        if proof.chain_id != tx.chain_id {
            return QdagVerifyResult::ZkpFailed {
                input_index: i,
                reason: "proof.chain_id != tx.chain_id".into(),
            };
        }

        // Full unified verification: Σ-protocol + nullifier + OR-proofs
        if let Err(e) = unified_verify(&a, &recomputed_root, &digest, &input.nullifier, &proof) {
            return QdagVerifyResult::ZkpFailed {
                input_index: i, reason: format!("verify: {e}"),
            };
        }
    }

    // ── 4. Range proofs ──
    for (i, output) in tx.outputs.iter().enumerate() {
        if let Err(e) = verify_range(crs, &output.commitment, &output.range_proof) {
            return QdagVerifyResult::RangeProofFailed {
                output_index: i, reason: e.to_string(),
            };
        }
    }

    // ── 5. Confidential fee ──
    if let Err(e) = misaka_pqc::confidential_fee::verify_confidential_fee(crs, &tx.fee) {
        return QdagVerifyResult::FeeFailed(e.to_string());
    }

    // ── 6. Balance proof ──
    let mut sum_in = Poly::zero();
    for inp in &tx.inputs { sum_in = sum_in.add(&inp.input_commitment.0); }
    let mut sum_out = Poly::zero();
    for out in &tx.outputs { sum_out = sum_out.add(&out.commitment.0); }
    let balance_diff = BdlopCommitment(sum_in.sub(&sum_out).sub(&tx.fee.commitment.0));

    if let Err(e) = verify_balance_with_excess(crs, &balance_diff, &tx.balance_proof) {
        return QdagVerifyResult::BalanceProofFailed(e.to_string());
    }

    QdagVerifyResult::Valid
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_pqc::qdag_tx::{QdagTransaction, QdagTxType, ConfidentialInput, QDAG_VERSION};
    use misaka_pqc::nullifier::OutputId;
    use misaka_pqc::bdlop::{BalanceExcessProof, BdlopCommitment};
    use misaka_pqc::pq_ring::Poly;
    use misaka_pqc::range_proof::RangeProof;
    use misaka_pqc::confidential_fee::{ConfidentialFee, FeeMinimumProof};

    fn dummy_fee() -> ConfidentialFee {
        ConfidentialFee {
            commitment: BdlopCommitment(Poly::zero()),
            range_proof: RangeProof { bit_commitments: vec![], bit_proofs: vec![] },
            minimum_proof: FeeMinimumProof {
                diff_range_proof: RangeProof { bit_commitments: vec![], bit_proofs: vec![] },
            },
            proposer_hint_ct: vec![],
        }
    }

    #[test]
    fn test_coinbase_valid() {
        let crs = BdlopCrs::default_crs();
        let tx = QdagTransaction {
            version: QDAG_VERSION, tx_type: QdagTxType::Coinbase, chain_id: 2,
            parents: vec![], inputs: vec![], outputs: vec![],
            fee: dummy_fee(),
            balance_proof: BalanceExcessProof { challenge: [0;32], response: Poly::zero() },
            extra: vec![],
        };
        assert!(verify_qdag_tx(&tx, &crs, &[]).is_valid());
    }

    #[test]
    fn test_transfer_no_inputs_rejected() {
        let crs = BdlopCrs::default_crs();
        let tx = QdagTransaction {
            version: QDAG_VERSION, tx_type: QdagTxType::Transfer, chain_id: 2,
            parents: vec![], inputs: vec![], outputs: vec![],
            fee: dummy_fee(),
            balance_proof: BalanceExcessProof { challenge: [0;32], response: Poly::zero() },
            extra: vec![],
        };
        assert!(!verify_qdag_tx(&tx, &crs, &[]).is_valid());
    }

    #[test]
    fn test_root_mismatch_rejected() {
        let crs = BdlopCrs::default_crs();
        let tx = QdagTransaction {
            version: QDAG_VERSION, tx_type: QdagTxType::Transfer, chain_id: 2,
            parents: vec![],
            inputs: vec![ConfidentialInput {
                anonymity_root: [0xFF; 32],
                nullifier: [0x11; 32],
                membership_proof: vec![0; 100],
                spent_output_id: OutputId { tx_hash: [0;32], output_index: 0 },
                input_commitment: BdlopCommitment(Poly::zero()),
                ring_member_refs: vec![],
            }],
            outputs: vec![],
            fee: dummy_fee(),
            balance_proof: BalanceExcessProof { challenge: [0;32], response: Poly::zero() },
            extra: vec![],
        };
        let result = verify_qdag_tx(&tx, &crs, &[vec![]]);
        assert!(!result.is_valid());
    }
}
