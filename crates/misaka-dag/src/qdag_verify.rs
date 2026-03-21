//! Q-DAG-CT Verification Engine — Zero-Knowledge Membership Proof (ZKMP).
//!
//! # Architecture: Perfect ZK, O(log N) Verification, NO Ring Scanning
//!
//! ```text
//! QdagTransaction
//!   ├─→ 0. DoS pre-check: sizes, counts, version (FREE)
//!   ├─→ 1. Root binding: SIS root hash == chain state (CHEAP)
//!   ├─→ 2. ZKMP per input: O(log N) verification
//!   │      - Σ-protocol (key ownership + nullifier binding)
//!   │      - ZK Membership (SIS Merkle + committed path + OR-proofs)
//!   │      - NO ring scanning, NO pk reconstruction
//!   ├─→ 3. Range proofs per output (EXPENSIVE, parallelizable)
//!   ├─→ 4. Confidential fee verification (EXPENSIVE)
//!   ├─→ 5. Balance proof: Σ C_in = Σ C_out + C_fee (EXPENSIVE)
//!   └─→ 6. Nullifier uniqueness: DAG state manager (SEQUENTIAL, external)
//! ```

use misaka_pqc::bdlop::{BdlopCrs, BdlopCommitment, verify_balance_with_excess};
use misaka_pqc::range_proof::verify_range;
use misaka_pqc::unified_zkp::{UnifiedMembershipProof, unified_verify};
use misaka_pqc::pq_ring::{Poly, derive_public_param, DEFAULT_A_SEED};
use misaka_pqc::qdag_tx::{QdagTransaction, QdagTxType};
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
/// # ZKMP Architecture — Perfect ZK, NO ring, O(log N)
///
/// The Zero-Knowledge Membership Proof is self-contained:
/// - The proof contains ONLY BDLOP commitments and OR-proof responses
/// - The verifier checks algebraic equations over commitments
/// - NO ring_pubkeys, NO ring scanning, NO pk reconstruction
/// - Verification: O(depth) = O(log |UTXO_set|)
///
/// # Security
///
/// Even an unbounded verifier (quantum or classical) cannot determine:
/// - Which public key belongs to the signer
/// - Which leaf in the Merkle tree was used
/// - Which direction bits were chosen at each level
///
/// # Parameters
///
/// - `tx`: The transaction to verify
/// - `crs`: BDLOP Common Reference String
/// - `expected_roots`: Per-input SIS root hash from chain state
pub fn verify_qdag_tx(
    tx: &QdagTransaction,
    crs: &BdlopCrs,
    expected_roots: &[[u8; 32]],
) -> QdagVerifyResult {
    // ── 0. Structural + DoS ──
    if let Err(e) = tx.validate_structure() {
        return QdagVerifyResult::StructuralError(e.to_string());
    }
    if tx.tx_type == QdagTxType::Coinbase {
        return QdagVerifyResult::Valid;
    }
    if expected_roots.len() != tx.inputs.len() {
        return QdagVerifyResult::StructuralError(
            format!("expected_roots count {} != input count {}",
                expected_roots.len(), tx.inputs.len()));
    }

    let a = derive_public_param(&DEFAULT_A_SEED);
    let digest = tx.signing_digest();

    for (i, input) in tx.inputs.iter().enumerate() {
        // ── 1. Root binding against chain state ──
        //
        // The input declares an anonymity_root. This MUST match the
        // expected root from the validator's UTXO tree state.
        if input.anonymity_root != expected_roots[i] {
            return QdagVerifyResult::RootBindingFailed {
                input_index: i,
                reason: "input.anonymity_root != chain state root".into(),
            };
        }

        // ── 2. Parse FCMP proof ──
        let proof = match UnifiedMembershipProof::from_bytes(&input.membership_proof) {
            Ok(p) => p,
            Err(e) => return QdagVerifyResult::ZkpFailed {
                input_index: i, reason: format!("parse: {e}"),
            },
        };

        // ── 3. Verify root in proof matches declared root ──
        if proof.membership.sis_root_hash != input.anonymity_root {
            return QdagVerifyResult::ZkpFailed {
                input_index: i,
                reason: "proof.membership.sis_root_hash != input.anonymity_root".into(),
            };
        }

        // ── 4. ZKMP verification — O(log N), Perfect ZK ──
        //
        // unified_verify() performs:
        //   a) Nullifier hash binding: H(null_poly) == input.nullifier
        //   b) Σ-protocol challenge consistency
        //   c) Nullifier Σ: a_null·z − c·null_poly == w_null
        //   d) ZK Membership: committed leaf in SIS Merkle tree (OR-proofs)
        //   e) Root binding: SIS root hash == expected_root
        //
        // The verifier does NOT:
        //   - Receive ring_pubkeys
        //   - Scan any ring members
        //   - Reconstruct the signer's pk
        //   - Learn any information about which UTXO was spent
        if let Err(e) = unified_verify(
            &a, &expected_roots[i], &digest, &input.nullifier, &proof,
        ) {
            return QdagVerifyResult::ZkpFailed {
                input_index: i, reason: format!("FCMP verify: {e}"),
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
                input_commitment: BdlopCommitment(Poly::zero()),
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
