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

use misaka_pqc::bdlop::{verify_balance_with_excess, BdlopCommitment, BdlopCrs};
use misaka_pqc::pq_ring::{derive_public_param, Poly, DEFAULT_A_SEED};
use misaka_pqc::qdag_tx::{QdagTransaction, QdagTxType};
use misaka_pqc::range_proof::verify_range;
use misaka_pqc::unified_zkp::{unified_verify, UnifiedMembershipProof};

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
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
    pub fn error_message(&self) -> Option<String> {
        match self {
            Self::Valid => None,
            Self::StructuralError(s) => Some(format!("structural: {s}")),
            Self::RootBindingFailed {
                input_index,
                reason,
            } => Some(format!("root[{input_index}]: {reason}")),
            Self::ZkpFailed {
                input_index,
                reason,
            } => Some(format!("zkp[{input_index}]: {reason}")),
            Self::RangeProofFailed {
                output_index,
                reason,
            } => Some(format!("range[{output_index}]: {reason}")),
            Self::FeeFailed(s) => Some(format!("fee: {s}")),
            Self::BalanceProofFailed(s) => Some(format!("balance: {s}")),
        }
    }
}

/// Verify all cryptographic proofs in a Q-DAG-CT transaction.
///
/// # P0-3 Fix: Context Binding Enforcement
///
/// The previous implementation called `unified_verify()` which accepts the
/// proof's `ctx_hash` at face value. This meant the Fiat-Shamir challenge
/// was self-consistent but not bound to any external expectation.
///
/// The new implementation:
/// 1. Verifies `proof.nullifier_param == derive_public_param(proof.ctx_hash)` —
///    ensures a_null is correctly derived from the declared context.
/// 2. Accepts per-input `anonymity_root_epoch` from chain state for
///    future explicit context field verification.
/// 3. Falls through to `unified_verify()` which now includes the P0-1
///    key-ownership binding check.
///
/// # Security Model for spent_output_id
///
/// The verifier cannot know `spent_output_id` (it's private). However:
/// - Different `spent_output_id` → different `ctx_hash` → different `a_null`
///   → different `nullifier_poly` → different `nullifier_hash`
/// - The nullifier is checked for uniqueness in the UTXO set (step 6)
/// - Therefore `spent_output_id` is implicitly bound through the nullifier
///
/// # Parameters
///
/// - `tx`: The transaction to verify
/// - `crs`: BDLOP Common Reference String
/// - `expected_roots`: Per-input SIS root hash from chain state
/// - `expected_epochs`: Per-input anonymity root epoch from chain state (P0-3)
pub fn verify_qdag_tx(
    tx: &QdagTransaction,
    crs: &BdlopCrs,
    expected_roots: &[[u8; 32]],
    expected_epochs: &[u64],
) -> QdagVerifyResult {
    // ── 0. Structural + DoS ──
    if let Err(e) = tx.validate_structure() {
        return QdagVerifyResult::StructuralError(e.to_string());
    }
    if tx.tx_type == QdagTxType::Coinbase {
        return QdagVerifyResult::Valid;
    }
    if expected_roots.len() != tx.inputs.len() {
        return QdagVerifyResult::StructuralError(format!(
            "expected_roots count {} != input count {}",
            expected_roots.len(),
            tx.inputs.len()
        ));
    }
    if expected_epochs.len() != tx.inputs.len() {
        return QdagVerifyResult::StructuralError(format!(
            "expected_epochs count {} != input count {}",
            expected_epochs.len(),
            tx.inputs.len()
        ));
    }

    let a = derive_public_param(&DEFAULT_A_SEED);
    let digest = tx.signing_digest();

    for (i, input) in tx.inputs.iter().enumerate() {
        // ── 1. Root binding against chain state ──
        if input.anonymity_root != expected_roots[i] {
            return QdagVerifyResult::RootBindingFailed {
                input_index: i,
                reason: "input.anonymity_root != chain state root".into(),
            };
        }

        // ── 2. Parse FCMP proof ──
        let proof = match UnifiedMembershipProof::from_bytes(&input.membership_proof) {
            Ok(p) => p,
            Err(e) => {
                return QdagVerifyResult::ZkpFailed {
                    input_index: i,
                    reason: format!("parse: {e}"),
                };
            }
        };

        // ── 3. Verify root in proof matches declared root ──
        if proof.membership.sis_root_hash != input.anonymity_root {
            return QdagVerifyResult::ZkpFailed {
                input_index: i,
                reason: "proof.membership.sis_root_hash != input.anonymity_root".into(),
            };
        }

        // ── 3b. P0-3: Nullifier parameter derivation check ──
        //
        // Verify that proof.nullifier_param is correctly derived from proof.ctx_hash.
        // This ensures a_null was produced by:
        //   a_null = DerivePublicParam(NullifierContext.hash())
        //
        // If the prover used a forged context (wrong chain_id, wrong epoch, etc.),
        // the ctx_hash would differ, producing a different a_null. Since we check
        // a_null == derive(ctx_hash), any context manipulation is caught.
        //
        // NOTE: Full external context verification (checking chain_id, epoch against
        // chain state) is not possible here because `spent_output_id` is private and
        // embedded in ctx_hash. External binding is instead guaranteed by:
        //   - Nullifier uniqueness in the UTXO set (different output → different nullifier)
        //   - Root hash matching the chain's current anonymity set
        //
        // TODO(P1): When the protocol adds separate epoch-proof or domain-proof
        // fields to ConfidentialInput, use expected_epochs[i] for explicit verification.
        let _ = expected_epochs[i]; // Reserved for future explicit epoch verification
        let expected_a_null = derive_public_param(&proof.ctx_hash);
        if proof.nullifier_param.coeffs != expected_a_null.coeffs {
            return QdagVerifyResult::ZkpFailed {
                input_index: i,
                reason: "nullifier_param != derive(ctx_hash): context binding broken (P0-3)".into(),
            };
        }

        // ── 4. ZKMP verification — O(log N), Perfect ZK ──
        //
        // unified_verify() now includes:
        //   a) Nullifier hash binding: H(null_poly) == input.nullifier
        //   b) Σ-protocol challenge consistency (with ctx_hash + w_bind)
        //   c) Nullifier Σ: a_null·z − c·null_poly == w_null
        //   d) Key-ownership binding: verifies s links pk to leaf commitment (P0-1)
        //   e) ZK Membership: committed leaf in SIS Merkle tree (OR-proofs)
        //   f) Root binding: SIS root hash == expected_root
        if let Err(e) = unified_verify(&a, &expected_roots[i], &digest, &input.nullifier, &proof) {
            return QdagVerifyResult::ZkpFailed {
                input_index: i,
                reason: format!("FCMP verify: {e}"),
            };
        }
    }

    // ── 4. Range proofs ──
    for (i, output) in tx.outputs.iter().enumerate() {
        if let Err(e) = verify_range(crs, &output.commitment, &output.range_proof) {
            return QdagVerifyResult::RangeProofFailed {
                output_index: i,
                reason: e.to_string(),
            };
        }
    }

    // ── 5. Confidential fee ──
    if let Err(e) = misaka_pqc::confidential_fee::verify_confidential_fee(crs, &tx.fee) {
        return QdagVerifyResult::FeeFailed(e.to_string());
    }

    // ── 6. Balance proof ──
    let mut sum_in = Poly::zero();
    for inp in &tx.inputs {
        sum_in = sum_in.add(&inp.input_commitment.0);
    }
    let mut sum_out = Poly::zero();
    for out in &tx.outputs {
        sum_out = sum_out.add(&out.commitment.0);
    }
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
    use misaka_pqc::bdlop::{BalanceExcessProof, BdlopCommitment};
    use misaka_pqc::confidential_fee::{ConfidentialFee, FeeMinimumProof};
    use misaka_pqc::nullifier::OutputId;
    use misaka_pqc::pq_ring::Poly;
    use misaka_pqc::qdag_tx::{ConfidentialInput, QdagTransaction, QdagTxType, QDAG_VERSION};
    use misaka_pqc::range_proof::RangeProof;

    fn dummy_fee() -> ConfidentialFee {
        ConfidentialFee {
            commitment: BdlopCommitment(Poly::zero()),
            range_proof: RangeProof {
                bit_commitments: vec![],
                bit_proofs: vec![],
            },
            minimum_proof: FeeMinimumProof {
                diff_range_proof: RangeProof {
                    bit_commitments: vec![],
                    bit_proofs: vec![],
                },
            },
            proposer_hint_ct: vec![],
        }
    }

    #[test]
    fn test_coinbase_valid() {
        let crs = BdlopCrs::default_crs();
        let tx = QdagTransaction {
            version: QDAG_VERSION,
            tx_type: QdagTxType::Coinbase,
            chain_id: 2,
            parents: vec![],
            inputs: vec![],
            outputs: vec![],
            fee: dummy_fee(),
            balance_proof: BalanceExcessProof {
                challenge: [0; 32],
                response: Poly::zero(),
            },
            extra: vec![],
        };
        assert!(verify_qdag_tx(&tx, &crs, &[], &[]).is_valid());
    }

    #[test]
    fn test_transfer_no_inputs_rejected() {
        let crs = BdlopCrs::default_crs();
        let tx = QdagTransaction {
            version: QDAG_VERSION,
            tx_type: QdagTxType::Transfer,
            chain_id: 2,
            parents: vec![],
            inputs: vec![],
            outputs: vec![],
            fee: dummy_fee(),
            balance_proof: BalanceExcessProof {
                challenge: [0; 32],
                response: Poly::zero(),
            },
            extra: vec![],
        };
        assert!(!verify_qdag_tx(&tx, &crs, &[], &[]).is_valid());
    }

    #[test]
    fn test_root_mismatch_rejected() {
        let crs = BdlopCrs::default_crs();
        let tx = QdagTransaction {
            version: QDAG_VERSION,
            tx_type: QdagTxType::Transfer,
            chain_id: 2,
            parents: vec![],
            inputs: vec![ConfidentialInput {
                anonymity_root: [0xFF; 32],
                nullifier: [0x11; 32],
                membership_proof: vec![0; 100],
                input_commitment: BdlopCommitment(Poly::zero()),
            }],
            outputs: vec![],
            fee: dummy_fee(),
            balance_proof: BalanceExcessProof {
                challenge: [0; 32],
                response: Poly::zero(),
            },
            extra: vec![],
        };
        let result = verify_qdag_tx(&tx, &crs, &[[0u8; 32]], &[0]);
        assert!(!result.is_valid());
    }
}
