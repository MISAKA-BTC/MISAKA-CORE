//! Mempool admission pipeline — ZKP-only (v4).
//!
//! Ring-signature stages (LogRingLinkTagConflict, SameAmountRing, RingFamilyProof)
//! have been removed. All transactions are validated via UnifiedZKP.
//!
//! # Cheap Check Gate (Task 4.1)
//!
//! Before invoking expensive ZKP verification, the mempool performs O(1) checks:
//! 1. Transaction byte length ≤ MAX_TX_SIZE
//! 2. Proof byte length ≤ MAX_PROOF_SIZE per input
//! 3. Nullifier collision against mempool + chain (O(1) HashSet lookup)
//! These gates prevent DoS via malformed or oversized payloads.

use crate::MempoolError;
use misaka_pqc::{
    tx_spend_semantics_for_backend, validate_public_statement, Poly, PrivacyBackendFamily,
    SpendIdentifierModel, TransactionPrivacyConstraints, TransactionPublicStatement,
};
use misaka_storage::utxo_set::UtxoSet;
use misaka_types::utxo::{TxType, UtxoTransaction};

// ═══════════════════════════════════════════════════════════════
//  Task 4.1: Cheap Check Constants
// ═══════════════════════════════════════════════════════════════

/// Maximum serialized transaction size (bytes). Transactions exceeding this
/// are rejected before any cryptographic verification.
/// 2 MiB — generous for confidential TXs with ZKP membership proofs.
pub const MAX_TX_SIZE: usize = 2 * 1024 * 1024;

/// Maximum ZKP membership proof size per input (bytes).
/// UnifiedMembershipProof: ~5 × 512 (Poly) + membership proof (variable).
/// 256 KiB per input is generous for depth-20 Merkle trees.
pub const MAX_PROOF_BYTES_PER_INPUT: usize = 256 * 1024;

/// Maximum total proof bytes across all inputs in a single transaction.
pub const MAX_TOTAL_PROOF_BYTES: usize = 1024 * 1024; // 1 MiB

// ═══════════════════════════════════════════════════════════════
//  Admission Stages
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MempoolAdmissionStage {
    /// Structural validation (version, input/output counts, field sizes).
    Structural,
    /// Cheap size gate: tx byte length, proof byte length.
    CheapSizeGate,
    /// Mempool capacity check.
    Capacity,
    /// Duplicate transaction check.
    Duplicate,
    /// O(1) nullifier conflict check (mempool + chain).
    NullifierConflict,
    /// Stealth output sanity (KEM ciphertext size, version).
    StealthSanity,
    /// Privacy statement consistency (constraints match tx fields).
    PrivacyStatementConsistency,
    /// Full ZKP verification (Σ-protocol + SIS Merkle + range proofs).
    ZeroKnowledgeProof,
    /// Insert into mempool.
    Insert,
}

// ═══════════════════════════════════════════════════════════════
//  P0-3: Per-Peer TX Admission Rate Gate
// ═══════════════════════════════════════════════════════════════

/// Maximum TX submissions per peer per sliding window.
///
/// The transport layer already limits generic messages to 150/sec, but
/// each TX triggers expensive ZKP verification (~10ms per lattice proof).
/// At 150 TX/sec, a single peer can burn 1.5 CPU-seconds per wall-second.
///
/// This limit caps TX admissions per peer to a sustainable rate that
/// leaves CPU headroom for block production and other peers' TXs.
pub const MAX_TX_PER_PEER_PER_WINDOW: u32 = 30;

/// Sliding window size for per-peer TX rate limiting.
pub const TX_RATE_WINDOW_SECS: u64 = 60;

/// Maximum total pending TX evaluations across all peers.
/// Prevents aggregate CPU exhaustion even if many peers each stay
/// within their individual limit.
pub const MAX_GLOBAL_PENDING_TX_EVALUATIONS: usize = 200;

/// Per-peer TX admission rate gate.
///
/// Runs BEFORE expensive ZKP verification. Tracks the number of TX
/// submissions per peer in a sliding window. If a peer exceeds the
/// limit, their TXs are rejected with a rate-limit error.
///
/// # Why Not Just Use Transport Rate Limiting?
///
/// The transport layer (150 msg/sec) handles generic flooding — ping,
/// block requests, inventory. But TX submission is asymmetrically
/// expensive: each TX requires ZKP verification (10-50ms). A peer
/// sending 150 TXs/sec can consume 1.5-7.5 CPU-seconds/sec on
/// verification alone, starving block production.
///
/// This gate ensures no single peer can monopolize the verification
/// pipeline, regardless of how fast they send at the transport layer.
pub struct PeerTxAdmissionGate {
    /// peer_id_prefix (first 8 bytes) → (window_start_ms, count)
    counters: std::collections::HashMap<[u8; 8], (u64, u32)>,
    /// Total pending evaluations across all peers.
    global_pending: usize,
    /// Last GC timestamp (ms).
    last_gc_ms: u64,
}

impl PeerTxAdmissionGate {
    pub fn new() -> Self {
        Self {
            counters: std::collections::HashMap::new(),
            global_pending: 0,
            last_gc_ms: 0,
        }
    }

    /// Check if a TX from `peer_prefix` should be admitted for evaluation.
    ///
    /// Returns `Ok(())` if allowed, `Err(reason)` if rate-limited.
    pub fn check(&mut self, peer_prefix: &[u8], now_ms: u64) -> Result<(), String> {
        // Global budget check
        if self.global_pending >= MAX_GLOBAL_PENDING_TX_EVALUATIONS {
            return Err(format!(
                "global TX evaluation budget exhausted ({}/{})",
                self.global_pending, MAX_GLOBAL_PENDING_TX_EVALUATIONS
            ));
        }

        // GC every 5 minutes
        if now_ms.saturating_sub(self.last_gc_ms) > 300_000 {
            let cutoff = now_ms.saturating_sub(TX_RATE_WINDOW_SECS * 2 * 1000);
            self.counters.retain(|_, (start, _)| *start > cutoff);
            self.last_gc_ms = now_ms;
        }

        let mut key = [0u8; 8];
        let copy_len = peer_prefix.len().min(8);
        key[..copy_len].copy_from_slice(&peer_prefix[..copy_len]);

        let window_ms = TX_RATE_WINDOW_SECS * 1000;
        let entry = self.counters.entry(key).or_insert((now_ms, 0));

        // Reset window if expired
        if now_ms.saturating_sub(entry.0) >= window_ms {
            *entry = (now_ms, 0);
        }

        entry.1 += 1;

        if entry.1 > MAX_TX_PER_PEER_PER_WINDOW {
            Err(format!(
                "peer TX rate limit exceeded ({}/{} per {}s window)",
                entry.1, MAX_TX_PER_PEER_PER_WINDOW, TX_RATE_WINDOW_SECS
            ))
        } else {
            self.global_pending += 1;
            Ok(())
        }
    }

    /// Mark one TX evaluation as completed (whether accepted or rejected).
    pub fn complete_evaluation(&mut self) {
        self.global_pending = self.global_pending.saturating_sub(1);
    }

    /// Current number of pending evaluations.
    pub fn pending_count(&self) -> usize {
        self.global_pending
    }
}

impl MempoolAdmissionStage {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Structural => "structural",
            Self::CheapSizeGate => "cheap_size_gate",
            Self::Capacity => "capacity",
            Self::Duplicate => "duplicate",
            Self::NullifierConflict => "nullifier_conflict",
            Self::StealthSanity => "stealth_sanity",
            Self::PrivacyStatementConsistency => "privacy_statement_consistency",
            Self::ZeroKnowledgeProof => "zero_knowledge_proof",
            Self::Insert => "insert",
        }
    }
}

/// ZKP-only admission pipeline.
///
/// Order is critical: cheap checks FIRST, expensive ZKP verification LAST.
/// This prevents DoS attacks where an attacker submits invalid but
/// expensive-to-verify transactions.
pub const ZKP_ADMISSION_PIPELINE: &[MempoolAdmissionStage] = &[
    MempoolAdmissionStage::Structural,
    MempoolAdmissionStage::CheapSizeGate, // Task 4.1: reject oversized before crypto
    MempoolAdmissionStage::Capacity,
    MempoolAdmissionStage::Duplicate,
    MempoolAdmissionStage::NullifierConflict, // Task 4.1: O(1) nullifier check
    MempoolAdmissionStage::StealthSanity,
    MempoolAdmissionStage::PrivacyStatementConsistency,
    MempoolAdmissionStage::ZeroKnowledgeProof, // Expensive — always last
    MempoolAdmissionStage::Insert,
];

pub const fn mempool_admission_pipeline(
    _backend_family: PrivacyBackendFamily,
) -> &'static [MempoolAdmissionStage] {
    ZKP_ADMISSION_PIPELINE
}

// ═══════════════════════════════════════════════════════════════
//  Task 4.1: Cheap Check Implementation
// ═══════════════════════════════════════════════════════════════

/// Perform cheap O(1) size checks before any cryptographic verification.
///
/// Rejects:
/// - Transactions exceeding MAX_TX_SIZE total bytes
/// - Individual input proof bytes exceeding MAX_PROOF_BYTES_PER_INPUT
/// - Total proof bytes exceeding MAX_TOTAL_PROOF_BYTES
pub fn cheap_size_gate(tx: &UtxoTransaction) -> Result<(), MempoolError> {
    // Check total serialized size (approximate — uses proof + ki_proof + extra + zk_proof)
    let mut total_bytes: usize = 0;
    for inp in &tx.inputs {
        total_bytes = total_bytes.saturating_add(inp.proof.len());
        total_bytes = total_bytes.saturating_add(inp.ki_proof.len());
    }
    for out in &tx.outputs {
        if let Some(ref stealth) = out.pq_stealth {
            total_bytes = total_bytes.saturating_add(stealth.kem_ct.len());
            total_bytes = total_bytes.saturating_add(stealth.payload_ct.len());
        }
    }
    total_bytes = total_bytes.saturating_add(tx.extra.len());
    if let Some(ref zk) = tx.zk_proof {
        total_bytes = total_bytes.saturating_add(zk.proof_bytes.len());
    }

    if total_bytes > MAX_TX_SIZE {
        return Err(MempoolError::Structural(format!(
            "transaction too large: {} bytes > {} max",
            total_bytes, MAX_TX_SIZE
        )));
    }

    // Check per-input proof sizes
    let mut total_proof_bytes: usize = 0;
    for (i, inp) in tx.inputs.iter().enumerate() {
        // In v4, proof carries the UnifiedMembershipProof bytes
        let proof_len = inp.proof.len();
        if proof_len > MAX_PROOF_BYTES_PER_INPUT {
            return Err(MempoolError::Structural(format!(
                "input[{}] proof too large: {} bytes > {} max",
                i, proof_len, MAX_PROOF_BYTES_PER_INPUT
            )));
        }
        total_proof_bytes = total_proof_bytes.saturating_add(proof_len);
    }

    if total_proof_bytes > MAX_TOTAL_PROOF_BYTES {
        return Err(MempoolError::Structural(format!(
            "total proof bytes too large: {} > {} max",
            total_proof_bytes, MAX_TOTAL_PROOF_BYTES
        )));
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
//  Privacy Constraint Helpers (kept for v4 statement validation)
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedInputAmounts {
    pub input_amounts: Vec<u64>,
    pub sum_inputs: u64,
    pub sum_outputs: u64,
    pub required: u64,
}

pub fn build_privacy_constraints(
    tx: &UtxoTransaction,
    resolved: &ResolvedInputAmounts,
    backend_family: PrivacyBackendFamily,
) -> Result<TransactionPrivacyConstraints, MempoolError> {
    let constraints = TransactionPrivacyConstraints::from_tx_and_input_amounts_for_backend(
        tx,
        &resolved.input_amounts,
        backend_family,
    )
    .map_err(|e| MempoolError::PrivacyConstraints(e.to_string()))?;

    Ok(constraints)
}

pub fn build_privacy_statement(
    tx: &UtxoTransaction,
    constraints: &TransactionPrivacyConstraints,
    ring_pubkeys: &[Vec<Poly>],
    backend_family: PrivacyBackendFamily,
) -> Result<TransactionPublicStatement, MempoolError> {
    let statement = TransactionPublicStatement::from_constraints_and_resolved_rings(
        tx,
        constraints,
        ring_pubkeys,
        backend_family,
    )
    .map_err(|e| MempoolError::PrivacyStatement(e.to_string()))?;

    validate_public_statement(&statement, tx, constraints, backend_family)
        .map_err(|e| MempoolError::PrivacyStatement(e.to_string()))?;

    Ok(statement)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionPrivacyConstraintError {
    #[error("tx_hash mismatch")]
    TxHashMismatch,
    #[error("signing_digest mismatch")]
    SigningDigestMismatch,
    #[error("tx_type mismatch: constraints={constraints:?} tx={tx:?}")]
    TxTypeMismatch { constraints: TxType, tx: TxType },
    #[error("proof_scheme mismatch: constraints=0x{constraints:02x} tx=0x{tx:02x}")]
    RingSchemeMismatch { constraints: u8, tx: u8 },
    #[error("input_count mismatch: constraints={constraints} tx={tx}")]
    InputCountMismatch { constraints: usize, tx: usize },
    #[error("output_count mismatch: constraints={constraints} tx={tx}")]
    OutputCountMismatch { constraints: usize, tx: usize },
    #[error("sum_inputs mismatch: constraints={constraints} resolved={resolved}")]
    SumInputsMismatch { constraints: u64, resolved: u64 },
    #[error("sum_outputs mismatch: constraints={constraints} resolved={resolved}")]
    SumOutputsMismatch { constraints: u64, resolved: u64 },
    #[error("fee mismatch: constraints={constraints} tx={tx}")]
    FeeMismatch { constraints: u64, tx: u64 },
    #[error("output_amounts mismatch")]
    OutputAmountsMismatch,
    #[error("spend_identifier_model mismatch: constraints={constraints:?} tx={tx:?}")]
    SpendIdentifierModelMismatch {
        constraints: SpendIdentifierModel,
        tx: SpendIdentifierModel,
    },
    #[error("spend_identifier_label mismatch")]
    SpendIdentifierLabelMismatch,
    #[error("spend_identifiers mismatch")]
    SpendIdentifiersMismatch,
    #[error("key_images mismatch")]
    KeyImagesMismatch,
}

pub fn validate_resolved_privacy_constraints(
    constraints: &TransactionPrivacyConstraints,
    tx: &UtxoTransaction,
    resolved: &ResolvedInputAmounts,
    backend_family: PrivacyBackendFamily,
) -> Result<(), AdmissionPrivacyConstraintError> {
    // v4: use tx_hash_without_zk_proof for ZK backend
    let expected_tx_hash = tx.tx_hash_without_zk_proof();
    if constraints.tx_hash != expected_tx_hash {
        return Err(AdmissionPrivacyConstraintError::TxHashMismatch);
    }
    if constraints.signing_digest != tx.signing_digest() {
        return Err(AdmissionPrivacyConstraintError::SigningDigestMismatch);
    }
    if constraints.tx_type != tx.tx_type {
        return Err(AdmissionPrivacyConstraintError::TxTypeMismatch {
            constraints: constraints.tx_type,
            tx: tx.tx_type,
        });
    }
    if constraints.proof_scheme != tx.proof_scheme {
        return Err(AdmissionPrivacyConstraintError::RingSchemeMismatch {
            constraints: constraints.proof_scheme,
            tx: tx.proof_scheme,
        });
    }
    if constraints.input_count != tx.inputs.len() {
        return Err(AdmissionPrivacyConstraintError::InputCountMismatch {
            constraints: constraints.input_count,
            tx: tx.inputs.len(),
        });
    }
    if constraints.output_count != tx.outputs.len() {
        return Err(AdmissionPrivacyConstraintError::OutputCountMismatch {
            constraints: constraints.output_count,
            tx: tx.outputs.len(),
        });
    }
    if constraints.fee != tx.fee {
        return Err(AdmissionPrivacyConstraintError::FeeMismatch {
            constraints: constraints.fee,
            tx: tx.fee,
        });
    }

    let expected_spend_semantics = tx_spend_semantics_for_backend(tx, backend_family);
    if constraints.spend_identifier_model != expected_spend_semantics.spend_identifier_model {
        return Err(
            AdmissionPrivacyConstraintError::SpendIdentifierModelMismatch {
                constraints: constraints.spend_identifier_model,
                tx: expected_spend_semantics.spend_identifier_model,
            },
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_pqc::unified_zkp::SCHEME_UNIFIED_ZKP;
    use misaka_types::utxo::{OutputRef, TxInput, TxOutput, UtxoTransaction, UTXO_TX_VERSION_V4};

    fn sample_v4_tx() -> UtxoTransaction {
        UtxoTransaction {
            version: UTXO_TX_VERSION_V4,
            proof_scheme: SCHEME_UNIFIED_ZKP,
            tx_type: TxType::Transfer,
            inputs: vec![TxInput {
                utxo_refs: vec![
                    OutputRef {
                        tx_hash: [1u8; 32],
                        output_index: 0,
                    },
                    OutputRef {
                        tx_hash: [2u8; 32],
                        output_index: 0,
                    },
                    OutputRef {
                        tx_hash: [3u8; 32],
                        output_index: 0,
                    },
                    OutputRef {
                        tx_hash: [4u8; 32],
                        output_index: 0,
                    },
                ],
                proof: vec![0u8; 4096], // Simulated proof
                key_image: [9u8; 32],
                ki_proof: vec![],
            }],
            outputs: vec![TxOutput {
                amount: 9_900,
                one_time_address: [3u8; 32],
                pq_stealth: None,
                spending_pubkey: None,
            }],
            fee: 100,
            extra: vec![],
            zk_proof: None,
        }
    }

    #[test]
    fn test_zkp_pipeline_has_cheap_gate_before_zkp() {
        let stages = mempool_admission_pipeline(PrivacyBackendFamily::ZeroKnowledge);
        let gate_idx = stages
            .iter()
            .position(|s| *s == MempoolAdmissionStage::CheapSizeGate)
            .unwrap();
        let zk_idx = stages
            .iter()
            .position(|s| *s == MempoolAdmissionStage::ZeroKnowledgeProof)
            .unwrap();
        assert!(
            gate_idx < zk_idx,
            "cheap gate must come before ZKP verification"
        );
    }

    #[test]
    fn test_cheap_size_gate_accepts_normal_tx() {
        let tx = sample_v4_tx();
        cheap_size_gate(&tx).unwrap();
    }

    #[test]
    fn test_cheap_size_gate_rejects_oversized_proof() {
        let mut tx = sample_v4_tx();
        tx.inputs[0].proof = vec![0u8; MAX_PROOF_BYTES_PER_INPUT + 1];
        assert!(cheap_size_gate(&tx).is_err());
    }

    #[test]
    fn test_cheap_size_gate_rejects_oversized_total() {
        let mut tx = sample_v4_tx();
        tx.extra = vec![0u8; MAX_TX_SIZE + 1];
        assert!(cheap_size_gate(&tx).is_err());
    }

    #[test]
    fn test_nullifier_conflict_before_zkp() {
        let stages = mempool_admission_pipeline(PrivacyBackendFamily::ZeroKnowledge);
        let null_idx = stages
            .iter()
            .position(|s| *s == MempoolAdmissionStage::NullifierConflict)
            .unwrap();
        let zk_idx = stages
            .iter()
            .position(|s| *s == MempoolAdmissionStage::ZeroKnowledgeProof)
            .unwrap();
        assert!(null_idx < zk_idx, "nullifier conflict must come before ZKP");
    }

    // ── P0-3 Tests: Per-Peer TX Admission Rate Gate ──

    #[test]
    fn test_peer_tx_gate_allows_within_limit() {
        let mut gate = PeerTxAdmissionGate::new();
        let peer = [0xAA; 8];
        let now = 1_000_000u64;

        for _ in 0..MAX_TX_PER_PEER_PER_WINDOW {
            assert!(gate.check(&peer, now).is_ok());
        }
    }

    #[test]
    fn test_peer_tx_gate_rejects_over_limit() {
        let mut gate = PeerTxAdmissionGate::new();
        let peer = [0xBB; 8];
        let now = 1_000_000u64;

        for _ in 0..MAX_TX_PER_PEER_PER_WINDOW {
            gate.check(&peer, now).unwrap();
        }

        let result = gate.check(&peer, now);
        assert!(result.is_err(), "must reject when over per-peer limit");
    }

    #[test]
    fn test_peer_tx_gate_separate_peers_independent() {
        let mut gate = PeerTxAdmissionGate::new();
        let peer_a = [0xAA; 8];
        let peer_b = [0xBB; 8];
        let now = 1_000_000u64;

        // Exhaust peer A's budget
        for _ in 0..MAX_TX_PER_PEER_PER_WINDOW {
            gate.check(&peer_a, now).unwrap();
        }
        assert!(gate.check(&peer_a, now).is_err());

        // Peer B is unaffected
        assert!(gate.check(&peer_b, now).is_ok());
    }

    #[test]
    fn test_peer_tx_gate_window_resets() {
        let mut gate = PeerTxAdmissionGate::new();
        let peer = [0xCC; 8];

        // Exhaust budget at t=0
        let t0 = 1_000_000u64;
        for _ in 0..MAX_TX_PER_PEER_PER_WINDOW {
            gate.check(&peer, t0).unwrap();
        }
        assert!(gate.check(&peer, t0).is_err());

        // Window resets after TX_RATE_WINDOW_SECS
        let t1 = t0 + TX_RATE_WINDOW_SECS * 1000;
        assert!(gate.check(&peer, t1).is_ok(), "window should have reset");
    }

    #[test]
    fn test_peer_tx_gate_global_budget() {
        let mut gate = PeerTxAdmissionGate::new();
        let now = 1_000_000u64;

        // Fill global budget from many different peers
        for i in 0..MAX_GLOBAL_PENDING_TX_EVALUATIONS {
            let peer = (i as u64).to_le_bytes();
            gate.check(&peer, now).unwrap();
        }

        // Next TX from any peer should fail (global budget exhausted)
        let new_peer = [0xFF; 8];
        let result = gate.check(&new_peer, now);
        assert!(result.is_err(), "must reject when global budget exhausted");
        assert!(
            result.unwrap_err().contains("global"),
            "error should mention global budget"
        );
    }

    #[test]
    fn test_peer_tx_gate_complete_frees_budget() {
        let mut gate = PeerTxAdmissionGate::new();
        let now = 1_000_000u64;

        // Fill global budget
        for i in 0..MAX_GLOBAL_PENDING_TX_EVALUATIONS {
            let peer = (i as u64).to_le_bytes();
            gate.check(&peer, now).unwrap();
        }
        assert!(gate.check(&[0xFF; 8], now).is_err());

        // Complete one evaluation
        gate.complete_evaluation();
        assert_eq!(gate.pending_count(), MAX_GLOBAL_PENDING_TX_EVALUATIONS - 1);

        // Now one more TX should be allowed
        assert!(gate.check(&[0xFF; 8], now).is_ok());
    }
}
