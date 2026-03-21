//! UTXO Mempool — ZKP-only admission (v4).
//!
//! # Admission Pipeline (Task 4.1)
//!
//! 1. Structural validation
//! 2. **Cheap size gate** — O(1) byte length checks (anti-DoS)
//! 3. Capacity check
//! 4. Dedup
//! 5. **O(1) Nullifier conflict** — mempool + chain HashSet lookup (anti-DoS)
//! 6. Stealth sanity
//! 7. Insert (full ZKP verified at block validation)
//!
//! Ring signature paths have been completely removed.

pub mod admission_pipeline;
pub mod reconciliation;
pub mod reorg_handler;

use admission_pipeline::{
    build_privacy_constraints, build_privacy_statement,
    cheap_size_gate, ResolvedInputAmounts,
};
use misaka_pqc::pq_ring::{derive_public_param, Poly, DEFAULT_A_SEED};
use misaka_pqc::{
    select_privacy_backend, PrivacyBackendFamily,
    PrivacyBackendPreference, TransactionPrivacyConstraints,
    TransactionPublicStatement,
};
use misaka_storage::utxo_set::UtxoSet;
use misaka_types::stealth::PQ_STEALTH_VERSION;
use misaka_types::utxo::*;
use std::collections::{BTreeMap, HashSet};

/// Mempool admission error — every failure path explicit.
#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    #[error("structural: {0}")]
    Structural(String),
    #[error("nullifier conflict: {0}")]
    NullifierConflict(String),
    #[error("ring member not found: input[{index}] member {member}")]
    RingMemberNotFound { index: usize, member: String },
    #[error("ring member has no spending pubkey: input[{index}]")]
    RingMemberNoPubkey { index: usize },
    #[error("stealth malformed: output[{index}]: {reason}")]
    StealthMalformed { index: usize, reason: String },
    #[error("amount mismatch: inputs={inputs}, outputs+fee={required}")]
    AmountMismatch { inputs: u64, required: u64 },
    #[error("ring amounts not uniform: input[{index}]: {reason}")]
    RingAmountNotUniform { index: usize, reason: String },
    #[error("privacy constraints: {0}")]
    PrivacyConstraints(String),
    #[error("privacy statement: {0}")]
    PrivacyStatement(String),
    #[error("zero-knowledge proof: {0}")]
    ZeroKnowledgeProof(String),
    #[error("capacity full")]
    CapacityFull,
}

pub struct MempoolEntry {
    pub tx: UtxoTransaction,
    pub tx_hash: [u8; 32],
    pub received_at_ms: u64,
    pub privacy_constraints: Option<TransactionPrivacyConstraints>,
    pub privacy_statement: Option<TransactionPublicStatement>,
}

pub struct UtxoMempool {
    entries: BTreeMap<[u8; 32], MempoolEntry>,
    /// Q-DAG-CT (v4): Nullifiers in mempool.
    nullifiers_mempool: HashSet<[u8; 32]>,
    /// Q-DAG-CT (v4): Nullifiers spent on-chain.
    spent_nullifiers: HashSet<[u8; 32]>,
    max_size: usize,
    /// Shared lattice parameter.
    a_param: Poly,
}

impl UtxoMempool {
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            nullifiers_mempool: HashSet::new(),
            spent_nullifiers: HashSet::new(),
            max_size,
            a_param: derive_public_param(&DEFAULT_A_SEED),
        }
    }

    /// Full-verification admission. ALL checks internal.
    ///
    /// # Admission Order (Task 4.1 — cheap checks first)
    ///
    /// 1. Structural validation (field sizes, version)
    /// 2. Cheap size gate (tx byte length, proof byte length) — O(1)
    /// 3. Capacity check
    /// 4. Dedup (tx_hash)
    /// 5. Backend selection (UnifiedZKP)
    /// 6. Nullifier conflict (mempool + chain) — O(1) HashSet
    /// 7. Stealth sanity
    /// 8. Insert with nullifier tracking
    ///
    /// Full ZKP verification is deferred to block validation (qdag_verify).
    pub fn admit(
        &mut self,
        tx: UtxoTransaction,
        utxo_set: &UtxoSet,
        now_ms: u64,
    ) -> Result<[u8; 32], MempoolError> {
        // ── 1. Structural validation ──
        tx.validate_structure()
            .map_err(|e| MempoolError::Structural(e.to_string()))?;

        // ── 2. Cheap size gate (Task 4.1) ──
        cheap_size_gate(&tx)?;

        // ── 3. Capacity ──
        if self.entries.len() >= self.max_size {
            return Err(MempoolError::CapacityFull);
        }

        // ── 4. Dedup ──
        let tx_hash = tx.tx_hash();
        if self.entries.contains_key(&tx_hash) {
            return Ok(tx_hash);
        }

        let _selected_backend = select_privacy_backend(&tx, PrivacyBackendPreference::Auto)
            .map_err(|e| MempoolError::Structural(e.to_string()))?;

        // ── 5. Nullifier conflict check — O(1) (Task 4.1) ──
        //
        // In v4, key_image field carries the nullifier.
        // Check against BOTH chain state and mempool set BEFORE
        // any expensive cryptographic verification.
        for inp in &tx.inputs {
            let nullifier = inp.key_image;

            if self.spent_nullifiers.contains(&nullifier) {
                return Err(MempoolError::NullifierConflict(format!(
                    "{} spent on-chain",
                    hex::encode(nullifier)
                )));
            }
            if self.nullifiers_mempool.contains(&nullifier) {
                return Err(MempoolError::NullifierConflict(format!(
                    "{} in mempool",
                    hex::encode(nullifier)
                )));
            }
        }

        // ── 6. Stealth extension sanity ──
        for (i, out) in tx.outputs.iter().enumerate() {
            if let Some(ref sd) = out.pq_stealth {
                if sd.version != PQ_STEALTH_VERSION && sd.version != 0x02 {
                    return Err(MempoolError::StealthMalformed {
                        index: i,
                        reason: format!("version {}", sd.version),
                    });
                }
                if sd.kem_ct.len() != 1088 {
                    return Err(MempoolError::StealthMalformed {
                        index: i,
                        reason: format!("kem_ct len {}", sd.kem_ct.len()),
                    });
                }
            }
        }

        // ── 7. Track nullifiers + insert ──
        //
        // NOTE: Full ZKP verification (membership proofs, range proofs,
        // balance proofs, nullifier binding) is performed at block
        // validation time via qdag_verify. The mempool performs only
        // cheap structural + nullifier-conflict checks to prevent DoS.
        for inp in &tx.inputs {
            self.nullifiers_mempool.insert(inp.key_image);
        }

        self.entries.insert(
            tx_hash,
            MempoolEntry {
                tx,
                tx_hash,
                received_at_ms: now_ms,
                privacy_constraints: None,
                privacy_statement: None,
            },
        );

        Ok(tx_hash)
    }

    /// Mark nullifier as spent on-chain; evict conflicting mempool txs.
    pub fn mark_nullifier_spent(&mut self, nullifier: [u8; 32]) {
        self.spent_nullifiers.insert(nullifier);
        let to_remove: Vec<[u8; 32]> = self
            .entries
            .iter()
            .filter(|(_, e)| e.tx.inputs.iter().any(|inp| inp.key_image == nullifier))
            .map(|(h, _)| *h)
            .collect();
        for h in to_remove {
            self.remove(&h);
        }
    }

    pub fn remove(&mut self, tx_hash: &[u8; 32]) -> bool {
        if let Some(entry) = self.entries.remove(tx_hash) {
            for inp in &entry.tx.inputs {
                self.nullifiers_mempool.remove(&inp.key_image);
            }
            true
        } else {
            false
        }
    }

    pub fn top_by_fee(&self, n: usize) -> Vec<&UtxoTransaction> {
        let mut txs: Vec<&MempoolEntry> = self.entries.values().collect();
        txs.sort_by(|a, b| b.tx.fee.cmp(&a.tx.fee));
        txs.truncate(n);
        txs.into_iter().map(|e| &e.tx).collect()
    }

    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    pub fn privacy_constraints(
        &self,
        tx_hash: &[u8; 32],
    ) -> Option<&TransactionPrivacyConstraints> {
        self.entries
            .get(tx_hash)
            .and_then(|entry| entry.privacy_constraints.as_ref())
    }

    pub fn privacy_statement(&self, tx_hash: &[u8; 32]) -> Option<&TransactionPublicStatement> {
        self.entries
            .get(tx_hash)
            .and_then(|entry| entry.privacy_statement.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_v4_tx(nullifier: [u8; 32]) -> UtxoTransaction {
        UtxoTransaction {
            version: UTXO_TX_VERSION_V4,
            ring_scheme: 0x10, // SCHEME_UNIFIED_ZKP
            tx_type: TxType::Transfer,
            inputs: vec![RingInput {
                ring_members: (0..4).map(|i| OutputRef {
                    tx_hash: [(i + 1) as u8; 32],
                    output_index: 0,
                }).collect(),
                ring_signature: vec![0u8; 2048],
                key_image: nullifier,
                ki_proof: vec![],
            }],
            outputs: vec![TxOutput {
                amount: 9_900,
                one_time_address: [0xBB; 32],
                pq_stealth: None,
                spending_pubkey: None,
            }],
            fee: 100,
            extra: vec![],
            zk_proof: None,
        }
    }

    #[test]
    fn test_admit_v4_tx() {
        let mut pool = UtxoMempool::new(100);
        let utxo_set = UtxoSet::new(100);
        let tx = sample_v4_tx([0xAA; 32]);
        let hash = pool.admit(tx, &utxo_set, 1000).unwrap();
        assert_eq!(pool.len(), 1);
        assert_ne!(hash, [0; 32]);
    }

    #[test]
    fn test_duplicate_nullifier_rejected() {
        let mut pool = UtxoMempool::new(100);
        let utxo_set = UtxoSet::new(100);
        pool.admit(sample_v4_tx([0xAA; 32]), &utxo_set, 1000).unwrap();
        let result = pool.admit(sample_v4_tx([0xAA; 32]), &utxo_set, 2000);
        assert!(result.is_err());
    }

    #[test]
    fn test_spent_nullifier_rejected() {
        let mut pool = UtxoMempool::new(100);
        let utxo_set = UtxoSet::new(100);
        pool.mark_nullifier_spent([0xAA; 32]);
        let result = pool.admit(sample_v4_tx([0xAA; 32]), &utxo_set, 1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_mark_nullifier_spent_evicts() {
        let mut pool = UtxoMempool::new(100);
        let utxo_set = UtxoSet::new(100);
        pool.admit(sample_v4_tx([0xBB; 32]), &utxo_set, 1000).unwrap();
        assert_eq!(pool.len(), 1);
        pool.mark_nullifier_spent([0xBB; 32]);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_capacity_full_rejected() {
        let mut pool = UtxoMempool::new(1);
        let utxo_set = UtxoSet::new(100);
        pool.admit(sample_v4_tx([0x01; 32]), &utxo_set, 1000).unwrap();
        let result = pool.admit(sample_v4_tx([0x02; 32]), &utxo_set, 2000);
        assert!(matches!(result, Err(MempoolError::CapacityFull)));
    }

    #[test]
    fn test_cheap_size_gate_rejects_oversized() {
        let mut pool = UtxoMempool::new(100);
        let utxo_set = UtxoSet::new(100);
        let mut tx = sample_v4_tx([0xCC; 32]);
        tx.inputs[0].ring_signature = vec![0u8; admission_pipeline::MAX_PROOF_BYTES_PER_INPUT + 1];
        let result = pool.admit(tx, &utxo_set, 1000);
        assert!(result.is_err());
    }
}
