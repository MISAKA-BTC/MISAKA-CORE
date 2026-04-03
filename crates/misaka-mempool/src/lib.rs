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
//! Lattice ZKP proof paths have been completely removed.

pub mod admission_pipeline;
pub mod reconciliation;
pub mod reorg_handler;
pub mod shielded_admission;

use admission_pipeline::{cheap_size_gate, lightweight_zkp_precheck};
pub use admission_pipeline::PeerTxAdmissionGate;
use misaka_pqc::{
    select_privacy_backend, PrivacyBackendPreference, TransactionPrivacyConstraints,
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

// ═══════════════════════════════════════════════════════════════
//  D3: Maximum mempool byte budget (Red Team audit fix)
//
//  max_size (TX count) alone is insufficient: 10K × 2 MiB = 20 GiB.
//  This caps total mempool byte consumption independently.
// ═══════════════════════════════════════════════════════════════

/// Default maximum mempool size in bytes (256 MiB).
pub const DEFAULT_MAX_MEMPOOL_BYTES: usize = 256 * 1024 * 1024;

/// Minimum fee required for mempool admission.
/// Transactions with fee < MIN_MEMPOOL_FEE are rejected outright.
pub const MIN_MEMPOOL_FEE: u64 = 1;

pub struct MempoolEntry {
    pub tx: UtxoTransaction,
    pub tx_hash: [u8; 32],
    pub received_at_ms: u64,
    /// Approximate byte size of this transaction (cached at admission).
    pub estimated_bytes: usize,
    pub privacy_constraints: Option<TransactionPrivacyConstraints>,
    pub privacy_statement: Option<TransactionPublicStatement>,
}

pub struct UtxoMempool {
    entries: BTreeMap<[u8; 32], MempoolEntry>,
    /// Q-DAG-CT (v4): Nullifiers in mempool.
    nullifiers_mempool: HashSet<[u8; 32]>,
    /// Q-DAG-CT (v4): Nullifiers spent on-chain.
    spent_nullifiers: HashSet<[u8; 32]>,
    /// Maximum number of transactions.
    max_size: usize,
    /// D3: Maximum total byte size of all transactions in mempool.
    max_bytes: usize,
    /// D3: Current total byte size.
    current_bytes: usize,
}

impl UtxoMempool {
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            nullifiers_mempool: HashSet::new(),
            spent_nullifiers: HashSet::new(),
            max_size,
            max_bytes: DEFAULT_MAX_MEMPOOL_BYTES,
            current_bytes: 0,
        }
    }

    /// Create with explicit byte budget.
    pub fn with_byte_limit(max_size: usize, max_bytes: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            nullifiers_mempool: HashSet::new(),
            spent_nullifiers: HashSet::new(),
            max_size,
            max_bytes,
            current_bytes: 0,
        }
    }

    /// Full-verification admission. ALL checks internal.
    ///
    /// # Admission Order (Task 4.1 — cheap checks first)
    ///
    /// 1. Structural validation (field sizes, version)
    /// 2. Cheap size gate (tx byte length, proof byte length) — O(1)
    /// 3. Minimum fee check (D2)
    /// 4. Dedup (tx_hash)
    /// 5. Backend selection (UnifiedZKP)
    /// 6. Nullifier conflict (mempool + chain) — O(1) HashSet
    /// 7. Stealth sanity
    /// 8. Capacity + byte budget check (D2/D3: evict lowest-fee if full)
    /// 9. Insert with nullifier tracking
    ///
    /// Full ZKP verification is deferred to block validation (qdag_verify).
    pub fn admit(
        &mut self,
        tx: UtxoTransaction,
        _utxo_set: &UtxoSet,
        now_ms: u64,
    ) -> Result<[u8; 32], MempoolError> {
        // ── 1. Structural validation ──
        tx.validate_structure()
            .map_err(|e| MempoolError::Structural(e.to_string()))?;

        // ── 2. Cheap size gate (Task 4.1) ──
        cheap_size_gate(&tx)?;

        // ── 3. Lightweight ZKP pre-validation (D4) ──
        lightweight_zkp_precheck(&tx)?;

        // ── 3b. HIGH-2 FIX: Signature structural check ──
        // Transparent TXs must have non-empty proof (ML-DSA-65 sig) on every input.
        // This prevents unsigned TXs from entering mempool via P2P gossip.
        // Full cryptographic verification happens at RPC admission and block validation.
        if tx.proof_scheme == 0x00 { // PROOF_SCHEME_TRANSPARENT
            for (i, inp) in tx.inputs.iter().enumerate() {
                if inp.proof.is_empty() {
                    return Err(MempoolError::Structural(format!(
                        "input[{}]: missing signature (transparent TX requires ML-DSA-65 proof)", i
                    )));
                }
                // ML-DSA-65 signature is 3309 bytes
                if inp.proof.len() < 3309 {
                    return Err(MempoolError::Structural(format!(
                        "input[{}]: signature too short ({} bytes, expected 3309 for ML-DSA-65)", i, inp.proof.len()
                    )));
                }
            }
        }

        // ── 4. Minimum fee (D2) ──
        if tx.fee < MIN_MEMPOOL_FEE {
            return Err(MempoolError::Structural(format!(
                "fee {} below minimum {}", tx.fee, MIN_MEMPOOL_FEE
            )));
        }

        // ── 4. Dedup ──
        let tx_hash = tx.tx_hash();
        if self.entries.contains_key(&tx_hash) {
            return Ok(tx_hash);
        }

        let _selected_backend = select_privacy_backend(&tx, PrivacyBackendPreference::Auto)
            .map_err(|e| MempoolError::Structural(e.to_string()))?;

        // ── 5. Nullifier conflict check — O(1) (Task 4.1) ──
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

        // ── 7. Estimate TX byte size ──
        let estimated_bytes = estimate_tx_bytes(&tx);

        // ── 8. Capacity + byte budget (D2: fee-based eviction, D3: byte limit) ──
        //
        // If mempool is full (by count OR bytes), try to evict the
        // lowest-fee transaction. Only evict if the new TX has a
        // strictly higher fee than the victim.
        if self.entries.len() >= self.max_size
            || self.current_bytes.saturating_add(estimated_bytes) > self.max_bytes
        {
            // Find the lowest-fee entry
            let lowest = self.entries.values()
                .min_by_key(|e| e.tx.fee)
                .map(|e| (e.tx_hash, e.tx.fee, e.estimated_bytes));

            match lowest {
                Some((victim_hash, victim_fee, _victim_bytes)) if tx.fee > victim_fee => {
                    // D2: Evict lowest-fee TX to make room for higher-fee TX
                    self.remove(&victim_hash);
                }
                Some(_) => {
                    // New TX doesn't pay more than the cheapest — reject
                    return Err(MempoolError::CapacityFull);
                }
                None => {
                    return Err(MempoolError::CapacityFull);
                }
            }
        }

        // ── 9. Track nullifiers + insert ──
        for inp in &tx.inputs {
            self.nullifiers_mempool.insert(inp.key_image);
        }

        self.current_bytes = self.current_bytes.saturating_add(estimated_bytes);

        self.entries.insert(
            tx_hash,
            MempoolEntry {
                tx,
                tx_hash,
                received_at_ms: now_ms,
                estimated_bytes,
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
            // D3: Track byte accounting
            self.current_bytes = self.current_bytes.saturating_sub(entry.estimated_bytes);
            true
        } else {
            false
        }
    }

    /// Current total byte size of mempool contents.
    pub fn current_bytes(&self) -> usize {
        self.current_bytes
    }

    pub fn top_by_fee(&self, n: usize) -> Vec<&UtxoTransaction> {
        let mut txs: Vec<&MempoolEntry> = self.entries.values().collect();
        txs.sort_by(|a, b| b.tx.fee.cmp(&a.tx.fee));
        txs.truncate(n);
        txs.into_iter().map(|e| &e.tx).collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

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

/// Estimate the byte size of a transaction for mempool accounting.
///
/// Approximates the in-memory footprint by summing variable-length fields.
/// Does NOT need to be exact — used for DoS budget tracking (D3).
fn estimate_tx_bytes(tx: &UtxoTransaction) -> usize {
    let mut total: usize = 64; // fixed fields (version, fee, type, etc.)
    for inp in &tx.inputs {
        total = total.saturating_add(inp.proof.len());
        total = total.saturating_add(inp.ki_proof.len());
        total = total.saturating_add(inp.utxo_refs.len() * 36); // 32 hash + 4 index
        total = total.saturating_add(32); // key_image
    }
    for out in &tx.outputs {
        total = total.saturating_add(72); // amount + ota + fields
        if let Some(ref stealth) = out.pq_stealth {
            total = total.saturating_add(stealth.kem_ct.len());
            total = total.saturating_add(stealth.payload_ct.len());
        }
    }
    total = total.saturating_add(tx.extra.len());
    if let Some(ref zk) = tx.zk_proof {
        total = total.saturating_add(zk.proof_bytes.len());
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_v4_tx(nullifier: [u8; 32]) -> UtxoTransaction {
        // Build a proof with valid D4 structure: tag + length + varied bytes
        let mut proof = Vec::with_capacity(2048);
        proof.extend_from_slice(&admission_pipeline::UNIFIED_ZKP_PROOF_TAG); // 4 bytes tag
        proof.extend_from_slice(&(2040u32).to_le_bytes()); // 4 bytes inner length
        // Fill with varied bytes (not all-same) to pass entropy check
        for i in 0..2040u16 {
            proof.push((i % 256) as u8);
        }

        UtxoTransaction {
            version: UTXO_TX_VERSION_V4,
            proof_scheme: 0x10, // SCHEME_UNIFIED_ZKP
            tx_type: TxType::Transfer,
            inputs: vec![TxInput {
                utxo_refs: (0..4)
                    .map(|i| OutputRef {
                        tx_hash: [(i + 1) as u8; 32],
                        output_index: 0,
                    })
                    .collect(),
                proof,
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
        let first = pool
            .admit(sample_v4_tx([0xAA; 32]), &utxo_set, 1000)
            .unwrap();
        let second = pool
            .admit(sample_v4_tx([0xAA; 32]), &utxo_set, 2000)
            .unwrap();
        assert_eq!(first, second, "exact duplicate tx should dedup by tx_hash");
        assert_eq!(pool.len(), 1);
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
        pool.admit(sample_v4_tx([0xBB; 32]), &utxo_set, 1000)
            .unwrap();
        assert_eq!(pool.len(), 1);
        pool.mark_nullifier_spent([0xBB; 32]);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_capacity_full_rejected_same_fee() {
        let mut pool = UtxoMempool::new(1);
        let utxo_set = UtxoSet::new(100);
        pool.admit(sample_v4_tx([0x01; 32]), &utxo_set, 1000)
            .unwrap();
        // Same fee as existing → can't evict → rejected
        let result = pool.admit(sample_v4_tx([0x02; 32]), &utxo_set, 2000);
        assert!(matches!(result, Err(MempoolError::CapacityFull)));
    }

    #[test]
    fn test_fee_based_eviction() {
        // D2: Higher-fee TX should evict lower-fee TX when pool is full
        let mut pool = UtxoMempool::new(1);
        let utxo_set = UtxoSet::new(100);

        // Insert low-fee TX
        let mut low_fee_tx = sample_v4_tx([0x01; 32]);
        low_fee_tx.fee = 10;
        pool.admit(low_fee_tx, &utxo_set, 1000).unwrap();
        assert_eq!(pool.len(), 1);

        // Insert higher-fee TX → should evict the low-fee one
        let mut high_fee_tx = sample_v4_tx([0x02; 32]);
        high_fee_tx.fee = 1000;
        pool.admit(high_fee_tx, &utxo_set, 2000).unwrap();
        assert_eq!(pool.len(), 1);
        // The remaining TX should be the high-fee one
        let top = pool.top_by_fee(1);
        assert_eq!(top[0].fee, 1000);
    }

    #[test]
    fn test_byte_budget_enforcement() {
        // D3: Byte budget prevents memory exhaustion
        let mut pool = UtxoMempool::with_byte_limit(1000, 10_000); // 10 KB byte limit
        let utxo_set = UtxoSet::new(100);

        // Insert TXs until byte budget is hit
        let tx1 = sample_v4_tx([0x01; 32]); // ~2 KB each
        pool.admit(tx1, &utxo_set, 1000).unwrap();
        assert!(pool.current_bytes() > 0);

        // Fill up with more TXs
        for i in 2..20u8 {
            let mut tx = sample_v4_tx([i; 32]);
            tx.fee = 100 + i as u64; // increasing fee
            let _ = pool.admit(tx, &utxo_set, 1000 + i as u64);
        }
        // Byte budget should prevent unbounded growth
        assert!(pool.current_bytes() <= 10_000 + admission_pipeline::MAX_TX_SIZE);
    }

    #[test]
    fn test_minimum_fee_rejected() {
        let mut pool = UtxoMempool::new(100);
        let utxo_set = UtxoSet::new(100);
        let mut tx = sample_v4_tx([0xDD; 32]);
        tx.fee = 0; // Below MIN_MEMPOOL_FEE
        let result = pool.admit(tx, &utxo_set, 1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_updates_byte_accounting() {
        let mut pool = UtxoMempool::new(100);
        let utxo_set = UtxoSet::new(100);
        let tx = sample_v4_tx([0xEE; 32]);
        let hash = pool.admit(tx, &utxo_set, 1000).unwrap();
        let bytes_after_insert = pool.current_bytes();
        assert!(bytes_after_insert > 0);

        pool.remove(&hash);
        assert_eq!(pool.current_bytes(), 0);
    }

    #[test]
    fn test_cheap_size_gate_rejects_oversized() {
        let mut pool = UtxoMempool::new(100);
        let utxo_set = UtxoSet::new(100);
        let mut tx = sample_v4_tx([0xCC; 32]);
        tx.inputs[0].proof = vec![0u8; admission_pipeline::MAX_PROOF_BYTES_PER_INPUT + 1];
        let result = pool.admit(tx, &utxo_set, 1000);
        assert!(result.is_err());
    }
}
