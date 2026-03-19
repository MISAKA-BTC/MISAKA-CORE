//! DAG Block Producer — Q-DAG-CT native (legacy UtxoTransaction removed).
//!
//! All transactions are `QdagTransaction` with confidential amounts.

use std::sync::Arc;
use std::collections::HashSet;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use tracing::{info, warn, debug, error};

use misaka_pqc::qdag_tx::QdagTransaction;

use crate::dag_block::{DagBlockHeader, DagBlock, Hash, ZERO_HASH, DAG_VERSION, MAX_PARENTS};
use crate::ghostdag::GhostDagManager;
use crate::dag_store::ThreadSafeDagStore;
use crate::dag_state_manager::{
    DagStateManager, OrderedBlockData, OrderedTxData, TxApplyStatus, UtxoAction,
};

// ═══════════════════════════════════════════════════════════════
//  DAG Node State
// ═══════════════════════════════════════════════════════════════

pub struct DagNodeState {
    pub dag_store: ThreadSafeDagStore,
    pub ghostdag: GhostDagManager,
    pub state_manager: DagStateManager,
    pub mempool: DagMempool,
    pub proposer_id: [u8; 32],
    pub block_interval_ms: u64,
    pub max_txs_per_block: usize,
    pub blocks_produced: u64,
}

// ═══════════════════════════════════════════════════════════════
//  Q-DAG-CT Mempool (legacy UtxoTransaction fully removed)
// ═══════════════════════════════════════════════════════════════

/// Mempool for Q-DAG-CT confidential transactions.
///
/// Item 4: All UtxoTransaction references removed.
/// Nullifier-based duplicate detection (not key_image-based).
pub struct DagMempool {
    txs: Vec<QdagTransaction>,
    /// Nullifier set for in-pool duplicate prevention.
    nullifier_set: HashSet<[u8; 32]>,
    max_size: usize,
}

impl DagMempool {
    pub fn new(max_size: usize) -> Self {
        Self { txs: Vec::new(), nullifier_set: HashSet::new(), max_size }
    }

    /// Insert a confidential TX into the mempool.
    ///
    /// Pre-checks:
    /// 1. Pool not full
    /// 2. No nullifier collision within pool
    /// 3. No nullifier already spent in DAG (via callback)
    pub fn insert<F>(&mut self, tx: QdagTransaction, is_null_spent: F) -> Result<(), String>
    where
        F: Fn(&[u8; 32]) -> bool,
    {
        if self.txs.len() >= self.max_size {
            return Err("mempool full".into());
        }

        let nullifiers = tx.nullifiers();

        // Check pool-internal collisions
        for null in &nullifiers {
            if self.nullifier_set.contains(null) {
                return Err(format!(
                    "nullifier {} already in mempool", hex::encode(&null[..8])
                ));
            }
        }

        // Check DAG-level spent status
        for null in &nullifiers {
            if is_null_spent(null) {
                return Err(format!(
                    "nullifier {} already spent in DAG", hex::encode(&null[..8])
                ));
            }
        }

        // Register nullifiers and add TX
        for null in &nullifiers {
            self.nullifier_set.insert(*null);
        }
        self.txs.push(tx);
        Ok(())
    }

    /// Remove a TX by its transcript hash.
    pub fn remove(&mut self, tx_hash: &[u8; 32]) {
        if let Some(pos) = self.txs.iter().position(|tx| &tx.tx_hash() == tx_hash) {
            let tx = self.txs.remove(pos);
            for null in tx.nullifiers() {
                self.nullifier_set.remove(&null);
            }
        }
    }

    /// Evict all TXs whose nullifiers are now spent.
    pub fn evict_spent_nullifiers(&mut self, spent: &HashSet<[u8; 32]>) {
        let before = self.txs.len();
        self.txs.retain(|tx| {
            let dominated = tx.nullifiers().iter().any(|n| spent.contains(n));
            if dominated {
                for n in tx.nullifiers() {
                    self.nullifier_set.remove(&n);
                }
            }
            !dominated
        });
        let evicted = before - self.txs.len();
        if evicted > 0 { debug!("Mempool: evicted {} txs with spent nullifiers", evicted); }
    }

    /// Get top N transactions (by input count as proxy for fee priority).
    /// With confidential fees, exact ordering requires proposer decryption.
    pub fn take_top(&self, n: usize) -> Vec<&QdagTransaction> {
        self.txs.iter().take(n).collect()
    }

    pub fn len(&self) -> usize { self.txs.len() }
    pub fn is_empty(&self) -> bool { self.txs.is_empty() }
}

// ═══════════════════════════════════════════════════════════════
//  Block Assembly
// ═══════════════════════════════════════════════════════════════

/// Assemble a Q-DAG-CT block from tips and confidential transactions.
pub fn assemble_dag_block(
    tips: &[Hash],
    txs: Vec<QdagTransaction>,
    proposer_id: [u8; 32],
    timestamp_ms: u64,
    chain_id: u32,
    epoch: u64,
    proposer_randomness_commitment: [u8; 32],
    protocol_version: u32,
) -> DagBlock {
    let parents: Vec<Hash> = tips.iter().take(MAX_PARENTS).copied().collect();

    let mut block = DagBlock::new(
        DagBlockHeader {
            version: DAG_VERSION,
            chain_id,
            epoch,
            parents,
            timestamp_ms,
            tx_root: ZERO_HASH,
            proposer_id,
            proposer_randomness_commitment,
            protocol_version,
            blue_score: 0,
        },
        txs,
    );
    block.header.tx_root = block.compute_tx_root();
    block
}

// ═══════════════════════════════════════════════════════════════
//  TX Data Conversion (QdagTransaction → OrderedTxData)
// ═══════════════════════════════════════════════════════════════

/// Convert a `QdagTransaction` to `OrderedTxData` for DAG state manager.
///
/// Item 4: Replaces the old `utxo_tx_to_ordered` which used UtxoTransaction.
pub fn qdag_tx_to_ordered(tx: &QdagTransaction) -> OrderedTxData {
    use misaka_pqc::qdag_tx::QdagTxType;
    OrderedTxData {
        tx_hash: tx.tx_hash(),
        nullifiers: tx.nullifiers(),
        is_coinbase: tx.tx_type == QdagTxType::Coinbase,
        output_amounts: vec![], // Confidential: amounts are hidden
        fee: 0, // Confidential: fee is hidden in commitment
        crypto_verified: false,
    }
}

/// Build `OrderedBlockData` from DAG total order (Q-DAG-CT native).
pub fn build_ordered_block_data(
    total_order: &[Hash],
    dag_store: &ThreadSafeDagStore,
) -> Vec<OrderedBlockData> {
    let mut result = Vec::new();
    for block_hash in total_order {
        let txs = dag_store.get_block_qdag_txs(block_hash);
        let blue_score = dag_store.get_blue_score(block_hash);

        let ordered_txs: Vec<OrderedTxData> = txs.iter()
            .map(|tx| qdag_tx_to_ordered(tx))
            .collect();

        result.push(OrderedBlockData {
            block_hash: *block_hash,
            blue_score,
            transactions: ordered_txs,
        });
    }
    result
}

// ═══════════════════════════════════════════════════════════════
//  Block Production Loop
// ═══════════════════════════════════════════════════════════════

/// Run the DAG block production loop (async).
pub async fn run_dag_block_producer(
    state: Arc<RwLock<DagNodeState>>,
) {
    let block_interval = {
        let s = state.read().await;
        Duration::from_millis(s.block_interval_ms)
    };

    let mut ticker = interval(block_interval);
    info!("DAG block producer started (Q-DAG-CT native, interval={}ms)",
        block_interval.as_millis());

    loop {
        ticker.tick().await;
        let mut s = state.write().await;

        if s.mempool.is_empty() {
            continue;
        }

        // 1. Get tips
        let tips = s.dag_store.get_current_tips();
        if tips.is_empty() {
            warn!("No tips available, skipping block production");
            continue;
        }

        // 2. Select TXs from mempool
        let candidate_txs: Vec<QdagTransaction> = s.mempool
            .take_top(s.max_txs_per_block)
            .into_iter()
            .cloned()
            .collect();

        if candidate_txs.is_empty() {
            continue;
        }

        let tx_count = candidate_txs.len();

        // 3. Assemble block
        let block = assemble_dag_block(
            &tips,
            candidate_txs,
            s.proposer_id,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        );

        let block_hash = block.header.compute_hash();

        // 4. Insert into DAG store
        if let Err(e) = s.dag_store.insert_block_with_qdag_txs(
            block_hash,
            block.header.clone(),
            &block.transactions,
        ) {
            error!("Failed to insert block: {}", e);
            continue;
        }

        // 5. Compute GhostDAG
        let ghostdag_data = s.ghostdag.add_block(&block.header, &s.dag_store);
        s.dag_store.store_ghostdag_data(block_hash, ghostdag_data);

        // 6. Re-evaluate total order and apply state
        let total_order = s.ghostdag.get_total_ordering(&s.dag_store);
        let ordered = build_ordered_block_data(&total_order, &s.dag_store);

        let mut new_nullifiers = HashSet::new();
        let results = s.state_manager.apply_ordered_transactions(
            &ordered,
            |action| {
                if let UtxoAction::RecordNullifier { nullifier, .. } = &action {
                    new_nullifiers.insert(*nullifier);
                }
            },
        );

        // 7. Evict spent nullifiers from mempool
        s.mempool.evict_spent_nullifiers(&new_nullifiers);

        // 8. Remove included TXs from mempool
        for tx_hash in block.transactions.iter().map(|tx| tx.tx_hash()) {
            s.mempool.remove(&tx_hash);
        }

        s.blocks_produced += 1;
        let applied = results.iter().filter(|r| matches!(r.status, TxApplyStatus::Applied)).count();
        let failed = results.iter().filter(|r| !matches!(r.status, TxApplyStatus::Applied | TxApplyStatus::AppliedCoinbase)).count();

        info!("Block {} produced: {} txs ({} applied, {} failed), hash={}",
            s.blocks_produced, tx_count, applied, failed,
            hex::encode(&block_hash[..8]));
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_pqc::qdag_tx::{QdagTxType, QDAG_VERSION, ConfidentialInput};
    use misaka_pqc::nullifier::OutputId;
    use misaka_pqc::bdlop::{BdlopCommitment, BalanceExcessProof};
    use misaka_pqc::pq_ring::Poly;
    use misaka_pqc::confidential_fee::{ConfidentialFee, FeeMinimumProof};
    use misaka_pqc::range_proof::RangeProof;

    fn dummy_range_proof() -> RangeProof {
        RangeProof { bit_commitments: vec![], bit_proofs: vec![] }
    }

    fn dummy_fee() -> ConfidentialFee {
        ConfidentialFee {
            commitment: BdlopCommitment(Poly::zero()),
            range_proof: dummy_range_proof(),
            minimum_proof: FeeMinimumProof { diff_range_proof: dummy_range_proof() },
            proposer_hint_ct: vec![],
        }
    }

    fn make_test_tx(nullifiers: Vec<[u8;32]>) -> QdagTransaction {
        let inputs: Vec<ConfidentialInput> = nullifiers.into_iter().map(|n| {
            ConfidentialInput {
                anonymity_root: [0xAA;32], nullifier: n,
                membership_proof: vec![0;100],
                spent_output_id: OutputId { tx_hash: [0xBB;32], output_index: 0 },
                input_commitment: BdlopCommitment(Poly::zero()),
                ring_member_refs: vec![],
            }
        }).collect();
        QdagTransaction {
            version: QDAG_VERSION, tx_type: QdagTxType::Transfer, chain_id: 2,
            parents: vec![], inputs, outputs: vec![], fee: dummy_fee(),
            balance_proof: BalanceExcessProof { challenge: [0;32], response: Poly::zero() },
            extra: vec![],
        }
    }

    #[test]
    fn test_mempool_insert_and_nullifier_check() {
        let mut mp = DagMempool::new(100);
        let tx = make_test_tx(vec![[0x11;32]]);
        mp.insert(tx, |_| false).unwrap();
        assert_eq!(mp.len(), 1);

        // Duplicate nullifier in pool
        let tx2 = make_test_tx(vec![[0x11;32]]);
        assert!(mp.insert(tx2, |_| false).is_err());
    }

    #[test]
    fn test_mempool_spent_nullifier_rejected() {
        let mut mp = DagMempool::new(100);
        let tx = make_test_tx(vec![[0x22;32]]);
        // Nullifier already spent in DAG
        assert!(mp.insert(tx, |n| *n == [0x22;32]).is_err());
    }

    #[test]
    fn test_mempool_evict_spent() {
        let mut mp = DagMempool::new(100);
        mp.insert(make_test_tx(vec![[0x11;32]]), |_| false).unwrap();
        mp.insert(make_test_tx(vec![[0x22;32]]), |_| false).unwrap();
        assert_eq!(mp.len(), 2);

        let mut spent = HashSet::new();
        spent.insert([0x11;32]);
        mp.evict_spent_nullifiers(&spent);
        assert_eq!(mp.len(), 1);
    }

    #[test]
    fn test_qdag_tx_to_ordered() {
        let tx = make_test_tx(vec![[0xAA;32], [0xBB;32]]);
        let ordered = qdag_tx_to_ordered(&tx);
        assert_eq!(ordered.nullifiers.len(), 2);
        assert_eq!(ordered.nullifiers[0], [0xAA;32]);
        assert!(!ordered.is_coinbase);
        assert!(ordered.output_amounts.is_empty(), "amounts are confidential");
    }

    #[test]
    fn test_assemble_block() {
        let tips = vec![[0x01;32], [0x02;32]];
        let txs = vec![make_test_tx(vec![[0xCC;32]])];
        let block = assemble_dag_block(&tips, txs, [0xFF;32], 1000);
        assert_eq!(block.header.parents.len(), 2);
        assert_eq!(block.tx_count(), 1);
        assert_ne!(block.header.tx_root, ZERO_HASH);
    }
}
