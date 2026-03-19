//! # DAG ブロック生成器 (MISAKA-CORE v2)
//!
//! ## v1 → v2 の変更点
//!
//! | v1 (block_producer.rs)                   | v2 (dag_block_producer.rs)                    |
//! |------------------------------------------|-----------------------------------------------|
//! | `parent_hash = chain.tip_hash`           | `parents = dag.get_tips()` (複数親)           |
//! | `height = s.height + 1`                  | `blue_score` (GhostDAG 計算後に確定)          |
//! | 即座に状態更新                            | **遅延状態評価** (Total Order 確定後)          |
//! | TX 不正 → ブロック全体拒否               | TX 不正 → TX のみ Failed (フェイルソフト)     |
//! | `execute_block()` 単一パス               | `GhostDAG → Total Order → apply_ordered_txs` |
//!
//! ## ブロック生成フロー
//!
//! ```text
//! 1. Tips 取得 (DAG の葉ノード群)
//! 2. Mempool から候補 TX を選択 (KI 事前チェック付き)
//! 3. TX Root 計算
//! 4. DagBlockHeader 組み立て (parents = tips)
//! 5. DAG に追加
//! 6. GhostDAG データ計算
//! 7. Total Order 再計算
//! 8. 遅延状態評価 (apply_ordered_transactions)
//! ```
//!
//! ## INVARIANT
//!
//! v1 と同様、このモジュールは **UTXO Set を直接操作しない**。
//! 全状態遷移は `DagStateManager::apply_ordered_transactions()` 経由。

use std::sync::Arc;
use std::collections::HashSet;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use tracing::{info, warn, debug, error};

use misaka_types::utxo::UtxoTransaction;

use crate::dag_block::{DagBlockHeader, DagBlock, Hash, ZERO_HASH, DAG_VERSION, MAX_PARENTS};
use crate::ghostdag::GhostDagManager;
use crate::dag_store::ThreadSafeDagStore;
use crate::dag_state_manager::{
    DagStateManager, OrderedBlockData, OrderedTxData, TxApplyStatus, UtxoAction,
};

// ═══════════════════════════════════════════════════════════════
//  DAG ノード状態
// ═══════════════════════════════════════════════════════════════

/// DAG ノードの共有状態。
///
/// v1 の `NodeState` に相当するが、`height` の代わりに `blue_score` を追跡し、
/// `ChainStore` の代わりに `ThreadSafeDagStore` を使用する。
pub struct DagNodeState {
    /// DAG ストア。
    pub dag_store: Arc<ThreadSafeDagStore>,

    /// GhostDAG コンセンサスエンジン。
    pub ghostdag: GhostDagManager,

    /// 遅延状態マネージャ。
    pub state_manager: DagStateManager,

    /// UTXO Set (v1 と同一の型)。
    pub utxo_set: misaka_storage::utxo_set::UtxoSet,

    /// Mempool (v1 と同一の型)。
    /// DAG では KI 事前チェックを追加する。
    pub mempool: DagMempool,

    /// チェーン ID。
    pub chain_id: u32,

    /// バリデータ/プロポーザー ID。
    pub proposer_id: [u8; 32],

    /// Genesis ハッシュ。
    pub genesis_hash: Hash,

    /// 統計。
    pub blocks_produced: u64,
}

/// DAG 対応 Mempool。
///
/// v1 の `UtxoMempool` を拡張し、以下を追加:
/// - KI 事前チェック: 既に DAG に含まれる KI を持つ TX を拒否
/// - 並列ブロック考慮: 他のブロック生成者が同じ TX を含む可能性
pub struct DagMempool {
    /// 未処理 TX プール (fee 降順で取得可能)。
    txs: Vec<UtxoTransaction>,
    /// プール内の Key Image 集合 (重複投入防止)。
    ki_set: HashSet<[u8; 32]>,
    /// 最大プールサイズ。
    max_size: usize,
}

impl DagMempool {
    pub fn new(max_size: usize) -> Self {
        Self {
            txs: Vec::new(),
            ki_set: HashSet::new(),
            max_size,
        }
    }

    /// TX をプールに追加する。
    ///
    /// # KI 事前チェック
    ///
    /// - プール内に同一 KI が既にある場合は拒否
    /// - DAG に既に記録された KI は `is_ki_spent` コールバックで確認
    ///
    /// # 引数
    ///
    /// - `tx`: 追加する TX
    /// - `is_ki_spent`: Key Image が既に DAG で使用済みかを確認する関数
    pub fn insert<F>(&mut self, tx: UtxoTransaction, is_ki_spent: F) -> Result<(), String>
    where
        F: Fn(&[u8; 32]) -> bool,
    {
        if self.txs.len() >= self.max_size {
            return Err("mempool full".into());
        }

        // KI 重複チェック (プール内)
        for inp in &tx.inputs {
            if self.ki_set.contains(&inp.key_image) {
                return Err(format!(
                    "key image {} already in mempool",
                    hex::encode(&inp.key_image[..8])
                ));
            }
        }

        // KI 重複チェック (DAG 内)
        for inp in &tx.inputs {
            if is_ki_spent(&inp.key_image) {
                return Err(format!(
                    "key image {} already spent in DAG",
                    hex::encode(&inp.key_image[..8])
                ));
            }
        }

        // KI 登録 + TX 追加
        for inp in &tx.inputs {
            self.ki_set.insert(inp.key_image);
        }
        self.txs.push(tx);
        Ok(())
    }

    /// Fee 降順で上位 N 件の TX を取得する。
    pub fn top_by_fee(&self, n: usize) -> Vec<&UtxoTransaction> {
        let mut sorted: Vec<&UtxoTransaction> = self.txs.iter().collect();
        sorted.sort_by(|a, b| b.fee.cmp(&a.fee));
        sorted.truncate(n);
        sorted
    }

    /// TX をプールから除去する。
    pub fn remove(&mut self, tx_hash: &[u8; 32]) {
        if let Some(pos) = self.txs.iter().position(|tx| &tx.tx_hash() == tx_hash) {
            let tx = self.txs.remove(pos);
            for inp in &tx.inputs {
                self.ki_set.remove(&inp.key_image);
            }
        }
    }

    /// 使用済み KI を持つ TX を全て除去する。
    pub fn evict_spent_ki(&mut self, spent_kis: &HashSet<[u8; 32]>) {
        let before = self.txs.len();
        self.txs.retain(|tx| {
            let dominated = tx.inputs.iter().any(|inp| spent_kis.contains(&inp.key_image));
            if dominated {
                for inp in &tx.inputs {
                    self.ki_set.remove(&inp.key_image);
                }
            }
            !dominated
        });
        let evicted = before - self.txs.len();
        if evicted > 0 {
            debug!("Mempool: evicted {} txs with spent key images", evicted);
        }
    }

    pub fn len(&self) -> usize { self.txs.len() }
    pub fn is_empty(&self) -> bool { self.txs.is_empty() }
}

// ═══════════════════════════════════════════════════════════════
//  ブロック候補の組み立て
// ═══════════════════════════════════════════════════════════════

/// DAG ブロック候補を組み立てる。
///
/// # v1 との違い
///
/// v1 では `parent_hash = chain.tip_hash` (単一親) だったが、
/// v2 では `parents = tips` (DAG の全葉ノード, 最大 MAX_PARENTS 個)。
///
/// # Parents 選択戦略
///
/// 1. 全 Tips を取得
/// 2. blue_score 降順でソート
/// 3. 上位 MAX_PARENTS 個を parents とする
/// 4. parents[0] は Selected Parent 候補 (blue_score 最大)
pub fn assemble_dag_block(
    tips: &[Hash],
    txs: Vec<UtxoTransaction>,
    proposer_id: [u8; 32],
    timestamp_ms: u64,
) -> DagBlock {
    // Parents: blue_score 降順で上位 MAX_PARENTS 個
    // (ここでは Tips をそのまま使用 — blue_score ソートは呼び出し元で行う)
    let parents: Vec<Hash> = tips.iter()
        .take(MAX_PARENTS)
        .copied()
        .collect();

    let mut block = DagBlock::new(
        DagBlockHeader {
            version: DAG_VERSION,
            parents,
            timestamp_ms,
            tx_root: ZERO_HASH, // 後で compute_tx_root() で上書き
            proposer_id,
            nonce: 0,
            blue_score: 0, // GhostDAG 計算後に確定
            bits: 0,
        },
        txs,
    );

    // TX root を計算してヘッダに反映
    block.header.tx_root = block.compute_tx_root();

    block
}

// ═══════════════════════════════════════════════════════════════
//  Total Order からの TX データ変換
// ═══════════════════════════════════════════════════════════════

/// `UtxoTransaction` から `OrderedTxData` (DagStateManager 入力) へ変換する。
pub fn utxo_tx_to_ordered(tx: &UtxoTransaction) -> OrderedTxData {
    OrderedTxData {
        tx_hash: tx.tx_hash(),
        key_images: tx.inputs.iter().map(|inp| inp.key_image).collect(),
        is_coinbase: tx.inputs.is_empty() && tx.fee == 0,
        output_amounts: tx.outputs.iter().map(|o| o.amount).collect(),
        fee: tx.fee,
        signature_verified: false, // 要検証
    }
}

/// DAG ブロック群から `OrderedBlockData` のリストを構築する。
///
/// GhostDAG の Total Order (ブロックハッシュリスト) と DAG Store から
/// `DagStateManager::apply_ordered_transactions()` に渡す入力を生成する。
pub fn build_ordered_block_data(
    total_order: &[Hash],
    dag_store: &ThreadSafeDagStore,
) -> Vec<OrderedBlockData> {
    total_order.iter()
        .map(|block_hash| {
            let txs = dag_store.get_block_txs(block_hash);
            let snapshot = dag_store.snapshot();
            let blue_score = snapshot
                .get_ghostdag_data(block_hash)
                .map(|d| d.blue_score)
                .unwrap_or(0);

            OrderedBlockData {
                block_hash: *block_hash,
                blue_score,
                transactions: txs.iter().map(utxo_tx_to_ordered).collect(),
            }
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════════
//  DAG ブロック生成ループ
// ═══════════════════════════════════════════════════════════════

/// DAG ブロック生成ループ (非同期)。
///
/// ## フロー (1 ブロック生成あたり)
///
/// ```text
/// 1. [Tips 取得]      → dag_store.snapshot().get_tips()
/// 2. [TX 選択]        → mempool.top_by_fee(max_txs)
/// 3. [ブロック組立]    → assemble_dag_block(tips, txs, ...)
/// 4. [DAG 挿入]       → dag_store.insert_block(hash, header, txs)
/// 5. [GhostDAG 計算]  → ghostdag.calculate_ghostdag_data(...)
/// 6. [Total Order]    → ghostdag.get_total_ordering(...)
/// 7. [遅延状態評価]    → state_manager.apply_ordered_transactions(...)
/// 8. [Mempool 清掃]   → mempool.evict_spent_ki(...)
/// 9. [P2P ブロードキャスト] → (別モジュール)
/// ```
///
/// ## INVARIANT
///
/// - UTXO Set は `apply_ordered_transactions()` のコールバック経由でのみ更新
/// - このループは UTXO Set を直接操作しない
pub async fn run_dag_block_producer(
    state: Arc<RwLock<DagNodeState>>,
    block_time_secs: u64,
    max_txs_per_block: usize,
) {
    let mut ticker = interval(Duration::from_secs(block_time_secs));
    ticker.tick().await;
    info!(
        "DAG block producer started (interval={}s, max_txs={})",
        block_time_secs, max_txs_per_block
    );

    loop {
        ticker.tick().await;
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;

        let mut guard = state.write().await;
        let s = &mut *guard;

        // ── Step 1: Tips 取得 ──
        let snapshot = s.dag_store.snapshot();
        let tips = snapshot.get_tips();
        if tips.is_empty() {
            warn!("DAG has no tips — skipping block production");
            continue;
        }

        // ── Step 2: TX 選択 ──
        let candidate_txs: Vec<UtxoTransaction> = s.mempool
            .top_by_fee(max_txs_per_block)
            .into_iter()
            .cloned()
            .collect();

        // ── Step 3: ブロック組立 ──
        let mut block = assemble_dag_block(
            &tips,
            candidate_txs.clone(),
            s.proposer_id,
            now_ms,
        );
        let block_hash = block.hash();

        // ── Step 4: DAG 挿入 ──
        if let Err(e) = s.dag_store.insert_block(
            block_hash,
            block.header.clone(),
            block.transactions.clone(),
        ) {
            error!("Failed to insert block into DAG: {}", e);
            continue;
        }

        // ── Step 5: GhostDAG 計算 ──
        let mut snapshot = s.dag_store.snapshot();
        let ghostdag_data = s.ghostdag.calculate_ghostdag_data(
            &block_hash,
            &block.header.parents,
            &snapshot,
        );
        let blue_score = ghostdag_data.blue_score;
        snapshot.set_ghostdag_data(block_hash, ghostdag_data.clone());
        s.dag_store.set_ghostdag(block_hash, ghostdag_data);

        // ── Step 6: Total Order 再計算 ──
        let snapshot = s.dag_store.snapshot();
        let total_order = s.ghostdag.get_total_ordering(&snapshot);

        // ── Step 7: 遅延状態評価 ──
        //
        // NOTE: 完全な再計算は重いため、実際の実装では
        // 「前回の確定ポイントからの差分のみ」を処理する。
        // ここではスケルトンとして全体を再計算する。
        let ordered_data = build_ordered_block_data(&total_order, &s.dag_store);

        // 状態マネージャをリセットして再適用
        // (本番ではチェックポイントベースの差分適用に最適化)
        let mut fresh_state_manager = DagStateManager::new(HashSet::new());
        let mut new_kis = HashSet::new();

        let results = fresh_state_manager.apply_ordered_transactions(
            &ordered_data,
            |action| {
                match &action {
                    UtxoAction::CreateOutput { .. } => {
                        // UTXO Set への反映は本番実装で行う
                        // ここではログのみ
                    }
                    UtxoAction::RecordNullifier { key_image, .. } => {
                        new_kis.insert(*key_image);
                    }
                }
            },
        );

        // TX 適用結果をストアに保存
        for result in &results {
            s.dag_store.set_tx_status(result.tx_hash, result.status);
        }

        // ── Step 8: Mempool 清掃 ──
        // 確認済み TX を除去
        for tx in &candidate_txs {
            s.mempool.remove(&tx.tx_hash());
        }
        // 使用済み KI を持つ TX を除去
        s.mempool.evict_spent_ki(&new_kis);

        // ── ログ ──
        s.blocks_produced += 1;
        let applied = fresh_state_manager.stats.txs_applied;
        let failed = fresh_state_manager.stats.txs_failed_ki_conflict;

        if candidate_txs.is_empty() {
            info!(
                "⛏  DAG Block {} | score={} | empty | tips={} | dag_size={}",
                hex::encode(&block_hash[..4]),
                blue_score,
                s.dag_store.tip_count(),
                s.dag_store.block_count(),
            );
        } else {
            info!(
                "⛏  DAG Block {} | score={} | txs={} (applied={}, failed={}) | tips={} | mempool={}",
                hex::encode(&block_hash[..4]),
                blue_score,
                candidate_txs.len(),
                applied,
                failed,
                s.dag_store.tip_count(),
                s.mempool.len(),
            );
        }

        // Step 9 は P2P モジュールが担当 (dag_p2p.rs)
    }
}

// ═══════════════════════════════════════════════════════════════
//  テスト
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag_block::DAG_VERSION;

    #[test]
    fn test_assemble_block() {
        let tips = vec![[0x01; 32], [0x02; 32]];
        let block = assemble_dag_block(
            &tips,
            vec![], // empty block
            [0xAA; 32],
            1700000000_000,
        );

        assert_eq!(block.header.version, DAG_VERSION);
        assert_eq!(block.header.parents.len(), 2);
        assert_eq!(block.header.tx_root, ZERO_HASH); // empty block → zero root
    }

    #[test]
    fn test_mempool_ki_dedup() {
        let mut pool = DagMempool::new(100);

        let tx1 = misaka_types::utxo::UtxoTransaction {
            version: 0x03,
            ring_scheme: 0x03,
            tx_type: misaka_types::utxo::TxType::Transfer,
            inputs: vec![misaka_types::utxo::RingInput {
                ring_members: vec![
                    misaka_types::utxo::OutputRef { tx_hash: [1; 32], output_index: 0 },
                    misaka_types::utxo::OutputRef { tx_hash: [2; 32], output_index: 0 },
                    misaka_types::utxo::OutputRef { tx_hash: [3; 32], output_index: 0 },
                    misaka_types::utxo::OutputRef { tx_hash: [4; 32], output_index: 0 },
                ],
                ring_signature: vec![0; 64],
                key_image: [0xAA; 32],
                ki_proof: vec![0; 32],
            }],
            outputs: vec![misaka_types::utxo::TxOutput {
                amount: 1000,
                one_time_address: [0; 20],
                pq_stealth: None,
                spending_pubkey: None,
            }],
            fee: 100,
            extra: vec![],
        };

        // 1st insert: OK
        pool.insert(tx1.clone(), |_| false).unwrap();
        assert_eq!(pool.len(), 1);

        // 2nd insert with same KI: rejected
        let result = pool.insert(tx1.clone(), |_| false);
        assert!(result.is_err());

        // Insert with DAG-spent KI: rejected
        let mut tx2 = tx1.clone();
        tx2.inputs[0].key_image = [0xBB; 32];
        let result = pool.insert(tx2, |ki| *ki == [0xBB; 32]);
        assert!(result.is_err());
    }
}
