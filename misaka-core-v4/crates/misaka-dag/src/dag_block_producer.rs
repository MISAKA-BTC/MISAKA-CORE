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
//! v1 と同様、このモジュールは **任意の場所から直接 state mutation しない**。
//! 全状態遷移は `DagStateManager::apply_ordered_transactions()` が発行する
//! `UtxoAction` を replay して materialize する。

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

use misaka_crypto::validator_sig::ValidatorKeypair;
use misaka_storage::utxo_set::{BlockDelta, UtxoSet};
use misaka_types::utxo::{OutputRef, UtxoTransaction};
use misaka_types::validator::{DagCheckpointFinalityProof, DagCheckpointVote, ValidatorIdentity};

use crate::dag_block::{DagBlock, DagBlockHeader, Hash, DAG_VERSION, MAX_PARENTS, ZERO_HASH};
use crate::dag_finality::DagCheckpoint;
use crate::dag_persistence::save_runtime_snapshot;
use crate::dag_state_manager::{
    DagStateManager, OrderedBlockData, OrderedTxData, TxApplyResult, UtxoAction,
};
use crate::dag_store::ThreadSafeDagStore;
use crate::ghostdag::{DagStore, GhostDagEngine, UniformStakeProvider, StakeWeightProvider};
use crate::reachability::ReachabilityStore;

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
    pub ghostdag: GhostDagEngine,

    /// 遅延状態マネージャ。
    pub state_manager: DagStateManager,

    /// UTXO Set (v1 と同一の型)。
    pub utxo_set: misaka_storage::utxo_set::UtxoSet,

    /// Mempool (v1 と同一の型)。
    /// DAG では KI 事前チェックを追加する。
    pub mempool: DagMempool,

    /// チェーン ID。
    pub chain_id: u32,

    /// Expected validator count for this local testnet/runtime.
    pub validator_count: usize,

    /// Known validator identities for experimental DAG checkpoint attestation.
    pub known_validators: Vec<ValidatorIdentity>,

    /// バリデータ/プロポーザー ID。
    pub proposer_id: [u8; 32],

    /// Local validator identity + secret, when this node can attest checkpoints.
    pub local_validator: Option<LocalDagValidator>,

    /// Genesis ハッシュ。
    pub genesis_hash: Hash,

    /// JSON snapshot path for restart-safe local persistence.
    pub snapshot_path: PathBuf,

    /// Latest finalized checkpoint persisted by the finality monitor.
    pub latest_checkpoint: Option<DagCheckpoint>,

    /// Latest local vote over `latest_checkpoint`, if this node is a validator.
    pub latest_checkpoint_vote: Option<DagCheckpointVote>,

    /// Latest local finality proof when the runtime is single-validator.
    pub latest_checkpoint_finality: Option<DagCheckpointFinalityProof>,

    /// Vote pool keyed by checkpoint signing target.
    pub checkpoint_vote_pool:
        HashMap<misaka_types::validator::DagCheckpointTarget, Vec<DagCheckpointVote>>,

    /// Experimental HTTP peers used for checkpoint vote gossip.
    pub attestation_rpc_peers: Vec<String>,

    /// 統計。
    pub blocks_produced: u64,

    /// Reachability Index — O(1) ancestor queries for GhostDAG V2.
    pub reachability: ReachabilityStore,
}

/// Local validator material kept in-memory by an experimental DAG node.
pub struct LocalDagValidator {
    pub identity: ValidatorIdentity,
    pub keypair: ValidatorKeypair,
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

    /// TX ハッシュで mempool 内の TX を参照する。
    pub fn get_by_hash(&self, tx_hash: &[u8; 32]) -> Option<&UtxoTransaction> {
        self.txs.iter().find(|tx| &tx.tx_hash() == tx_hash)
    }

    /// mempool に TX が存在するか確認する。
    pub fn contains_tx(&self, tx_hash: &[u8; 32]) -> bool {
        self.get_by_hash(tx_hash).is_some()
    }

    /// 使用済み KI を持つ TX を全て除去する。
    pub fn evict_spent_ki(&mut self, spent_kis: &HashSet<[u8; 32]>) {
        let before = self.txs.len();
        self.txs.retain(|tx| {
            let dominated = tx
                .inputs
                .iter()
                .any(|inp| spent_kis.contains(&inp.key_image));
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

    pub fn len(&self) -> usize {
        self.txs.len()
    }
    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }
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
    // ── Task 1.2: Canonical parent normalization ──
    //
    // Parents are sorted lexicographically here as a minimum deterministic
    // normalization. This ensures that two nodes assembling a block from
    // the same tip set (arriving in different orders) produce the same
    // parents array — and therefore the same block hash.
    //
    // The full ParentSortKey (blue_work → blue_score → proposer_id → hash)
    // normalization is performed at the GhostDAG calculation stage
    // (select_parent / classify_mergeset), where DagStore access is available.
    // Lexicographic sort here is a defense-in-depth measure.
    let mut parents: Vec<Hash> = tips.iter().take(MAX_PARENTS).copied().collect();
    parents.sort(); // Lexicographic: deterministic regardless of input order

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
///
/// v1/v2/v3: key_images から double-spend 検出。nullifiers は空。
/// v4 (Q-DAG-CT): QdagTransaction 側で nullifiers を抽出して設定する。
pub fn utxo_tx_to_ordered(tx: &UtxoTransaction) -> OrderedTxData {
    OrderedTxData {
        tx_hash: tx.tx_hash(),
        key_images: tx.inputs.iter().map(|inp| inp.key_image).collect(),
        nullifiers: vec![], // v4: populated by QdagTransaction::nullifiers()
        is_coinbase: tx.inputs.is_empty() && tx.fee == 0,
        outputs: tx.outputs.clone(),
        fee: tx.fee,
        signature_verified: false, // 要検証
    }
}

/// Ordered block 列を replay して、live runtime 用の UTXO / nullifier 状態を再構築する。
///
/// 現段階では「前回 checkpoint からの差分」ではなく、total order 全体を replay する。
/// そのためコストは高いが、挙動を local E2E と揃えやすい。
pub struct DagReplayOutcome {
    pub state_manager: DagStateManager,
    pub utxo_set: UtxoSet,
    pub results: Vec<TxApplyResult>,
    pub spent_key_images: HashSet<[u8; 32]>,
}

#[deprecated(note = "Use VirtualState::update_virtual() for O(1) diff-based updates. replay_ordered_state is O(|history|).")]
pub fn replay_ordered_state(
    ordered_blocks: &[OrderedBlockData],
    max_delta_history: usize,
) -> Result<DagReplayOutcome, String> {
    let mut state_manager = DagStateManager::new(HashSet::new(), HashSet::new());
    let mut utxo_set = UtxoSet::new(max_delta_history);
    let mut actions = Vec::new();
    let mut spent_key_images = HashSet::new();

    let results = state_manager.apply_ordered_transactions(ordered_blocks, |action| {
        actions.push(action);
    });

    let block_heights: HashMap<Hash, u64> = ordered_blocks
        .iter()
        .enumerate()
        .map(|(idx, block)| (block.block_hash, idx as u64))
        .collect();

    let tx_to_block: HashMap<[u8; 32], Hash> = ordered_blocks
        .iter()
        .flat_map(|block| {
            block
                .transactions
                .iter()
                .map(move |tx| (tx.tx_hash, block.block_hash))
        })
        .collect();

    let mut deltas: HashMap<Hash, BlockDelta> = HashMap::new();

    for action in actions {
        match action {
            UtxoAction::CreateOutput {
                tx_hash,
                block_hash,
                output_index,
                output,
            } => {
                let height = *block_heights.get(&block_hash).ok_or_else(|| {
                    format!("missing block height for {}", hex::encode(&block_hash[..8]))
                })?;
                let outref = OutputRef {
                    tx_hash,
                    output_index,
                };
                utxo_set
                    .add_output(outref.clone(), output.clone(), height)
                    .map_err(|e| e.to_string())?;
                if let Some(spk_bytes) = output.spending_pubkey.clone() {
                    utxo_set.register_spending_key(outref.clone(), spk_bytes);
                }
                deltas
                    .entry(block_hash)
                    .or_insert_with(|| BlockDelta::new(height))
                    .created
                    .push(outref);
            }
            UtxoAction::RecordNullifier { key_image, tx_hash } => {
                utxo_set
                    .record_nullifier(key_image)
                    .map_err(|e| e.to_string())?;
                spent_key_images.insert(key_image);
                let block_hash = *tx_to_block.get(&tx_hash).ok_or_else(|| {
                    format!("missing block for tx {}", hex::encode(&tx_hash[..8]))
                })?;
                let height = *block_heights.get(&block_hash).ok_or_else(|| {
                    format!("missing block height for {}", hex::encode(&block_hash[..8]))
                })?;
                deltas
                    .entry(block_hash)
                    .or_insert_with(|| BlockDelta::new(height))
                    .key_images_added
                    .push(key_image);
            }
        }
    }

    for (idx, block) in ordered_blocks.iter().enumerate() {
        let height = idx as u64;
        let mut delta = deltas
            .remove(&block.block_hash)
            .unwrap_or_else(|| BlockDelta::new(height));
        delta.height = height;
        utxo_set.apply_block(delta).map_err(|e| e.to_string())?;
    }

    Ok(DagReplayOutcome {
        state_manager,
        utxo_set,
        results,
        spent_key_images,
    })
}

/// DAG ブロック群から `OrderedBlockData` のリストを構築する。
///
/// GhostDAG の Total Order (ブロックハッシュリスト) と DAG Store から
/// `DagStateManager::apply_ordered_transactions()` に渡す入力を生成する。
pub fn build_ordered_block_data(
    total_order: &[Hash],
    dag_store: &ThreadSafeDagStore,
) -> Vec<OrderedBlockData> {
    total_order
        .iter()
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
/// 5. [GhostDAG 計算]  → ghostdag.calculate(...)
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
        let candidate_txs: Vec<UtxoTransaction> = s
            .mempool
            .top_by_fee(max_txs_per_block)
            .into_iter()
            .cloned()
            .collect();

        // ── Step 3: ブロック組立 ──
        let mut block = assemble_dag_block(&tips, candidate_txs.clone(), s.proposer_id, now_ms);
        let block_hash = block.hash();

        // ── Step 4: DAG 挿入 ──
        if let Err(e) =
            s.dag_store
                .insert_block(block_hash, block.header.clone(), block.transactions.clone())
        {
            error!("Failed to insert block into DAG: {}", e);
            continue;
        }

        // ── Step 5: GhostDAG 計算 (V2: Kaspa-compliant) ──
        let stake = UniformStakeProvider; // TODO: replace with real PoS stake provider
        let selected_parent = s.ghostdag.select_parent_public(&block.header.parents, &snapshot);
        if let Err(e) = s.reachability.add_child(selected_parent, block_hash) {
            error!("Failed to update reachability index: {}", e);
            continue;
        }
        let mut snapshot = s.dag_store.snapshot();
        let ghostdag_data = s.ghostdag.calculate(
            &block_hash, &block.header.parents, &snapshot, &s.reachability, &stake,
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
        let replay = match replay_ordered_state(&ordered_data, 1000) {
            Ok(replay) => replay,
            Err(e) => {
                error!("Failed to replay DAG ordered state: {}", e);
                continue;
            }
        };

        // TX 適用結果をストアに保存
        for result in &replay.results {
            s.dag_store.set_tx_status(result.tx_hash, result.status);
        }

        s.state_manager = replay.state_manager;
        s.utxo_set = replay.utxo_set;

        if let Err(e) = save_runtime_snapshot(
            &s.snapshot_path,
            &s.dag_store,
            &s.utxo_set,
            &s.state_manager.stats,
            s.latest_checkpoint.as_ref(),
            &s.known_validators,
            s.latest_checkpoint_vote.as_ref(),
            s.latest_checkpoint_finality.as_ref(),
            &s.checkpoint_vote_pool,
        ) {
            error!("Failed to persist DAG runtime snapshot: {}", e);
        }

        // ── Step 8: Mempool 清掃 ──
        // 確認済み TX を除去
        for tx in &candidate_txs {
            s.mempool.remove(&tx.tx_hash());
        }
        // 使用済み KI を持つ TX を除去
        s.mempool.evict_spent_ki(&replay.spent_key_images);

        // ── ログ ──
        s.blocks_produced += 1;
        let applied = s.state_manager.stats.txs_applied;
        let failed = s.state_manager.stats.txs_failed_ki_conflict;

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
    use misaka_types::utxo::{
        RingInput, TxOutput, TxType, RING_SCHEME_LOGRING, UTXO_TX_VERSION_V3,
    };

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
                    misaka_types::utxo::OutputRef {
                        tx_hash: [1; 32],
                        output_index: 0,
                    },
                    misaka_types::utxo::OutputRef {
                        tx_hash: [2; 32],
                        output_index: 0,
                    },
                    misaka_types::utxo::OutputRef {
                        tx_hash: [3; 32],
                        output_index: 0,
                    },
                    misaka_types::utxo::OutputRef {
                        tx_hash: [4; 32],
                        output_index: 0,
                    },
                ],
                ring_signature: vec![0; 64],
                key_image: [0xAA; 32],
                ki_proof: vec![0; 32],
            }],
            outputs: vec![misaka_types::utxo::TxOutput {
                amount: 1000,
                one_time_address: [0; 32],
                pq_stealth: None,
                spending_pubkey: None,
            }],
            fee: 100,
            extra: vec![],
            zk_proof: None,
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

    #[test]
    fn test_replay_ordered_state_preserves_full_output_data() {
        let genesis_hash = [0x01; 32];
        let genesis_header = DagBlockHeader {
            version: DAG_VERSION,
            parents: vec![],
            timestamp_ms: 1_700_000_000_000,
            tx_root: ZERO_HASH,
            proposer_id: [0; 32],
            nonce: 0,
            blue_score: 0,
            bits: 0,
        };
        let store = ThreadSafeDagStore::new(genesis_hash, genesis_header);
        let ghostdag = GhostDagEngine::new(18, genesis_hash);
        let mut reachability = crate::reachability::ReachabilityStore::new(genesis_hash);
        let stake = UniformStakeProvider;

        let tx = UtxoTransaction {
            version: UTXO_TX_VERSION_V3,
            ring_scheme: RING_SCHEME_LOGRING,
            tx_type: TxType::Transfer,
            inputs: vec![RingInput {
                ring_members: vec![
                    misaka_types::utxo::OutputRef {
                        tx_hash: [1; 32],
                        output_index: 0,
                    },
                    misaka_types::utxo::OutputRef {
                        tx_hash: [2; 32],
                        output_index: 0,
                    },
                    misaka_types::utxo::OutputRef {
                        tx_hash: [3; 32],
                        output_index: 0,
                    },
                    misaka_types::utxo::OutputRef {
                        tx_hash: [4; 32],
                        output_index: 0,
                    },
                ],
                ring_signature: vec![0xAA; 64],
                key_image: [0x55; 32],
                ki_proof: vec![0xBB; 32],
            }],
            outputs: vec![TxOutput {
                amount: 4242,
                one_time_address: [0xCC; 32],
                pq_stealth: None,
                spending_pubkey: Some(vec![0xDD; 48]),
            }],
            fee: 10,
            extra: vec![0xEE],
            zk_proof: None,
        };

        let mut block = assemble_dag_block(
            &[genesis_hash],
            vec![tx.clone()],
            [0x0A; 32],
            1_700_000_001_000,
        );
        let block_hash = block.hash();
        store
            .insert_block(block_hash, block.header.clone(), block.transactions.clone())
            .unwrap();
        let mut snapshot = store.snapshot();
        let sp = ghostdag.select_parent_public(&block.header.parents, &snapshot);
        reachability.add_child(sp, block_hash).unwrap();
        let gdata = ghostdag.calculate(&block_hash, &block.header.parents, &snapshot, &reachability, &stake);
        snapshot.set_ghostdag_data(block_hash, gdata.clone());
        store.set_ghostdag(block_hash, gdata);

        let total_order = ghostdag.get_total_ordering(&store.snapshot());
        let ordered = build_ordered_block_data(&total_order, &store);
        let replay = replay_ordered_state(&ordered, 16).unwrap();

        let outref = misaka_types::utxo::OutputRef {
            tx_hash: tx.tx_hash(),
            output_index: 0,
        };
        let stored = replay.utxo_set.get(&outref).unwrap();
        assert_eq!(stored.output.amount, 4242);
        assert_eq!(stored.output.one_time_address, [0xCC; 32]);
        assert_eq!(
            replay.utxo_set.get_spending_key(&outref).unwrap(),
            &[0xDD; 48]
        );
        assert!(replay.utxo_set.is_key_image_spent(&[0x55; 32]));
    }
}
