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
use crate::virtual_state::VirtualState;
use crate::state_diff::{StateDiff, CreatedUtxo, SpentUtxo, DiffTxResult, DiffTxStatus};
use crate::dag_block_ingestion::IngestionPipeline;

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

    /// 遅延状態マネージャ (legacy — used only for TX classification).
    pub state_manager: DagStateManager,

    /// UTXO Set (v1 と同一の型)。
    pub utxo_set: misaka_storage::utxo_set::UtxoSet,

    /// **VirtualState — SINGLE SOURCE OF TRUTH (SSOT)**。
    ///
    /// v8: すべてのコンセンサス決定 (ブロック生成時の親選択、RPC、Mempool 同期) は
    /// この VirtualState の最新 View に基づいて行われる。
    /// replay_ordered_state() は廃止。状態更新は resolve() 経由のみ。
    pub virtual_state: VirtualState,

    /// **Block Ingestion Pipeline** — Missing Parent State Machine (v8).
    ///
    /// P2P から受信したブロックの親ブロック追跡を行う。
    /// PendingParents → PendingValidation → Accepted/Rejected の厳密な状態遷移。
    pub ingestion_pipeline: IngestionPipeline,

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

    /// RocksDB persistent backend (write-through cache pattern).
    ///
    /// When `Some`, every block accepted by the in-memory `dag_store` is also
    /// written to this persistent backend. On restart, the persistent store
    /// is used to restore the in-memory store instead of JSON snapshots.
    ///
    /// `None` = in-memory only (testing / legacy JSON snapshot mode).
    pub persistent_backend: Option<Arc<crate::persistent_store::RocksDbDagStore>>,
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
    daa_bits: u32,
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
            bits: daa_bits, // v9: DAA から算出された difficulty
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
//  StateDiff 構築 (VirtualState resolve() 用)
// ═══════════════════════════════════════════════════════════════

/// ブロックの TX リストから `StateDiff` を構築する。
///
/// VirtualState の nullifier set を参照して、TX の accept/reject を決定する。
/// **replay_ordered_state() の代替**: O(|block_txs|) per block, NOT O(|history|)。
///
/// # Algorithm
///
/// ```text
/// for each TX in block:
///   for each nullifier (key_image) in TX:
///     if virtual_state.is_nullifier_spent(nf) OR seen_in_this_block(nf):
///       TX → DoubleSpend (reject)
///       break
///   if TX accepted:
///     record nullifiers_added
///     record utxos_created
///     TX → Applied
/// ```
///
/// # Kaspa 対応
///
/// Kaspa の `AcceptanceDataForBlock` 生成に相当。
/// 各ブロックの TX を virtual state に対して評価し、
/// accept/reject を決定する。
pub fn build_block_diff(
    block_hash: Hash,
    blue_score: u64,
    txs: &[UtxoTransaction],
    virtual_state: &VirtualState,
) -> StateDiff {
    let mut nullifiers_added = Vec::new();
    let mut utxos_created = Vec::new();
    let mut utxos_spent = Vec::new();
    let mut tx_results = Vec::new();
    // Track nullifiers seen within THIS block (intra-block double-spend detection)
    let mut block_local_nullifiers: HashSet<[u8; 32]> = HashSet::new();

    for tx in txs {
        let tx_hash = tx.tx_hash();
        let is_coinbase = tx.inputs.is_empty() && tx.fee == 0;

        if is_coinbase {
            // Coinbase: always accepted, no nullifiers
            for (idx, output) in tx.outputs.iter().enumerate() {
                utxos_created.push(CreatedUtxo {
                    outref: OutputRef { tx_hash, output_index: idx as u32 },
                    output: output.clone(),
                    tx_hash,
                });
            }
            tx_results.push(DiffTxResult::coinbase(tx_hash));
            continue;
        }

        // Check for nullifier (key_image) conflicts
        let mut conflicting_nf: Option<[u8; 32]> = None;
        for inp in &tx.inputs {
            let nf_hash: [u8; 32] = inp.key_image;
            // Check 1: Already spent in virtual state (prior blocks)
            // Note: VirtualState uses Hash = [u8; 32] for nullifiers
            if virtual_state.is_nullifier_spent(&nf_hash) {
                conflicting_nf = Some(nf_hash);
                break;
            }
            // Check 2: Already seen in THIS block (intra-block conflict)
            if block_local_nullifiers.contains(&nf_hash) {
                conflicting_nf = Some(nf_hash);
                break;
            }
            // Check 3: Already added by a prior TX in this diff
            if nullifiers_added.contains(&nf_hash) {
                conflicting_nf = Some(nf_hash);
                break;
            }
        }

        if let Some(nf) = conflicting_nf {
            // TX rejected: double-spend
            tx_results.push(DiffTxResult::failed_nullifier(tx_hash, nf, [0u8; 32]));
            debug!(
                "TX {} rejected: nullifier {} already spent",
                hex::encode(&tx_hash[..4]),
                hex::encode(&nf[..4]),
            );
        } else {
            // TX accepted: record nullifiers, spent UTXOs, and new outputs
            let mut tx_nullifiers = Vec::new();
            for inp in &tx.inputs {
                let nf_hash: [u8; 32] = inp.key_image;
                nullifiers_added.push(nf_hash);
                block_local_nullifiers.insert(nf_hash);
                tx_nullifiers.push(nf_hash);

                // ── v4: Record spent UTXOs with full PQC metadata ──
                //
                // リングメンバーの最初の要素を "真のインプット" として扱い、
                // VirtualState から完全な TxOutput を取得して SpentUtxo に記録する。
                // これにより revert 時に完全復元が可能になる。
                //
                // Note: リング署名モデルでは真のインプットがどれかは秘匿されているが、
                // DAG state manager は nullifier (key_image) による UTXO 消費を
                // 追跡するため、ここでは ring_members[0] を参照先として使用する。
                // 実際の UTXO 消費は nullifier ベースで管理される。
                if let Some(source_ref) = inp.ring_members.first() {
                    if let Some((output, creation_score)) = virtual_state.get_utxo_with_score(source_ref) {
                        utxos_spent.push(SpentUtxo {
                            outref: source_ref.clone(),
                            output: output.clone(),
                            creation_tx_hash: source_ref.tx_hash,
                            creation_blue_score: creation_score,
                            spending_tx_hash: tx_hash,
                            nullifier: nf_hash,
                        });
                    }
                }
            }
            for (idx, output) in tx.outputs.iter().enumerate() {
                utxos_created.push(CreatedUtxo {
                    outref: OutputRef { tx_hash, output_index: idx as u32 },
                    output: output.clone(),
                    tx_hash,
                });
            }
            tx_results.push(DiffTxResult::applied(tx_hash, tx_nullifiers));
        }
    }

    StateDiff {
        block_hash,
        blue_score,
        epoch: u32::try_from(crate::daa::DaaScore(blue_score).epoch()).unwrap_or(u32::MAX), // v9: DAA-derived epoch
        nullifiers_added,
        utxos_created,
        utxos_spent,
        tx_results,
    }
}

// ═══════════════════════════════════════════════════════════════
//  DAG ブロック生成ループ
// ═══════════════════════════════════════════════════════════════

/// DAG ブロック生成ループ (非同期)。
///
/// ## v8: VirtualState::resolve() 中心設計
///
/// v7 以前は毎ブロック `replay_ordered_state()` (O(|DAG|)) で全履歴を再計算していた。
/// v8 では `VirtualState::resolve()` (O(reorg_depth)) で差分のみ処理する。
///
/// ## フロー (1 ブロック生成あたり)
///
/// ```text
/// 1. [Tips 取得]           → dag_store.snapshot().get_tips()
/// 2. [TX 選択]             → mempool.top_by_fee(max_txs)
/// 3. [ブロック組立]         → assemble_dag_block(tips, txs, ...)
/// 4. [DAG 挿入]            → dag_store.insert_block(hash, header, txs)
/// 5. [GhostDAG 計算]       → ghostdag.try_calculate(...) [Fail-Closed]
/// 6. [Virtual Parents 再計算] → select_parent(tips) [SP = virtual tip]
/// 7. [StateDiff 構築]       → build_block_diff(block, txs, virtual_state)
/// 8. [VirtualState resolve] → virtual_state.resolve(new_tip, diffs) [O(reorg_depth)]
/// 9. [Mempool 清掃]         → mempool.evict_spent_ki(...)
/// 10. [P2P ブロードキャスト]  → (別モジュール)
/// ```
///
/// ## INVARIANT
///
/// - VirtualState は resolve() 経由でのみ更新される (SSOT)
/// - replay_ordered_state() は一切呼ばれない
/// - UTXO Set への直接操作は行わない
pub async fn run_dag_block_producer(
    state: Arc<RwLock<DagNodeState>>,
    block_time_secs: u64,
    max_txs_per_block: usize,
) {
    let mut ticker = interval(Duration::from_secs(block_time_secs));
    ticker.tick().await;
    info!(
        "DAG block producer started (interval={}s, max_txs={}, mode=VirtualState-resolve)",
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

        // ── Step 3: DAA bits 算出 (v9: DAA consensus 統合) ──
        //
        // Virtual selected parent の bits を基に、DAA window から
        // 次ブロックの expected bits を計算。block_processor 側で検証される。
        let virtual_sp_for_daa = s.ghostdag.select_parent_public(&tips, &snapshot);
        let current_bits = snapshot.get_header(&virtual_sp_for_daa)
            .map(|h| h.bits)
            .unwrap_or(crate::daa::INITIAL_BITS);
        let daa_bits = crate::daa::compute_next_bits(&virtual_sp_for_daa, &snapshot, current_bits);

        // ── Step 4: ブロック組立 ──
        let mut block = assemble_dag_block(&tips, candidate_txs.clone(), s.proposer_id, now_ms, daa_bits);
        let block_hash = block.hash();

        // ── Step 5: DAG 挿入 ──
        if let Err(e) =
            s.dag_store
                .insert_block(block_hash, block.header.clone(), block.transactions.clone())
        {
            error!("Failed to insert block into DAG: {}", e);
            continue;
        }

        // ── Step 6: GhostDAG 計算 (V2: Kaspa-compliant, Fail-Closed) ──
        //
        // v9: UniformStakeProvider は仮実装。本番では PoS cumulative security
        // score (validator weight, slash-adjusted, epoch-bounded) に置き換える。
        // blue_work は proposer_stake の累積であり、PoS 版の cumulative security
        // score として機能する。
        let stake = UniformStakeProvider;
        let selected_parent = s.ghostdag.select_parent_public(&block.header.parents, &snapshot);
        if let Err(e) = s.reachability.add_child(selected_parent, block_hash) {
            error!("Failed to update reachability index: {}", e);
            continue;
        }
        let mut snapshot = s.dag_store.snapshot();
        let ghostdag_data = match s.ghostdag.try_calculate(
            &block_hash, &block.header.parents, &snapshot, &s.reachability, &stake,
        ) {
            Ok(data) => data,
            Err(e) => {
                error!("GhostDAG calculation failed (block rejected): {}", e);
                continue;
            }
        };
        let blue_score = ghostdag_data.blue_score;
        snapshot.set_ghostdag_data(block_hash, ghostdag_data.clone());
        s.dag_store.set_ghostdag(block_hash, ghostdag_data.clone());

        // ── Step 6a: Persist to RocksDB (write-through) ──
        if let Some(ref backend) = s.persistent_backend {
            use crate::persistent_store::PersistentDagBackend;
            if let Err(e) = backend.insert_block_atomic(
                block_hash, block.header.clone(), ghostdag_data,
            ) {
                // Log but don't halt — in-memory store is primary
                tracing::warn!(
                    "RocksDB write-through failed for block {}: {}",
                    hex::encode(&block_hash[..4]), e,
                );
            }
        }

        // ── Step 6: Virtual Parents 再計算 ──
        //
        // Tips が更新されたので、virtual selected parent を再計算。
        // resolve() に渡す new_tip はこの virtual SP。
        let updated_snapshot = s.dag_store.snapshot();
        let updated_tips = updated_snapshot.get_tips();
        let virtual_sp = s.ghostdag.select_parent_public(&updated_tips, &updated_snapshot);
        let virtual_sp_score = updated_snapshot
            .get_ghostdag_data(&virtual_sp)
            .map(|d| d.blue_score)
            .unwrap_or(0);

        // ── Step 7: StateDiff 構築 ──
        //
        // 新ブロックの TX を VirtualState に対して評価し、
        // accept/reject を決定。O(|block_txs|)。
        // replay_ordered_state() は呼ばない。
        let diff = build_block_diff(
            block_hash,
            blue_score,
            &candidate_txs,
            &s.virtual_state,
        );

        // TX 適用結果をストアに保存 (lossless via DiffTxResult::to_apply_status)
        for tx_result in &diff.tx_results {
            s.dag_store.set_tx_status(tx_result.tx_hash, tx_result.to_apply_status());
        }

        // ── Step 8: VirtualState::resolve() ──
        //
        // **CORE CHANGE (v8)**: 差分ベースの状態更新。
        //
        // resolve() は:
        // 1. 現在の virtual tip と new tip を比較
        // 2. Simple advance → diff を apply (O(1))
        // 3. Reorg → common ancestor まで revert + 新 branch を apply (O(reorg_depth))
        // 4. ChainChanges + AcceptanceData を生成 (wallet/RPC 用)
        //
        // O(|history|) の replay は完全に廃止。
        let resolve_result = match s.virtual_state.resolve(
            virtual_sp,
            virtual_sp_score,
            vec![diff],
            &s.reachability,
            &updated_snapshot,
        ) {
            Ok(result) => result,
            Err(e) => {
                error!("VirtualState resolve failed: {} — state may be inconsistent", e);
                continue;
            }
        };

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

        // ── Step 9: Mempool 清掃 ──
        // 確認済み TX を除去
        for tx in &candidate_txs {
            s.mempool.remove(&tx.tx_hash());
        }
        // 使用済み nullifier を持つ TX を除去
        let spent_nfs: HashSet<[u8; 32]> = resolve_result.chain_changes.acceptance_data.iter()
            .flat_map(|ad| ad.tx_results.iter())
            .filter(|tr| tr.accepted)
            .flat_map(|_| vec![]) // Nullifiers are tracked in VirtualState
            .collect();
        // Also evict based on the diff's nullifiers
        let diff_nfs: HashSet<[u8; 32]> = s.virtual_state.all_nullifiers().iter().copied().collect();
        s.mempool.evict_spent_ki(&diff_nfs);

        // ── ログ ──
        s.blocks_produced += 1;

        if candidate_txs.is_empty() {
            info!(
                "⛏  DAG Block {} | score={} | empty | tips={} | dag_size={} | virtual_tip={} | reorg={}",
                hex::encode(&block_hash[..4]),
                blue_score,
                s.dag_store.tip_count(),
                s.dag_store.block_count(),
                hex::encode(&resolve_result.new_tip[..4]),
                resolve_result.reorg_depth,
            );
        } else {
            let accepted = resolve_result.chain_changes.acceptance_data.iter()
                .flat_map(|ad| ad.tx_results.iter())
                .filter(|tr| tr.accepted)
                .count();
            let rejected = resolve_result.chain_changes.acceptance_data.iter()
                .flat_map(|ad| ad.tx_results.iter())
                .filter(|tr| !tr.accepted)
                .count();
            info!(
                "⛏  DAG Block {} | score={} | txs={} (accepted={}, rejected={}) | tips={} | mempool={} | virtual_tip={} | reorg={}",
                hex::encode(&block_hash[..4]),
                blue_score,
                candidate_txs.len(),
                accepted,
                rejected,
                s.dag_store.tip_count(),
                s.mempool.len(),
                hex::encode(&resolve_result.new_tip[..4]),
                resolve_result.reorg_depth,
            );
        }

        // Step 10 は P2P モジュールが担当 (dag_p2p.rs)
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
            crate::daa::INITIAL_BITS,
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
            crate::daa::INITIAL_BITS,
        );
        let block_hash = block.hash();
        store
            .insert_block(block_hash, block.header.clone(), block.transactions.clone())
            .unwrap();
        let mut snapshot = store.snapshot();
        let sp = ghostdag.select_parent_public(&block.header.parents, &snapshot);
        reachability.add_child(sp, block_hash).unwrap();
        let gdata = ghostdag.try_calculate(&block_hash, &block.header.parents, &snapshot, &reachability, &stake).unwrap();
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
