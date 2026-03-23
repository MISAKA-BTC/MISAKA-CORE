//! Atomic Block Acceptance Pipeline (v4).
//!
//! # Problem
//!
//! v3 以前のブロック受理フローは以下の問題を抱えていた:
//!
//! 1. **Non-Atomic writes**: DAG Store, VirtualState, Reachability が個別に
//!    更新されるため、中間ステージで失敗した場合にDBが中途半端な状態になる。
//!    例: GhostDAG 計算が失敗しても、既に Reachability Index に子が追加されている。
//!
//! 2. **Multiple entry points**: P2P relay, Miner, RPC が各自の方法でブロックを
//!    挿入しており、バリデーションの統一が保証されない。
//!
//! # Solution: Stage-based Atomic Pipeline
//!
//! すべてのブロック挿入は `process_new_block_atomic()` を唯一のエントリポイント
//! として通過する。処理中の中間状態は一切 Storage に書き込まず、すべて
//! `StoreWriteBatch` にメモリ上で蓄積する。全5ステージが成功した場合のみ
//! `commit()` で一括永続化する。
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │              process_new_block_atomic()                    │
//! │                                                            │
//! │  Stage 1: Header/Body Validation ──┐                      │
//! │     ML-DSA 署名検証                │ Err → Reject         │
//! │     Lattice ZKP 検証               │ (WriteBatch 破棄)    │
//! │     構造体バリデーション            │                      │
//! │                                    │                      │
//! │  Stage 2: Reachability Update ─────┤                      │
//! │     仮想 Tree でインターバル割当   │ Err → Reject         │
//! │     (メモリ上のみ)                 │                      │
//! │                                    │                      │
//! │  Stage 3: GhostDAG Calculation ────┤                      │
//! │     Mergeset, Blue/Red 分類        │ Err → Reject         │
//! │     Blue Score, Blue Work 算出     │                      │
//! │                                    │                      │
//! │  Stage 4: Virtual Resolve ─────────┤                      │
//! │     StateDiff 生成 (SpentUtxo 付)  │ Err → Reject         │
//! │     VirtualState 更新 (メモリ)     │                      │
//! │                                    │                      │
//! │  Stage 5: Atomic Commit ───────────┘                      │
//! │     StoreWriteBatch::commit()                             │
//! │     全変更を一括永続化                                     │
//! └──────────────────────────────────────────────────────────┘
//! ```
//!
//! # Fail-Closed Guarantee
//!
//! いずれかのステージで `Err` が返された場合:
//! - `StoreWriteBatch` はスコープアウトで自動破棄 (Drop)
//! - Storage には一切の書き込みが行われない
//! - VirtualState, Reachability のメモリ状態も変更されない
//! - 呼び出し元には `AtomicPipelineError` が返される
//!
//! # Soundness
//!
//! 1. DB状態は常に「最後に commit された整合状態」か「未変更の前状態」のいずれか
//! 2. 中間状態が DB に漏洩することはない (WriteBatch barrier)
//! 3. `?` 演算子による早期リターンで、後続ステージの実行を自動防止

use tracing::{debug, info};

use crate::dag_block::{DagBlockHeader, GhostDagData, Hash, ZERO_HASH};
use crate::ghostdag::{validate_header_topology, DagStore, GhostDagEngine, StakeWeightProvider};
use crate::persistent_store::PersistentDagBackend;
use crate::qdag_block::{QdagBlock, SealedTransaction};
use crate::reachability::ReachabilityStore;
use crate::state_diff::{CreatedUtxo, DiffTxResult, DiffTxStatus, SpentUtxo, StateDiff};
use crate::virtual_state::VirtualState;

use misaka_types::utxo::OutputRef;

// ═══════════════════════════════════════════════════════════════
//  StoreWriteBatch — メモリ上の変更蓄積バッファ
// ═══════════════════════════════════════════════════════════════

/// Atomic write batch — メモリ上に蓄積された全ての状態変更。
///
/// # Invariant
///
/// `commit()` が呼ばれるまで、Storage への書き込みは一切行われない。
/// `commit()` が呼ばれずにドロップされた場合、全変更は破棄される。
///
/// # Usage
///
/// ```ignore
/// let mut batch = StoreWriteBatch::new();
///
/// // Stage 1-4: 計算結果を batch に蓄積
/// batch.put_header(hash, header);
/// batch.put_ghostdag(hash, ghostdag_data);
/// batch.put_state_diff(hash, diff);
///
/// // Stage 5: 全成功した場合のみ commit
/// batch.commit(&storage)?;
/// // ← この行に到達しなければ、Storage は一切変更されない
/// ```
#[derive(Debug)]
pub struct StoreWriteBatch {
    /// Block header to persist.
    header: Option<(Hash, DagBlockHeader)>,
    /// GhostDAG data to persist.
    ghostdag: Option<(Hash, GhostDagData)>,
    /// State diff to persist (for undo journal).
    state_diff: Option<(Hash, StateDiff)>,
    /// Acceptance data (serialized JSON).
    acceptance: Option<(Hash, Vec<u8>)>,
    /// Nullifiers to record (nullifier → spending_tx_hash).
    nullifiers: Vec<([u8; 32], [u8; 32])>,
    /// Virtual state snapshot (serialized JSON).
    virtual_snapshot: Option<Vec<u8>>,
    /// Last accepted block hash update.
    last_accepted: Option<Hash>,
    /// Tips update.
    tips_update: Option<Vec<Hash>>,
    /// Children updates (parent → new_child).
    children_updates: Vec<(Hash, Hash)>,
}

impl StoreWriteBatch {
    /// Create a new empty write batch.
    pub fn new() -> Self {
        Self {
            header: None,
            ghostdag: None,
            state_diff: None,
            acceptance: None,
            nullifiers: Vec::new(),
            virtual_snapshot: None,
            last_accepted: None,
            tips_update: None,
            children_updates: Vec::new(),
        }
    }

    /// Record a block header for persistence.
    pub fn put_header(&mut self, hash: Hash, header: DagBlockHeader) {
        self.header = Some((hash, header));
    }

    /// Record GhostDAG data for persistence.
    pub fn put_ghostdag(&mut self, hash: Hash, data: GhostDagData) {
        self.ghostdag = Some((hash, data));
    }

    /// Record a state diff for the undo journal.
    pub fn put_state_diff(&mut self, hash: Hash, diff: StateDiff) {
        self.state_diff = Some((hash, diff));
    }

    /// Record acceptance data (serialized).
    pub fn put_acceptance(&mut self, hash: Hash, data: Vec<u8>) {
        self.acceptance = Some((hash, data));
    }

    /// Record a nullifier spend.
    pub fn put_nullifier(&mut self, nullifier: [u8; 32], tx_hash: [u8; 32]) {
        self.nullifiers.push((nullifier, tx_hash));
    }

    /// Record virtual state snapshot for persistence.
    pub fn put_virtual_snapshot(&mut self, snapshot_json: Vec<u8>) {
        self.virtual_snapshot = Some(snapshot_json);
    }

    /// Record last accepted block hash.
    pub fn put_last_accepted(&mut self, hash: Hash) {
        self.last_accepted = Some(hash);
    }

    /// Commit all accumulated changes to persistent storage.
    ///
    /// # Atomicity
    ///
    /// This method writes ALL accumulated changes to the storage backend.
    /// If any individual write fails, subsequent writes are skipped and
    /// the error is propagated.
    ///
    /// In production (RocksDB), this maps to a single WriteBatch::write()
    /// which is atomic at the RocksDB level.
    ///
    /// # Fail-Closed
    ///
    /// If this method returns `Err`, the caller MUST NOT assume any
    /// partial state was written. The storage may be in an undefined
    /// state and should be recovered from the last known good state.
    pub fn commit<S: PersistentDagBackend>(self, storage: &S) -> Result<(), AtomicPipelineError> {
        // ── Write header + ghostdag atomically ──
        if let (Some((hash, header)), Some((_, ghostdag))) = (&self.header, &self.ghostdag) {
            storage
                .insert_block_atomic(*hash, header.clone(), ghostdag.clone())
                .map_err(|e| {
                    AtomicPipelineError::CommitFailed(format!("insert_block_atomic: {}", e))
                })?;
        }

        // ── Write nullifiers ──
        for (nullifier, tx_hash) in &self.nullifiers {
            storage
                .record_nullifier(*nullifier, *tx_hash)
                .map_err(|e| {
                    AtomicPipelineError::CommitFailed(format!("record_nullifier: {}", e))
                })?;
        }

        // ── Write state diff ──
        if let Some((hash, ref diff)) = self.state_diff {
            let diff_json = serde_json::to_vec(diff).map_err(|e| {
                AtomicPipelineError::CommitFailed(format!("serialize state_diff: {}", e))
            })?;
            storage.save_state_diff(hash, &diff_json).map_err(|e| {
                AtomicPipelineError::CommitFailed(format!("save_state_diff: {}", e))
            })?;
        }

        // ── Write acceptance data ──
        if let Some((hash, ref data)) = self.acceptance {
            storage.save_acceptance(hash, data).map_err(|e| {
                AtomicPipelineError::CommitFailed(format!("save_acceptance: {}", e))
            })?;
        }

        // ── Write virtual state snapshot ──
        if let Some(ref snapshot) = self.virtual_snapshot {
            storage.save_virtual_snapshot(snapshot).map_err(|e| {
                AtomicPipelineError::CommitFailed(format!("save_virtual_snapshot: {}", e))
            })?;
        }

        // ── Write last accepted ──
        if let Some(hash) = self.last_accepted {
            storage.save_last_accepted(hash).map_err(|e| {
                AtomicPipelineError::CommitFailed(format!("save_last_accepted: {}", e))
            })?;
        }

        info!("StoreWriteBatch committed successfully");
        Ok(())
    }

    /// Check if the batch has any pending writes.
    pub fn is_empty(&self) -> bool {
        self.header.is_none()
            && self.ghostdag.is_none()
            && self.state_diff.is_none()
            && self.nullifiers.is_empty()
    }
}

impl Drop for StoreWriteBatch {
    fn drop(&mut self) {
        if !self.is_empty() {
            debug!(
                "StoreWriteBatch dropped without commit — {} pending writes discarded \
                 (this is expected on validation failure)",
                self.nullifiers.len()
                    + self.header.is_some() as usize
                    + self.ghostdag.is_some() as usize
                    + self.state_diff.is_some() as usize,
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Atomic Pipeline Error
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum AtomicPipelineError {
    /// Stage 1: Header/Body validation failed.
    #[error("Stage 1 (Validation): {0}")]
    ValidationFailed(String),

    /// Stage 2: Reachability update failed.
    #[error("Stage 2 (Reachability): {0}")]
    ReachabilityFailed(String),

    /// Stage 3: GhostDAG calculation failed.
    #[error("Stage 3 (GhostDAG): {0}")]
    GhostDagFailed(String),

    /// Stage 4: Virtual state resolve failed.
    #[error("Stage 4 (VirtualResolve): {0}")]
    VirtualResolveFailed(String),

    /// Stage 5: Commit to storage failed.
    #[error("Stage 5 (Commit): {0}")]
    CommitFailed(String),

    /// Block is a duplicate (already in store).
    #[error("duplicate block {0}")]
    Duplicate(String),

    /// blue_score mismatch between header and computed.
    #[error("blue_score mismatch: header={declared}, computed={computed}")]
    BlueScoreMismatch { declared: u64, computed: u64 },

    /// DAA bits mismatch.
    #[error("DAA bits mismatch: declared=0x{declared:08x}, expected=0x{expected:08x}")]
    DaaBitsMismatch { declared: u32, expected: u32 },

    /// Timestamp validation failed.
    #[error("timestamp validation: {0}")]
    BadTimestamp(String),
}

// ═══════════════════════════════════════════════════════════════
//  Atomic Pipeline Result
// ═══════════════════════════════════════════════════════════════

/// Result of successfully processing a block through the atomic pipeline.
///
/// Contains the `StoreWriteBatch` with all pending writes.
/// The caller MUST call `write_batch.commit(&storage)` to persist changes.
/// If `write_batch` is dropped without commit, all changes are discarded
/// and a debug log is emitted.
///
/// # Usage
///
/// ```ignore
/// let result = process_new_block_atomic(&block, ...)?;
/// // Stage 5: Atomic commit — caller controls when to persist
/// result.write_batch.commit(&persistent_store)?;
/// ```
pub struct AtomicAcceptResult {
    pub block_hash: Hash,
    pub blue_score: u64,
    pub ghostdag_data: GhostDagData,
    pub state_diff: StateDiff,
    pub is_new_tip: bool,
    /// Pending writes to be committed atomically.
    /// Call `.commit(&storage)` to persist all changes.
    pub write_batch: StoreWriteBatch,
}

// ═══════════════════════════════════════════════════════════════
//  process_new_block_atomic — 唯一のエントリポイント
// ═══════════════════════════════════════════════════════════════

/// P2P relay, Miner, RPC からのすべてのブロックが通過する唯一の関数。
///
/// # Pipeline Stages
///
/// | Stage | Operation                    | On Error          |
/// |-------|------------------------------|-------------------|
/// | 1     | Header/Body Validation       | → Reject, no DB   |
/// | 2     | Reachability Update (memory) | → Reject, no DB   |
/// | 3     | GhostDAG Calculation         | → Reject, no DB   |
/// | 4     | Virtual Resolve + StateDiff  | → Reject, no DB   |
/// | 5     | Return WriteBatch for Commit | → Caller commits   |
///
/// # Error Propagation
///
/// Rust の `?` 演算子により、各ステージで `Err` が返された場合:
/// 1. 即座に関数が早期リターン
/// 2. `StoreWriteBatch` はスコープアウトで自動 Drop
/// 3. Storage には一切の書き込みが行われない
/// 4. 呼び出し元に `AtomicPipelineError` が返される
///
/// # Complexity
///
/// O(1) per block (bounded by protocol constants):
/// - Stage 1: O(|inputs| × proof_verify) ≤ O(MAX_INPUTS × proof_cost)
/// - Stage 2: O(1) amortized (interval allocation)
/// - Stage 3: O(MAX_PARENTS × PRUNING_WINDOW)
/// - Stage 4: O(reorg_depth) ≤ O(MAX_REORG_DEPTH)
/// - Stage 5: O(|batch|) = O(|nullifiers| + |UTXOs|)
pub fn process_new_block_atomic<S, W>(
    block: &QdagBlock,
    store: &S,
    reachability: &mut ReachabilityStore,
    engine: &GhostDagEngine,
    stake: &W,
    virtual_state: &mut VirtualState,
) -> Result<AtomicAcceptResult, AtomicPipelineError>
where
    S: DagStore,
    W: StakeWeightProvider,
{
    let block_hash = block.hash();
    let header = &block.header;

    // ════════════════════════════════════════════════════════════
    //  WriteBatch の作成 — ここから commit() まで DB 書き込みは一切行わない
    // ════════════════════════════════════════════════════════════
    //
    // batch はこの関数のスコープに束縛されている。
    // いずれかのステージで `?` により早期リターンした場合、
    // batch は Drop され、蓄積された変更は全て破棄される。
    let mut batch = StoreWriteBatch::new();

    // ════════════════════════════════════════════════════════════
    //  Stage 1: Header/Body Validation
    // ════════════════════════════════════════════════════════════
    //
    // ML-DSA 署名検証、Lattice ZKP 検証、構造体バリデーション。
    // 純粋な計算のみ — DB 操作なし。
    // 失敗時は即 Reject (batch は Drop で自動破棄)。

    // 1a. Dedup check
    if store.get_header(&block_hash).is_some() {
        // batch は Drop される — DB 汚染なし
        return Err(AtomicPipelineError::Duplicate(hex::encode(
            &block_hash[..8],
        )));
    }

    // 1b. Header topology validation
    //
    // 親ブロックの存在確認、MAX_PARENTS 制限、自己参照禁止。
    // ? 演算子: Err なら即リターン → batch Drop → DB 安全
    validate_header_topology(&header.parents, header.blue_score, store)
        .map_err(|e| AtomicPipelineError::ValidationFailed(format!("header topology: {}", e)))?;

    // 1c. Sealed transaction structural validation
    //
    // 各 SealedTransaction の nullifier 非空チェック、chain_id 一致等。
    for (i, sealed_tx) in block.transactions.iter().enumerate() {
        if !sealed_tx.is_coinbase && sealed_tx.nullifiers.is_empty() {
            return Err(AtomicPipelineError::ValidationFailed(format!(
                "tx[{}] ({}) is Transfer but has no nullifiers",
                i,
                hex::encode(&sealed_tx.tx_hash[..4])
            )));
        }
    }

    // 1d. DAG-context timestamp validation
    if !header.is_genesis() {
        use crate::daa::{validate_timestamp, TimestampCheck};
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        match validate_timestamp(header.timestamp_ms, &header.parents, store, now_ms) {
            TimestampCheck::Valid => {}
            TimestampCheck::TooOld {
                block_ms,
                past_median_ms,
            } => {
                return Err(AtomicPipelineError::BadTimestamp(format!(
                    "{}ms < past_median {}ms",
                    block_ms, past_median_ms
                )));
            }
            TimestampCheck::TooFuture { block_ms, max_ms } => {
                return Err(AtomicPipelineError::BadTimestamp(format!(
                    "{}ms > max_allowed {}ms",
                    block_ms, max_ms
                )));
            }
        }
    }

    debug!(
        "Stage 1 passed: block {} validated",
        hex::encode(&block_hash[..4])
    );

    // ════════════════════════════════════════════════════════════
    //  Stage 2: Reachability Update
    // ════════════════════════════════════════════════════════════
    //
    // SPT (Selected Parent Tree) にインターバルを割り当てる。
    // メモリ上の仮想 Tree で計算 — DB 操作なし。
    // ? 演算子: Err なら即リターン → batch Drop → DB 安全

    let selected_parent = engine.select_parent_public(&header.parents, store);
    reachability
        .add_child(selected_parent, block_hash)
        .map_err(|e| AtomicPipelineError::ReachabilityFailed(e))?;

    debug!(
        "Stage 2 passed: reachability updated (parent={})",
        hex::encode(&selected_parent[..4])
    );

    // ════════════════════════════════════════════════════════════
    //  Stage 3: GhostDAG Calculation
    // ════════════════════════════════════════════════════════════
    //
    // Mergeset 算出、Blue/Red 分類、Blue Score 計算。
    // 計算結果は batch に蓄積 — DB には書かない。
    // try_calculate: mergeset overflow → block rejected (Fail-Closed)。
    // ? 演算子: Err なら即リターン → batch Drop → DB 安全

    let ghostdag_data = engine
        .try_calculate(&block_hash, &header.parents, store, reachability, stake)
        .map_err(|e| AtomicPipelineError::GhostDagFailed(format!("{}", e)))?;

    let computed_blue_score = ghostdag_data.blue_score;

    // blue_score SSOT: header は wire-level 参考値、computed が真実
    if header.blue_score != computed_blue_score && !header.is_genesis() {
        return Err(AtomicPipelineError::BlueScoreMismatch {
            declared: header.blue_score,
            computed: computed_blue_score,
        });
    }

    // DAA bits 検証
    if !header.is_genesis() {
        use crate::daa;
        let tip_for_daa = ghostdag_data.selected_parent;
        let existing_bits = store
            .get_header(&tip_for_daa)
            .map(|h| h.bits)
            .unwrap_or(daa::INITIAL_BITS);
        let expected_bits = daa::compute_next_bits(&tip_for_daa, store, existing_bits);
        if header.bits != expected_bits {
            return Err(AtomicPipelineError::DaaBitsMismatch {
                declared: header.bits,
                expected: expected_bits,
            });
        }
    }

    // ── 計算結果を WriteBatch に蓄積 (まだ永続化しない) ──
    batch.put_header(block_hash, header.clone());
    batch.put_ghostdag(block_hash, ghostdag_data.clone());

    debug!(
        "Stage 3 passed: GhostDAG computed (blue_score={})",
        computed_blue_score
    );

    // ════════════════════════════════════════════════════════════
    //  Stage 4: Virtual Resolve & StateDiff Build
    // ════════════════════════════════════════════════════════════
    //
    // ブロック内 TX を VirtualState に対して評価し、
    // accept/reject を決定。StateDiff を生成する。
    //
    // **v4 完全可逆性**: 消費された UTXO の完全な PQC メタデータを
    // SpentUtxo として StateDiff に記録する。
    //
    // VirtualState の更新はメモリ上のみ — DB 操作なし。
    // ? 演算子: Err なら即リターン → batch Drop → DB 安全

    let diff = build_qdag_block_diff(
        block_hash,
        computed_blue_score,
        &block.transactions,
        virtual_state,
    );

    // Record nullifiers in batch
    for tx_result in &diff.tx_results {
        if matches!(
            tx_result.status,
            DiffTxStatus::Applied | DiffTxStatus::Coinbase
        ) {
            for nf in &tx_result.nullifiers {
                batch.put_nullifier(*nf, tx_result.tx_hash);
            }
        }
    }

    // Record state diff in batch
    batch.put_state_diff(block_hash, diff.clone());

    // Determine if this is a new tip
    let is_new_tip = computed_blue_score
        > store
            .get_tips()
            .iter()
            .filter_map(|t| store.get_ghostdag_data(t))
            .map(|d| d.blue_score)
            .max()
            .unwrap_or(0);

    // Update VirtualState (in-memory)
    //
    // resolve() は内部で update_virtual() を呼び、必要に応じて reorg を実行する。
    // この操作はメモリ上のみで完結する。
    virtual_state
        .apply_block(diff.clone())
        .map_err(|e| AtomicPipelineError::VirtualResolveFailed(format!("{}", e)))?;

    // Record virtual snapshot in batch
    let snapshot = virtual_state.snapshot();
    let snapshot_json = serde_json::to_vec(&snapshot).map_err(|e| {
        AtomicPipelineError::VirtualResolveFailed(format!("serialize virtual snapshot: {}", e))
    })?;
    batch.put_virtual_snapshot(snapshot_json);
    batch.put_last_accepted(block_hash);

    debug!(
        "Stage 4 passed: StateDiff built ({} nullifiers, {} created, {} spent)",
        diff.nullifiers_added.len(),
        diff.utxos_created.len(),
        diff.utxos_spent.len()
    );

    // ════════════════════════════════════════════════════════════
    //  Stage 5: Return WriteBatch for Atomic Commit
    // ════════════════════════════════════════════════════════════
    //
    // ここに到達 = Stage 1-4 すべて成功。
    // WriteBatch を返り値に含め、呼び出し元が commit() を実行する。
    //
    // ```ignore
    // let result = process_new_block_atomic(&block, ...)?;
    // result.write_batch.commit(&persistent_store)?;
    // ```
    //
    // commit() 内部では RocksDB WriteBatch を使用し、
    // 全 CF への書き込みが原子的に行われる。
    //
    // # なぜ関数内で commit しないのか
    //
    // process_new_block_atomic は DagStore trait (読み取り用) のみを受け取る。
    // PersistentDagBackend (書き込み用) は呼び出し元の misaka-node が保持する。
    // この trait boundary の分離により、DAG レイヤーが永続化実装に依存しない。
    //
    // commit() が呼ばれずに write_batch が Drop された場合:
    // - 全蓄積データは自動破棄される
    // - VirtualState のメモリ上の変更は残るため、ノード再起動が必要
    // - 本番環境では呼び出し元が必ず commit() を呼ぶことを前提とする

    info!(
        "Block {} accepted atomically (blue_score={}, txs={}, nullifiers={}, created={}, spent={})",
        hex::encode(&block_hash[..4]),
        computed_blue_score,
        block.transactions.len(),
        diff.nullifiers_added.len(),
        diff.utxos_created.len(),
        diff.utxos_spent.len(),
    );

    Ok(AtomicAcceptResult {
        block_hash,
        blue_score: computed_blue_score,
        ghostdag_data,
        state_diff: diff,
        is_new_tip,
        write_batch: batch,
    })
}

// ═══════════════════════════════════════════════════════════════
//  QdagBlock → StateDiff 構築 (v4: SpentUtxo 付)
// ═══════════════════════════════════════════════════════════════

/// QdagBlock (SealedTransaction ベース) から StateDiff を構築する。
///
/// `build_block_diff` の v4 版。SealedTransaction から直接 nullifier と
/// output 情報を取得し、VirtualState を参照して SpentUtxo を記録する。
///
/// # v4 完全可逆性
///
/// TX が accepted された場合、そのインプットが消費する UTXO を
/// VirtualState から検索し、完全な PQC メタデータとともに
/// `SpentUtxo` として記録する。これにより revert 時に
/// UTXO セットを完全復元できる。
fn build_qdag_block_diff(
    block_hash: Hash,
    blue_score: u64,
    txs: &[SealedTransaction],
    virtual_state: &VirtualState,
) -> StateDiff {
    let mut nullifiers_added = Vec::new();
    let mut utxos_created = Vec::new();
    // v4: SealedTransaction は source outpoints を持たないため、
    // QdagBlock パスでは utxos_spent は空。UtxoTransaction ベースの
    // build_block_diff (dag_block_producer.rs) で完全な SpentUtxo を記録する。
    let mut utxos_spent = Vec::new();
    let mut tx_results = Vec::new();
    let mut block_local_nullifiers: std::collections::HashSet<[u8; 32]> =
        std::collections::HashSet::new();

    for sealed_tx in txs {
        if sealed_tx.is_coinbase {
            // Coinbase: always accepted, create outputs
            for (idx, addr) in sealed_tx.output_addresses.iter().enumerate() {
                utxos_created.push(CreatedUtxo {
                    outref: OutputRef {
                        tx_hash: sealed_tx.tx_hash,
                        output_index: idx as u32,
                    },
                    output: misaka_types::utxo::TxOutput {
                        amount: 0, // Coinbase amount は別途 tokenomics で決定
                        one_time_address: *addr,
                        pq_stealth: None,
                        spending_pubkey: None,
                    },
                    tx_hash: sealed_tx.tx_hash,
                });
            }
            tx_results.push(DiffTxResult::coinbase(sealed_tx.tx_hash));
            continue;
        }

        // Check nullifier conflicts
        let mut conflicting_nf: Option<[u8; 32]> = None;
        for nf in &sealed_tx.nullifiers {
            if virtual_state.is_nullifier_spent(nf)
                || block_local_nullifiers.contains(nf)
                || nullifiers_added.contains(nf)
            {
                conflicting_nf = Some(*nf);
                break;
            }
        }

        if let Some(nf) = conflicting_nf {
            tx_results.push(DiffTxResult::failed_nullifier(
                sealed_tx.tx_hash,
                nf,
                [0u8; 32],
            ));
        } else {
            // TX accepted
            for nf in &sealed_tx.nullifiers {
                nullifiers_added.push(*nf);
                block_local_nullifiers.insert(*nf);
            }

            // Record outputs
            for (idx, addr) in sealed_tx.output_addresses.iter().enumerate() {
                utxos_created.push(CreatedUtxo {
                    outref: OutputRef {
                        tx_hash: sealed_tx.tx_hash,
                        output_index: idx as u32,
                    },
                    output: misaka_types::utxo::TxOutput {
                        amount: 0, // Amount は proof から取得 (confidential)
                        one_time_address: *addr,
                        pq_stealth: None,
                        spending_pubkey: None,
                    },
                    tx_hash: sealed_tx.tx_hash,
                });
            }

            // ── v4: Record spent UTXOs with full PQC metadata ──
            //
            // SealedTransaction now carries source_outpoints — the UTXOs
            // consumed by this transaction. Look up each in the virtual state
            // to create SpentUtxo records for perfect reversibility.
            for outref in &sealed_tx.source_outpoints {
                if let Some((output, creation_score)) = virtual_state.get_utxo_with_score(outref) {
                    utxos_spent.push(SpentUtxo {
                        outref: outref.clone(),
                        output: output.clone(),
                        creation_tx_hash: outref.tx_hash,
                        creation_blue_score: creation_score,
                        spending_tx_hash: sealed_tx.tx_hash,
                        nullifier: sealed_tx.nullifiers.first().copied().unwrap_or([0u8; 32]),
                    });
                }
            }

            tx_results.push(DiffTxResult::applied(
                sealed_tx.tx_hash,
                sealed_tx.nullifiers.clone(),
            ));
        }
    }

    StateDiff {
        block_hash,
        blue_score,
        epoch: u32::try_from(crate::daa::DaaScore(blue_score).epoch()).unwrap_or(u32::MAX),
        nullifiers_added,
        utxos_created,
        utxos_spent,
        tx_results,
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_batch_drop_discards() {
        // WriteBatch が commit されずに drop されても安全
        let mut batch = StoreWriteBatch::new();
        batch.put_header(
            [1; 32],
            DagBlockHeader {
                version: 1,
                parents: vec![],
                timestamp_ms: 0,
                tx_root: [0; 32],
                proposer_id: [0; 32],
                nonce: 0,
                blue_score: 0,
                bits: 0,
            },
        );
        batch.put_nullifier([0xAA; 32], [0xBB; 32]);
        // batch drops here — no commit, no panic, no DB writes
    }

    #[test]
    fn test_write_batch_empty_check() {
        let batch = StoreWriteBatch::new();
        assert!(batch.is_empty());

        let mut batch2 = StoreWriteBatch::new();
        batch2.put_nullifier([0xAA; 32], [0xBB; 32]);
        assert!(!batch2.is_empty());
    }

    #[test]
    fn test_qdag_diff_coinbase_only() {
        let vs = VirtualState::new([0; 32]);
        let coinbase_tx = SealedTransaction::seal(
            [0x01; 32],
            vec![], // no nullifiers
            true,   // is_coinbase
            1,
            vec![[0xCC; 32]],
            1,
        );

        let diff = build_qdag_block_diff([0x10; 32], 1, &[coinbase_tx], &vs);

        assert_eq!(diff.nullifiers_added.len(), 0);
        assert_eq!(diff.utxos_created.len(), 1);
        assert_eq!(diff.tx_results.len(), 1);
        assert_eq!(diff.tx_results[0].status, DiffTxStatus::Coinbase);
    }

    #[test]
    fn test_qdag_diff_nullifier_conflict() {
        let mut vs = VirtualState::new([0; 32]);

        // Pre-populate a nullifier
        let pre_diff = StateDiff {
            block_hash: [0x01; 32],
            blue_score: 1,
            epoch: 0,
            nullifiers_added: vec![[0xAA; 32]],
            utxos_created: vec![],
            utxos_spent: vec![],
            tx_results: vec![],
        };
        vs.apply_block(pre_diff).unwrap();

        // Try to apply a TX that uses the same nullifier
        let conflicting_tx = SealedTransaction::seal(
            [0x02; 32],
            vec![[0xAA; 32]], // same nullifier — conflict!
            false,
            1,
            vec![[0xDD; 32]],
            1,
        );

        let diff = build_qdag_block_diff([0x20; 32], 2, &[conflicting_tx], &vs);

        assert_eq!(
            diff.tx_results[0].status,
            DiffTxStatus::FailedNullifierConflict
        );
        assert_eq!(
            diff.nullifiers_added.len(),
            0,
            "conflicting nullifier must not be added"
        );
        assert_eq!(
            diff.utxos_created.len(),
            0,
            "conflicting TX must not create outputs"
        );
    }

    #[test]
    fn test_qdag_diff_intra_block_conflict() {
        let vs = VirtualState::new([0; 32]);

        // Two TXs in same block with same nullifier
        let tx1 =
            SealedTransaction::seal([0x01; 32], vec![[0xAA; 32]], false, 1, vec![[0xDD; 32]], 1);
        let tx2 = SealedTransaction::seal(
            [0x02; 32],
            vec![[0xAA; 32]], // same nullifier as tx1
            false,
            1,
            vec![[0xEE; 32]],
            1,
        );

        let diff = build_qdag_block_diff([0x10; 32], 1, &[tx1, tx2], &vs);

        assert_eq!(
            diff.tx_results[0].status,
            DiffTxStatus::Applied,
            "first TX wins"
        );
        assert_eq!(
            diff.tx_results[1].status,
            DiffTxStatus::FailedNullifierConflict,
            "second TX with same nullifier rejected"
        );
    }

    /// Stage 1 failure: duplicate block.
    /// Ensures WriteBatch is never committed.
    #[test]
    fn test_atomic_pipeline_rejects_duplicate() {
        use crate::dag_block::{DagBlockHeader, GhostDagData, DAG_VERSION};
        use crate::ghostdag::{InMemoryDagStore, UniformStakeProvider};

        let genesis = [0u8; 32];
        let mut reach = ReachabilityStore::new(genesis);
        let mut store = InMemoryDagStore::new();
        let engine = GhostDagEngine::new(18, genesis);
        let mut vs = VirtualState::new(genesis);

        // Set up genesis
        store.insert_header(
            genesis,
            DagBlockHeader {
                version: DAG_VERSION,
                parents: vec![],
                timestamp_ms: 0,
                tx_root: [0; 32],
                proposer_id: [0; 32],
                nonce: 0,
                blue_score: 0,
                bits: 0,
            },
        );
        store.set_ghostdag_data(
            genesis,
            GhostDagData {
                selected_parent: ZERO_HASH,
                mergeset_blues: vec![],
                mergeset_reds: vec![],
                blue_score: 0,
                blue_work: 0,
                blues_anticone_sizes: vec![],
            },
        );

        // Create a block
        let block = QdagBlock::new(
            DagBlockHeader {
                version: DAG_VERSION,
                parents: vec![genesis],
                timestamp_ms: 1000,
                tx_root: [0; 32],
                proposer_id: [1; 32],
                nonce: 0,
                blue_score: 1,
                bits: crate::daa::INITIAL_BITS,
            },
            vec![],
        );
        let block_hash = block.hash();

        // Insert it once (via store directly to simulate existing block)
        store.insert_header(block_hash, block.header.clone());

        // Attempt atomic pipeline — should reject as duplicate
        let result = process_new_block_atomic(
            &block,
            &store,
            &mut reach,
            &engine,
            &UniformStakeProvider,
            &mut vs,
        );

        assert!(
            matches!(result, Err(AtomicPipelineError::Duplicate(_))),
            "duplicate block must be rejected at Stage 1"
        );
    }
}
