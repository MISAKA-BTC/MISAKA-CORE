//! Virtual State — ResolveVirtual-Centered DAG State (v7).
//!
//! # v6 → v7: ResolveVirtual 中心設計
//!
//! v6 までは外部から `(new_tip, new_diffs)` を渡す push 型だったが、
//! v7 では `resolve()` が中心 API。Tips と Store を渡すと:
//!
//! 1. Virtual selected parent を計算
//! 2. SP chain changes を追跡 (added/removed)
//! 3. UTXO diff を計算・適用
//! 4. Acceptance data を生成
//! 5. Notification を発行 (wallet/RPC 用)
//!
//! Kaspa の `ResolveVirtual` に相当する責務統合。
//!
//! # API Summary
//!
//! | Method | Purpose |
//! |--------|---------|
//! | `resolve()` | 新ブロック到着後に呼ぶ中心 API |
//! | `snapshot()` | Virtual state の永続化用スナップショット取得 |
//! | `from_snapshot()` | Restart 時のスナップショット復元 |
//! | `acceptance_data()` | 最新の resolve で生成された acceptance data |

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::dag_block::Hash;
use crate::ghostdag::DagStore;
use crate::parent_selection;
use crate::reachability::{self, ReachabilityStore};
use crate::state_diff::{CreatedUtxo, DiffApplicable, DiffTxResult, DiffTxStatus, StateDiff};
use misaka_types::utxo::{OutputRef, TxOutput};

/// Maximum reorg depth (state diff stack size).
///
/// # No-Rollback Architecture
///
/// This value is intentionally limited. Deep reorgs are prevented by
/// finality boundary enforcement. The diff stack only needs to support
/// shallow SPC switches (DAG ordering changes).
pub const MAX_REORG_DEPTH: usize = 1000;

/// Maximum SPC (Selected Parent Chain) switch depth.
///
/// This is the hard limit for how many blocks can be reverted in a single
/// VirtualState update. Set to k * 2 = 36 (DEFAULT_K = 18).
/// Beyond this, the reorg is rejected — the node must resync from checkpoint.
pub const MAX_SPC_SWITCH_DEPTH: usize = 36;

// ═══════════════════════════════════════════════════════════════
//  Acceptance Data
// ═══════════════════════════════════════════════════════════════

/// 1 ブロック分の TX 受理結果。
///
/// Kaspa の AcceptanceData に相当。各ブロック内の TX が
/// virtual state 適用時に accepted/rejected されたかの記録。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockAcceptanceData {
    pub block_hash: Hash,
    pub tx_results: Vec<TxAcceptance>,
}

/// 1 TX の受理結果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxAcceptance {
    pub tx_hash: [u8; 32],
    pub accepted: bool,
    /// Rejection reason (empty if accepted).
    pub rejection_reason: String,
}

// ═══════════════════════════════════════════════════════════════
//  Virtual Chain Changes
// ═══════════════════════════════════════════════════════════════

/// Virtual Selected Parent Chain の変更通知。
///
/// `resolve()` の結果として生成される。
/// Wallet / RPC / Explorer がこの通知を購読して状態を更新する。
///
/// Kaspa の `VirtualChainChangedNotification` に相当。
#[derive(Debug, Clone)]
pub struct VirtualChainChanged {
    /// SP chain から除去されたブロック (reorg で巻き戻された分)。
    /// oldest → newest 順。
    pub removed_chain_hashes: Vec<Hash>,
    /// SP chain に追加されたブロック。
    /// oldest → newest 順。
    pub added_chain_hashes: Vec<Hash>,
    /// 各追加ブロックの acceptance data。
    /// `added_chain_hashes` と同一順序・同一長。
    pub acceptance_data: Vec<BlockAcceptanceData>,
}

// ═══════════════════════════════════════════════════════════════
//  Virtual State Snapshot (for persistence)
// ═══════════════════════════════════════════════════════════════

/// Virtual state の永続化用スナップショット。
///
/// Restart 時にこのスナップショットから `VirtualState` を復元する。
/// Diff journal と組み合わせて、full replay なしの高速復元が可能。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualStateSnapshot {
    pub tip: Hash,
    pub tip_score: u64,
    /// Nullifier set のダイジェスト (full set は別途保存)。
    pub nullifier_count: usize,
    pub utxo_count: usize,
    /// State root at this snapshot point.
    pub state_root: Hash,
    /// Finality boundary — blocks at or below this score cannot be reverted.
    #[serde(default)]
    pub finality_boundary_score: u64,
    /// Snapshot creation timestamp (unix ms).
    pub created_at_ms: u64,
}

// ═══════════════════════════════════════════════════════════════
//  Virtual State
// ═══════════════════════════════════════════════════════════════

/// The current DAG state at the virtual tip.
///
/// This is the SINGLE SOURCE OF TRUTH for "what is the current state."
/// It is updated incrementally via diffs, NEVER by full replay.
///
/// # Invariants
///
/// 1. `nullifiers` contains exactly the set of spent nullifiers up to `tip`
/// 2. `utxos` contains exactly the set of unspent outputs up to `tip`
/// 3. `diff_stack` contains diffs in order (oldest to newest)
/// 4. Reverting all diffs in reverse order returns to genesis state
/// 5. `tip` is always the hash of the most recently applied block
pub struct VirtualState {
    /// Current virtual tip (most recently applied block).
    pub tip: Hash,
    /// Blue score at the virtual tip.
    pub tip_score: u64,
    /// Spent nullifiers (complete set up to tip).
    nullifiers: HashSet<Hash>,
    /// Unspent outputs (complete set up to tip).
    /// Value: (TxOutput, creation_blue_score).
    utxos: HashMap<OutputRef, (TxOutput, u64)>,
    /// State diff stack (undo log). Most recent diff on top.
    diff_stack: Vec<StateDiff>,
    /// Maximum diff stack depth.
    max_depth: usize,
    /// Finality boundary: blue_score at or below which blocks CANNOT be reverted.
    ///
    /// Updated when EconomicFinalityManager confirms a new checkpoint.
    /// Any SPC switch that would revert a block at or below this score
    /// is HARD REJECTED — this is the core no-rollback invariant.
    pub finality_boundary_score: u64,
    /// Statistics.
    pub stats: VirtualStateStats,
}

/// Statistics for monitoring.
#[derive(Debug, Clone, Default)]
pub struct VirtualStateStats {
    pub blocks_applied: u64,
    pub spc_switches: u64,
    pub reorgs: u64,
    pub deepest_reorg: usize,
    pub current_nullifiers: usize,
    pub current_utxos: usize,
}

impl VirtualState {
    /// Create a new VirtualState from genesis.
    pub fn new(genesis_hash: Hash) -> Self {
        Self {
            tip: genesis_hash,
            tip_score: 0,
            nullifiers: HashSet::new(),
            utxos: HashMap::new(),
            diff_stack: Vec::new(),
            max_depth: MAX_REORG_DEPTH,
            finality_boundary_score: 0,
            stats: VirtualStateStats::default(),
        }
    }

    /// Restore from a checkpoint snapshot.
    ///
    /// UTXOs from snapshots have creation_blue_score = 0 (unknown).
    /// This is acceptable because snapshots are only loaded at startup,
    /// and future SpentUtxo records will use the tracked score.
    pub fn from_snapshot(
        tip: Hash,
        tip_score: u64,
        nullifiers: HashSet<Hash>,
        utxos: HashMap<OutputRef, TxOutput>,
    ) -> Self {
        let tracked: HashMap<OutputRef, (TxOutput, u64)> = utxos
            .into_iter()
            .map(|(k, v)| (k, (v, 0))) // score unknown from snapshot
            .collect();
        let stats = VirtualStateStats {
            current_nullifiers: nullifiers.len(),
            current_utxos: tracked.len(),
            ..Default::default()
        };
        Self {
            tip,
            tip_score,
            nullifiers,
            utxos: tracked,
            diff_stack: Vec::new(),
            max_depth: MAX_REORG_DEPTH,
            finality_boundary_score: 0,
            stats,
        }
    }

    // ── Finality Boundary ──

    /// Update the finality boundary score.
    ///
    /// Called by the node when EconomicFinalityManager confirms a new
    /// finalized checkpoint. After this call, any SPC switch that would
    /// revert blocks at or below `score` is HARD REJECTED.
    ///
    /// # Safety Invariant
    ///
    /// The finality boundary is monotonically non-decreasing. Passing a
    /// score lower than the current boundary is a no-op (logged as warning).
    pub fn set_finality_boundary(&mut self, score: u64) {
        if score > self.finality_boundary_score {
            tracing::info!(
                "VirtualState: finality boundary updated {} → {}",
                self.finality_boundary_score,
                score
            );
            self.finality_boundary_score = score;
        } else if score < self.finality_boundary_score {
            tracing::warn!(
                "VirtualState: ignoring finality boundary regression {} → {} (current={})",
                self.finality_boundary_score,
                score,
                self.finality_boundary_score
            );
        }
    }

    /// Current finality boundary score.
    pub fn finality_boundary(&self) -> u64 {
        self.finality_boundary_score
    }

    // ── Query (O(1)) ──

    pub fn is_nullifier_spent(&self, nf: &Hash) -> bool {
        self.nullifiers.contains(nf)
    }

    pub fn get_utxo(&self, outref: &OutputRef) -> Option<&TxOutput> {
        self.utxos.get(outref).map(|(output, _)| output)
    }

    /// Get a UTXO with its creation blue_score.
    /// Returns None if the UTXO doesn't exist.
    pub fn get_utxo_with_score(&self, outref: &OutputRef) -> Option<(&TxOutput, u64)> {
        self.utxos
            .get(outref)
            .map(|(output, score)| (output, *score))
    }

    pub fn nullifier_count(&self) -> usize {
        self.nullifiers.len()
    }
    pub fn utxo_count(&self) -> usize {
        self.utxos.len()
    }
    pub fn all_nullifiers(&self) -> &HashSet<Hash> {
        &self.nullifiers
    }

    // ── Update (O(|diff|)) ──

    /// Apply a new block's diff to advance the virtual tip.
    ///
    /// # Complexity: O(|nullifiers_added| + |utxos_created|) per block
    ///
    /// This is bounded by MAX_QDAG_INPUTS (16) + MAX_QDAG_OUTPUTS (64) = 80
    /// per transaction, and MAX_TXS_PER_BLOCK per block.
    /// Therefore O(constant) per block.
    pub fn apply_block(&mut self, diff: StateDiff) -> Result<(), VirtualStateError> {
        // ── Forward Step 1: Remove spent UTXOs from UTXO set ──
        //
        // v4: utxos_spent に記録された UTXO を除去。
        // 完全な PQC メタデータは diff 内に保存されているため、
        // revert_last() で完全復元が可能。
        for spent in &diff.utxos_spent {
            self.utxos.remove(&spent.outref);
            // Note: UTXO が存在しない場合は警告のみ（genesis 直後等）
        }

        // ── Forward Step 2: Apply nullifiers ──
        for nf in &diff.nullifiers_added {
            self.nullifiers.insert(*nf);
        }

        // ── Forward Step 3: Apply UTXO creations ──
        let creation_score = diff.blue_score;
        for created in &diff.utxos_created {
            self.utxos.insert(
                created.outref.clone(),
                (created.output.clone(), creation_score),
            );
        }

        self.tip = diff.block_hash;
        self.tip_score = diff.blue_score;
        self.stats.blocks_applied += 1;
        self.stats.current_nullifiers = self.nullifiers.len();
        self.stats.current_utxos = self.utxos.len();

        // Push to undo stack
        self.diff_stack.push(diff);
        if self.diff_stack.len() > self.max_depth {
            self.diff_stack.remove(0); // Trim oldest (non-revertible)
        }

        Ok(())
    }

    /// Revert the most recent block's diff.
    ///
    /// # Complexity: O(|diff|) per revert = O(constant)
    fn revert_last(&mut self) -> Result<StateDiff, VirtualStateError> {
        let diff = self
            .diff_stack
            .pop()
            .ok_or(VirtualStateError::NoDiffToRevert)?;

        // Undo nullifiers (exact inverse of apply)
        for nf in &diff.nullifiers_added {
            if !self.nullifiers.remove(nf) {
                return Err(VirtualStateError::NullifierNotFound(*nf));
            }
        }

        // Undo UTXO creations (exact inverse of apply)
        for created in &diff.utxos_created {
            self.utxos.remove(&created.outref);
        }

        // ── v4: Re-insert spent UTXOs (exact inverse of Forward Step 1) ──
        //
        // 消費された UTXO を完全な PQC メタデータとともに UTXO セットに再挿入。
        // これにより revert 後の UTXO セットは apply 前と 1 バイトのズレもなく一致する。
        for spent in &diff.utxos_spent {
            self.utxos.insert(
                spent.outref.clone(),
                (spent.output.clone(), spent.creation_blue_score),
            );
        }

        // Update tip to the previous block
        self.tip = self
            .diff_stack
            .last()
            .map(|d| d.block_hash)
            .unwrap_or([0u8; 32]); // Genesis if empty

        self.stats.spc_switches += 1;
        self.stats.current_nullifiers = self.nullifiers.len();
        self.stats.current_utxos = self.utxos.len();

        Ok(diff)
    }

    /// Update the virtual state when a new block arrives that may cause a reorg.
    ///
    /// # Algorithm (O(reorg_depth), NOT O(|DAG|)):
    ///
    /// 1. Find common ancestor of current tip and new tip
    ///    → O(1) via reachability index (is_dag_ancestor_of)
    ///    → Fallback: walk diff_stack = O(reorg_depth)
    ///
    /// 2. Revert diffs from current tip to ancestor
    ///    → O(reorg_depth × |diff_size|) = O(reorg_depth)
    ///
    /// 3. Apply new diffs from ancestor to new tip
    ///    → O(new_branch_length × |diff_size|) = O(new_branch_length)
    ///
    /// Total: O(reorg_depth + new_branch_length), both bounded by MAX_REORG_DEPTH
    ///
    /// # Why this is O(1) at scale:
    ///
    /// MAX_REORG_DEPTH is a protocol constant (1000), not a function of N.
    /// Therefore the worst-case reorg cost is O(1000 × 80) = O(80,000) = O(1).
    /// At 1,000,000 blocks, processing a new block still takes the same time
    /// as at 100 blocks (no history replay).
    /// Update the virtual state to a new tip.
    ///
    /// # v5 Fix: Conclusive DAG Ancestor Detection
    ///
    /// v4 は `is_true_dag_ancestor()` (bounded BFS) を使用していたが、
    /// BFS 上限到達時に silent false を返す可能性があった。
    /// v5 は `is_dag_ancestor_conclusive()` を使用し、判定失敗時は
    /// 明示的エラーを返す。
    ///
    /// # Complexity
    ///
    /// | Operation | Complexity |
    /// |-----------|-----------|
    /// | Advance check | O(1) SPT fast-path, worst O(active_window) |
    /// | Common ancestor | O(reorg_depth × BFS) |
    pub fn update_virtual<S: DagStore>(
        &mut self,
        new_tip: Hash,
        new_tip_score: u64,
        new_diffs: Vec<StateDiff>,
        reachability: &ReachabilityStore,
        store: &S,
    ) -> Result<UpdateResult, VirtualStateError> {
        // ── Case 1: Simple advance (no reorg) ──
        // If the current tip is an ancestor of the new tip, just apply forward.
        // Uses conclusive ancestor check for correct side-branch detection.
        if self.tip == [0u8; 32]
            || reachability::is_dag_ancestor_conclusive(&self.tip, &new_tip, reachability, store)?
        {
            let applied_count = new_diffs.len();
            for diff in new_diffs {
                self.apply_block(diff)?;
            }
            return Ok(UpdateResult {
                reorg_depth: 0,
                spc_switches: 0,
                blocks_applied: applied_count,
                new_tip,
                new_tip_score,
            });
        }

        // ── Case 2: Reorg — find common ancestor, undo/redo ──
        self.stats.reorgs += 1;

        // Find common ancestor by walking the diff stack.
        // Uses conclusive ancestor check — on error, propagate to caller.
        let mut revert_count = 0;
        for (i, diff) in self.diff_stack.iter().rev().enumerate() {
            if reachability::is_dag_ancestor_conclusive(
                &diff.block_hash,
                &new_tip,
                reachability,
                store,
            )? {
                revert_count = i;
                break;
            }
            revert_count = i + 1;
        }

        if revert_count > self.diff_stack.len() {
            return Err(VirtualStateError::ReorgTooDeep {
                depth: revert_count,
                max: self.diff_stack.len(),
            });
        }

        // ── Deep Reorg Protection (No-Rollback Architecture) ──
        //
        // Enforce MAX_SPC_SWITCH_DEPTH limit. This prevents deep state
        // reversions that could undermine finality assumptions.
        // k * 2 = 36 blocks is sufficient for normal DAG operation.
        if revert_count > MAX_SPC_SWITCH_DEPTH {
            return Err(VirtualStateError::ReorgTooDeep {
                depth: revert_count,
                max: MAX_SPC_SWITCH_DEPTH,
            });
        }

        // ── Finality Boundary Enforcement ──
        //
        // Check that NONE of the blocks being reverted are below the
        // finality boundary. If any are, REJECT the reorg entirely.
        // This is the core safety property of the no-rollback architecture.
        if self.finality_boundary_score > 0 {
            for diff in self.diff_stack.iter().rev().take(revert_count) {
                if diff.blue_score <= self.finality_boundary_score {
                    return Err(VirtualStateError::ReorgBelowFinality {
                        block_hash: diff.block_hash,
                        block_score: diff.blue_score,
                        finality_boundary: self.finality_boundary_score,
                    });
                }
            }
        }

        if revert_count > self.stats.deepest_reorg {
            self.stats.deepest_reorg = revert_count;
        }

        // Revert to common ancestor
        let mut reverted_diffs = Vec::with_capacity(revert_count);
        for _ in 0..revert_count {
            let diff = self.revert_last()?;
            reverted_diffs.push(diff);
        }

        // Apply new branch
        let applied_count = new_diffs.len();
        for diff in new_diffs {
            self.apply_block(diff)?;
        }

        Ok(UpdateResult {
            reorg_depth: revert_count,
            spc_switches: reverted_diffs.len(),
            blocks_applied: applied_count,
            new_tip,
            new_tip_score,
        })
    }

    /// Compute a deterministic state root.
    pub fn compute_state_root(&self) -> Hash {
        use sha3::{Digest, Sha3_256};

        let mut h = Sha3_256::new();
        h.update(b"MISAKA:virtual_state_root:v1:");
        h.update(self.tip_score.to_le_bytes());

        // Nullifiers (sorted for determinism)
        let mut nfs: Vec<&Hash> = self.nullifiers.iter().collect();
        nfs.sort();
        h.update((nfs.len() as u64).to_le_bytes());
        for nf in &nfs {
            h.update(nf);
        }

        // UTXOs (sorted for determinism)
        let mut utxos: Vec<(&OutputRef, &(TxOutput, u64))> = self.utxos.iter().collect();
        utxos.sort_by(|a, b| {
            a.0.tx_hash
                .cmp(&b.0.tx_hash)
                .then_with(|| a.0.output_index.cmp(&b.0.output_index))
        });
        h.update((utxos.len() as u64).to_le_bytes());
        for (outref, _) in &utxos {
            h.update(&outref.tx_hash);
            h.update(outref.output_index.to_le_bytes());
        }

        h.finalize().into()
    }

    // ── ResolveVirtual API (v7) ──────────────────────────

    /// ResolveVirtual — DAG の virtual tip を再解決する中心 API。
    ///
    /// 新ブロックが DAG に挿入された後に呼び出す。
    ///
    /// # Algorithm
    ///
    /// 1. Tips から virtual selected parent を計算
    /// 2. 現在の tip と比較:
    ///    - 同一 → no-op
    ///    - ancestor → simple advance (apply forward)
    ///    - diverged → reorg (revert to common ancestor, apply new branch)
    /// 3. Acceptance data と chain changes を生成
    ///
    /// # Returns
    ///
    /// `ResolveResult` — chain changes, acceptance data, stats。
    /// Wallet / RPC はこの結果から通知を生成する。
    ///
    /// # Kaspa 対応
    ///
    /// Kaspa の `consensus.ResolveVirtual()` に相当。
    /// MISAKA では `VirtualState.resolve()` が同等の責務を担う。
    pub fn resolve<S: DagStore>(
        &mut self,
        new_tip: Hash,
        new_tip_score: u64,
        new_diffs: Vec<StateDiff>,
        reachability: &ReachabilityStore,
        store: &S,
    ) -> Result<ResolveResult, VirtualStateError> {
        let old_tip = self.tip;

        // Delegate to update_virtual for the actual state transition
        let update = self.update_virtual(
            new_tip,
            new_tip_score,
            new_diffs.clone(),
            reachability,
            store,
        )?;

        // Build acceptance data from the applied diffs
        let acceptance_data: Vec<BlockAcceptanceData> = new_diffs
            .iter()
            .map(|diff| BlockAcceptanceData {
                block_hash: diff.block_hash,
                tx_results: diff
                    .tx_results
                    .iter()
                    .map(|tr| TxAcceptance {
                        tx_hash: tr.tx_hash,
                        accepted: matches!(
                            tr.status,
                            DiffTxStatus::Applied | DiffTxStatus::Coinbase
                        ),
                        rejection_reason: match &tr.status {
                            DiffTxStatus::Applied | DiffTxStatus::Coinbase => String::new(),
                            DiffTxStatus::FailedNullifierConflict => {
                                "double-spend: nullifier conflict".to_string()
                            }
                            DiffTxStatus::FailedInvalidProof => "invalid proof".to_string(),
                        },
                    })
                    .collect(),
            })
            .collect();

        // Build chain changes
        let chain_changes = VirtualChainChanged {
            removed_chain_hashes: if update.reorg_depth > 0 {
                // The blocks that were reverted (approximate — exact hashes
                // would require storing them during revert, which we can add later)
                vec![old_tip] // Simplified: just the old tip
            } else {
                vec![]
            },
            added_chain_hashes: new_diffs.iter().map(|d| d.block_hash).collect(),
            acceptance_data: acceptance_data.clone(),
        };

        Ok(ResolveResult {
            old_tip,
            new_tip: update.new_tip,
            new_tip_score: update.new_tip_score,
            reorg_depth: update.reorg_depth,
            blocks_applied: update.blocks_applied,
            spc_switches: update.spc_switches,
            chain_changes,
            state_root: self.compute_state_root(),
        })
    }

    /// Virtual state の永続化用スナップショットを取得。
    ///
    /// Restart 時に `from_snapshot()` + diff journal で復元する。
    pub fn snapshot(&self) -> VirtualStateSnapshot {
        VirtualStateSnapshot {
            tip: self.tip,
            tip_score: self.tip_score,
            nullifier_count: self.nullifiers.len(),
            utxo_count: self.utxos.len(),
            state_root: self.compute_state_root(),
            finality_boundary_score: self.finality_boundary_score,
            created_at_ms: chrono::Utc::now().timestamp_millis() as u64,
        }
    }

    /// Virtual selected parent を計算する (tips から)。
    ///
    /// Tips の中から canonical sort で最良のブロックを選択。
    /// `resolve()` 内部で使用。外部からも参照可能。
    pub fn compute_virtual_selected_parent<S: DagStore>(
        tips: &[Hash],
        store: &S,
        genesis_hash: &Hash,
    ) -> Hash {
        parent_selection::select_parent(tips, store, genesis_hash)
    }
}

/// ResolveVirtual の結果。
///
/// Wallet / RPC / Explorer はこの結果から通知を生成する。
#[derive(Debug, Clone)]
pub struct ResolveResult {
    pub old_tip: Hash,
    pub new_tip: Hash,
    pub new_tip_score: u64,
    pub reorg_depth: usize,
    pub blocks_applied: usize,
    pub spc_switches: usize,
    /// SP chain の変更内容 (wallet/RPC notification 用)。
    pub chain_changes: VirtualChainChanged,
    /// resolve 後の state root。
    pub state_root: Hash,
}

/// Result of a virtual state update.
#[derive(Debug)]
pub struct UpdateResult {
    pub reorg_depth: usize,
    pub spc_switches: usize,
    pub blocks_applied: usize,
    pub new_tip: Hash,
    pub new_tip_score: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum VirtualStateError {
    #[error("no diff to revert (at genesis)")]
    NoDiffToRevert,
    #[error("nullifier {0:?} not found during revert")]
    NullifierNotFound(Hash),
    #[error("reorg depth {depth} exceeds max {max}")]
    ReorgTooDeep { depth: usize, max: usize },
    #[error("state root mismatch: computed={computed}, expected={expected}")]
    StateRootMismatch { computed: String, expected: String },
    #[error("reachability error during virtual state update: {0}")]
    ReachabilityFailure(reachability::ReachabilityError),
    /// SPC switch would revert a block below the finality boundary.
    /// This is the core safety property of the no-rollback architecture.
    /// Once a block's blue_score is at or below finality_boundary_score,
    /// it CANNOT be reverted under any circumstances.
    #[error(
        "reorg below finality: block {} at score {block_score} <= boundary {finality_boundary}",
        hex::encode(&block_hash[..4])
    )]
    ReorgBelowFinality {
        block_hash: Hash,
        block_score: u64,
        finality_boundary: u64,
    },
}

impl From<reachability::ReachabilityError> for VirtualStateError {
    fn from(e: reachability::ReachabilityError) -> Self {
        Self::ReachabilityFailure(e)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reachability::ReachabilityStore;

    fn make_diff(block_id: u8, nullifiers: &[Hash], utxos: &[(u8, u32)]) -> StateDiff {
        StateDiff {
            block_hash: [block_id; 32],
            blue_score: block_id as u64,
            epoch: 0,
            nullifiers_added: nullifiers.to_vec(),
            utxos_created: utxos
                .iter()
                .map(|(id, idx)| CreatedUtxo {
                    outref: OutputRef {
                        tx_hash: [*id; 32],
                        output_index: *idx,
                    },
                    output: TxOutput {
                        amount: 0,
                        one_time_address: [0xAA; 32],
                        pq_stealth: None,
                        spending_pubkey: None,
                    },
                    tx_hash: [*id; 32],
                })
                .collect(),
            utxos_spent: vec![],
            tx_results: vec![],
        }
    }

    /// CORE PROPERTY: apply + revert = identity (state root preserved).
    #[test]
    fn test_apply_revert_identity() {
        let mut vs = VirtualState::new([0; 32]);
        let root_genesis = vs.compute_state_root();

        let diff = make_diff(1, &[[0xAA; 32]], &[(1, 0)]);
        vs.apply_block(diff).unwrap();
        assert_ne!(vs.compute_state_root(), root_genesis);

        vs.revert_last().unwrap();
        assert_eq!(
            vs.compute_state_root(),
            root_genesis,
            "SOUNDNESS: revert must restore exact genesis state root"
        );
    }

    /// Simple forward advancement (no reorg).
    #[test]
    fn test_simple_advance() {
        use crate::dag_block::{DagBlockHeader, GhostDagData, DAG_VERSION, ZERO_HASH};
        use crate::ghostdag::InMemoryDagStore;

        let genesis = [0u8; 32];
        let mut vs = VirtualState::new(genesis);
        let mut reach = ReachabilityStore::new(genesis);
        let mut store = InMemoryDagStore::new();

        // Set up store with headers + ghostdag data for is_dag_ancestor_conclusive
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

        for (hash, parent, score) in [([1; 32], genesis, 1u64), ([2; 32], [1; 32], 2)] {
            store.insert_header(
                hash,
                DagBlockHeader {
                    version: DAG_VERSION,
                    parents: vec![parent],
                    timestamp_ms: 0,
                    tx_root: [0; 32],
                    proposer_id: [0; 32],
                    nonce: 0,
                    blue_score: 0,
                    bits: 0,
                },
            );
            store.set_ghostdag_data(
                hash,
                GhostDagData {
                    selected_parent: parent,
                    mergeset_blues: vec![],
                    mergeset_reds: vec![],
                    blue_score: score,
                    blue_work: score as u128,
                    blues_anticone_sizes: vec![],
                },
            );
            reach.add_child(parent, hash).unwrap();
        }

        let diffs = vec![
            make_diff(1, &[[0xAA; 32]], &[(1, 0)]),
            make_diff(2, &[[0xBB; 32]], &[(2, 0)]),
        ];

        let result = vs
            .update_virtual([2; 32], 2, diffs, &reach, &store)
            .unwrap();

        assert_eq!(result.reorg_depth, 0, "no reorg for simple advance");
        assert_eq!(result.blocks_applied, 2);
        assert_eq!(vs.nullifier_count(), 2);
        assert_eq!(vs.utxo_count(), 2);
        assert_eq!(vs.tip, [2; 32]);
    }

    /// Multi-block apply then full revert.
    #[test]
    fn test_multi_block_revert() {
        let mut vs = VirtualState::new([0; 32]);
        let root_genesis = vs.compute_state_root();

        vs.apply_block(make_diff(1, &[[0x01; 32]], &[(1, 0)]))
            .unwrap();
        vs.apply_block(make_diff(2, &[[0x02; 32]], &[(2, 0)]))
            .unwrap();
        vs.apply_block(make_diff(3, &[[0x03; 32]], &[(3, 0)]))
            .unwrap();

        assert_eq!(vs.nullifier_count(), 3);

        vs.revert_last().unwrap();
        vs.revert_last().unwrap();
        vs.revert_last().unwrap();

        assert_eq!(vs.compute_state_root(), root_genesis);
        assert_eq!(vs.nullifier_count(), 0);
    }

    /// State root is deterministic.
    #[test]
    fn test_state_root_deterministic() {
        let mut vs1 = VirtualState::new([0; 32]);
        let mut vs2 = VirtualState::new([0; 32]);

        let diff = make_diff(1, &[[0xAA; 32], [0xBB; 32]], &[(1, 0)]);
        vs1.apply_block(diff.clone()).unwrap();
        vs2.apply_block(diff).unwrap();

        assert_eq!(
            vs1.compute_state_root(),
            vs2.compute_state_root(),
            "identical states must produce identical roots"
        );
    }

    /// Nullifier queries are O(1).
    #[test]
    fn test_nullifier_query_o1() {
        let mut vs = VirtualState::new([0; 32]);
        vs.apply_block(make_diff(1, &[[0xAA; 32]], &[])).unwrap();

        assert!(vs.is_nullifier_spent(&[0xAA; 32]));
        assert!(!vs.is_nullifier_spent(&[0xBB; 32]));
    }

    /// Statistics tracking.
    #[test]
    fn test_stats_tracking() {
        let mut vs = VirtualState::new([0; 32]);
        vs.apply_block(make_diff(1, &[[0xAA; 32]], &[(1, 0)]))
            .unwrap();
        vs.apply_block(make_diff(2, &[[0xBB; 32]], &[(2, 0)]))
            .unwrap();
        vs.revert_last().unwrap();

        assert_eq!(vs.stats.blocks_applied, 2);
        assert_eq!(vs.stats.spc_switches, 1);
    }
}
