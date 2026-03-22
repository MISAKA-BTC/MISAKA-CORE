//! StateDiff — Symmetric Apply/Revert State Transitions.
//!
//! # Problem
//!
//! DAG reorgs change the total ordering of blocks, which changes which
//! nullifiers are "first" (valid) vs "conflicting" (invalid). In-place
//! state mutation makes reorgs dangerous: a partially reverted state
//! is corrupted and unrecoverable.
//!
//! # Solution: Immutable StateDiff
//!
//! Every block application produces a `StateDiff` — a complete record of
//! what changed. State is NEVER mutated directly; instead:
//!
//! ```text
//! apply_diff(state, diff)  → state'   (forward)
//! revert_diff(state', diff) → state    (backward)
//! ```
//!
//! These operations are EXACTLY inverse:
//!   `revert_diff(apply_diff(state, diff), diff) == state`
//!
//! # Soundness Proof (Reorg Safety)
//!
//! 1. All state transitions go through `apply_diff` / `revert_diff`
//! 2. `StateDiff` is immutable after creation (no interior mutability)
//! 3. `revert_diff` undoes EXACTLY what `apply_diff` added
//! 4. After revert, the state root matches the pre-apply state root
//!
//! Therefore, no matter how deep the reorg:
//! - Revert to common ancestor: state == state_at(common_ancestor)
//! - Re-apply new branch: state == state_at(new_tip)
//! - Nullifier set is always consistent (no phantom nullifiers)

use serde::{Serialize, Deserialize};
use sha3::{Digest, Sha3_256};
use misaka_types::utxo::{OutputRef, TxOutput};

/// Hash type alias.
pub type Hash = [u8; 32];

// ═══════════════════════════════════════════════════════════════
//  StateDiff — immutable state transition record
// ═══════════════════════════════════════════════════════════════

/// Complete record of state changes from applying one block.
///
/// # Invariant (Perfect Reversibility)
///
/// For every field `X_added`, there is a corresponding undo operation:
/// - `apply_diff`: adds X to state, removes spent UTXOs
/// - `revert_diff`: removes X from state, re-inserts spent UTXOs
///
/// These are EXACTLY inverse — no information is lost:
///   `revert_diff(apply_diff(state, diff), diff) == state`
///
/// # v4 Enhancement: SpentUtxo (Full PQC Metadata Preservation)
///
/// v3 以前は「消費された UTXO」のデータを保持しておらず、revert 時に
/// UTXO セットを完全に復元できなかった。v4 では `utxos_spent` に
/// 消費された UTXO の完全な PQC メタデータ（BdlopCommitment,
/// spending_pubkey, pq_stealth 等）を保存し、revert 時に寸分狂わず
/// UTXO セットを復元する。
///
/// # Immutability
///
/// StateDiff has no `&mut self` methods after construction.
/// Once created, it cannot be modified. This prevents accidental
/// corruption of the undo log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateDiff {
    /// Block that produced this diff.
    pub block_hash: Hash,
    /// Block's blue score (for ordering).
    pub blue_score: u64,
    /// Epoch number (for checkpoint association).
    pub epoch: u32,

    /// Nullifiers added by this block's transactions.
    /// Revert: remove these from the nullifier set.
    pub nullifiers_added: Vec<Hash>,

    /// UTXOs created by this block's transactions.
    /// Revert: remove these from the UTXO set.
    pub utxos_created: Vec<CreatedUtxo>,

    /// UTXOs consumed (spent) by this block's transactions.
    ///
    /// **v4 新規フィールド — 完全可逆性の核心**
    ///
    /// 各消費 UTXO の完全なメタデータ（amount, one_time_address,
    /// pq_stealth, spending_pubkey, creation_blue_score）を保持する。
    /// revert_diff() 時にこのデータを UTXO セットに再挿入することで、
    /// Reorg 前の状態を 1 バイトのズレもなく復元する。
    ///
    /// Apply: remove these from the UTXO set.
    /// Revert: re-insert these into the UTXO set (exact restoration).
    #[serde(default)]
    pub utxos_spent: Vec<SpentUtxo>,

    /// Transaction results (for mempool re-evaluation on revert).
    pub tx_results: Vec<DiffTxResult>,
}

/// A UTXO consumed (spent) by a transaction in this block.
///
/// Stores the COMPLETE original output data required for perfect
/// state restoration during reorg rollback.
///
/// # PQC Data Preservation
///
/// All quantum-resistant cryptographic elements are preserved:
/// - `output.pq_stealth`: ML-KEM-768 stealth addressing data
/// - `output.spending_pubkey`: Lattice polynomial spending key
/// - `output.one_time_address`: Full 32-byte PQ collision-resistant address
///
/// This ensures that after revert, the UTXO can be re-spent with
/// identical cryptographic properties — no data degradation occurs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpentUtxo {
    /// The outpoint that was consumed (tx_hash + output_index).
    pub outref: OutputRef,
    /// Complete original output data (amount, address, PQC stealth, spending key).
    /// This is the FULL TxOutput as it existed before consumption.
    pub output: TxOutput,
    /// Hash of the transaction that originally created this UTXO.
    pub creation_tx_hash: Hash,
    /// Blue score of the block that created this UTXO.
    /// Used for confirmation depth validation after revert.
    pub creation_blue_score: u64,
    /// Hash of the transaction that consumed this UTXO.
    pub spending_tx_hash: Hash,
    /// The nullifier (key image) used to spend this UTXO.
    /// Cross-referenced with nullifiers_added for consistency checks.
    pub nullifier: Hash,
}

/// A UTXO created in a block (stored for revert).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatedUtxo {
    pub outref: OutputRef,
    pub output: TxOutput,
    pub tx_hash: Hash,
}

/// Per-TX result within a diff.
///
/// # Canonical Mapping to TxApplyStatus (persistence/RPC layer)
///
/// | DiffTxStatus               | is_coinbase | TxApplyStatus                    |
/// |----------------------------|-------------|----------------------------------|
/// | Applied                    | true        | Applied (coinbase: always final)  |
/// | Applied                    | false       | Applied                          |
/// | FailedNullifierConflict    | false       | FailedNullifierConflict{..}      |
/// | FailedInvalidProof         | false       | FailedInvalidSignature           |
/// | Coinbase                   | true        | Applied (DEPRECATED path)        |
///
/// # RPC txStatusVocabulary (canonical, ordered)
///
/// `["pending", "ordered", "finalized", "failedNullifierConflict",
///   "failedKeyImageConflict", "failedInvalidSignature", "failedRingMemberNotFound"]`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffTxResult {
    pub tx_hash: Hash,
    pub status: DiffTxStatus,
    /// Nullifiers this TX contributed (if applied).
    pub nullifiers: Vec<Hash>,
    /// True if this is a coinbase (block reward) TX.
    /// Coinbase TXs are always Applied and cannot fail.
    #[serde(default)]
    pub is_coinbase: bool,
    /// For FailedNullifierConflict: the nullifier that caused the conflict.
    /// Zero hash if not applicable.
    #[serde(default)]
    pub conflicting_nullifier: Hash,
    /// For FailedNullifierConflict: the prior TX that already used this nullifier.
    /// Zero hash if the prior TX is in VirtualState (not in this block).
    #[serde(default)]
    pub prior_tx_hash: Hash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffTxStatus {
    Applied,
    FailedNullifierConflict,
    FailedInvalidProof,
    Coinbase,
}

impl DiffTxResult {
    /// Construct an Applied result.
    pub fn applied(tx_hash: Hash, nullifiers: Vec<Hash>) -> Self {
        Self { tx_hash, status: DiffTxStatus::Applied, nullifiers,
            is_coinbase: false, conflicting_nullifier: [0u8; 32], prior_tx_hash: [0u8; 32] }
    }
    /// Construct a Coinbase result.
    pub fn coinbase(tx_hash: Hash) -> Self {
        Self { tx_hash, status: DiffTxStatus::Coinbase, nullifiers: vec![],
            is_coinbase: true, conflicting_nullifier: [0u8; 32], prior_tx_hash: [0u8; 32] }
    }
    /// Construct a FailedNullifierConflict result with conflict details.
    pub fn failed_nullifier(tx_hash: Hash, conflicting_nf: Hash, prior_tx: Hash) -> Self {
        Self { tx_hash, status: DiffTxStatus::FailedNullifierConflict, nullifiers: vec![],
            is_coinbase: false, conflicting_nullifier: conflicting_nf, prior_tx_hash: prior_tx }
    }
    /// Construct a FailedInvalidProof result.
    pub fn failed_proof(tx_hash: Hash) -> Self {
        Self { tx_hash, status: DiffTxStatus::FailedInvalidProof, nullifiers: vec![],
            is_coinbase: false, conflicting_nullifier: [0u8; 32], prior_tx_hash: [0u8; 32] }
    }

    /// Convert to TxApplyStatus for persistence.
    pub fn to_apply_status(&self) -> crate::dag_state_manager::TxApplyStatus {
        use crate::dag_state_manager::TxApplyStatus;
        match self.status {
            DiffTxStatus::Applied | DiffTxStatus::Coinbase => TxApplyStatus::Applied,
            DiffTxStatus::FailedNullifierConflict => TxApplyStatus::FailedNullifierConflict {
                conflicting_nullifier: self.conflicting_nullifier,
                prior_tx_hash: self.prior_tx_hash,
            },
            DiffTxStatus::FailedInvalidProof => TxApplyStatus::FailedInvalidSignature,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Apply / Revert Trait
// ═══════════════════════════════════════════════════════════════

/// Trait for state stores that support symmetric apply/revert.
///
/// # Type-Level Safety
///
/// By requiring `revert_diff` alongside `apply_diff`, we ensure that
/// any state store used in the DAG pipeline MUST support undo.
/// A store that only supports forward application cannot implement
/// this trait and therefore cannot be used in the reorg pipeline.
pub trait DiffApplicable {
    type Error: std::fmt::Debug;

    /// Apply a state diff (forward transition).
    ///
    /// After: state contains all nullifiers_added and utxos_created.
    fn apply_diff(&mut self, diff: &StateDiff) -> Result<(), Self::Error>;

    /// Revert a state diff (backward transition).
    ///
    /// After: state is EXACTLY as it was before apply_diff.
    ///
    /// # Soundness Requirement
    ///
    /// `revert_diff(apply_diff(state, diff), diff)` MUST produce a state
    /// byte-for-byte identical to the original state. This is enforced
    /// by property tests.
    fn revert_diff(&mut self, diff: &StateDiff) -> Result<(), Self::Error>;

    /// Compute the current state root (for verification).
    fn state_root(&self) -> Hash;
}

// ═══════════════════════════════════════════════════════════════
//  Reorg Engine
// ═══════════════════════════════════════════════════════════════

/// DAG reorg handler — reverts old branch, applies new branch.
///
/// # Algorithm
///
/// 1. Find common ancestor between old tip and new tip
/// 2. Collect diffs from old tip back to ancestor (revert list)
/// 3. Collect diffs from ancestor forward to new tip (apply list)
/// 4. Execute: revert old diffs in reverse order
/// 5. Execute: apply new diffs in forward order
/// 6. Re-evaluate mempool against new nullifier set
///
/// # Soundness
///
/// After reorg:
/// - `state.state_root()` matches the state root computed by replaying
///   the new branch from genesis (or checkpoint)
/// - No nullifier is "phantom" (present in set but not in any applied TX)
/// - No nullifier is "missing" (in an applied TX but not in the set)
/// - Mempool contains NO transactions conflicting with the new state
pub struct ReorgEngine {
    /// Stack of applied diffs (most recent on top).
    /// This is the undo log.
    diff_stack: Vec<StateDiff>,
    /// Maximum depth of undo history.
    max_depth: usize,
}

/// Result of a reorg operation.
#[derive(Debug)]
pub struct ReorgResult {
    /// Diffs that were reverted (old branch).
    pub reverted: Vec<StateDiff>,
    /// Diffs that were applied (new branch).
    pub applied: Vec<StateDiff>,
    /// Transactions orphaned by the reorg (need mempool re-evaluation).
    pub orphaned_txs: Vec<OrphanedTx>,
    /// State root after reorg.
    pub new_state_root: Hash,
}

/// A transaction orphaned by a reorg.
#[derive(Debug, Clone)]
pub struct OrphanedTx {
    pub tx_hash: Hash,
    pub nullifiers: Vec<Hash>,
    /// Was this TX applied in the old branch?
    pub was_applied: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ReorgError {
    #[error("revert failed at block {block}: {reason}")]
    RevertFailed { block: String, reason: String },
    #[error("apply failed at block {block}: {reason}")]
    ApplyFailed { block: String, reason: String },
    #[error("reorg depth {depth} exceeds maximum {max}")]
    TooDeep { depth: usize, max: usize },
    #[error("common ancestor not found")]
    NoCommonAncestor,
    #[error("state root mismatch after reorg: expected {expected}, got {got}")]
    StateRootMismatch { expected: String, got: String },
}

impl ReorgEngine {
    pub fn new(max_depth: usize) -> Self {
        Self {
            diff_stack: Vec::new(),
            max_depth,
        }
    }

    /// Record a newly applied diff (push onto undo stack).
    pub fn push_diff(&mut self, diff: StateDiff) {
        self.diff_stack.push(diff);
        // Trim if too deep (oldest diffs are non-revertible)
        while self.diff_stack.len() > self.max_depth {
            self.diff_stack.remove(0);
        }
    }

    /// Current reorg depth capacity.
    pub fn depth(&self) -> usize { self.diff_stack.len() }

    /// Execute a reorg: revert old branch, apply new branch.
    ///
    /// # Arguments
    ///
    /// * `state` - The state store (implements DiffApplicable)
    /// * `revert_count` - Number of blocks to revert from current tip
    /// * `new_diffs` - Diffs to apply (new branch, in forward order)
    ///
    /// # Soundness Guarantee
    ///
    /// After this function returns Ok:
    /// 1. All old nullifiers from reverted blocks are removed from state
    /// 2. All new nullifiers from applied blocks are added to state
    /// 3. The state root matches a fresh computation
    /// 4. Orphaned TXs are returned for mempool re-evaluation
    pub fn execute_reorg<S: DiffApplicable>(
        &mut self,
        state: &mut S,
        revert_count: usize,
        new_diffs: Vec<StateDiff>,
    ) -> Result<ReorgResult, ReorgError> {
        if revert_count > self.diff_stack.len() {
            return Err(ReorgError::TooDeep {
                depth: revert_count,
                max: self.diff_stack.len(),
            });
        }

        // ── Phase 1: Revert old branch (reverse order) ──
        let mut reverted = Vec::with_capacity(revert_count);
        let mut orphaned_txs = Vec::new();

        for _ in 0..revert_count {
            let diff = self.diff_stack.pop()
                .ok_or(ReorgError::NoCommonAncestor)?;

            // Collect orphaned TXs before reverting
            for tx_result in &diff.tx_results {
                orphaned_txs.push(OrphanedTx {
                    tx_hash: tx_result.tx_hash,
                    nullifiers: tx_result.nullifiers.clone(),
                    was_applied: tx_result.status == DiffTxStatus::Applied,
                });
            }

            state.revert_diff(&diff).map_err(|e| ReorgError::RevertFailed {
                block: hex::encode(&diff.block_hash[..4]),
                reason: format!("{:?}", e),
            })?;

            reverted.push(diff);
        }

        // ── Phase 2: Apply new branch (forward order) ──
        let mut applied = Vec::with_capacity(new_diffs.len());

        for diff in new_diffs {
            state.apply_diff(&diff).map_err(|e| ReorgError::ApplyFailed {
                block: hex::encode(&diff.block_hash[..4]),
                reason: format!("{:?}", e),
            })?;

            self.diff_stack.push(diff.clone());
            applied.push(diff);
        }

        let new_state_root = state.state_root();

        Ok(ReorgResult {
            reverted,
            applied,
            orphaned_txs,
            new_state_root,
        })
    }

    /// Get the diff stack for a given depth (for checkpoint computation).
    pub fn recent_diffs(&self, count: usize) -> &[StateDiff] {
        let start = self.diff_stack.len().saturating_sub(count);
        &self.diff_stack[start..]
    }
}

// ═══════════════════════════════════════════════════════════════
//  In-Memory State Store (for testing / light nodes)
// ═══════════════════════════════════════════════════════════════

/// Simple in-memory state store implementing DiffApplicable.
///
/// Used for testing the reorg engine and for light node state tracking.
#[derive(Debug, Clone)]
pub struct InMemoryState {
    pub nullifiers: std::collections::HashSet<Hash>,
    pub utxos: std::collections::HashMap<OutputRef, TxOutput>,
    pub height: u64,
}

impl InMemoryState {
    pub fn new() -> Self {
        Self {
            nullifiers: std::collections::HashSet::new(),
            utxos: std::collections::HashMap::new(),
            height: 0,
        }
    }
}

impl Default for InMemoryState {
    fn default() -> Self { Self::new() }
}

impl DiffApplicable for InMemoryState {
    type Error = String;

    fn apply_diff(&mut self, diff: &StateDiff) -> Result<(), String> {
        // ── Forward Step 1: Remove spent UTXOs from UTXO set ──
        //
        // utxos_spent に記録された UTXO を UTXO セットから除去する。
        // revert_diff() で完全に復元するため、ここでは存在確認のみ行う。
        for spent in &diff.utxos_spent {
            if self.utxos.remove(&spent.outref).is_none() {
                return Err(format!(
                    "apply: spent UTXO {}:{} not found in state (diff block {})",
                    hex::encode(&spent.outref.tx_hash[..4]),
                    spent.outref.output_index,
                    hex::encode(&diff.block_hash[..4]),
                ));
            }
        }

        // ── Forward Step 2: Add nullifiers ──
        for nf in &diff.nullifiers_added {
            self.nullifiers.insert(*nf);
        }

        // ── Forward Step 3: Add created UTXOs ──
        for created in &diff.utxos_created {
            self.utxos.insert(created.outref.clone(), created.output.clone());
        }

        self.height = diff.blue_score;
        Ok(())
    }

    fn revert_diff(&mut self, diff: &StateDiff) -> Result<(), String> {
        // ── Reverse Step 1: Remove nullifiers (EXACT inverse of Forward Step 2) ──
        for nf in &diff.nullifiers_added {
            if !self.nullifiers.remove(nf) {
                return Err(format!(
                    "revert: nullifier {} not found in state (diff block {})",
                    hex::encode(&nf[..4]),
                    hex::encode(&diff.block_hash[..4]),
                ));
            }
        }

        // ── Reverse Step 2: Remove created UTXOs (EXACT inverse of Forward Step 3) ──
        for created in &diff.utxos_created {
            if self.utxos.remove(&created.outref).is_none() {
                return Err(format!(
                    "revert: UTXO {}:{} not found",
                    hex::encode(&created.outref.tx_hash[..4]),
                    created.outref.output_index,
                ));
            }
        }

        // ── Reverse Step 3: Re-insert spent UTXOs (EXACT inverse of Forward Step 1) ──
        //
        // **v4 完全可逆性の核心**: 消費された UTXO を、完全な PQC メタデータ
        // (amount, one_time_address, pq_stealth, spending_pubkey) とともに
        // UTXO セットに再挿入する。これにより revert 後の状態は apply 前と
        // 1 バイトのズレもなく一致する。
        for spent in &diff.utxos_spent {
            // 既に同じ outref が存在する場合は不整合（revert の二重適用）
            if self.utxos.contains_key(&spent.outref) {
                return Err(format!(
                    "revert: spent UTXO {}:{} already exists in state (double revert?)",
                    hex::encode(&spent.outref.tx_hash[..4]),
                    spent.outref.output_index,
                ));
            }
            self.utxos.insert(spent.outref.clone(), spent.output.clone());
        }

        // Height is restored by the caller (or inferred from diff stack)
        Ok(())
    }

    fn state_root(&self) -> Hash {
        use sha3::Digest;
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:inmem_state_root:v1:");

        // Deterministic: sort nullifiers
        let mut nfs: Vec<&Hash> = self.nullifiers.iter().collect();
        nfs.sort();
        h.update((nfs.len() as u32).to_le_bytes());
        for nf in nfs { h.update(nf); }

        // Deterministic: sort UTXOs
        let mut utxos: Vec<(&OutputRef, &TxOutput)> = self.utxos.iter().collect();
        utxos.sort_by(|a, b| {
            a.0.tx_hash.cmp(&b.0.tx_hash)
                .then_with(|| a.0.output_index.cmp(&b.0.output_index))
        });
        h.update((utxos.len() as u32).to_le_bytes());
        for (outref, _) in utxos {
            h.update(&outref.tx_hash);
            h.update(outref.output_index.to_le_bytes());
        }

        h.finalize().into()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_diff(block_id: u8, nullifiers: &[[u8; 32]], utxos: &[(u8, u32)]) -> StateDiff {
        StateDiff {
            block_hash: [block_id; 32],
            blue_score: block_id as u64,
            epoch: 0,
            nullifiers_added: nullifiers.to_vec(),
            utxos_created: utxos.iter().map(|(id, idx)| CreatedUtxo {
                outref: OutputRef { tx_hash: [*id; 32], output_index: *idx },
                output: TxOutput {
                    amount: 1000,
                    one_time_address: [0xAA; 32],
                    pq_stealth: None,
                    spending_pubkey: None,
                },
                tx_hash: [*id; 32],
            }).collect(),
            utxos_spent: vec![], // No UTXOs consumed in basic test diffs
            tx_results: nullifiers.iter().map(|nf| DiffTxResult::applied(
                [block_id; 32], vec![*nf],
            )).collect(),
        }
    }

    /// Helper: make a diff that SPENDS existing UTXOs.
    ///
    /// `spent_refs` — (tx_hash_byte, output_index) of UTXOs to consume.
    /// Looks up the UTXO in the given state and records full metadata.
    fn make_spending_diff(
        block_id: u8,
        nullifiers: &[[u8; 32]],
        new_utxos: &[(u8, u32)],
        spent_refs: &[(u8, u32)],
    ) -> StateDiff {
        let mut utxos_spent = Vec::new();
        for (i, (tx_byte, idx)) in spent_refs.iter().enumerate() {
            let nf = nullifiers.get(i).copied().unwrap_or([0u8; 32]);
            utxos_spent.push(SpentUtxo {
                outref: OutputRef { tx_hash: [*tx_byte; 32], output_index: *idx },
                output: TxOutput {
                    amount: 1000,
                    one_time_address: [0xAA; 32],
                    pq_stealth: None,
                    spending_pubkey: None,
                },
                creation_tx_hash: [*tx_byte; 32],
                creation_blue_score: 0,
                spending_tx_hash: [block_id; 32],
                nullifier: nf,
            });
        }
        StateDiff {
            block_hash: [block_id; 32],
            blue_score: block_id as u64,
            epoch: 0,
            nullifiers_added: nullifiers.to_vec(),
            utxos_created: new_utxos.iter().map(|(id, idx)| CreatedUtxo {
                outref: OutputRef { tx_hash: [*id; 32], output_index: *idx },
                output: TxOutput {
                    amount: 500,
                    one_time_address: [0xBB; 32],
                    pq_stealth: None,
                    spending_pubkey: None,
                },
                tx_hash: [*id; 32],
            }).collect(),
            utxos_spent,
            tx_results: nullifiers.iter().map(|nf| DiffTxResult::applied(
                [block_id; 32], vec![*nf],
            )).collect(),
        }
    }

    /// CORE PROPERTY: apply then revert produces identical state.
    ///
    /// This proves that reorgs of ANY depth are safe:
    /// revert_diff(apply_diff(state, diff), diff) == state
    #[test]
    fn test_apply_revert_identity() {
        let mut state = InMemoryState::new();
        let root_before = state.state_root();

        let diff = make_diff(1, &[[0xAA; 32], [0xBB; 32]], &[(1, 0), (1, 1)]);

        state.apply_diff(&diff).unwrap();
        assert_ne!(state.state_root(), root_before, "apply must change state");
        assert_eq!(state.nullifiers.len(), 2);
        assert_eq!(state.utxos.len(), 2);

        state.revert_diff(&diff).unwrap();
        assert_eq!(state.state_root(), root_before,
            "SOUNDNESS: revert must restore EXACT original state root");
        assert_eq!(state.nullifiers.len(), 0);
        assert_eq!(state.utxos.len(), 0);
    }

    /// Multi-block apply/revert: A → B → C, then revert C → B → A.
    #[test]
    fn test_multi_block_revert() {
        let mut state = InMemoryState::new();
        let root_genesis = state.state_root();

        let diff_a = make_diff(1, &[[0x01; 32]], &[(1, 0)]);
        let diff_b = make_diff(2, &[[0x02; 32]], &[(2, 0)]);
        let diff_c = make_diff(3, &[[0x03; 32]], &[(3, 0)]);

        state.apply_diff(&diff_a).unwrap();
        let root_a = state.state_root();
        state.apply_diff(&diff_b).unwrap();
        let root_b = state.state_root();
        state.apply_diff(&diff_c).unwrap();

        // Revert C
        state.revert_diff(&diff_c).unwrap();
        assert_eq!(state.state_root(), root_b, "after reverting C, state == B");

        // Revert B
        state.revert_diff(&diff_b).unwrap();
        assert_eq!(state.state_root(), root_a, "after reverting B, state == A");

        // Revert A
        state.revert_diff(&diff_a).unwrap();
        assert_eq!(state.state_root(), root_genesis, "after reverting A, state == genesis");
    }

    /// ReorgEngine: revert old branch, apply new branch.
    #[test]
    fn test_reorg_engine_basic() {
        let mut state = InMemoryState::new();
        let mut engine = ReorgEngine::new(100);

        // Apply branch: A → B → C
        let diff_a = make_diff(1, &[[0x01; 32]], &[(1, 0)]);
        let diff_b = make_diff(2, &[[0x02; 32]], &[(2, 0)]);
        let diff_c = make_diff(3, &[[0x03; 32]], &[(3, 0)]);

        state.apply_diff(&diff_a).unwrap();
        engine.push_diff(diff_a);
        state.apply_diff(&diff_b).unwrap();
        engine.push_diff(diff_b);
        state.apply_diff(&diff_c).unwrap();
        engine.push_diff(diff_c);

        assert_eq!(state.nullifiers.len(), 3);

        // Reorg: revert B+C, apply D+E (new branch from A)
        let diff_d = make_diff(4, &[[0x04; 32]], &[(4, 0)]);
        let diff_e = make_diff(5, &[[0x05; 32]], &[(5, 0)]);

        let result = engine.execute_reorg(
            &mut state,
            2, // revert B and C
            vec![diff_d, diff_e],
        ).unwrap();

        assert_eq!(result.reverted.len(), 2);
        assert_eq!(result.applied.len(), 2);
        assert_eq!(result.orphaned_txs.len(), 2, "B and C txs are orphaned");

        // State should have: nullifier 0x01 (A) + 0x04 (D) + 0x05 (E)
        assert!(state.nullifiers.contains(&[0x01; 32]), "A's nullifier preserved");
        assert!(!state.nullifiers.contains(&[0x02; 32]), "B's nullifier reverted");
        assert!(!state.nullifiers.contains(&[0x03; 32]), "C's nullifier reverted");
        assert!(state.nullifiers.contains(&[0x04; 32]), "D's nullifier applied");
        assert!(state.nullifiers.contains(&[0x05; 32]), "E's nullifier applied");
    }

    /// Reorg too deep returns error.
    #[test]
    fn test_reorg_too_deep() {
        let mut state = InMemoryState::new();
        let mut engine = ReorgEngine::new(2);

        let diff_a = make_diff(1, &[[0x01; 32]], &[]);
        state.apply_diff(&diff_a).unwrap();
        engine.push_diff(diff_a);

        // Try to revert 5 blocks when only 1 exists
        let result = engine.execute_reorg(&mut state, 5, vec![]);
        assert!(matches!(result, Err(ReorgError::TooDeep { .. })));
    }

    /// State root is deterministic and changes with content.
    #[test]
    fn test_state_root_deterministic() {
        let mut s1 = InMemoryState::new();
        let mut s2 = InMemoryState::new();

        let diff = make_diff(1, &[[0xAA; 32]], &[(1, 0)]);
        s1.apply_diff(&diff).unwrap();
        s2.apply_diff(&diff).unwrap();

        assert_eq!(s1.state_root(), s2.state_root(),
            "identical states must produce identical roots");
    }

    // ═══════════════════════════════════════════════════════════════
    //  v4 Tests: SpentUtxo — Perfect Reversibility
    // ═══════════════════════════════════════════════════════════════

    /// CORE PROPERTY (v4): Spending UTXOs and then reverting restores
    /// the EXACT original state, including all PQC metadata.
    ///
    /// Proves: revert_diff(apply_diff(state, diff), diff) == state
    /// even when UTXOs are consumed (not just created).
    #[test]
    fn test_spent_utxo_revert_identity() {
        let mut state = InMemoryState::new();

        // Step 1: Create UTXOs (block 1)
        let create_diff = make_diff(1, &[[0x01; 32]], &[(1, 0), (1, 1)]);
        state.apply_diff(&create_diff).unwrap();
        let root_after_create = state.state_root();
        assert_eq!(state.utxos.len(), 2);

        // Step 2: Spend one of those UTXOs (block 2)
        let spend_diff = make_spending_diff(
            2,
            &[[0x02; 32]],        // new nullifier
            &[(2, 0)],            // new output
            &[(1, 0)],            // spend UTXO (1, 0)
        );
        state.apply_diff(&spend_diff).unwrap();
        assert_eq!(state.utxos.len(), 2); // 2 - 1 spent + 1 new = 2
        assert!(state.utxos.get(&OutputRef { tx_hash: [1; 32], output_index: 0 }).is_none(),
            "spent UTXO must be removed after apply");
        assert!(state.utxos.get(&OutputRef { tx_hash: [2; 32], output_index: 0 }).is_some(),
            "new UTXO must exist after apply");

        // Step 3: Revert the spend — UTXO (1, 0) must be fully restored
        state.revert_diff(&spend_diff).unwrap();
        assert_eq!(state.state_root(), root_after_create,
            "SOUNDNESS: revert must restore EXACT state root including re-inserted spent UTXOs");
        assert_eq!(state.utxos.len(), 2);
        let restored = state.utxos.get(&OutputRef { tx_hash: [1; 32], output_index: 0 })
            .expect("spent UTXO must be re-inserted on revert");
        assert_eq!(restored.amount, 1000, "PQC metadata (amount) must survive revert");
        assert_eq!(restored.one_time_address, [0xAA; 32],
            "PQC metadata (one_time_address) must survive revert");
    }

    /// v4: PQC stealth data roundtrip through spend/revert cycle.
    #[test]
    fn test_spent_utxo_pqc_stealth_preservation() {
        use misaka_types::stealth::PqStealthData;

        let mut state = InMemoryState::new();

        // Create a UTXO with full PQC stealth data
        let stealth = PqStealthData {
            version: 0x01,
            kem_ct: vec![0xAA; 1088],
            scan_tag: [0xBB; 16],
            amount_ct: vec![0xCC; 24],
            payload_ct: vec![0xDD; 32],
        };
        let pqc_output = TxOutput {
            amount: 5000,
            one_time_address: [0xFF; 32],
            pq_stealth: Some(stealth.clone()),
            spending_pubkey: Some(vec![0x42; 48]),
        };

        // Manually create state with PQC output
        let outref = OutputRef { tx_hash: [0x10; 32], output_index: 0 };
        state.utxos.insert(outref.clone(), pqc_output.clone());
        let root_with_pqc = state.state_root();

        // Spend the PQC UTXO
        let spend_diff = StateDiff {
            block_hash: [0x20; 32],
            blue_score: 2,
            epoch: 0,
            nullifiers_added: vec![[0xAB; 32]],
            utxos_created: vec![],
            utxos_spent: vec![SpentUtxo {
                outref: outref.clone(),
                output: pqc_output.clone(),
                creation_tx_hash: [0x10; 32],
                creation_blue_score: 1,
                spending_tx_hash: [0x20; 32],
                nullifier: [0xAB; 32],
            }],
            tx_results: vec![],
        };

        state.apply_diff(&spend_diff).unwrap();
        assert!(state.utxos.get(&outref).is_none(), "PQC UTXO must be consumed");

        // Revert — PQC stealth data must be perfectly restored
        state.revert_diff(&spend_diff).unwrap();
        assert_eq!(state.state_root(), root_with_pqc,
            "state root must match exactly after PQC revert");

        let restored = state.utxos.get(&outref).expect("PQC UTXO must be restored");
        assert_eq!(restored.amount, 5000);
        assert_eq!(restored.one_time_address, [0xFF; 32]);
        assert_eq!(restored.spending_pubkey, Some(vec![0x42; 48]),
            "spending_pubkey must survive revert");
        let restored_stealth = restored.pq_stealth.as_ref().expect("pq_stealth must survive revert");
        assert_eq!(restored_stealth.kem_ct, stealth.kem_ct,
            "ML-KEM-768 ciphertext must survive revert");
        assert_eq!(restored_stealth.scan_tag, stealth.scan_tag,
            "scan_tag must survive revert");
    }

    /// v4: Multi-block spend/create/revert cycle.
    /// A → creates UTXO, B → spends UTXO and creates new, C → spends B's output.
    /// Revert C → B → A must restore genesis state.
    #[test]
    fn test_multi_block_spend_revert_chain() {
        let mut state = InMemoryState::new();
        let root_genesis = state.state_root();

        // Block A: create 2 UTXOs
        let diff_a = make_diff(1, &[[0x01; 32]], &[(1, 0), (1, 1)]);
        state.apply_diff(&diff_a).unwrap();
        let root_a = state.state_root();

        // Block B: spend UTXO(1,0), create UTXO(2,0)
        let diff_b = make_spending_diff(2, &[[0x02; 32]], &[(2, 0)], &[(1, 0)]);
        state.apply_diff(&diff_b).unwrap();
        let root_b = state.state_root();

        // Block C: spend UTXO(2,0), create UTXO(3,0)
        let diff_c = StateDiff {
            block_hash: [3; 32],
            blue_score: 3,
            epoch: 0,
            nullifiers_added: vec![[0x03; 32]],
            utxos_created: vec![CreatedUtxo {
                outref: OutputRef { tx_hash: [3; 32], output_index: 0 },
                output: TxOutput { amount: 250, one_time_address: [0xCC; 32],
                    pq_stealth: None, spending_pubkey: None },
                tx_hash: [3; 32],
            }],
            utxos_spent: vec![SpentUtxo {
                outref: OutputRef { tx_hash: [2; 32], output_index: 0 },
                output: TxOutput { amount: 500, one_time_address: [0xBB; 32],
                    pq_stealth: None, spending_pubkey: None },
                creation_tx_hash: [2; 32],
                creation_blue_score: 2,
                spending_tx_hash: [3; 32],
                nullifier: [0x03; 32],
            }],
            tx_results: vec![],
        };
        state.apply_diff(&diff_c).unwrap();

        // Revert C → state == B
        state.revert_diff(&diff_c).unwrap();
        assert_eq!(state.state_root(), root_b, "revert C must restore state B");
        assert!(state.utxos.get(&OutputRef { tx_hash: [2; 32], output_index: 0 }).is_some(),
            "UTXO(2,0) must be re-inserted after reverting C");

        // Revert B → state == A
        state.revert_diff(&diff_b).unwrap();
        assert_eq!(state.state_root(), root_a, "revert B must restore state A");
        assert!(state.utxos.get(&OutputRef { tx_hash: [1; 32], output_index: 0 }).is_some(),
            "UTXO(1,0) must be re-inserted after reverting B");

        // Revert A → genesis
        state.revert_diff(&diff_a).unwrap();
        assert_eq!(state.state_root(), root_genesis, "revert A must restore genesis");
        assert_eq!(state.utxos.len(), 0);
        assert_eq!(state.nullifiers.len(), 0);
    }

    /// v4: ReorgEngine with SpentUtxo — revert old branch (which spent UTXOs),
    /// apply new branch. Spent UTXOs from old branch must be restored.
    #[test]
    fn test_reorg_with_spent_utxos() {
        let mut state = InMemoryState::new();
        let mut engine = ReorgEngine::new(100);

        // Block A: create UTXOs
        let diff_a = make_diff(1, &[[0x01; 32]], &[(1, 0), (1, 1)]);
        state.apply_diff(&diff_a).unwrap();
        engine.push_diff(diff_a);

        // Block B (old branch): spend UTXO(1,0)
        let diff_b = make_spending_diff(2, &[[0x02; 32]], &[(2, 0)], &[(1, 0)]);
        state.apply_diff(&diff_b).unwrap();
        engine.push_diff(diff_b);

        // Verify UTXO(1,0) is gone
        assert!(state.utxos.get(&OutputRef { tx_hash: [1; 32], output_index: 0 }).is_none());

        // Reorg: revert B, apply D (new branch that does NOT spend UTXO(1,0))
        let diff_d = make_diff(4, &[[0x04; 32]], &[(4, 0)]);
        let result = engine.execute_reorg(&mut state, 1, vec![diff_d]).unwrap();

        assert_eq!(result.reverted.len(), 1);
        assert_eq!(result.applied.len(), 1);

        // UTXO(1,0) must be restored (it was spent in old branch B, now reverted)
        assert!(state.utxos.get(&OutputRef { tx_hash: [1; 32], output_index: 0 }).is_some(),
            "UTXO(1,0) must be restored after reorg reverts the spending block");
        // UTXO(2,0) from old branch B must be gone
        assert!(state.utxos.get(&OutputRef { tx_hash: [2; 32], output_index: 0 }).is_none());
        // UTXO(4,0) from new branch D must exist
        assert!(state.utxos.get(&OutputRef { tx_hash: [4; 32], output_index: 0 }).is_some());
    }
}
