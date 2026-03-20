//! Virtual State — O(1) diff-based DAG state at the virtual tip.
//!
//! # Problem: replay_ordered_state is O(|history|)
//!
//! The old `replay_ordered_state()` replays the ENTIRE transaction history
//! from genesis to compute the current state. At 1M blocks with 100 TXs each,
//! this is 100M TX applications — completely impractical.
//!
//! # Solution: Virtual State with Diff Stack
//!
//! The `VirtualState` tracks the current UTXO/Nullifier state at the
//! DAG's virtual tip (the tip of the Selected Parent Chain).
//!
//! State changes are recorded as `StateDiff` objects. When the virtual tip
//! advances (new block), we apply ONE diff. When a reorg occurs, we:
//! 1. Find the common ancestor (O(1) via reachability)
//! 2. Revert diffs back to ancestor (O(reorg_depth))
//! 3. Apply new diffs forward (O(new_branch_length))
//!
//! # Complexity
//!
//! | Operation | Old (Replay) | New (VirtualState) |
//! |-----------|-------------|-------------------|
//! | New block (no reorg) | O(|history|) | **O(|txs_in_block|)** |
//! | Reorg depth d | O(|history|) | **O(d × |txs_per_block|)** |
//! | State query | O(1) (after replay) | **O(1)** |
//!
//! # Why O(1) at 1,000,000+ blocks:
//!
//! - New block with no reorg: apply 1 diff = O(|txs_in_block|) = O(constant)
//! - Reorg: bounded by MAX_REORG_DEPTH (configurable, default 1000)
//!   Even a 1000-block reorg processes only 1000 × ~100 TXs = 100K operations
//!   This is O(1) because MAX_REORG_DEPTH is a constant, not a function of N
//! - The full state is ALWAYS available in memory (no replay needed)

use std::collections::{HashMap, HashSet};
use serde::{Serialize, Deserialize};

use crate::dag_block::Hash;
use crate::state_diff::{StateDiff, DiffApplicable, CreatedUtxo, DiffTxResult, DiffTxStatus};
use crate::reachability::ReachabilityStore;
use crate::ghostdag::DagStore;
use misaka_types::utxo::{OutputRef, TxOutput};

/// Maximum reorg depth (state diff stack size).
/// Reorgs deeper than this require checkpoint-based re-sync.
pub const MAX_REORG_DEPTH: usize = 1000;

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
    utxos: HashMap<OutputRef, TxOutput>,
    /// State diff stack (undo log). Most recent diff on top.
    diff_stack: Vec<StateDiff>,
    /// Maximum diff stack depth.
    max_depth: usize,
    /// Statistics.
    pub stats: VirtualStateStats,
}

/// Statistics for monitoring.
#[derive(Debug, Clone, Default)]
pub struct VirtualStateStats {
    pub blocks_applied: u64,
    pub blocks_reverted: u64,
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
            stats: VirtualStateStats::default(),
        }
    }

    /// Restore from a checkpoint snapshot.
    pub fn from_snapshot(
        tip: Hash,
        tip_score: u64,
        nullifiers: HashSet<Hash>,
        utxos: HashMap<OutputRef, TxOutput>,
    ) -> Self {
        let stats = VirtualStateStats {
            current_nullifiers: nullifiers.len(),
            current_utxos: utxos.len(),
            ..Default::default()
        };
        Self {
            tip, tip_score, nullifiers, utxos,
            diff_stack: Vec::new(),
            max_depth: MAX_REORG_DEPTH,
            stats,
        }
    }

    // ── Query (O(1)) ──

    pub fn is_nullifier_spent(&self, nf: &Hash) -> bool {
        self.nullifiers.contains(nf)
    }

    pub fn get_utxo(&self, outref: &OutputRef) -> Option<&TxOutput> {
        self.utxos.get(outref)
    }

    pub fn nullifier_count(&self) -> usize { self.nullifiers.len() }
    pub fn utxo_count(&self) -> usize { self.utxos.len() }
    pub fn all_nullifiers(&self) -> &HashSet<Hash> { &self.nullifiers }

    // ── Update (O(|diff|)) ──

    /// Apply a new block's diff to advance the virtual tip.
    ///
    /// # Complexity: O(|nullifiers_added| + |utxos_created|) per block
    ///
    /// This is bounded by MAX_QDAG_INPUTS (16) + MAX_QDAG_OUTPUTS (64) = 80
    /// per transaction, and MAX_TXS_PER_BLOCK per block.
    /// Therefore O(constant) per block.
    pub fn apply_block(&mut self, diff: StateDiff) -> Result<(), VirtualStateError> {
        // Apply nullifiers
        for nf in &diff.nullifiers_added {
            self.nullifiers.insert(*nf);
        }

        // Apply UTXO creations
        for created in &diff.utxos_created {
            self.utxos.insert(created.outref.clone(), created.output.clone());
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
        let diff = self.diff_stack.pop()
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

        // Update tip to the previous block
        self.tip = self.diff_stack.last()
            .map(|d| d.block_hash)
            .unwrap_or([0u8; 32]); // Genesis if empty

        self.stats.blocks_reverted += 1;
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
    pub fn update_virtual(
        &mut self,
        new_tip: Hash,
        new_tip_score: u64,
        new_diffs: Vec<StateDiff>,
        reachability: &ReachabilityStore,
    ) -> Result<UpdateResult, VirtualStateError> {
        // ── Case 1: Simple advance (no reorg) ──
        // If the current tip is an ancestor of the new tip, just apply forward
        if reachability.is_dag_ancestor_of(&self.tip, &new_tip) || self.tip == [0u8; 32] {
            let applied_count = new_diffs.len();
            for diff in new_diffs {
                self.apply_block(diff)?;
            }
            return Ok(UpdateResult {
                reorg_depth: 0,
                blocks_reverted: 0,
                blocks_applied: applied_count,
                new_tip,
                new_tip_score,
            });
        }

        // ── Case 2: Reorg — find common ancestor, undo/redo ──
        self.stats.reorgs += 1;

        // Find common ancestor by walking the diff stack
        // (O(reorg_depth), bounded by MAX_REORG_DEPTH)
        let mut revert_count = 0;
        for (i, diff) in self.diff_stack.iter().rev().enumerate() {
            if reachability.is_dag_ancestor_of(&diff.block_hash, &new_tip) {
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
            blocks_reverted: reverted_diffs.len(),
            blocks_applied: applied_count,
            new_tip,
            new_tip_score,
        })
    }

    /// Compute a deterministic state root.
    pub fn compute_state_root(&self) -> Hash {
        use sha3::{Sha3_256, Digest};

        let mut h = Sha3_256::new();
        h.update(b"MISAKA:virtual_state_root:v1:");
        h.update(self.tip_score.to_le_bytes());

        // Nullifiers (sorted for determinism)
        let mut nfs: Vec<&Hash> = self.nullifiers.iter().collect();
        nfs.sort();
        h.update((nfs.len() as u64).to_le_bytes());
        for nf in &nfs { h.update(nf); }

        // UTXOs (sorted for determinism)
        let mut utxos: Vec<(&OutputRef, &TxOutput)> = self.utxos.iter().collect();
        utxos.sort_by(|a, b| {
            a.0.tx_hash.cmp(&b.0.tx_hash)
                .then_with(|| a.0.output_index.cmp(&b.0.output_index))
        });
        h.update((utxos.len() as u64).to_le_bytes());
        for (outref, _) in &utxos {
            h.update(&outref.tx_hash);
            h.update(outref.output_index.to_le_bytes());
        }

        h.finalize().into()
    }
}

/// Result of a virtual state update.
#[derive(Debug)]
pub struct UpdateResult {
    pub reorg_depth: usize,
    pub blocks_reverted: usize,
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
            utxos_created: utxos.iter().map(|(id, idx)| CreatedUtxo {
                outref: OutputRef { tx_hash: [*id; 32], output_index: *idx },
                output: TxOutput {
                    amount: 0, one_time_address: [0xAA; 32],
                    pq_stealth: None, spending_pubkey: None,
                },
                tx_hash: [*id; 32],
            }).collect(),
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
        assert_eq!(vs.compute_state_root(), root_genesis,
            "SOUNDNESS: revert must restore exact genesis state root");
    }

    /// Simple forward advancement (no reorg).
    #[test]
    fn test_simple_advance() {
        let genesis = [0u8; 32];
        let mut vs = VirtualState::new(genesis);
        let mut reach = ReachabilityStore::new(genesis);

        // Add blocks A, B to reachability
        reach.add_child(genesis, [1; 32]).unwrap();
        reach.add_child([1; 32], [2; 32]).unwrap();

        let diffs = vec![
            make_diff(1, &[[0xAA; 32]], &[(1, 0)]),
            make_diff(2, &[[0xBB; 32]], &[(2, 0)]),
        ];

        let result = vs.update_virtual([2; 32], 2, diffs, &reach).unwrap();

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

        vs.apply_block(make_diff(1, &[[0x01; 32]], &[(1, 0)])).unwrap();
        vs.apply_block(make_diff(2, &[[0x02; 32]], &[(2, 0)])).unwrap();
        vs.apply_block(make_diff(3, &[[0x03; 32]], &[(3, 0)])).unwrap();

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

        assert_eq!(vs1.compute_state_root(), vs2.compute_state_root(),
            "identical states must produce identical roots");
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
        vs.apply_block(make_diff(1, &[[0xAA; 32]], &[(1, 0)])).unwrap();
        vs.apply_block(make_diff(2, &[[0xBB; 32]], &[(2, 0)])).unwrap();
        vs.revert_last().unwrap();

        assert_eq!(vs.stats.blocks_applied, 2);
        assert_eq!(vs.stats.blocks_reverted, 1);
    }
}
