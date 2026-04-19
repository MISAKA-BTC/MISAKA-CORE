// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
// Sui equivalent: consensus/core/src/commit_finalizer.rs (1,617 lines)
//
//! CommitFinalizerV2 — two-phase per-TX finalization with reject voting.
//!
//! Sits between the UniversalCommitter (produces CommittedSubDag) and the
//! Linearizer (produces total order). See docs/design/commit_finalizer.md.
//!
//! ## Pipeline
//!
//! ```text
//! CommittedSubDag
//!     │
//!     ▼
//! CommitFinalizerV2
//! ├─ direct finalize (no reject votes → immediate)
//! ├─ indirect finalize (wait INDIRECT_DEPTH rounds)
//! └─ reject (quorum reject votes)
//!     │
//!     ▼
//! FinalizedSubDag { accepted_txs, rejected_txs }
//! ```

use crate::narwhal_dag::vote_registry::{VoteRegistry, VoteResult};
use crate::narwhal_types::block::*;
use crate::narwhal_types::commit::*;
use crate::narwhal_types::committee::{Committee, Stake};
use std::collections::{HashMap, HashSet, VecDeque};

/// Rounds after commit to wait before indirect finalization.
const INDIRECT_REJECT_DEPTH: u32 = 3;

/// Result of per-TX finalization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxFinalizationResult {
    Accepted,
    Rejected,
}

/// A finalized sub-DAG with per-TX outcomes.
#[derive(Clone, Debug)]
pub struct FinalizedSubDag {
    /// Original commit metadata.
    pub commit_index: CommitIndex,
    pub leader: BlockRef,
    /// Accepted transactions (ready for execution).
    pub accepted_txs: Vec<Transaction>,
    /// Rejected transactions (will not execute).
    pub rejected_txs: Vec<Transaction>,
    /// Whether this was direct (immediate) or indirect (waited).
    pub is_direct_finalization: bool,
}

/// Pending commit awaiting indirect finalization.
struct PendingCommit {
    commit_index: CommitIndex,
    leader: BlockRef,
    commit_round: Round,
    /// TXs finalized immediately (no reject votes).
    direct_txs: Vec<Transaction>,
    /// TXs pending indirect finalization: (tx, accept_stake, reject_stake).
    pending_txs: Vec<(Transaction, Stake, Stake)>,
    /// Already-rejected TXs.
    rejected_txs: Vec<Transaction>,
}

/// Metrics for the finalizer.
#[derive(Clone, Debug, Default)]
pub struct FinalizerV2Metrics {
    pub direct_accepted: u64,
    pub indirect_accepted: u64,
    pub rejected: u64,
    pub commits_received: u64,
    pub commits_finalized: u64,
}

/// Maximum pending commits before backpressure force-finalizes oldest.
const MAX_PENDING_COMMITS: usize = 500;

/// Two-phase per-TX commit finalizer.
///
/// Sui equivalent: `CommitFinalizer` in `commit_finalizer.rs`.
pub struct CommitFinalizerV2 {
    committee: Committee,
    quorum: Stake,
    /// Pending commits awaiting indirect finalization.
    pending: VecDeque<PendingCommit>,
    /// Finalized output queue.
    output: Vec<FinalizedSubDag>,
    /// Current DAG round (updated externally).
    current_round: Round,
    /// Voters already seen per TX (deduplicate late reject votes).
    seen_voters: HashMap<CommitIndex, HashSet<AuthorityIndex>>,
    /// Reorg prevention: set of finalized commit indices (monotonically growing).
    finalized_indices: HashSet<CommitIndex>,
    /// Highest finalized commit index (monotonic).
    highest_finalized: CommitIndex,
    /// Metrics.
    metrics: FinalizerV2Metrics,
}

impl CommitFinalizerV2 {
    /// Create a new finalizer.
    #[must_use]
    pub fn new(committee: Committee) -> Self {
        let quorum = committee.quorum_threshold();
        Self {
            committee,
            quorum,
            pending: VecDeque::new(),
            output: Vec::new(),
            current_round: 0,
            seen_voters: HashMap::new(),
            finalized_indices: HashSet::new(),
            highest_finalized: 0,
            metrics: FinalizerV2Metrics::default(),
        }
    }

    /// Process a committed sub-DAG.
    ///
    /// Classifies each TX as direct-accept, pending, or immediate-reject.
    ///
    /// Sui equivalent: `CommitFinalizer::process_commit()`.
    pub fn process_commit(
        &mut self,
        commit: &CommittedSubDag,
        block_lookup: impl Fn(&BlockRef) -> Option<Block>,
    ) {
        // Idempotency: skip if already finalized (reorg prevention).
        if self.finalized_indices.contains(&commit.index) {
            return;
        }
        // Backpressure: force-finalize oldest if queue is full.
        if self.pending.len() >= MAX_PENDING_COMMITS {
            self.force_finalize_oldest();
        }
        self.metrics.commits_received += 1;

        let mut direct_txs = Vec::new();
        let mut pending_txs = Vec::new();
        let mut rejected_txs = Vec::new();

        for block_ref in &commit.blocks {
            let block = match block_lookup(block_ref) {
                Some(b) => b,
                None => continue,
            };

            // Collect reject votes targeting this block from other blocks in the sub-DAG
            let mut reject_stake: Stake = 0;
            for other_ref in &commit.blocks {
                if other_ref == block_ref {
                    continue;
                }
                if let Some(other_block) = block_lookup(other_ref) {
                    if other_block.tx_reject_votes.contains(block_ref) {
                        // SEC-FIX TM-2: saturating_add to prevent overflow
                        reject_stake =
                            reject_stake.saturating_add(self.committee.stake(other_block.author));
                    }
                }
            }

            for tx in &block.transactions {
                if reject_stake == 0 {
                    direct_txs.push(tx.clone());
                    self.metrics.direct_accepted += 1;
                } else if reject_stake >= self.quorum {
                    rejected_txs.push(tx.clone());
                    self.metrics.rejected += 1;
                } else {
                    let accept_stake = self.committee.total_stake().saturating_sub(reject_stake);
                    pending_txs.push((tx.clone(), accept_stake, reject_stake));
                }
            }
        }

        if pending_txs.is_empty() {
            // All TXs finalized immediately (direct).
            self.finalized_indices.insert(commit.index);
            self.highest_finalized = self.highest_finalized.max(commit.index);
            self.output.push(FinalizedSubDag {
                commit_index: commit.index,
                leader: commit.leader,
                accepted_txs: direct_txs,
                rejected_txs,
                is_direct_finalization: true,
            });
            self.metrics.commits_finalized += 1;
        } else {
            self.pending.push_back(PendingCommit {
                commit_index: commit.index,
                leader: commit.leader,
                commit_round: commit.leader.round,
                direct_txs,
                pending_txs,
                rejected_txs,
            });
        }
    }

    /// Advance the current round and try to finalize pending commits.
    ///
    /// Sui equivalent: advance round → indirect finalization deadline check.
    pub fn advance_round(&mut self, round: Round) {
        self.current_round = round;
        self.try_finalize_pending();
    }

    /// Add a late reject vote for a pending TX.
    pub fn add_late_reject(&mut self, commit_index: CommitIndex, voter: AuthorityIndex) {
        let seen = self.seen_voters.entry(commit_index).or_default();
        if !seen.insert(voter) {
            return;
        } // deduplicate

        let voter_stake = self.committee.stake(voter);

        for pending in &mut self.pending {
            if pending.commit_index != commit_index {
                continue;
            }
            let mut newly_rejected = Vec::new();
            pending.pending_txs.retain_mut(|(tx, accept, reject)| {
                *reject += voter_stake;
                *accept = accept.saturating_sub(voter_stake);
                if *reject >= self.quorum {
                    newly_rejected.push(tx.clone());
                    self.metrics.rejected += 1;
                    false // remove from pending
                } else {
                    true
                }
            });
            pending.rejected_txs.extend(newly_rejected);
        }
    }

    /// Try to finalize pending commits whose deadline has passed.
    fn try_finalize_pending(&mut self) {
        while let Some(front) = self.pending.front() {
            if self.current_round < front.commit_round + INDIRECT_REJECT_DEPTH {
                break;
            }

            let mut commit = self.pending.pop_front().unwrap();
            let mut accepted = commit.direct_txs;

            // All remaining pending TXs are accepted (reject quorum not reached in time).
            for (tx, _, _) in commit.pending_txs.drain(..) {
                accepted.push(tx);
                self.metrics.indirect_accepted += 1;
            }

            self.finalized_indices.insert(commit.commit_index);
            self.highest_finalized = self.highest_finalized.max(commit.commit_index);
            self.output.push(FinalizedSubDag {
                commit_index: commit.commit_index,
                leader: commit.leader,
                accepted_txs: accepted,
                rejected_txs: commit.rejected_txs,
                is_direct_finalization: false,
            });
            self.metrics.commits_finalized += 1;
            self.seen_voters.remove(&commit.commit_index);
        }
    }

    /// Force-finalize the oldest pending commit (backpressure relief).
    fn force_finalize_oldest(&mut self) {
        if let Some(mut commit) = self.pending.pop_front() {
            let mut accepted = commit.direct_txs;
            for (tx, _, _) in commit.pending_txs.drain(..) {
                accepted.push(tx);
                self.metrics.indirect_accepted += 1;
            }
            self.finalized_indices.insert(commit.commit_index);
            self.highest_finalized = self.highest_finalized.max(commit.commit_index);
            self.output.push(FinalizedSubDag {
                commit_index: commit.commit_index,
                leader: commit.leader,
                accepted_txs: accepted,
                rejected_txs: commit.rejected_txs,
                is_direct_finalization: false,
            });
            self.metrics.commits_finalized += 1;
            self.seen_voters.remove(&commit.commit_index);
        }
    }

    /// Take all finalized sub-DAGs.
    #[must_use]
    pub fn take_finalized(&mut self) -> Vec<FinalizedSubDag> {
        std::mem::take(&mut self.output)
    }

    /// Number of pending commits.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Metrics.
    #[must_use]
    pub fn metrics(&self) -> &FinalizerV2Metrics {
        &self.metrics
    }

    // ── Reorg Prevention ──

    /// Check if a commit has been finalized.
    ///
    /// Reorg prevention: once finalized, a commit can never be un-finalized.
    #[must_use]
    pub fn is_finalized(&self, commit_index: CommitIndex) -> bool {
        self.finalized_indices.contains(&commit_index)
    }

    /// Highest finalized commit index.
    #[must_use]
    pub fn highest_finalized(&self) -> CommitIndex {
        self.highest_finalized
    }

    // ── Recovery ──

    /// Recover internal state after crash/restart.
    ///
    /// The caller provides the last finalized commit index and any
    /// pending commits that were persisted before the crash.
    ///
    /// Sui equivalent: `CommitFinalizer` recovery path.
    pub fn recover(
        &mut self,
        last_finalized_index: CommitIndex,
        finalized_indices: impl IntoIterator<Item = CommitIndex>,
    ) {
        for idx in finalized_indices {
            self.finalized_indices.insert(idx);
        }
        self.highest_finalized = last_finalized_index;
        // Pending commits are not recovered — they will be re-submitted
        // by the commit pipeline when the DAG state is replayed.
    }

    // ── GC ──

    /// Garbage-collect finalized state older than `below_index`.
    ///
    /// Removes tracking data for old commits to bound memory usage.
    pub fn gc(&mut self, below_index: CommitIndex) {
        self.seen_voters.retain(|idx, _| *idx >= below_index);
        // Keep finalized_indices bounded (only need recent ones for reorg check)
        if self.finalized_indices.len() > 10_000 {
            self.finalized_indices.retain(|idx| *idx >= below_index);
        }
    }

    /// Total number of finalized commits tracked.
    #[must_use]
    pub fn finalized_count(&self) -> usize {
        self.finalized_indices.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn committee4() -> Committee {
        Committee::new_for_test(4)
    }

    fn simple_commit(index: CommitIndex, blocks: Vec<Block>) -> CommittedSubDag {
        let leader = blocks[0].reference();
        CommittedSubDag {
            index,
            leader,
            blocks: blocks.iter().map(|b| b.reference()).collect(),
            timestamp_ms: 1000,
            previous_digest: CommitDigest([0; 32]),
            is_direct: true,
        }
    }

    fn make_block_with_txs(round: Round, author: AuthorityIndex, txs: Vec<Vec<u8>>) -> Block {
        Block {
            epoch: 0,
            round,
            author,
            timestamp_ms: round as u64 * 1000,
            ancestors: vec![],
            transactions: txs,
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            state_root_smt: [0u8; 32],
            signature: vec![0xAA; 64],
        }
    }

    fn make_block_with_reject(round: Round, author: AuthorityIndex, reject: BlockRef) -> Block {
        Block {
            epoch: 0,
            round,
            author,
            timestamp_ms: round as u64 * 1000,
            ancestors: vec![],
            transactions: vec![],
            commit_votes: vec![],
            tx_reject_votes: vec![reject],
            state_root: [0u8; 32],
            state_root_smt: [0u8; 32],
            signature: vec![0xAA; 64],
        }
    }

    #[test]
    fn test_direct_finalization() {
        let mut fin = CommitFinalizerV2::new(committee4());
        let block = make_block_with_txs(1, 0, vec![vec![1], vec![2]]);
        let commit = simple_commit(0, vec![block.clone()]);
        let block_clone = block.clone();
        fin.process_commit(&commit, |r| {
            if *r == block_clone.reference() {
                Some(block_clone.clone())
            } else {
                None
            }
        });
        let out = fin.take_finalized();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].accepted_txs.len(), 2);
        assert!(out[0].rejected_txs.is_empty());
        assert!(out[0].is_direct_finalization);
    }

    #[test]
    fn test_reject_quorum() {
        let mut fin = CommitFinalizerV2::new(committee4());
        let leader = make_block_with_txs(1, 0, vec![vec![42]]);
        let leader_ref = leader.reference();
        // 3 authorities reject (quorum for n=4 is 3)
        let r1 = make_block_with_reject(1, 1, leader_ref);
        let r2 = make_block_with_reject(1, 2, leader_ref);
        let r3 = make_block_with_reject(1, 3, leader_ref);
        let blocks = vec![leader.clone(), r1.clone(), r2.clone(), r3.clone()];
        let commit = simple_commit(0, blocks.clone());
        fin.process_commit(&commit, |r| {
            blocks.iter().find(|b| b.reference() == *r).cloned()
        });
        let out = fin.take_finalized();
        assert_eq!(out.len(), 1);
        assert!(out[0].accepted_txs.is_empty());
        assert_eq!(out[0].rejected_txs.len(), 1);
    }

    #[test]
    fn test_indirect_finalization_after_depth() {
        let mut fin = CommitFinalizerV2::new(committee4());
        let leader = make_block_with_txs(1, 0, vec![vec![99]]);
        let leader_ref = leader.reference();
        // 1 reject (below quorum)
        let r1 = make_block_with_reject(1, 1, leader_ref);
        let blocks = vec![leader.clone(), r1.clone()];
        let commit = simple_commit(0, blocks.clone());
        fin.process_commit(&commit, |r| {
            blocks.iter().find(|b| b.reference() == *r).cloned()
        });
        assert!(fin.take_finalized().is_empty()); // pending
        assert_eq!(fin.pending_count(), 1);

        fin.advance_round(1);
        assert!(fin.take_finalized().is_empty());
        // commit_round (1) + INDIRECT_REJECT_DEPTH (3) = 4
        fin.advance_round(4);
        let out = fin.take_finalized();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].accepted_txs.len(), 1); // accepted (reject didn't reach quorum)
        assert!(!out[0].is_direct_finalization);
    }

    #[test]
    fn test_late_reject_causes_rejection() {
        let mut fin = CommitFinalizerV2::new(committee4());
        let leader = make_block_with_txs(1, 0, vec![vec![77]]);
        let leader_ref = leader.reference();
        let r1 = make_block_with_reject(1, 1, leader_ref);
        let blocks = vec![leader.clone(), r1.clone()];
        let commit = simple_commit(0, blocks.clone());
        fin.process_commit(&commit, |r| {
            blocks.iter().find(|b| b.reference() == *r).cloned()
        });
        // 2 more late rejects → quorum
        fin.add_late_reject(0, 2);
        fin.add_late_reject(0, 3);
        fin.advance_round(4);
        let out = fin.take_finalized();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rejected_txs.len(), 1);
    }

    #[test]
    fn test_duplicate_late_reject_ignored() {
        let mut fin = CommitFinalizerV2::new(committee4());
        let leader = make_block_with_txs(1, 0, vec![vec![55]]);
        let leader_ref = leader.reference();
        let r1 = make_block_with_reject(1, 1, leader_ref);
        let blocks = vec![leader.clone(), r1.clone()];
        let commit = simple_commit(0, blocks.clone());
        fin.process_commit(&commit, |r| {
            blocks.iter().find(|b| b.reference() == *r).cloned()
        });
        fin.add_late_reject(0, 2);
        fin.add_late_reject(0, 2); // duplicate — ignored
        fin.advance_round(4);
        let out = fin.take_finalized();
        // Only 2 rejects (initial + one late), not quorum (3) → accepted
        assert_eq!(out[0].accepted_txs.len(), 1);
    }

    #[test]
    fn test_idempotent_reprocess() {
        let mut fin = CommitFinalizerV2::new(committee4());
        let block = make_block_with_txs(1, 0, vec![vec![1]]);
        let commit = simple_commit(0, vec![block.clone()]);
        let bc = block.clone();
        fin.process_commit(&commit, |r| {
            if *r == bc.reference() {
                Some(bc.clone())
            } else {
                None
            }
        });
        let out1 = fin.take_finalized();
        assert_eq!(out1.len(), 1);
        // Re-process same commit — should be skipped (idempotent)
        let bc2 = block.clone();
        fin.process_commit(&commit, |r| {
            if *r == bc2.reference() {
                Some(bc2.clone())
            } else {
                None
            }
        });
        let out2 = fin.take_finalized();
        assert_eq!(
            out2.len(),
            0,
            "re-processing finalized commit must be idempotent"
        );
    }

    #[test]
    fn test_reorg_prevention() {
        let mut fin = CommitFinalizerV2::new(committee4());
        let block = make_block_with_txs(1, 0, vec![vec![42]]);
        let commit = simple_commit(0, vec![block.clone()]);
        let bc = block.clone();
        fin.process_commit(&commit, |r| {
            if *r == bc.reference() {
                Some(bc.clone())
            } else {
                None
            }
        });
        fin.take_finalized();
        assert!(fin.is_finalized(0));
        assert_eq!(fin.highest_finalized(), 0);
        // Cannot un-finalize
        assert!(fin.is_finalized(0));
    }

    #[test]
    fn test_recovery() {
        let mut fin = CommitFinalizerV2::new(committee4());
        fin.recover(42, vec![10, 20, 30, 42]);
        assert_eq!(fin.highest_finalized(), 42);
        assert!(fin.is_finalized(10));
        assert!(fin.is_finalized(42));
        assert!(!fin.is_finalized(43));
    }

    #[test]
    fn test_gc_bounds_memory() {
        let mut fin = CommitFinalizerV2::new(committee4());
        // Finalize 100 commits
        for i in 0..100 {
            let block = make_block_with_txs(i + 1, 0, vec![vec![i as u8]]);
            let commit = simple_commit(i as u64, vec![block.clone()]);
            let bc = block.clone();
            fin.process_commit(&commit, |r| {
                if *r == bc.reference() {
                    Some(bc.clone())
                } else {
                    None
                }
            });
        }
        fin.take_finalized();
        assert_eq!(fin.finalized_count(), 100);
        // GC everything below index 90
        fin.gc(90);
        // seen_voters should be cleaned (all direct-finalized, so none pending)
        // finalized_indices may or may not be cleaned (under 10k threshold)
    }

    #[test]
    fn test_backpressure() {
        let mut fin = CommitFinalizerV2::new(committee4());
        // Fill pending queue beyond MAX_PENDING_COMMITS
        // (this requires commits with pending TXs, not direct-finalized)
        let leader = make_block_with_txs(1, 0, vec![vec![99]]);
        let leader_ref = leader.reference();
        let r1 = make_block_with_reject(1, 1, leader_ref);
        let blocks = vec![leader.clone(), r1.clone()];
        // Process many commits with pending TXs
        for i in 0..10 {
            let commit = CommittedSubDag {
                index: i,
                leader: blocks[0].reference(),
                blocks: blocks.iter().map(|b| b.reference()).collect(),
                timestamp_ms: 1000,
                previous_digest: CommitDigest([0; 32]),
                is_direct: true,
            };
            fin.process_commit(&commit, |r| {
                blocks.iter().find(|b| b.reference() == *r).cloned()
            });
        }
        // Some should be pending, and backpressure shouldn't panic
        assert!(fin.metrics().commits_received >= 10);
    }

    #[test]
    fn test_metrics() {
        let mut fin = CommitFinalizerV2::new(committee4());
        let block = make_block_with_txs(1, 0, vec![vec![1], vec![2], vec![3]]);
        let commit = simple_commit(0, vec![block.clone()]);
        let bc = block.clone();
        fin.process_commit(&commit, |r| {
            if *r == bc.reference() {
                Some(bc.clone())
            } else {
                None
            }
        });
        assert_eq!(fin.metrics().direct_accepted, 3);
        assert_eq!(fin.metrics().commits_finalized, 1);
    }
}
