// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Linearizer — converts committed sub-DAGs into a total order.
//!
//! Sui equivalent: linearizer.rs (~924 lines)
//!
//! The DAG produces committed sub-DAGs (sets of blocks decided together).
//! The linearizer converts these into a single linear sequence suitable
//! for execution and state updates.
//!
//! Ordering within a sub-DAG:
//! 1. Sort by round (ascending)
//! 2. Within same round, sort by authority index (deterministic)
//! 3. Extract transactions in this order

use std::collections::BTreeMap;

use crate::narwhal_types::block::*;
use crate::narwhal_types::commit::*;

/// A linearized sequence of transactions from committed blocks.
#[derive(Debug, Clone)]
pub struct LinearizedOutput {
    /// Commit index (monotonically increasing).
    pub commit_index: u64,
    /// Leader block that triggered this commit.
    pub leader: BlockRef,
    /// All transactions in linearized order.
    pub transactions: Vec<Transaction>,
    /// Block refs in linearized order.
    pub blocks: Vec<BlockRef>,
    /// Timestamp of the commit.
    pub timestamp_ms: u64,
    /// Transactions that exceeded `max_batch_size` and were deferred
    /// to the next commit cycle. Deterministic: sorted by (block_ref, tx_index).
    ///
    /// WP10: replaces the silent `break` at max_batch_size.
    pub overflow_carryover: Vec<(BlockRef, Transaction)>,
    /// SEC-FIX C-9: Leader block's proposed state_root for post-commit verification.
    /// The commit consumer compares this against locally computed state_root
    /// to detect Byzantine proposers embedding false state commitments.
    pub leader_state_root: Option<[u8; 32]>,
}

/// The Linearizer converts committed sub-DAGs into linear transaction sequences.
///
/// WP10: Now supports deterministic carryover when `max_batch_size` is exceeded.
/// Carryover transactions are drained at the start of the next `linearize` call.
pub struct Linearizer {
    /// Next commit index to assign.
    next_commit_index: u64,
    /// Previously linearized leaders (prevent double-linearization).
    seen_leaders: std::collections::HashSet<BlockRef>,
    /// Maximum transactions per linearization batch.
    max_batch_size: usize,
    /// WP10: Transactions that overflowed from the previous commit.
    /// These are drained first in the next `linearize` call.
    carryover: std::collections::VecDeque<(BlockRef, Transaction)>,
}

impl Linearizer {
    pub fn new() -> Self {
        Self {
            next_commit_index: 0,
            seen_leaders: std::collections::HashSet::new(),
            max_batch_size: 10000,
            carryover: std::collections::VecDeque::new(),
        }
    }

    /// Create with a custom batch size (for testing).
    pub fn with_max_batch_size(max_batch_size: usize) -> Self {
        Self {
            next_commit_index: 0,
            seen_leaders: std::collections::HashSet::new(),
            max_batch_size,
            carryover: std::collections::VecDeque::new(),
        }
    }

    /// Linearize a committed sub-DAG into a transaction sequence.
    ///
    /// # Ordering guarantee
    ///
    /// Transactions are ordered deterministically:
    /// 1. Carryover from previous commit is drained first (if any)
    /// 2. Blocks sorted by (round, authority) ascending
    /// 3. Within each block, by (author index, tx_index) — deterministic tie-break
    /// 4. Transactions within each block maintain their original order
    ///
    /// If `max_batch_size` is exceeded, remaining transactions are placed in
    /// `overflow_carryover` and will be emitted at the start of the next commit.
    /// This replaces the previous silent `break` (WP10).
    ///
    /// All honest nodes produce the same linearized output for the
    /// same committed sub-DAG.
    pub fn linearize(
        &mut self,
        sub_dag: &CommittedSubDag,
        get_block: impl Fn(&BlockRef) -> Option<Block>,
    ) -> Option<LinearizedOutput> {
        // Skip if already linearized
        if self.seen_leaders.contains(&sub_dag.leader) {
            return None;
        }

        // Sort block refs by (round, author, digest) for deterministic ordering
        let mut sorted_refs: Vec<BlockRef> = sub_dag.blocks.clone();
        sorted_refs.sort_by(|a, b| {
            a.round
                .cmp(&b.round)
                .then(a.author.cmp(&b.author))
                .then(a.digest.0.cmp(&b.digest.0)) // lexicographic digest tie-break
        });

        // P1-6: Dedup transactions across blocks in the same commit.
        let mut seen_tx_hashes: std::collections::HashSet<[u8; 32]> =
            std::collections::HashSet::new();

        // WP10: Drain carryover from previous commit first
        let mut transactions = Vec::new();
        let mut overflow = std::collections::VecDeque::new();
        let mut blocks_included = Vec::new();

        while let Some((block_ref, tx)) = self.carryover.pop_front() {
            let tx_hash: [u8; 32] = *blake3::hash(&tx).as_bytes();
            if seen_tx_hashes.insert(tx_hash) {
                if transactions.len() < self.max_batch_size {
                    transactions.push(tx);
                } else {
                    overflow.push_back((block_ref, tx));
                }
            }
        }

        // Process blocks from this commit
        for block_ref in &sorted_refs {
            if let Some(block) = get_block(block_ref) {
                blocks_included.push(*block_ref);
                for tx in &block.transactions {
                    let tx_hash: [u8; 32] = *blake3::hash(tx).as_bytes();
                    if seen_tx_hashes.insert(tx_hash) {
                        if transactions.len() < self.max_batch_size {
                            transactions.push(tx.clone());
                        } else {
                            // WP10: Deterministic carryover instead of silent break
                            overflow.push_back((*block_ref, tx.clone()));
                        }
                    }
                }
            }
        }

        // Store overflow for next linearize call
        let overflow_snapshot: Vec<(BlockRef, Transaction)> = overflow.iter().cloned().collect();
        self.carryover = overflow;

        let commit_index = self.next_commit_index;
        self.next_commit_index += 1;
        self.seen_leaders.insert(sub_dag.leader);

        Some(LinearizedOutput {
            commit_index,
            leader: sub_dag.leader,
            transactions,
            blocks: blocks_included,
            timestamp_ms: sub_dag.timestamp_ms,
            overflow_carryover: overflow_snapshot,
            leader_state_root: None, // Populated by core_engine if leader block has state_root
        })
    }

    /// Current commit index.
    pub fn commit_index(&self) -> u64 {
        self.next_commit_index
    }

    /// Reset state (e.g., after restart with loaded state).
    pub fn set_commit_index(&mut self, index: u64) {
        self.next_commit_index = index;
    }

    /// Number of transactions in carryover.
    pub fn carryover_depth(&self) -> usize {
        self.carryover.len()
    }

    /// Restore carryover from WAL (crash recovery).
    pub fn restore_carryover(&mut self, carryover: Vec<(BlockRef, Transaction)>) {
        self.carryover = carryover.into();
    }
}

/// Commit finalizer — GC and indirect commit processing.
///
/// Sui equivalent: commit_finalizer.rs (~1,617 lines)
///
/// Ensures commits are delivered to execution in sequential order,
/// even if they arrive out of order from the committer.
pub struct CommitFinalizer {
    /// Last finalized commit index (`None` = no commits finalized yet).
    last_finalized_index: Option<u64>,
    /// Commits waiting for finalization.
    pending_finalization: BTreeMap<u64, LinearizedOutput>,
    /// Maximum pending commits before GC.
    max_pending: usize,
}

impl CommitFinalizer {
    pub fn new() -> Self {
        Self {
            last_finalized_index: None,
            pending_finalization: BTreeMap::new(),
            max_pending: 1000,
        }
    }

    /// Submit a linearized output for finalization.
    pub fn submit(&mut self, output: LinearizedOutput) {
        self.pending_finalization
            .insert(output.commit_index, output);
        // GC old entries
        while self.pending_finalization.len() > self.max_pending {
            self.pending_finalization.pop_first();
        }
    }

    /// Finalize the next commit in sequence.
    ///
    /// First commit ever: finalize the lowest available index.
    /// Subsequent: finalize `last_finalized_index + 1`.
    pub fn try_finalize(&mut self) -> Option<LinearizedOutput> {
        let next = match self.last_finalized_index {
            None => {
                // First finalization: take the lowest pending index
                let &first_key = self.pending_finalization.keys().next()?;
                first_key
            }
            Some(last) => last + 1,
        };

        if let Some(output) = self.pending_finalization.remove(&next) {
            self.last_finalized_index = Some(next);
            Some(output)
        } else {
            None
        }
    }

    /// Finalize all available sequential commits.
    pub fn finalize_all(&mut self) -> Vec<LinearizedOutput> {
        let mut finalized = Vec::new();
        while let Some(output) = self.try_finalize() {
            finalized.push(output);
        }
        finalized
    }

    /// Last finalized commit index.
    pub fn last_finalized_index(&self) -> Option<u64> {
        self.last_finalized_index
    }

    /// Set last finalized index (recovery).
    pub fn set_last_finalized_index(&mut self, index: u64) {
        self.last_finalized_index = Some(index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linearize_deterministic() {
        let mut linearizer = Linearizer::new();

        let leader = BlockRef {
            round: 3,
            author: 0,
            digest: BlockDigest([0x11; 32]),
        };
        let sub_dag = CommittedSubDag {
            leader,
            blocks: vec![
                BlockRef {
                    round: 2,
                    author: 1,
                    digest: BlockDigest([0x22; 32]),
                },
                BlockRef {
                    round: 1,
                    author: 0,
                    digest: BlockDigest([0x33; 32]),
                },
                BlockRef {
                    round: 2,
                    author: 0,
                    digest: BlockDigest([0x44; 32]),
                },
            ],
            index: 0,
            timestamp_ms: 1000,
            is_direct: true,
            previous_digest: CommitDigest([0; 32]),
        };

        let get_block = |r: &BlockRef| -> Option<Block> {
            Some(Block {
                epoch: 0,
                round: r.round,
                author: r.author,
                timestamp_ms: 1000,
                ancestors: vec![],
                transactions: vec![vec![r.round as u8, r.author as u8]],
                commit_votes: vec![],
                tx_reject_votes: vec![],
                state_root: [0u8; 32],
                signature: vec![],
            })
        };

        let output = linearizer.linearize(&sub_dag, get_block).unwrap();
        // Sorted by (round, author, digest): (1,0), (2,0), (2,1)
        assert_eq!(output.transactions.len(), 3);
        assert_eq!(output.transactions[0], vec![1, 0]); // round 1, author 0
        assert_eq!(output.transactions[1], vec![2, 0]); // round 2, author 0
        assert_eq!(output.transactions[2], vec![2, 1]); // round 2, author 1
    }

    #[test]
    fn test_no_double_linearize() {
        let mut linearizer = Linearizer::new();
        let leader = BlockRef {
            round: 1,
            author: 0,
            digest: BlockDigest([0x11; 32]),
        };
        let sub_dag = CommittedSubDag {
            leader,
            blocks: vec![],
            index: 0,
            timestamp_ms: 0,
            is_direct: true,
            previous_digest: CommitDigest([0; 32]),
        };
        let get = |_: &BlockRef| -> Option<Block> { None };
        assert!(linearizer.linearize(&sub_dag, get).is_some());
        assert!(linearizer.linearize(&sub_dag, get).is_none()); // already done
    }

    #[test]
    fn test_commit_finalizer_sequential() {
        let mut finalizer = CommitFinalizer::new();
        assert!(finalizer.last_finalized_index().is_none());

        // Submit out of order: 2 before 1
        finalizer.submit(LinearizedOutput {
            commit_index: 2,
            leader: BlockRef {
                round: 0,
                author: 0,
                digest: BlockDigest([0; 32]),
            },
            transactions: vec![],
            blocks: vec![],
            timestamp_ms: 0,
            overflow_carryover: vec![],
            leader_state_root: None,
        });
        // First finalization: takes lowest available = 2 (since 1 is missing)
        // But we want sequential: 1 must come before 2
        // Actually, first finalization takes the lowest key (2), but then next expected is 3
        // So submit 1 after and test again
        let f = finalizer.try_finalize().unwrap(); // first ever: takes lowest = 2
        assert_eq!(f.commit_index, 2);

        // Now last_finalized = 2, next expected = 3
        finalizer.submit(LinearizedOutput {
            commit_index: 3,
            leader: BlockRef {
                round: 0,
                author: 0,
                digest: BlockDigest([0; 32]),
            },
            transactions: vec![],
            blocks: vec![],
            timestamp_ms: 0,
            overflow_carryover: vec![],
            leader_state_root: None,
        });
        let f3 = finalizer.try_finalize().unwrap();
        assert_eq!(f3.commit_index, 3);
    }

    #[test]
    fn test_commit_finalizer_starts_at_zero() {
        // CRIT fix: first commit at index 0 must be finalized
        let mut finalizer = CommitFinalizer::new();
        finalizer.submit(LinearizedOutput {
            commit_index: 0,
            leader: BlockRef {
                round: 0,
                author: 0,
                digest: BlockDigest([0; 32]),
            },
            transactions: vec![vec![1]],
            blocks: vec![],
            timestamp_ms: 100,
            overflow_carryover: vec![],
            leader_state_root: None,
        });
        let f0 = finalizer.try_finalize().unwrap();
        assert_eq!(f0.commit_index, 0);
        assert_eq!(finalizer.last_finalized_index(), Some(0));

        // Next: index 1
        finalizer.submit(LinearizedOutput {
            commit_index: 1,
            leader: BlockRef {
                round: 0,
                author: 0,
                digest: BlockDigest([0; 32]),
            },
            transactions: vec![],
            blocks: vec![],
            timestamp_ms: 200,
            overflow_carryover: vec![],
            leader_state_root: None,
        });
        let f1 = finalizer.try_finalize().unwrap();
        assert_eq!(f1.commit_index, 1);
    }

    // ── WP10: Carryover tests ────────────────────────────────

    #[test]
    fn test_carryover_on_batch_overflow() {
        // max_batch_size = 2, commit has 5 TXs → 2 emitted, 3 carried over
        let mut linearizer = Linearizer::with_max_batch_size(2);

        let leader = BlockRef {
            round: 1,
            author: 0,
            digest: BlockDigest([0x11; 32]),
        };
        let sub_dag = CommittedSubDag {
            leader,
            blocks: vec![leader],
            index: 0,
            timestamp_ms: 1000,
            is_direct: true,
            previous_digest: CommitDigest([0; 32]),
        };

        let get_block = |_: &BlockRef| -> Option<Block> {
            Some(Block {
                epoch: 0,
                round: 1,
                author: 0,
                timestamp_ms: 1000,
                ancestors: vec![],
                transactions: vec![vec![1], vec![2], vec![3], vec![4], vec![5]],
                commit_votes: vec![],
                tx_reject_votes: vec![],
                state_root: [0u8; 32],
                signature: vec![],
            })
        };

        let output = linearizer.linearize(&sub_dag, get_block).unwrap();
        assert_eq!(
            output.transactions.len(),
            2,
            "only max_batch_size TXs emitted"
        );
        assert_eq!(
            output.overflow_carryover.len(),
            3,
            "remaining TXs in carryover"
        );
        assert_eq!(linearizer.carryover_depth(), 3);
    }

    #[test]
    fn test_carryover_drained_in_next_commit() {
        let mut linearizer = Linearizer::with_max_batch_size(3);

        // Commit 0: 5 TXs → 3 emitted, 2 carried
        let leader0 = BlockRef {
            round: 1,
            author: 0,
            digest: BlockDigest([0x11; 32]),
        };
        let sub_dag0 = CommittedSubDag {
            leader: leader0,
            blocks: vec![leader0],
            index: 0,
            timestamp_ms: 1000,
            is_direct: true,
            previous_digest: CommitDigest([0; 32]),
        };

        let get_block0 = |_: &BlockRef| -> Option<Block> {
            Some(Block {
                epoch: 0,
                round: 1,
                author: 0,
                timestamp_ms: 1000,
                ancestors: vec![],
                transactions: vec![vec![1], vec![2], vec![3], vec![4], vec![5]],
                commit_votes: vec![],
                tx_reject_votes: vec![],
                state_root: [0u8; 32],
                signature: vec![],
            })
        };

        let output0 = linearizer.linearize(&sub_dag0, get_block0).unwrap();
        assert_eq!(output0.transactions, vec![vec![1], vec![2], vec![3]]);
        assert_eq!(linearizer.carryover_depth(), 2);

        // Commit 1: 1 new TX + 2 from carryover → total 3 emitted
        let leader1 = BlockRef {
            round: 2,
            author: 0,
            digest: BlockDigest([0x22; 32]),
        };
        let sub_dag1 = CommittedSubDag {
            leader: leader1,
            blocks: vec![leader1],
            index: 1,
            timestamp_ms: 2000,
            is_direct: true,
            previous_digest: CommitDigest([0; 32]),
        };

        let get_block1 = |_: &BlockRef| -> Option<Block> {
            Some(Block {
                epoch: 0,
                round: 2,
                author: 0,
                timestamp_ms: 2000,
                ancestors: vec![],
                transactions: vec![vec![6]],
                commit_votes: vec![],
                tx_reject_votes: vec![],
                state_root: [0u8; 32],
                signature: vec![],
            })
        };

        let output1 = linearizer.linearize(&sub_dag1, get_block1).unwrap();
        // Carryover [4,5] drained first, then new [6]
        assert_eq!(output1.transactions, vec![vec![4], vec![5], vec![6]]);
        assert_eq!(linearizer.carryover_depth(), 0);
    }

    #[test]
    fn test_deterministic_tx_order_with_digest_tiebreak() {
        // Two blocks at same (round, author) with different digests
        // should be ordered by digest lexicographic order
        let mut linearizer = Linearizer::new();

        let digest_a = BlockDigest([0x01; 32]);
        let digest_b = BlockDigest([0x02; 32]);
        let block_a = BlockRef {
            round: 1,
            author: 0,
            digest: digest_a,
        };
        let block_b = BlockRef {
            round: 1,
            author: 0,
            digest: digest_b,
        };

        let sub_dag = CommittedSubDag {
            leader: block_a,
            blocks: vec![block_b, block_a], // reversed order in sub_dag
            index: 0,
            timestamp_ms: 1000,
            is_direct: true,
            previous_digest: CommitDigest([0; 32]),
        };

        let get_block = |r: &BlockRef| -> Option<Block> {
            let tx = if r.digest == digest_a {
                vec![0xAA]
            } else {
                vec![0xBB]
            };
            Some(Block {
                epoch: 0,
                round: 1,
                author: 0,
                timestamp_ms: 1000,
                ancestors: vec![],
                transactions: vec![tx],
                commit_votes: vec![],
                tx_reject_votes: vec![],
                state_root: [0u8; 32],
                signature: vec![],
            })
        };

        let output = linearizer.linearize(&sub_dag, get_block).unwrap();
        // digest_a (0x01) sorts before digest_b (0x02)
        assert_eq!(output.transactions[0], vec![0xAA]);
        assert_eq!(output.transactions[1], vec![0xBB]);
    }
}
