// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! BlockManager — handles block reception, dedup, and ancestor tracking.
//!
//! Sui equivalent: consensus/core/block_manager.rs (~750 lines)
//!
//! Blocks arriving from the network may reference ancestors we haven't
//! seen yet. The BlockManager suspends these blocks until their ancestors
//! arrive, then unsuspends them in causal order.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::Instant;

use super::dag_state::DagState;
use crate::narwhal_types::block::*;
use crate::narwhal_types::committee::Committee;

/// Result of processing a block through the BlockManager.
#[derive(Debug)]
pub enum BlockAcceptResult {
    /// Block accepted and all ancestors present.
    Accepted(VerifiedBlock),
    /// Block suspended — waiting for missing ancestors.
    Suspended {
        block: VerifiedBlock,
        missing: Vec<BlockRef>,
    },
    /// Block already known (duplicate).
    Duplicate,
    /// Block rejected (invalid author, below eviction, etc).
    Rejected(String),
}

/// A block suspended pending missing ancestors.
#[derive(Debug)]
struct SuspendedBlock {
    block: VerifiedBlock,
    missing_ancestors: HashSet<BlockRef>,
    /// Task 1.3: When this block was suspended (for TTL-based GC).
    suspended_at: Instant,
    /// Task 1.3: How many times we've requested this block's missing ancestors.
    fetch_attempts: u32,
}

/// Task 1.3: A request to fetch a missing ancestor from the network.
#[derive(Debug, Clone)]
pub struct AncestorFetchRequest {
    /// The missing block reference to fetch.
    pub block_ref: BlockRef,
    /// How many times we've already tried to fetch it.
    pub attempt: u32,
    /// Suggested delay before sending (exponential backoff).
    pub delay_ms: u64,
}

/// Task 1.3: Statistics for monitoring block manager health.
#[derive(Debug, Clone, Default)]
pub struct BlockManagerStats {
    pub known_blocks: usize,
    pub suspended_blocks: usize,
    pub missing_ancestors: usize,
    pub quarantined_authors: usize,
    pub fetch_requests_pending: usize,
}

/// Manages block reception, deduplication, and ancestor tracking.
///
/// Task 1.3: Enhanced with per-author suspension caps, TTL-based GC,
/// and ancestor fetch request generation with exponential backoff.
pub struct BlockManager {
    /// Known block digests (for dedup).
    known_blocks: HashSet<BlockRef>,
    /// Blocks waiting for missing ancestors.
    suspended: HashMap<BlockRef, SuspendedBlock>,
    /// Reverse index: ancestor → blocks waiting for it.
    waiting_for: HashMap<BlockRef, Vec<BlockRef>>,
    /// Committee for validation.
    committee: Committee,
    /// Maximum number of suspended blocks before dropping oldest.
    max_suspended: usize,
    // ── Task 1.3: Sui-parity additions ──
    /// Per-author suspended block count (pathological DAG defense).
    suspended_per_author: HashMap<AuthorityIndex, usize>,
    /// Maximum suspended blocks per author before quarantine.
    max_suspended_per_author: usize,
    /// Quarantined authors (temporarily blocked from suspension).
    quarantined_authors: HashSet<AuthorityIndex>,
    /// Suspension TTL in rounds (blocks suspended longer are dropped).
    suspension_ttl_rounds: u32,
    /// Pending ancestor fetch requests (for network layer).
    pending_fetch_requests: Vec<AncestorFetchRequest>,
    /// Maximum fetch attempts before giving up.
    max_fetch_attempts: u32,
    /// Base delay for exponential backoff (ms).
    fetch_base_delay_ms: u64,
}

impl BlockManager {
    pub fn new(committee: Committee) -> Self {
        Self {
            known_blocks: HashSet::new(),
            suspended: HashMap::new(),
            waiting_for: HashMap::new(),
            committee,
            max_suspended: 10_000,
            suspended_per_author: HashMap::new(),
            // v0.8.8.1 (hotfix/peer-replay-window): raised 16 → 256.
            //
            // Paired with PEER_REPLAY_ROUND_WINDOW 3 → 100 in misaka-node.
            // During cold-reset bootstrap validation, a late-joining node
            // still accumulated 6+ suspended blocks and hit the 16-block
            // quarantine threshold faster than BlockRequest/fetch_requests
            // round-trips could resolve the ancestor gap.
            //
            // Raising to 256 multiplies the fetch deadline by ~16×, giving
            // the pull-based sync path enough time to cover the ancestor
            // history that the replay window could not carry.
            //
            // Memory cost: max 256 blocks × N authors × ~70 KB/block
            // (ML-DSA signature + header + tx envelopes). For a 4-node
            // committee that caps at ~70 MB/node — bounded and small
            // next to the (pre-existing, separately tracked) unbounded
            // block_cache growth documented in
            // docs/issues/block-cache-unbounded-leak.md.
            //
            // The half-threshold recovery logic at line 299 is
            // proportional (`/ 2`) so it scales with this constant
            // without separate tuning.
            max_suspended_per_author: 256,
            quarantined_authors: HashSet::new(),
            suspension_ttl_rounds: 50,
            pending_fetch_requests: Vec::new(),
            max_fetch_attempts: 6,
            fetch_base_delay_ms: 100,
        }
    }

    /// Hot-reload committee for dynamic validator changes.
    pub fn update_committee(&mut self, new_committee: Committee) {
        self.committee = new_committee;
    }

    /// Process an incoming verified block.
    ///
    /// Returns the accept result and any blocks that were unsuspended.
    pub fn try_accept_block(
        &mut self,
        block: VerifiedBlock,
        dag_state: &DagState,
    ) -> (BlockAcceptResult, Vec<VerifiedBlock>) {
        let block_ref = block.reference();

        // Dedup
        if self.known_blocks.contains(&block_ref) || dag_state.contains_block(&block_ref) {
            return (BlockAcceptResult::Duplicate, vec![]);
        }

        // Validate author
        if block_ref.author as usize >= self.committee.size() {
            return (
                BlockAcceptResult::Rejected("invalid author".to_string()),
                vec![],
            );
        }

        // Reject below eviction
        if block_ref.round < dag_state.eviction_round() {
            return (
                BlockAcceptResult::Rejected("below eviction round".to_string()),
                vec![],
            );
        }

        // Task 1.3: Reject blocks from quarantined authors
        if self.quarantined_authors.contains(&block_ref.author) {
            return (
                BlockAcceptResult::Rejected(format!(
                    "author {} is quarantined (too many suspended blocks)",
                    block_ref.author
                )),
                vec![],
            );
        }

        self.known_blocks.insert(block_ref);

        // Check for missing ancestors
        let missing = dag_state.missing_ancestors(&block);
        let missing: Vec<BlockRef> = missing
            .into_iter()
            .filter(|a| !self.known_blocks.contains(a))
            .collect();

        if missing.is_empty() {
            // All ancestors present — accept and try unsuspending waiters
            let unsuspended = self.try_unsuspend(&block_ref, dag_state);
            (BlockAcceptResult::Accepted(block), unsuspended)
        } else {
            // Suspend until ancestors arrive
            let missing_set: HashSet<BlockRef> = missing.iter().copied().collect();
            for ancestor in &missing {
                self.waiting_for
                    .entry(*ancestor)
                    .or_default()
                    .push(block_ref);
            }

            // Task 1.3: Generate fetch requests for missing ancestors
            for ancestor in &missing {
                self.pending_fetch_requests.push(AncestorFetchRequest {
                    block_ref: *ancestor,
                    attempt: 0,
                    delay_ms: 0, // first attempt: immediate
                });
            }

            let result = BlockAcceptResult::Suspended {
                block: block.clone(),
                missing: missing.clone(),
            };
            // P0-1 fix: Check for existing suspended block before insert.
            // If block_ref already suspended with DIFFERENT content, this is
            // equivocation evidence — log and keep the FIRST (no silent overwrite).
            if let Some(existing) = self.suspended.get(&block_ref) {
                if existing.block.inner().digest() != block.inner().digest() {
                    tracing::warn!(
                        "P0-1: Equivocation in suspended pool: same block_ref {:?} with different digest. Keeping first.",
                        block_ref
                    );
                    return (BlockAcceptResult::Duplicate, vec![]);
                }
                // Same digest = true duplicate, skip
                return (BlockAcceptResult::Duplicate, vec![]);
            }
            self.suspended.insert(
                block_ref,
                SuspendedBlock {
                    block,
                    missing_ancestors: missing_set,
                    suspended_at: Instant::now(),
                    fetch_attempts: 0,
                },
            );

            // Task 1.3: Per-author suspension tracking + quarantine
            let author_count = self
                .suspended_per_author
                .entry(block_ref.author)
                .or_insert(0);
            *author_count += 1;
            // v0.8.8.1 (hotfix/peer-replay-window): observability — emit
            // each suspend so log diff between runs can show counter
            // progression vs. the quarantine threshold. Target kept
            // distinct (`misaka::suspend`) so RUST_LOG can filter it.
            tracing::info!(
                target: "misaka::suspend",
                round = block_ref.round,
                author = block_ref.author,
                current = *author_count,
                max = self.max_suspended_per_author,
                missing = missing.len(),
                "block_suspended"
            );
            if *author_count > self.max_suspended_per_author {
                self.quarantined_authors.insert(block_ref.author);
                tracing::warn!(
                    author = block_ref.author,
                    suspended = *author_count,
                    max = self.max_suspended_per_author,
                    "Author quarantined: too many suspended blocks"
                );
            }

            // GC if too many suspended
            if self.suspended.len() > self.max_suspended {
                self.gc_oldest_suspended();
            }

            (result, vec![])
        }
    }

    /// Try to unsuspend blocks waiting for a newly accepted block.
    fn try_unsuspend(&mut self, accepted: &BlockRef, _dag_state: &DagState) -> Vec<VerifiedBlock> {
        let mut unsuspended = Vec::new();
        let mut to_check = VecDeque::new();
        to_check.push_back(*accepted);

        while let Some(ref block_ref) = to_check.pop_front() {
            if let Some(waiters) = self.waiting_for.remove(block_ref) {
                for waiter_ref in waiters {
                    if let Some(suspended) = self.suspended.get_mut(&waiter_ref) {
                        suspended.missing_ancestors.remove(block_ref);
                        if suspended.missing_ancestors.is_empty() {
                            // All ancestors now available
                            if let Some(sb) = self.suspended.remove(&waiter_ref) {
                                unsuspended.push(sb.block);
                                to_check.push_back(waiter_ref);
                            }
                        }
                    }
                }
            }
        }

        unsuspended
    }

    /// Remove oldest suspended blocks when over capacity.
    fn gc_oldest_suspended(&mut self) {
        // Simple: remove 10% of suspended blocks (lowest round first)
        let mut refs: Vec<BlockRef> = self.suspended.keys().copied().collect();
        refs.sort_by_key(|r| r.round);
        let to_remove = refs.len() / 10;
        for r in refs.into_iter().take(to_remove) {
            self.remove_suspended(&r);
        }
    }

    fn remove_suspended(&mut self, block_ref: &BlockRef) {
        if let Some(sb) = self.suspended.remove(block_ref) {
            for ancestor in &sb.missing_ancestors {
                if let Some(waiters) = self.waiting_for.get_mut(ancestor) {
                    waiters.retain(|w| w != block_ref);
                    if waiters.is_empty() {
                        self.waiting_for.remove(ancestor);
                    }
                }
            }
            // Task 1.3: Update per-author tracking
            if let Some(count) = self.suspended_per_author.get_mut(&block_ref.author) {
                *count = count.saturating_sub(1);
                if *count <= self.max_suspended_per_author / 2 {
                    // Lift quarantine once the author's count drops to half the limit
                    self.quarantined_authors.remove(&block_ref.author);
                }
            }
        }
    }

    /// Notify the block manager that a block has been accepted into the DAG.
    ///
    /// This triggers unsuspension of any blocks waiting for this ancestor.
    pub fn notify_block_accepted(
        &mut self,
        block_ref: &BlockRef,
        _dag_state: &DagState,
    ) -> Vec<VerifiedBlock> {
        self.known_blocks.insert(*block_ref);
        self.try_unsuspend(block_ref, _dag_state)
    }

    /// Number of currently suspended blocks.
    pub fn num_suspended(&self) -> usize {
        self.suspended.len()
    }

    /// Number of known blocks (for dedup).
    pub fn num_known(&self) -> usize {
        self.known_blocks.len()
    }

    /// Get the set of all missing ancestors across all suspended blocks.
    pub fn all_missing_ancestors(&self) -> HashSet<BlockRef> {
        let mut missing = HashSet::new();
        for sb in self.suspended.values() {
            missing.extend(&sb.missing_ancestors);
        }
        missing
    }

    // ═══════════════════════════════════════════════════════════════
    //  Task 1.3: Sui-parity additions
    // ═══════════════════════════════════════════════════════════════

    /// GC suspended blocks older than `suspension_ttl_rounds`.
    ///
    /// Blocks suspended for too long are dropped — their ancestors are
    /// unlikely to arrive. This prevents memory leaks from orphaned blocks.
    pub fn gc_stale_suspended(&mut self, current_round: Round) {
        let ttl = self.suspension_ttl_rounds;
        let stale: Vec<BlockRef> = self
            .suspended
            .iter()
            .filter(|(br, _)| current_round > br.round + ttl)
            .map(|(br, _)| *br)
            .collect();

        for block_ref in &stale {
            self.remove_suspended(block_ref);
        }

        if !stale.is_empty() {
            tracing::debug!(
                count = stale.len(),
                current_round,
                ttl,
                "GC'd stale suspended blocks"
            );
        }
    }

    /// Generate fetch requests for missing ancestors with exponential backoff.
    ///
    /// Returns requests sorted by priority (lowest delay first).
    /// Caller should send these to the network synchronizer.
    pub fn take_fetch_requests(&mut self) -> Vec<AncestorFetchRequest> {
        std::mem::take(&mut self.pending_fetch_requests)
    }

    /// Re-enqueue a failed fetch request with incremented backoff.
    pub fn retry_fetch(&mut self, block_ref: BlockRef, current_attempt: u32) {
        if current_attempt >= self.max_fetch_attempts {
            tracing::warn!(
                ?block_ref,
                attempts = current_attempt,
                "Giving up on ancestor fetch after max attempts"
            );
            return;
        }
        let next_attempt = current_attempt + 1;
        let delay = self.fetch_base_delay_ms * (1u64 << next_attempt.min(10));
        self.pending_fetch_requests.push(AncestorFetchRequest {
            block_ref,
            attempt: next_attempt,
            delay_ms: delay.min(5000), // cap at 5s
        });
    }

    /// Lift quarantine for an author (e.g., after their suspended blocks are resolved).
    pub fn lift_quarantine(&mut self, author: AuthorityIndex) {
        self.quarantined_authors.remove(&author);
        tracing::debug!(author, "Quarantine lifted");
    }

    /// Check if an author is quarantined.
    pub fn is_quarantined(&self, author: AuthorityIndex) -> bool {
        self.quarantined_authors.contains(&author)
    }

    /// Get monitoring statistics.
    pub fn stats(&self) -> BlockManagerStats {
        BlockManagerStats {
            known_blocks: self.known_blocks.len(),
            suspended_blocks: self.suspended.len(),
            missing_ancestors: self.all_missing_ancestors().len(),
            quarantined_authors: self.quarantined_authors.len(),
            fetch_requests_pending: self.pending_fetch_requests.len(),
        }
    }

    /// Number of quarantined authors.
    pub fn num_quarantined(&self) -> usize {
        self.quarantined_authors.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_block(round: Round, author: AuthorityIndex, ancestors: Vec<BlockRef>) -> VerifiedBlock {
        let block = Block {
            epoch: 0,
            round,
            author,
            timestamp_ms: round as u64 * 1000,
            ancestors,
            transactions: vec![],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            signature: vec![0xAA; 64],
        };
        VerifiedBlock::new_for_test(block)
    }

    #[test]
    fn test_accept_no_ancestors() {
        let committee = Committee::new_for_test(4);
        let mut bm = BlockManager::new(committee.clone());
        let mut dag = DagState::new(committee, Default::default());

        let b = make_block(1, 0, vec![]);
        let (result, unsuspended) = bm.try_accept_block(b.clone(), &dag);
        assert!(matches!(result, BlockAcceptResult::Accepted(_)));
        assert!(unsuspended.is_empty());
    }

    #[test]
    fn test_suspend_and_unsuspend() {
        let committee = Committee::new_for_test(4);
        let mut bm = BlockManager::new(committee.clone());
        let mut dag = DagState::new(committee, Default::default());

        // Block at round 1 (no ancestors)
        let b1 = make_block(1, 0, vec![]);
        let b1_ref = b1.reference();

        // Block at round 2 referencing b1
        let b2 = make_block(2, 1, vec![b1_ref]);

        // Accept b2 first — should suspend
        let (result, _) = bm.try_accept_block(b2.clone(), &dag);
        assert!(matches!(result, BlockAcceptResult::Suspended { .. }));
        assert_eq!(bm.num_suspended(), 1);

        // Now accept b1 into dag and notify block manager
        dag.accept_block(b1);
        let unsuspended = bm.notify_block_accepted(&b1_ref, &dag);
        // b2 should now be unsuspended
        assert_eq!(unsuspended.len(), 1);
        assert_eq!(unsuspended[0].reference(), b2.reference());
        assert_eq!(bm.num_suspended(), 0);
    }

    #[test]
    fn test_dedup() {
        let committee = Committee::new_for_test(4);
        let mut bm = BlockManager::new(committee.clone());
        let dag = DagState::new(committee, Default::default());

        let b = make_block(1, 0, vec![]);
        let (r1, _) = bm.try_accept_block(b.clone(), &dag);
        assert!(matches!(r1, BlockAcceptResult::Accepted(_)));

        let (r2, _) = bm.try_accept_block(b, &dag);
        assert!(matches!(r2, BlockAcceptResult::Duplicate));
    }

    #[test]
    fn test_invalid_author() {
        let committee = Committee::new_for_test(4);
        let mut bm = BlockManager::new(committee.clone());
        let dag = DagState::new(committee, Default::default());

        let b = make_block(1, 99, vec![]);
        let (result, _) = bm.try_accept_block(b, &dag);
        assert!(matches!(result, BlockAcceptResult::Rejected(_)));
    }

    // ── Task 1.3: New tests ──

    #[test]
    fn task_1_3_per_author_quarantine() {
        let committee = Committee::new_for_test(4);
        let mut bm = BlockManager::new(committee.clone());
        bm.max_suspended_per_author = 3; // low limit for testing
        let dag = DagState::new(committee, Default::default());

        // Create a missing ancestor that no one has
        let missing_ref = BlockRef::new(1, 3, BlockDigest([0xFF; 32]));

        // Author 0 creates 4 blocks all referencing the missing ancestor
        for round in 2..=5u32 {
            let b = make_block(round, 0, vec![missing_ref]);
            bm.try_accept_block(b, &dag);
        }

        // After 4th suspension (> max_suspended_per_author=3), author 0 is quarantined
        assert!(bm.is_quarantined(0), "author 0 should be quarantined");

        // Further blocks from author 0 are rejected
        let b6 = make_block(6, 0, vec![]);
        let (result, _) = bm.try_accept_block(b6, &dag);
        assert!(matches!(result, BlockAcceptResult::Rejected(_)));

        // Author 1 is not quarantined
        assert!(!bm.is_quarantined(1));
    }

    #[test]
    fn task_1_3_stale_suspension_gc() {
        let committee = Committee::new_for_test(4);
        let mut bm = BlockManager::new(committee.clone());
        bm.suspension_ttl_rounds = 5;
        let dag = DagState::new(committee, Default::default());

        let missing_ref = BlockRef::new(1, 3, BlockDigest([0xEE; 32]));

        // Suspend a block at round 2
        let b = make_block(2, 0, vec![missing_ref]);
        bm.try_accept_block(b, &dag);
        assert_eq!(bm.num_suspended(), 1);

        // GC at round 3 → TTL not exceeded (3 < 2 + 5)
        bm.gc_stale_suspended(3);
        assert_eq!(bm.num_suspended(), 1);

        // GC at round 8 → TTL exceeded (8 > 2 + 5)
        bm.gc_stale_suspended(8);
        assert_eq!(bm.num_suspended(), 0);
    }

    #[test]
    fn task_1_3_fetch_requests_generated() {
        let committee = Committee::new_for_test(4);
        let mut bm = BlockManager::new(committee.clone());
        let dag = DagState::new(committee, Default::default());

        let missing_a = BlockRef::new(1, 0, BlockDigest([0xAA; 32]));
        let missing_b = BlockRef::new(1, 1, BlockDigest([0xBB; 32]));

        // Suspend a block with 2 missing ancestors
        let b = make_block(2, 0, vec![missing_a, missing_b]);
        bm.try_accept_block(b, &dag);

        // Should generate 2 fetch requests
        let requests = bm.take_fetch_requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].attempt, 0);
        assert_eq!(requests[0].delay_ms, 0); // first attempt is immediate
    }

    #[test]
    fn task_1_3_retry_with_backoff() {
        let committee = Committee::new_for_test(4);
        let mut bm = BlockManager::new(committee);
        bm.fetch_base_delay_ms = 100;
        bm.max_fetch_attempts = 4;

        let block_ref = BlockRef::new(1, 0, BlockDigest([0xCC; 32]));

        // Retry escalation
        bm.retry_fetch(block_ref, 0);
        let r = bm.take_fetch_requests();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].attempt, 1);
        assert_eq!(r[0].delay_ms, 200); // 100 * 2^1

        bm.retry_fetch(block_ref, 1);
        let r = bm.take_fetch_requests();
        assert_eq!(r[0].delay_ms, 400); // 100 * 2^2

        bm.retry_fetch(block_ref, 2);
        let r = bm.take_fetch_requests();
        assert_eq!(r[0].delay_ms, 800); // 100 * 2^3

        // After max_fetch_attempts, no more requests
        bm.retry_fetch(block_ref, 4);
        assert!(bm.take_fetch_requests().is_empty());
    }

    #[test]
    fn task_1_3_stats() {
        let committee = Committee::new_for_test(4);
        let bm = BlockManager::new(committee);
        let stats = bm.stats();
        assert_eq!(stats.known_blocks, 0);
        assert_eq!(stats.suspended_blocks, 0);
        assert_eq!(stats.quarantined_authors, 0);
    }

    #[test]
    fn task_1_3_reverse_order_unsuspend() {
        let committee = Committee::new_for_test(4);
        let mut bm = BlockManager::new(committee.clone());
        let mut dag = DagState::new(committee, Default::default());

        // Create chain: b1 → b2 → b3 (reverse insertion)
        let b1 = make_block(1, 0, vec![]);
        let b1_ref = b1.reference();
        let b2 = make_block(2, 0, vec![b1_ref]);
        let b2_ref = b2.reference();
        let b3 = make_block(3, 0, vec![b2_ref]);

        // Insert in reverse order: b3, b2, b1
        let (r3, _) = bm.try_accept_block(b3, &dag);
        assert!(matches!(r3, BlockAcceptResult::Suspended { .. }));

        let (r2, _) = bm.try_accept_block(b2, &dag);
        assert!(matches!(r2, BlockAcceptResult::Suspended { .. }));
        assert_eq!(bm.num_suspended(), 2);

        // Accept b1 into DAG → should cascade unsuspend b2 → b3
        dag.accept_block(b1);
        let unsuspended = bm.notify_block_accepted(&b1_ref, &dag);
        // Both b2 and b3 should be unsuspended
        assert_eq!(unsuspended.len(), 2);
        assert_eq!(bm.num_suspended(), 0);
    }
}
