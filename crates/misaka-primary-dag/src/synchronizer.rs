//! Synchronizer — tracks missing ancestors and coordinates data recovery.
//!
//! When accept_block() rejects a block due to MissingAncestor,
//! the Synchronizer queues the block and the missing ancestor for later.
//! When the missing ancestor arrives (via pull from peers), the
//! queued block is re-attempted.

use misaka_dag_types::block::*;
use std::collections::{HashMap, HashSet, VecDeque};

/// A block waiting for missing ancestors.
#[derive(Clone, Debug)]
pub struct PendingBlock {
    pub block: Block,
    pub missing_ancestors: HashSet<BlockRef>,
    pub received_at: std::time::Instant,
}

/// Request to fetch a missing block from peers.
#[derive(Clone, Debug)]
pub struct SyncRequest {
    pub block_ref: BlockRef,
    pub requested_at: std::time::Instant,
    pub retry_count: u32,
}

/// Synchronizer manages missing data recovery.
pub struct Synchronizer {
    /// Blocks waiting for their ancestors to arrive.
    pending: HashMap<BlockRef, PendingBlock>,
    /// Ancestors we need to fetch (queued for network request).
    fetch_queue: VecDeque<SyncRequest>,
    /// Already-requested refs (prevent duplicate requests).
    requested: HashSet<BlockRef>,
    /// Maximum pending blocks before we start dropping oldest.
    max_pending: usize,
    /// Maximum age for pending blocks (seconds).
    max_pending_age_secs: u64,
}

impl Synchronizer {
    pub fn new(max_pending: usize, max_pending_age_secs: u64) -> Self {
        Self {
            pending: HashMap::new(),
            fetch_queue: VecDeque::new(),
            requested: HashSet::new(),
            max_pending,
            max_pending_age_secs,
        }
    }

    /// Queue a block that was rejected due to missing ancestors.
    pub fn queue_pending(&mut self, block: Block, missing: Vec<BlockRef>) {
        let block_ref = block.reference();

        // Evict oldest if at capacity
        if self.pending.len() >= self.max_pending {
            self.evict_oldest();
        }

        let missing_set: HashSet<BlockRef> = missing.iter().copied().collect();

        // Queue fetch requests for missing ancestors
        for ancestor_ref in &missing_set {
            if !self.requested.contains(ancestor_ref) {
                self.fetch_queue.push_back(SyncRequest {
                    block_ref: *ancestor_ref,
                    requested_at: std::time::Instant::now(),
                    retry_count: 0,
                });
                self.requested.insert(*ancestor_ref);
            }
        }

        self.pending.insert(block_ref, PendingBlock {
            block,
            missing_ancestors: missing_set,
            received_at: std::time::Instant::now(),
        });
    }

    /// Notify that a previously missing block has arrived.
    /// Returns blocks that are now ready to be re-processed.
    pub fn resolve(&mut self, arrived_ref: &BlockRef) -> Vec<Block> {
        self.requested.remove(arrived_ref);

        let mut ready = Vec::new();
        let mut resolved_keys = Vec::new();

        for (key, pending) in &mut self.pending {
            pending.missing_ancestors.remove(arrived_ref);
            if pending.missing_ancestors.is_empty() {
                resolved_keys.push(*key);
            }
        }

        for key in resolved_keys {
            if let Some(pending) = self.pending.remove(&key) {
                ready.push(pending.block);
            }
        }

        ready
    }

    /// Get the next fetch request (for the network layer to process).
    pub fn next_fetch_request(&mut self) -> Option<SyncRequest> {
        self.fetch_queue.pop_front()
    }

    /// Prune expired pending blocks.
    pub fn prune_expired(&mut self) {
        let cutoff = std::time::Duration::from_secs(self.max_pending_age_secs);
        self.pending.retain(|_, p| p.received_at.elapsed() < cutoff);
    }

    /// Number of blocks waiting for ancestors.
    pub fn pending_count(&self) -> usize { self.pending.len() }

    /// Number of fetch requests in queue.
    pub fn fetch_queue_len(&self) -> usize { self.fetch_queue.len() }

    fn evict_oldest(&mut self) {
        if let Some(oldest_key) = self.pending.iter()
            .min_by_key(|(_, p)| p.received_at)
            .map(|(k, _)| *k)
        {
            self.pending.remove(&oldest_key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_flow() {
        let mut sync = Synchronizer::new(100, 60);

        let missing_ref = BlockRef { round: 1, author: 0, digest: BlockDigest([0xAA; 32]) };
        let block = Block {
            epoch: 0, round: 2, author: 1, timestamp_ms: 2000,
            ancestors: vec![missing_ref],
            transactions: vec![], commit_votes: vec![],
            tx_reject_votes: vec![], signature: vec![],
        };

        // Queue pending block with missing ancestor
        sync.queue_pending(block.clone(), vec![missing_ref]);
        assert_eq!(sync.pending_count(), 1);
        assert_eq!(sync.fetch_queue_len(), 1);

        // Fetch request available
        let req = sync.next_fetch_request().unwrap();
        assert_eq!(req.block_ref, missing_ref);

        // Resolve when ancestor arrives
        let ready = sync.resolve(&missing_ref);
        assert_eq!(ready.len(), 1);
        assert_eq!(sync.pending_count(), 0);
    }

    #[test]
    fn test_eviction() {
        let mut sync = Synchronizer::new(2, 60);
        for i in 0..3 {
            let missing = BlockRef { round: 1, author: i, digest: BlockDigest([i as u8; 32]) };
            let block = Block {
                epoch: 0, round: 2, author: i, timestamp_ms: 2000,
                ancestors: vec![missing], transactions: vec![],
                commit_votes: vec![], tx_reject_votes: vec![], signature: vec![],
            };
            sync.queue_pending(block, vec![missing]);
        }
        // Max 2, oldest should be evicted
        assert_eq!(sync.pending_count(), 2);
    }
}
