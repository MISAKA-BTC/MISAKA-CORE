// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Synchronizer — missing block/commit recovery.
//!
//! Sui equivalent: consensus/core/synchronizer.rs (~1,100 lines)
//!
//! When blocks reference ancestors we haven't seen, the synchronizer
//! fetches them from peers via the sync RPC protocol.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::narwhal_types::block::*;
use crate::narwhal_types::committee::Committee;

/// Sync request for missing blocks.
#[derive(Clone, Debug)]
pub struct SyncRequest {
    /// Missing block references to fetch.
    pub missing_refs: Vec<BlockRef>,
    /// Peer to request from (authority index).
    pub peer: AuthorityIndex,
    /// When this request was created.
    pub created_at: Instant,
}

/// Configuration for the synchronizer.
#[derive(Clone, Debug)]
pub struct SynchronizerConfig {
    /// Maximum concurrent sync requests.
    pub max_concurrent_requests: usize,
    /// Timeout for sync requests.
    pub request_timeout: Duration,
    /// Minimum interval between requests to same peer.
    pub peer_request_interval: Duration,
    /// Maximum blocks to request in one batch.
    pub max_batch_size: usize,
}

impl Default for SynchronizerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_requests: 20,
            request_timeout: Duration::from_secs(10),
            peer_request_interval: Duration::from_millis(500),
            max_batch_size: 100,
        }
    }
}

/// Tracks sync state for missing block recovery.
pub struct Synchronizer {
    /// Configuration.
    config: SynchronizerConfig,
    /// Committee.
    committee: Committee,
    /// Currently pending sync requests by block ref.
    pending_requests: HashMap<BlockRef, SyncRequest>,
    /// Last request time per peer.
    last_request_time: HashMap<AuthorityIndex, Instant>,
    /// Block refs that have been requested but not yet received.
    inflight: HashSet<BlockRef>,
    /// Number of completed sync fetches.
    completed_syncs: u64,
    /// Number of failed sync fetches.
    failed_syncs: u64,
}

impl Synchronizer {
    pub fn new(committee: Committee, config: SynchronizerConfig) -> Self {
        Self {
            config,
            committee,
            pending_requests: HashMap::new(),
            last_request_time: HashMap::new(),
            inflight: HashSet::new(),
            completed_syncs: 0,
            failed_syncs: 0,
        }
    }

    /// Schedule fetching of missing block references.
    ///
    /// Groups missing refs by their author (fetch from the block's author
    /// first, then fallback to other peers).
    pub fn schedule_fetch(&mut self, missing: &[BlockRef]) -> Vec<SyncRequest> {
        let now = Instant::now();
        let mut requests = Vec::new();

        // Group by author (preferred peer)
        let mut by_author: HashMap<AuthorityIndex, Vec<BlockRef>> = HashMap::new();
        for block_ref in missing {
            if self.inflight.contains(block_ref) {
                continue; // already being fetched
            }
            by_author
                .entry(block_ref.author)
                .or_default()
                .push(*block_ref);
        }

        for (peer, refs) in by_author {
            // Check rate limiting
            if let Some(last) = self.last_request_time.get(&peer) {
                if now.duration_since(*last) < self.config.peer_request_interval {
                    continue;
                }
            }

            // Check max concurrent
            if self.inflight.len() >= self.config.max_concurrent_requests {
                break;
            }

            // Batch refs
            let batch: Vec<BlockRef> = refs.into_iter().take(self.config.max_batch_size).collect();

            for r in &batch {
                self.inflight.insert(*r);
            }

            let request = SyncRequest {
                missing_refs: batch,
                peer,
                created_at: now,
            };
            self.last_request_time.insert(peer, now);
            requests.push(request);
        }

        requests
    }

    /// Mark a block as successfully received.
    pub fn mark_received(&mut self, block_ref: &BlockRef) {
        self.inflight.remove(block_ref);
        self.pending_requests.remove(block_ref);
        self.completed_syncs += 1;
    }

    /// Mark a sync request as failed.
    pub fn mark_failed(&mut self, block_refs: &[BlockRef]) {
        for r in block_refs {
            self.inflight.remove(r);
        }
        self.failed_syncs += 1;
    }

    /// Expire old inflight requests that have timed out.
    pub fn expire_timed_out(&mut self) -> Vec<BlockRef> {
        let now = Instant::now();
        let timeout = self.config.request_timeout;
        let expired: Vec<BlockRef> = self
            .pending_requests
            .iter()
            .filter(|(_, req)| now.duration_since(req.created_at) > timeout)
            .map(|(r, _)| *r)
            .collect();

        for r in &expired {
            self.inflight.remove(r);
            self.pending_requests.remove(r);
        }

        expired
    }

    /// Number of blocks currently being fetched.
    pub fn num_inflight(&self) -> usize {
        self.inflight.len()
    }

    /// Stats.
    pub fn completed_syncs(&self) -> u64 {
        self.completed_syncs
    }
    pub fn failed_syncs(&self) -> u64 {
        self.failed_syncs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schedule_fetch() {
        let committee = Committee::new_for_test(4);
        let mut sync = Synchronizer::new(committee, SynchronizerConfig::default());

        let missing = vec![
            BlockRef::new(5, 0, BlockDigest([0x11; 32])),
            BlockRef::new(5, 1, BlockDigest([0x22; 32])),
            BlockRef::new(5, 2, BlockDigest([0x33; 32])),
        ];

        let requests = sync.schedule_fetch(&missing);
        // Each author gets its own request
        assert_eq!(requests.len(), 3);
        assert_eq!(sync.num_inflight(), 3);
    }

    #[test]
    fn test_mark_received() {
        let committee = Committee::new_for_test(4);
        let mut sync = Synchronizer::new(committee, SynchronizerConfig::default());

        let block_ref = BlockRef::new(5, 0, BlockDigest([0x11; 32]));
        sync.schedule_fetch(&[block_ref]);
        assert_eq!(sync.num_inflight(), 1);

        sync.mark_received(&block_ref);
        assert_eq!(sync.num_inflight(), 0);
        assert_eq!(sync.completed_syncs(), 1);
    }

    #[test]
    fn test_dedup_inflight() {
        let committee = Committee::new_for_test(4);
        let mut sync = Synchronizer::new(committee, SynchronizerConfig::default());

        let block_ref = BlockRef::new(5, 0, BlockDigest([0x11; 32]));
        let r1 = sync.schedule_fetch(&[block_ref]);
        let r2 = sync.schedule_fetch(&[block_ref]); // already inflight
        assert_eq!(r1.len(), 1);
        assert_eq!(r2.len(), 0); // deduped
    }
}
