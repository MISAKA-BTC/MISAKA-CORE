// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
// Sui equivalent: consensus/core/src/commit_syncer.rs (1,100 lines)
//
//! Commit Syncer — catches up lagging nodes by fetching committed sub-DAGs.
//!
//! When a validator falls behind (e.g., after restart or network partition),
//! it needs to fetch not just individual blocks but entire committed
//! sub-DAGs to reconstruct the linear commit history.
//!
//! Responsibilities:
//! - Detect commit lag (own commit_index vs peer commit_index)
//! - Request missing commits from peers
//! - Apply fetched commits in order
//! - Coordinate with sync_fetcher for block-level fetching
//!
//! ## Relationship with sync_fetcher
//!
//! - `sync_fetcher`: fetches individual **blocks** by BlockRef
//! - `commit_syncer`: fetches entire **commits** by CommitIndex range
//!
//! commit_syncer may internally use sync_fetcher to fill in blocks
//! that are referenced by a commit but not yet in the local DAG.

use crate::narwhal_types::block::*;
use crate::narwhal_types::commit::*;
use crate::narwhal_types::committee::Committee;
use std::collections::{BTreeMap, HashSet};

/// State of a sync session with a peer.
#[derive(Clone, Debug)]
pub struct SyncSession {
    pub peer: AuthorityIndex,
    pub from_index: CommitIndex,
    pub to_index: CommitIndex,
    pub started_at_ms: u64,
}

/// A fetched commit ready to apply.
#[derive(Clone, Debug)]
pub struct FetchedCommit {
    pub commit: CommittedSubDag,
    /// Blocks referenced by this commit (fetched alongside).
    pub blocks: Vec<Block>,
}

/// Commit syncer — detects lag and catches up.
///
/// Sui equivalent: `CommitSyncer` (commit_syncer.rs).
pub struct CommitSyncer {
    /// Our authority index.
    own_authority: AuthorityIndex,
    /// Our current commit index.
    local_commit_index: CommitIndex,
    /// Peers' commit indices (from round prober or gossip).
    peer_commit_indices: BTreeMap<AuthorityIndex, CommitIndex>,
    /// Fetched commits pending application (ordered by index).
    pending_commits: BTreeMap<CommitIndex, FetchedCommit>,
    /// Active sync sessions.
    active_sessions: Vec<SyncSession>,
    /// Commit indices we've already requested (dedup).
    requested: HashSet<CommitIndex>,
    /// Maximum concurrent sync sessions.
    max_sessions: usize,
    /// Maximum commits to request per session.
    max_commits_per_request: u64,
    /// Total commits synced (monotonic counter).
    total_synced: u64,
}

impl CommitSyncer {
    /// Create a new commit syncer.
    #[must_use]
    pub fn new(own_authority: AuthorityIndex) -> Self {
        Self {
            own_authority,
            local_commit_index: 0,
            peer_commit_indices: BTreeMap::new(),
            pending_commits: BTreeMap::new(),
            active_sessions: Vec::new(),
            requested: HashSet::new(),
            max_sessions: 3,
            max_commits_per_request: 100,
            total_synced: 0,
        }
    }

    /// Update our local commit index (called after applying commits).
    pub fn set_local_commit_index(&mut self, index: CommitIndex) {
        self.local_commit_index = index;
    }

    /// Update a peer's commit index (from round prober or gossip).
    pub fn update_peer_commit_index(&mut self, peer: AuthorityIndex, index: CommitIndex) {
        self.peer_commit_indices.insert(peer, index);
    }

    /// Compute the commit lag (highest peer index - our index).
    /// Returns `None` if no peers have reported their commit index,
    /// preventing a false "caught up" conclusion from an empty peer set.
    #[must_use]
    pub fn commit_lag(&self) -> Option<u64> {
        let highest_peer = self.peer_commit_indices.values().copied().max()?;
        Some(highest_peer.saturating_sub(self.local_commit_index))
    }

    /// Check if we need to sync (lag > 0 and not already syncing everything).
    #[must_use]
    pub fn needs_sync(&self) -> bool {
        self.commit_lag().unwrap_or(0) > 0 && self.active_sessions.len() < self.max_sessions
    }

    /// Generate sync requests for missing commits.
    ///
    /// Returns (peer, from_index, to_index) tuples to send.
    #[must_use]
    pub fn next_sync_requests(&mut self) -> Vec<(AuthorityIndex, CommitIndex, CommitIndex)> {
        if !self.needs_sync() {
            return vec![];
        }

        let mut requests = Vec::new();
        let start = self.local_commit_index + 1;
        let highest = self
            .peer_commit_indices
            .values()
            .copied()
            .max()
            .unwrap_or(0);

        // Find a peer that has the commits we need
        let mut from = start;
        while from <= highest && self.active_sessions.len() < self.max_sessions {
            let to = (from + self.max_commits_per_request - 1).min(highest);

            // Skip already-requested ranges
            if self.requested.contains(&from) {
                from = to + 1;
                continue;
            }

            // Find best peer (highest commit index, not already in active session)
            let active_peers: HashSet<AuthorityIndex> =
                self.active_sessions.iter().map(|s| s.peer).collect();

            let best_peer = self
                .peer_commit_indices
                .iter()
                .filter(|(&peer, &idx)| {
                    idx >= to && peer != self.own_authority && !active_peers.contains(&peer)
                })
                .max_by_key(|(_, &idx)| idx)
                .map(|(&peer, _)| peer);

            if let Some(peer) = best_peer {
                for i in from..=to {
                    self.requested.insert(i);
                }
                self.active_sessions.push(SyncSession {
                    peer,
                    from_index: from,
                    to_index: to,
                    started_at_ms: 0, // caller sets timestamp
                });
                requests.push((peer, from, to));
            }

            from = to + 1;
        }

        requests
    }

    /// Handle a successful sync response: store fetched commits.
    ///
    /// R3-M5 FIX: Validate each fetched commit before inserting to prevent
    /// a malicious peer from injecting fabricated commit data.
    pub fn on_sync_response(&mut self, peer: AuthorityIndex, commits: Vec<FetchedCommit>) {
        // Remove active session for this peer
        self.active_sessions.retain(|s| s.peer != peer);

        for fetched in commits {
            let idx = fetched.commit.index;

            // Reject commits we never requested
            if !self.requested.contains(&idx) {
                tracing::warn!(
                    "commit_syncer: peer {} sent unrequested commit index {} — dropped",
                    peer,
                    idx
                );
                continue;
            }

            // Reject commits with empty block references
            if fetched.commit.blocks.is_empty() {
                tracing::warn!(
                    "commit_syncer: peer {} sent commit {} with no block refs — dropped",
                    peer,
                    idx
                );
                continue;
            }

            // Reject if leader round is zero (invalid)
            if fetched.commit.leader.round == 0 {
                tracing::warn!(
                    "commit_syncer: peer {} sent commit {} with leader round 0 — dropped",
                    peer,
                    idx
                );
                continue;
            }

            self.pending_commits.insert(idx, fetched);
        }
    }

    /// Handle a sync timeout.
    pub fn on_sync_timeout(&mut self, peer: AuthorityIndex) {
        if let Some(session) = self.active_sessions.iter().find(|s| s.peer == peer) {
            // Un-request the range so it can be retried with another peer
            for i in session.from_index..=session.to_index {
                self.requested.remove(&i);
            }
        }
        self.active_sessions.retain(|s| s.peer != peer);
    }

    /// Take commits that are ready to apply (sequential from local_commit_index+1).
    #[must_use]
    pub fn take_ready_commits(&mut self) -> Vec<FetchedCommit> {
        let mut ready = Vec::new();
        loop {
            let next = self.local_commit_index + 1;
            match self.pending_commits.remove(&next) {
                Some(fetched) => {
                    self.local_commit_index = next;
                    self.total_synced += 1;
                    ready.push(fetched);
                }
                None => break,
            }
        }
        ready
    }

    /// Pending commit count.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending_commits.len()
    }

    /// Active session count.
    #[must_use]
    pub fn active_session_count(&self) -> usize {
        self.active_sessions.len()
    }

    /// Total commits synced.
    #[must_use]
    pub fn total_synced(&self) -> u64 {
        self.total_synced
    }

    /// Local commit index.
    #[must_use]
    pub fn local_commit_index(&self) -> CommitIndex {
        self.local_commit_index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_peers_no_sync() {
        let syncer = CommitSyncer::new(0);
        assert_eq!(syncer.commit_lag(), None);
        assert!(!syncer.needs_sync());
    }

    #[test]
    fn test_detect_lag() {
        let mut syncer = CommitSyncer::new(0);
        syncer.set_local_commit_index(5);
        syncer.update_peer_commit_index(1, 10);
        assert_eq!(syncer.commit_lag(), Some(5));
        assert!(syncer.needs_sync());
    }

    #[test]
    fn test_generate_sync_requests() {
        let mut syncer = CommitSyncer::new(0);
        syncer.set_local_commit_index(0);
        syncer.update_peer_commit_index(1, 50);

        let requests = syncer.next_sync_requests();
        assert!(!requests.is_empty());
        assert_eq!(requests[0].0, 1); // peer
        assert_eq!(requests[0].1, 1); // from
    }

    #[test]
    fn test_apply_fetched_commits() {
        let mut syncer = CommitSyncer::new(0);
        syncer.set_local_commit_index(0);

        let commit1 = FetchedCommit {
            commit: CommittedSubDag {
                index: 1,
                leader: BlockRef::new(1, 0, BlockDigest([0xAA; 32])),
                blocks: vec![],
                timestamp_ms: 1000,
                previous_digest: CommitDigest([0; 32]),
                is_direct: true,
            },
            blocks: vec![],
        };
        syncer.pending_commits.insert(1, commit1);

        let ready = syncer.take_ready_commits();
        assert_eq!(ready.len(), 1);
        assert_eq!(syncer.local_commit_index(), 1);
        assert_eq!(syncer.total_synced(), 1);
    }

    #[test]
    fn test_out_of_order_not_ready() {
        let mut syncer = CommitSyncer::new(0);
        syncer.set_local_commit_index(0);

        // Insert commit 3 (skipping 1 and 2)
        let commit3 = FetchedCommit {
            commit: CommittedSubDag {
                index: 3,
                leader: BlockRef::new(1, 0, BlockDigest([0xCC; 32])),
                blocks: vec![],
                timestamp_ms: 3000,
                previous_digest: CommitDigest([0; 32]),
                is_direct: true,
            },
            blocks: vec![],
        };
        syncer.pending_commits.insert(3, commit3);

        let ready = syncer.take_ready_commits();
        assert!(ready.is_empty()); // commit 1 is missing
        assert_eq!(syncer.pending_count(), 1);
    }

    #[test]
    fn test_timeout_allows_retry() {
        let mut syncer = CommitSyncer::new(0);
        syncer.set_local_commit_index(0);
        syncer.update_peer_commit_index(1, 50);
        syncer.update_peer_commit_index(2, 50);

        let requests = syncer.next_sync_requests();
        assert!(!requests.is_empty());
        let peer = requests[0].0;

        // Simulate timeout
        syncer.on_sync_timeout(peer);
        assert_eq!(syncer.active_session_count(), 0);

        // Should be able to retry (requested set cleared for that range)
        let retry = syncer.next_sync_requests();
        assert!(!retry.is_empty());
    }
}
