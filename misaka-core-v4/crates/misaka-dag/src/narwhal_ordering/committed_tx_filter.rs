// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Cross-commit transaction deduplication filter (WP10).
//!
//! The linearizer already deduplicates transactions **within** a single commit
//! (see `linearizer.rs`). This module provides deduplication **across** commits
//! so that a transaction included by validators in two different sub-DAGs is
//! only executed once.
//!
//! ## Design
//!
//! We use a two-generation HashSet approach:
//!
//! - **Current generation**: actively accumulating transaction hashes.
//! - **Previous generation**: read-only; checked for membership but never
//!   mutated.
//!
//! Every `rotation_interval` commits the generations rotate: the current
//! generation becomes the previous one (read-only), the old previous generation
//! is discarded, and a fresh empty set becomes the current generation.
//!
//! This bounds memory to at most `2 * rotation_interval` entries while still
//! covering a window of `2 * rotation_interval` commits for dedup.
//!
//! ## Persistence
//!
//! The filter can be serialized to / deserialized from a byte vector for
//! storage in RocksDB. The format is intentionally simple (no versioning
//! beyond a leading magic byte) because the filter is rebuilt from the commit
//! log on mismatch.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::narwhal_types::commit::CommitIndex;

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// Counters exposed for Prometheus scraping / internal dashboards.
#[derive(Debug, Default)]
pub struct FilterMetrics {
    /// Number of `contains_or_insert` calls that returned `true` (duplicate).
    pub hits: AtomicU64,
    /// Total `contains_or_insert` calls.
    pub queries: AtomicU64,
    /// Number of generation rotations performed.
    pub rotations: AtomicU64,
}

impl FilterMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn hit_count(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    pub fn query_count(&self) -> u64 {
        self.queries.load(Ordering::Relaxed)
    }

    pub fn rotation_count(&self) -> u64 {
        self.rotations.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// CommittedTxFilter
// ---------------------------------------------------------------------------

/// Default rotation interval in commits.
pub const DEFAULT_ROTATION_INTERVAL: u64 = 36_000;

/// Magic byte used as a serialization format tag.
const SERIALIZATION_MAGIC: u8 = 0xCF; // "Committed Filter"

/// Two-generation transaction deduplication filter.
///
/// All transaction hashes are 32-byte blake3 digests.
pub struct CommittedTxFilter {
    /// Currently active generation (read-write).
    current: HashSet<[u8; 32]>,
    /// Previous generation (read-only lookups).
    previous: HashSet<[u8; 32]>,
    /// How many commits between rotations.
    rotation_interval: u64,
    /// Commits processed since the last rotation.
    commits_since_rotation: u64,
    /// The commit index at which the filter was last rotated.
    last_rotation_commit: CommitIndex,
    /// Observable counters.
    pub metrics: FilterMetrics,
}

impl CommittedTxFilter {
    /// Create a new filter with the default rotation interval.
    pub fn new() -> Self {
        Self::with_rotation_interval(DEFAULT_ROTATION_INTERVAL)
    }

    /// Create a new filter with a custom rotation interval.
    pub fn with_rotation_interval(rotation_interval: u64) -> Self {
        assert!(rotation_interval > 0, "rotation_interval must be > 0");
        Self {
            current: HashSet::new(),
            previous: HashSet::new(),
            rotation_interval,
            commits_since_rotation: 0,
            last_rotation_commit: 0,
            metrics: FilterMetrics::new(),
        }
    }

    /// Check whether `tx_hash` is already known. If not, insert it into the
    /// current generation and return `false`. If it is present in either
    /// generation, return `true` (duplicate).
    pub fn contains_or_insert(&mut self, tx_hash: &[u8; 32]) -> bool {
        self.metrics.queries.fetch_add(1, Ordering::Relaxed);

        // Check current generation first (most likely location).
        if self.current.contains(tx_hash) {
            self.metrics.hits.fetch_add(1, Ordering::Relaxed);
            return true;
        }

        // Check previous generation.
        if self.previous.contains(tx_hash) {
            self.metrics.hits.fetch_add(1, Ordering::Relaxed);
            return true;
        }

        // Not seen — insert into current generation.
        self.current.insert(*tx_hash);
        false
    }

    /// Notify the filter that a commit has been processed. This drives the
    /// generation rotation clock.
    pub fn on_commit(&mut self, commit_index: CommitIndex) {
        self.commits_since_rotation += 1;
        if self.commits_since_rotation >= self.rotation_interval {
            self.rotate();
            self.last_rotation_commit = commit_index;
        }
    }

    /// Force a generation rotation: current becomes previous, previous is
    /// discarded, a new empty set becomes current.
    pub fn rotate(&mut self) {
        let old_current = std::mem::take(&mut self.current);
        self.previous = old_current;
        self.commits_since_rotation = 0;
        self.metrics.rotations.fetch_add(1, Ordering::Relaxed);
    }

    /// Number of unique hashes tracked across both generations.
    pub fn len(&self) -> usize {
        self.current.len() + self.previous.len()
    }

    /// Whether both generations are empty.
    pub fn is_empty(&self) -> bool {
        self.current.is_empty() && self.previous.is_empty()
    }

    /// The commit index at which the last rotation occurred.
    pub fn last_rotation_commit(&self) -> CommitIndex {
        self.last_rotation_commit
    }

    // -----------------------------------------------------------------------
    // Serialization (for RocksDB persistence)
    // -----------------------------------------------------------------------

    /// Serialize the filter state to bytes.
    ///
    /// Layout:
    /// ```text
    /// [magic: 1B]
    /// [rotation_interval: 8B LE]
    /// [commits_since_rotation: 8B LE]
    /// [last_rotation_commit: 8B LE]
    /// [current_len: 8B LE]  [current hashes: current_len * 32B]
    /// [previous_len: 8B LE] [previous hashes: previous_len * 32B]
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let capacity = 1 + 8 * 4 + self.current.len() * 32 + self.previous.len() * 32;
        let mut buf = Vec::with_capacity(capacity);

        buf.push(SERIALIZATION_MAGIC);
        buf.extend_from_slice(&self.rotation_interval.to_le_bytes());
        buf.extend_from_slice(&self.commits_since_rotation.to_le_bytes());
        buf.extend_from_slice(&self.last_rotation_commit.to_le_bytes());

        buf.extend_from_slice(&(self.current.len() as u64).to_le_bytes());
        for hash in &self.current {
            buf.extend_from_slice(hash);
        }

        buf.extend_from_slice(&(self.previous.len() as u64).to_le_bytes());
        for hash in &self.previous {
            buf.extend_from_slice(hash);
        }

        buf
    }

    /// Deserialize from bytes previously produced by [`to_bytes`].
    ///
    /// Returns `None` on malformed input.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.is_empty() || data[0] != SERIALIZATION_MAGIC {
            return None;
        }

        let mut pos: usize = 1;

        let read_u64 = |pos: &mut usize, data: &[u8]| -> Option<u64> {
            if *pos + 8 > data.len() {
                return None;
            }
            let val = u64::from_le_bytes(data[*pos..*pos + 8].try_into().ok()?);
            *pos += 8;
            Some(val)
        };

        let rotation_interval = read_u64(&mut pos, data)?;
        let commits_since_rotation = read_u64(&mut pos, data)?;
        let last_rotation_commit = read_u64(&mut pos, data)?;

        let read_hashset = |pos: &mut usize, data: &[u8]| -> Option<HashSet<[u8; 32]>> {
            let count = read_u64(pos, data)? as usize;
            let mut set = HashSet::with_capacity(count);
            for _ in 0..count {
                if *pos + 32 > data.len() {
                    return None;
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&data[*pos..*pos + 32]);
                set.insert(hash);
                *pos += 32;
            }
            Some(set)
        };

        let current = read_hashset(&mut pos, data)?;
        let previous = read_hashset(&mut pos, data)?;

        Some(Self {
            current,
            previous,
            rotation_interval,
            commits_since_rotation,
            last_rotation_commit,
            metrics: FilterMetrics::new(),
        })
    }
}

impl Default for CommittedTxFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for CommittedTxFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommittedTxFilter")
            .field("current_len", &self.current.len())
            .field("previous_len", &self.previous.len())
            .field("rotation_interval", &self.rotation_interval)
            .field("commits_since_rotation", &self.commits_since_rotation)
            .field("last_rotation_commit", &self.last_rotation_commit)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: produce a deterministic 32-byte hash from an integer.
    fn tx_hash(n: u64) -> [u8; 32] {
        *blake3::hash(&n.to_le_bytes()).as_bytes()
    }

    #[test]
    fn test_basic_insert_and_dedup() {
        let mut filter = CommittedTxFilter::new();
        let h = tx_hash(1);

        assert!(
            !filter.contains_or_insert(&h),
            "first insert should return false"
        );
        assert!(
            filter.contains_or_insert(&h),
            "second insert should return true (dup)"
        );
        assert_eq!(filter.len(), 1);
    }

    #[test]
    fn test_multiple_distinct_transactions() {
        let mut filter = CommittedTxFilter::new();
        for i in 0..100 {
            assert!(!filter.contains_or_insert(&tx_hash(i)));
        }
        assert_eq!(filter.len(), 100);

        // All should now be duplicates.
        for i in 0..100 {
            assert!(filter.contains_or_insert(&tx_hash(i)));
        }
    }

    #[test]
    fn test_rotation_discards_old_generation() {
        let mut filter = CommittedTxFilter::with_rotation_interval(10);

        // Insert into current generation.
        let h1 = tx_hash(1);
        filter.contains_or_insert(&h1);
        assert_eq!(filter.current.len(), 1);
        assert_eq!(filter.previous.len(), 0);

        // First rotation: current -> previous.
        filter.rotate();
        assert_eq!(filter.current.len(), 0);
        assert_eq!(filter.previous.len(), 1);
        // h1 is still visible via the previous generation.
        assert!(filter.contains_or_insert(&h1));

        // Insert something new into current.
        let h2 = tx_hash(2);
        filter.contains_or_insert(&h2);
        assert_eq!(filter.current.len(), 1); // h2 (h1 dup hit doesn't insert)

        // Second rotation: previous (h1) is discarded; current (h2) -> previous.
        filter.rotate();
        assert_eq!(filter.previous.len(), 1); // h2
        assert!(
            !filter.contains_or_insert(&h1),
            "h1 should be gone after two rotations"
        );
        assert!(
            filter.contains_or_insert(&h2),
            "h2 should still be in previous"
        );
    }

    #[test]
    fn test_on_commit_triggers_rotation() {
        let interval = 5;
        let mut filter = CommittedTxFilter::with_rotation_interval(interval);

        let h = tx_hash(42);
        filter.contains_or_insert(&h);

        // Process commits 0..4 (5 total) -> should trigger rotation.
        for i in 0..interval {
            filter.on_commit(i);
        }

        assert_eq!(filter.metrics.rotation_count(), 1);
        assert_eq!(filter.commits_since_rotation, 0);
        // h should still be visible in the previous generation.
        assert!(filter.contains_or_insert(&h));

        // Another full interval of commits -> second rotation.
        for i in interval..2 * interval {
            filter.on_commit(i);
        }
        assert_eq!(filter.metrics.rotation_count(), 2);
        // h is now gone (was in previous, which got discarded).
        assert!(!filter.contains_or_insert(&h));
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut filter = CommittedTxFilter::with_rotation_interval(100);

        // Populate both generations.
        for i in 0..50 {
            filter.contains_or_insert(&tx_hash(i));
        }
        filter.rotate();
        for i in 50..80 {
            filter.contains_or_insert(&tx_hash(i));
        }
        filter.commits_since_rotation = 7;
        filter.last_rotation_commit = 42;

        let bytes = filter.to_bytes();
        let restored =
            CommittedTxFilter::from_bytes(&bytes).expect("deserialization should succeed");

        assert_eq!(restored.rotation_interval, 100);
        assert_eq!(restored.commits_since_rotation, 7);
        assert_eq!(restored.last_rotation_commit, 42);
        assert_eq!(restored.current.len(), 30);
        assert_eq!(restored.previous.len(), 50);

        // Verify all hashes are present.
        for i in 0..80 {
            let h = tx_hash(i);
            assert!(
                restored.current.contains(&h) || restored.previous.contains(&h),
                "hash for tx {} should be present after roundtrip",
                i,
            );
        }
    }

    #[test]
    fn test_from_bytes_rejects_bad_magic() {
        let bad = vec![0x00, 0x01, 0x02];
        assert!(CommittedTxFilter::from_bytes(&bad).is_none());
    }

    #[test]
    fn test_from_bytes_rejects_truncated() {
        let mut filter = CommittedTxFilter::new();
        filter.contains_or_insert(&tx_hash(1));
        let bytes = filter.to_bytes();
        // Truncate in the middle of a hash.
        let truncated = &bytes[..bytes.len() - 10];
        assert!(CommittedTxFilter::from_bytes(truncated).is_none());
    }

    #[test]
    fn test_from_bytes_empty() {
        assert!(CommittedTxFilter::from_bytes(&[]).is_none());
    }

    #[test]
    fn test_empty_filter_serialization() {
        let filter = CommittedTxFilter::new();
        let bytes = filter.to_bytes();
        let restored = CommittedTxFilter::from_bytes(&bytes).unwrap();
        assert!(restored.is_empty());
        assert_eq!(restored.rotation_interval, DEFAULT_ROTATION_INTERVAL);
    }

    #[test]
    fn test_metrics_counters() {
        let mut filter = CommittedTxFilter::new();
        let h = tx_hash(99);

        filter.contains_or_insert(&h); // miss
        filter.contains_or_insert(&h); // hit
        filter.contains_or_insert(&h); // hit

        assert_eq!(filter.metrics.query_count(), 3);
        assert_eq!(filter.metrics.hit_count(), 2);
    }

    #[test]
    fn test_metrics_rotation_counter() {
        let mut filter = CommittedTxFilter::with_rotation_interval(2);
        assert_eq!(filter.metrics.rotation_count(), 0);

        filter.on_commit(0);
        filter.on_commit(1); // triggers rotation
        assert_eq!(filter.metrics.rotation_count(), 1);

        filter.on_commit(2);
        filter.on_commit(3); // triggers rotation
        assert_eq!(filter.metrics.rotation_count(), 2);
    }

    #[test]
    fn test_last_rotation_commit_tracking() {
        let mut filter = CommittedTxFilter::with_rotation_interval(3);
        filter.on_commit(10);
        filter.on_commit(11);
        filter.on_commit(12); // rotation at commit 12
        assert_eq!(filter.last_rotation_commit(), 12);

        filter.on_commit(13);
        filter.on_commit(14);
        filter.on_commit(15); // rotation at commit 15
        assert_eq!(filter.last_rotation_commit(), 15);
    }

    #[test]
    fn test_default_trait() {
        let filter = CommittedTxFilter::default();
        assert_eq!(filter.rotation_interval, DEFAULT_ROTATION_INTERVAL);
        assert!(filter.is_empty());
    }

    #[test]
    fn test_debug_format() {
        let filter = CommittedTxFilter::new();
        let debug = format!("{:?}", filter);
        assert!(debug.contains("CommittedTxFilter"));
        assert!(debug.contains("current_len"));
    }

    #[test]
    #[should_panic(expected = "rotation_interval must be > 0")]
    fn test_zero_rotation_interval_panics() {
        CommittedTxFilter::with_rotation_interval(0);
    }

    #[test]
    fn test_large_batch_dedup() {
        let mut filter = CommittedTxFilter::with_rotation_interval(100);
        let count = 10_000;

        for i in 0..count {
            assert!(!filter.contains_or_insert(&tx_hash(i)));
        }
        assert_eq!(filter.len(), count as usize);

        // Re-insert all — every one should be a dup.
        for i in 0..count {
            assert!(filter.contains_or_insert(&tx_hash(i)));
        }
        assert_eq!(filter.metrics.hit_count(), count);
    }

    #[test]
    fn test_cross_generation_dedup() {
        // Simulate the real workflow: insert txs, commit, rotate, then see
        // the same txs in a later commit — they must still be detected.
        let mut filter = CommittedTxFilter::with_rotation_interval(2);

        let h = tx_hash(7);
        assert!(!filter.contains_or_insert(&h));

        // Two commits -> rotation.
        filter.on_commit(0);
        filter.on_commit(1);

        // h is now in the previous generation.
        assert!(
            filter.contains_or_insert(&h),
            "should still detect dup across rotation"
        );
    }
}
