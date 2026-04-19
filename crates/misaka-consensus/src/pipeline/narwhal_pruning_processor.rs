// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Narwhal-native pruning processor (Phase 2 Path X R6-b, Option W).
//!
//! # Why
//!
//! The legacy [`super::pruning_processor::PruningProcessor`] was a
//! direct port of Kaspa's GhostDAG pruning algorithm (blue-score
//! walks, selected-parent chains, `DbGhostdagStore`). v6 of this
//! codebase removed GhostDAG consensus entirely; the Narwhal pipeline
//! commits sub-DAGs indexed by a monotonic [`u64`]. Pruning on the
//! Narwhal side is therefore an integer compare, not a DAG
//! traversal.
//!
//! This module implements that integer compare. It is the v6
//! replacement for the GhostDAG-bound [`super::pruning_processor`];
//! the legacy module remains in the tree for now because deleting
//! it is destructive (its scaffolding + test harnesses span ~500 LoC
//! across `pipeline/` and `stores/`). A follow-up PR can retire the
//! legacy code once its absence is verified harmless.
//!
//! # Pipeline
//!
//! ```text
//!                 ┌─────────────────────┐
//!                 │ Narwhal CommitConsumer │
//!                 └──────────┬──────────┘
//!                            │  CommittedSubDag (per commit)
//!                            ▼
//!            ┌───────────────────────────────┐
//!            │ NarwhalPruningProcessor       │
//!            │   on_committed_subdag(meta)   │
//!            └──────────┬────────────────────┘
//!                       │  PruningDecision::Advance{..}
//!                       ▼
//!     ┌─────────────────────────────────┐
//!     │ DbCommitPruningStore            │   ← persisted
//!     │   StorePrefixes::PruningPoint   │
//!     └──────────┬──────────────────────┘
//!                │
//!                ▼
//!       downstream GC (future wiring — out of R6-b):
//!       - misaka_dag::narwhal_dag::rocksdb_store::gc_below_round
//!       - Kaspa-aligned PruningStore::set_pruning_point
//! ```
//!
//! # Decoupling from `misaka-dag`
//!
//! This crate does **not** depend on `misaka-dag`. Callers
//! (typically `misaka-node::main::start_narwhal_node`) extract the
//! fields we need — `commit_index` and `timestamp_ms` — from
//! `misaka_dag::narwhal_types::commit::CommittedSubDag` into a local
//! [`NarwhalCommitMeta`] and pass it in. This keeps the
//! `misaka-consensus → misaka-dag` direction out of the dep graph.

use std::sync::Arc;

use parking_lot::RwLock;

use crate::stores::commit_pruning::{CommitPruningError, CommitPruningInfo, DbCommitPruningStore};

/// Minimal projection of `CommittedSubDag` needed to make a pruning
/// decision. Extracted here so this module stays off the `misaka-dag`
/// dep graph (see rustdoc above).
#[derive(Clone, Copy, Debug)]
pub struct NarwhalCommitMeta {
    /// The commit's sequential index.
    pub commit_index: u64,
    /// The commit's timestamp in milliseconds.
    pub timestamp_ms: u64,
}

/// Runtime config for the processor.
#[derive(Clone, Copy, Debug)]
pub struct NarwhalPruningConfig {
    /// How many commits to retain behind the tip before the processor
    /// starts emitting `Advance`. Sourced from
    /// `NodeConfig::prune_mode.keep_rounds()` on an archival-vs-pruned
    /// split:
    ///
    /// * `PruneMode::Archival`  → the processor is **not
    ///   constructed** at all; `Archival` is represented by its
    ///   absence. (Do not pass `u64::MAX`.)
    /// * `PruneMode::Pruned { keep_rounds }` → `pruning_depth_commits
    ///   = keep_rounds`.
    pub pruning_depth_commits: u64,
}

/// What the processor decided to do for a given commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PruningDecision {
    /// Not enough history yet, or the pruning index would regress.
    /// Downstream GC SHOULD do nothing.
    NoChange,
    /// The pruning index advanced. Downstream GC MAY delete data
    /// whose commit index is `< new_pruning_index`.
    Advance {
        /// The new floor — commits strictly below this are prunable.
        new_pruning_index: u64,
        /// The timestamp recorded alongside, for correlation in
        /// logs/dashboards.
        timestamp: u64,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum NarwhalPruningError {
    #[error(transparent)]
    Store(#[from] CommitPruningError),
}

/// Pure pruning decision logic plus a persistent
/// [`DbCommitPruningStore`].
///
/// Stateless across calls — the watermark lives in the store, not
/// in the processor struct, so multiple processor instances sharing
/// the same DB handle are consistent.
pub struct NarwhalPruningProcessor {
    config: NarwhalPruningConfig,
    store: Arc<RwLock<DbCommitPruningStore>>,
}

impl NarwhalPruningProcessor {
    #[must_use]
    pub fn new(config: NarwhalPruningConfig, store: Arc<RwLock<DbCommitPruningStore>>) -> Self {
        Self { config, store }
    }

    /// Decide whether `meta` advances the pruning point, and if so
    /// persist the new watermark.
    ///
    /// Returns the decision. Persistence failure is surfaced as
    /// [`NarwhalPruningError::Store`] — the caller should log and
    /// retry; it's safe to call again on a subsequent commit because
    /// the decision is idempotent relative to the stored watermark.
    ///
    /// Invariants:
    ///
    /// * `pruning_depth_commits == 0` would mean "prune everything"
    ///   which is unsafe — the constructor accepts 0 but this method
    ///   treats it as a guard: 0 returns `NoChange`. Prefer
    ///   constructing only when `PruneMode::Pruned { keep_rounds >= MIN_KEEP_ROUNDS }`.
    /// * Out-of-order calls (a later tick sees a stale `meta.commit_index`)
    ///   are tolerated: we use `max(current, candidate)`.
    pub fn on_committed_subdag(
        &self,
        meta: &NarwhalCommitMeta,
    ) -> Result<PruningDecision, NarwhalPruningError> {
        if self.config.pruning_depth_commits == 0 {
            // Defensive — see rustdoc above.
            return Ok(PruningDecision::NoChange);
        }

        // Candidate = how far behind this commit we'd prune *if* we
        // acted now. Saturating sub handles the early-chain case
        // where commit_index < pruning_depth_commits.
        let candidate = meta
            .commit_index
            .saturating_sub(self.config.pruning_depth_commits);
        if candidate == 0 {
            return Ok(PruningDecision::NoChange);
        }

        let current = self.store.read().get()?;

        // Only advance — never regress — the watermark. Handles
        // out-of-order callers and re-broadcast of old commits.
        let should_advance = match current {
            None => true,
            Some(info) => candidate > info.commit_index,
        };
        if !should_advance {
            return Ok(PruningDecision::NoChange);
        }

        let new = CommitPruningInfo {
            commit_index: candidate,
            timestamp_ms: meta.timestamp_ms,
        };
        self.store.write().set(&new)?;

        Ok(PruningDecision::Advance {
            new_pruning_index: candidate,
            timestamp: meta.timestamp_ms,
        })
    }

    /// Read-only access to the current watermark (for metrics /
    /// RPC introspection). Returns `None` if the store has never
    /// been written.
    pub fn current(&self) -> Result<Option<CommitPruningInfo>, NarwhalPruningError> {
        Ok(self.store.read().get()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocksdb::{Options, DB as RocksDB};
    use tempfile::TempDir;

    fn make_processor(pruning_depth_commits: u64) -> (TempDir, NarwhalPruningProcessor) {
        let dir = TempDir::new().unwrap();
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = Arc::new(RocksDB::open(&opts, dir.path()).unwrap());
        let store = Arc::new(RwLock::new(DbCommitPruningStore::new(db)));
        let config = NarwhalPruningConfig {
            pruning_depth_commits,
        };
        (dir, NarwhalPruningProcessor::new(config, store))
    }

    fn meta(idx: u64, ts: u64) -> NarwhalCommitMeta {
        NarwhalCommitMeta {
            commit_index: idx,
            timestamp_ms: ts,
        }
    }

    // ── Zero-depth guard ──────────────────────────────────────────

    #[test]
    fn zero_depth_is_no_change() {
        let (_d, p) = make_processor(0);
        let d = p.on_committed_subdag(&meta(100, 1000)).unwrap();
        assert_eq!(d, PruningDecision::NoChange);
    }

    // ── Early chain (commit_index < depth) ────────────────────────

    #[test]
    fn below_depth_is_no_change() {
        let (_d, p) = make_processor(100);
        // commit 50 < depth 100 → candidate saturates to 0 → NoChange.
        let d = p.on_committed_subdag(&meta(50, 1000)).unwrap();
        assert_eq!(d, PruningDecision::NoChange);
    }

    #[test]
    fn equal_to_depth_is_no_change() {
        let (_d, p) = make_processor(100);
        // commit 100 - depth 100 = candidate 0 → NoChange.
        let d = p.on_committed_subdag(&meta(100, 1000)).unwrap();
        assert_eq!(d, PruningDecision::NoChange);
    }

    // ── First advance ─────────────────────────────────────────────

    #[test]
    fn first_advance_above_depth() {
        let (_d, p) = make_processor(100);
        let d = p.on_committed_subdag(&meta(150, 1234)).unwrap();
        assert_eq!(
            d,
            PruningDecision::Advance {
                new_pruning_index: 50,
                timestamp: 1234
            }
        );
        // And it persisted.
        let cur = p.current().unwrap().unwrap();
        assert_eq!(cur.commit_index, 50);
        assert_eq!(cur.timestamp_ms, 1234);
    }

    // ── Monotonic advance ────────────────────────────────────────

    #[test]
    fn second_commit_advances_further() {
        let (_d, p) = make_processor(100);
        p.on_committed_subdag(&meta(150, 1000)).unwrap();
        let d = p.on_committed_subdag(&meta(200, 2000)).unwrap();
        assert_eq!(
            d,
            PruningDecision::Advance {
                new_pruning_index: 100,
                timestamp: 2000
            }
        );
    }

    // ── No-regress ───────────────────────────────────────────────

    #[test]
    fn stale_commit_does_not_regress() {
        let (_d, p) = make_processor(100);
        p.on_committed_subdag(&meta(300, 3000)).unwrap();
        // Watermark is now 200.
        // An out-of-order caller sends commit 150 (candidate = 50).
        let d = p.on_committed_subdag(&meta(150, 1500)).unwrap();
        assert_eq!(d, PruningDecision::NoChange);
        // Watermark unchanged.
        let cur = p.current().unwrap().unwrap();
        assert_eq!(cur.commit_index, 200);
        assert_eq!(cur.timestamp_ms, 3000);
    }

    #[test]
    fn same_index_is_no_change() {
        let (_d, p) = make_processor(100);
        p.on_committed_subdag(&meta(200, 2000)).unwrap();
        // Re-delivery of the same commit.
        let d = p.on_committed_subdag(&meta(200, 2000)).unwrap();
        assert_eq!(d, PruningDecision::NoChange);
    }

    // ── current() ────────────────────────────────────────────────

    #[test]
    fn current_returns_none_before_first_advance() {
        let (_d, p) = make_processor(100);
        assert!(p.current().unwrap().is_none());
    }

    #[test]
    fn current_reflects_latest_advance() {
        let (_d, p) = make_processor(50);
        p.on_committed_subdag(&meta(100, 1000)).unwrap();
        let cur = p.current().unwrap().unwrap();
        assert_eq!(cur.commit_index, 50);
        assert_eq!(cur.timestamp_ms, 1000);
    }

    // ── Many commits — monotone behaviour ────────────────────────

    #[test]
    fn many_advances_are_monotone() {
        let (_d, p) = make_processor(10);
        let mut last = 0u64;
        for idx in [20u64, 30, 100, 1_000, 10_000] {
            let d = p.on_committed_subdag(&meta(idx, idx * 10)).unwrap();
            match d {
                PruningDecision::Advance {
                    new_pruning_index, ..
                } => {
                    assert!(
                        new_pruning_index > last,
                        "new_pruning_index {new_pruning_index} must be > last {last}"
                    );
                    last = new_pruning_index;
                }
                PruningDecision::NoChange => panic!("expected advance at idx={idx}"),
            }
        }
    }
}
