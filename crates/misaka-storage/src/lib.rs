//! # misaka-storage — Kaspa-Aligned Storage Layer with PQ Integrity
//!
//! ## Architecture
//!
//! ```text
//! ┌───────────────────────────────────────────────────────┐
//! │                    Application Layer                    │
//! │  (Consensus, Node, RPC)                                │
//! ├───────────────────────────────────────────────────────┤
//! │              Typed Store Access (cached)                │
//! │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐ │
//! │  │ Headers  │ │   UTXO   │ │ Reachab. │ │ Pruning │ │
//! │  │  Store   │ │   Set    │ │  Store   │ │  Store  │ │
//! │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬────┘ │
//! │       │             │             │             │      │
//! ├───────▼─────────────▼─────────────▼─────────────▼─────┤
//! │            CachedDbAccess + LRU Cache                   │
//! │            DbWriter (Direct / Batch / Atomic)           │
//! ├─────────────────────────────────────────────────────────┤
//! │                      RocksDB                             │
//! │  (prefix-namespaced, single instance, WAL + checkpoints)│
//! └─────────────────────────────────────────────────────────┘
//! ```

// ─── Existing modules (preserved) ───
pub mod block_store;
pub mod checkpoint;
pub mod columns;
pub mod dag_recovery;
pub mod flat_merkle;
pub mod object_store;
pub mod quarantine_store;
pub mod recovery;
pub mod utxo_set;
pub mod wal;

pub mod block_archive;

/// eUTXO v5 state commitment (datum/script_ref in element bytes).
/// Feature-gated behind `eutxo-v1-state`. Activated at v2.0 hard fork.
///
/// NOTE: merged snapshot tests reference `utxo_set::utxo_element_bytes_v4_pub`
/// which is introduced in PR C (common-file utxo_set.rs diff). Until PR C
/// lands, the `#[cfg(any(..., test))]` dual gate would fail the test build,
/// so the feature-only gate is retained here and the test gate is restored
/// in PR C.
#[cfg(feature = "eutxo-v1-state")]
pub mod eutxo_state;

// ─── New: Kaspa-Aligned Storage Infrastructure ───
pub mod cache;
pub mod cached_access;
pub mod db_key;
pub mod db_writer;
pub mod pruning_store;
pub mod reachability_store;
pub mod store_errors;
pub mod store_registry;

// ═══════════════════════════════════════════════════════════════
//  Re-exports — Existing
// ═══════════════════════════════════════════════════════════════

pub use block_store::RocksBlockStore;
pub use checkpoint::{
    verify_checkpoint_state, Checkpoint, CheckpointError, CheckpointManager, CHECKPOINT_INTERVAL,
    MAX_CHECKPOINTS_RETAINED,
};
pub use dag_recovery::{
    bootstrap as dag_bootstrap, compact_wal_after_recovery, discard_incomplete_blocks,
    scan_wal_for_incomplete, DagRecoveryResult, RecoverySyncMode,
};
pub use flat_merkle::JellyfishMerkleTree;
pub use object_store::{ContractEvent, InMemoryObjectStore, ObjectMutation, ObjectStoreAccess};
pub use quarantine_store::QuarantineStore;
pub use recovery::{run_startup_check, verify_startup_integrity, StartupCheckResult};
pub use utxo_set::UtxoSet;
pub use wal::{
    AcceptPhase, IncompleteBlock, JournalEntry, RecoveryResult, WalError, WriteAheadLog,
    COMPACT_THRESHOLD, MAX_JOURNAL_SIZE,
};

// ═══════════════════════════════════════════════════════════════
//  Re-exports — Kaspa-Aligned
// ═══════════════════════════════════════════════════════════════

pub use cache::{Cache, CachePolicy, MemSizeEstimate};
pub use cached_access::{CachedDbAccess, CachedDbItem};
pub use db_key::DbKey;
pub use db_writer::{
    AtomicBatch, BatchDbWriter, DbWriter, DirectDbWriter, DirectWriter, MemoryWriter,
};
pub use pruning_store::{PruningPointInfo, PruningStore, PruningUtxoEntry};
pub use reachability_store::{
    BlockRelations, ChildrenList, FutureCoveringSet, ReachabilityInterval, ReachabilityStore,
};
pub use store_errors::StoreError;
pub use store_registry::StorePrefixes;
pub mod encryption;
