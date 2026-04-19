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

// ─── New: Kaspa-Aligned Storage Infrastructure ───
pub mod cache;
pub mod cached_access;
pub mod db_key;
pub mod db_writer;
pub mod pruning_store;
pub mod reachability_store;
pub mod schema_version;
pub mod startup_integrity;
pub mod store_errors;
pub mod store_registry;

// ═══════════════════════════════════════════════════════════════
//  Re-exports — Existing
// ═══════════════════════════════════════════════════════════════

pub use block_store::RocksBlockStore;
pub use checkpoint::{
    verify_checkpoint_state, Checkpoint, CheckpointError, CheckpointManager, CheckpointTrigger,
    CHECKPOINT_INTERVAL, MAX_CHECKPOINTS_RETAINED,
};
pub use dag_recovery::{
    bootstrap as dag_bootstrap, compact_wal_after_recovery, discard_incomplete_blocks,
    scan_wal_for_incomplete, DagRecoveryResult, RecoverySyncMode,
};
pub use flat_merkle::JellyfishMerkleTree;
pub use object_store::{ContractEvent, InMemoryObjectStore, ObjectMutation, ObjectStoreAccess};
pub use quarantine_store::QuarantineStore;
pub use recovery::{
    run_startup_check, run_startup_check_kaspa_aware, verify_startup_integrity, StartupCheckResult,
};
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
pub use schema_version::{
    check_compatible as check_storage_schema_compatible,
    check_compatible_arc as check_storage_schema_compatible_arc,
    read_schema_version as read_storage_schema_version,
    write_schema_version as write_storage_schema_version, SchemaVersionError,
    CURRENT_STORAGE_SCHEMA_VERSION, STORAGE_SCHEMA_VERSION_V088, STORAGE_SCHEMA_VERSION_V090,
};
pub use startup_integrity::{
    read_committed_state, verify_integrity as verify_startup_integrity_kaspa,
    verify_integrity_arc as verify_startup_integrity_kaspa_arc, write_committed_state,
    CommittedState, IntegrityError as StartupIntegrityError, IntegrityStatus,
};
pub use store_errors::StoreError;
pub use store_registry::StorePrefixes;
pub mod encryption;
