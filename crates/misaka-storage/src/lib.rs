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
//
// Phase 2 Path X R1 step 4 (2026-04-19): the legacy `block_store`
// module (5-CF `RocksBlockStore`) was deleted. Its only live consumer
// was `recovery.rs::run_startup_check`'s legacy fallback, which R1
// step 3 made optional and step 4 removes entirely. See
// `docs/design/v090_phase2_tail_work.md` §2.3 step 4.
pub mod checkpoint;
pub mod columns;
pub mod dag_recovery;
pub mod flat_merkle;
pub mod object_store;
/// Phase P1 (v0.9.2): persistent peer store types + event policy.
/// RocksDB wiring lives under `StorageCf::Peerstore`; this module
/// defines the schema + the pure-logic event → record mutations.
pub mod peerstore;
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
pub mod schema_version;
pub mod startup_integrity;
pub mod store_errors;
pub mod store_registry;

// ═══════════════════════════════════════════════════════════════
//  Re-exports — Existing
// ═══════════════════════════════════════════════════════════════

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
pub use schema_version::{
    check_compatible as check_storage_schema_compatible,
    check_compatible_arc as check_storage_schema_compatible_arc,
    read_schema_version as read_storage_schema_version,
    write_schema_version as write_storage_schema_version, SchemaVersionError,
    CURRENT_STORAGE_SCHEMA_VERSION, STORAGE_SCHEMA_VERSION_V088, STORAGE_SCHEMA_VERSION_V090,
    STORAGE_SCHEMA_VERSION_V091,
};
pub use startup_integrity::{
    read_committed_state, verify_integrity as verify_startup_integrity_kaspa,
    verify_integrity_arc as verify_startup_integrity_kaspa_arc, write_committed_state,
    CommittedState, IntegrityError as StartupIntegrityError, IntegrityStatus,
};
pub use store_errors::StoreError;
pub use store_registry::StorePrefixes;
pub mod encryption;
