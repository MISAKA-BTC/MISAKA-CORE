//! # MISAKA-DAG: Privacy BlockDAG (Lattice ZKP + GhostDAG)
//!
//! ## Architecture (v4)
//!
//! Privacy is achieved via lattice-based zero-knowledge proofs:
//! - **BDLOP Commitments**: Hide amounts (Module-SIS/LWE)
//! - **SIS Merkle Membership**: Prove UTXO ownership without identification
//! - **Algebraic Nullifiers**: Ring-independent double-spend prevention
//! - **Lattice Range Proofs**: Non-negativity without value revelation
//!
//! GhostDAG provides parallel block production with deterministic ordering.
//!
//! ## アーキテクチャ概要 (Architecture Overview)
//!
//! ```text
//!  ┌─────────────────────────────────────────────────────────────────┐
//!  │                     MISAKA-CORE v2 Layer Cake                   │
//!  ├─────────────────────────────────────────────────────────────────┤
//!  │                                                                 │
//!  │  ┌──────────────────┐    ┌────────────────────────────────┐    │
//!  │  │   P2P Network     │───▶│  DAG Block Pool (Unordered)    │    │
//!  │  │  (libp2p relay)   │    │  dag_block.rs                  │    │
//!  │  └──────────────────┘    └──────────────┬─────────────────┘    │
//!  │                                          │                      │
//!  │                                          ▼                      │
//!  │  ┌──────────────────────────────────────────────────────┐      │
//!  │  │           GhostDAG Consensus Engine                   │      │
//!  │  │           ghostdag.rs                                 │      │
//!  │  │                                                       │      │
//!  │  │  • Selected Parent Chain 構築                         │      │
//!  │  │  • Blue set / Red set 分類                            │      │
//!  │  │  • Total Order (決定論的線形化)                       │      │
//!  │  │  • Confirmation Depth 算出                            │      │
//!  │  └────────────────────────┬─────────────────────────────┘      │
//!  │                           │                                     │
//!  │                           │ Total Order                         │
//!  │                           ▼                                     │
//!  │  ┌──────────────────────────────────────────────────────┐      │
//!  │  │         DAG State Manager (遅延状態評価)              │      │
//!  │  │         dag_state_manager.rs                          │      │
//!  │  │                                                       │      │
//!  │  │  • Key Image 競合検出・解決                           │      │
//!  │  │  • フェイルソフト TX 無効化                           │      │
//!  │  │  • UTXO Set 更新 (コールバック)                      │      │
//!  │  │  • 安全なデコイ選択フィルタ                           │      │
//!  │  └────────────────────────┬─────────────────────────────┘      │
//!  │                           │                                     │
//!  │                           │ UtxoAction callbacks                │
//!  │                           ▼                                     │
//!  │  ┌──────────────────────────────────────────────────────┐      │
//!  │  │            UTXO Set (misaka-storage)                  │      │
//!  │  │  ┌───────────────────────────────────────────┐       │      │
//!  │  │  │  unspent: HashMap<OutputRef, UtxoEntry>    │       │      │
//!  │  │  │  key_images: HashSet<[u8; 32]>             │       │      │
//!  │  │  │  spending_pubkeys: HashMap<OutputRef, Poly> │       │      │
//!  │  │  └───────────────────────────────────────────┘       │      │
//!  │  └──────────────────────────────────────────────────────┘      │
//!  │                                                                 │
//!  │  ┌──────────────────────────────────────────────────────┐      │
//!  │  │         Lattice ZKP Layer (misaka-pqc)              │      │
//!  │  │  • Lattice-based unified ZKP (Σ + SIS Merkle)                   │      │
//!  │  │  • Algebraic nullifier binding proofs                       │      │
//!  │  │  • Module-SIS/LWE polynomial arithmetic                   │      │
//!  │  └──────────────────────────────────────────────────────┘      │
//!  └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## モジュール構成
//!
//! | モジュール            | 責務                                                  |
//! |-----------------------|------------------------------------------------------|
//! | `dag_block`           | DAG ブロックヘッダ (multi-parent) + GhostDagData      |
//! | `ghostdag`            | GhostDAG コンセンサス: Blue/Red 分類, Total Order     |
//! | `dag_state_manager`   | 遅延状態評価: KI 競合解決, フェイルソフト TX, デコイ   |
//!
//! ## 設計上の重要な判断
//!
//! ### 1. コンセンサス層と状態遷移層の分離
//!
//! `ghostdag.rs` はブロックの順序付けのみを担当し、UTXO 状態には一切触れない。
//! `dag_state_manager.rs` は順序付けの結果を受け取り、状態遷移を行う。
//! これにより:
//! - コンセンサスアルゴリズムの変更が状態遷移に影響しない
//! - 状態遷移ロジックのテストがコンセンサスなしで可能
//! - v1 の `UtxoSet` をそのまま再利用できる
//!
//! ### 2. v1 型の再利用
//!
//! `UtxoTransaction`, `RingInput`, `TxOutput`, `OutputRef` は v1 と同一。
//! DAG レイヤーはトランザクション形式に依存しない。
//!
//! ### 3. フェイルソフトな TX 無効化
//!
//! v1 では「ブロック内の TX が不正 → ブロック全体が不正」だったが、
//! v2 では「TX が競合 → TX のみ無効、ブロックは有効」。
//! これは DAG の並列ブロック生成が善意のノードでも起こりうるため必須。

// ─── Phase 0: Protocol Constants (SSOT) ───
pub mod constants;

// ─── Phase 1: データ構造とコンセンサス ───
pub mod architecture;
pub mod block_processor;
pub mod dag_block;
pub mod dag_state_manager;
pub mod ghostdag;
pub mod ghostdag_v2;
pub mod legacy_ghostdag;
pub mod parent_selection;
pub mod qdag_block;
pub mod state_diff;
pub mod virtual_state;

// ─── Phase 2: インフラストラクチャ ───
pub mod dag_block_ingestion;
pub mod dag_block_producer;
pub mod dag_finality;
pub mod dag_p2p;
pub mod dag_persistence;
pub mod dag_store;
pub mod pruning;

// ─── Phase 3: Q-DAG-CT Extensions ───
pub mod atomic_pipeline;
pub mod daa;
pub mod decoy_selection;
pub mod header_validation;
pub mod persistent_store;
pub mod pruning_proof;
#[cfg(feature = "qdag-ct")]
pub mod qdag_verify;
pub mod reachability;
pub mod validation_pipeline;
pub mod wire_protocol;

// ═══════════════════════════════════════════════════════════════
//  Re-exports — Phase 1: Core
// ═══════════════════════════════════════════════════════════════

pub use block_processor::{process_new_block, BlockProcessError, BlockProcessResult};
pub use dag_block::{DagBlock, DagBlockHeader, GhostDagData, Hash, ZERO_HASH};
pub use dag_state_manager::{
    DagStateManager, DecoyCandidate, DecoyFilter, OrderedBlockData, OrderedTxData, TxApplyResult,
    TxApplyStatus, UtxoAction,
};
pub use ghostdag::{
    canonical_compare, canonical_select_parent, validate_header_topology, DagStore,
    EpochAwareStakeProvider, GhostDagEngine, GhostDagError, HeaderTopologyError, InMemoryDagStore,
    ParentSortKey, StakeWeightProvider, UniformStakeProvider, DEFAULT_K, MAX_MERGESET_SIZE,
    MAX_PARENTS, MIN_DECOY_DEPTH, PRUNING_WINDOW,
};
pub use virtual_state::{
    BlockAcceptanceData, ResolveResult, TxAcceptance, UpdateResult, VirtualChainChanged,
    VirtualState, VirtualStateError, VirtualStateSnapshot, VirtualStateStats, MAX_REORG_DEPTH,
};
// Canonical parent selection (re-export from parent_selection via ghostdag)
pub use parent_selection::{
    check_block_template_quality, pick_virtual_parents, select_canonical_parents, AnticoneSpread,
    BlockTemplateQuality, VirtualParents, MAX_MERGE_DEPTH, MIN_PARENTS,
};
// True DAG ancestor/anticone (hybrid SPT + BFS)
pub use reachability::{
    is_dag_ancestor_conclusive, is_dag_anticone_conclusive, ReachabilityError,
    CONCLUSIVE_BFS_HARD_CAP,
};
// Deprecated — REMOVED from consensus paths.
// These functions use bounded BFS with silent false on exhaustion (Fail-Open).
// Production code MUST use is_dag_ancestor_conclusive / is_dag_anticone_conclusive.
// Retained for backward-compatible external test code.
pub use qdag_block::{QdagBlock, SealedTransaction};
#[allow(deprecated)]
pub use reachability::{is_true_dag_ancestor, is_true_dag_anticone};
pub use state_diff::{
    CreatedUtxo, DiffApplicable, DiffTxResult, DiffTxStatus, InMemoryState, ReorgEngine,
    ReorgError, ReorgResult, SpentUtxo, StateDiff,
};

// ═══════════════════════════════════════════════════════════════
//  Re-exports — Phase 2: Infrastructure
// ═══════════════════════════════════════════════════════════════

pub use dag_block_producer::{
    assemble_dag_block, build_block_diff, build_ordered_block_data, run_dag_block_producer,
    utxo_tx_to_ordered, DagMempool, DagNodeState, LocalDagValidator,
};
// replay_ordered_state is deprecated (O(|history|)) — use VirtualState::resolve() instead.
// Retained for backward-compatible test code and migration path.
pub use architecture::{
    BlockExecutionResult, BlockTxReader, DagPipeline, ExecutionLayer, OrderingLayer, PipelineError,
    PipelineResult, SealedTxRef, StorageLayer,
};
pub use atomic_pipeline::{
    process_new_block_atomic, AtomicAcceptResult, AtomicPipelineError, StoreWriteBatch,
};
pub use daa::{
    check_block_quality, compute_block_rate, compute_bounded_past_median_time,
    compute_direct_parents_median, compute_epoch, compute_next_bits, compute_past_median_time,
    compute_proposer_cadence_ms, validate_timestamp, BlockQualityCheck, DaaScore, DaaWindow,
    DaaWindowBlock, TimestampCheck, BLOCKS_PER_EPOCH, BOUNDED_MEDIAN_WINDOW, DAA_WINDOW_SIZE,
    INITIAL_BITS, MAX_FUTURE_DRIFT_MS, TARGET_BLOCK_INTERVAL_MS,
};
pub use dag_block_ingestion::{
    BlockIngestState, IngestAction, IngestError, IngestionPipeline, IngestionStats, PendingBlock,
    MAX_PENDING_BLOCKS, MAX_PENDING_TIMEOUT_SECS,
};
#[allow(deprecated)]
pub use dag_block_producer::{replay_ordered_state, DagReplayOutcome};
pub use dag_finality::{
    DagCheckpoint, FinalityManager, VirtualBlock, FINALITY_DEPTH, PRUNING_DEPTH,
};
pub use dag_p2p::{
    build_block_locator, find_shared_block, DagP2pMessage, DagSyncManager, DagSyncState,
    PeerQuality, SyncAction, SyncMode, SyncStats, BAN_THRESHOLD, BODY_BATCH_SIZE,
    DAG_PROTOCOL_VERSION, HEADER_BATCH_SIZE, SCORE_PREFERENCE_THRESHOLD,
};
pub use dag_persistence::{
    load_runtime_snapshot, save_runtime_snapshot, DagRuntimeSnapshot, RestoredDagRuntime,
};
pub use dag_store::{DagStoreSnapshot, ThreadSafeDagStore};
pub use pruning::{
    PruneLevel, PruneResult, PruningManager, PruningPoint, PRUNING_POINT_MIN_DEPTH,
    PRUNING_POINT_UPDATE_INTERVAL,
};
pub use pruning_proof::{
    compute_nullifier_commitment, compute_utxo_commitment, DagSnapshot, ProofBlock,
    ProofVerifyResult, PruningProof,
};
