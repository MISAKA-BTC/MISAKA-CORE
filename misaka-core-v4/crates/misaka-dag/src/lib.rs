//! # MISAKA-DAG: Narwhal/Bullshark DAG Consensus (Sui-aligned)
//!
//! ## Architecture (v6 — Narwhal Only)
//!
//! All consensus is handled by Narwhal/Bullshark:
//! - **Block proposal**: CoreEngine with ML-DSA-65 signing
//! - **DAG state**: DagState with equivocation detection, eviction, write batching
//! - **Commit**: UniversalCommitter (pipelined Bullshark) with direct/indirect/skip
//! - **Linearization**: Linearizer → CommitFinalizer (deterministic total order)
//! - **Finality**: BFT checkpoint voting with per-digest quorum
//! - **Network**: Anemo-style binary protocol + HTTP fallback
//! - **Persistence**: WAL + JSON snapshot + RocksDB
//!
//! GhostDAG has been fully removed as of v6.

// L-1: test-utils feature gates test infrastructure (TestValidatorSet,
// MlDsa65TestSigner, DagBuilder, CommitFixture) for integration tests.
// MUST NOT be used in production binaries — compile_error! enforces this.
#[cfg(all(not(debug_assertions), not(test), feature = "test-utils"))]
compile_error!(
    "FATAL: 'test-utils' feature MUST NOT be compiled in release mode. \
     It is only for integration tests and dev builds."
);

// ─── Protocol Constants (SSOT) ───
pub mod constants;

// ─── DAA (block timing) ───
pub mod daa;

// ─── Narwhal/Bullshark Consensus (Sui-aligned) ───
pub mod narwhal_dag;
pub mod narwhal_finality;
pub mod narwhal_ordering;
pub mod narwhal_types;

// ─── Declarative test infrastructure (Sui Mysticeti-aligned) ───
#[cfg(any(test, feature = "test-utils"))]
pub mod testing;

// REMOVED: Q-DAG-CT verification (qdag_verify) — deprecated in v1.0.

// ═══════════════════════════════════════════════════════════════
//  Re-exports — Narwhal/Bullshark
// ═══════════════════════════════════════════════════════════════

pub use narwhal_types::block::MlDsa65Verifier;
pub use narwhal_types::block::{
    AuthorityIndex, Block as NarwhalBlock, BlockDigest, BlockRef, BlockSigner, BlockTimestampMs,
    CompactBlockMeta, Round, SignatureVerifier, Slot, Transaction as NarwhalTransaction,
    VerifiedBlock,
};
pub use narwhal_types::commit::{
    CommitDigest, CommitIndex, CommitRef, CommitVote, CommittedSubDag, LeaderStatus,
};
pub use narwhal_types::committee::{Authority, Committee, Stake};

pub use narwhal_dag::authority_node::{AuthorityNode, AuthorityNodeConfig, AuthorityNodeState};
pub use narwhal_dag::authority_service::AuthorityService;
pub use narwhal_dag::block_manager::{BlockAcceptResult, BlockManager};
pub use narwhal_dag::block_verifier::BlockVerifier;
pub use narwhal_dag::context::Context;
pub use narwhal_dag::core_engine::CoreEngine;
pub use narwhal_dag::dag_state::{
    BlockInfo, DagState, DagStateConfig, DagWriteBatch, Equivocation, PendingCommitVote,
};
pub use narwhal_dag::leader_schedule::{
    LeaderSchedule, ReputationScores, StakeAggregator, ThresholdClock, TimeoutBackoff,
};
pub use narwhal_dag::broadcaster::{Broadcaster, BroadcasterConfig, BroadcasterMetrics};
pub use narwhal_dag::block_subscriber::{BlockSubscriber, BlockSubscriberConfig, BlockSubscriberMetrics};
pub use narwhal_dag::commit_consumer::{
    ChannelCommitConsumer, CommitConsumer, CommitRecord, LogCommitConsumer, MultiConsumer,
};
pub use narwhal_dag::observer_service::{ObservedCommit, ObserverMetrics, ObserverService, QuorumProof};
pub use narwhal_dag::proposed_block_handler::{
    BroadcastSink, ProposalOutcome, ProposedBlockHandler, ProposedBlockHandlerMetrics, WalWriter,
};
pub use narwhal_dag::round_tracker::{
    PeerSyncStatus, RoundTracker, RoundTrackerConfig, RoundTrackerMetrics,
};
pub use narwhal_dag::synchronizer::{SyncRequest, Synchronizer, SynchronizerConfig};

pub use narwhal_ordering::base_committer::{BaseCommitter, Decision};
pub use narwhal_ordering::linearizer::{CommitFinalizer, LinearizedOutput, Linearizer};
pub use narwhal_ordering::universal_committer::UniversalCommitter;

// Phase 2c-B D9: BFT types gated behind #[cfg(test)].
#[cfg(test)]
pub use narwhal_finality::bft::{BftPhase, BftRound, VoteEquivocation};
pub use narwhal_finality::checkpoint_manager::{CheckpointManager, CHECKPOINT_INTERVAL};
pub use narwhal_finality::{
    Checkpoint, CheckpointDigest as NarwhalCheckpointDigest,
    CheckpointVote as NarwhalCheckpointVote, FinalizedCheckpoint,
};

pub use daa::{
    compute_block_rate, compute_bounded_past_median_time, compute_epoch, compute_past_median_time,
    validate_timestamp, DaaScore, DaaWindow, DaaWindowBlock, TimestampCheck, BLOCKS_PER_EPOCH,
    BOUNDED_MEDIAN_WINDOW, DAA_WINDOW_SIZE, MAX_FUTURE_DRIFT_MS, TARGET_BLOCK_INTERVAL_MS,
};
