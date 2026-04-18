//! Public PoS Consensus — PQ main path.
//!
//! All verification is MANDATORY. No fallback.
//!
//! # Module Architecture (v10 — DAG Consensus + Economic Layer)
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │  misaka-consensus (Economic / Validation Layer)          │
//! │                                                         │
//! │  ┌──────────────────┐  ┌───────────────────────────┐    │
//! │  │  Validation        │  │  Finality & Checkpoint    │    │
//! │  │  block_validation  │  │  finality                │    │
//! │  │  validation_pipeline│  │  economic_finality       │    │
//! │  │  tx_resolve        │  │  checkpoint              │    │
//! │  │  state_root        │  │                          │    │
//! │  └──────────────────┘  └───────────────────────────┘    │
//! │                                                         │
//! │  ┌──────────────────┐  ┌───────────────────────────┐    │
//! │  │  Staking/Epoch     │  │  Validator System (v9)    │    │
//! │  │  staking           │  │  validator_registry       │    │
//! │  │  reward_epoch      │  │  validator_system_v2      │    │
//! │  │  epoch_rotation    │  │  validator_scoring        │    │
//! │  │  epoch             │  │  equivocation_detector    │    │
//! │  └──────────────────┘  └───────────────────────────┘    │
//! │                                                         │
//! │  BFT consensus (block production, ordering, commit)      │
//! │  → Moved to misaka-dag/narwhal_dag/ (Phase 23)          │
//! └─────────────────────────────────────────────────────────┘
//! ```

pub mod block_validation;
pub mod checkpoint;
pub mod committee;
pub mod economic_finality;
pub mod epoch;
pub mod finality;
pub mod peer_scoring;
pub mod proposer;
pub mod safe_mode;
pub mod state_root;
pub mod tx_resolve;
pub mod validation_pipeline;
pub mod validator_set;
// REMOVED: pub mod zkp_budget — confidential TX cost accounting deprecated in v1.0.

// ── BFT Consensus Protocol (v5.2) ──
// Replaced by Narwhal/Bullshark DAG consensus in misaka-dag.
// Deleted: bft_types, bft_state_machine, vrf_proposer, slash_detector,
//          fork_choice, bft_driver (Phase 23).

// ── Validator Workload + sqrt(stake) Epoch Rewards ──
pub mod reward_epoch;

// ── Reputation metrics + reward history (Prompt 2D) ──
//
// Additive-only modules: record per-validator performance metrics and
// bounded reward history without modifying ValidatorRegistry /
// StakingRegistry / ValidatorSystemV2 / RewardEpochTracker.
//
// v0.8.0 semantics: metrics are recorded but NOT used for validator
// ranking (ranking uses self_stake only). See docs/internal/STAKING_MODEL.md.
// NOTE (PR C): `reputation`, `reward_history`, and `slashing` modules
// are declared in the merged snapshot but their source files are
// deferred to PR D (they depend on misaka-node common-file changes).
// Re-enable these `pub mod` lines when PR D lands.
// pub mod reputation;
// pub mod reward_history;
// pub mod slashing;

// ── On-Chain Staking & Slashing ──
pub mod staking;

// PR C: merged snapshot removed this module (stake-tx verification was
// refactored into a different pipeline), but misaka-node/utxo_executor.rs
// still imports `verify_stake_tx_signature` from here. Keep the module
// until PR D migrates misaka-node.
pub mod stake_tx_verify;
pub use stake_tx_verify::{verify_stake_tx_signature, StakeVerifyError};

// ── Validator Selection System (v9) ──
// ADA-inspired: no slashing, saturation cap, linear credit,
// monthly rotation with max 3 demotions, Backup free-join.
pub mod epoch_rotation;
pub mod p2p_mode;
pub mod validator_registry;

pub use epoch_rotation::{
    DemotionRecord, EpochRotationEngine, PromotionRecord, RewardDistributor, RotationResult,
};
pub use p2p_mode::{
    ActiveEndpointInfo, NodeConnectionMode, P2pConnectionRequirements, ReachabilityProbeResult,
    ValidatorNetworkProfile,
};
pub use validator_cooldown::{CooldownConfig, CooldownReason, CooldownRegistry};
pub use validator_registry::{
    RegistryError, RotationConfig, ValidatorRecord, ValidatorRegistry, ValidatorRole,
    ACTIVE_SET_SIZE, MAX_DEMOTION_PER_EPOCH,
};
pub use validator_scoring::{
    active_contribution, backup_contribution, compute_score, ScoreBreakdown, ScoringConfig,
    ValidatorMetrics,
};
pub mod validator_cooldown;
pub mod validator_epoch;
pub mod validator_rewards;
pub mod validator_scoring;

// ── Deleted modules (Phase 23) ──
// delegation.rs (594 lines) — replaced by validator_system_v2
// inactivity.rs — replaced by validator_system_v2 (ADA-style, no-slash)
// weak_subjectivity.rs (336 lines) — not needed for DAG consensus

// ── Protocol Upgrade & Feature Activation ──
pub mod protocol_upgrade;

// ═══════════════════════════════════════════════════════════════
//  Validator System V2 — ADA-Style No-Slash Design
//
//  Replaces: staking.rs (slashing), inactivity.rs (leak),
//            slash_detector.rs (evidence → slash)
//
//  元本没収なし。報酬減額 + スコア低下 + Active降格 で統制。
//  Active 21人固定、Backup自由参加、月次ローテーション。
// ═══════════════════════════════════════════════════════════════
pub mod validator_system_v2;

// ── Unified Node System (v6) — Deleted (Phase 23) ──
// unified_node.rs (331 lines), role_scoring.rs (390 lines) removed.
// Replaced by validator_registry + epoch_rotation.

pub use block_validation::*;

// ── New Kaspa-inspired subsystems (v10) ──
// Typed consensus stores backed by misaka-database
pub mod stores;
// 4-stage consensus pipeline: header → body → virtual → pruning
pub mod pipeline;
// Core consensus processes: GhostDAG, reachability, tx validation
pub mod processes;

pub use checkpoint::{
    AccumulatorProof, CheckpointAccumulator, ProductionCheckpoint, CHECKPOINT_PROTOCOL_VERSION,
};
pub use committee::*;
pub use economic_finality::{
    EconomicFinalityManager, FinalityCheckpoint, FinalityError, FinalizedEpoch,
    ValidatorAttestation, EPOCH_LENGTH, FINALITY_THRESHOLD,
};
pub use epoch::*;
pub use finality::*;
pub use peer_scoring::{PeerId, PeerScoring, PenaltyReason};
pub use proposer::*;
pub use state_root::{
    DiffDigest, IncrementalStateRoot, SignedCheckpoint, StateRoot, StateRootError,
    VerifiedCheckpoint,
};
pub use tx_resolve::resolve_tx;
pub use validation_pipeline::*;
pub use validator_set::*;
// REMOVED: zkp_budget re-exports — deprecated in v1.0.

// ── Validator System V2 (ADA-style, no-slash) ──
pub use validator_system_v2::{
    ConnectionMode, EpochUpdateResult, Infraction, InfractionResult, JailReason,
    ValidatorAccountV2, ValidatorStatus, ValidatorSystemConfig, ValidatorSystemError,
    ValidatorSystemV2,
};
pub mod architecture_target;
pub mod equivocation_detector;
pub mod pruning_logic;

// ── Phase 23: Dead code deleted (10,081 lines total) ──
// Pass 1 (7,387 lines): DAG duplicates of misaka-dag/narwhal_dag/
//   round_prober, leader_scoring, transaction_certifier, dag_state,
//   block_manager, commit_finalizer, core_engine, synchronizer,
//   ancestor_scoring, test_dag_builder, test_dag_parser.
// Pass 2 (2,694 lines): Orphan modules (commented out, 0 imports)
//   delegation (594), fork_choice (565), role_scoring (390),
//   unified_node (331), vrf_proposer (478), weak_subjectivity (336).
// See docs/refactor/CONSENSUS_DEDUP_INVENTORY.md for rationale.

pub use architecture_target::{
    completion_target_architecture, completion_target_checkpoint_decision_source,
    completion_target_committee_architecture, completion_target_committee_selection,
    completion_target_committee_size_cap, completion_target_committee_stage,
    completion_target_dissemination_stage, completion_target_ordering_input,
    completion_target_ordering_stage, consensus_architecture_summary,
    current_checkpoint_decision_source, current_committee_architecture,
    current_committee_selection, current_committee_size_cap, current_committee_stage,
    current_consensus_architecture, current_dissemination_stage, current_ordering_input,
    current_ordering_stage, CheckpointDecisionSource, CommitteeArchitecture, CommitteeSelection,
    CommitteeStage, CompletionTargetArchitecture, ConsensusArchitectureSummary,
    CurrentConsensusArchitecture, DisseminationArchitecture, DisseminationStage,
    FinalityArchitecture, OrderingArchitecture, OrderingInputSource, OrderingStage,
    PrivacyCompletionScope,
};
