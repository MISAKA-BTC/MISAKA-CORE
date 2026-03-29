//! Public PoS Consensus — PQ main path.
//!
//! All verification is MANDATORY. No fallback.
//!
//! # Module Architecture (v5.2 — BFT PoS)
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │  misaka-consensus                                       │
//! │                                                         │
//! │  ┌──────────────────┐  ┌───────────────────────────┐    │
//! │  │  BFT Protocol     │  │  GhostDAG Integration     │    │
//! │  │  bft_types        │  │  fork_choice              │    │
//! │  │  bft_state_machine│  │  block_validation         │    │
//! │  │  vrf_proposer     │  │  validation_pipeline      │    │
//! │  │  slash_detector   │  │  tx_resolve               │    │
//! │  └──────────────────┘  └───────────────────────────┘    │
//! │                                                         │
//! │  ┌──────────────────┐  ┌───────────────────────────┐    │
//! │  │  Finality         │  │  Economics                │    │
//! │  │  economic_finality│  │  staking                  │    │
//! │  │  finality         │  │  reward_epoch             │    │
//! │  │  checkpoint        │  │  zkp_budget              │    │
//! │  └──────────────────┘  └───────────────────────────┘    │
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
pub mod zkp_budget;

// ── BFT Consensus Protocol (v5.2) ──
// Tendermint/HotStuff hybrid with VRF proposer selection
// pub mod bft_types;
// pub mod bft_state_machine;
// pub mod vrf_proposer;
// pub mod slash_detector;
// pub mod fork_choice;
// pub mod bft_driver;

// ── Validator Workload + sqrt(stake) Epoch Rewards ──
pub mod reward_epoch;

// ── On-Chain Staking & Slashing ──
pub mod staking;

// ── Validator Selection System (v9) ──
// ADA-inspired: no slashing, saturation cap, linear credit,
// monthly rotation with max 3 demotions, Backup free-join.
pub mod p2p_mode;
pub mod validator_registry;
pub mod epoch_rotation;

pub use p2p_mode::{
    ActiveEndpointInfo, NodeConnectionMode, P2pConnectionRequirements,
    ReachabilityProbeResult, ValidatorNetworkProfile,
};
pub use validator_registry::{
    RegistryError, RotationConfig, ValidatorRecord,
    ValidatorRegistry, ValidatorRole, ACTIVE_SET_SIZE, MAX_DEMOTION_PER_EPOCH,
};
pub use validator_scoring::{
    active_contribution, backup_contribution, compute_score, ScoreBreakdown,
    ScoringConfig, ValidatorMetrics,
};
pub use validator_cooldown::{CooldownConfig, CooldownReason, CooldownRegistry};
pub use epoch_rotation::{
    DemotionRecord, EpochRotationEngine, PromotionRecord, RewardDistributor,
    RotationResult,
};
pub mod validator_scoring;
pub mod validator_rewards;
pub mod validator_cooldown;
pub mod validator_epoch;

// ── Delegation (DPoS) ──
// pub mod delegation;

// ── Inactivity Leak & Correlation Penalty (Nothing-at-Stake Defense) ──
// DEPRECATED [v9.1]: Replaced by validator_system_v2 (ADA-style, no-slash).
// pub mod inactivity;

// ── Weak Subjectivity (Long-Range Attack Prevention) ──
// pub mod weak_subjectivity;

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

// ── Unified Node System (v6) ──
// Single node type, automatic role assignment, relay protocol
// pub mod unified_node;
// pub mod role_scoring;
// pub mod relay_protocol;
// pub mod contribution;
// pub mod unified_reward;

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
pub use tx_resolve::{resolve_tx, resolve_tx_with_backend_family};
pub use validation_pipeline::*;
pub use validator_set::*;
pub use zkp_budget::{
    BudgetError, BudgetSummary, ZkpVerificationBudget, COST_BALANCE_EXCESS, COST_NULLIFIER_PROOF,
    COST_RANGE_PROOF, COST_UNIFIED_MEMBERSHIP, MAX_BLOCK_VERIFICATION_TIME,
    MAX_BLOCK_VERIFICATION_UNITS, MAX_BLOCK_ZKP_COUNT,
};

// ── Validator System V2 (ADA-style, no-slash) ──
pub use validator_system_v2::{
    ValidatorSystemV2, ValidatorSystemConfig, ValidatorAccountV2,
    ConnectionMode, ValidatorStatus, JailReason,
    Infraction, InfractionResult, EpochUpdateResult,
    ValidatorSystemError,
};
pub mod security;
pub mod mass;
pub mod pruning_logic;
pub mod sync_manager;
pub mod utxo_validation;
pub mod coinbase_validation;
pub mod header_processing;
pub mod sync_protocol;
pub mod acceptance_data;
pub mod virtual_state;
pub mod dag_traversal;
pub mod merge_set;
pub mod difficulty_adjustment;
pub mod chain_selection;
pub mod reachability_service;
pub mod ghostdag_service;
pub mod pruning_service;
pub mod tips_manager;
pub mod block_builder;
pub mod state_diff;
pub mod finality_service;
pub mod validation_rules;
pub mod block_status;
pub mod test_consensus;
pub mod block_window;
