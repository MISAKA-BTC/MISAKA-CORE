//! Public PoS Consensus — PQ main path.
//!
//! All verification is MANDATORY. No fallback.

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

// ── Validator Workload + sqrt(stake) Epoch Rewards ──
pub mod reward_epoch;

// ── On-Chain Staking & Slashing ──
pub mod staking;

// ── Protocol Upgrade & Feature Activation ──
pub mod protocol_upgrade;

pub use block_validation::*;
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
