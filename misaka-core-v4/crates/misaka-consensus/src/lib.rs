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

pub use block_validation::*;
pub use committee::*;
pub use epoch::*;
pub use finality::*;
pub use peer_scoring::{PeerScoring, PeerId, PenaltyReason};
pub use proposer::*;
pub use tx_resolve::{resolve_tx, resolve_tx_with_backend_family};
pub use validation_pipeline::*;
pub use validator_set::*;
pub use zkp_budget::{
    ZkpVerificationBudget, BudgetError, BudgetSummary,
    MAX_BLOCK_VERIFICATION_UNITS, MAX_BLOCK_VERIFICATION_TIME, MAX_BLOCK_ZKP_COUNT,
    COST_UNIFIED_MEMBERSHIP, COST_RANGE_PROOF, COST_BALANCE_EXCESS, COST_NULLIFIER_PROOF,
};
pub use state_root::{
    StateRoot, IncrementalStateRoot, DiffDigest, SignedCheckpoint, VerifiedCheckpoint, StateRootError,
};
pub use economic_finality::{
    EconomicFinalityManager, FinalityCheckpoint, FinalizedEpoch,
    ValidatorAttestation, FinalityError, EPOCH_LENGTH, FINALITY_THRESHOLD,
};
pub use checkpoint::{
    ProductionCheckpoint, CheckpointAccumulator, AccumulatorProof,
    CHECKPOINT_PROTOCOL_VERSION,
};
