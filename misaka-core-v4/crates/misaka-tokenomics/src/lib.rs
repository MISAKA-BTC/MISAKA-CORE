//! # MISAKA Tokenomics — 2-Role Model (v2)
//!
//! ## Canonical Supply
//!
//! - Solana is the canonical chain (10B MISAKA total supply)
//! - MISAKA L1 uses wMISAKA (wrapped representation)
//! - Bridge invariant: `outstanding_wMISAKA <= locked_MISAKA_on_Solana`
//! - 2B MISAKA reserved on Solana for validator reward subsidies
//!
//! ## Roles (exactly 2)
//!
//! | Role | Reward Pool | Scoring |
//! |------|------------|---------|
//! | **Validator** | 75% of weekly | stake^0.5 × (uptime × vote × correctness × bridge) |
//! | **Service** | 20% of weekly | uptime × relay × rpc × peer_diversity |
//! | *Burn* | 5% | — |
//!
//! ## Key Properties
//!
//! - Sub-linear stake weighting (α=0.5) reduces wealth concentration
//! - Multiplicative contribution prevents gaming single metrics
//! - Weekly backstop subsidy smooths reward volatility
//! - Proposer rewards capped at 20% per validator per week
//! - Service nodes require ≥80% uptime for any reward

pub mod canonical_supply;
pub mod reward_engine;

// Legacy modules (retained for backward compatibility, not used in v2 path)
pub mod distribution;
pub mod inflation;
pub mod supply;

// ═══════════════════════════════════════════════════════════════
//  Primary exports (v2 — 2-role model)
// ═══════════════════════════════════════════════════════════════

pub use canonical_supply::{
    CanonicalSupplyTracker, VerifiedLockProof, VerifiedBurnProof,
    SupplySnapshot, SupplyError,
    VALIDATOR_REWARD_RESERVE, DECIMALS, ONE_MISAKA,
};

pub use reward_engine::{
    // Constants
    TOTAL_SUPPLY, REWARD_RESERVE, RESERVE_DEPLETION_WEEKS, WEEKLY_RESERVE_CAP,
    ALPHA, VALIDATOR_POOL_BPS, SERVICE_POOL_BPS, BURN_POOL_BPS,
    PROPOSER_SUB_BPS, VALIDATOR_BASE_SUB_BPS, PROPOSER_CAP_BPS,
    SERVICE_MIN_UPTIME, DEFAULT_WEEKLY_TARGET,
    // Config
    RewardConfig,
    // Inputs
    ValidatorInput, ServiceNodeInput,
    // Outputs
    WeeklyDistribution, ValidatorRewardOutput, ServiceRewardOutput,
    // Errors
    RewardError,
    // Functions
    compute_weekly_distribution, execute_weekly, gini,
    // State
    ProtocolEconomicState,
};

// Legacy re-exports
pub use distribution::*;
pub use inflation::*;
pub use supply::*;
