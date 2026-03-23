//! # misaka-tokenomics — Fee-Only Reward Model + Supply + sqrt(stake) Weighting
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────┐
//! │                       misaka-tokenomics                            │
//! │                                                                    │
//! │  ── Existing ──────────────────  ── New (v4.1) ──────────────────  │
//! │  distribution.rs  — fee split    sqrt.rs      — isqrt_u128        │
//! │  inflation.rs     — schedule     workload.rs  — validator metrics  │
//! │  supply.rs        — cap/mint     reward.rs    — sqrt(stake)×score  │
//! └────────────────────────────────────────────────────────────────────┘
//! ```

// ── Existing modules (Spec 10) ──
pub mod distribution;
pub mod inflation;
pub mod supply;

// ── Block Reward (connects inflation + distribution → coinbase) ──
pub mod block_reward;

// ── New: Validator Workload + sqrt(stake) Reward Model ──
pub mod reward;
pub mod sqrt;
pub mod workload;

// ── Re-exports: Existing ──
pub use distribution::*;
pub use inflation::*;
pub use supply::*;

// ── Re-exports: New ──
pub use reward::{
    distribute_epoch_rewards, EpochRewardResult, RewardBreakdownSnapshot, RewardWeightConfig,
    ValidatorRewardInput,
};
pub use sqrt::{isqrt_u128, sqrt_scaled};
pub use workload::{
    compute_network_summary, compute_workload_score_from_raw, NetworkWorkloadSummary,
    ValidatorWorkloadSnapshot, WorkloadAccumulator, WorkloadConfig, WorkloadWeights,
};
