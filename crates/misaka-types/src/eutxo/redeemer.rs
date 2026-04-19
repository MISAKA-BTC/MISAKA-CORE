//! Redeemer: data + budget provided to a script at validation time.

use borsh::{BorshDeserialize, BorshSerialize};

/// Maximum redeemer data size.
pub const MAX_REDEEMER_SIZE: usize = 16_384;

/// Redeemer purpose: which aspect of the transaction this redeemer validates.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum RedeemerPurpose {
    /// Spending a script-locked input at the given index.
    Spend(u32),
    /// Minting/burning under a policy at the given index in the mint list.
    Mint(u32),
    /// Certifying (reserved for governance, E8+).
    Cert(u32),
    /// Rewarding (reserved for staking rewards, E8+).
    Reward(u32),
}

/// A redeemer: data passed to a script + execution budget.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct Redeemer {
    /// Which script this redeemer is for.
    pub purpose: RedeemerPurpose,
    /// Arbitrary data passed to the script (CBOR or borsh, script-defined).
    pub data: Vec<u8>,
    /// Execution budget allocated to this script invocation.
    /// RESERVED for E2 — set to ExUnits::zero() in E1.
    pub ex_units: super::cost_model::ExUnits,
}
