//! Collateral types (Cardano Vasil-style).
//!
//! Script transactions MUST provide collateral inputs. If script
//! validation fails (Phase 2), the collateral is consumed instead
//! of the regular inputs — incentivizing correct script usage.

use crate::utxo::OutputRef;
use borsh::{BorshDeserialize, BorshSerialize};

/// Maximum collateral inputs per transaction.
pub const MAX_COLLATERAL_INPUTS: usize = 3;

/// A collateral input: consumed only if script validation fails.
///
/// Collateral inputs MUST be pubkey-locked (no scripts) to ensure
/// they can always be consumed without script execution.
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
pub struct CollateralInput {
    pub outref: OutputRef,
}

/// Collateral return output: the change from collateral consumption.
///
/// Vasil improvement: instead of consuming the entire collateral,
/// the excess is returned to this output.
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
pub struct CollateralReturn {
    /// Address to receive the collateral change.
    pub address: [u8; 32],
    /// Value returned (must be <= total collateral - required collateral).
    pub value: super::value::AssetValue,
}
