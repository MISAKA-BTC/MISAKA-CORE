//! Validity interval: slot range during which a transaction is valid.
//!
//! Scripts can inspect the validity interval to implement time-locks,
//! deadline-based logic, etc.

use borsh::{BorshDeserialize, BorshSerialize};

/// Validity interval: a half-open range [valid_from, valid_to).
///
/// Both bounds are optional:
/// - `None, None` = valid at any slot
/// - `Some(from), None` = valid from `from` onward
/// - `None, Some(to)` = valid until `to` (exclusive)
/// - `Some(from), Some(to)` = valid in [from, to)
///
/// Slot numbers correspond to commit indices (E4 maps these).
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct ValidityInterval {
    /// Earliest slot (commit_index) at which this tx is valid.
    pub valid_from: Option<u64>,
    /// Slot after which this tx is no longer valid (exclusive).
    pub valid_to: Option<u64>,
}
