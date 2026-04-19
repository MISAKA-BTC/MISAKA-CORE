//! Minting entries: create or destroy native assets.
//!
//! E1: Structure only. The mint list MUST be empty (enforced by
//! validate_structural). Minting logic is implemented in E3.

use super::value::AssetId;
use borsh::{BorshDeserialize, BorshSerialize};

/// A mint entry: creates (positive) or burns (negative) native assets.
///
/// Each entry references a minting policy script and specifies the
/// asset + quantity to mint/burn.
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
pub struct MintEntry {
    /// The asset being minted or burned.
    pub asset_id: AssetId,
    /// Positive = mint, negative = burn. i64 to support burning.
    pub quantity: i64,
}
