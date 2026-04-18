//! Multi-asset value type (Cardano Mary-style native assets).
//!
//! `AssetValue` extends the base MLP (MISAKA Ledger Picocoin) amount
//! with a canonical BTreeMap of native asset balances.

use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::BTreeMap;

/// Maximum number of distinct native assets in a single value.
pub const MAX_ASSETS_PER_VALUE: usize = 64;

/// Maximum asset name length in bytes.
pub const MAX_ASSET_NAME_LEN: usize = 32;

/// Multi-asset value: base MLP amount + native asset bundle.
///
/// The `native_assets` map MUST be in canonical BTreeMap ordering
/// (sorted by AssetId). This is enforced by the BTreeMap container.
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
pub struct AssetValue {
    /// Base MLP (MISAKA Ledger Picocoin) amount.
    pub mlp: u64,
    /// Native asset balances, keyed by AssetId.
    /// Empty map = pure MLP transfer (no native assets).
    pub native_assets: BTreeMap<AssetId, u64>,
}

impl AssetValue {
    /// Pure MLP value with no native assets.
    pub fn mlp_only(amount: u64) -> Self {
        Self {
            mlp: amount,
            native_assets: BTreeMap::new(),
        }
    }

    /// Whether this value contains any native assets.
    pub fn has_native_assets(&self) -> bool {
        !self.native_assets.is_empty()
    }
}

impl Default for AssetValue {
    fn default() -> Self {
        Self::mlp_only(0)
    }
}

/// Unique identifier for a native asset: policy hash + asset name.
///
/// Cardano equivalent: PolicyId + AssetName.
/// The policy is a script hash that controls minting/burning (E3).
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct AssetId {
    /// Minting policy script hash (SHA3-256, 32 bytes).
    pub policy: [u8; 32],
    /// Human-readable asset name (max 32 bytes, UTF-8 recommended).
    pub asset_name: AssetName,
}

/// Asset name: arbitrary bytes, max 32 bytes.
///
/// Empty name is valid (represents the "default" token under a policy).
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct AssetName(pub Vec<u8>);

impl AssetName {
    pub fn is_valid(&self) -> bool {
        self.0.len() <= MAX_ASSET_NAME_LEN
    }
}
