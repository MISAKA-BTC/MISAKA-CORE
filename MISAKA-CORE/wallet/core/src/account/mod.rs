//! Account abstraction for multi-account wallet support.
//!
//! Supports multiple account types:
//! - BIP32-style hierarchical deterministic accounts
//! - Multisig accounts with M-of-N threshold
//! - Watch-only accounts (public keys only)
//! - Hardware wallet proxy accounts
//! - Post-quantum enhanced accounts

pub mod bip32;
pub mod multisig;
pub mod watchonly;
pub mod hardware;
pub mod derivation;

use serde::{Serialize, Deserialize};

/// Unique account identifier.
pub type AccountId = u64;

/// Account types supported by the wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountKind {
    /// Standard BIP32-derived account.
    Bip32,
    /// Multi-signature account.
    MultiSig,
    /// Watch-only account (no spending keys).
    WatchOnly,
    /// Hardware wallet proxy.
    Hardware,
    /// Post-quantum native account (ML-DSA-65 + ML-KEM-768).
    PostQuantum,
}

/// Common account metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountMeta {
    pub id: AccountId,
    pub name: String,
    pub kind: AccountKind,
    pub created_at: u64,
    pub is_active: bool,
    pub receive_address_index: u32,
    pub change_address_index: u32,
    pub balance_cache: Option<u64>,
}

impl AccountMeta {
    pub fn new(id: AccountId, name: String, kind: AccountKind) -> Self {
        Self {
            id,
            name,
            kind,
            created_at: 0,
            is_active: true,
            receive_address_index: 0,
            change_address_index: 0,
            balance_cache: None,
        }
    }
}

/// Account interface trait.
pub trait Account: Send + Sync {
    fn meta(&self) -> &AccountMeta;
    fn kind(&self) -> AccountKind;
    fn receive_address(&self) -> String;
    fn change_address(&self) -> String;
    fn next_receive_address(&mut self) -> String;
    fn next_change_address(&mut self) -> String;
    fn can_sign(&self) -> bool;
}
