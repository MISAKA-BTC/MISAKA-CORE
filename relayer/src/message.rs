//! Shared message types for the Burn & Mint bridge relayer.

use serde::{Deserialize, Serialize};

/// Status of a burn event through the relay pipeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BurnStatus {
    /// Burn transaction detected on Solana but not yet verified.
    Detected,
    /// Burn verified against on-chain data.
    Verified,
    /// Mint request submitted to MISAKA chain.
    MintRequested,
    /// Mint confirmed on MISAKA chain.
    MintCompleted,
    /// Mint failed (with reason).
    MintFailed(String),
}

impl BurnStatus {
    /// Convert to a string suitable for SQLite storage.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Detected => "detected",
            Self::Verified => "verified",
            Self::MintRequested => "mint_requested",
            Self::MintCompleted => "mint_completed",
            Self::MintFailed(_) => "mint_failed",
        }
    }

    /// Parse from SQLite status string + optional error message.
    pub fn from_db(status: &str, error_msg: Option<&str>) -> Self {
        match status {
            "detected" => Self::Detected,
            "verified" => Self::Verified,
            "mint_requested" => Self::MintRequested,
            "mint_completed" => Self::MintCompleted,
            "mint_failed" => Self::MintFailed(error_msg.unwrap_or("unknown").to_string()),
            _ => Self::Detected,
        }
    }
}

/// A Solana SPL Token Burn event detected by the relayer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnEvent {
    /// Unique event ID: hex(SHA3-256(tx_sig + burn_index)).
    pub id: String,
    /// Solana transaction signature (base58).
    pub solana_tx_signature: String,
    /// SPL token mint address on Solana (base58).
    pub mint_address: String,
    /// Token account owner (wallet) on Solana (base58).
    pub wallet_address: String,
    /// Amount burned in raw base units (u64, no floating point).
    pub burn_amount_raw: u64,
    /// Solana slot where the burn was finalized.
    pub slot: u64,
    /// Block timestamp (unix seconds).
    pub block_time: i64,
    /// Current processing status.
    pub status: BurnStatus,
}

/// Result of verifying a burn transaction on-chain.
#[derive(Debug, Clone)]
pub struct VerifiedBurn {
    /// Burn amount in raw base units.
    pub amount: u64,
    /// Wallet (owner) that burned tokens.
    pub wallet: String,
    /// SPL token mint address.
    pub mint: String,
    /// Solana slot of the transaction.
    pub slot: u64,
    /// Block timestamp (unix seconds).
    pub block_time: i64,
    /// Index of the burn instruction within the transaction.
    pub burn_index: usize,
}

/// Address registration: maps a Solana wallet to a MISAKA receive address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressRegistration {
    /// Solana wallet address (base58).
    pub wallet_address: String,
    /// MISAKA chain receive address.
    pub misaka_receive_address: String,
}
