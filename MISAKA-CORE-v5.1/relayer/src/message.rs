//! Shared message types for the bridge relayer.

use serde::{Serialize, Deserialize};

/// A Solana lock event detected by the relayer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockEvent {
    /// Unique event ID (hash of Solana tx signature + log index).
    pub id: String,
    /// SPL token mint address on Solana.
    pub asset_id: String,
    /// Amount locked (in base units).
    pub amount: u64,
    /// Recipient address on Misaka chain.
    pub misaka_recipient: String,
    /// Solana transaction signature.
    pub solana_tx_hash: String,
    /// Block slot on Solana.
    pub solana_slot: u64,
    /// Timestamp.
    pub timestamp: String,
}

/// A Misaka burn receipt ready for relay to Solana.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnReceipt {
    /// Unique receipt ID (hex of request_id).
    pub id: String,
    /// Asset being burned (wrapped token ID).
    pub asset_id: String,
    /// Amount burned.
    pub amount: u64,
    /// Recipient address on Solana.
    pub solana_recipient: String,
    /// Misaka block height where burn was finalized.
    pub misaka_height: u64,
    /// Request ID bytes (hex).
    pub request_id: String,
    /// Source TX hash on Misaka chain (hex, 32 bytes).
    #[serde(default)]
    pub source_tx_hash: String,
    /// Nonce for replay protection.
    #[serde(default)]
    pub nonce: u64,
}

impl BurnReceipt {
    /// Parse request_id hex to 32 bytes.
    pub fn request_id_bytes(&self) -> Option<[u8; 32]> {
        hex::decode(&self.request_id)
            .ok()
            .and_then(|v| v.try_into().ok())
    }
}
