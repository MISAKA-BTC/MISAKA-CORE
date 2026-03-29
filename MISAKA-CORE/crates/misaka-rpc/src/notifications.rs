//! RPC notification delivery.

use serde::{Serialize, Deserialize};

/// Notification event types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum NotificationEvent {
    BlockAdded { hash: String, blue_score: u64 },
    VirtualChainChanged { added: Vec<String>, removed: Vec<String> },
    FinalityConflict { violating_hash: String },
    UtxosChanged { added: Vec<UtxoChange>, removed: Vec<UtxoChange> },
    SinkBlueScoreChanged { blue_score: u64 },
    VirtualDaaScoreChanged { daa_score: u64 },
    PruningPointUtxoSetOverride,
    NewBlockTemplate,
    MempoolChanged { added_tx_ids: Vec<String>, removed_tx_ids: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoChange {
    pub address: String,
    pub outpoint: String,
    pub amount: u64,
}

/// Notification delivery result.
pub struct DeliveryResult {
    pub delivered: usize,
    pub failed: usize,
    pub total_subscribers: usize,
}
