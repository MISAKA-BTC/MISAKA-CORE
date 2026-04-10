//! Notification payload types.

use crate::events::EventType;

/// A notification payload.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Notification {
    pub event_type: EventType,
    pub payload: NotificationPayload,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum NotificationPayload {
    BlockAdded(BlockAddedNotification),
    VirtualChainChanged(VirtualChainChangedNotification),
    FinalityConflict(FinalityConflictNotification),
    UtxosChanged(UtxosChangedNotification),
    SinkBlueScoreChanged(SinkBlueScoreChangedNotification),
    VirtualDaaScoreChanged(VirtualDaaScoreChangedNotification),
    PruningPointUtxoSetOverride,
    NewBlockTemplate,
    MempoolChanged(MempoolChangedNotification),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlockAddedNotification {
    pub block_hash: String,
    pub blue_score: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VirtualChainChangedNotification {
    pub added_chain_block_hashes: Vec<String>,
    pub removed_chain_block_hashes: Vec<String>,
    pub accepted_transaction_ids: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FinalityConflictNotification {
    pub violating_block_hash: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UtxosChangedNotification {
    pub added: Vec<UtxoEntry>,
    pub removed: Vec<UtxoEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UtxoEntry {
    pub address: String,
    pub outpoint: String,
    pub amount: u64,
    pub script_public_key: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SinkBlueScoreChangedNotification {
    pub sink_blue_score: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VirtualDaaScoreChangedNotification {
    pub virtual_daa_score: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MempoolChangedNotification {
    pub added_tx_ids: Vec<String>,
    pub removed_tx_ids: Vec<String>,
}
