//! RPC notification delivery interface.

/// Notification types that can be pushed to RPC clients.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum RpcNotification {
    BlockAdded { hash: String, blue_score: u64 },
    VirtualDaaScoreChanged { score: u64 },
    SinkBlueScoreChanged { score: u64 },
    NewBlockTemplate,
    UtxosChanged { added: Vec<serde_json::Value>, removed: Vec<serde_json::Value> },
    VirtualChainChanged { added: Vec<String>, removed: Vec<String> },
    FinalityConflict { hash: String },
    MempoolChanged { added: Vec<String>, removed: Vec<String> },
}
