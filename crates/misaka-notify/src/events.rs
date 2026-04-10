//! Event type definitions for the notification system.

/// All possible event types that can be subscribed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum EventType {
    BlockAdded,
    VirtualChainChanged,
    FinalityConflict,
    FinalityConflictResolved,
    UtxosChanged,
    SinkBlueScoreChanged,
    VirtualDaaScoreChanged,
    PruningPointUtxoSetOverride,
    NewBlockTemplate,
    MempoolChanged,
}

impl EventType {
    pub fn all() -> &'static [EventType] {
        &[
            EventType::BlockAdded,
            EventType::VirtualChainChanged,
            EventType::FinalityConflict,
            EventType::FinalityConflictResolved,
            EventType::UtxosChanged,
            EventType::SinkBlueScoreChanged,
            EventType::VirtualDaaScoreChanged,
            EventType::PruningPointUtxoSetOverride,
            EventType::NewBlockTemplate,
            EventType::MempoolChanged,
        ]
    }
}
