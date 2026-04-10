//! Convert internal events to notification payloads.

use crate::notification::*;

/// Convert a block hash to a BlockAdded notification.
pub fn block_added(hash: [u8; 32], blue_score: u64) -> Notification {
    Notification {
        event_type: crate::events::EventType::BlockAdded,
        payload: NotificationPayload::BlockAdded(BlockAddedNotification {
            block_hash: hex::encode(hash),
            blue_score,
        }),
    }
}

/// Convert to a VirtualDaaScoreChanged notification.
pub fn daa_score_changed(score: u64) -> Notification {
    Notification {
        event_type: crate::events::EventType::VirtualDaaScoreChanged,
        payload: NotificationPayload::VirtualDaaScoreChanged(VirtualDaaScoreChangedNotification {
            virtual_daa_score: score,
        }),
    }
}

/// Convert to a SinkBlueScoreChanged notification.
pub fn blue_score_changed(score: u64) -> Notification {
    Notification {
        event_type: crate::events::EventType::SinkBlueScoreChanged,
        payload: NotificationPayload::SinkBlueScoreChanged(SinkBlueScoreChangedNotification {
            sink_blue_score: score,
        }),
    }
}

/// New block template available.
pub fn new_block_template() -> Notification {
    Notification {
        event_type: crate::events::EventType::NewBlockTemplate,
        payload: NotificationPayload::NewBlockTemplate,
    }
}
