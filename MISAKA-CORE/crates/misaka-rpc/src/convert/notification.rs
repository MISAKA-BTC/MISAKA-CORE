//! Notification conversion from internal to RPC format.

use crate::api::notifications::RpcNotification;

pub fn block_added_notification(hash: [u8; 32], blue_score: u64) -> RpcNotification {
    RpcNotification::BlockAdded { hash: hex::encode(hash), blue_score }
}

pub fn daa_score_notification(score: u64) -> RpcNotification {
    RpcNotification::VirtualDaaScoreChanged { score }
}
