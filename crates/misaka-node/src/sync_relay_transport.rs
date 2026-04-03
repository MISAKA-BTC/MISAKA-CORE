use std::net::SocketAddr;

use tracing::debug;

use crate::p2p_network::P2pMessage;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyncRelayDirection {
    InboundRead,
    OutboundRead,
    OutboundWrite,
}

impl SyncRelayDirection {
    fn as_str(self) -> &'static str {
        match self {
            Self::InboundRead => "inbound-read",
            Self::OutboundRead => "outbound-read",
            Self::OutboundWrite => "outbound-write",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SyncRelaySurface {
    BlockAnnounce {
        height: u64,
        hash: [u8; 32],
        parent_hash: [u8; 32],
        timestamp_ms: u64,
        tx_count: usize,
        proposer_index: usize,
    },
    BlockRequest {
        height: u64,
    },
}

impl SyncRelaySurface {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::BlockAnnounce { .. } => "block-announce",
            Self::BlockRequest { .. } => "block-request",
        }
    }

    pub(crate) fn height(&self) -> u64 {
        match self {
            Self::BlockAnnounce { height, .. } | Self::BlockRequest { height } => *height,
        }
    }
}

pub(crate) fn classify_sync_relay_message(msg: &P2pMessage) -> Option<SyncRelaySurface> {
    match msg {
        P2pMessage::NewBlock {
            height,
            hash,
            parent_hash,
            timestamp_ms,
            tx_count,
            proposer_index,
        } => Some(SyncRelaySurface::BlockAnnounce {
            height: *height,
            hash: *hash,
            parent_hash: *parent_hash,
            timestamp_ms: *timestamp_ms,
            tx_count: *tx_count,
            proposer_index: *proposer_index,
        }),
        P2pMessage::RequestBlock { height } => {
            Some(SyncRelaySurface::BlockRequest { height: *height })
        }
        _ => None,
    }
}

#[cfg(test)]
pub(crate) fn is_sync_relay_message(msg: &P2pMessage) -> bool {
    classify_sync_relay_message(msg).is_some()
}

pub(crate) fn observe_sync_relay_message(
    direction: SyncRelayDirection,
    addr: SocketAddr,
    msg: &P2pMessage,
) -> bool {
    let Some(surface) = classify_sync_relay_message(msg) else {
        return false;
    };

    debug!(
        direction = %direction.as_str(),
        surface = %surface.label(),
        addr = %addr,
        height = surface.height(),
        "observed sync relay"
    );
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p_network::P2pMessage;

    #[test]
    fn test_sync_relay_classification_and_observation() {
        let announce = P2pMessage::NewBlock {
            height: 8,
            hash: [1u8; 32],
            parent_hash: [2u8; 32],
            timestamp_ms: 123,
            tx_count: 4,
            proposer_index: 2,
        };
        let request = P2pMessage::RequestBlock { height: 9 };
        let other = P2pMessage::Ping { nonce: 77 };
        let addr: SocketAddr = "127.0.0.1:6690".parse().unwrap();

        assert!(is_sync_relay_message(&announce));
        assert!(is_sync_relay_message(&request));
        assert!(!is_sync_relay_message(&other));
        assert!(observe_sync_relay_message(
            SyncRelayDirection::OutboundWrite,
            addr,
            &announce,
        ));
        assert!(!observe_sync_relay_message(
            SyncRelayDirection::InboundRead,
            addr,
            &other,
        ));
    }
}
