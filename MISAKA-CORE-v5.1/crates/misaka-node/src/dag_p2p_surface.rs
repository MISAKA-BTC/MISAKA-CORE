use misaka_dag::dag_p2p::DagP2pMessage;
use serde::Serialize;
use std::collections::BTreeMap;
use tracing::debug;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DagP2pDirection {
    Inbound,
    OutboundUnicast,
    OutboundBroadcast,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Serialize)]
pub enum DagP2pSurface {
    Handshake,
    SharedPastNegotiation,
    HeaderSync,
    BodySync,
    SteadyStateRelay,
    Inventory,
    TxRelay,
    PruningSync,
    SnapshotSync,
    PeerDiscovery,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DagP2pSurfaceDirectionCount {
    pub inbound: u64,
    pub outbound_unicast: u64,
    pub outbound_broadcast: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DagP2pObservationState {
    pub total_messages: u64,
    pub last_surface: Option<DagP2pSurface>,
    pub last_direction: Option<DagP2pDirection>,
    pub last_peer_prefix: Option<String>,
    pub by_surface: BTreeMap<DagP2pSurface, DagP2pSurfaceDirectionCount>,
    /// Peer addresses discovered via gossip, waiting for transport to connect.
    #[serde(skip)]
    pub discovered_peers: Vec<String>,
}

impl DagP2pObservationState {
    pub fn record(
        &mut self,
        direction: DagP2pDirection,
        message: &DagP2pMessage,
        peer_id: Option<&[u8; 20]>,
    ) {
        let surface = classify_dag_p2p_surface(message);
        self.total_messages += 1;
        self.last_surface = Some(surface);
        self.last_direction = Some(direction);
        self.last_peer_prefix = peer_id.map(|id| hex::encode(&id[..4]));

        let entry = self.by_surface.entry(surface).or_default();
        match direction {
            DagP2pDirection::Inbound => entry.inbound += 1,
            DagP2pDirection::OutboundUnicast => entry.outbound_unicast += 1,
            DagP2pDirection::OutboundBroadcast => entry.outbound_broadcast += 1,
        }
    }
}

pub fn classify_dag_p2p_surface(message: &DagP2pMessage) -> DagP2pSurface {
    match message {
        DagP2pMessage::DagHello { .. } => DagP2pSurface::Handshake,
        DagP2pMessage::GetBlockLocator | DagP2pMessage::BlockLocator { .. } => {
            DagP2pSurface::SharedPastNegotiation
        }
        DagP2pMessage::GetHeaders { .. } | DagP2pMessage::Headers { .. } => {
            DagP2pSurface::HeaderSync
        }
        DagP2pMessage::GetBodies { .. } | DagP2pMessage::Bodies { .. } => {
            DagP2pSurface::BodySync
        }
        DagP2pMessage::NewDagBlock { .. }
        | DagP2pMessage::DagBlockData { .. }
        | DagP2pMessage::GetDagBlocks { .. }
        | DagP2pMessage::GetDagTips
        | DagP2pMessage::DagTips { .. } => DagP2pSurface::SteadyStateRelay,
        DagP2pMessage::DagInventory { .. } => DagP2pSurface::Inventory,
        DagP2pMessage::NewTx { .. }
        | DagP2pMessage::GetTx { .. }
        | DagP2pMessage::TxData { .. } => DagP2pSurface::TxRelay,
        DagP2pMessage::GetPruningProof | DagP2pMessage::PruningProofData { .. } => {
            DagP2pSurface::PruningSync
        }
        DagP2pMessage::GetDagSnapshot { .. } | DagP2pMessage::DagSnapshotData { .. } => {
            DagP2pSurface::SnapshotSync
        }
        DagP2pMessage::GetPeers | DagP2pMessage::Peers { .. } => {
            DagP2pSurface::PeerDiscovery
        }
    }
}

pub fn observe_dag_p2p_message(
    direction: DagP2pDirection,
    message: &DagP2pMessage,
    peer_id: Option<&[u8; 20]>,
) {
    let surface = classify_dag_p2p_surface(message);
    let peer = peer_id
        .map(|id| hex::encode(&id[..4]))
        .unwrap_or_else(|| "broadcast".to_string());
    debug!(
        peer = %peer,
        direction = ?direction,
        surface = ?surface,
        message = ?std::mem::discriminant(message),
        "observed DAG P2P surface"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_dag_p2p_surface_categories() {
        assert_eq!(
            classify_dag_p2p_surface(&DagP2pMessage::DagHello {
                chain_id: 1,
                dag_version: 9,
                blue_score: 0,
                tips: vec![],
                pruning_point: [0u8; 32],
                node_name: "n".to_string(),
                mode: "validator".to_string(),
                listen_addr: None,
            }),
            DagP2pSurface::Handshake
        );
        assert_eq!(
            classify_dag_p2p_surface(&DagP2pMessage::BlockLocator {
                hashes: vec![],
                tip_blue_score: 0,
                pruning_point: [0u8; 32],
            }),
            DagP2pSurface::SharedPastNegotiation
        );
        assert_eq!(
            classify_dag_p2p_surface(&DagP2pMessage::Headers {
                headers_json: vec![],
                count: 0,
                has_more: false,
            }),
            DagP2pSurface::HeaderSync
        );
        assert_eq!(
            classify_dag_p2p_surface(&DagP2pMessage::Bodies { blocks: vec![] }),
            DagP2pSurface::BodySync
        );
        assert_eq!(
            classify_dag_p2p_surface(&DagP2pMessage::NewDagBlock {
                hash: [0u8; 32],
                parents: vec![],
                blue_score: 0,
                timestamp_ms: 0,
                tx_count: 0,
                proposer_id: [0u8; 32],
            }),
            DagP2pSurface::SteadyStateRelay
        );
        assert_eq!(
            classify_dag_p2p_surface(&DagP2pMessage::DagInventory {
                from_blue_score: 0,
                to_blue_score: 0,
                block_hashes: vec![],
            }),
            DagP2pSurface::Inventory
        );
        assert_eq!(
            classify_dag_p2p_surface(&DagP2pMessage::NewTx {
                tx_hash: [0u8; 32],
                fee: 0,
                size: 0,
            }),
            DagP2pSurface::TxRelay
        );
        assert_eq!(
            classify_dag_p2p_surface(&DagP2pMessage::GetPruningProof),
            DagP2pSurface::PruningSync
        );
        assert_eq!(
            classify_dag_p2p_surface(&DagP2pMessage::GetDagSnapshot {
                pruning_point: [0u8; 32],
            }),
            DagP2pSurface::SnapshotSync
        );
    }

    #[test]
    fn test_observation_state_records_counts() {
        let mut obs = DagP2pObservationState::default();
        let peer_id = [0xAB; 20];
        let msg = DagP2pMessage::GetDagTips;

        obs.record(DagP2pDirection::Inbound, &msg, Some(&peer_id));
        obs.record(DagP2pDirection::OutboundBroadcast, &msg, None);

        assert_eq!(obs.total_messages, 2);
        assert_eq!(obs.last_surface, Some(DagP2pSurface::SteadyStateRelay));
        assert_eq!(obs.last_direction, Some(DagP2pDirection::OutboundBroadcast));
        assert_eq!(obs.last_peer_prefix, None);

        let counts = obs
            .by_surface
            .get(&DagP2pSurface::SteadyStateRelay)
            .expect("surface counts");
        assert_eq!(counts.inbound, 1);
        assert_eq!(counts.outbound_broadcast, 1);
    }
}
