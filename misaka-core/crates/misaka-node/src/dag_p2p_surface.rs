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
    pub last_message_kind: Option<String>,
    pub last_direction: Option<DagP2pDirection>,
    pub last_peer_prefix: Option<String>,
    pub by_surface: BTreeMap<DagP2pSurface, DagP2pSurfaceDirectionCount>,
    pub by_message_kind: BTreeMap<String, DagP2pSurfaceDirectionCount>,
    pub ingest_attempts: u64,
    pub ingest_accepted: u64,
    pub ingest_rejected: u64,
    pub ingest_fetch_parents: u64,
    pub ingest_timed_out: u64,
    pub ingest_errors: u64,
    pub last_ingest_block_prefix: Option<String>,
    pub last_ingest_reject_reason: Option<String>,
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
        let message_kind = dag_p2p_message_kind(message);
        self.total_messages += 1;
        self.last_surface = Some(surface);
        self.last_message_kind = Some(message_kind.to_string());
        self.last_direction = Some(direction);
        self.last_peer_prefix = peer_id.map(|id| hex::encode(&id[..4]));

        let entry = self.by_surface.entry(surface).or_default();
        match direction {
            DagP2pDirection::Inbound => entry.inbound += 1,
            DagP2pDirection::OutboundUnicast => entry.outbound_unicast += 1,
            DagP2pDirection::OutboundBroadcast => entry.outbound_broadcast += 1,
        }

        let entry = self
            .by_message_kind
            .entry(message_kind.to_string())
            .or_default();
        match direction {
            DagP2pDirection::Inbound => entry.inbound += 1,
            DagP2pDirection::OutboundUnicast => entry.outbound_unicast += 1,
            DagP2pDirection::OutboundBroadcast => entry.outbound_broadcast += 1,
        }
    }

    pub fn record_ingest_attempt(&mut self, block_hash: [u8; 32]) {
        self.ingest_attempts += 1;
        self.last_ingest_block_prefix = Some(hex::encode(&block_hash[..4]));
    }

    pub fn record_ingest_accepted(&mut self, block_hash: [u8; 32]) {
        self.ingest_accepted += 1;
        self.last_ingest_block_prefix = Some(hex::encode(&block_hash[..4]));
        self.last_ingest_reject_reason = None;
    }

    pub fn record_ingest_rejected(&mut self, block_hash: [u8; 32], reason: impl Into<String>) {
        self.ingest_rejected += 1;
        self.last_ingest_block_prefix = Some(hex::encode(&block_hash[..4]));
        self.last_ingest_reject_reason = Some(reason.into());
    }

    pub fn record_ingest_fetch_parents(&mut self, block_hash: [u8; 32]) {
        self.ingest_fetch_parents += 1;
        self.last_ingest_block_prefix = Some(hex::encode(&block_hash[..4]));
    }

    pub fn record_ingest_timed_out(&mut self, block_hash: [u8; 32]) {
        self.ingest_timed_out += 1;
        self.last_ingest_block_prefix = Some(hex::encode(&block_hash[..4]));
    }

    pub fn record_ingest_error(&mut self, block_hash: [u8; 32], reason: impl Into<String>) {
        self.ingest_errors += 1;
        self.last_ingest_block_prefix = Some(hex::encode(&block_hash[..4]));
        self.last_ingest_reject_reason = Some(reason.into());
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
        DagP2pMessage::GetBodies { .. } | DagP2pMessage::Bodies { .. } => DagP2pSurface::BodySync,
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
        DagP2pMessage::GetPeers | DagP2pMessage::Peers { .. } => DagP2pSurface::PeerDiscovery,
    }
}

pub fn dag_p2p_message_kind(message: &DagP2pMessage) -> &'static str {
    match message {
        DagP2pMessage::DagHello { .. } => "DagHello",
        DagP2pMessage::GetBlockLocator => "GetBlockLocator",
        DagP2pMessage::BlockLocator { .. } => "BlockLocator",
        DagP2pMessage::GetHeaders { .. } => "GetHeaders",
        DagP2pMessage::Headers { .. } => "Headers",
        DagP2pMessage::GetBodies { .. } => "GetBodies",
        DagP2pMessage::Bodies { .. } => "Bodies",
        DagP2pMessage::NewDagBlock { .. } => "NewDagBlock",
        DagP2pMessage::DagBlockData { .. } => "DagBlockData",
        DagP2pMessage::GetDagBlocks { .. } => "GetDagBlocks",
        DagP2pMessage::DagInventory { .. } => "DagInventory",
        DagP2pMessage::NewTx { .. } => "NewTx",
        DagP2pMessage::GetTx { .. } => "GetTx",
        DagP2pMessage::TxData { .. } => "TxData",
        DagP2pMessage::GetPruningProof => "GetPruningProof",
        DagP2pMessage::PruningProofData { .. } => "PruningProofData",
        DagP2pMessage::GetDagSnapshot { .. } => "GetDagSnapshot",
        DagP2pMessage::DagSnapshotData { .. } => "DagSnapshotData",
        DagP2pMessage::GetDagTips => "GetDagTips",
        DagP2pMessage::DagTips { .. } => "DagTips",
        DagP2pMessage::GetPeers => "GetPeers",
        DagP2pMessage::Peers { .. } => "Peers",
    }
}

pub fn observe_dag_p2p_message(
    direction: DagP2pDirection,
    message: &DagP2pMessage,
    peer_id: Option<&[u8; 20]>,
) {
    let surface = classify_dag_p2p_surface(message);
    let kind = dag_p2p_message_kind(message);
    let peer = peer_id
        .map(|id| hex::encode(&id[..4]))
        .unwrap_or_else(|| "broadcast".to_string());
    debug!(
        peer = %peer,
        direction = ?direction,
        surface = ?surface,
        message_kind = kind,
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
        assert_eq!(obs.last_message_kind.as_deref(), Some("GetDagTips"));
        assert_eq!(obs.last_direction, Some(DagP2pDirection::OutboundBroadcast));
        assert_eq!(obs.last_peer_prefix, None);

        let counts = obs
            .by_surface
            .get(&DagP2pSurface::SteadyStateRelay)
            .expect("surface counts");
        assert_eq!(counts.inbound, 1);
        assert_eq!(counts.outbound_broadcast, 1);

        let msg_counts = obs
            .by_message_kind
            .get("GetDagTips")
            .expect("message kind counts");
        assert_eq!(msg_counts.inbound, 1);
        assert_eq!(msg_counts.outbound_broadcast, 1);
    }

    #[test]
    fn test_observation_state_records_ingestion_outcomes() {
        let mut obs = DagP2pObservationState::default();
        let block = [0x11; 32];

        obs.record_ingest_attempt(block);
        obs.record_ingest_fetch_parents(block);
        obs.record_ingest_rejected(block, "missing parent");
        obs.record_ingest_error(block, "pipeline error");
        obs.record_ingest_timed_out(block);
        obs.record_ingest_accepted(block);

        assert_eq!(obs.ingest_attempts, 1);
        assert_eq!(obs.ingest_fetch_parents, 1);
        assert_eq!(obs.ingest_rejected, 1);
        assert_eq!(obs.ingest_errors, 1);
        assert_eq!(obs.ingest_timed_out, 1);
        assert_eq!(obs.ingest_accepted, 1);
        assert_eq!(obs.last_ingest_block_prefix.as_deref(), Some("11111111"));
        assert_eq!(obs.last_ingest_reject_reason, None);
    }
}
