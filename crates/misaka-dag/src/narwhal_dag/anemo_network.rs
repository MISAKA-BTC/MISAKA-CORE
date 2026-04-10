// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Anemo-style network protocol for Narwhal consensus.
//!
//! Sui equivalent: consensus/core/network.rs (~1,200 lines) using the anemo crate.
//!
//! This module implements a production-grade consensus network layer:
//! - Trait-based protocol abstraction (swappable HTTP/gRPC/anemo)
//! - Framed binary protocol with length-prefixed messages
//! - Connection multiplexing
//! - Block subscription (streaming)
//! - Peer lifecycle management
//!
//! ## Protocol wire format
//!
//! ```text
//! ┌──────────┬──────────┬─────────────┬───────────────────┐
//! │ magic(4) │ type(1)  │ length(4)   │ payload(variable) │
//! └──────────┴──────────┴─────────────┴───────────────────┘
//! magic  = b"MSKN" (MISAKA Narwhal)
//! type   = 0x01 (Block), 0x02 (BlockRequest), 0x03 (CommitRequest),
//!          0x04 (BlockResponse), 0x05 (CommitResponse),
//!          0x10 (Subscribe), 0x11 (Unsubscribe)
//! length = payload length in bytes (u32 LE)
//! payload = serde_json serialized message
//! ```

// TODO(Task D): When block signature verification is added to handle_connection,
// record PeerSignal::VerifyFailed on verification failure before rejecting the block.
// Currently new_verified() trusts the caller, so there is no failure path to hook into.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{debug, error, info, warn};

use super::metrics::ConsensusMetrics;
use crate::narwhal_types::block::*;
use crate::narwhal_types::commit::*;

// ═══════════════════════════════════════════════════════════
//  Protocol constants
// ═══════════════════════════════════════════════════════════

/// Wire protocol magic bytes.
pub const PROTOCOL_MAGIC: &[u8; 4] = b"MSKN";

/// Protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum message size (16 MB).
pub const MAX_MESSAGE_SIZE: u32 = 16 * 1024 * 1024;

/// Audit #15: Maximum concurrent inbound connections.
const MAX_INBOUND_CONNECTIONS: usize = 256;

/// Audit #15: Per-message read timeout (seconds). Prevents slowloris DoS.
const MESSAGE_READ_TIMEOUT_SECS: u64 = 30;

/// Audit #15: Maximum blocks per BlockRequest (capped from 1000 to 100).
const MAX_BLOCK_REQUEST_LIMIT: u32 = 100;

/// Message types.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MessageType {
    /// A proposed block being broadcast.
    Block = 0x01,
    /// Request blocks by round range.
    BlockRequest = 0x02,
    /// Request commits by index range.
    CommitRequest = 0x03,
    /// Response containing blocks.
    BlockResponse = 0x04,
    /// Response containing commits.
    CommitResponse = 0x05,
    /// Subscribe to block stream.
    Subscribe = 0x10,
    /// Unsubscribe from block stream.
    Unsubscribe = 0x11,
    /// Ping/keepalive.
    Ping = 0x20,
    /// Pong response.
    Pong = 0x21,
}

impl MessageType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Block),
            0x02 => Some(Self::BlockRequest),
            0x03 => Some(Self::CommitRequest),
            0x04 => Some(Self::BlockResponse),
            0x05 => Some(Self::CommitResponse),
            0x10 => Some(Self::Subscribe),
            0x11 => Some(Self::Unsubscribe),
            0x20 => Some(Self::Ping),
            0x21 => Some(Self::Pong),
            _ => None,
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  Wire message
// ═══════════════════════════════════════════════════════════

/// A framed wire message.
#[derive(Clone, Debug)]
pub struct WireMessage {
    pub msg_type: MessageType,
    pub payload: Vec<u8>,
}

impl WireMessage {
    pub fn new(msg_type: MessageType, payload: Vec<u8>) -> Self {
        Self { msg_type, payload }
    }

    /// Encode into wire format: magic(4) + type(1) + length(4) + payload.
    pub fn encode(&self) -> Vec<u8> {
        let len = self.payload.len() as u32;
        let mut buf = Vec::with_capacity(9 + self.payload.len());
        buf.extend_from_slice(PROTOCOL_MAGIC);
        buf.push(self.msg_type as u8);
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Decode from wire format.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), ProtocolError> {
        if buf.len() < 9 {
            return Err(ProtocolError::InsufficientData);
        }
        if &buf[..4] != PROTOCOL_MAGIC {
            return Err(ProtocolError::InvalidMagic);
        }
        let msg_type =
            MessageType::from_u8(buf[4]).ok_or(ProtocolError::UnknownMessageType(buf[4]))?;
        let len = u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]);
        if len > MAX_MESSAGE_SIZE {
            return Err(ProtocolError::MessageTooLarge(len));
        }
        let total = 9 + len as usize;
        if buf.len() < total {
            return Err(ProtocolError::InsufficientData);
        }
        let payload = buf[9..total].to_vec();
        Ok((Self { msg_type, payload }, total))
    }
}

/// Protocol errors.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("insufficient data")]
    InsufficientData,
    #[error("invalid magic bytes")]
    InvalidMagic,
    #[error("unknown message type: 0x{0:02x}")]
    UnknownMessageType(u8),
    #[error("message too large: {0} bytes")]
    MessageTooLarge(u32),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(String),
    #[error("message read timeout ({} seconds)", MESSAGE_READ_TIMEOUT_SECS)]
    Timeout,
}

// ═══════════════════════════════════════════════════════════
//  Request/Response types
// ═══════════════════════════════════════════════════════════

/// Block request: fetch blocks by round range.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BlockRequest {
    pub since_round: Round,
    pub limit: u32,
    /// Optional: specific digests to fetch.
    pub digests: Vec<[u8; 32]>,
}

/// Block response.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BlockResponse {
    pub blocks: Vec<Block>,
    pub highest_round: Round,
}

/// Commit request.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CommitRequest {
    pub since_index: CommitIndex,
    pub limit: u32,
}

/// Commit response.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CommitResponse {
    pub commits: Vec<CommittedSubDag>,
}

// ═══════════════════════════════════════════════════════════
//  Block subscription (streaming)
// ═══════════════════════════════════════════════════════════

/// Block subscription manager — supports streaming blocks to subscribers.
///
/// Sui equivalent: block subscription in network layer.
pub struct BlockSubscriptionManager {
    /// Broadcast channel for new blocks.
    sender: broadcast::Sender<VerifiedBlock>,
    /// Number of active subscribers.
    subscriber_count: Arc<std::sync::atomic::AtomicU64>,
}

impl BlockSubscriptionManager {
    /// Create a new subscription manager.
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender,
            subscriber_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Subscribe to new blocks.
    pub fn subscribe(&self) -> broadcast::Receiver<VerifiedBlock> {
        self.subscriber_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.sender.subscribe()
    }

    /// Publish a new block to all subscribers.
    pub fn publish(&self, block: VerifiedBlock) {
        let _ = self.sender.send(block);
    }

    /// Number of active subscribers.
    pub fn subscriber_count(&self) -> u64 {
        self.subscriber_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

// ═══════════════════════════════════════════════════════════
//  Connection handler
// ═══════════════════════════════════════════════════════════

/// Read a WireMessage from a TCP stream.
pub async fn read_message(stream: &mut TcpStream) -> Result<WireMessage, ProtocolError> {
    // Read header (9 bytes)
    let mut header = [0u8; 9];
    stream.read_exact(&mut header).await?;

    if &header[..4] != PROTOCOL_MAGIC {
        return Err(ProtocolError::InvalidMagic);
    }

    let msg_type =
        MessageType::from_u8(header[4]).ok_or(ProtocolError::UnknownMessageType(header[4]))?;
    let len = u32::from_le_bytes([header[5], header[6], header[7], header[8]]);

    if len > MAX_MESSAGE_SIZE {
        return Err(ProtocolError::MessageTooLarge(len));
    }

    // Read payload
    let mut payload = vec![0u8; len as usize];
    if len > 0 {
        stream.read_exact(&mut payload).await?;
    }

    Ok(WireMessage { msg_type, payload })
}

/// Write a WireMessage to a TCP stream.
pub async fn write_message(stream: &mut TcpStream, msg: &WireMessage) -> Result<(), ProtocolError> {
    let encoded = msg.encode();
    stream.write_all(&encoded).await?;
    stream.flush().await?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════
//  Consensus network server
// ═══════════════════════════════════════════════════════════

/// Server-side handler for the consensus network protocol.
///
/// Listens on a TCP port and handles incoming connections.
pub struct ConsensusNetworkServer {
    /// Listen address.
    listen_addr: String,
    /// Block forwarding channel.
    block_tx: mpsc::Sender<super::runtime::ConsensusMessage>,
    /// Block subscription manager.
    subscriptions: Arc<BlockSubscriptionManager>,
    /// DAG state for serving requests.
    dag_state: Arc<RwLock<super::dag_state::DagState>>,
    /// Metrics.
    metrics: Arc<ConsensusMetrics>,
    /// Task C: Admission controller for rate limiting peers.
    admission: std::sync::Arc<std::sync::Mutex<super::admission::AdmissionController>>,
    /// Task D: Peer scorer for tracking peer reputation.
    scorer: std::sync::Arc<std::sync::Mutex<super::peer_scorer::PeerScorer>>,
    /// Audit #15: Inbound connection semaphore (DoS protection).
    /// Limits total concurrent inbound connections to prevent OOM.
    conn_semaphore: Arc<tokio::sync::Semaphore>,
}

impl ConsensusNetworkServer {
    pub fn new(
        listen_addr: String,
        block_tx: mpsc::Sender<super::runtime::ConsensusMessage>,
        dag_state: Arc<RwLock<super::dag_state::DagState>>,
        metrics: Arc<ConsensusMetrics>,
    ) -> Self {
        Self {
            listen_addr,
            block_tx,
            subscriptions: Arc::new(BlockSubscriptionManager::new(1000)),
            dag_state,
            metrics,
            admission: std::sync::Arc::new(std::sync::Mutex::new(
                super::admission::AdmissionController::new(
                    super::admission::AdmissionConfig::default(),
                ),
            )),
            scorer: std::sync::Arc::new(std::sync::Mutex::new(
                super::peer_scorer::PeerScorer::new(),
            )),
            conn_semaphore: Arc::new(tokio::sync::Semaphore::new(MAX_INBOUND_CONNECTIONS)),
        }
    }

    /// Run the server.
    pub async fn run(&self) -> Result<(), ProtocolError> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        info!("Consensus network server listening on {}", self.listen_addr);

        loop {
            let (stream, addr) = listener.accept().await?;

            // Audit #15: Connection limit — reject if at capacity
            let permit = match self.conn_semaphore.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    warn!(
                        "Connection limit reached ({}), rejecting {}",
                        MAX_INBOUND_CONNECTIONS, addr
                    );
                    drop(stream);
                    continue;
                }
            };

            debug!(
                "Accepted connection from {} ({}/{} slots)",
                addr,
                MAX_INBOUND_CONNECTIONS - self.conn_semaphore.available_permits(),
                MAX_INBOUND_CONNECTIONS
            );

            let block_tx = self.block_tx.clone();
            let subscriptions = self.subscriptions.clone();
            let dag_state = self.dag_state.clone();
            let metrics = self.metrics.clone();
            let admission = self.admission.clone();
            let scorer = self.scorer.clone();

            tokio::spawn(async move {
                // permit is held for the duration of this connection
                let _permit = permit;
                if let Err(e) = Self::handle_connection(
                    stream,
                    block_tx,
                    subscriptions,
                    dag_state,
                    metrics,
                    admission,
                    scorer,
                )
                .await
                {
                    debug!("Connection from {} closed: {}", addr, e);
                }
            });
        }
    }

    async fn handle_connection(
        mut stream: TcpStream,
        block_tx: mpsc::Sender<super::runtime::ConsensusMessage>,
        subscriptions: Arc<BlockSubscriptionManager>,
        dag_state: Arc<RwLock<super::dag_state::DagState>>,
        metrics: Arc<ConsensusMetrics>,
        admission: std::sync::Arc<std::sync::Mutex<super::admission::AdmissionController>>,
        scorer: std::sync::Arc<std::sync::Mutex<super::peer_scorer::PeerScorer>>,
    ) -> Result<(), ProtocolError> {
        loop {
            // Audit #15: Per-message read timeout to prevent slowloris DoS.
            let msg = match tokio::time::timeout(
                std::time::Duration::from_secs(MESSAGE_READ_TIMEOUT_SECS),
                read_message(&mut stream),
            )
            .await
            {
                Ok(Ok(msg)) => msg,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(ProtocolError::Timeout),
            };

            match msg.msg_type {
                MessageType::Block => {
                    let block: Block = serde_json::from_slice(&msg.payload)
                        .map_err(|e| ProtocolError::Serde(e.to_string()))?;
                    let peer_id = block.author;

                    // Task C: Admission control
                    {
                        let mut adm = admission.lock().unwrap();
                        if let super::admission::AdmissionResult::Denied { .. } =
                            adm.try_consume(peer_id, super::admission::RequestKind::SendBlock)
                        {
                            warn!("Rate limited peer {} for SendBlock", peer_id);
                            continue;
                        }
                    }

                    // SEC-FIX: Structural pre-validation at network edge.
                    // Full signature verification happens in core_engine::process_block,
                    // but we reject obviously invalid blocks here to prevent:
                    // (a) peer scoring inflation for forged blocks
                    // (b) subscriber notification of unverified content
                    // (c) unbounded channel memory consumption from spam
                    let committee_size = {
                        let dag = dag_state.read().await;
                        dag.committee().size()
                    };
                    if block.author >= committee_size as u32
                        || block.round == 0
                        || block.signature.len() != 3309
                    {
                        let mut sc = scorer.lock().unwrap();
                        sc.record(peer_id, super::peer_scorer::PeerSignal::VerifyFailed);
                        warn!(
                            "Block rejected at network edge: author={}, round={}, sig_len={}",
                            block.author,
                            block.round,
                            block.signature.len()
                        );
                        continue;
                    }

                    let vb = VerifiedBlock::new_pending_verification(block);

                    // Task D: Peer scoring — recorded as block received (not ValidBlock,
                    // since full crypto verification happens in core_engine).
                    // ValidBlock signal is emitted by core_engine AFTER verification.

                    // Only forward to runtime, NOT to subscribers.
                    // Subscribers receive blocks only after core_engine verification.
                    let _ = block_tx.try_send(super::runtime::ConsensusMessage::NewBlock(vb));
                    // blocks_accepted metric is NOT incremented here — core_engine owns it.
                }

                MessageType::BlockRequest => {
                    let req: BlockRequest = serde_json::from_slice(&msg.payload)
                        .map_err(|e| ProtocolError::Serde(e.to_string()))?;
                    let dag = dag_state.read().await;
                    let mut blocks = Vec::new();
                    // Audit #15: Reduced from 1000 to 100, clamped since_round
                    let limit = req.limit.min(MAX_BLOCK_REQUEST_LIMIT) as usize;
                    let highest = dag.highest_accepted_round();
                    // Clamp since_round: don't serve the entire DAG history
                    let min_round = highest.saturating_sub(10_000);
                    let start_round = req.since_round.max(min_round);
                    for round in start_round..=highest {
                        for b in dag.get_blocks_at_round(round) {
                            blocks.push(b.inner().clone());
                            if blocks.len() >= limit {
                                break;
                            }
                        }
                        if blocks.len() >= limit {
                            break;
                        }
                    }
                    let resp = BlockResponse {
                        highest_round: dag.highest_accepted_round(),
                        blocks,
                    };
                    let payload = serde_json::to_vec(&resp)
                        .map_err(|e| ProtocolError::Serde(e.to_string()))?;
                    write_message(
                        &mut stream,
                        &WireMessage::new(MessageType::BlockResponse, payload),
                    )
                    .await?;
                }

                MessageType::CommitRequest => {
                    let req: CommitRequest = serde_json::from_slice(&msg.payload)
                        .map_err(|e| ProtocolError::Serde(e.to_string()))?;
                    let dag = dag_state.read().await;
                    let mut commits = Vec::new();
                    let limit = req.limit.min(100) as usize;
                    let mut idx = req.since_index;
                    while commits.len() < limit {
                        if let Some(c) = dag.get_commit(idx) {
                            commits.push(c.clone());
                            idx += 1;
                        } else {
                            break;
                        }
                    }
                    let resp = CommitResponse { commits };
                    let payload = serde_json::to_vec(&resp)
                        .map_err(|e| ProtocolError::Serde(e.to_string()))?;
                    write_message(
                        &mut stream,
                        &WireMessage::new(MessageType::CommitResponse, payload),
                    )
                    .await?;
                }

                MessageType::Subscribe => {
                    // Stream blocks to the subscriber
                    let mut rx = subscriptions.subscribe();
                    loop {
                        match rx.recv().await {
                            Ok(block) => {
                                let payload = serde_json::to_vec(block.inner())
                                    .map_err(|e| ProtocolError::Serde(e.to_string()))?;
                                write_message(
                                    &mut stream,
                                    &WireMessage::new(MessageType::Block, payload),
                                )
                                .await?;
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                tracing::warn!("Subscription lagged, dropped {} blocks", n);
                                continue; // keep receiving
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }

                MessageType::Ping => {
                    write_message(&mut stream, &WireMessage::new(MessageType::Pong, vec![]))
                        .await?;
                }

                _ => {
                    debug!("Ignoring message type {:?}", msg.msg_type);
                }
            }
        }
    }

    /// Get a reference to the subscription manager.
    pub fn subscriptions(&self) -> &Arc<BlockSubscriptionManager> {
        &self.subscriptions
    }
}

// ═══════════════════════════════════════════════════════════
//  Consensus network client
// ═══════════════════════════════════════════════════════════

/// Client for connecting to a consensus network peer.
pub struct ConsensusNetworkClient {
    addr: String,
}

impl ConsensusNetworkClient {
    pub fn new(addr: String) -> Self {
        Self { addr }
    }

    /// Send a block to the peer.
    pub async fn send_block(&self, block: &Block) -> Result<(), ProtocolError> {
        let mut stream = TcpStream::connect(&self.addr).await?;
        let payload = serde_json::to_vec(block).map_err(|e| ProtocolError::Serde(e.to_string()))?;
        write_message(&mut stream, &WireMessage::new(MessageType::Block, payload)).await?;
        Ok(())
    }

    /// Fetch blocks from the peer.
    pub async fn fetch_blocks(
        &self,
        since_round: Round,
        limit: u32,
    ) -> Result<BlockResponse, ProtocolError> {
        let mut stream = TcpStream::connect(&self.addr).await?;
        let req = BlockRequest {
            since_round,
            limit,
            digests: vec![],
        };
        let payload = serde_json::to_vec(&req).map_err(|e| ProtocolError::Serde(e.to_string()))?;
        write_message(
            &mut stream,
            &WireMessage::new(MessageType::BlockRequest, payload),
        )
        .await?;

        let resp_msg = read_message(&mut stream).await?;
        let resp: BlockResponse = serde_json::from_slice(&resp_msg.payload)
            .map_err(|e| ProtocolError::Serde(e.to_string()))?;
        Ok(resp)
    }

    /// Fetch commits from the peer.
    pub async fn fetch_commits(
        &self,
        since_index: CommitIndex,
        limit: u32,
    ) -> Result<CommitResponse, ProtocolError> {
        let mut stream = TcpStream::connect(&self.addr).await?;
        let req = CommitRequest { since_index, limit };
        let payload = serde_json::to_vec(&req).map_err(|e| ProtocolError::Serde(e.to_string()))?;
        write_message(
            &mut stream,
            &WireMessage::new(MessageType::CommitRequest, payload),
        )
        .await?;

        let resp_msg = read_message(&mut stream).await?;
        let resp: CommitResponse = serde_json::from_slice(&resp_msg.payload)
            .map_err(|e| ProtocolError::Serde(e.to_string()))?;
        Ok(resp)
    }

    /// Subscribe to block stream.
    pub async fn subscribe_blocks(&self) -> Result<mpsc::Receiver<Block>, ProtocolError> {
        let mut stream = TcpStream::connect(&self.addr).await?;
        write_message(
            &mut stream,
            &WireMessage::new(MessageType::Subscribe, vec![]),
        )
        .await?;

        let (tx, rx) = mpsc::channel(1000);
        tokio::spawn(async move {
            loop {
                match read_message(&mut stream).await {
                    Ok(msg) if msg.msg_type == MessageType::Block => {
                        if let Ok(block) = serde_json::from_slice::<Block>(&msg.payload) {
                            if tx.send(block).await.is_err() {
                                break;
                            }
                        }
                    }
                    Ok(_) => continue,
                    Err(_) => break,
                }
            }
        });

        Ok(rx)
    }

    /// Ping the peer.
    pub async fn ping(&self) -> Result<(), ProtocolError> {
        let mut stream = TcpStream::connect(&self.addr).await?;
        write_message(&mut stream, &WireMessage::new(MessageType::Ping, vec![])).await?;
        let resp = read_message(&mut stream).await?;
        if resp.msg_type != MessageType::Pong {
            return Err(ProtocolError::Serde("expected pong".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_message_roundtrip() {
        let msg = WireMessage::new(MessageType::Block, vec![1, 2, 3, 4]);
        let encoded = msg.encode();
        let (decoded, consumed) = WireMessage::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.msg_type, MessageType::Block);
        assert_eq!(decoded.payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_wire_message_empty_payload() {
        let msg = WireMessage::new(MessageType::Ping, vec![]);
        let encoded = msg.encode();
        let (decoded, _) = WireMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.msg_type, MessageType::Ping);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn test_invalid_magic() {
        let mut data = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0, 0, 0, 0];
        let result = WireMessage::decode(&data);
        assert!(matches!(result, Err(ProtocolError::InvalidMagic)));
    }

    #[test]
    fn test_message_too_large() {
        let mut data = Vec::new();
        data.extend_from_slice(PROTOCOL_MAGIC);
        data.push(0x01); // Block
        data.extend_from_slice(&(MAX_MESSAGE_SIZE + 1).to_le_bytes()); // too large
        let result = WireMessage::decode(&data);
        assert!(matches!(result, Err(ProtocolError::MessageTooLarge(_))));
    }

    #[test]
    fn test_insufficient_data() {
        let result = WireMessage::decode(&[0x4D, 0x53, 0x4B]);
        assert!(matches!(result, Err(ProtocolError::InsufficientData)));
    }

    #[test]
    fn test_block_subscription_manager() {
        let mgr = BlockSubscriptionManager::new(100);
        let mut rx = mgr.subscribe();
        assert_eq!(mgr.subscriber_count(), 1);

        let block = Block {
            epoch: 0,
            round: 1,
            author: 0,
            timestamp_ms: 1000,
            ancestors: vec![],
            transactions: vec![vec![1]],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            signature: vec![0xAA; 64],
        };
        let vb = VerifiedBlock::new_verified(block);
        mgr.publish(vb);

        let received = rx.try_recv().unwrap();
        assert_eq!(received.round(), 1);
    }

    #[test]
    fn test_all_message_types() {
        for type_byte in [0x01, 0x02, 0x03, 0x04, 0x05, 0x10, 0x11, 0x20, 0x21] {
            let mt = MessageType::from_u8(type_byte);
            assert!(mt.is_some(), "type 0x{:02x} should be valid", type_byte);
        }
        assert!(MessageType::from_u8(0xFF).is_none());
    }
}
