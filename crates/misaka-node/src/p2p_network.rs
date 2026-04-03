//! P2P network with NodeMode-aware behavior.
//!
//! - **Public**: listen + advertise + relay + discovery
//! - **Hidden**: outbound-only, no advertisement, no peer-list inclusion
//! - **Seed**: listen + discovery-only (no block production)
//!
//! Message framing: 4-byte big-endian length prefix + JSON body.
//! Max message size: 1 MB.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, RwLock};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::config::{NodeMode, P2pConfig};
use crate::sync_relay_transport::{
    classify_sync_relay_message, observe_sync_relay_message, SyncRelayDirection,
};
use misaka_p2p::{
    build_peer_discovery_response, sanitize_peer_discovery_entries, PeerAdvertisementCandidate,
    PeerDiscoveryEntry, PeerModeLabel,
};

const MAX_MSG_SIZE: usize = 1_048_576; // 1 MB
/// Read timeout for P2P handshake (Slowloris protection).
const HANDSHAKE_TIMEOUT_SECS: u64 = 10;
/// Read timeout for ongoing P2P messages.
const MSG_READ_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum P2pTransportLane {
    HandshakeHello,
    DiscoveryRequest,
    BroadcastRelay,
    SyncRelay,
    ResponseRelay,
}

impl P2pTransportLane {
    fn as_str(self) -> &'static str {
        match self {
            Self::HandshakeHello => "handshake-hello",
            Self::DiscoveryRequest => "discovery-request",
            Self::BroadcastRelay => "broadcast-relay",
            Self::SyncRelay => "sync-relay",
            Self::ResponseRelay => "response-relay",
        }
    }
}

// ─── Messages ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2pMessage {
    /// Node identity on connect.
    Hello {
        chain_id: u32,
        height: u64,
        node_name: String,
        /// Peer's operating mode (so hidden nodes can signal "don't advertise me").
        mode: String,
        /// Advertised address for peer discovery (None for hidden/no-advertise nodes).
        /// This is the external address, NOT the listen address (which may be 0.0.0.0).
        listen_addr: Option<String>,
    },
    /// Announce new block.
    NewBlock {
        height: u64,
        hash: [u8; 32],
        parent_hash: [u8; 32],
        timestamp_ms: u64,
        tx_count: usize,
        proposer_index: usize,
    },
    /// New transaction broadcast.
    NewTx {
        tx_hash: [u8; 32],
        fee: u64,
        size: usize,
    },
    /// Request block by height.
    RequestBlock {
        height: u64,
    },
    /// Request peer list (seed node discovery).
    GetPeers,
    /// Response with known peers (only from public/seed nodes).
    Peers {
        /// List of (addr, node_name) that are advertisable.
        addrs: Vec<(String, String)>,
    },
    /// Typed peer discovery response.
    PeersV2 {
        peers: Vec<PeerDiscoveryEntry>,
    },
    /// Keepalive.
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
}

impl P2pMessage {
    /// Encode message with 4-byte length prefix.
    ///
    /// Returns `Err` on serialization failure (fail-closed).
    /// Callers MUST handle the error (disconnect peer, etc).
    pub fn encode(&self) -> Result<Vec<u8>, serde_json::Error> {
        let json = serde_json::to_vec(self)?;
        let len = (json.len() as u32).to_be_bytes();
        let mut buf = Vec::with_capacity(4 + json.len());
        buf.extend_from_slice(&len);
        buf.extend_from_slice(&json);
        Ok(buf)
    }

    pub fn decode(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

// ─── Peer tracking ──────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ConnectedPeer {
    pub addr: SocketAddr,
    pub node_name: String,
    pub height: u64,
    pub inbound: bool,
    /// Whether this peer wants to be advertised in GetPeers responses.
    pub advertisable: bool,
    /// The peer's advertised address (validated — no 0.0.0.0 or loopback).
    pub advertise_addr: Option<SocketAddr>,
    /// Peer's reported mode.
    pub peer_mode: PeerModeLabel,
    /// When this peer connected (epoch ms).
    pub connected_at_ms: u64,
    /// Last activity timestamp (epoch ms).
    pub last_seen_ms: u64,
}

/// Peer info returned by the /api/get_peers RPC endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfoRpc {
    pub node_name: String,
    pub remote_addr: String,
    pub advertise_addr: Option<String>,
    pub mode: String,
    pub advertisable: bool,
    #[serde(rename = "servesPeerDiscovery")]
    pub serves_peer_discovery: bool,
    pub direction: String,
    pub height: u64,
    pub connected_at: String,
    pub last_seen: String,
}

// ─── P2P Network ────────────────────────────────────────────

pub struct P2pNetwork {
    peers: Arc<RwLock<HashMap<SocketAddr, ConnectedPeer>>>,
    broadcast_tx: broadcast::Sender<P2pMessage>,
    chain_id: u32,
    node_name: String,
    config: P2pConfig,
    /// Our listen port (for reference).
    listen_port: std::sync::atomic::AtomicU16,
}

/// Validate and parse an advertised address string, rejecting invalid ones.
fn validate_advertise_addr(addr_str: &str) -> Option<SocketAddr> {
    let addr: SocketAddr = addr_str.parse().ok()?;
    if crate::config::is_valid_advertise_addr(&addr) {
        Some(addr)
    } else {
        debug!("Rejected invalid advertise address: {}", addr_str);
        None
    }
}

fn now_ms() -> u64 {
    chrono::Utc::now().timestamp_millis() as u64
}

fn ms_to_iso(ms: u64) -> String {
    chrono::DateTime::from_timestamp_millis(ms as i64)
        .map(|d| d.to_rfc3339())
        .unwrap_or_default()
}

async fn read_p2p_frame<R>(reader: &mut R, timeout_secs: u64) -> anyhow::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    timeout(
        std::time::Duration::from_secs(timeout_secs),
        reader.read_exact(&mut len_buf),
    )
    .await
    .map_err(|_| anyhow::anyhow!("p2p read timeout while waiting for frame header"))??;

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MSG_SIZE {
        anyhow::bail!("message too large: {}", len);
    }

    let mut msg_buf = vec![0u8; len];
    timeout(
        std::time::Duration::from_secs(timeout_secs),
        reader.read_exact(&mut msg_buf),
    )
    .await
    .map_err(|_| anyhow::anyhow!("p2p read timeout while waiting for frame body"))??;

    Ok(msg_buf)
}

async fn write_p2p_message<W>(
    writer: &mut W,
    msg: &P2pMessage,
    lane: P2pTransportLane,
) -> anyhow::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let encoded = msg
        .encode()
        .map_err(|e| anyhow::anyhow!("encode {}: {}", lane.as_str(), e))?;
    writer
        .write_all(&encoded)
        .await
        .map_err(|e| anyhow::anyhow!("write {}: {}", lane.as_str(), e))?;
    Ok(())
}

fn relay_transport_lane(msg: &P2pMessage) -> P2pTransportLane {
    if classify_sync_relay_message(msg).is_some() {
        P2pTransportLane::SyncRelay
    } else {
        P2pTransportLane::BroadcastRelay
    }
}

impl P2pNetwork {
    pub fn new(chain_id: u32, node_name: String, config: P2pConfig) -> Self {
        let (broadcast_tx, _) = broadcast::channel(512);
        info!(
            "P2P mode={} | listen={} | advertise={} | max_in={} | max_out={}",
            config.mode,
            config.listen,
            config.advertise_address,
            config.max_inbound_peers,
            config.max_outbound_peers,
        );
        if let Some(ref addr) = config.advertise_addr {
            info!("Advertising as {}", addr);
        } else if config.advertise_address {
            warn!(
                "No --advertise-addr set; this node will NOT be discoverable by peers. Use --advertise-addr <HOST:PORT>"
            );
        }
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            broadcast_tx,
            chain_id,
            node_name,
            config,
            listen_port: std::sync::atomic::AtomicU16::new(0),
        }
    }

    pub fn broadcast(&self, msg: P2pMessage) {
        let _ = self.broadcast_tx.send(msg);
    }

    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    pub async fn inbound_count(&self) -> usize {
        self.peers
            .read()
            .await
            .values()
            .filter(|p| p.inbound)
            .count()
    }

    pub async fn outbound_count(&self) -> usize {
        self.peers
            .read()
            .await
            .values()
            .filter(|p| !p.inbound)
            .count()
    }

    /// Get list of advertisable peers (for GetPeers responses).
    /// Only returns peers with valid advertise addresses.
    pub async fn get_advertisable_peers(&self) -> Vec<PeerDiscoveryEntry> {
        let candidates = self
            .peers
            .read()
            .await
            .values()
            .map(|p| {
                PeerAdvertisementCandidate::new(
                    p.advertise_addr.map(|addr| addr.to_string()),
                    p.node_name.clone(),
                    p.peer_mode,
                    p.advertisable,
                )
            })
            .collect::<Vec<_>>();
        build_peer_discovery_response(&candidates)
    }

    /// Get peer info list for RPC /api/get_peers endpoint.
    pub async fn get_peer_info_list(&self) -> Vec<PeerInfoRpc> {
        self.peers
            .read()
            .await
            .values()
            .map(|p| PeerInfoRpc {
                node_name: p.node_name.clone(),
                remote_addr: p.addr.to_string(),
                advertise_addr: p.advertise_addr.map(|a| a.to_string()),
                mode: p.peer_mode.as_str().into(),
                advertisable: p.advertisable,
                serves_peer_discovery: p.peer_mode.serves_peer_discovery(),
                direction: if p.inbound {
                    "inbound".into()
                } else {
                    "outbound".into()
                },
                height: p.height,
                connected_at: ms_to_iso(p.connected_at_ms),
                last_seen: ms_to_iso(p.last_seen_ms),
            })
            .collect()
    }

    // ─── Listener (public / seed only) ──────────────────────

    /// Start TCP listener. Skipped if mode is Hidden.
    pub async fn start_listener(&self, addr: SocketAddr) -> anyhow::Result<()> {
        if !self.config.listen {
            info!("P2P listener DISABLED (mode={})", self.config.mode);
            return Ok(());
        }

        self.listen_port
            .store(addr.port(), std::sync::atomic::Ordering::Relaxed);

        let listener = TcpListener::bind(addr).await?;
        info!("P2P listening on {} (mode={})", addr, self.config.mode);

        let peers = self.peers.clone();
        let chain_id = self.chain_id;
        let node_name = self.node_name.clone();
        let broadcast_tx = self.broadcast_tx.clone();
        let max_inbound = self.config.max_inbound_peers;
        let mode = self.config.mode;
        // Use effective_advertise_addr — never sends 0.0.0.0
        let advertise_str = self.config.effective_advertise_addr(addr.port());

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        // Enforce inbound limit
                        let inb = peers.read().await.values().filter(|p| p.inbound).count();
                        if inb >= max_inbound {
                            warn!(
                                "Inbound limit reached ({}), rejecting {}",
                                max_inbound, peer_addr
                            );
                            drop(stream);
                            continue;
                        }

                        debug!("Inbound peer: {}", peer_addr);
                        let peers = peers.clone();
                        let node_name = node_name.clone();
                        let mut rx = broadcast_tx.subscribe();
                        let advertise_str = advertise_str.clone();

                        tokio::spawn(async move {
                            if let Err(e) = handle_inbound(
                                stream,
                                peer_addr,
                                peers.clone(),
                                chain_id,
                                &node_name,
                                mode,
                                advertise_str.as_deref(),
                                &mut rx,
                            )
                            .await
                            {
                                debug!("Peer {} disconnected: {}", peer_addr, e);
                            }
                            peers.write().await.remove(&peer_addr);
                        });
                    }
                    Err(e) => error!("Accept error: {}", e),
                }
            }
        });

        Ok(())
    }

    // ─── Outbound connections ───────────────────────────────

    /// Connect to static/seed peers.
    pub async fn connect_to_peers(&self, addrs: &[SocketAddr], our_height: u64) {
        let outbound_count = self.outbound_count().await;
        let remaining = self
            .config
            .max_outbound_peers
            .saturating_sub(outbound_count);

        for (i, &addr) in addrs.iter().enumerate() {
            if i >= remaining {
                warn!("Outbound limit reached, skipping remaining peers");
                break;
            }

            let peers = self.peers.clone();
            let chain_id = self.chain_id;
            let node_name = self.node_name.clone();
            let mut rx = self.broadcast_tx.subscribe();
            let height = our_height;
            let mode = self.config.mode;
            let p2p_config = self.config.clone();
            // Use effective_advertise_addr — never sends 0.0.0.0
            let listen_port = self.listen_port.load(std::sync::atomic::Ordering::Relaxed);
            let advertise_str = self.config.effective_advertise_addr(listen_port);

            tokio::spawn(async move {
                match TcpStream::connect(addr).await {
                    Ok(stream) => {
                        info!("Outbound connected: {}", addr);
                        let (mut reader, mut writer) = stream.into_split();

                        // Send Hello — advertise_str is None if no valid address
                        let hello = P2pMessage::Hello {
                            chain_id,
                            height,
                            node_name: node_name.clone(),
                            mode: mode.to_string(),
                            listen_addr: advertise_str,
                        };
                        if let Err(e) =
                            write_p2p_message(&mut writer, &hello, P2pTransportLane::HandshakeHello)
                                .await
                        {
                            error!("Failed to send Hello to {}: {}", addr, e);
                            return;
                        }

                        // Ask seed nodes for peers
                        if mode != NodeMode::Seed {
                            let get_peers = P2pMessage::GetPeers;
                            if let Err(e) = write_p2p_message(
                                &mut writer,
                                &get_peers,
                                P2pTransportLane::DiscoveryRequest,
                            )
                            .await
                            {
                                error!("Failed to send GetPeers to {}: {}", addr, e);
                                return;
                            }
                        }

                        let peers_r = peers.clone();
                        let serves_discovery = p2p_config.mode.serves_peer_discovery();

                        // Read loop
                        tokio::spawn(async move {
                            loop {
                                let msg_buf = match read_p2p_frame(
                                    &mut reader,
                                    MSG_READ_TIMEOUT_SECS,
                                )
                                .await
                                {
                                    Ok(buf) => buf,
                                    Err(e) => {
                                        debug!("Outbound read loop for {} stopped: {}", addr, e);
                                        break;
                                    }
                                };
                                match P2pMessage::decode(&msg_buf) {
                                    Ok(msg) => {
                                        let _ = observe_sync_relay_message(
                                            SyncRelayDirection::OutboundRead,
                                            addr,
                                            &msg,
                                        );
                                        match msg {
                                            P2pMessage::Hello {
                                                node_name: name,
                                                height,
                                                chain_id: their_chain,
                                                mode: peer_mode,
                                                listen_addr,
                                            } => {
                                                // Validate chain_id
                                                if their_chain != chain_id {
                                                    warn!(
                                                        "Outbound peer {} chain_id mismatch: ours={} theirs={}",
                                                        addr, chain_id, their_chain
                                                    );
                                                    break;
                                                }
                                                let peer_mode_label =
                                                    PeerModeLabel::parse(&peer_mode);
                                                let advertisable =
                                                    peer_mode_label.is_advertisable();
                                                // Validate advertised address — reject 0.0.0.0/loopback
                                                let validated_addr = listen_addr
                                                    .as_deref()
                                                    .and_then(validate_advertise_addr);
                                                debug!(
                                                    "Outbound Hello from {}: mode={} listen_addr={:?} validated={:?}",
                                                    addr, peer_mode, listen_addr, validated_addr
                                                );
                                                let ts = now_ms();
                                                peers_r.write().await.insert(
                                                    addr,
                                                    ConnectedPeer {
                                                        addr,
                                                        node_name: name,
                                                        height,
                                                        inbound: false,
                                                        advertisable,
                                                        advertise_addr: validated_addr,
                                                        peer_mode: peer_mode_label,
                                                        connected_at_ms: ts,
                                                        last_seen_ms: ts,
                                                    },
                                                );
                                            }
                                            P2pMessage::NewBlock { height, .. } => {
                                                debug!("Peer {} block #{}", addr, height);
                                            }
                                            P2pMessage::Peers { addrs } => {
                                                let entries = addrs
                                                    .into_iter()
                                                    .map(|(address, node_name)| {
                                                        PeerDiscoveryEntry::from_legacy_tuple(
                                                            address, node_name,
                                                        )
                                                    })
                                                    .collect::<Vec<_>>();
                                                let summary = sanitize_peer_discovery_entries(
                                                    &entries,
                                                    |address| {
                                                        validate_advertise_addr(address).is_some()
                                                    },
                                                );
                                                if summary.truncated > 0 {
                                                    tracing::warn!(
                                                        "Peers response has {} addrs (max 100), truncating",
                                                        entries.len()
                                                    );
                                                }
                                                info!(
                                                    "Received {} peers from {} ({} valid, {} rejected)",
                                                    entries.len(),
                                                    addr,
                                                    summary.accepted.len(),
                                                    summary.rejected
                                                );
                                                for entry in &summary.accepted {
                                                    debug!(
                                                        "  discovered: {} ({})",
                                                        entry.address, entry.node_name
                                                    );
                                                }
                                                if summary.rejected > 0 {
                                                    debug!(
                                                        "  rejected {} peers with invalid addresses",
                                                        summary.rejected
                                                    );
                                                }
                                            }
                                            P2pMessage::PeersV2 { peers } => {
                                                let summary = sanitize_peer_discovery_entries(
                                                    &peers,
                                                    |address| {
                                                        validate_advertise_addr(address).is_some()
                                                    },
                                                );
                                                if summary.truncated > 0 {
                                                    tracing::warn!(
                                                        "PeersV2 response has {} entries (max 100), truncating",
                                                        peers.len()
                                                    );
                                                }
                                                info!(
                                                    "Received {} peers from {} ({} valid, {} rejected)",
                                                    peers.len(),
                                                    addr,
                                                    summary.accepted.len(),
                                                    summary.rejected
                                                );
                                                for entry in &summary.accepted {
                                                    debug!(
                                                        "  discovered: {} ({}) mode={} discovery={}",
                                                        entry.address,
                                                        entry.node_name,
                                                        entry.mode.as_str(),
                                                        entry.serves_peer_discovery
                                                    );
                                                }
                                            }
                                            P2pMessage::GetPeers if serves_discovery => {
                                                let peer_list = peers_r.read().await;
                                                let advertisable = peer_list
                                                    .values()
                                                    .map(|p| {
                                                        PeerAdvertisementCandidate::new(
                                                            p.advertise_addr.map(|a| a.to_string()),
                                                            p.node_name.clone(),
                                                            p.peer_mode,
                                                            p.advertisable,
                                                        )
                                                    })
                                                    .collect::<Vec<_>>();
                                                drop(peer_list);
                                                let peer_list =
                                                    build_peer_discovery_response(&advertisable);
                                                // Can't write from read loop; log for now
                                                debug!(
                                                    "GetPeers request from {} ({} advertisable)",
                                                    addr,
                                                    peer_list.len()
                                                );
                                            }
                                            P2pMessage::Ping { .. } | P2pMessage::Pong { .. } => {}
                                            _ => {}
                                        }
                                    }
                                    Err(_) => {}
                                }
                            }
                        });

                        // Write loop: broadcast + sync relay messages
                        tokio::spawn(async move {
                            while let Ok(msg) = rx.recv().await {
                                let _ = observe_sync_relay_message(
                                    SyncRelayDirection::OutboundWrite,
                                    addr,
                                    &msg,
                                );
                                let lane = relay_transport_lane(&msg);
                                if let Err(e) = write_p2p_message(&mut writer, &msg, lane).await {
                                    error!(
                                        "Write failed for {} (outbound to {}): {}",
                                        lane.as_str(),
                                        addr,
                                        e
                                    );
                                    break;
                                }
                            }
                        });
                    }
                    Err(e) => warn!("Failed to connect to {}: {}", addr, e),
                }
            });
        }
    }
}

// ─── Inbound handler ────────────────────────────────────────

async fn handle_inbound(
    stream: TcpStream,
    addr: SocketAddr,
    peers: Arc<RwLock<HashMap<SocketAddr, ConnectedPeer>>>,
    chain_id: u32,
    node_name: &str,
    our_mode: NodeMode,
    our_listen_addr: Option<&str>,
    rx: &mut broadcast::Receiver<P2pMessage>,
) -> anyhow::Result<()> {
    let (mut reader, mut writer) = stream.into_split();

    // Send our Hello
    let hello = P2pMessage::Hello {
        chain_id,
        height: 0,
        node_name: node_name.to_string(),
        mode: our_mode.to_string(),
        listen_addr: our_listen_addr.map(String::from),
    };
    {
        write_p2p_message(&mut writer, &hello, P2pTransportLane::HandshakeHello).await?
    };

    // Read peer's Hello
    let msg_buf = read_p2p_frame(&mut reader, HANDSHAKE_TIMEOUT_SECS).await?;

    if let Ok(P2pMessage::Hello {
        node_name: name,
        height,
        chain_id: their_chain,
        mode: peer_mode,
        listen_addr,
    }) = P2pMessage::decode(&msg_buf)
    {
        if their_chain != chain_id {
            anyhow::bail!(
                "chain_id mismatch: ours={} theirs={}",
                chain_id,
                their_chain
            );
        }

        // Hidden peers are NOT added to advertisable list
        let peer_mode_label = PeerModeLabel::parse(&peer_mode);
        let advertisable = peer_mode_label.is_advertisable();
        // Validate advertised address — reject 0.0.0.0/loopback
        let validated_addr = listen_addr.as_deref().and_then(validate_advertise_addr);
        debug!(
            "Inbound Hello from {}: mode={} listen_addr={:?} validated={:?}",
            addr, peer_mode, listen_addr, validated_addr
        );
        let ts = now_ms();

        peers.write().await.insert(
            addr,
            ConnectedPeer {
                addr,
                node_name: name.clone(),
                height,
                inbound: true,
                advertisable,
                advertise_addr: validated_addr,
                peer_mode: peer_mode_label,
                connected_at_ms: ts,
                last_seen_ms: ts,
            },
        );
        info!(
            "Peer {} identified: {} (mode={}, height={})",
            addr, name, peer_mode, height
        );
    } else {
        anyhow::bail!("expected Hello, got something else");
    }

    // Serve peer: broadcast + sync relay + handle GetPeers
    let peers_for_read = peers.clone();
    let serves_discovery = our_mode.serves_peer_discovery();

    // Spawn a reader task for GetPeers handling
    let (response_tx, mut response_rx) = tokio::sync::mpsc::channel::<P2pMessage>(32);
    tokio::spawn(async move {
        loop {
            let msg_buf = match read_p2p_frame(&mut reader, MSG_READ_TIMEOUT_SECS).await {
                Ok(buf) => buf,
                Err(_) => break,
            };

            match P2pMessage::decode(&msg_buf) {
                Ok(msg) => {
                    let _ = observe_sync_relay_message(SyncRelayDirection::InboundRead, addr, &msg);
                    match msg {
                        P2pMessage::GetPeers if serves_discovery => {
                            // Only return peers with valid advertise addresses
                            let candidates = peers_for_read
                                .read()
                                .await
                                .values()
                                .map(|p| {
                                    PeerAdvertisementCandidate::new(
                                        p.advertise_addr.map(|a| a.to_string()),
                                        p.node_name.clone(),
                                        p.peer_mode,
                                        p.advertisable,
                                    )
                                })
                                .collect::<Vec<_>>();
                            let peer_list = build_peer_discovery_response(&candidates);
                            let _ = response_tx
                                .send(P2pMessage::PeersV2 { peers: peer_list })
                                .await;
                        }
                        P2pMessage::Ping { nonce } => {
                            let _ = response_tx.send(P2pMessage::Pong { nonce }).await;
                        }
                        _ => {}
                    }
                }
                Err(_) => {}
            }
        }
    });

    // Writer loop: broadcasts + responses to GetPeers/Ping
    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Ok(m) => {
                        let _ = observe_sync_relay_message(
                            SyncRelayDirection::OutboundWrite,
                            addr,
                            &m,
                        );
                        let lane = relay_transport_lane(&m);
                        if let Err(e) = write_p2p_message(&mut writer, &m, lane).await {
                            error!("Write failed for {} (inbound): {}", lane.as_str(), e);
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            Some(resp) = response_rx.recv() => {
                if let Err(e) = write_p2p_message(&mut writer, &resp, P2pTransportLane::ResponseRelay).await {
                    error!("Write failed for response relay (inbound): {}", e);
                    break;
                }
            }
        }
    }

    Ok(())
}

// ─── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{NodeMode, P2pConfig};

    #[test]
    fn test_hidden_mode_config() {
        let cfg = P2pConfig::from_mode(NodeMode::Hidden);
        assert!(!cfg.listen);
        assert!(!cfg.advertise_address);
        assert_eq!(cfg.max_inbound_peers, 0);
    }

    #[test]
    fn test_public_mode_config() {
        let cfg = P2pConfig::from_mode(NodeMode::Public);
        assert!(cfg.listen);
        assert!(cfg.advertise_address);
        assert!(cfg.max_inbound_peers > 0);
    }

    #[test]
    fn test_seed_mode_config() {
        let cfg = P2pConfig::from_mode(NodeMode::Seed);
        assert!(cfg.listen);
        assert!(cfg.advertise_address);
        assert_eq!(cfg.max_inbound_peers, 128);
    }

    #[test]
    fn test_overrides() {
        let cfg = P2pConfig::from_mode(NodeMode::Public).with_overrides(
            Some(10),
            None,
            false,
            true,
            vec![],
            None,
            None,
        );
        assert_eq!(cfg.max_inbound_peers, 10);
        assert!(!cfg.advertise_address); // hide_ip override
        assert!(cfg.listen); // not overridden
    }

    #[test]
    fn test_outbound_only_override() {
        let cfg = P2pConfig::from_mode(NodeMode::Public).with_overrides(
            None,
            None,
            true,
            false,
            vec![],
            None,
            None,
        );
        assert!(!cfg.listen);
        assert_eq!(cfg.max_inbound_peers, 0);
    }

    #[test]
    fn test_message_roundtrip() {
        let msg = P2pMessage::Hello {
            chain_id: 2,
            height: 100,
            node_name: "test".into(),
            mode: "hidden".into(),
            listen_addr: None,
        };
        let encoded = msg.encode().unwrap();
        let decoded = P2pMessage::decode(&encoded[4..]).unwrap();
        if let P2pMessage::Hello {
            mode, listen_addr, ..
        } = decoded
        {
            assert_eq!(mode, "hidden");
            assert!(listen_addr.is_none());
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_peers_v2_roundtrip() {
        let msg = P2pMessage::PeersV2 {
            peers: vec![PeerDiscoveryEntry::from_parts(
                "203.0.113.10:6690".into(),
                "seed-1".into(),
                PeerModeLabel::Seed,
            )],
        };
        let encoded = msg.encode().unwrap();
        let decoded = P2pMessage::decode(&encoded[4..]).unwrap();
        match decoded {
            P2pMessage::PeersV2 { peers } => {
                assert_eq!(peers.len(), 1);
                assert_eq!(peers[0].node_name, "seed-1");
                assert_eq!(peers[0].mode, PeerModeLabel::Seed);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn test_hidden_hello_no_addr() {
        let msg = P2pMessage::Hello {
            chain_id: 2,
            height: 0,
            node_name: "hidden-val".into(),
            mode: "hidden".into(),
            listen_addr: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(!json.contains("6690")); // no port leaked
    }

    // ─── New address validation tests ───────────────────────

    #[test]
    fn test_validate_rejects_unspecified() {
        assert!(validate_advertise_addr("0.0.0.0:6690").is_none());
    }

    #[test]
    fn test_validate_rejects_ipv6_unspecified() {
        assert!(validate_advertise_addr("[::]:6690").is_none());
    }

    #[test]
    fn test_validate_rejects_loopback() {
        assert!(validate_advertise_addr("127.0.0.1:6690").is_none());
    }

    #[test]
    fn test_validate_rejects_ipv6_loopback() {
        assert!(validate_advertise_addr("[::1]:6690").is_none());
    }

    #[test]
    fn test_validate_accepts_public_ip() {
        let addr = validate_advertise_addr("198.51.100.1:6690");
        assert!(addr.is_some());
        assert_eq!(addr.unwrap().to_string(), "198.51.100.1:6690");
    }

    #[test]
    fn test_validate_rejects_garbage() {
        assert!(validate_advertise_addr("not-an-address").is_none());
    }

    #[test]
    fn test_validate_rejects_zero_port() {
        assert!(validate_advertise_addr("1.2.3.4:0").is_none());
    }

    #[test]
    fn test_relay_transport_lane_classifies_sync_messages() {
        let sync = P2pMessage::RequestBlock { height: 7 };
        let relay = P2pMessage::Ping { nonce: 9 };
        assert_eq!(relay_transport_lane(&sync), P2pTransportLane::SyncRelay);
        assert_eq!(
            relay_transport_lane(&relay),
            P2pTransportLane::BroadcastRelay
        );
    }

    #[tokio::test]
    async fn test_read_p2p_frame_timeout() {
        let (mut client, _server) = tokio::io::duplex(64);
        let err = read_p2p_frame(&mut client, 0).await.unwrap_err();
        assert!(err.to_string().contains("timeout"));
    }

    #[tokio::test]
    async fn test_write_p2p_message_roundtrip() {
        let (mut client, mut server) = tokio::io::duplex(256);
        let msg = P2pMessage::Ping { nonce: 42 };

        let writer = tokio::spawn(async move {
            write_p2p_message(&mut server, &msg, P2pTransportLane::BroadcastRelay)
                .await
                .unwrap();
        });

        let frame = read_p2p_frame(&mut client, 1).await.unwrap();
        let decoded = P2pMessage::decode(&frame).unwrap();
        match decoded {
            P2pMessage::Ping { nonce } => assert_eq!(nonce, 42),
            other => panic!("unexpected variant: {other:?}"),
        }

        writer.await.unwrap();
    }
}
