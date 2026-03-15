//! P2P network with NodeMode-aware behavior.
//!
//! - **Public**: listen + advertise + relay + discovery
//! - **Hidden**: outbound-only, no advertisement, no peer-list inclusion
//! - **Seed**: listen + discovery-only (no block production)
//!
//! Message framing: 4-byte big-endian length prefix + JSON body.
//! Max message size: 1 MB.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, broadcast};
use tracing::{info, warn, error, debug};
use serde::{Serialize, Deserialize};

use crate::config::{NodeMode, P2pConfig};

const MAX_MSG_SIZE: usize = 1_048_576; // 1 MB

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
        /// Advertised listen address (None for hidden nodes).
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
    RequestBlock { height: u64 },
    /// Request peer list (seed node discovery).
    GetPeers,
    /// Response with known peers (only from public/seed nodes).
    Peers {
        /// List of (addr, node_name) that are advertisable.
        addrs: Vec<(String, String)>,
    },
    /// Keepalive.
    Ping { nonce: u64 },
    Pong { nonce: u64 },
}

impl P2pMessage {
    pub fn encode(&self) -> Vec<u8> {
        let json = serde_json::to_vec(self).unwrap();
        let len = (json.len() as u32).to_be_bytes();
        let mut buf = Vec::with_capacity(4 + json.len());
        buf.extend_from_slice(&len);
        buf.extend_from_slice(&json);
        buf
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
    /// The peer's listen address (may differ from connection addr due to NAT).
    pub listen_addr: Option<SocketAddr>,
}

// ─── P2P Network ────────────────────────────────────────────

pub struct P2pNetwork {
    peers: Arc<RwLock<HashMap<SocketAddr, ConnectedPeer>>>,
    broadcast_tx: broadcast::Sender<P2pMessage>,
    chain_id: u32,
    node_name: String,
    config: P2pConfig,
}

impl P2pNetwork {
    pub fn new(chain_id: u32, node_name: String, config: P2pConfig) -> Self {
        let (broadcast_tx, _) = broadcast::channel(512);
        info!(
            "P2P mode={} | listen={} | advertise={} | max_in={} | max_out={}",
            config.mode, config.listen, config.advertise_address,
            config.max_inbound_peers, config.max_outbound_peers,
        );
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            broadcast_tx,
            chain_id,
            node_name,
            config,
        }
    }

    pub fn broadcast(&self, msg: P2pMessage) {
        let _ = self.broadcast_tx.send(msg);
    }

    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    pub async fn inbound_count(&self) -> usize {
        self.peers.read().await.values().filter(|p| p.inbound).count()
    }

    pub async fn outbound_count(&self) -> usize {
        self.peers.read().await.values().filter(|p| !p.inbound).count()
    }

    /// Get list of advertisable peers (for GetPeers responses).
    pub async fn get_advertisable_peers(&self) -> Vec<(String, String)> {
        self.peers.read().await.values()
            .filter(|p| p.advertisable)
            .filter_map(|p| {
                let addr = p.listen_addr.unwrap_or(p.addr);
                Some((addr.to_string(), p.node_name.clone()))
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

        let listener = TcpListener::bind(addr).await?;
        info!("P2P listening on {} (mode={})", addr, self.config.mode);

        let peers = self.peers.clone();
        let chain_id = self.chain_id;
        let node_name = self.node_name.clone();
        let broadcast_tx = self.broadcast_tx.clone();
        let max_inbound = self.config.max_inbound_peers;
        let advertise = self.config.advertise_address;
        let mode = self.config.mode;
        let listen_str = if advertise { Some(addr.to_string()) } else { None };

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        // Enforce inbound limit
                        let inb = peers.read().await.values().filter(|p| p.inbound).count();
                        if inb >= max_inbound {
                            warn!("Inbound limit reached ({}), rejecting {}", max_inbound, peer_addr);
                            drop(stream);
                            continue;
                        }

                        debug!("Inbound peer: {}", peer_addr);
                        let peers = peers.clone();
                        let node_name = node_name.clone();
                        let mut rx = broadcast_tx.subscribe();
                        let listen_str = listen_str.clone();

                        tokio::spawn(async move {
                            if let Err(e) = handle_inbound(
                                stream, peer_addr, peers.clone(), chain_id,
                                &node_name, mode, listen_str.as_deref(), &mut rx,
                            ).await {
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
        let remaining = self.config.max_outbound_peers.saturating_sub(outbound_count);

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
            let advertise = self.config.advertise_address;
            let p2p_config = self.config.clone();

            tokio::spawn(async move {
                match TcpStream::connect(addr).await {
                    Ok(stream) => {
                        info!("Outbound connected: {}", addr);
                        let (mut reader, mut writer) = stream.into_split();

                        // Send Hello (hidden nodes: no listen_addr)
                        let hello = P2pMessage::Hello {
                            chain_id,
                            height,
                            node_name: node_name.clone(),
                            mode: mode.to_string(),
                            listen_addr: if advertise {
                                Some(format!("0.0.0.0:{}", addr.port()))
                            } else {
                                None
                            },
                        };
                        if writer.write_all(&hello.encode()).await.is_err() {
                            return;
                        }

                        // Ask seed nodes for peers
                        if mode != NodeMode::Seed {
                            let get_peers = P2pMessage::GetPeers;
                            let _ = writer.write_all(&get_peers.encode()).await;
                        }

                        let peers_r = peers.clone();
                        let serves_discovery = p2p_config.mode.serves_peer_discovery();

                        // Read loop
                        tokio::spawn(async move {
                            let mut buf = [0u8; 4];
                            loop {
                                if reader.read_exact(&mut buf).await.is_err() { break; }
                                let len = u32::from_be_bytes(buf) as usize;
                                if len > MAX_MSG_SIZE { break; }
                                let mut msg_buf = vec![0u8; len];
                                if reader.read_exact(&mut msg_buf).await.is_err() { break; }
                                match P2pMessage::decode(&msg_buf) {
                                    Ok(P2pMessage::Hello { node_name: name, height, mode: peer_mode, listen_addr, .. }) => {
                                        let advertisable = peer_mode != "hidden";
                                        let listen = listen_addr.and_then(|s| s.parse().ok());
                                        peers_r.write().await.insert(addr, ConnectedPeer {
                                            addr, node_name: name, height, inbound: false,
                                            advertisable, listen_addr: listen,
                                        });
                                    }
                                    Ok(P2pMessage::NewBlock { height, .. }) => {
                                        debug!("Peer {} block #{}", addr, height);
                                    }
                                    Ok(P2pMessage::Peers { addrs }) => {
                                        info!("Received {} peers from {}", addrs.len(), addr);
                                        // Future: connect to discovered peers
                                        for (a, n) in &addrs {
                                            debug!("  discovered: {} ({})", a, n);
                                        }
                                    }
                                    Ok(P2pMessage::GetPeers) if serves_discovery => {
                                        let peer_list = peers_r.read().await;
                                        let advertisable: Vec<(String, String)> = peer_list.values()
                                            .filter(|p| p.advertisable)
                                            .filter_map(|p| p.listen_addr.map(|la| (la.to_string(), p.node_name.clone())))
                                            .collect();
                                        drop(peer_list);
                                        // Can't write from read loop; log for now
                                        debug!("GetPeers request from {} ({} advertisable)", addr, advertisable.len());
                                    }
                                    Ok(P2pMessage::Ping { .. }) | Ok(P2pMessage::Pong { .. }) => {}
                                    _ => {}
                                }
                            }
                        });

                        // Write loop: relay broadcasts
                        tokio::spawn(async move {
                            while let Ok(msg) = rx.recv().await {
                                if writer.write_all(&msg.encode()).await.is_err() { break; }
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
    writer.write_all(&hello.encode()).await?;

    // Read peer's Hello
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MSG_SIZE { anyhow::bail!("message too large: {}", len); }
    let mut msg_buf = vec![0u8; len];
    reader.read_exact(&mut msg_buf).await?;

    if let Ok(P2pMessage::Hello { node_name: name, height, chain_id: their_chain, mode: peer_mode, listen_addr }) = P2pMessage::decode(&msg_buf) {
        if their_chain != chain_id {
            anyhow::bail!("chain_id mismatch: ours={} theirs={}", chain_id, their_chain);
        }

        // Hidden peers are NOT added to advertisable list
        let advertisable = peer_mode != "hidden";
        let listen = listen_addr.and_then(|s| s.parse().ok());

        peers.write().await.insert(addr, ConnectedPeer {
            addr, node_name: name.clone(), height,
            inbound: true, advertisable, listen_addr: listen,
        });
        info!("Peer {} identified: {} (mode={}, height={})", addr, name, peer_mode, height);
    } else {
        anyhow::bail!("expected Hello, got something else");
    }

    // Serve peer: relay broadcasts + handle GetPeers
    let peers_for_read = peers.clone();
    let serves_discovery = our_mode.serves_peer_discovery();

    // Spawn a reader task for GetPeers handling
    let (response_tx, mut response_rx) = tokio::sync::mpsc::channel::<P2pMessage>(32);
    tokio::spawn(async move {
        let mut buf = [0u8; 4];
        loop {
            if reader.read_exact(&mut buf).await.is_err() { break; }
            let len = u32::from_be_bytes(buf) as usize;
            if len > MAX_MSG_SIZE { break; }
            let mut msg_buf = vec![0u8; len];
            if reader.read_exact(&mut msg_buf).await.is_err() { break; }

            match P2pMessage::decode(&msg_buf) {
                Ok(P2pMessage::GetPeers) if serves_discovery => {
                    let peer_list: Vec<(String, String)> = peers_for_read.read().await.values()
                        .filter(|p| p.advertisable)
                        .filter_map(|p| p.listen_addr.map(|la| (la.to_string(), p.node_name.clone())))
                        .collect();
                    let _ = response_tx.send(P2pMessage::Peers { addrs: peer_list }).await;
                }
                Ok(P2pMessage::Ping { nonce }) => {
                    let _ = response_tx.send(P2pMessage::Pong { nonce }).await;
                }
                _ => {}
            }
        }
    });

    // Writer loop: broadcasts + responses to GetPeers/Ping
    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Ok(m) => { if writer.write_all(&m.encode()).await.is_err() { break; } }
                    Err(_) => break,
                }
            }
            Some(resp) = response_rx.recv() => {
                if writer.write_all(&resp.encode()).await.is_err() { break; }
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
        let cfg = P2pConfig::from_mode(NodeMode::Public)
            .with_overrides(Some(10), None, false, true, vec![], None);
        assert_eq!(cfg.max_inbound_peers, 10);
        assert!(!cfg.advertise_address); // hide_ip override
        assert!(cfg.listen); // not overridden
    }

    #[test]
    fn test_outbound_only_override() {
        let cfg = P2pConfig::from_mode(NodeMode::Public)
            .with_overrides(None, None, true, false, vec![], None);
        assert!(!cfg.listen);
        assert_eq!(cfg.max_inbound_peers, 0);
    }

    #[test]
    fn test_message_roundtrip() {
        let msg = P2pMessage::Hello {
            chain_id: 2, height: 100, node_name: "test".into(),
            mode: "hidden".into(), listen_addr: None,
        };
        let encoded = msg.encode();
        let decoded = P2pMessage::decode(&encoded[4..]).unwrap();
        if let P2pMessage::Hello { mode, listen_addr, .. } = decoded {
            assert_eq!(mode, "hidden");
            assert!(listen_addr.is_none());
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_hidden_hello_no_addr() {
        let msg = P2pMessage::Hello {
            chain_id: 2, height: 0, node_name: "hidden-val".into(),
            mode: "hidden".into(), listen_addr: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(!json.contains("6690")); // no port leaked
    }
}
