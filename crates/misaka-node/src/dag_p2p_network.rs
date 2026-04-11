//! # DAG P2P Event Loop — Network ↔ Consensus Pipeline Binding (v4)
//!
//! # Problem
//!
//! v3 以前は `dag_p2p.rs` の sync state machine と `dag_block_ingestion.rs` の
//! IngestionPipeline が main.rs の TODO コメントで「Phase 3」として放置されていた。
//! P2P からの受信メッセージはコンセンサスに一切到達していなかった。
//!
//! # Solution: DagP2pEventLoop
//!
//! このモジュールは P2P 受信メッセージと IngestionPipeline の間のブリッジとして
//! 非同期イベントループを提供する。
//!
//! ```text
//! ┌─────────────────────┐     tokio::mpsc     ┌───────────────────────┐
//! │   P2P Transport     │ ──────────────────▶ │  DagP2pEventLoop      │
//! │   (TCP / QUIC)      │                     │                       │
//! │                     │ ◀────────────────── │  ┌─────────────────┐  │
//! │                     │   outbound messages  │  │ IngestionPipeline│  │
//! └─────────────────────┘                     │  └────────┬────────┘  │
//!                                             │           │           │
//!                                             │  ┌────────▼────────┐  │
//!                                             │  │ AtomicPipeline  │  │
//!                                             │  │ (validate +     │  │
//!                                             │  │  commit)        │  │
//!                                             │  └────────┬────────┘  │
//!                                             │           │           │
//!                                             │  ┌────────▼────────┐  │
//!                                             │  │ VirtualState    │  │
//!                                             │  │ ::resolve()     │  │
//!                                             │  └─────────────────┘  │
//!                                             └───────────────────────┘
//! ```
//!
//! # Inventory (Peer State)
//!
//! 各ピアが「既知」と宣言したブロックハッシュの集合を保持する。
//! 未知のハッシュを受信したときのみ RequestHeaders / GetDagBlocks を返す。
//! これにより不要な重複ダウンロードを防止する。

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

use crate::dag_p2p_surface::{observe_dag_p2p_message, DagP2pDirection, DagP2pObservationState};
use misaka_dag::dag_block::{DagBlockHeader, Hash, ZERO_HASH};
use misaka_dag::dag_block_ingestion::IngestAction;
use misaka_dag::dag_p2p::{DagP2pMessage, DagSyncManager, SyncAction};
use misaka_dag::{DagNodeState, DagStore};

// ═══════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════

/// Maximum per-peer known-hash inventory size.
pub const MAX_INVENTORY_PER_PEER: usize = 16_384;

/// Channel capacity for inbound P2P messages.
pub const INBOUND_CHANNEL_SIZE: usize = 1024;

/// Channel capacity for outbound P2P messages.
pub const OUTBOUND_CHANNEL_SIZE: usize = 512;

/// Tick interval for IngestionPipeline retries (milliseconds).
pub const PIPELINE_TICK_MS: u64 = 500;

/// Periodic sync poll interval in ticks.
///
/// With the default tick interval this emits a catch-up pulse every 10 seconds.
pub const PERIODIC_SYNC_POLL_TICKS: u64 = 20;

fn tx_payload_requires_admission_gate(txs_json: &[u8]) -> bool {
    let trimmed = txs_json
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect::<Vec<_>>();
    !(trimmed.is_empty() || trimmed == b"[]")
}

// ═══════════════════════════════════════════════════════════════
//  Peer Inventory
// ═══════════════════════════════════════════════════════════════

/// Per-peer inventory — tracks which block hashes a peer has announced.
///
/// When we receive a NewDagBlock or DagInventory, we add hashes here.
/// When we need a block, we only request it from peers whose inventory
/// contains the hash.
#[derive(Debug)]
pub struct PeerInventory {
    /// Known block hashes for this peer.
    pub known: HashSet<Hash>,
    /// Peer's last announced blue_score.
    pub blue_score: u64,
    /// Peer's last announced tips.
    pub tips: Vec<Hash>,
    /// Peer's advertised listen address (from DagHello).
    pub listen_addr: Option<String>,
    /// SEC-L3: Last time this inventory received any update.
    /// Used by periodic GC to remove stale (disconnected) peer inventories.
    pub last_activity: std::time::Instant,
}

/// SEC-L3: Maximum idle time before a peer inventory is eligible for GC.
const INVENTORY_IDLE_TIMEOUT_SECS: u64 = 600; // 10 minutes

impl PeerInventory {
    pub fn new() -> Self {
        Self {
            known: HashSet::new(),
            blue_score: 0,
            tips: Vec::new(),
            listen_addr: None,
            last_activity: std::time::Instant::now(),
        }
    }

    /// Add a hash to the inventory, evicting old entries if over capacity.
    pub fn add(&mut self, hash: Hash) {
        self.last_activity = std::time::Instant::now();
        if self.known.len() >= MAX_INVENTORY_PER_PEER {
            // Simple eviction: clear half the set.
            // Production would use a proper LRU, but this prevents unbounded growth.
            let to_remove: Vec<Hash> = self
                .known
                .iter()
                .take(MAX_INVENTORY_PER_PEER / 2)
                .copied()
                .collect();
            for h in to_remove {
                self.known.remove(&h);
            }
        }
        self.known.insert(hash);
    }

    /// Check if the peer is known to have a specific block.
    pub fn contains(&self, hash: &Hash) -> bool {
        self.known.contains(hash)
    }

    /// Touch the inventory (mark as active).
    pub fn touch(&mut self) {
        self.last_activity = std::time::Instant::now();
    }

    /// Whether this inventory is stale (no activity for INVENTORY_IDLE_TIMEOUT_SECS).
    pub fn is_stale(&self) -> bool {
        self.last_activity.elapsed() > std::time::Duration::from_secs(INVENTORY_IDLE_TIMEOUT_SECS)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Inbound Event (from P2P transport)
// ═══════════════════════════════════════════════════════════════

/// A message received from a peer, ready for processing.
#[derive(Debug)]
pub struct InboundDagEvent {
    /// Peer identifier (e.g., truncated public key hash).
    pub peer_id: misaka_p2p::PeerId,
    /// The P2P message payload.
    pub message: DagP2pMessage,
}

/// An outbound message to be sent to a specific peer (or broadcast).
#[derive(Debug, Clone)]
pub struct OutboundDagEvent {
    /// Target peer. If None, broadcast to all connected peers.
    pub peer_id: Option<misaka_p2p::PeerId>,
    /// The message to send.
    pub message: DagP2pMessage,
}

// ═══════════════════════════════════════════════════════════════
//  DagP2pEventLoop
// ═══════════════════════════════════════════════════════════════

/// Main DAG P2P event loop (legacy GhostDAG pipeline).
///
/// # SEC-AUDIT WARNING
///
/// This module uses `serde_json::from_slice` for TX deserialization (line ~987)
/// while the production Narwhal executor uses `borsh::from_slice`. These formats
/// are NOT deterministically equivalent. This module is NOT used in the Narwhal
/// consensus path (DagP2pEventLoop is not instantiated in main.rs for Narwhal mode).
///
/// If this module is ever reactivated, ALL TX deserialization MUST be migrated to borsh.
///
/// # Lifecycle
///
/// 1. Spawn with `DagP2pEventLoop::run()`
/// 2. Feed inbound messages via `inbound_tx`
/// 3. Read outbound messages from `outbound_rx`
/// 4. The loop processes messages, drives the ingestion pipeline,
///    runs sync state transitions, and emits outbound messages.
pub struct DagP2pEventLoop {
    /// Per-peer sync managers.
    peer_syncs: HashMap<misaka_p2p::PeerId, DagSyncManager>,
    /// Per-peer inventory.
    inventories: HashMap<misaka_p2p::PeerId, PeerInventory>,
    /// Shared DAG node state (block store, virtual state, etc.).
    state: Arc<RwLock<DagNodeState>>,
    /// Inbound message receiver.
    inbound_rx: mpsc::Receiver<InboundDagEvent>,
    /// Outbound message sender.
    outbound_tx: mpsc::Sender<OutboundDagEvent>,
    /// Local chain ID for handshake validation.
    chain_id: u32,
    /// Shared live observation state for DAG P2P surfaces.
    observation: Arc<RwLock<DagP2pObservationState>>,
    /// Local tips already announced to peers.
    announced_local_tips: HashSet<Hash>,
    /// Tick counter for periodic block locator polling.
    sync_poll_ticks: u64,
    /// P0-3: Per-peer TX admission rate gate.
    /// Prevents a single peer from monopolizing ZKP verification CPU.
    tx_admission_gate: misaka_mempool::PeerTxAdmissionGate,
}

impl DagP2pEventLoop {
    /// Create a new event loop with channels.
    ///
    /// Returns `(event_loop, inbound_tx, outbound_rx, observation, outbound_tx_clone)`.
    /// The caller sends InboundDagEvent to `inbound_tx` and reads
    /// OutboundDagEvent from `outbound_rx`.
    /// `outbound_tx_clone` is for the BFT event loop to inject outbound messages.
    pub fn new(
        state: Arc<RwLock<DagNodeState>>,
        chain_id: u32,
    ) -> (
        Self,
        mpsc::Sender<InboundDagEvent>,
        mpsc::Receiver<OutboundDagEvent>,
        Arc<RwLock<DagP2pObservationState>>,
    ) {
        let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_CHANNEL_SIZE);
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_CHANNEL_SIZE);
        let observation: Arc<RwLock<DagP2pObservationState>> =
            Arc::new(RwLock::new(DagP2pObservationState::default()));

        let event_loop = Self {
            peer_syncs: HashMap::new(),
            inventories: HashMap::new(),
            state,
            inbound_rx,
            outbound_tx,
            chain_id,
            observation: observation.clone(),
            announced_local_tips: HashSet::new(),
            sync_poll_ticks: 0,
            tx_admission_gate: misaka_mempool::PeerTxAdmissionGate::new(),
        };

        (event_loop, inbound_tx, outbound_rx, observation)
    }

    /// Run the event loop. This is the main async task.
    ///
    /// Listens for:
    /// - Inbound P2P messages → dispatches to sync/ingestion
    /// - Pipeline tick timer → retries pending parent fetches
    pub async fn run(mut self) {
        let mut tick = tokio::time::interval(tokio::time::Duration::from_millis(PIPELINE_TICK_MS));

        info!("DAG P2P event loop started");

        loop {
            tokio::select! {
                // ── Inbound message ──
                msg = self.inbound_rx.recv() => {
                    match msg {
                        Some(event) => self.handle_inbound(event).await,
                        None => {
                            info!("DAG P2P event loop: inbound channel closed, shutting down");
                            break;
                        }
                    }
                }

                // ── Pipeline tick (retry missing parents, timeout eviction) ──
                _ = tick.tick() => {
                    self.handle_tick().await;
                }
            }
        }
    }

    // ─── Inbound Message Dispatch ───

    async fn handle_inbound(&mut self, event: InboundDagEvent) {
        let peer_id = event.peer_id;
        observe_dag_p2p_message(DagP2pDirection::Inbound, &event.message, Some(&peer_id));
        self.observation.write().await.record(
            DagP2pDirection::Inbound,
            &event.message,
            Some(&peer_id),
        );

        match event.message {
            // ── Handshake ──
            DagP2pMessage::DagHello {
                chain_id,
                dag_version: _,
                blue_score,
                tips,
                pruning_point,
                node_name: _,
                mode: _,
                listen_addr,
            } => {
                if chain_id != self.chain_id {
                    warn!(
                        "Peer {} has wrong chain_id {} (expected {}), disconnecting",
                        peer_id.short_hex(),
                        chain_id,
                        self.chain_id
                    );
                    return;
                }

                let sync = self.get_or_create_sync(&peer_id).await;
                let actions = sync.on_dag_hello(tips.clone(), blue_score, pruning_point);

                // Update inventory
                let inv = self
                    .inventories
                    .entry(peer_id)
                    .or_insert_with(PeerInventory::new);
                inv.blue_score = blue_score;
                inv.tips = tips.clone();
                inv.listen_addr = listen_addr;
                for tip in &tips {
                    inv.add(*tip);
                }

                self.process_sync_actions(peer_id, actions).await;
            }

            // ── Block Locator ──
            DagP2pMessage::BlockLocator {
                hashes,
                tip_blue_score,
                pruning_point,
            } => {
                let sync = self.get_or_create_sync(&peer_id).await;
                let actions = sync.on_block_locator(&hashes, tip_blue_score, pruning_point);
                self.process_sync_actions(peer_id, actions).await;
            }

            DagP2pMessage::GetBlockLocator => {
                // Build our locator and send it back
                let guard = self.state.read().await;
                let snapshot = guard.dag_store.snapshot();
                let tips = snapshot.get_tips();
                let genesis = guard.genesis_hash;
                let max_score = guard.dag_store.max_blue_score();

                // Use the highest-score tip as the locator start
                let best_tip = tips
                    .iter()
                    .max_by_key(|t| {
                        snapshot
                            .get_ghostdag_data(t)
                            .map(|d| d.blue_score)
                            .unwrap_or(0)
                    })
                    .copied()
                    .unwrap_or(genesis);

                let locator = misaka_dag::build_block_locator(
                    best_tip,
                    |h| snapshot.get_ghostdag_data(h).map(|d| d.selected_parent),
                    genesis,
                );

                let pruning_point = guard
                    .latest_checkpoint
                    .as_ref()
                    .map(|cp| cp.block_hash)
                    .unwrap_or(genesis);

                drop(guard);

                self.send_to_peer(
                    peer_id,
                    DagP2pMessage::BlockLocator {
                        hashes: locator,
                        tip_blue_score: max_score,
                        pruning_point,
                    },
                )
                .await;
            }

            // ── Header Sync ──
            DagP2pMessage::Headers {
                headers_json,
                count: _,
                has_more,
            } => {
                // Deserialize headers
                let headers: Vec<(Hash, Vec<u8>)> = match serde_json::from_slice(&headers_json) {
                    Ok(h) => h,
                    Err(e) => {
                        warn!(
                            "Failed to deserialize headers from {}: {}",
                            peer_id.short_hex(),
                            e
                        );
                        if let Some(sync) = self.peer_syncs.get_mut(&peer_id) {
                            sync.on_validation_failed(&ZERO_HASH, "malformed headers");
                        }
                        return;
                    }
                };

                let sync = self.get_or_create_sync(&peer_id).await;
                let actions = sync.on_headers(&headers, has_more);
                self.process_sync_actions(peer_id, actions).await;
            }

            // ── Body Download ──
            DagP2pMessage::Bodies { blocks } => {
                // blocks: Vec<(Hash, Vec<u8>)> → need to split into (hash, header, txs)
                let bodies: Vec<(Hash, Vec<u8>, Vec<u8>)> = blocks
                    .iter()
                    .map(|(hash, data)| {
                        // For now, the data contains serialized block (header + txs)
                        (*hash, data.clone(), vec![])
                    })
                    .collect();

                let sync = self.get_or_create_sync(&peer_id).await;
                let actions = sync.on_bodies(&bodies);
                self.process_sync_actions(peer_id, actions).await;
            }

            // ── Steady-State: New Block Announcement ──
            DagP2pMessage::NewDagBlock {
                hash,
                parents,
                blue_score: _,
                timestamp_ms: _,
                tx_count: _,
                proposer_id: _,
            } => {
                // ── Quarantine Relay Gate: skip quarantined blocks ──
                {
                    let guard = self.state.read().await;
                    if guard.quarantined_blocks.contains(&hash) {
                        debug!(
                            "Ignoring quarantined block {} from {}",
                            hex::encode(&hash[..4]),
                            peer_id.short_hex()
                        );
                        return;
                    }
                }

                // Update inventory
                let inv = self
                    .inventories
                    .entry(peer_id)
                    .or_insert_with(PeerInventory::new);
                inv.add(hash);
                for p in &parents {
                    inv.add(*p);
                }

                // Check if we already know this block
                let guard = self.state.read().await;
                let known = guard.dag_store.snapshot().get_header(&hash).is_some();
                drop(guard);

                if known {
                    return;
                }

                // Feed to sync manager for missing parent detection
                if let Some(sync) = self.peer_syncs.get_mut(&peer_id) {
                    let actions = sync.on_new_block(hash, &parents);
                    self.process_sync_actions(peer_id, actions).await;
                }

                // Request full block data
                self.send_to_peer(peer_id, DagP2pMessage::GetDagBlocks { hashes: vec![hash] })
                    .await;
            }

            // ── Full Block Data (from GetDagBlocks response) ──
            DagP2pMessage::DagBlockData {
                hash,
                header_json,
                txs_json,
            } => {
                self.handle_full_block(peer_id, hash, header_json, txs_json)
                    .await;
            }

            // ── Inventory ──
            DagP2pMessage::DagInventory {
                from_blue_score: _,
                to_blue_score: _,
                block_hashes,
            } => {
                let inv = self
                    .inventories
                    .entry(peer_id)
                    .or_insert_with(PeerInventory::new);
                for h in &block_hashes {
                    inv.add(*h);
                }

                // Request any unknown blocks
                let guard = self.state.read().await;
                let unknown: Vec<Hash> = block_hashes
                    .iter()
                    .filter(|h| guard.dag_store.snapshot().get_header(h).is_none())
                    .copied()
                    .collect();
                drop(guard);

                if !unknown.is_empty() {
                    self.send_to_peer(peer_id, DagP2pMessage::GetDagBlocks { hashes: unknown })
                        .await;
                }
            }

            // ── Pruning Proof ──
            DagP2pMessage::GetPruningProof => {
                // Serve our pruning proof to the requesting peer
                let guard = self.state.read().await;
                if let Some(cp) = &guard.latest_checkpoint {
                    let snapshot = guard.dag_store.snapshot();
                    if let Some(proof) = misaka_dag::PruningProof::build(
                        cp.block_hash,
                        &snapshot,
                        cp.utxo_root,
                        ZERO_HASH,
                    ) {
                        let proof_json = serde_json::to_vec(&proof).unwrap_or_default();
                        drop(guard);
                        self.send_to_peer(peer_id, DagP2pMessage::PruningProofData { proof_json })
                            .await;
                    }
                }
            }

            // ── Tips request ──
            DagP2pMessage::GetDagTips => {
                let guard = self.state.read().await;
                let snapshot = guard.dag_store.snapshot();
                let tips = snapshot.get_tips();
                let max_score = guard.dag_store.max_blue_score();
                drop(guard);

                self.send_to_peer(
                    peer_id,
                    DagP2pMessage::DagTips {
                        tips,
                        max_blue_score: max_score,
                    },
                )
                .await;
            }

            // ── Request for specific blocks (serve) ──
            DagP2pMessage::GetDagBlocks { hashes } => {
                let guard = self.state.read().await;
                let snapshot = guard.dag_store.snapshot();
                for hash in hashes {
                    if let Some(header) = snapshot.get_header(&hash) {
                        let header_json = serde_json::to_vec(&header).unwrap_or_default();
                        // SEC-FIX-4: Retrieve real block body from storage.
                        // Serialize stored TXs to JSON for transmission.
                        let block_txs = guard.dag_store.get_block_txs(&hash);
                        let txs_json = if block_txs.is_empty() {
                            warn!(
                                "GetDagBlocks: serving header-only for {} (no TXs stored)",
                                hex::encode(&hash[..4])
                            );
                            vec![]
                        } else {
                            serde_json::to_vec(&block_txs).unwrap_or_default()
                        };
                        drop(guard);
                        self.send_to_peer(
                            peer_id,
                            DagP2pMessage::DagBlockData {
                                hash,
                                header_json,
                                txs_json,
                            },
                        )
                        .await;
                        return; // simplified: one at a time
                    }
                }
            }

            // ── Peer Discovery Gossip ──
            DagP2pMessage::GetPeers => {
                // Respond with our known connected peers
                let peers: Vec<misaka_dag::dag_p2p::PeerInfo> = self
                    .inventories
                    .iter()
                    .filter_map(|(id, inv)| {
                        inv.listen_addr
                            .as_ref()
                            .map(|addr| misaka_dag::dag_p2p::PeerInfo {
                                listen_addr: addr.clone(),
                                peer_id: hex::encode(&id.0),
                                blue_score: inv.blue_score,
                            })
                    })
                    .collect();

                if !peers.is_empty() {
                    self.send_to_peer(peer_id, DagP2pMessage::Peers { peers })
                        .await;
                }
            }

            DagP2pMessage::Peers { peers } => {
                // Feed discovered peers into the inbound channel as synthetic DagHello
                // candidates. The transport layer will decide whether to connect.
                let mut obs = self.observation.write().await;

                // SEC-FIX-7: Limit peers accepted from a single source to prevent
                // one malicious peer from filling the entire discovery list.
                let max_per_source: usize = 5;
                let mut accepted_from_source = 0usize;

                for peer_info in peers {
                    if accepted_from_source >= max_per_source {
                        debug!(
                            "Discovery: per-source limit ({}) reached for {}",
                            max_per_source,
                            peer_id.short_hex(),
                        );
                        break;
                    }

                    // SEC-FIX-3: Reject private/reserved IP addresses from discovery
                    // to prevent SSRF-style attacks via crafted peer gossip.
                    if is_discovery_addr_rejected(&peer_info.listen_addr) {
                        debug!(
                            "Discovery: rejecting private/reserved addr '{}' from {}",
                            peer_info.listen_addr,
                            peer_id.short_hex(),
                        );
                        continue;
                    }

                    // SEC-FIX-7: Deduplication — skip if already in the list.
                    if obs
                        .discovered_peers
                        .iter()
                        .any(|dp| dp.address == peer_info.listen_addr)
                    {
                        continue;
                    }

                    // SEC-FIX-7: Subnet diversity — reject if we already have too many
                    // peers in the same /24 (IPv4) or /48 (IPv6) subnet.
                    let max_per_subnet: usize = 3;
                    let subnet_prefix = extract_subnet_prefix(&peer_info.listen_addr);
                    if let Some(ref prefix) = subnet_prefix {
                        let same_subnet_count = obs
                            .discovered_peers
                            .iter()
                            .filter(|dp| {
                                extract_subnet_prefix(&dp.address)
                                    .as_ref()
                                    .map(|p| p == prefix)
                                    .unwrap_or(false)
                            })
                            .count();
                        if same_subnet_count >= max_per_subnet {
                            debug!(
                                "Discovery: subnet {} already has {} peers, skipping {}",
                                prefix, same_subnet_count, peer_info.listen_addr,
                            );
                            continue;
                        }
                    }

                    debug!(
                        "Discovered peer via gossip: {} (score={}, from={})",
                        peer_info.listen_addr,
                        peer_info.blue_score,
                        peer_id.short_hex(),
                    );
                    obs.discovered_peers
                        .push(crate::dag_p2p_surface::DiscoveredPeer {
                            address: peer_info.listen_addr,
                            // DagHello-based discovery doesn't carry transport PK.
                            // TODO: When PeerRecord gossip is implemented, populate
                            // this from PeerRecord.transport_pubkey for verified dials.
                            transport_pubkey: None,
                        });
                    accepted_from_source += 1;
                }
                // Cap discovered list to prevent memory growth
                if obs.discovered_peers.len() > 100 {
                    let excess = obs.discovered_peers.len() - 100;
                    obs.discovered_peers.drain(0..excess);
                }
            }

            // Other messages (including BFT): log and ignore
            _other => {
                debug!(
                    "Unhandled DAG P2P message from {}: {:?}",
                    peer_id.short_hex(),
                    std::mem::discriminant(&_other)
                );
            }
        }
    }

    // ─── Full Block Ingestion ───

    /// Process a received full block (header + txs) through the IngestionPipeline.
    async fn handle_full_block(
        &mut self,
        peer_id: misaka_p2p::PeerId,
        hash: Hash,
        header_json: Vec<u8>,
        txs_json: Vec<u8>,
    ) {
        self.observation.write().await.record_ingest_attempt(hash);

        // ── P0-2: Cheap structural pre-checks BEFORE deserialization ──
        // Reject obviously invalid payloads before spending CPU on JSON
        // parsing and cryptographic verification.
        const MAX_HEADER_JSON: usize = 64 * 1024; // 64 KB
        const MAX_TXS_JSON: usize = 2 * 1024 * 1024; // 2 MB
        if header_json.len() > MAX_HEADER_JSON {
            warn!(
                "P0-2: Rejecting block {} from {} — header_json too large ({} bytes, max {})",
                hex::encode(&hash[..4]),
                peer_id.short_hex(),
                header_json.len(),
                MAX_HEADER_JSON,
            );
            if let Some(sync) = self.peer_syncs.get_mut(&peer_id) {
                sync.on_validation_failed(&hash, "header_json too large");
            }
            return;
        }
        if txs_json.len() > MAX_TXS_JSON {
            warn!(
                "P0-2: Rejecting block {} from {} — txs_json too large ({} bytes, max {})",
                hex::encode(&hash[..4]),
                peer_id.short_hex(),
                txs_json.len(),
                MAX_TXS_JSON,
            );
            if let Some(sync) = self.peer_syncs.get_mut(&peer_id) {
                sync.on_validation_failed(&hash, "txs_json too large");
            }
            return;
        }

        // ── P0-3: Per-peer TX admission rate gate ──
        // Check BEFORE JSON deserialization and ingestion pipeline.
        // This prevents a single peer from submitting blocks at a rate
        // that exhausts the ZKP verification CPU budget.
        let tx_gate_reserved = if tx_payload_requires_admission_gate(&txs_json) {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            if let Err(reason) = self.tx_admission_gate.check(&peer_id.0, now_ms) {
                warn!(
                    "P0-3: Rejecting block {} from {} — {}",
                    hex::encode(&hash[..4]),
                    peer_id.short_hex(),
                    reason,
                );
                return;
            }
            true
        } else {
            false
        };

        let header: DagBlockHeader = match serde_json::from_slice(&header_json) {
            Ok(h) => h,
            Err(e) => {
                self.observation
                    .write()
                    .await
                    .record_ingest_error(hash, format!("malformed header JSON: {}", e));
                warn!(
                    "Failed to deserialize block header from {}: {}",
                    peer_id.short_hex(),
                    e
                );
                if let Some(sync) = self.peer_syncs.get_mut(&peer_id) {
                    sync.on_validation_failed(&hash, "malformed header JSON");
                }
                return;
            }
        };

        // Feed into IngestionPipeline
        let mut guard = self.state.write().await;
        let snapshot = guard.dag_store.snapshot();

        if snapshot.get_header(&hash).is_some() {
            guard.ingestion_pipeline.add_known(hash);
            debug!(
                "Skipping P2P ingest for already-known block {}",
                hex::encode(&hash[..4])
            );
            if tx_gate_reserved {
                self.tx_admission_gate.complete_evaluation();
            }
            return;
        }

        for parent in &header.parents {
            if *parent != ZERO_HASH && snapshot.get_header(parent).is_some() {
                guard.ingestion_pipeline.add_known(*parent);
            }
        }

        let ingest_result = guard
            .ingestion_pipeline
            .ingest_block(hash, header, txs_json.clone());

        match ingest_result {
            Ok(actions) => {
                // Process IngestActions
                for action in actions {
                    match action {
                        IngestAction::ValidateBlock { block_hash } => {
                            // Run validation through the atomic pipeline
                            self.run_block_validation(&mut guard, block_hash).await;
                        }
                        IngestAction::FetchParents { missing, .. } => {
                            self.observation
                                .write()
                                .await
                                .record_ingest_fetch_parents(hash);
                            // Request missing parents from the peer
                            drop(guard);
                            self.send_to_peer(
                                peer_id,
                                DagP2pMessage::GetDagBlocks { hashes: missing },
                            )
                            .await;
                            if tx_gate_reserved {
                                self.tx_admission_gate.complete_evaluation();
                            }
                            return;
                        }
                        IngestAction::SendP2p(msg) => {
                            drop(guard);
                            self.send_to_peer(peer_id, msg).await;
                            if tx_gate_reserved {
                                self.tx_admission_gate.complete_evaluation();
                            }
                            return;
                        }
                        IngestAction::BlockAccepted { block_hash } => {
                            self.observation
                                .write()
                                .await
                                .record_ingest_accepted(block_hash);
                            info!("Block {} accepted via P2P", hex::encode(&block_hash[..4]));
                        }
                        IngestAction::BlockRejected { block_hash, reason } => {
                            self.observation
                                .write()
                                .await
                                .record_ingest_rejected(block_hash, reason.clone());
                            warn!(
                                "Block {} rejected: {}",
                                hex::encode(&block_hash[..4]),
                                reason
                            );
                            if let Some(sync) = self.peer_syncs.get_mut(&peer_id) {
                                sync.on_validation_failed(&block_hash, &reason);
                            }
                        }
                        IngestAction::BlockQuarantined {
                            block_hash,
                            reason,
                            source_peer,
                        } => {
                            // ── Quarantine Relay Gate (No-Rollback Architecture) ──
                            //
                            // Quarantined blocks are:
                            // 1. Added to quarantined_blocks set (fast O(1) relay gate)
                            // 2. NEVER relayed to any peer
                            // 3. Source peer is penalized
                            //
                            // The QuarantineStore persistence is done at the node layer
                            // (main.rs) using the quarantine_store module.
                            guard.quarantined_blocks.insert(block_hash);

                            self.observation.write().await.record_ingest_rejected(
                                block_hash,
                                format!("QUARANTINED: {}", reason),
                            );
                            warn!(
                                "Block {} QUARANTINED: {} (source: {})",
                                hex::encode(&block_hash[..4]),
                                reason,
                                source_peer
                                    .map(|p| hex::encode(&p[..4]))
                                    .unwrap_or_else(|| "unknown".into()),
                            );

                            if let Some(sync) = self.peer_syncs.get_mut(&peer_id) {
                                sync.on_validation_failed(&block_hash, &reason);
                            }
                        }
                        IngestAction::BlockTimedOut { block_hash } => {
                            self.observation
                                .write()
                                .await
                                .record_ingest_timed_out(block_hash);
                            debug!(
                                "Block {} timed out in pending",
                                hex::encode(&block_hash[..4])
                            );
                        }
                    }
                }
            }
            Err(e) => {
                self.observation
                    .write()
                    .await
                    .record_ingest_error(hash, format!("ingestion error: {}", e));
                debug!("Block {} ingestion error: {}", hex::encode(&hash[..4]), e);
            }
        }
        // P0-3: Release the admission gate slot after all processing paths.
        if tx_gate_reserved {
            self.tx_admission_gate.complete_evaluation();
        }
    }

    /// Run block validation through the atomic pipeline.
    ///
    /// This is the critical path that connects P2P → Consensus:
    /// 1. Header topology validation
    /// 2. GhostDAG calculation
    /// 3. Reachability update
    /// 4. VirtualState resolve
    /// 5. Atomic commit
    async fn run_block_validation(&self, guard: &mut DagNodeState, block_hash: Hash) {
        // Retrieve the pending block from the pipeline
        let pending_block = match guard.ingestion_pipeline.get_pending_block(&block_hash) {
            Some(pb) => pb,
            None => return,
        };

        let header = pending_block.header.clone();
        let _txs_payload = pending_block.txs_payload.clone();

        // Stage 1: Header topology validation
        let snapshot = guard.dag_store.snapshot();
        if let Err(e) =
            misaka_dag::validate_header_topology(&header.parents, header.blue_score, &snapshot)
        {
            let reason = format!("header topology invalid: {}", e);
            self.observation
                .write()
                .await
                .record_ingest_rejected(block_hash, reason.clone());
            // Quarantine: topology failures are consensus-critical
            guard
                .ingestion_pipeline
                .mark_quarantined(block_hash, reason, None);
            return;
        }

        // Stage 2-5: Run through atomic pipeline
        // SEC-FIX-4: Deserialize received transaction body and validate.
        // Empty body is acceptable only for empty blocks (coinbase-only).
        let received_txs: Vec<misaka_types::utxo::UtxoTransaction> = if _txs_payload.is_empty() {
            vec![]
        } else {
            match serde_json::from_slice(&_txs_payload) {
                Ok(txs) => txs,
                Err(e) => {
                    let reason = format!("malformed txs_json body: {}", e);
                    self.observation
                        .write()
                        .await
                        .record_ingest_rejected(block_hash, reason.clone());
                    guard
                        .ingestion_pipeline
                        .mark_quarantined(block_hash, reason, None);
                    return;
                }
            }
        };

        // For now, use the simpler insertion path:
        let computed_hash = header.compute_hash();
        if computed_hash != block_hash {
            self.observation
                .write()
                .await
                .record_ingest_rejected(block_hash, "hash mismatch");
            // Quarantine: hash mismatch is tamper indicator
            guard.ingestion_pipeline.mark_quarantined(
                block_hash,
                "hash mismatch".to_string(),
                None,
            );
            return;
        }

        // Insert into DAG store
        let ghostdag_data = match guard.ghostdag.try_calculate(
            &block_hash,
            &header.parents,
            &snapshot,
            &guard.reachability,
            &misaka_dag::UniformStakeProvider,
        ) {
            Ok(data) => data,
            Err(e) => {
                self.observation.write().await.record_ingest_rejected(
                    block_hash,
                    format!("ghostdag calculation failed: {}", e),
                );
                // Quarantine: GhostDAG failures (k-cluster violation, mergeset overflow, etc.)
                guard.ingestion_pipeline.mark_quarantined(
                    block_hash,
                    format!("ghostdag: {}", e),
                    None,
                );
                return;
            }
        };

        // SEC-FIX-4: Store the actual received TXs, not an empty vec.
        if let Err(e) = guard
            .dag_store
            .insert_block(block_hash, header.clone(), received_txs)
        {
            self.observation
                .write()
                .await
                .record_ingest_rejected(block_hash, format!("dag store insert failed: {}", e));
            guard
                .ingestion_pipeline
                .mark_rejected(block_hash, format!("dag store insert failed: {}", e));
            return;
        }
        guard
            .dag_store
            .set_ghostdag(block_hash, ghostdag_data.clone());

        // Update reachability
        let parent = ghostdag_data.selected_parent;
        if parent != ZERO_HASH {
            let _ = guard.reachability.add_child(parent, block_hash);
        }

        // Mark block as accepted in the ingestion pipeline.
        //
        // NOTE: VirtualState::resolve() is NOT called here directly because it
        // requires (new_tip, new_tip_score, diffs, reachability, store) which
        // the block production loop already manages. The block is now in the DAG
        // store with correct GhostDAG data, and the next finality/production cycle
        // will incorporate it into the VirtualState via the existing resolve path.
        let actions = guard.ingestion_pipeline.mark_accepted(block_hash);
        for action in actions {
            if let IngestAction::ValidateBlock { block_hash: child } = action {
                debug!(
                    "Child block {} woken by {} acceptance, will validate on next tick",
                    hex::encode(&child[..4]),
                    hex::encode(&block_hash[..4])
                );
            }
        }

        info!(
            "P2P block accepted: {} (score={})",
            hex::encode(&block_hash[..4]),
            ghostdag_data.blue_score,
        );
    }

    // ─── Pipeline Tick ───

    async fn handle_tick(&mut self) {
        let mut guard = self.state.write().await;
        let actions = guard.ingestion_pipeline.tick();
        drop(guard);

        for action in actions {
            match action {
                IngestAction::FetchParents { missing, .. } => {
                    if let Some(first_missing) = missing.first().copied() {
                        self.observation
                            .write()
                            .await
                            .record_ingest_fetch_parents(first_missing);
                    }
                    // Broadcast parent request to all peers
                    self.broadcast(DagP2pMessage::GetDagBlocks { hashes: missing })
                        .await;
                }
                IngestAction::BlockTimedOut { block_hash } => {
                    self.observation
                        .write()
                        .await
                        .record_ingest_timed_out(block_hash);
                    debug!(
                        "Block {} evicted from pending (timeout)",
                        hex::encode(&block_hash[..4])
                    );
                }
                _ => {}
            }
        }

        self.announce_local_tips().await;

        self.sync_poll_ticks = self.sync_poll_ticks.saturating_add(1);
        if self.sync_poll_ticks >= PERIODIC_SYNC_POLL_TICKS {
            self.sync_poll_ticks = 0;
            self.broadcast(DagP2pMessage::GetBlockLocator).await;

            // SEC-L3: GC stale peer inventories (peers that disconnected without
            // cleanup, or whose transport connection silently died).
            let before = self.inventories.len();
            self.inventories.retain(|pid, inv| {
                if inv.is_stale() {
                    debug!("GC stale inventory for peer {}", pid.short_hex());
                    false
                } else {
                    true
                }
            });
            let removed = before - self.inventories.len();
            if removed > 0 {
                debug!("Inventory GC: removed {} stale peer entries", removed);
            }
        }
    }

    // ─── SyncAction → OutboundMessage ───

    async fn process_sync_actions(
        &mut self,
        peer_id: misaka_p2p::PeerId,
        actions: Vec<SyncAction>,
    ) {
        for action in actions {
            match action {
                SyncAction::Send(msg) => {
                    self.send_to_peer(peer_id, msg).await;
                }
                SyncAction::Ban(reason) => {
                    warn!("Banning peer {}: {}", peer_id.short_hex(), reason);
                    self.peer_syncs.remove(&peer_id);
                    self.inventories.remove(&peer_id);
                }
                SyncAction::ProcessBlock {
                    hash,
                    header_json,
                    txs_json,
                } => {
                    self.handle_full_block(peer_id, hash, header_json, txs_json)
                        .await;
                }
                SyncAction::ValidateHeader { hash, header_json } => {
                    // During IBD header-only phase, validate without body
                    let header: Result<DagBlockHeader, _> = serde_json::from_slice(&header_json);
                    match header {
                        Ok(hdr) => {
                            let guard = self.state.read().await;
                            let snapshot = guard.dag_store.snapshot();
                            let valid = misaka_dag::validate_header_topology(
                                &hdr.parents,
                                hdr.blue_score,
                                &snapshot,
                            )
                            .is_ok();
                            drop(guard);

                            if let Some(sync) = self.peer_syncs.get_mut(&peer_id) {
                                if !valid {
                                    sync.on_validation_failed(
                                        &hash,
                                        "header topology check failed",
                                    );
                                }
                            }
                        }
                        Err(_) => {
                            if let Some(sync) = self.peer_syncs.get_mut(&peer_id) {
                                sync.on_validation_failed(&hash, "invalid header JSON");
                            }
                        }
                    }
                }
            }
        }
    }

    async fn announce_local_tips(&mut self) {
        let announcements: Vec<(Hash, DagP2pMessage)> = {
            let guard = self.state.read().await;
            let snapshot = guard.dag_store.snapshot();
            let genesis_hash = guard.genesis_hash;

            let mut announcements = Vec::new();
            for tip in snapshot.get_tips() {
                if tip == genesis_hash || self.announced_local_tips.contains(&tip) {
                    continue;
                }
                let Some(header) = snapshot.get_header(&tip).cloned() else {
                    continue;
                };
                let blue_score = snapshot
                    .get_ghostdag_data(&tip)
                    .map(|data| data.blue_score)
                    .unwrap_or(header.blue_score);

                let message = DagP2pMessage::NewDagBlock {
                    hash: tip,
                    parents: header.parents.clone(),
                    blue_score,
                    timestamp_ms: header.timestamp_ms,
                    tx_count: 0,
                    proposer_id: header.proposer_id,
                };
                announcements.push((tip, message));
            }

            announcements
        };

        for (tip, message) in announcements {
            self.broadcast(message).await;
            self.announced_local_tips.insert(tip);
        }
    }

    // ─── Helpers ───

    #[allow(clippy::unwrap_used)] // get_mut follows unconditional insert above
    async fn get_or_create_sync(&mut self, peer_id: &misaka_p2p::PeerId) -> &mut DagSyncManager {
        if !self.peer_syncs.contains_key(peer_id) {
            let mut sync: DagSyncManager = DagSyncManager::new();
            let guard = self.state.read().await;
            let snapshot = guard.dag_store.snapshot();

            // Seed the sync view from the full persisted DAG snapshot.
            //
            // After restart, the DAG store can already contain a large set of
            // ancestors that are not tips anymore. If we only seed tips here,
            // the peer sync state will rediscover already-persisted blocks as
            // missing parents and fall back to genesis during locator matching.
            sync.set_local_blue_score(guard.dag_store.max_blue_score());
            for hash in snapshot.all_hashes() {
                sync.add_known(hash);
            }
            drop(guard);
            self.peer_syncs.insert(*peer_id, sync);
        }
        self.peer_syncs
            .get_mut(peer_id)
            .expect("INVARIANT: peer_syncs.insert() called on line above; key must exist")
    }

    async fn send_to_peer(&self, peer_id: misaka_p2p::PeerId, message: DagP2pMessage) {
        observe_dag_p2p_message(DagP2pDirection::OutboundUnicast, &message, Some(&peer_id));
        self.observation.write().await.record(
            DagP2pDirection::OutboundUnicast,
            &message,
            Some(&peer_id),
        );
        if let Err(e) = self
            .outbound_tx
            .send(OutboundDagEvent {
                peer_id: Some(peer_id),
                message,
            })
            .await
        {
            warn!("Failed to send outbound DAG message: {}", e);
        }
    }

    async fn broadcast(&self, message: DagP2pMessage) {
        observe_dag_p2p_message(DagP2pDirection::OutboundBroadcast, &message, None);
        self.observation
            .write()
            .await
            .record(DagP2pDirection::OutboundBroadcast, &message, None);
        if let Err(e) = self
            .outbound_tx
            .send(OutboundDagEvent {
                peer_id: None,
                message,
            })
            .await
        {
            warn!("Failed to broadcast DAG message: {}", e);
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  SEC-FIX-3: Discovery Address Validation
// ═══════════════════════════════════════════════════════════════

/// Reject private, reserved, loopback, and link-local addresses from peer
/// discovery gossip. Prevents SSRF-style attacks where a malicious peer
/// advertises internal addresses to make us connect to local services.
fn is_discovery_addr_rejected(addr_str: &str) -> bool {
    // Parse just the IP part (addr may be "host:port")
    let ip_str = if let Some(bracket_end) = addr_str.find(']') {
        // IPv6 with brackets: [::1]:8080
        &addr_str[1..bracket_end]
    } else if let Some(colon_pos) = addr_str.rfind(':') {
        // IPv4:port or bare IPv6 — try splitting at last colon for v4
        let candidate = &addr_str[..colon_pos];
        if candidate.parse::<std::net::IpAddr>().is_ok() {
            candidate
        } else {
            addr_str
        }
    } else {
        addr_str
    };

    let ip: std::net::IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => {
            // If we can't parse the IP at all, reject as suspicious
            return true;
        }
    };

    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()           // 127.0.0.0/8
            || v4.is_private()         // 10/8, 172.16/12, 192.168/16
            || v4.is_link_local()      // 169.254/16
            || v4.is_broadcast()       // 255.255.255.255
            || v4.is_unspecified()     // 0.0.0.0
            || v4.is_documentation()   // 192.0.2/24, 198.51.100/24, 203.0.113/24
            || v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64 // CGN 100.64/10
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()           // ::1
            || v6.is_unspecified()     // ::
            // Unique local fc00::/7
            || (v6.segments()[0] & 0xFE00) == 0xFC00
            // Link-local fe80::/10
            || (v6.segments()[0] & 0xFFC0) == 0xFE80
        }
    }
}

/// SEC-FIX-7: Extract subnet prefix for diversity checks.
/// Returns /24 prefix for IPv4, /48 prefix for IPv6.
fn extract_subnet_prefix(addr_str: &str) -> Option<String> {
    // Strip port if present
    let ip_str = if let Some(bracket_end) = addr_str.find(']') {
        &addr_str[1..bracket_end]
    } else if let Some(colon_pos) = addr_str.rfind(':') {
        let candidate = &addr_str[..colon_pos];
        if candidate.parse::<std::net::IpAddr>().is_ok() {
            candidate
        } else {
            addr_str
        }
    } else {
        addr_str
    };

    match ip_str.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            let o = v4.octets();
            Some(format!("{}.{}.{}", o[0], o[1], o[2]))
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            let s = v6.segments();
            Some(format!("{:x}:{:x}:{:x}", s[0], s[1], s[2]))
        }
        Err(_) => None,
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    use misaka_dag::dag_block::{DagBlockHeader, DAG_VERSION};
    use misaka_dag::dag_store::ThreadSafeDagStore;
    use misaka_dag::reachability::ReachabilityStore;
    use misaka_dag::{
        DagCheckpoint, DagMempool, DagNodeState, DagStateManager, GhostDagEngine,
        ProofVerifyResult, PruningProof,
    };
    use misaka_storage::utxo_set::UtxoSet;
    use tokio::sync::RwLock;
    use tokio::time::{timeout, Duration};

    fn peer_id(byte: u8) -> misaka_p2p::PeerId {
        misaka_p2p::PeerId::from([byte; 32])
    }

    fn make_test_dag_state() -> DagNodeState {
        let genesis_header = DagBlockHeader {
            version: DAG_VERSION,
            parents: vec![],
            timestamp_ms: 1_700_000_000_000,
            tx_root: ZERO_HASH,
            proposer_id: [0u8; 32],
            nonce: 0,
            blue_score: 0,
            bits: 0,
        };
        let genesis_hash = genesis_header.compute_hash();

        DagNodeState {
            dag_store: Arc::new(ThreadSafeDagStore::new(genesis_hash, genesis_header)),
            ghostdag: GhostDagEngine::new(18, genesis_hash),
            state_manager: DagStateManager::new(HashSet::new(), HashSet::new()),
            utxo_set: UtxoSet::new(32),
            virtual_state: misaka_dag::VirtualState::new(genesis_hash),
            ingestion_pipeline: misaka_dag::IngestionPipeline::new(
                [genesis_hash].into_iter().collect(),
            ),
            quarantined_blocks: HashSet::new(),
            mempool: DagMempool::new(32),
            chain_id: 31337,
            validator_count: 2,
            known_validators: Vec::new(),
            proposer_id: [0xAB; 32],
            sr_index: 0,
            num_active_srs: 1,
            runtime_active_sr_validator_ids: Vec::new(),
            local_validator: None,
            genesis_hash,
            snapshot_path: PathBuf::from("/tmp/misaka-dag-p2p-network-test-snapshot.json"),
            latest_checkpoint: None,
            latest_checkpoint_vote: None,
            latest_checkpoint_finality: None,
            checkpoint_vote_pool: HashMap::new(),
            attestation_rpc_peers: Vec::new(),
            blocks_produced: 0,
            reachability: ReachabilityStore::new(genesis_hash),
            persistent_backend: None,
            faucet_cooldowns: HashMap::new(),
            pending_transactions: HashMap::new(),
        }
    }

    async fn make_test_dag_state_with_checkpoint() -> DagNodeState {
        let mut state = make_test_dag_state();
        state.latest_checkpoint = Some(DagCheckpoint {
            block_hash: state.genesis_hash,
            blue_score: 0,
            utxo_root: ZERO_HASH,
            total_spent_count: 0,
            total_applied_txs: 0,
            timestamp_ms: 1_700_000_000_000,
        });
        state
    }

    async fn make_restart_sync_test_state() -> (Arc<RwLock<DagNodeState>>, Hash, Hash, Hash, Hash) {
        let state = Arc::new(RwLock::new(make_test_dag_state()));
        let genesis_hash = state.read().await.genesis_hash;

        let mid_header = DagBlockHeader {
            version: DAG_VERSION,
            parents: vec![genesis_hash],
            timestamp_ms: 1_700_000_000_001,
            tx_root: ZERO_HASH,
            proposer_id: [0xCD; 32],
            nonce: 11,
            blue_score: 1,
            bits: 0,
        };
        let mid_hash = mid_header.compute_hash();

        let tip_header = DagBlockHeader {
            version: DAG_VERSION,
            parents: vec![mid_hash],
            timestamp_ms: 1_700_000_000_002,
            tx_root: ZERO_HASH,
            proposer_id: [0xCE; 32],
            nonce: 12,
            blue_score: 2,
            bits: 0,
        };
        let tip_hash = tip_header.compute_hash();

        let remote_child_header = DagBlockHeader {
            version: DAG_VERSION,
            parents: vec![mid_hash],
            timestamp_ms: 1_700_000_000_003,
            tx_root: ZERO_HASH,
            proposer_id: [0xCF; 32],
            nonce: 13,
            blue_score: 3,
            bits: 0,
        };
        let remote_child_hash = remote_child_header.compute_hash();

        {
            let guard = state.write().await;
            guard
                .dag_store
                .insert_block(mid_hash, mid_header.clone(), vec![])
                .expect("insert mid block");
            guard.dag_store.set_ghostdag(
                mid_hash,
                misaka_dag::GhostDagData {
                    selected_parent: genesis_hash,
                    mergeset_blues: vec![],
                    mergeset_reds: vec![],
                    blues_anticone_sizes: vec![],
                    blue_score: 1,
                    blue_work: 1u128,
                },
            );
            guard
                .dag_store
                .insert_block(tip_hash, tip_header.clone(), vec![])
                .expect("insert tip block");
            guard.dag_store.set_ghostdag(
                tip_hash,
                misaka_dag::GhostDagData {
                    selected_parent: mid_hash,
                    mergeset_blues: vec![],
                    mergeset_reds: vec![],
                    blues_anticone_sizes: vec![],
                    blue_score: 2,
                    blue_work: 2u128,
                },
            );
        }

        (state, genesis_hash, mid_hash, tip_hash, remote_child_hash)
    }

    #[test]
    fn test_peer_inventory_add_and_evict() {
        let mut inv = PeerInventory::new();
        for i in 0..MAX_INVENTORY_PER_PEER + 10 {
            let mut h = [0u8; 32];
            h[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            inv.add(h);
        }
        // Should not exceed capacity
        assert!(inv.known.len() <= MAX_INVENTORY_PER_PEER);
    }

    #[test]
    fn test_peer_inventory_contains() {
        let mut inv = PeerInventory::new();
        let h = [0xAA; 32];
        assert!(!inv.contains(&h));
        inv.add(h);
        assert!(inv.contains(&h));
    }

    #[tokio::test]
    async fn test_event_loop_serves_get_dag_tips() {
        let state = Arc::new(RwLock::new(make_test_dag_state()));
        let genesis_hash = state.read().await.genesis_hash;
        let (event_loop, inbound_tx, mut outbound_rx, _observation) =
            DagP2pEventLoop::new(state, 31337);
        let handle = tokio::spawn(event_loop.run());

        inbound_tx
            .send(InboundDagEvent {
                peer_id: peer_id(0x11),
                message: DagP2pMessage::GetDagTips,
            })
            .await
            .unwrap();

        let outbound = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .expect("timed out waiting for DAG tips")
            .expect("outbound channel closed");

        match outbound.message {
            DagP2pMessage::DagTips {
                tips,
                max_blue_score,
            } => {
                assert_eq!(max_blue_score, 0);
                assert!(tips.contains(&genesis_hash));
            }
            other => panic!("unexpected outbound DAG message: {:?}", other),
        }

        drop(inbound_tx);
        handle.abort();
    }

    #[tokio::test]
    async fn test_event_loop_serves_get_block_locator() {
        let state = Arc::new(RwLock::new(make_test_dag_state()));
        let genesis_hash = state.read().await.genesis_hash;
        let (event_loop, inbound_tx, mut outbound_rx, _observation) =
            DagP2pEventLoop::new(state, 31337);
        let handle = tokio::spawn(event_loop.run());

        inbound_tx
            .send(InboundDagEvent {
                peer_id: peer_id(0x22),
                message: DagP2pMessage::GetBlockLocator,
            })
            .await
            .unwrap();

        let outbound = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .expect("timed out waiting for block locator")
            .expect("outbound channel closed");

        match outbound.message {
            DagP2pMessage::BlockLocator {
                hashes,
                tip_blue_score,
                pruning_point,
            } => {
                assert_eq!(tip_blue_score, 0);
                assert_eq!(pruning_point, genesis_hash);
                assert!(!hashes.is_empty());
                assert_eq!(hashes[0], genesis_hash);
            }
            other => panic!("unexpected outbound DAG message: {:?}", other),
        }

        drop(inbound_tx);
        handle.abort();
    }

    #[tokio::test]
    async fn test_restart_sync_locator_prefers_known_non_tip_ancestor() {
        let (state, genesis_hash, mid_hash, _tip_hash, remote_child_hash) =
            make_restart_sync_test_state().await;
        let (event_loop, inbound_tx, mut outbound_rx, _observation) =
            DagP2pEventLoop::new(state, 31337);
        let handle = tokio::spawn(event_loop.run());
        let peer_id = peer_id(0x23);

        inbound_tx
            .send(InboundDagEvent {
                peer_id,
                message: DagP2pMessage::DagHello {
                    chain_id: 31337,
                    dag_version: DAG_VERSION,
                    blue_score: 3,
                    tips: vec![remote_child_hash],
                    pruning_point: genesis_hash,
                    node_name: "peer".to_string(),
                    mode: "validator".to_string(),
                    listen_addr: None,
                },
            })
            .await
            .unwrap();

        let outbound = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .expect("timed out waiting for locator request")
            .expect("outbound channel closed");
        assert!(matches!(outbound.message, DagP2pMessage::GetBlockLocator));

        inbound_tx
            .send(InboundDagEvent {
                peer_id,
                message: DagP2pMessage::BlockLocator {
                    hashes: vec![remote_child_hash, mid_hash, genesis_hash],
                    tip_blue_score: 3,
                    pruning_point: genesis_hash,
                },
            })
            .await
            .unwrap();

        let outbound = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .expect("timed out waiting for shared-past request")
            .expect("outbound channel closed");
        match outbound.message {
            DagP2pMessage::GetHeaders { after_hash, .. } => {
                assert_eq!(after_hash, mid_hash);
            }
            other => panic!("unexpected outbound DAG message: {:?}", other),
        }

        drop(inbound_tx);
        handle.abort();
    }

    #[tokio::test]
    async fn test_event_loop_requests_unknown_inventory_blocks() {
        let state = Arc::new(RwLock::new(make_test_dag_state()));
        let unknown_hash = [0x44; 32];
        let (event_loop, inbound_tx, mut outbound_rx, _observation) =
            DagP2pEventLoop::new(state, 31337);
        let handle = tokio::spawn(event_loop.run());

        inbound_tx
            .send(InboundDagEvent {
                peer_id: peer_id(0x33),
                message: DagP2pMessage::DagInventory {
                    from_blue_score: 0,
                    to_blue_score: 1,
                    block_hashes: vec![unknown_hash],
                },
            })
            .await
            .unwrap();

        let outbound = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .expect("timed out waiting for inventory response")
            .expect("outbound channel closed");

        match outbound.message {
            DagP2pMessage::GetDagBlocks { hashes } => {
                assert_eq!(hashes, vec![unknown_hash]);
            }
            other => panic!("unexpected outbound DAG message: {:?}", other),
        }

        drop(inbound_tx);
        handle.abort();
    }

    #[tokio::test]
    async fn test_restart_sync_does_not_fetch_known_parent_for_relay_block() {
        let (state, genesis_hash, mid_hash, _tip_hash, remote_child_hash) =
            make_restart_sync_test_state().await;
        let (event_loop, inbound_tx, mut outbound_rx, _observation) =
            DagP2pEventLoop::new(state, 31337);
        let handle = tokio::spawn(event_loop.run());
        let peer_id = peer_id(0x34);

        inbound_tx
            .send(InboundDagEvent {
                peer_id,
                message: DagP2pMessage::DagHello {
                    chain_id: 31337,
                    dag_version: DAG_VERSION,
                    blue_score: 3,
                    tips: vec![remote_child_hash],
                    pruning_point: genesis_hash,
                    node_name: "peer".to_string(),
                    mode: "validator".to_string(),
                    listen_addr: None,
                },
            })
            .await
            .unwrap();

        let outbound = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .expect("timed out waiting for locator request")
            .expect("outbound channel closed");
        assert!(matches!(outbound.message, DagP2pMessage::GetBlockLocator));

        inbound_tx
            .send(InboundDagEvent {
                peer_id,
                message: DagP2pMessage::NewDagBlock {
                    hash: remote_child_hash,
                    parents: vec![mid_hash],
                    blue_score: 3,
                    timestamp_ms: 1_700_000_000_003,
                    tx_count: 0,
                    proposer_id: [0xCF; 32],
                },
            })
            .await
            .unwrap();

        let outbound = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .expect("timed out waiting for block request")
            .expect("outbound channel closed");
        match outbound.message {
            DagP2pMessage::GetDagBlocks { hashes } => {
                assert_eq!(hashes, vec![remote_child_hash]);
            }
            other => panic!("unexpected outbound DAG message: {:?}", other),
        }

        while let Ok(Some(extra)) = timeout(Duration::from_millis(200), outbound_rx.recv()).await {
            if let DagP2pMessage::GetDagBlocks { hashes } = extra.message {
                panic!(
                    "known parent should not trigger an extra block fetch after restart: {:?}",
                    hashes
                );
            }
        }

        drop(inbound_tx);
        handle.abort();
    }

    #[tokio::test]
    async fn test_event_loop_serves_get_dag_blocks_for_known_hash() {
        let state = Arc::new(RwLock::new(make_test_dag_state()));
        let genesis_hash = state.read().await.genesis_hash;
        let (event_loop, inbound_tx, mut outbound_rx, _observation) =
            DagP2pEventLoop::new(state, 31337);
        let handle = tokio::spawn(event_loop.run());

        inbound_tx
            .send(InboundDagEvent {
                peer_id: peer_id(0x55),
                message: DagP2pMessage::GetDagBlocks {
                    hashes: vec![genesis_hash],
                },
            })
            .await
            .unwrap();

        let outbound = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .expect("timed out waiting for block data")
            .expect("outbound channel closed");

        match outbound.message {
            DagP2pMessage::DagBlockData {
                hash,
                header_json,
                txs_json,
            } => {
                assert_eq!(hash, genesis_hash);
                assert!(!header_json.is_empty());
                assert!(txs_json.is_empty());
            }
            other => panic!("unexpected outbound DAG message: {:?}", other),
        }

        drop(inbound_tx);
        handle.abort();
    }

    #[tokio::test]
    async fn test_event_loop_serves_get_pruning_proof() {
        let state = Arc::new(RwLock::new(make_test_dag_state_with_checkpoint().await));
        let genesis_hash = state.read().await.genesis_hash;
        let (event_loop, inbound_tx, mut outbound_rx, _observation) =
            DagP2pEventLoop::new(state, 31337);
        let handle = tokio::spawn(event_loop.run());

        inbound_tx
            .send(InboundDagEvent {
                peer_id: peer_id(0x66),
                message: DagP2pMessage::GetPruningProof,
            })
            .await
            .unwrap();

        let outbound = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .expect("timed out waiting for pruning proof")
            .expect("outbound channel closed");

        match outbound.message {
            DagP2pMessage::PruningProofData { proof_json } => {
                assert!(!proof_json.is_empty());
                let proof: PruningProof = serde_json::from_slice(&proof_json).unwrap();
                assert_eq!(proof.pruning_point_hash, genesis_hash);
                assert_eq!(proof.verify(), ProofVerifyResult::Valid);
            }
            other => panic!("unexpected outbound DAG message: {:?}", other),
        }

        drop(inbound_tx);
        handle.abort();
    }

    #[tokio::test]
    async fn test_event_loop_does_not_request_known_inventory_blocks() {
        let state = Arc::new(RwLock::new(make_test_dag_state()));
        let genesis_hash = state.read().await.genesis_hash;
        let (event_loop, inbound_tx, mut outbound_rx, _observation) =
            DagP2pEventLoop::new(state, 31337);
        let handle = tokio::spawn(event_loop.run());

        inbound_tx
            .send(InboundDagEvent {
                peer_id: peer_id(0x77),
                message: DagP2pMessage::DagInventory {
                    from_blue_score: 0,
                    to_blue_score: 0,
                    block_hashes: vec![genesis_hash],
                },
            })
            .await
            .unwrap();

        assert!(
            timeout(Duration::from_millis(150), outbound_rx.recv())
                .await
                .is_err(),
            "known inventory should not trigger a block request"
        );

        drop(inbound_tx);
        handle.abort();
    }

    #[tokio::test]
    async fn test_event_loop_does_not_serve_unknown_dag_block_hash() {
        let state = Arc::new(RwLock::new(make_test_dag_state()));
        let unknown_hash = [0x88; 32];
        let (event_loop, inbound_tx, mut outbound_rx, _observation) =
            DagP2pEventLoop::new(state, 31337);
        let handle = tokio::spawn(event_loop.run());

        inbound_tx
            .send(InboundDagEvent {
                peer_id: peer_id(0x88),
                message: DagP2pMessage::GetDagBlocks {
                    hashes: vec![unknown_hash],
                },
            })
            .await
            .unwrap();

        assert!(
            timeout(Duration::from_millis(150), outbound_rx.recv())
                .await
                .is_err(),
            "unknown hashes should not produce DagBlockData"
        );

        drop(inbound_tx);
        handle.abort();
    }

    #[tokio::test]
    async fn test_event_loop_does_not_serve_pruning_proof_without_checkpoint() {
        let state = Arc::new(RwLock::new(make_test_dag_state()));
        let (event_loop, inbound_tx, mut outbound_rx, _observation) =
            DagP2pEventLoop::new(state, 31337);
        let handle = tokio::spawn(event_loop.run());

        inbound_tx
            .send(InboundDagEvent {
                peer_id: peer_id(0x99),
                message: DagP2pMessage::GetPruningProof,
            })
            .await
            .unwrap();

        assert!(
            timeout(Duration::from_millis(150), outbound_rx.recv())
                .await
                .is_err(),
            "nodes without a checkpoint should not fabricate pruning proofs"
        );

        drop(inbound_tx);
        handle.abort();
    }

    #[tokio::test]
    async fn test_handle_tick_periodically_requests_block_locator_from_known_peers() {
        let state = Arc::new(RwLock::new(make_test_dag_state()));
        let (mut event_loop, _inbound_tx, mut outbound_rx, _observation) =
            DagP2pEventLoop::new(state, 31337);
        event_loop.sync_poll_ticks = PERIODIC_SYNC_POLL_TICKS - 1;

        event_loop.handle_tick().await;

        let outbound = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .expect("timed out waiting for periodic sync request")
            .expect("outbound channel closed");

        assert_eq!(outbound.peer_id, None);
        assert!(matches!(outbound.message, DagP2pMessage::GetBlockLocator));
    }

    #[tokio::test]
    async fn test_handle_tick_announces_new_local_tip_once() {
        let state = Arc::new(RwLock::new(make_test_dag_state()));
        let (mut event_loop, _inbound_tx, mut outbound_rx, _observation) =
            DagP2pEventLoop::new(state.clone(), 31337);

        let genesis_hash = state.read().await.genesis_hash;
        let new_header = DagBlockHeader {
            version: DAG_VERSION,
            parents: vec![genesis_hash],
            timestamp_ms: 1_700_000_000_001,
            tx_root: ZERO_HASH,
            proposer_id: [0xCC; 32],
            nonce: 7,
            blue_score: 1,
            bits: 0,
        };
        let new_hash = new_header.compute_hash();
        {
            let guard = state.write().await;
            guard
                .dag_store
                .insert_block(new_hash, new_header.clone(), vec![])
                .expect("insert test tip");
            guard.dag_store.set_ghostdag(
                new_hash,
                misaka_dag::GhostDagData {
                    selected_parent: genesis_hash,
                    mergeset_blues: vec![],
                    mergeset_reds: vec![],
                    blues_anticone_sizes: vec![],
                    blue_score: 1,
                    blue_work: 1u128,
                },
            );
        }

        event_loop.handle_tick().await;

        let outbound = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .expect("timed out waiting for new tip announcement")
            .expect("outbound channel closed");
        assert_eq!(outbound.peer_id, None);
        match outbound.message {
            DagP2pMessage::NewDagBlock {
                hash, blue_score, ..
            } => {
                assert_eq!(hash, new_hash);
                assert_eq!(blue_score, 1);
            }
            other => panic!("unexpected outbound DAG message: {:?}", other),
        }

        event_loop.handle_tick().await;
        assert!(
            timeout(Duration::from_millis(200), outbound_rx.recv())
                .await
                .is_err(),
            "same tip should not be re-announced immediately"
        );
    }

    #[tokio::test]
    async fn test_handle_full_block_bypasses_tx_gate_for_header_only_payload() {
        let state = Arc::new(RwLock::new(make_test_dag_state()));
        let peer_id = peer_id(0xAA);
        let (mut event_loop, _inbound_tx, _outbound_rx, _observation) =
            DagP2pEventLoop::new(state.clone(), 31337);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        for _ in 0..32 {
            let _ = event_loop.tx_admission_gate.check(&peer_id.0, now_ms);
        }

        let genesis_hash = state.read().await.genesis_hash;
        let header = DagBlockHeader {
            version: DAG_VERSION,
            parents: vec![genesis_hash],
            timestamp_ms: 1_700_000_000_001,
            tx_root: ZERO_HASH,
            proposer_id: [0xAB; 32],
            nonce: 99,
            blue_score: 1,
            bits: 0,
        };
        let hash = header.compute_hash();

        event_loop
            .handle_full_block(
                peer_id,
                hash,
                serde_json::to_vec(&header).expect("serialize header"),
                Vec::new(),
            )
            .await;

        let guard = state.read().await;
        let snapshot = guard.dag_store.snapshot();
        assert!(snapshot.get_header(&hash).is_some());
        assert_eq!(event_loop.tx_admission_gate.pending_count(), 30);
    }
}
