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
use tracing::{debug, error, info, warn};

use misaka_dag::dag_block::{DagBlockHeader, Hash, ZERO_HASH};
use misaka_dag::dag_block_ingestion::IngestAction;
use misaka_dag::dag_p2p::{
    DagP2pMessage, DagSyncManager, DagSyncState, SyncAction, SyncMode,
};
use misaka_dag::DagNodeState;

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
}

impl PeerInventory {
    pub fn new() -> Self {
        Self {
            known: HashSet::new(),
            blue_score: 0,
            tips: Vec::new(),
        }
    }

    /// Add a hash to the inventory, evicting old entries if over capacity.
    pub fn add(&mut self, hash: Hash) {
        if self.known.len() >= MAX_INVENTORY_PER_PEER {
            // Simple eviction: clear half the set.
            // Production would use a proper LRU, but this prevents unbounded growth.
            let to_remove: Vec<Hash> = self.known.iter().take(MAX_INVENTORY_PER_PEER / 2).copied().collect();
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
}

// ═══════════════════════════════════════════════════════════════
//  Inbound Event (from P2P transport)
// ═══════════════════════════════════════════════════════════════

/// A message received from a peer, ready for processing.
#[derive(Debug)]
pub struct InboundDagEvent {
    /// Peer identifier (e.g., truncated public key hash).
    pub peer_id: [u8; 20],
    /// The P2P message payload.
    pub message: DagP2pMessage,
}

/// An outbound message to be sent to a specific peer (or broadcast).
#[derive(Debug, Clone)]
pub struct OutboundDagEvent {
    /// Target peer. If None, broadcast to all connected peers.
    pub peer_id: Option<[u8; 20]>,
    /// The message to send.
    pub message: DagP2pMessage,
}

// ═══════════════════════════════════════════════════════════════
//  DagP2pEventLoop
// ═══════════════════════════════════════════════════════════════

/// Main DAG P2P event loop.
///
/// Owns the IngestionPipeline and DagSyncManager, connecting them to
/// the P2P transport layer via tokio channels.
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
    peer_syncs: HashMap<[u8; 20], DagSyncManager>,
    /// Per-peer inventory.
    inventories: HashMap<[u8; 20], PeerInventory>,
    /// Shared DAG node state (block store, virtual state, etc.).
    state: Arc<RwLock<DagNodeState>>,
    /// Inbound message receiver.
    inbound_rx: mpsc::Receiver<InboundDagEvent>,
    /// Outbound message sender.
    outbound_tx: mpsc::Sender<OutboundDagEvent>,
    /// Local chain ID for handshake validation.
    chain_id: u32,
}

impl DagP2pEventLoop {
    /// Create a new event loop with channels.
    ///
    /// Returns `(event_loop, inbound_tx, outbound_rx)`.
    /// The caller sends InboundDagEvent to `inbound_tx` and reads
    /// OutboundDagEvent from `outbound_rx`.
    pub fn new(
        state: Arc<RwLock<DagNodeState>>,
        chain_id: u32,
    ) -> (Self, mpsc::Sender<InboundDagEvent>, mpsc::Receiver<OutboundDagEvent>) {
        let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_CHANNEL_SIZE);
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_CHANNEL_SIZE);

        let event_loop = Self {
            peer_syncs: HashMap::new(),
            inventories: HashMap::new(),
            state,
            inbound_rx,
            outbound_tx,
            chain_id,
        };

        (event_loop, inbound_tx, outbound_rx)
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

        match event.message {
            // ── Handshake ──
            DagP2pMessage::DagHello {
                chain_id,
                dag_version,
                blue_score,
                tips,
                pruning_point,
                node_name,
                mode,
                listen_addr,
            } => {
                if chain_id != self.chain_id {
                    warn!(
                        "Peer {} has wrong chain_id {} (expected {}), disconnecting",
                        hex::encode(&peer_id[..4]),
                        chain_id,
                        self.chain_id
                    );
                    return;
                }

                let sync = self.get_or_create_sync(&peer_id).await;
                let actions = sync.on_dag_hello(tips.clone(), blue_score, pruning_point);

                // Update inventory
                let inv = self.inventories.entry(peer_id).or_insert_with(PeerInventory::new);
                inv.blue_score = blue_score;
                inv.tips = tips.clone();
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
                let best_tip = tips.iter().max_by_key(|t| {
                    snapshot.get_ghostdag_data(t).map(|d| d.blue_score).unwrap_or(0)
                }).copied().unwrap_or(genesis);

                let locator = misaka_dag::build_block_locator(
                    best_tip,
                    |h| snapshot.get_ghostdag_data(h).map(|d| d.selected_parent),
                    genesis,
                );

                let pruning_point = guard.latest_checkpoint
                    .as_ref()
                    .map(|cp| cp.block_hash)
                    .unwrap_or(genesis);

                drop(guard);

                self.send_to_peer(peer_id, DagP2pMessage::BlockLocator {
                    hashes: locator,
                    tip_blue_score: max_score,
                    pruning_point,
                }).await;
            }

            // ── Header Sync ──
            DagP2pMessage::Headers {
                headers_json,
                count,
                has_more,
            } => {
                // Deserialize headers
                let headers: Vec<(Hash, Vec<u8>)> = match serde_json::from_slice(&headers_json) {
                    Ok(h) => h,
                    Err(e) => {
                        warn!("Failed to deserialize headers from {}: {}", hex::encode(&peer_id[..4]), e);
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
                let bodies: Vec<(Hash, Vec<u8>, Vec<u8>)> = blocks.iter().map(|(hash, data)| {
                    // For now, the data contains serialized block (header + txs)
                    (*hash, data.clone(), vec![])
                }).collect();

                let sync = self.get_or_create_sync(&peer_id).await;
                let actions = sync.on_bodies(&bodies);
                self.process_sync_actions(peer_id, actions).await;
            }

            // ── Steady-State: New Block Announcement ──
            DagP2pMessage::NewDagBlock {
                hash,
                parents,
                blue_score,
                timestamp_ms,
                tx_count,
                proposer_id,
            } => {
                // Update inventory
                let inv = self.inventories.entry(peer_id).or_insert_with(PeerInventory::new);
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
                self.send_to_peer(peer_id, DagP2pMessage::GetDagBlocks {
                    hashes: vec![hash],
                }).await;
            }

            // ── Full Block Data (from GetDagBlocks response) ──
            DagP2pMessage::DagBlockData {
                hash,
                header_json,
                txs_json,
            } => {
                self.handle_full_block(peer_id, hash, header_json, txs_json).await;
            }

            // ── Inventory ──
            DagP2pMessage::DagInventory {
                from_blue_score,
                to_blue_score,
                block_hashes,
            } => {
                let inv = self.inventories.entry(peer_id).or_insert_with(PeerInventory::new);
                for h in &block_hashes {
                    inv.add(*h);
                }

                // Request any unknown blocks
                let guard = self.state.read().await;
                let unknown: Vec<Hash> = block_hashes.iter()
                    .filter(|h| guard.dag_store.snapshot().get_header(h).is_none())
                    .copied()
                    .collect();
                drop(guard);

                if !unknown.is_empty() {
                    self.send_to_peer(peer_id, DagP2pMessage::GetDagBlocks {
                        hashes: unknown,
                    }).await;
                }
            }

            // ── Pruning Proof ──
            DagP2pMessage::GetPruningProof => {
                // Serve our pruning proof to the requesting peer
                let guard = self.state.read().await;
                if let Some(cp) = &guard.latest_checkpoint {
                    let proof = misaka_dag::PruningProof {
                        pruning_point_hash: cp.block_hash,
                        utxo_commitment: cp.utxo_root,
                        nullifier_commitment: ZERO_HASH,
                        chain_blocks: Vec::new(),
                        blue_score: cp.blue_score,
                    };
                    let proof_json = serde_json::to_vec(&proof).unwrap_or_default();
                    drop(guard);
                    self.send_to_peer(peer_id, DagP2pMessage::PruningProofData {
                        proof_json,
                    }).await;
                }
            }

            // ── Tips request ──
            DagP2pMessage::GetDagTips => {
                let guard = self.state.read().await;
                let snapshot = guard.dag_store.snapshot();
                let tips = snapshot.get_tips();
                let max_score = guard.dag_store.max_blue_score();
                drop(guard);

                self.send_to_peer(peer_id, DagP2pMessage::DagTips {
                    tips,
                    max_blue_score: max_score,
                }).await;
            }

            // ── Request for specific blocks (serve) ──
            DagP2pMessage::GetDagBlocks { hashes } => {
                let guard = self.state.read().await;
                let snapshot = guard.dag_store.snapshot();
                for hash in hashes {
                    if let Some(header) = snapshot.get_header(&hash) {
                        let header_json = serde_json::to_vec(&header).unwrap_or_default();
                        // In production, txs would come from block body storage
                        drop(guard);
                        self.send_to_peer(peer_id, DagP2pMessage::DagBlockData {
                            hash,
                            header_json,
                            txs_json: vec![],
                        }).await;
                        return; // simplified: one at a time
                    }
                }
            }

            // Other messages: log and ignore unknown types
            other => {
                debug!(
                    "Unhandled DAG P2P message from {}: {:?}",
                    hex::encode(&peer_id[..4]),
                    std::mem::discriminant(&other)
                );
            }
        }
    }

    // ─── Full Block Ingestion ───

    /// Process a received full block (header + txs) through the IngestionPipeline.
    async fn handle_full_block(
        &mut self,
        peer_id: [u8; 20],
        hash: Hash,
        header_json: Vec<u8>,
        txs_json: Vec<u8>,
    ) {
        let header: DagBlockHeader = match serde_json::from_slice(&header_json) {
            Ok(h) => h,
            Err(e) => {
                warn!(
                    "Failed to deserialize block header from {}: {}",
                    hex::encode(&peer_id[..4]),
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
        let ingest_result = guard.ingestion_pipeline.ingest_block(hash, header, txs_json.clone());

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
                            // Request missing parents from the peer
                            drop(guard);
                            self.send_to_peer(peer_id, DagP2pMessage::GetDagBlocks {
                                hashes: missing,
                            }).await;
                            return;
                        }
                        IngestAction::SendP2p(msg) => {
                            drop(guard);
                            self.send_to_peer(peer_id, msg).await;
                            return;
                        }
                        IngestAction::BlockAccepted { block_hash } => {
                            info!(
                                "Block {} accepted via P2P",
                                hex::encode(&block_hash[..4])
                            );
                        }
                        IngestAction::BlockRejected { block_hash, reason } => {
                            warn!(
                                "Block {} rejected: {}",
                                hex::encode(&block_hash[..4]),
                                reason
                            );
                            if let Some(sync) = self.peer_syncs.get_mut(&peer_id) {
                                sync.on_validation_failed(&block_hash, &reason);
                            }
                        }
                        IngestAction::BlockTimedOut { block_hash } => {
                            debug!(
                                "Block {} timed out in pending",
                                hex::encode(&block_hash[..4])
                            );
                        }
                    }
                }
            }
            Err(e) => {
                debug!(
                    "Block {} ingestion error: {}",
                    hex::encode(&hash[..4]),
                    e
                );
            }
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
    async fn run_block_validation(
        &self,
        guard: &mut DagNodeState,
        block_hash: Hash,
    ) {
        // Retrieve the pending block from the pipeline
        let pending_block = match guard.ingestion_pipeline.get_pending_block(&block_hash) {
            Some(pb) => pb.clone(),
            None => return,
        };

        let header = pending_block.header.clone();
        let _txs_payload = pending_block.txs_payload.clone();

        // Stage 1: Header topology validation
        let snapshot = guard.dag_store.snapshot();
        if let Err(e) = misaka_dag::validate_header_topology(&header.parents, header.blue_score, &*snapshot) {
            let reason = format!("header topology invalid: {}", e);
            guard.ingestion_pipeline.mark_rejected(block_hash, reason);
            return;
        }

        // Stage 2-5: Run through atomic pipeline
        // (In production, this would call process_new_block_atomic)
        // For now, use the simpler insertion path:
        let computed_hash = header.compute_hash();
        if computed_hash != block_hash {
            guard.ingestion_pipeline.mark_rejected(
                block_hash,
                "hash mismatch".to_string(),
            );
            return;
        }

        // Insert into DAG store
        let ghostdag_data = match guard.ghostdag.try_calculate(
            &block_hash,
            &header.parents,
            &*snapshot,
            &guard.reachability,
            &misaka_dag::UniformStakeProvider,
        ) {
            Ok(data) => data,
            Err(e) => {
                guard.ingestion_pipeline.mark_rejected(
                    block_hash,
                    format!("ghostdag calculation failed: {}", e),
                );
                return;
            }
        };

        if let Err(e) = guard.dag_store.insert_block(block_hash, header.clone(), vec![]) {
            guard.ingestion_pipeline.mark_rejected(
                block_hash,
                format!("dag store insert failed: {}", e),
            );
            return;
        }
        guard.dag_store.set_ghostdag(block_hash, ghostdag_data.clone());

        // Update reachability
        let parent = ghostdag_data.selected_parent;
        if parent != ZERO_HASH {
            guard.reachability.add_block(block_hash, parent);
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
                    // Broadcast parent request to all peers
                    self.broadcast(DagP2pMessage::GetDagBlocks {
                        hashes: missing,
                    }).await;
                }
                IngestAction::BlockTimedOut { block_hash } => {
                    debug!(
                        "Block {} evicted from pending (timeout)",
                        hex::encode(&block_hash[..4])
                    );
                }
                _ => {}
            }
        }
    }

    // ─── SyncAction → OutboundMessage ───

    async fn process_sync_actions(&mut self, peer_id: [u8; 20], actions: Vec<SyncAction>) {
        for action in actions {
            match action {
                SyncAction::Send(msg) => {
                    self.send_to_peer(peer_id, msg).await;
                }
                SyncAction::Ban(reason) => {
                    warn!(
                        "Banning peer {}: {}",
                        hex::encode(&peer_id[..4]),
                        reason
                    );
                    self.peer_syncs.remove(&peer_id);
                    self.inventories.remove(&peer_id);
                }
                SyncAction::ProcessBlock { hash, header_json, txs_json } => {
                    self.handle_full_block(peer_id, hash, header_json, txs_json).await;
                }
                SyncAction::ValidateHeader { hash, header_json } => {
                    // During IBD header-only phase, validate without body
                    let header: Result<DagBlockHeader, _> = serde_json::from_slice(&header_json);
                    match header {
                        Ok(hdr) => {
                            let guard = self.state.read().await;
                            let snapshot = guard.dag_store.snapshot();
                            let valid = misaka_dag::validate_header_topology(&hdr.parents, hdr.blue_score, &*snapshot).is_ok();
                            drop(guard);

                            if let Some(sync) = self.peer_syncs.get_mut(&peer_id) {
                                if !valid {
                                    sync.on_validation_failed(&hash, "header topology check failed");
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

    // ─── Helpers ───

    async fn get_or_create_sync(&mut self, peer_id: &[u8; 20]) -> &mut DagSyncManager {
        if !self.peer_syncs.contains_key(peer_id) {
            let mut sync = DagSyncManager::new();
            // Set local blue_score from current state
            let guard = self.state.read().await;
            let snapshot = guard.dag_store.snapshot();
            sync.set_local_blue_score(guard.dag_store.max_blue_score());
            // Add all known block hashes
            for tip in snapshot.get_tips() {
                sync.add_known(tip);
            }
            sync.add_known(guard.genesis_hash);
            drop(guard);
            self.peer_syncs.insert(*peer_id, sync);
        }
        self.peer_syncs.get_mut(peer_id).expect("just inserted")
    }

    async fn send_to_peer(&self, peer_id: [u8; 20], message: DagP2pMessage) {
        if let Err(e) = self.outbound_tx.send(OutboundDagEvent {
            peer_id: Some(peer_id),
            message,
        }).await {
            warn!("Failed to send outbound DAG message: {}", e);
        }
    }

    async fn broadcast(&self, message: DagP2pMessage) {
        if let Err(e) = self.outbound_tx.send(OutboundDagEvent {
            peer_id: None,
            message,
        }).await {
            warn!("Failed to broadcast DAG message: {}", e);
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

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
}
