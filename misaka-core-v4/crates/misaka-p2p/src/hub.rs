//! # P2P Hub — Central Peer Management
//!
//! Kaspa-aligned peer hub that:
//! 1. Maintains a map of active peers (by PeerKey)
//! 2. Runs an event loop processing NewPeer / PeerClosing events
//! 3. Provides broadcast, targeted send, and peer selection APIs
//!
//! All peer identity verification uses ML-DSA-65 signatures; no ECC.

use std::collections::hash_map::Entry::Occupied;
use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use rand::prelude::IteratorRandom;
use tracing::{debug, info, warn};

use tokio::sync::mpsc::Receiver as MpscReceiver;

use crate::payload_type::MisakaMessage;
use crate::protocol_error::ProtocolError;
use crate::router::{HubEvent, Peer, PeerKey, Router};

/// Trait for initializing new inbound connections.
///
/// Implementors perform the PQ handshake, version negotiation,
/// and flow registration before the router starts.
#[async_trait::async_trait]
pub trait ConnectionInitializer: Send + Sync + 'static {
    async fn initialize_connection(&self, router: Arc<Router>) -> Result<(), ProtocolError>;
}

/// Central hub of active peers.
///
/// All public methods are thread-safe. The internal peer map uses
/// `parking_lot::RwLock` for low-overhead concurrent reads.
#[derive(Debug, Clone)]
pub struct Hub {
    peers: Arc<RwLock<HashMap<PeerKey, Arc<Router>>>>,
}

impl Default for Hub {
    fn default() -> Self {
        Self::new()
    }
}

impl Hub {
    pub fn new() -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start the hub event loop that processes NewPeer / PeerClosing events.
    ///
    /// This must be called once during node startup. The `initializer`
    /// handles PQ handshake + flow setup for inbound connections.
    pub fn start_event_loop(
        self,
        mut hub_rx: MpscReceiver<HubEvent>,
        initializer: Arc<dyn ConnectionInitializer>,
    ) {
        tokio::spawn(async move {
            while let Some(event) = hub_rx.recv().await {
                match event {
                    HubEvent::NewPeer(router) => {
                        if router.is_outbound() {
                            // Outbound: handshake already done during connect().
                            let count = self.outbound_count() + 1;
                            info!(
                                "P2P connected to outgoing peer {} (outbound: {})",
                                router, count
                            );
                            self.insert_router(router).await;
                        } else {
                            // Inbound: run PQ handshake + flow init.
                            match initializer.initialize_connection(router.clone()).await {
                                Ok(()) => {
                                    let count = self.inbound_count() + 1;
                                    info!(
                                        "P2P connected to incoming peer {} (inbound: {})",
                                        router, count
                                    );
                                    self.insert_router(router).await;
                                }
                                Err(err) => {
                                    router.try_sending_reject(&err).await;
                                    router.close().await;

                                    match &err {
                                        ProtocolError::LoopbackConnection(_)
                                        | ProtocolError::PeerAlreadyExists(_) => {
                                            debug!(
                                                "P2P handshake failed for inbound {}: {}",
                                                router, err
                                            );
                                        }
                                        ProtocolError::VersionMismatch { theirs, .. }
                                            if *theirs <= 2 =>
                                        {
                                            debug!(
                                                "P2P handshake failed (legacy peer) {}: {}",
                                                router, err
                                            );
                                        }
                                        _ => {
                                            warn!(
                                                "P2P handshake failed for inbound {}: {}",
                                                router, err
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    HubEvent::PeerClosing(router) => {
                        if let Occupied(entry) = self.peers.write().entry(router.key()) {
                            // Only remove if it's the exact same Arc (prevents race on reconnect).
                            if Arc::ptr_eq(entry.get(), &router) {
                                entry.remove_entry();
                                debug!("P2P Hub removed peer, id={}", router.identity());
                            }
                        }
                    }
                }
            }
            debug!("P2P Hub event loop exiting");
        });
    }

    async fn insert_router(&self, router: Arc<Router>) {
        let prev = self.peers.write().insert(router.key(), router.clone());
        if let Some(old) = prev {
            // Rare race: close the stale router.
            old.close().await;
            warn!("P2P Hub replaced duplicate peer: {}", old.key());
        }
    }

    // ════════════════════════════════════════════════════
    //  Send / Broadcast
    // ════════════════════════════════════════════════════

    /// Send a message to a specific peer. Returns `false` if peer not found.
    pub async fn send(&self, peer_key: PeerKey, msg: MisakaMessage) -> Result<bool, ProtocolError> {
        let router = self.peers.read().get(&peer_key).cloned();
        if let Some(r) = router {
            r.enqueue(msg).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Broadcast a message to all peers (optionally excluding one).
    pub async fn broadcast(&self, msg: MisakaMessage, exclude: Option<PeerKey>) {
        let peers: Vec<Arc<Router>> = self
            .peers
            .read()
            .values()
            .filter(|r| exclude.map_or(true, |ex| r.key() != ex))
            .cloned()
            .collect();

        for router in peers {
            let _ = router.enqueue(msg.clone()).await;
        }
    }

    /// Broadcast to a random subset of peers, balancing outbound/inbound.
    ///
    /// Tries to select at least half from outbound peers for better
    /// network topology resistance.
    pub async fn broadcast_to_some(&self, msg: MisakaMessage, num_peers: usize) {
        if num_peers == 0 {
            return;
        }

        let selected = self.select_some_peers(num_peers);
        for router in selected {
            let _ = router.enqueue(msg.clone()).await;
        }
    }

    /// Broadcast multiple messages to all peers.
    pub async fn broadcast_many(&self, msgs: Vec<MisakaMessage>, exclude: Option<PeerKey>) {
        if msgs.is_empty() {
            return;
        }

        let peers: Vec<Arc<Router>> = self
            .peers
            .read()
            .values()
            .filter(|r| exclude.map_or(true, |ex| r.key() != ex))
            .cloned()
            .collect();

        for router in peers {
            for msg in msgs.iter().cloned() {
                let _ = router.enqueue(msg).await;
            }
        }
    }

    /// Select a random subset of peers with outbound/inbound balance.
    fn select_some_peers(&self, num: usize) -> Vec<Arc<Router>> {
        let peers = self.peers.read();
        let total_outbound = peers.values().filter(|r| r.is_outbound()).count();
        let total_inbound = peers.len().saturating_sub(total_outbound);

        let mut out_count = num.div_ceil(2).min(total_outbound);
        if total_inbound + out_count < num {
            out_count = num.saturating_sub(total_inbound).min(total_outbound);
        }
        let in_count = num.saturating_sub(out_count).min(total_inbound);

        let mut rng = rand::thread_rng();

        let outbound: Vec<_> = peers
            .values()
            .filter(|r| r.is_outbound())
            .cloned()
            .choose_multiple(&mut rng, out_count);

        let inbound: Vec<_> = peers
            .values()
            .filter(|r| !r.is_outbound())
            .cloned()
            .choose_multiple(&mut rng, in_count);

        outbound.into_iter().chain(inbound).collect()
    }

    // ════════════════════════════════════════════════════
    //  Peer Management
    // ════════════════════════════════════════════════════

    /// Terminate a specific peer connection.
    pub async fn terminate(&self, key: PeerKey) {
        let router = self.peers.read().get(&key).cloned();
        if let Some(r) = router {
            r.close().await;
        }
    }

    /// Terminate all peer connections.
    pub async fn terminate_all(&self) {
        let all: Vec<Arc<Router>> = self.peers.write().drain().map(|(_, r)| r).collect();
        for r in all {
            r.close().await;
        }
    }

    /// List all active peers.
    pub fn active_peers(&self) -> Vec<Peer> {
        self.peers
            .read()
            .values()
            .map(|r| r.as_ref().into())
            .collect()
    }

    pub fn active_peers_len(&self) -> usize {
        self.peers.read().len()
    }

    pub fn outbound_count(&self) -> usize {
        self.peers
            .read()
            .values()
            .filter(|r| r.is_outbound())
            .count()
    }

    pub fn inbound_count(&self) -> usize {
        let peers = self.peers.read();
        peers
            .len()
            .saturating_sub(peers.values().filter(|r| r.is_outbound()).count())
    }

    pub fn has_peers(&self) -> bool {
        !self.peers.read().is_empty()
    }

    pub fn has_peer(&self, key: &PeerKey) -> bool {
        self.peers.read().contains_key(key)
    }

    /// Get a specific router by key (for targeted operations).
    pub fn get_router(&self, key: &PeerKey) -> Option<Arc<Router>> {
        self.peers.read().get(key).cloned()
    }
}
