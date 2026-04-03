//! # Transaction Relay Flow — Mempool Gossip with Deduplication
//!
//! Kaspa-aligned transaction relay:
//! 1. Peer announces tx IDs via InvTransactions
//! 2. We request only unknown txs via RequestTransactions
//! 3. Peer sends full Transaction messages
//! 4. We validate and add to mempool, then relay inv to others
//!
//! Overflow policy for InvTransactions is Drop (safe gossip).

use std::sync::Arc;

use tracing::{debug, trace, warn};

use crate::flow_context::{FlowContext, Hash};
use crate::flow_trait::Flow;
use crate::payload_type::{MisakaMessage, MisakaPayloadType};
use crate::protocol_error::ProtocolError;
use crate::router::{IncomingRoute, Router};

/// Maximum transaction IDs per inv message.
const MAX_TX_INV: usize = 1024;

/// Maximum transaction size (bytes) — rejects oversized txs.
const MAX_TX_SIZE: usize = 1_048_576; // 1 MB

pub struct TxRelayFlow {
    pub router: Arc<Router>,
    pub ctx: Arc<FlowContext>,
    pub incoming: IncomingRoute,
}

impl TxRelayFlow {
    pub fn new(router: Arc<Router>, ctx: Arc<FlowContext>) -> Result<Self, ProtocolError> {
        let incoming = router.subscribe_with_capacity(
            vec![
                MisakaPayloadType::InvTransactions,
                MisakaPayloadType::RequestTransactions,
                MisakaPayloadType::Transaction,
                MisakaPayloadType::TransactionNotFound,
            ],
            1024,
        )?;
        Ok(Self {
            router,
            ctx,
            incoming,
        })
    }

    fn parse_tx_inv(payload: &[u8]) -> Result<Vec<Hash>, ProtocolError> {
        if payload.len() % 32 != 0 {
            return Err(ProtocolError::ProtocolViolation(
                "tx inv payload not a multiple of 32 bytes".into(),
            ));
        }
        let count = payload.len() / 32;
        if count > MAX_TX_INV {
            return Err(ProtocolError::ProtocolViolation(format!(
                "tx inv contains {} IDs (max {})",
                count, MAX_TX_INV
            )));
        }
        let mut ids = Vec::with_capacity(count);
        for chunk in payload.chunks_exact(32) {
            let mut h = [0u8; 32];
            h.copy_from_slice(chunk);
            ids.push(h);
        }
        Ok(ids)
    }
}

#[async_trait::async_trait]
impl Flow for TxRelayFlow {
    fn name(&self) -> &'static str {
        "TxRelayFlow"
    }

    async fn run(mut self: Box<Self>) -> Result<(), ProtocolError> {
        let peer_key = self.router.key();

        loop {
            let msg = match self.incoming.recv().await {
                Some(m) => m,
                None => return Err(ProtocolError::ConnectionClosed),
            };

            match msg.msg_type {
                MisakaPayloadType::InvTransactions => {
                    let tx_ids = Self::parse_tx_inv(&msg.payload)?;

                    // Record that this peer knows these txs.
                    {
                        let mut spread = self.ctx.tx_spread.lock();
                        for id in &tx_ids {
                            spread.add(*id, peer_key);
                        }
                    }

                    // MED-5 FIX: Filter out TXs we already know about.
                    // Uses tx_spread (P2P dedup layer) to avoid re-requesting TXs
                    // that we've already seen from any peer. This prevents redundant
                    // relay and saves network bandwidth.
                    let unknown: Vec<Hash> = {
                        let spread = self.ctx.tx_spread.lock();
                        tx_ids
                            .into_iter()
                            .filter(|id| !spread.is_known(id))
                            .collect()
                    };

                    if unknown.is_empty() {
                        continue;
                    }

                    let mut payload = Vec::with_capacity(unknown.len() * 32);
                    for id in &unknown {
                        payload.extend_from_slice(id);
                    }

                    let request =
                        MisakaMessage::new(MisakaPayloadType::RequestTransactions, payload);
                    self.router.enqueue(request).await?;
                }

                MisakaPayloadType::RequestTransactions => {
                    let tx_ids = Self::parse_tx_inv(&msg.payload)?;

                    trace!(
                        "P2P peer {} requesting {} transactions",
                        self.router,
                        tx_ids.len()
                    );

                    // CRIT-4 FIX: Look up TX bodies from cache and serve to peer.
                    // Collect responses while holding the lock, then send after dropping it.
                    let responses: Vec<MisakaMessage> = {
                        let cache = self.ctx.tx_body_cache.lock();
                        tx_ids.iter().map(|id| {
                            if let Some(body) = cache.get(id) {
                                MisakaMessage::new(MisakaPayloadType::Transaction, body.to_vec())
                            } else {
                                MisakaMessage::new(MisakaPayloadType::TransactionNotFound, id.to_vec())
                            }
                        }).collect()
                    }; // lock dropped here
                    for msg_out in responses {
                        self.router.enqueue(msg_out).await?;
                    }
                }

                MisakaPayloadType::Transaction => {
                    if msg.payload.len() > MAX_TX_SIZE {
                        return Err(ProtocolError::ProtocolViolation(format!(
                            "transaction too large: {} bytes (max {})",
                            msg.payload.len(),
                            MAX_TX_SIZE
                        )));
                    }

                    // Compute tx hash (SHA3-256 of the payload).
                    let tx_hash: Hash = {
                        use sha3::{Digest, Sha3_256};
                        let digest = Sha3_256::digest(&msg.payload);
                        let mut h = [0u8; 32];
                        h.copy_from_slice(&digest);
                        h
                    };

                    // Record in spread tracker and body cache.
                    {
                        let mut spread = self.ctx.tx_spread.lock();
                        spread.add(tx_hash, peer_key);
                    }
                    {
                        // CRIT-4: Cache TX body for serving to other peers
                        let mut cache = self.ctx.tx_body_cache.lock();
                        cache.insert(tx_hash, msg.payload.clone());
                    }

                    // Relay inv to other peers.
                    let all_peers: Vec<_> = self
                        .ctx
                        .hub
                        .active_peers()
                        .iter()
                        .map(|p| crate::router::PeerKey::new(p.identity, p.address.ip()))
                        .collect();

                    let relay_to = self
                        .ctx
                        .tx_spread
                        .lock()
                        .peers_not_knowing(&tx_hash, &all_peers);

                    if !relay_to.is_empty() {
                        let inv = MisakaMessage::new(
                            MisakaPayloadType::InvTransactions,
                            tx_hash.to_vec(),
                        );
                        // Broadcast to peers who don't know.
                        self.ctx.hub.broadcast(inv, Some(peer_key)).await;
                    }

                    debug!(
                        "P2P received tx {} from {}",
                        hex::encode(&tx_hash[..8]),
                        self.router
                    );
                }

                MisakaPayloadType::TransactionNotFound => {
                    // Peer doesn't have a tx we requested — that's fine.
                    trace!("P2P tx not found response from {}", self.router);
                }

                other => {
                    warn!("P2P TxRelayFlow unexpected message {:?}", other);
                }
            }
        }
    }
}
