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
    pub fn new(router: Arc<Router>, ctx: Arc<FlowContext>) -> Self {
        let incoming = router.subscribe_with_capacity(
            vec![
                MisakaPayloadType::InvTransactions,
                MisakaPayloadType::RequestTransactions,
                MisakaPayloadType::Transaction,
                MisakaPayloadType::TransactionNotFound,
            ],
            1024,
        );
        Self {
            router,
            ctx,
            incoming,
        }
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

                    // Request txs we don't have in mempool.
                    // (The actual mempool check would be done by consensus layer;
                    //  here we just track what we've seen via tx_spread.)
                    let unknown: Vec<Hash> = {
                        let spread = self.ctx.tx_spread.lock();
                        tx_ids
                            .into_iter()
                            .filter(|id| !spread.is_known_by(id, &peer_key))
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

                    // Peer is requesting txs from us.
                    // In a full implementation, we'd look up the mempool
                    // and send the full transaction data.
                    trace!(
                        "P2P peer {} requesting {} transactions",
                        self.router,
                        tx_ids.len()
                    );

                    // Look up each requested TX in the mempool.
                    for id in tx_ids {
                        if let Some(tx_data) = self.ctx.mempool.get_transaction(&id) {
                            let tx_msg =
                                MisakaMessage::new(MisakaPayloadType::Transaction, tx_data);
                            self.router.enqueue(tx_msg).await?;
                        } else {
                            let not_found = MisakaMessage::new(
                                MisakaPayloadType::TransactionNotFound,
                                id.to_vec(),
                            );
                            self.router.enqueue(not_found).await?;
                        }
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

                    // Validate and insert into mempool.
                    // validate_and_insert() checks structural validity before insertion.
                    match self
                        .ctx
                        .mempool
                        .validate_and_insert(tx_hash, msg.payload.clone())
                    {
                        Ok(false) => continue, // already known
                        Ok(true) => {}         // newly inserted, continue to relay
                        Err(reason) => {
                            warn!(
                                "P2P rejected invalid tx {} from {}: {}",
                                hex::encode(&tx_hash[..8]),
                                self.router,
                                reason
                            );
                            continue;
                        }
                    }

                    // Record in spread tracker.
                    {
                        let mut spread = self.ctx.tx_spread.lock();
                        spread.add(tx_hash, peer_key);
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
