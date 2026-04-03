//! # Block Relay Flow — Inventory-Based Block Propagation
//!
//! Kaspa-aligned block relay protocol:
//! 1. Peer announces new block via InvRelayBlock (just the hash)
//! 2. If we don't have it, we RequestRelayBlocks
//! 3. Peer sends full RelayBlock
//! 4. We validate and add to consensus, then broadcast inv to others
//!
//! Anti-DoS: inv messages use Drop overflow policy (safe to lose some).
//! Full blocks use Disconnect policy (must not lose once requested).

use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, trace, warn};

use crate::flow_context::{BlockLogEvent, FlowContext, Hash};
use crate::flow_trait::Flow;
use crate::payload_type::{MisakaMessage, MisakaPayloadType};
use crate::protocol_error::ProtocolError;
use crate::router::{IncomingRoute, Router};

/// Maximum inv hashes per message.
const MAX_INV_PER_MSG: usize = 256;

/// Maximum concurrent block requests per peer.
const MAX_CONCURRENT_REQUESTS: usize = 8;

pub struct BlockRelayFlow {
    pub router: Arc<Router>,
    pub ctx: Arc<FlowContext>,
    pub incoming: IncomingRoute,
    /// Blocks we've requested but not yet received.
    pending_requests: HashSet<Hash>,
}

impl BlockRelayFlow {
    pub fn new(router: Arc<Router>, ctx: Arc<FlowContext>) -> Result<Self, ProtocolError> {
        let incoming = router.subscribe_with_capacity(
            vec![
                MisakaPayloadType::InvRelayBlock,
                MisakaPayloadType::RelayBlock,
                MisakaPayloadType::NewBlockTemplate,
            ],
            512, // Larger capacity for block relay
        )?;
        Ok(Self {
            router,
            ctx,
            incoming,
            pending_requests: HashSet::new(),
        })
    }

    /// Parse an inv message containing block hashes.
    fn parse_inv_hashes(payload: &[u8]) -> Result<Vec<Hash>, ProtocolError> {
        if payload.len() % 32 != 0 {
            return Err(ProtocolError::ProtocolViolation(
                "inv payload not a multiple of 32 bytes".into(),
            ));
        }
        let count = payload.len() / 32;
        if count > MAX_INV_PER_MSG {
            return Err(ProtocolError::ProtocolViolation(format!(
                "inv contains {} hashes (max {})",
                count, MAX_INV_PER_MSG
            )));
        }
        let mut hashes = Vec::with_capacity(count);
        for chunk in payload.chunks_exact(32) {
            let mut h = [0u8; 32];
            h.copy_from_slice(chunk);
            hashes.push(h);
        }
        Ok(hashes)
    }

    /// Parse a relay block: first 32 bytes = hash, rest = block data.
    fn parse_relay_block(payload: &[u8]) -> Result<(Hash, Vec<u8>), ProtocolError> {
        if payload.len() < 33 {
            return Err(ProtocolError::ProtocolViolation(
                "relay block too small".into(),
            ));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        let block_data = payload[32..].to_vec();
        Ok((hash, block_data))
    }
}

#[async_trait::async_trait]
impl Flow for BlockRelayFlow {
    fn name(&self) -> &'static str {
        "BlockRelayFlow"
    }

    async fn run(mut self: Box<Self>) -> Result<(), ProtocolError> {
        loop {
            let msg = match self.incoming.recv().await {
                Some(m) => m,
                None => return Err(ProtocolError::ConnectionClosed),
            };

            match msg.msg_type {
                MisakaPayloadType::InvRelayBlock => {
                    let hashes = Self::parse_inv_hashes(&msg.payload)?;

                    // Filter: only request blocks we don't have.
                    let unknown: Vec<Hash> = hashes
                        .into_iter()
                        .filter(|h| {
                            !self.ctx.process_queue.lock().contains(h)
                                && !self.ctx.orphans.lock().contains(h)
                                && !self.pending_requests.contains(h)
                        })
                        .take(MAX_CONCURRENT_REQUESTS.saturating_sub(self.pending_requests.len()))
                        .collect();

                    if unknown.is_empty() {
                        continue;
                    }

                    trace!(
                        "P2P requesting {} relay blocks from {}",
                        unknown.len(),
                        self.router
                    );

                    // Build request payload: concatenated hashes.
                    let mut request_payload = Vec::with_capacity(unknown.len() * 32);
                    for h in &unknown {
                        request_payload.extend_from_slice(h);
                        self.pending_requests.insert(*h);
                    }

                    let request =
                        MisakaMessage::new(MisakaPayloadType::RequestRelayBlocks, request_payload);
                    self.router.enqueue(request).await?;
                }

                MisakaPayloadType::RelayBlock => {
                    let (hash, block_data) = Self::parse_relay_block(&msg.payload)?;

                    self.pending_requests.remove(&hash);

                    // Enqueue for consensus processing.
                    let peer_key = self.router.key();
                    let enqueued = self
                        .ctx
                        .process_queue
                        .lock()
                        .push(hash, block_data, peer_key);

                    if enqueued {
                        self.ctx.block_logger.log(BlockLogEvent::Relay(hash));

                        // Broadcast inv to other peers.
                        let inv =
                            MisakaMessage::new(MisakaPayloadType::InvRelayBlock, hash.to_vec());
                        self.ctx.hub.broadcast(inv, Some(peer_key)).await;
                    }
                }

                MisakaPayloadType::NewBlockTemplate => {
                    // Block template from a miner — handle similarly to relay.
                    debug!("P2P received NewBlockTemplate from {}", self.router);
                    // Templates are processed by the mining subsystem.
                }

                other => {
                    warn!("P2P BlockRelayFlow unexpected message {:?}", other);
                }
            }
        }
    }
}
