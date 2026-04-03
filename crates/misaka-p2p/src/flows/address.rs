//! # Address Flow — Peer Discovery Gossip
//!
//! Handles RequestAddresses / Addresses message exchange.
//! Peers periodically request addresses of other known nodes
//! to build a diverse topology.

use std::sync::Arc;

use tracing::{debug, trace};

use crate::flow_context::FlowContext;
use crate::flow_trait::Flow;
use crate::payload_type::{MisakaMessage, MisakaPayloadType};
use crate::protocol_error::ProtocolError;
use crate::router::{IncomingRoute, Router};

/// Maximum addresses per response.
const MAX_ADDRESSES_PER_RESPONSE: usize = 1000;

pub struct AddressFlow {
    pub router: Arc<Router>,
    pub ctx: Arc<FlowContext>,
    pub incoming: IncomingRoute,
}

impl AddressFlow {
    pub fn new(router: Arc<Router>, ctx: Arc<FlowContext>) -> Result<Self, ProtocolError> {
        let incoming = router.subscribe(vec![
            MisakaPayloadType::RequestAddresses,
            MisakaPayloadType::Addresses,
            MisakaPayloadType::RequestPeerInfo,
            MisakaPayloadType::PeerInfo,
        ])?;
        Ok(Self {
            router,
            ctx,
            incoming,
        })
    }
}

#[async_trait::async_trait]
impl Flow for AddressFlow {
    fn name(&self) -> &'static str {
        "AddressFlow"
    }

    async fn run(mut self: Box<Self>) -> Result<(), ProtocolError> {
        loop {
            let msg = match self.incoming.recv().await {
                Some(m) => m,
                None => return Err(ProtocolError::ConnectionClosed),
            };

            match msg.msg_type {
                MisakaPayloadType::RequestAddresses => {
                    trace!("P2P peer {} requesting addresses", self.router);

                    // Collect known peer addresses from the hub.
                    let peers = self.ctx.hub.active_peers();
                    let addresses: Vec<String> = peers
                        .iter()
                        .filter(|p| p.is_outbound) // Only share outbound peers
                        .take(MAX_ADDRESSES_PER_RESPONSE)
                        .map(|p| p.address.to_string())
                        .collect();

                    let payload = serde_json::to_vec(&addresses).unwrap_or_default();
                    let response = MisakaMessage::new(MisakaPayloadType::Addresses, payload);
                    self.router.enqueue(response).await?;
                }

                MisakaPayloadType::Addresses => {
                    // Received addresses from a peer.
                    let addresses: Vec<String> =
                        serde_json::from_slice(&msg.payload).unwrap_or_default();

                    if addresses.len() > MAX_ADDRESSES_PER_RESPONSE {
                        return Err(ProtocolError::ProtocolViolation(format!(
                            "address response too large: {} (max {})",
                            addresses.len(),
                            MAX_ADDRESSES_PER_RESPONSE
                        )));
                    }

                    debug!(
                        "P2P received {} addresses from {}",
                        addresses.len(),
                        self.router
                    );

                    // The address manager would process these for future outbound connections.
                    // For now, just log them.
                }

                MisakaPayloadType::RequestPeerInfo => {
                    // Respond with our node's information.
                    let info = serde_json::json!({
                        "version": self.ctx.config.protocol_version,
                        "user_agent": self.ctx.config.user_agent,
                        "chain_id": self.ctx.config.chain_id,
                        "blue_score": self.ctx.virtual_blue_score.load(
                            std::sync::atomic::Ordering::Relaxed
                        ),
                        "peer_count": self.ctx.hub.active_peers_len(),
                        "is_ibd": self.ctx.is_ibd(),
                    });
                    let payload = serde_json::to_vec(&info).unwrap_or_default();
                    let response = MisakaMessage::new(MisakaPayloadType::PeerInfo, payload);
                    self.router.enqueue(response).await?;
                }

                MisakaPayloadType::PeerInfo => {
                    trace!("P2P received peer info from {}", self.router);
                    // Could update peer properties if needed.
                }

                _ => {}
            }
        }
    }
}
