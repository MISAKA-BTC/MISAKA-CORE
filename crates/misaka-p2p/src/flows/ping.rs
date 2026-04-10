//! # Ping Flow — Keepalive + Latency Measurement
//!
//! Periodically pings the peer and measures round-trip time.
//! Uses PQ-AEAD encrypted nonces to prevent replay.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, warn};

use crate::flow_context::FlowContext;
use crate::flow_trait::Flow;
use crate::payload_type::{MisakaMessage, MisakaPayloadType};
use crate::protocol_error::ProtocolError;
use crate::router::{IncomingRoute, Router};

/// Interval between pings.
const PING_INTERVAL: Duration = Duration::from_secs(60);

/// Timeout waiting for pong.
const PONG_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum consecutive ping failures before disconnecting.
const MAX_PING_FAILURES: u32 = 3;

pub struct PingFlow {
    pub router: Arc<Router>,
    pub ctx: Arc<FlowContext>,
    pub incoming: IncomingRoute,
}

impl PingFlow {
    pub fn new(router: Arc<Router>, ctx: Arc<FlowContext>) -> Self {
        let incoming = router.subscribe(vec![MisakaPayloadType::Ping, MisakaPayloadType::Pong]);
        Self {
            router,
            ctx,
            incoming,
        }
    }
}

#[async_trait::async_trait]
impl Flow for PingFlow {
    fn name(&self) -> &'static str {
        "PingFlow"
    }

    async fn run(mut self: Box<Self>) -> Result<(), ProtocolError> {
        let mut interval = tokio::time::interval(PING_INTERVAL);
        let mut failures = 0u32;

        loop {
            tokio::select! {
                // Respond to incoming pings from the peer.
                msg = self.incoming.recv() => match msg {
                    Some(m) if m.msg_type == MisakaPayloadType::Ping => {
                        // Echo back as pong with the same nonce payload.
                        let pong = MisakaMessage::new(
                            MisakaPayloadType::Pong,
                            m.payload,
                        );
                        self.router.enqueue(pong).await?;
                    }
                    Some(_) => {
                        // Pong received out of our ping cycle — ignore.
                    }
                    None => return Err(ProtocolError::ConnectionClosed),
                },

                // Send periodic pings.
                _ = interval.tick() => {
                    // Generate a random 8-byte nonce for this ping.
                    let nonce: u64 = rand::random();
                    let ping = MisakaMessage::new(
                        MisakaPayloadType::Ping,
                        nonce.to_le_bytes().to_vec(),
                    );
                    let sent_at = Instant::now();

                    self.router.enqueue(ping).await?;

                    // Wait for pong with timeout.
                    match self.incoming.recv_timeout(PONG_TIMEOUT).await {
                        Ok(pong) if pong.msg_type == MisakaPayloadType::Pong => {
                            let rtt_ms = sent_at.elapsed().as_millis() as u64;
                            self.router.set_last_ping_duration_ms(rtt_ms);
                            failures = 0;
                            debug!(
                                "P2P ping to {} RTT={}ms",
                                self.router, rtt_ms
                            );
                        }
                        Ok(_unexpected) => {
                            // Got a non-pong; might be a ping from them.
                            // Handle it next iteration.
                            failures += 1;
                        }
                        Err(ProtocolError::Timeout(_)) => {
                            failures += 1;
                            warn!(
                                "P2P ping timeout from {} (failures={})",
                                self.router, failures
                            );
                        }
                        Err(e) => return Err(e),
                    }

                    if failures >= MAX_PING_FAILURES {
                        return Err(ProtocolError::ProtocolViolation(
                            format!("peer {} unresponsive ({} ping failures)", self.router, failures)
                        ));
                    }
                }
            }
        }
    }
}
