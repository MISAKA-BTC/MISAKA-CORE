//! # Flow Trait — Async Protocol Flow Abstraction
//!
//! Each P2P "flow" is an independent async task that processes
//! messages of specific types from a single peer.
//!
//! Flows are registered during connection initialization and
//! run until the peer disconnects or an error occurs.

use std::sync::Arc;

use crate::flow_context::FlowContext;
use crate::protocol_error::ProtocolError;
use crate::router::Router;

/// Trait for P2P protocol flows.
///
/// Each flow:
/// 1. Subscribes to specific message types via `Router::subscribe()`
/// 2. Processes messages in a loop
/// 3. Returns when the peer disconnects or a protocol error occurs
#[async_trait::async_trait]
pub trait Flow: Send + Sync + 'static {
    /// Human-readable name for logging.
    fn name(&self) -> &'static str;

    /// Run the flow until completion or error.
    async fn run(self: Box<Self>) -> Result<(), ProtocolError>;
}

/// Helper to spawn a flow as a tokio task with error logging.
pub fn spawn_flow(
    flow: Box<dyn Flow>,
    router: Arc<Router>,
    ctx: Arc<FlowContext>,
) -> tokio::task::JoinHandle<()> {
    let name = flow.name();
    let peer_addr = router.net_address();

    tokio::spawn(async move {
        let result = flow.run().await;
        match result {
            Ok(()) => {
                tracing::debug!(
                    "P2P flow '{}' completed for peer {}",
                    name,
                    peer_addr
                );
            }
            Err(ProtocolError::ConnectionClosed) => {
                tracing::debug!(
                    "P2P flow '{}' peer {} disconnected",
                    name,
                    peer_addr
                );
            }
            Err(ref e) if e.should_penalize() => {
                tracing::warn!(
                    "P2P flow '{}' protocol error from {}: {}",
                    name,
                    peer_addr,
                    e
                );
                // Score penalty would be applied by the caller via ScoreManager.
            }
            Err(e) => {
                tracing::debug!(
                    "P2P flow '{}' error from {}: {}",
                    name,
                    peer_addr,
                    e
                );
            }
        }
        // The router will be closed by the receive loop when all flows exit.
        drop(ctx);
    })
}
