//! # P2P Router — Kaspa-Aligned Flow-Based Message Routing
//!
//! Each connected peer is represented by a `Router` object that:
//! 1. Owns the PQ-AEAD encrypted read/write streams
//! 2. Routes incoming messages to subscribed flows by message type
//! 3. Supports request–response correlation via route IDs
//! 4. Manages session lifetime and PQ re-keying
//!
//! ```text
//! ┌─────────────┐          ┌──────────────────────────────┐
//! │  TCP/QUIC   │ ◄──────► │         Router               │
//! │  + PQ-AEAD  │          │ ┌─────────────────────────┐  │
//! │             │  decrypt  │ │  routing_map_by_type     │  │
//! │             │ ────────► │ │  InvRelayBlock → Flow A  │  │
//! │             │           │ │  Transaction   → Flow B  │  │
//! │             │           │ │  Ping          → Flow C  │  │
//! │             │  encrypt  │ └─────────────────────────┘  │
//! │             │ ◄──────── │  outgoing_route (mpsc)       │
//! └─────────────┘          │  hub_sender (events)         │
//!                          └──────────────────────────────┘
//! ```

use std::collections::HashMap;
use std::fmt::{self, Debug, Display};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::{Mutex, RwLock};
use tokio::sync::mpsc::{channel as mpsc_channel, Receiver as MpscReceiver, Sender as MpscSender};
use tokio::sync::oneshot::{channel as oneshot_channel, Sender as OneshotSender};
use tracing::{debug, error, info, trace, warn};

use crate::message_validation::{validate_raw_message, MessageRateTracker, RateCheckResult};
use crate::payload_type::{MisakaMessage, MisakaPayloadType, OverflowPolicy, BLANK_ROUTE_ID};
use crate::peer_id::PeerId;
use crate::protocol_error::ProtocolError;

// ═══════════════════════════════════════════════════════════════
//  Incoming Route
// ═══════════════════════════════════════════════════════════════

static ROUTE_ID_COUNTER: AtomicU32 = AtomicU32::new(BLANK_ROUTE_ID + 1);

/// A receive channel for a specific P2P flow.
pub struct IncomingRoute {
    rx: MpscReceiver<MisakaMessage>,
    id: u32,
}

impl IncomingRoute {
    pub fn new(rx: MpscReceiver<MisakaMessage>) -> Self {
        let id = ROUTE_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
        Self { rx, id }
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub async fn recv(&mut self) -> Option<MisakaMessage> {
        self.rx.recv().await
    }

    /// Receive with a timeout. Returns `Err(Timeout)` on expiry.
    pub async fn recv_timeout(
        &mut self,
        duration: std::time::Duration,
    ) -> Result<MisakaMessage, ProtocolError> {
        match tokio::time::timeout(duration, self.rx.recv()).await {
            Ok(Some(msg)) => Ok(msg),
            Ok(None) => Err(ProtocolError::ConnectionClosed),
            Err(_) => Err(ProtocolError::Timeout(format!(
                "route {} timed out after {:?}",
                self.id, duration
            ))),
        }
    }
}

/// Thread-safe shared incoming route for flows that need concurrent access.
#[derive(Clone)]
pub struct SharedIncomingRoute(Arc<tokio::sync::Mutex<IncomingRoute>>);

impl SharedIncomingRoute {
    pub fn new(incoming_route: IncomingRoute) -> Self {
        Self(Arc::new(tokio::sync::Mutex::new(incoming_route)))
    }

    pub async fn recv(&self) -> Option<MisakaMessage> {
        self.0.lock().await.recv().await
    }

    pub async fn recv_timeout(
        &self,
        duration: std::time::Duration,
    ) -> Result<MisakaMessage, ProtocolError> {
        self.0.lock().await.recv_timeout(duration).await
    }
}

// ═══════════════════════════════════════════════════════════════
//  Peer Properties
// ═══════════════════════════════════════════════════════════════

/// Immutable properties exchanged during PQ handshake.
#[derive(Debug, Clone, Default)]
pub struct PeerProperties {
    /// Protocol version negotiated during handshake.
    pub protocol_version: u32,
    /// Network identifier (chain_id).
    pub network_id: u32,
    /// The peer's user agent / node name.
    pub user_agent: String,
    /// Whether the peer serves historical data (archival node).
    pub is_archival: bool,
    /// Peer's ML-DSA-65 public key fingerprint (SHA3-256 of pk).
    pub pq_identity_fingerprint: [u8; 32],
    /// Peer's declared blue score at handshake time.
    pub handshake_blue_score: u64,
}

/// Uniquely identifies a peer connection by (identity, IP).
/// Prevents identity impersonation from different IPs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerKey {
    pub identity: PeerId,
    pub ip: std::net::IpAddr,
}

impl PeerKey {
    pub fn new(identity: PeerId, ip: std::net::IpAddr) -> Self {
        Self { identity, ip }
    }
}

impl Display for PeerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.identity, self.ip)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Peer (public snapshot)
// ═══════════════════════════════════════════════════════════════

/// Public snapshot of a connected peer (returned by Hub queries).
#[derive(Debug, Clone)]
pub struct Peer {
    pub identity: PeerId,
    pub address: SocketAddr,
    pub is_outbound: bool,
    pub connected_at: Instant,
    pub properties: Arc<PeerProperties>,
    pub last_ping_ms: u64,
}

// ═══════════════════════════════════════════════════════════════
//  Hub Events
// ═══════════════════════════════════════════════════════════════

/// Events sent from each Router to the central Hub.
#[derive(Debug)]
pub enum HubEvent {
    /// A new peer has completed the PQ handshake.
    NewPeer(Arc<Router>),
    /// A peer's router is closing (disconnected or error).
    PeerClosing(Arc<Router>),
}

// ═══════════════════════════════════════════════════════════════
//  Router Mutable State
// ═══════════════════════════════════════════════════════════════

#[derive(Default)]
struct RouterMutableState {
    start_signal: Option<OneshotSender<()>>,
    shutdown_signal: Option<OneshotSender<()>>,
    properties: Arc<PeerProperties>,
    last_ping_duration_ms: u64,
}

impl RouterMutableState {
    fn new(
        start_signal: Option<OneshotSender<()>>,
        shutdown_signal: Option<OneshotSender<()>>,
    ) -> Self {
        Self {
            start_signal,
            shutdown_signal,
            ..Default::default()
        }
    }
}

impl Debug for RouterMutableState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouterMutableState")
            .field("has_start_signal", &self.start_signal.is_some())
            .field("has_shutdown_signal", &self.shutdown_signal.is_some())
            .field("last_ping_ms", &self.last_ping_duration_ms)
            .finish()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Router
// ═══════════════════════════════════════════════════════════════

/// Default channel capacity for flow subscriptions.
pub const FLOW_CHANNEL_CAPACITY: usize = 256;

/// Outgoing channel capacity.
pub const OUTGOING_CHANNEL_CAPACITY: usize = 512;

/// A Router manages all communication with a single network peer.
///
/// It routes incoming messages to registered flows based on message type
/// or response ID, and provides an outgoing channel for sending messages.
pub struct Router {
    /// PQ peer identity (derived from ML-DSA-65 public key).
    identity: parking_lot::RwLock<PeerId>,

    /// Socket address of this peer.
    net_address: SocketAddr,

    /// Whether this is an outbound connection we initiated.
    is_outbound: bool,

    /// When this connection was established.
    connection_started: Instant,

    /// Flow subscriptions by message type.
    routing_map_by_type: RwLock<HashMap<MisakaPayloadType, MpscSender<MisakaMessage>>>,

    /// Flow subscriptions by response ID (for request–response pairing).
    routing_map_by_id: RwLock<HashMap<u32, MpscSender<MisakaMessage>>>,

    /// Outgoing message channel to the write loop.
    outgoing_route: MpscSender<MisakaMessage>,

    /// Channel to send lifecycle events to the Hub.
    hub_sender: MpscSender<HubEvent>,

    /// Mutable state protected by parking_lot::Mutex.
    mutable_state: Mutex<RouterMutableState>,

    /// SEC-FIX TM-5: Per-peer message rate tracker.
    rate_tracker: Mutex<MessageRateTracker>,
}

impl Debug for Router {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Router")
            .field("identity", &self.identity())
            .field("address", &self.net_address)
            .field("outbound", &self.is_outbound)
            .finish()
    }
}

impl Display for Router {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.net_address)
    }
}

impl From<&Router> for PeerKey {
    fn from(r: &Router) -> Self {
        Self::new(r.identity(), r.net_address.ip())
    }
}

impl From<&Router> for Peer {
    fn from(r: &Router) -> Self {
        Self {
            identity: r.identity(),
            address: r.net_address,
            is_outbound: r.is_outbound,
            connected_at: r.connection_started,
            properties: r.properties(),
            last_ping_ms: r.last_ping_duration_ms(),
        }
    }
}

impl Router {
    /// Create a new Router and spawn the receive loop.
    ///
    /// The receive loop starts paused; call `start()` after flow registration.
    ///
    /// `incoming_rx` is the decrypted message stream from the PQ-AEAD layer.
    pub fn new(
        net_address: SocketAddr,
        is_outbound: bool,
        hub_sender: MpscSender<HubEvent>,
        mut incoming_rx: MpscReceiver<MisakaMessage>,
        outgoing_route: MpscSender<MisakaMessage>,
    ) -> Arc<Self> {
        let (start_tx, start_rx) = oneshot_channel();
        let (shutdown_tx, mut shutdown_rx) = oneshot_channel();

        let router = Arc::new(Router {
            identity: parking_lot::RwLock::new(PeerId::default()),
            net_address,
            is_outbound,
            connection_started: Instant::now(),
            routing_map_by_type: RwLock::new(HashMap::new()),
            routing_map_by_id: RwLock::new(HashMap::new()),
            outgoing_route,
            hub_sender,
            mutable_state: Mutex::new(RouterMutableState::new(Some(start_tx), Some(shutdown_tx))),
            rate_tracker: Mutex::new(MessageRateTracker::new()),
        });

        let router_clone = router.clone();
        tokio::spawn(async move {
            // Wait for start signal (flows must be registered first).
            let _ = start_rx.await;
            loop {
                tokio::select! {
                    biased;

                    _ = &mut shutdown_rx => {
                        debug!(
                            "P2P Router receive loop shutdown, peer={}",
                            router.identity()
                        );
                        break;
                    }

                    msg_opt = incoming_rx.recv() => match msg_opt {
                        Some(msg) => {
                            trace!(
                                "P2P msg: type={}, peer={}",
                                msg.msg_type.name(),
                                router
                            );
                            match router.route_to_flow(msg) {
                                Ok(()) => {}
                                Err(ProtocolError::IgnorableReject(reason)) => {
                                    debug!("P2P ignorable reject from {}: {}", router, reason);
                                }
                                Err(ProtocolError::Rejected(reason)) => {
                                    warn!("P2P rejected by {}: {}", router, reason);
                                    break;
                                }
                                Err(e) => {
                                    warn!("P2P route error for {}: {}", router, e);
                                    break;
                                }
                            }
                        }
                        None => {
                            info!("P2P incoming stream ended from {}", router);
                            break;
                        }
                    }
                }
            }
            router.close().await;
            debug!(
                "P2P Router loop exited, peer={}, refs={}",
                router.identity(),
                Arc::strong_count(&router)
            );
        });

        router_clone
    }

    // ── Identity ──

    pub fn identity(&self) -> PeerId {
        *self.identity.read()
    }

    pub fn set_identity(&self, id: PeerId) {
        *self.identity.write() = id;
    }

    pub fn net_address(&self) -> SocketAddr {
        self.net_address
    }

    pub fn key(&self) -> PeerKey {
        self.into()
    }

    pub fn is_outbound(&self) -> bool {
        self.is_outbound
    }

    pub fn connection_started(&self) -> Instant {
        self.connection_started
    }

    pub fn time_connected_ms(&self) -> u64 {
        Instant::now()
            .duration_since(self.connection_started)
            .as_millis() as u64
    }

    // ── Properties ──

    pub fn properties(&self) -> Arc<PeerProperties> {
        self.mutable_state.lock().properties.clone()
    }

    pub fn set_properties(&self, props: Arc<PeerProperties>) {
        self.mutable_state.lock().properties = props;
    }

    pub fn set_last_ping_duration_ms(&self, ms: u64) {
        self.mutable_state.lock().last_ping_duration_ms = ms;
    }

    pub fn last_ping_duration_ms(&self) -> u64 {
        self.mutable_state.lock().last_ping_duration_ms
    }

    // ── Flow Subscription ──

    /// Subscribe to one or more message types with default channel capacity.
    pub fn subscribe(&self, msg_types: Vec<MisakaPayloadType>) -> IncomingRoute {
        self.subscribe_with_capacity(msg_types, FLOW_CHANNEL_CAPACITY)
    }

    /// Subscribe to one or more message types with custom channel capacity.
    pub fn subscribe_with_capacity(
        &self,
        msg_types: Vec<MisakaPayloadType>,
        capacity: usize,
    ) -> IncomingRoute {
        let (tx, rx) = mpsc_channel(capacity);
        let route = IncomingRoute::new(rx);

        let mut map_type = self.routing_map_by_type.write();
        for msg_type in msg_types {
            if let Some(_prev) = map_type.insert(msg_type, tx.clone()) {
                error!(
                    "P2P Router::subscribe overrides existing type {:?}, peer={}",
                    msg_type,
                    self.identity()
                );
                panic!("P2P: tried to subscribe to an existing route");
            }
            trace!("P2P subscribed to {:?}, peer={}", msg_type, self.identity());
        }

        let mut map_id = self.routing_map_by_id.write();
        if map_id.insert(route.id, tx).is_some() {
            error!(
                "P2P Router::subscribe overrides existing route_id={}, peer={}",
                route.id,
                self.identity()
            );
            panic!("P2P: tried to subscribe with duplicate route ID");
        }

        route
    }

    // ── Message Routing ──

    /// Route an incoming message to the correct flow channel.
    pub fn route_to_flow(&self, msg: MisakaMessage) -> Result<(), ProtocolError> {
        let msg_type = msg.msg_type;

        // SEC-FIX NH-1: Validate message size/structure before routing.
        let type_label = format!("{:?}", msg_type);
        if let Err(e) = validate_raw_message(&type_label, &msg.payload) {
            warn!(
                peer = %self,
                "P2P message validation failed for {}: {}",
                type_label, e
            );
            return Err(ProtocolError::MessageValidationFailed(e.to_string()));
        }

        // SEC-FIX TM-5: Per-type message rate limiting.
        {
            let mut tracker = self.rate_tracker.lock();
            if let RateCheckResult::Exceeded { msg_type: mt, count, limit } = tracker.check_rate(&type_label) {
                warn!(
                    peer = %self,
                    "P2P message rate limit exceeded for {}: {}/{} per minute",
                    mt, count, limit
                );
                return Err(ProtocolError::MessageValidationFailed(
                    format!("rate limit exceeded for {}", mt),
                ));
            }
        }

        // Handle reject messages specially.
        if msg_type == MisakaPayloadType::Reject {
            let reason = String::from_utf8_lossy(&msg.payload).to_string();
            return Err(ProtocolError::from_reject_message(reason));
        }

        // Try response_id routing first, then type-based routing.
        let sender = if msg.response_id != BLANK_ROUTE_ID {
            self.routing_map_by_id.read().get(&msg.response_id).cloned()
        } else {
            self.routing_map_by_type.read().get(&msg_type).cloned()
        };

        if let Some(tx) = sender {
            match tx.try_send(msg) {
                Ok(()) => Ok(()),
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    Err(ProtocolError::ConnectionClosed)
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    match msg_type.overflow_policy() {
                        OverflowPolicy::Drop => Ok(()),
                        OverflowPolicy::Disconnect => Err(
                            ProtocolError::IncomingRouteCapacityReached(msg_type, self.to_string()),
                        ),
                    }
                }
            }
        } else {
            Err(ProtocolError::NoRouteForMessageType(msg_type))
        }
    }

    // ── Outgoing ──

    /// Enqueue a message for sending to this peer.
    pub async fn enqueue(&self, msg: MisakaMessage) -> Result<(), ProtocolError> {
        match self.outgoing_route.try_send(msg) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                Err(ProtocolError::ConnectionClosed)
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => Err(
                ProtocolError::OutgoingRouteCapacityReached(self.to_string()),
            ),
        }
    }

    /// Send a reject message before closing (best-effort).
    pub async fn try_sending_reject(&self, err: &ProtocolError) {
        if err.can_send_outgoing_message() {
            let _ = self
                .enqueue(MisakaMessage::reject(&err.to_reject_message()))
                .await;
        }
    }

    // ── Lifecycle ──

    /// Send the start signal to begin the receive loop.
    pub fn start(&self) {
        let signal = self.mutable_state.lock().start_signal.take();
        if let Some(tx) = signal {
            let _ = tx.send(());
        } else {
            debug!(
                "P2P Router::start called more than once, peer={}",
                self.identity()
            );
        }
    }

    /// Close the router, clean up all resources. Returns `true` on first call.
    pub async fn close(self: &Arc<Router>) -> bool {
        {
            let mut state = self.mutable_state.lock();

            // Ensure start signal fires (in case start() was never called).
            if let Some(tx) = state.start_signal.take() {
                let _ = tx.send(());
            }

            if let Some(tx) = state.shutdown_signal.take() {
                let _ = tx.send(());
            } else {
                trace!("P2P Router::close called again, peer={}", self.identity());
                return false;
            }
        }

        // Drop all flow senders → unblock any waiting flows.
        self.routing_map_by_type.write().clear();
        self.routing_map_by_id.write().clear();

        // Notify the Hub.
        self.hub_sender
            .send(HubEvent::PeerClosing(self.clone()))
            .await
            .unwrap_or_else(|_| {
                warn!("P2P Hub receiver dropped before router close");
            });

        true
    }
}
