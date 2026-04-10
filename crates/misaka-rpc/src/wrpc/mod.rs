//! wRPC — WebSocket-based RPC for real-time bidirectional communication.
//!
//! wRPC extends JSON-RPC 2.0 over WebSocket with:
//! - Persistent connections with automatic reconnection
//! - Server-pushed notifications (subscriptions)
//! - Binary message encoding for efficiency
//! - Connection multiplexing
//! - Client-side request routing

pub mod client;
pub mod encoding;
pub mod message;
pub mod router;
pub mod server;

/// wRPC protocol version.
pub const WRPC_VERSION: u32 = 1;

/// Maximum message size (16 MB).
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Maximum concurrent subscriptions per client.
pub const MAX_SUBSCRIPTIONS: usize = 256;
