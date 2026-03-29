//! wRPC message types.

use serde::{Serialize, Deserialize};

/// A wRPC message envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrpcMessage {
    pub id: Option<u64>,
    pub kind: MessageKind,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageKind {
    Request,
    Response,
    Notification,
    Error,
    Ping,
    Pong,
    Subscribe,
    Unsubscribe,
}

/// wRPC request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrpcRequest {
    pub id: u64,
    pub method: String,
    pub params: serde_json::Value,
}

/// wRPC response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrpcResponse {
    pub id: u64,
    pub result: Option<serde_json::Value>,
    pub error: Option<WrpcError>,
}

/// wRPC error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrpcError {
    pub code: i32,
    pub message: String,
}

/// wRPC notification (server push).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrpcNotification {
    pub method: String,
    pub params: serde_json::Value,
}

/// Subscription request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionRequest {
    pub scope: String,
    pub params: Option<serde_json::Value>,
}

/// Subscription acknowledgment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionAck {
    pub listener_id: u64,
    pub scope: String,
}
