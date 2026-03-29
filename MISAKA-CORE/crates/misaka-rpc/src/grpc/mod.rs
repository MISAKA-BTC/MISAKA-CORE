//! gRPC compatibility layer for MISAKA RPC.
//!
//! Provides a gRPC service definition compatible with Kaspa's protobuf API.

pub mod service;
pub mod convert;

/// gRPC server configuration.
#[derive(Debug, Clone)]
pub struct GrpcConfig {
    pub listen_addr: String,
    pub max_message_size: usize,
    pub enable_reflection: bool,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:16210".to_string(),
            max_message_size: 64 * 1024 * 1024,
            enable_reflection: true,
        }
    }
}
