//! # misaka-rpc
//!
//! RPC server for MISAKA Network. Provides:
//! - JSON-RPC 2.0 over HTTP
//! - wRPC (WebSocket RPC) for real-time subscriptions
//! - gRPC compatibility layer
//! - Full Kaspa-compatible RPC API surface
//! - Rate limiting and authentication

// H1 fix: dev-noauth MUST NOT be enabled in release builds.
// This feature disables ALL authentication, including admin methods.
#[cfg(all(feature = "dev-noauth", not(debug_assertions)))]
compile_error!(
    "FATAL: 'dev-noauth' feature disables ALL RPC authentication. \
     This MUST NOT be enabled in release/production builds. \
     Remove dev-noauth from your Cargo.toml features."
);

pub mod api;
pub mod auth;
pub mod convert;
pub mod error;
pub mod grpc;
pub mod model;
pub mod notifications;
pub mod ops;
pub mod server;
pub mod service;
pub mod service_impl;
pub mod subscriptions;
pub mod wrpc;

pub use error::{RpcError, RpcResult};
pub use service::RpcService;
// Phase 2c-B: 24 scaffolding modules deleted (dead code)
