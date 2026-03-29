//! # misaka-rpc
//!
//! RPC server for MISAKA Network. Provides:
//! - JSON-RPC 2.0 over HTTP
//! - wRPC (WebSocket RPC) for real-time subscriptions
//! - gRPC compatibility layer
//! - Full Kaspa-compatible RPC API surface
//! - Rate limiting and authentication

pub mod api;
pub mod convert;
pub mod error;
pub mod grpc;
pub mod model;
pub mod notifications;
pub mod ops;
pub mod server;
pub mod service;
pub mod handler;
pub mod service_impl;
pub mod auth;
pub mod subscriptions;
pub mod wrpc;

pub use error::{RpcError, RpcResult};
pub use service::RpcService;
pub mod connection_manager;
pub mod middleware;
pub mod metrics_collector;
pub mod proxy;
pub mod request_validator;
pub mod response_builder;
pub mod batch_handler;
pub mod websocket_handler;
pub mod health_check;
pub mod cors_handler;
pub mod notification_relay;
pub mod peer_api;
pub mod block_api;
pub mod transaction_api;
pub mod utxo_api;
pub mod dag_api;
pub mod subscribe_api;
pub mod mining_api;
pub mod network_api;
pub mod load_balancer;
pub mod tls_config;
pub mod encoding;
pub mod version_negotiation;
pub mod grpc_convert;
