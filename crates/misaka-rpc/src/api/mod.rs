//! RPC API trait definitions.

pub mod connection;
pub mod ctl;
pub mod notifications;
pub mod rpc;

pub use connection::RpcConnection;
pub use rpc::RpcApi;
