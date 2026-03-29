//! RPC API trait definitions.

pub mod connection;
pub mod rpc;
pub mod ctl;
pub mod notifications;

pub use rpc::RpcApi;
pub use connection::RpcConnection;
