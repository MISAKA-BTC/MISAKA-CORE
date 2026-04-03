//! # P2P Protocol Flows
//!
//! Each flow is an independent async task bound to a specific peer.
//! Flows subscribe to message types via the Router and process them
//! in a loop until disconnection.

pub mod address;
pub mod block_relay;
pub mod ibd;
pub mod ping;
pub mod tx_relay;
