//! # misaka-utils
//!
//! Core utility library for the MISAKA Network node. Provides:
//! - Lifecycle management (task spawning, graceful shutdown)
//! - Rate limiting and throttling
//! - Metrics collection and counters
//! - Hash utilities and domain-separated hashing
//! - Networking helpers (IP classification, peer scoring)
//! - Tower-compatible middleware
//! - General-purpose data structures

pub mod alloc;
pub mod binary_heap;
pub mod channel;
pub mod counter;
pub mod fd_budget;
pub mod hash;
pub mod hashmap;
pub mod lifecycle;
pub mod mem_size;
pub mod networking;
pub mod rate_limit;
pub mod refs;
pub mod serde_utils;
pub mod sysinfo;
pub mod tick;
pub mod tower;
pub mod triggers;
pub mod vec;

/// Re-export commonly used items
pub use lifecycle::{AsyncRuntime, AsyncService, Service};
pub use counter::AtomicCounter;
pub use triggers::DuplexTrigger;
