//! # misaka-mining
//!
//! Block production manager for MISAKA Network. In MISAKA's PoS/DAG context,
//! "mining" means block template construction by validators. This crate manages:
//! - Transaction mempool with fee-rate ordering and RBF support
//! - Block template building with mass/size policy enforcement
//! - Orphan transaction tracking and eviction
//! - Fee estimation and fee-rate statistics
//! - Template caching for rapid block production

pub mod block_template;
pub mod cache;
pub mod errors;
pub mod fee_rate;
pub mod manager;
pub mod mass;
pub mod mempool;
pub mod model;
pub mod monitor;
pub mod stratum;
pub mod testutils;

pub use errors::{MiningError, MiningResult};
pub use manager::MiningManager;
pub use model::MiningCounters;

/// Re-export mempool types.
pub use mempool::config::MempoolConfig;
pub use mempool::tx::{Orphan, Priority, RbfPolicy};
pub mod block_validator;
pub mod difficulty_manager;
pub mod orphan_manager;
pub mod pool_manager;
pub mod reward_calculator;
