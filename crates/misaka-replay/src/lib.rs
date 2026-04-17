// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! # misaka-replay — Forensic Replay Engine
//!
//! Re-execute past transactions against historical state to diagnose
//! incidents. Operates in read-only mode — never writes to production DB.
//!
//! ## Design Principles
//!
//! - **Read-only**: Production DB is never modified
//! - **Deterministic**: Same input → same output
//! - **Lightweight**: Target 5-minute incident response
//! - **No consensus**: Uses committed state only, no DAG traversal
//!
//! ## Honest Report: Limitations
//!
//! - **No RocksDB read-only open**: misaka-storage doesn't expose read-only
//!   DB API. Replay operates on snapshot files, not live DB.
//! - **Simplified validation**: Full ML-DSA-65 signature re-verification
//!   is optional (disabled by default for performance).
//! - **utxo_executor.rs logic**: Tx validation is ported via UtxoSet
//!   integration, not by directly extracting from misaka-node.

pub mod detectors;
pub mod engine;
pub mod error;
pub mod executor;
pub mod store;

#[cfg(test)]
mod tests;

pub use engine::{ReplayConfig, ReplayEngine, ReplayResult};
pub use error::{ReplayError, SupplyViolation, TxMismatch};
pub use executor::{ReplayExecutionContext, ReplayExecutor, UtxoReplayExecutor};
pub use store::{MemoryReplayStore, ReadOnlyStore, ReplayBlock};
