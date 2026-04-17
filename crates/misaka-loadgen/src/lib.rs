// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! # misaka-loadgen — TPS / Latency Load Generator
//!
//! Generates ML-DSA-65-signed transactions and submits them to a MISAKA
//! node cluster via RPC. Measures submit TPS, latency distributions, and
//! ML-DSA-65 signature overhead.
//!
//! ## Design Principles
//!
//! - **Honest measurement**: ML-DSA-65 signing cost is always included
//! - **4 TPS metrics**: submit / commit / finality / bandwidth-adjusted
//! - **Read-only against cluster**: does not modify consensus parameters
//! - **Deterministic**: seed-based tx generation for reproducibility
//!
//! ## Current Limitations
//!
//! - commit_tps / finality_tps require RPC polling (not yet implemented)
//! - e2e testing requires misaka-test-cluster Swarm mode (separate blocker)
//! - ML-DSA-65 keygen is ~10ms/key — warmup phase required

pub mod client;
pub mod engine;
pub mod error;
pub mod txgen;
pub mod types;

#[cfg(test)]
mod tests;

pub use client::{LoadgenClient, MockClient, TxAccepted};
pub use engine::run_loadgen;
pub use error::LoadgenError;
pub use txgen::{KeypairPool, LoadgenKeypair};
pub use types::{LatencyHistogram, LoadgenConfig, LoadgenReport, SignatureCostReport, Workload};
