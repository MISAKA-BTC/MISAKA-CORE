// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! # misaka-authority-aggregation
//!
//! Generic, async, stake-weighted quorum aggregation for MISAKA Network.
//!
//! Provides fan-out to N authorities, collects responses as they arrive,
//! reduces with a user-defined function, and stops at quorum.
//!
//! ## Key traits
//!
//! - [`StakeCommittee`]: generic authority set with stake weights
//! - [`AuthorityClient`]: async request/response to a single authority
//! - [`QuorumReducer`]: user-defined response reduction logic
//!
//! ## Design
//!
//! This crate intentionally does NOT depend on `misaka-dag` to avoid
//! circular dependencies. The [`StakeCommittee`] trait is implemented by
//! both `misaka-dag::Committee` and `misaka-consensus::ValidatorSet`
//! via thin adapters in their respective crates.
//!
//! For **synchronous, in-process** vote accumulation (consensus hot path),
//! see `misaka-dag::narwhal_dag::stake_aggregator` instead. This crate
//! handles **async peer request/response** aggregation only.

pub mod aggregator;
pub mod client;
pub mod committee;
pub mod error;
pub mod policy;
pub mod reducer;

#[cfg(test)]
mod tests;

// ── Re-exports ──────────────────────────────────────────────────
pub use aggregator::{AggregationResult, QuorumAggregator};
pub use client::AuthorityClient;
pub use committee::{AuthorityIndex, SimpleStakeCommittee, StakeCommittee, StakeWeight};
pub use error::{AuthorityError, QuorumError};
pub use policy::{AggregationPolicy, RetryPolicy};
pub use reducer::{QuorumReducer, ReduceAction};
