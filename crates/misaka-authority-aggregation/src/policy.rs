// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Aggregation policy — configures timeouts, concurrency, and fault handling.

use std::time::Duration;

/// Configures how the quorum aggregator behaves.
#[derive(Debug, Clone)]
pub struct AggregationPolicy {
    /// Timeout for individual authority requests.
    pub per_authority_timeout: Duration,

    /// Total timeout for the entire aggregation.
    /// After this, return whatever partial result is available.
    pub total_timeout: Duration,

    /// Maximum number of concurrent in-flight requests.
    /// Set to `usize::MAX` for unbounded (all at once).
    pub max_concurrent: usize,

    /// Retry policy for failed requests.
    pub retry: RetryPolicy,

    /// Whether to abort early when quorum becomes mathematically impossible
    /// (i.e., remaining_stake + accumulated_ok_stake < threshold).
    pub abort_on_impossible: bool,
}

impl Default for AggregationPolicy {
    fn default() -> Self {
        Self {
            per_authority_timeout: Duration::from_secs(5),
            total_timeout: Duration::from_secs(30),
            max_concurrent: usize::MAX,
            retry: RetryPolicy::None,
            abort_on_impossible: true,
        }
    }
}

/// Retry policy for individual authority failures.
#[derive(Debug, Clone)]
pub enum RetryPolicy {
    /// No retries.
    None,
    /// Retry up to `max_retries` times with `delay` between attempts.
    Fixed { max_retries: u32, delay: Duration },
}
