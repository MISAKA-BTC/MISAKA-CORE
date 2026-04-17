// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! `QuorumAggregator` — parallel fan-out, first-arriving reduce, quorum-stop.
//!
//! Sends a request to all authorities in the committee concurrently,
//! reduces responses as they arrive, and stops as soon as the reducer
//! signals quorum (EarlyReturn) or when quorum becomes impossible.

use std::sync::Arc;
use std::time::Instant;

use tokio::task::JoinSet;
use tracing::{debug, warn};

use crate::client::AuthorityClient;
use crate::committee::{AuthorityIndex, StakeCommittee, StakeWeight};
use crate::error::{AuthorityError, QuorumError};
use crate::policy::AggregationPolicy;
use crate::reducer::{QuorumReducer, ReduceAction};

/// Result of a quorum aggregation.
#[derive(Debug)]
pub struct AggregationResult<Output> {
    /// The aggregated output (if quorum reached or finalize succeeded).
    pub output: Option<Output>,
    /// Per-authority errors encountered.
    pub errors: Vec<(AuthorityIndex, AuthorityError)>,
    /// Number of successful responses received.
    pub success_count: usize,
    /// Number of failed/rejected responses.
    pub fail_count: usize,
    /// Total elapsed time.
    pub elapsed: std::time::Duration,
}

/// Generic quorum aggregator.
///
/// Uses `tokio::task::JoinSet` for concurrent fan-out — no `futures` crate needed.
pub struct QuorumAggregator;

impl QuorumAggregator {
    /// Run quorum aggregation.
    ///
    /// Sends `request` to all authorities via `client`, collects responses
    /// as they arrive, and reduces via `reducer`. Stops on:
    /// - `EarlyReturn` from reducer (quorum reached)
    /// - `QuorumImpossible` (remaining + accumulated < threshold)
    /// - `total_timeout` exceeded
    /// - All authorities responded
    pub async fn aggregate<C, Req, Resp, Output, R, A>(
        committee: &C,
        client: Arc<A>,
        request: Req,
        mut reducer: R,
        policy: &AggregationPolicy,
    ) -> Result<AggregationResult<Output>, QuorumError>
    where
        C: StakeCommittee,
        Req: Clone + Send + Sync + 'static,
        Resp: Send + 'static,
        Output: Send + 'static,
        R: QuorumReducer<Resp, Output>,
        A: AuthorityClient<Req, Resp> + 'static,
    {
        let n = committee.size();
        if n == 0 {
            return Err(QuorumError::EmptyCommittee);
        }

        let start = Instant::now();
        let threshold = committee.quorum_threshold();
        let total_timeout = policy.total_timeout;
        let per_timeout = policy.per_authority_timeout;

        let mut errors: Vec<(AuthorityIndex, AuthorityError)> = Vec::new();
        let mut success_count: usize = 0;
        let mut fail_count: usize = 0;
        let mut accumulated_ok_stake: StakeWeight = 0;
        let mut remaining_stake: StakeWeight = committee.total_stake();

        // Build stake lookup
        let stakes: Vec<(AuthorityIndex, StakeWeight)> = committee
            .authority_indices()
            .map(|idx| (idx, committee.stake(idx)))
            .collect();

        // Spawn per-authority requests into JoinSet.
        let mut join_set: JoinSet<(AuthorityIndex, StakeWeight, Result<Resp, AuthorityError>)> =
            JoinSet::new();

        for &(authority, stake) in &stakes {
            let client = Arc::clone(&client);
            let req = request.clone();
            let timeout_dur = per_timeout;

            join_set.spawn(async move {
                let result = tokio::time::timeout(timeout_dur, client.request(authority, req))
                    .await
                    .unwrap_or_else(|_| {
                        Err(AuthorityError::Timeout {
                            authority,
                            timeout_ms: timeout_dur.as_millis() as u64,
                        })
                    });
                (authority, stake, result)
            });
        }

        // Process results as they arrive, with total timeout.
        let deadline = tokio::time::Instant::now() + total_timeout;

        loop {
            tokio::select! {
                result = join_set.join_next() => {
                    match result {
                        None => {
                            // All tasks completed — no EarlyReturn was triggered.
                            break;
                        }
                        Some(Ok((authority, stake, Ok(resp)))) => {
                            remaining_stake = remaining_stake.saturating_sub(stake);
                            success_count += 1;
                            debug!(authority, stake, "authority responded OK");

                            match reducer.reduce(authority, stake, resp) {
                                ReduceAction::EarlyReturn(output) => {
                                    // Quorum reached — abort remaining tasks.
                                    join_set.shutdown().await;
                                    return Ok(AggregationResult {
                                        output: Some(output),
                                        errors,
                                        success_count,
                                        fail_count,
                                        elapsed: start.elapsed(),
                                    });
                                }
                                ReduceAction::Continue => {
                                    accumulated_ok_stake =
                                        accumulated_ok_stake.saturating_add(stake);
                                }
                                ReduceAction::Reject => {
                                    fail_count += 1;
                                    // Stake NOT added to accumulated.
                                }
                            }
                        }
                        Some(Ok((authority, stake, Err(err)))) => {
                            remaining_stake = remaining_stake.saturating_sub(stake);
                            fail_count += 1;
                            debug!(authority, %err, "authority request failed");

                            match reducer.reduce_error(authority, stake, &err) {
                                ReduceAction::EarlyReturn(output) => {
                                    join_set.shutdown().await;
                                    return Ok(AggregationResult {
                                        output: Some(output),
                                        errors,
                                        success_count,
                                        fail_count,
                                        elapsed: start.elapsed(),
                                    });
                                }
                                ReduceAction::Continue | ReduceAction::Reject => {}
                            }

                            errors.push((authority, err));
                        }
                        Some(Err(join_err)) => {
                            // Task panicked — should not happen in production.
                            warn!("JoinSet task panicked: {join_err}");
                            fail_count += 1;
                        }
                    }

                    // Check if quorum is still possible.
                    if policy.abort_on_impossible
                        && remaining_stake.saturating_add(accumulated_ok_stake) < threshold
                    {
                        join_set.shutdown().await;
                        return Err(QuorumError::QuorumImpossible {
                            remaining_stake,
                            accumulated_stake: accumulated_ok_stake,
                            threshold,
                        });
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    // Total timeout — abort remaining.
                    join_set.shutdown().await;
                    return Err(QuorumError::TotalTimeout {
                        elapsed_ms: start.elapsed().as_millis() as u64,
                        responses_received: success_count,
                    });
                }
            }
        }

        // All authorities responded — no EarlyReturn triggered.
        let output = reducer.finalize();
        if output.is_none() && success_count == 0 {
            return Err(QuorumError::AllFailed);
        }
        Ok(AggregationResult {
            output,
            errors,
            success_count,
            fail_count,
            elapsed: start.elapsed(),
        })
    }
}
