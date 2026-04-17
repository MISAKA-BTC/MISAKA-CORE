// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! `QuorumReducer` trait — user-defined logic for reducing authority responses.

use crate::committee::{AuthorityIndex, StakeWeight};
use crate::error::AuthorityError;

/// Action returned by the reducer after processing each authority response.
#[derive(Debug)]
pub enum ReduceAction<Output> {
    /// Continue collecting responses. No quorum yet.
    Continue,
    /// Quorum reached. Stop collecting, drop pending futures.
    EarlyReturn(Output),
    /// Reject this authority's response. Its stake is NOT counted toward quorum.
    Reject,
}

/// Trait for reducing authority responses into a quorum decision.
///
/// The aggregator calls `reduce` for each arriving response. The reducer
/// maintains internal state (accumulated data, stake sums, etc.) and
/// returns a [`ReduceAction`] to tell the aggregator what to do next.
pub trait QuorumReducer<Resp, Output>: Send
where
    Resp: Send + 'static,
    Output: Send + 'static,
{
    /// Process a successful response from `authority` with `stake` weight.
    ///
    /// Called in arrival order — the reducer must be deterministic given
    /// the same sequence, but the sequence itself may vary across runs.
    fn reduce(
        &mut self,
        authority: AuthorityIndex,
        stake: StakeWeight,
        response: Resp,
    ) -> ReduceAction<Output>;

    /// Process a failed request to `authority`.
    ///
    /// Default: ignore the failure (authority simply doesn't contribute).
    /// Override to implement byzantine fault tracking.
    fn reduce_error(
        &mut self,
        _authority: AuthorityIndex,
        _stake: StakeWeight,
        _error: &AuthorityError,
    ) -> ReduceAction<Output> {
        ReduceAction::Continue
    }

    /// Called when all authorities have responded without any `EarlyReturn`.
    /// Returns the best-effort output or `None`.
    fn finalize(self) -> Option<Output>;
}
