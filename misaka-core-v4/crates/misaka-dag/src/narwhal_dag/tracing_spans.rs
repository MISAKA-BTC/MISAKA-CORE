// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Tracing span definitions for structured observability.
//!
//! Two span trees exist:
//!
//! ## Span Tree 1: Block Lifetime
//! ```text
//! block_received(block_ref, round, author)
//! ├─ signature_verify (ML-DSA-65, pk_len, sig_len)
//! ├─ dag_accept (result, equivocation)
//! ├─ commit_eligibility (decision, leader_round)
//! └─ finalize (commit_index, is_direct)
//! ```
//!
//! ## Span Tree 2: Commit Pipeline
//! ```text
//! commit_cycle(round)
//! ├─ try_commit (decisions_count)
//! ├─ linearize (commit_index, tx_count)
//! ├─ certify (certified_count, rejected_count)
//! └─ round_advance (new_round)
//! ```
//!
//! Spans attach to the real processing boundaries in core_engine.rs.
//! They are NOT decorative — each span corresponds to a measurable
//! phase with its own latency and failure mode.

/// Create a block processing span.
///
/// Attach at `CoreEngine::process_block()` entry.
#[macro_export]
macro_rules! span_block_received {
    ($round:expr, $author:expr, $digest:expr) => {
        tracing::info_span!(
            "block_received",
            round = $round,
            author = $author,
            digest = %hex::encode(&$digest[..4]),
        )
    };
}

/// Create a signature verification sub-span.
#[macro_export]
macro_rules! span_sig_verify {
    ($round:expr, $author:expr) => {
        tracing::debug_span!(
            "signature_verify",
            round = $round,
            author = $author,
            scheme = "ML-DSA-65",
        )
    };
}

/// Create a DAG accept sub-span.
#[macro_export]
macro_rules! span_dag_accept {
    ($round:expr, $author:expr) => {
        tracing::debug_span!("dag_accept", round = $round, author = $author,)
    };
}

/// Create a commit cycle span.
///
/// Attach at the beginning of the commit attempt in `process_block`.
#[macro_export]
macro_rules! span_commit_cycle {
    ($round:expr) => {
        tracing::info_span!("commit_cycle", round = $round,)
    };
}

/// Create a linearization sub-span.
#[macro_export]
macro_rules! span_linearize {
    ($commit_index:expr) => {
        tracing::debug_span!("linearize", commit_index = $commit_index,)
    };
}
