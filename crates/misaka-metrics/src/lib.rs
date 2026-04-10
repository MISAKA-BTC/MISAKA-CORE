// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! `misaka-metrics` — SLO-driven prometheus metrics infrastructure.
//!
//! Sui equivalent: `crates/mysten-metrics/`
//!
//! Provides:
//! - Global prometheus `Registry` (one per process)
//! - Helper macros for registering counters, gauges, histograms
//! - `monitored_scope!()` for automatic latency measurement
//! - `MetricsProvider` trait for subsystem registration
//! - `/metrics` endpoint text encoder
//!
//! All 24 SLO metrics defined in `docs/ops/SLO.md` are registered
//! through this crate. No metric is registered outside this pattern.

pub mod registry;
pub mod scope;

pub use prometheus::{
    self, Encoder, TextEncoder,
    Histogram, HistogramOpts, HistogramVec,
    IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
    Opts,
};
pub use registry::{global_registry, register_counter, register_gauge, register_histogram};
pub use scope::monitored_scope;
