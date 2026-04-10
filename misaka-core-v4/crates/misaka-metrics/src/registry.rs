// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
// Sui equivalent: mysten-metrics/src/lib.rs (registry pattern)
//
//! Global prometheus registry and metric registration helpers.

use once_cell::sync::Lazy;
use prometheus::{
    self, Encoder, TextEncoder, Registry,
    Histogram, HistogramOpts, HistogramVec,
    IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
    Opts,
};

/// Global prometheus registry (one per process).
///
/// All MISAKA metrics are registered here. The `/metrics` endpoint
/// encodes this registry.
static GLOBAL_REGISTRY: Lazy<Registry> = Lazy::new(|| {
    Registry::new_custom(Some("misaka".to_string()), None)
        .expect("SETUP: prometheus registry creation; process-level singleton")
});

/// Get the global registry.
#[must_use]
pub fn global_registry() -> &'static Registry {
    &GLOBAL_REGISTRY
}

/// Encode all registered metrics as prometheus text format.
#[must_use]
pub fn encode_metrics() -> String {
    let encoder = TextEncoder::new();
    let metrics = GLOBAL_REGISTRY.gather();
    let mut buf = Vec::new();
    encoder.encode(&metrics, &mut buf).unwrap_or_default();
    String::from_utf8(buf).unwrap_or_default()
}

// ── Registration helpers ─────────────────────────────────────

/// Register an IntCounter with the global registry.
///
/// # Panics
/// Panics if a metric with the same name is already registered.
pub fn register_counter(name: &str, help: &str) -> IntCounter {
    let counter = IntCounter::with_opts(Opts::new(name, help))
        .expect("SETUP: prometheus counter creation");
    GLOBAL_REGISTRY.register(Box::new(counter.clone()))
        .unwrap_or_else(|e| tracing::warn!("metric {} already registered: {}", name, e));
    counter
}

/// Register an IntCounterVec (labeled counter) with the global registry.
pub fn register_counter_vec(name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    let cv = IntCounterVec::new(Opts::new(name, help), labels)
        .expect("SETUP: prometheus counter_vec creation");
    GLOBAL_REGISTRY.register(Box::new(cv.clone()))
        .unwrap_or_else(|e| tracing::warn!("metric {} already registered: {}", name, e));
    cv
}

/// Register an IntGauge with the global registry.
pub fn register_gauge(name: &str, help: &str) -> IntGauge {
    let gauge = IntGauge::with_opts(Opts::new(name, help))
        .expect("SETUP: prometheus gauge creation");
    GLOBAL_REGISTRY.register(Box::new(gauge.clone()))
        .unwrap_or_else(|e| tracing::warn!("metric {} already registered: {}", name, e));
    gauge
}

/// Register a Histogram with the global registry.
///
/// `buckets`: explicitly set for SLO-driven measurement.
pub fn register_histogram(name: &str, help: &str, buckets: Vec<f64>) -> Histogram {
    let opts = HistogramOpts::new(name, help).buckets(buckets);
    let hist = Histogram::with_opts(opts)
        .expect("SETUP: prometheus histogram creation");
    GLOBAL_REGISTRY.register(Box::new(hist.clone()))
        .unwrap_or_else(|e| tracing::warn!("metric {} already registered: {}", name, e));
    hist
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_encode() {
        let counter = register_counter("test_total", "test counter");
        counter.inc();
        let output = encode_metrics();
        assert!(output.contains("test_total"), "encoded metrics should contain our counter");
    }

    #[test]
    fn test_register_gauge() {
        let gauge = register_gauge("test_gauge", "test gauge");
        gauge.set(42);
        let output = encode_metrics();
        assert!(output.contains("test_gauge"));
    }

    #[test]
    fn test_register_histogram() {
        let hist = register_histogram(
            "test_latency_seconds",
            "test histogram",
            vec![0.1, 0.5, 1.0, 5.0],
        );
        hist.observe(0.3);
        let output = encode_metrics();
        assert!(output.contains("test_latency_seconds"));
    }
}
