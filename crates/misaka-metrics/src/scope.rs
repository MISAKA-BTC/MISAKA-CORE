// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
// Sui equivalent: mysten-metrics/src/monitored_scope.rs
//
//! `monitored_scope!()` — automatic scope latency measurement.
//!
//! Measures wall-clock duration of a code block and records it as a
//! prometheus Histogram observation. Also emits a tracing span.
//!
//! # Usage
//!
//! ```ignore
//! let _guard = monitored_scope("process_block");
//! // ... expensive work ...
//! // guard drops here → latency recorded
//! ```

use std::time::Instant;
use prometheus::Histogram;

/// Guard that records scope duration on drop.
pub struct ScopeGuard {
    histogram: Histogram,
    start: Instant,
    #[allow(dead_code)]
    name: &'static str,
}

impl Drop for ScopeGuard {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed().as_secs_f64();
        self.histogram.observe(elapsed);
    }
}

/// Create a scope guard that measures duration.
///
/// Returns a guard that records the elapsed time to the given histogram
/// when it goes out of scope.
#[must_use]
pub fn monitored_scope(name: &'static str, histogram: Histogram) -> ScopeGuard {
    ScopeGuard {
        histogram,
        start: Instant::now(),
        name,
    }
}

/// Convenience macro for monitored scope with tracing span.
///
/// ```ignore
/// let _guard = misaka_metrics::scope!("verify_block", VERIFY_LATENCY);
/// ```
#[macro_export]
macro_rules! scope {
    ($name:expr, $histogram:expr) => {
        let _span = tracing::debug_span!($name).entered();
        let _guard = $crate::scope::monitored_scope($name, $histogram.clone());
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::register_histogram;

    #[test]
    fn test_scope_guard_records() {
        let hist = register_histogram(
            "scope_test_seconds",
            "test scope",
            vec![0.001, 0.01, 0.1],
        );
        {
            let _guard = monitored_scope("test", hist.clone());
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        // Histogram should have exactly 1 sample
        assert_eq!(hist.get_sample_count(), 1);
        assert!(hist.get_sample_sum() >= 0.004); // at least 4ms
    }
}
