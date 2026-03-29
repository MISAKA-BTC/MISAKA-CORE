//! Periodic tick utilities for background tasks.

use std::time::Duration;
use tokio::time::{interval, MissedTickBehavior};

/// Run a closure at fixed intervals until shutdown.
pub async fn tick_loop<F, Fut>(period: Duration, mut shutdown: crate::lifecycle::ShutdownSignal, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mut ticker = interval(period);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = ticker.tick() => { f().await; }
            _ = shutdown.wait() => { break; }
        }
    }
}

/// Stopwatch for measuring elapsed time.
pub struct Stopwatch {
    start: std::time::Instant,
    label: String,
}

impl Stopwatch {
    pub fn start(label: impl Into<String>) -> Self {
        Self { start: std::time::Instant::now(), label: label.into() }
    }

    pub fn elapsed_ms(&self) -> f64 {
        self.start.elapsed().as_secs_f64() * 1000.0
    }

    pub fn log_if_slow(&self, threshold_ms: f64) {
        let elapsed = self.elapsed_ms();
        if elapsed > threshold_ms {
            tracing::warn!("{} took {:.1}ms (threshold: {:.1}ms)", self.label, elapsed, threshold_ms);
        }
    }
}

impl Drop for Stopwatch {
    fn drop(&mut self) {
        tracing::trace!("{}: {:.2}ms", self.label, self.elapsed_ms());
    }
}
