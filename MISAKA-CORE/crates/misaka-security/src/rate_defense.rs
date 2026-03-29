//! Rate-based defense mechanisms against DoS attacks.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use parking_lot::Mutex;

/// Adaptive rate defense that adjusts thresholds based on load.
pub struct AdaptiveDefense {
    baseline_rps: f64,
    current_threshold: f64,
    load_history: Mutex<Vec<(Instant, f64)>>,
    max_amplification: f64,
}

impl AdaptiveDefense {
    pub fn new(baseline_rps: f64) -> Self {
        Self {
            baseline_rps,
            current_threshold: baseline_rps,
            load_history: Mutex::new(Vec::new()),
            max_amplification: 5.0,
        }
    }

    pub fn record_load(&self, load: f64) {
        let mut history = self.load_history.lock();
        history.push((Instant::now(), load));
        // Keep last 100 samples
        if history.len() > 100 { history.remove(0); }
    }

    pub fn current_threshold(&self) -> f64 { self.current_threshold }
    pub fn is_under_attack(&self) -> bool {
        let history = self.load_history.lock();
        let recent: Vec<f64> = history.iter()
            .filter(|(t, _)| t.elapsed() < Duration::from_secs(60))
            .map(|(_, l)| *l)
            .collect();
        if recent.is_empty() { return false; }
        let avg: f64 = recent.iter().sum::<f64>() / recent.len() as f64;
        avg > self.baseline_rps * self.max_amplification
    }
}

/// Connection flood detector.
pub struct FloodDetector {
    connection_times: Mutex<HashMap<String, Vec<Instant>>>,
    threshold_per_minute: usize,
}

impl FloodDetector {
    pub fn new(threshold: usize) -> Self {
        Self {
            connection_times: Mutex::new(HashMap::new()),
            threshold_per_minute: threshold,
        }
    }

    pub fn record_connection(&self, source: &str) -> bool {
        let mut times = self.connection_times.lock();
        let entry = times.entry(source.to_string()).or_default();
        let cutoff = Instant::now() - Duration::from_secs(60);
        entry.retain(|t| *t > cutoff);
        entry.push(Instant::now());
        entry.len() <= self.threshold_per_minute
    }

    pub fn is_flooding(&self, source: &str) -> bool {
        let times = self.connection_times.lock();
        times.get(source).map_or(false, |t| {
            let cutoff = Instant::now() - Duration::from_secs(60);
            t.iter().filter(|&&t| t > cutoff).count() > self.threshold_per_minute
        })
    }
}
