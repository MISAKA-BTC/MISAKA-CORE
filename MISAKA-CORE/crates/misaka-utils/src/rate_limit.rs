//! Token-bucket and sliding-window rate limiters.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use parking_lot::Mutex;

/// Token bucket rate limiter.
pub struct TokenBucket {
    capacity: u64,
    tokens: AtomicU64,
    refill_rate: f64,
    last_refill: Mutex<Instant>,
}

impl TokenBucket {
    pub fn new(capacity: u64, refill_per_second: f64) -> Self {
        Self {
            capacity,
            tokens: AtomicU64::new(capacity),
            refill_rate: refill_per_second,
            last_refill: Mutex::new(Instant::now()),
        }
    }

    pub fn try_consume(&self, n: u64) -> bool {
        self.refill();
        loop {
            let current = self.tokens.load(Ordering::Relaxed);
            if current < n { return false; }
            if self.tokens.compare_exchange(current, current - n, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                return true;
            }
        }
    }

    pub fn available(&self) -> u64 {
        self.refill();
        self.tokens.load(Ordering::Relaxed)
    }

    fn refill(&self) {
        let mut last = self.last_refill.lock();
        let now = Instant::now();
        let elapsed = now.duration_since(*last).as_secs_f64();
        let new_tokens = (elapsed * self.refill_rate) as u64;
        if new_tokens > 0 {
            let current = self.tokens.load(Ordering::Relaxed);
            let refilled = current.saturating_add(new_tokens).min(self.capacity);
            self.tokens.store(refilled, Ordering::Relaxed);
            *last = now;
        }
    }
}

/// Per-IP sliding window rate limiter.
pub struct SlidingWindowLimiter {
    window_size: Duration,
    max_requests: u64,
    windows: Mutex<HashMap<IpAddr, Vec<Instant>>>,
}

impl SlidingWindowLimiter {
    pub fn new(window: Duration, max_requests: u64) -> Self {
        Self {
            window_size: window,
            max_requests,
            windows: Mutex::new(HashMap::new()),
        }
    }

    pub fn check(&self, addr: &IpAddr) -> bool {
        let mut windows = self.windows.lock();
        let now = Instant::now();
        let cutoff = now - self.window_size;
        let entry = windows.entry(*addr).or_insert_with(Vec::new);
        entry.retain(|t| *t > cutoff);
        if entry.len() as u64 >= self.max_requests {
            false
        } else {
            entry.push(now);
            true
        }
    }

    pub fn cleanup(&self) {
        let mut windows = self.windows.lock();
        let cutoff = Instant::now() - self.window_size;
        windows.retain(|_, v| {
            v.retain(|t| *t > cutoff);
            !v.is_empty()
        });
    }

    pub fn tracked_count(&self) -> usize {
        self.windows.lock().len()
    }
}

/// Adaptive rate limiter that adjusts based on system load.
pub struct AdaptiveRateLimiter {
    base_rate: f64,
    current_rate: AtomicU64, // stored as f64 bits
    bucket: TokenBucket,
    load_threshold_high: f64,
    load_threshold_low: f64,
}

impl AdaptiveRateLimiter {
    pub fn new(base_rate: f64, capacity: u64) -> Self {
        Self {
            base_rate,
            current_rate: AtomicU64::new(base_rate.to_bits()),
            bucket: TokenBucket::new(capacity, base_rate),
            load_threshold_high: 0.8,
            load_threshold_low: 0.3,
        }
    }

    pub fn try_consume(&self) -> bool {
        self.bucket.try_consume(1)
    }

    pub fn update_load(&self, load_factor: f64) {
        let new_rate = if load_factor > self.load_threshold_high {
            self.base_rate * 0.5
        } else if load_factor < self.load_threshold_low {
            self.base_rate * 1.5
        } else {
            self.base_rate
        };
        self.current_rate.store(new_rate.to_bits(), Ordering::Relaxed);
    }

    pub fn current_rate(&self) -> f64 {
        f64::from_bits(self.current_rate.load(Ordering::Relaxed))
    }
}

/// Connection rate limiter for P2P handshakes.
pub struct ConnectionRateLimiter {
    global_bucket: TokenBucket,
    per_ip: SlidingWindowLimiter,
}

impl ConnectionRateLimiter {
    pub fn new(global_per_sec: f64, per_ip_per_minute: u64) -> Self {
        Self {
            global_bucket: TokenBucket::new(
                (global_per_sec * 10.0) as u64,
                global_per_sec,
            ),
            per_ip: SlidingWindowLimiter::new(
                Duration::from_secs(60),
                per_ip_per_minute,
            ),
        }
    }

    pub fn check(&self, addr: &IpAddr) -> RateLimitResult {
        if !self.global_bucket.try_consume(1) {
            return RateLimitResult::GlobalLimited;
        }
        if !self.per_ip.check(addr) {
            return RateLimitResult::PerIpLimited;
        }
        RateLimitResult::Allowed
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitResult {
    Allowed,
    GlobalLimited,
    PerIpLimited,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket() {
        let bucket = TokenBucket::new(10, 100.0);
        for _ in 0..10 {
            assert!(bucket.try_consume(1));
        }
        assert!(!bucket.try_consume(1));
    }

    #[test]
    fn test_sliding_window() {
        let limiter = SlidingWindowLimiter::new(Duration::from_secs(60), 3);
        let addr: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(limiter.check(&addr));
        assert!(limiter.check(&addr));
        assert!(limiter.check(&addr));
        assert!(!limiter.check(&addr));
    }
}
