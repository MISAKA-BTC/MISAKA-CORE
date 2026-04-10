//! Tower-compatible middleware for RPC rate limiting.

/// Simple rate-limit layer that wraps tower services.
pub struct RateLimitLayer {
    max_requests_per_second: f64,
}

impl RateLimitLayer {
    pub fn new(max_rps: f64) -> Self {
        Self {
            max_requests_per_second: max_rps,
        }
    }
    pub fn max_rps(&self) -> f64 {
        self.max_requests_per_second
    }
}

/// Concurrency limiter for controlling parallel request processing.
pub struct ConcurrencyLimiter {
    permits: std::sync::Arc<tokio::sync::Semaphore>,
}

impl ConcurrencyLimiter {
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            permits: std::sync::Arc::new(tokio::sync::Semaphore::new(max_concurrent)),
        }
    }

    pub async fn acquire(&self) -> tokio::sync::OwnedSemaphorePermit {
        self.permits
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore closed")
    }

    pub fn try_acquire(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.permits.clone().try_acquire_owned().ok()
    }

    pub fn available_permits(&self) -> usize {
        self.permits.available_permits()
    }
}
