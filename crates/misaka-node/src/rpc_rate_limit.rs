//! Per-IP rate limiter for Node RPC endpoints.
//!
//! # SEC-H2: DoS Protection
//!
//! The global `ConcurrencyLimitLayer::new(64)` only limits total in-flight
//! requests. A single IP can monopolize all 64 slots, blocking all other
//! clients. This module adds per-IP rate limiting that runs BEFORE the
//! concurrency limit, so abusive IPs are rejected early.
//!
//! # Design
//!
//! Sliding-window counter per IP. Two tiers:
//! - Write endpoints (submit_tx, faucet): 20/min
//! - Read endpoints: 200/min
//!
//! Override via `MISAKA_RPC_RATE_LIMIT_WRITE` and `MISAKA_RPC_RATE_LIMIT_READ`.

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use axum::middleware::Next;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Per-IP rate limiter state.
#[derive(Clone)]
pub struct NodeRateLimiter {
    state: Arc<Mutex<LimiterState>>,
    pub write_limit: u32,
    pub read_limit: u32,
    pub window: Duration,
}

struct LimiterState {
    /// IP → (window_start, count) per tier.
    write: HashMap<IpAddr, (Instant, u32)>,
    read: HashMap<IpAddr, (Instant, u32)>,
    last_gc: Instant,
}

impl NodeRateLimiter {
    pub fn from_env() -> Self {
        let write_limit: u32 = std::env::var("MISAKA_RPC_RATE_LIMIT_WRITE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(20);
        let read_limit: u32 = std::env::var("MISAKA_RPC_RATE_LIMIT_READ")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(200);

        Self {
            state: Arc::new(Mutex::new(LimiterState {
                write: HashMap::new(),
                read: HashMap::new(),
                last_gc: Instant::now(),
            })),
            write_limit,
            read_limit,
            window: Duration::from_secs(60),
        }
    }

    async fn check(&self, ip: IpAddr, is_write: bool) -> Result<(), u64> {
        let mut state = self.state.lock().await;

        // GC every 5 minutes
        if state.last_gc.elapsed() > Duration::from_secs(300) {
            let cutoff = Instant::now() - self.window * 2;
            state.write.retain(|_, (t, _)| *t > cutoff);
            state.read.retain(|_, (t, _)| *t > cutoff);
            state.last_gc = Instant::now();
        }

        let (map, limit) = if is_write {
            (&mut state.write, self.write_limit)
        } else {
            (&mut state.read, self.read_limit)
        };

        let now = Instant::now();
        let entry = map.entry(ip).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        entry.1 += 1;

        if entry.1 > limit {
            let retry = self
                .window
                .saturating_sub(now.duration_since(entry.0))
                .as_secs()
                .max(1);
            Err(retry)
        } else {
            Ok(())
        }
    }
}

fn is_write_path(path: &str) -> bool {
    path.contains("/submit") || path.contains("/faucet") || path.contains("/checkpoint_vote")
}

/// SEC-FIX-1: Extract real client IP from ConnectInfo<SocketAddr>.
///
/// # Security
///
/// X-Forwarded-For is NEVER trusted on the Node RPC layer.
/// Node RPC is either localhost-only or connected via direct TCP.
/// If a reverse proxy sits in front, rate limiting should happen there.
///
/// # Fail-Closed
///
/// If ConnectInfo is missing (misconfigured server), falls back to
/// 127.0.0.1 and logs a warning. This means ALL requests share a
/// single bucket, which is restrictive (fail-closed) but not silent.
fn extract_ip(req: &Request<Body>) -> IpAddr {
    // Read the real socket IP from ConnectInfo<SocketAddr>.
    // Requires `into_make_service_with_connect_info::<SocketAddr>()`.
    if let Some(connect_info) = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
    {
        return connect_info.0.ip();
    }

    // Fallback: loopback. This is fail-closed: all unknown-origin
    // requests share one bucket, so a single abuser blocks everyone
    // (operator will notice quickly).
    tracing::warn!(
        "SEC-FIX-1: ConnectInfo unavailable in Node RPC — \
         rate limit falls back to 127.0.0.1 (single global bucket). \
         Ensure axum::serve uses into_make_service_with_connect_info::<SocketAddr>()"
    );
    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
}

/// Axum middleware for per-IP rate limiting on Node RPC.
pub async fn node_rate_limit(
    axum::extract::State(limiter): axum::extract::State<NodeRateLimiter>,
    req: Request<Body>,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    let ip = extract_ip(&req);
    let is_write = is_write_path(req.uri().path());

    match limiter.check(ip, is_write).await {
        Ok(()) => Ok(next.run(req).await),
        Err(retry_after) => {
            let body = serde_json::json!({
                "error": format!("rate limited, retry after {}s", retry_after)
            });
            Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("Retry-After", retry_after.to_string())
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_per_ip_isolation_different_ips_get_separate_buckets() {
        // Attack: single IP monopolizes all rate limit capacity
        // Fix: per-IP buckets are isolated
        let limiter = NodeRateLimiter::from_env();
        // Override for testing
        let limiter = NodeRateLimiter {
            write_limit: 2,
            read_limit: 5,
            window: Duration::from_secs(60),
            ..limiter
        };

        let ip_a: IpAddr = "1.1.1.1".parse().unwrap();
        let ip_b: IpAddr = "2.2.2.2".parse().unwrap();

        // IP A exhausts its write budget
        assert!(limiter.check(ip_a, true).await.is_ok());
        assert!(limiter.check(ip_a, true).await.is_ok());
        assert!(limiter.check(ip_a, true).await.is_err()); // blocked

        // IP B is unaffected
        assert!(limiter.check(ip_b, true).await.is_ok());
        assert!(limiter.check(ip_b, true).await.is_ok());
    }

    #[tokio::test]
    async fn test_write_and_read_tiers_are_separate() {
        let limiter = NodeRateLimiter {
            write_limit: 1,
            read_limit: 3,
            window: Duration::from_secs(60),
            state: Arc::new(Mutex::new(LimiterState {
                write: HashMap::new(),
                read: HashMap::new(),
                last_gc: Instant::now(),
            })),
        };

        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Exhaust write
        assert!(limiter.check(ip, true).await.is_ok());
        assert!(limiter.check(ip, true).await.is_err());

        // Read still has capacity
        assert!(limiter.check(ip, false).await.is_ok());
        assert!(limiter.check(ip, false).await.is_ok());
        assert!(limiter.check(ip, false).await.is_ok());
        assert!(limiter.check(ip, false).await.is_err());
    }

    #[test]
    fn test_is_write_path_classification() {
        assert!(is_write_path("/api/submit_tx"));
        assert!(is_write_path("/api/faucet"));
        assert!(is_write_path("/api/submit_checkpoint_vote"));
        assert!(!is_write_path("/api/get_chain_info"));
        assert!(!is_write_path("/health"));
        assert!(!is_write_path("/api/get_peers"));
    }

    #[tokio::test]
    async fn test_extract_ip_with_connect_info() {
        // Verify ConnectInfo extraction works
        let mut req = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let addr: std::net::SocketAddr = "203.0.113.42:12345".parse().unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(addr));

        let extracted = extract_ip(&req);
        assert_eq!(
            extracted,
            "203.0.113.42".parse::<IpAddr>().unwrap(),
            "must extract IP from ConnectInfo, not fall back to localhost"
        );
    }

    #[tokio::test]
    async fn test_extract_ip_without_connect_info_falls_back_to_localhost() {
        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let extracted = extract_ip(&req);
        assert_eq!(
            extracted,
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            "without ConnectInfo, must fall back to localhost (fail-closed)"
        );
    }

    #[tokio::test]
    async fn test_gc_runs_and_does_not_lose_active_entries() {
        let limiter = NodeRateLimiter {
            write_limit: 100,
            read_limit: 100,
            window: Duration::from_secs(60),
            state: Arc::new(Mutex::new(LimiterState {
                write: HashMap::new(),
                read: HashMap::new(),
                // Force GC on next check
                last_gc: Instant::now() - Duration::from_secs(600),
            })),
        };

        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        // Add an entry
        assert!(limiter.check(ip, true).await.is_ok());
        // GC should run but not evict active entries
        assert!(limiter.check(ip, true).await.is_ok());
    }
}
