//! API Middleware — rate limiting, idempotency, timeouts.
//!
//! # Rate Limiting
//!
//! Two-tier IP-based rate limiter:
//! - **General** endpoints: 100 requests/minute per IP.
//! - **Sensitive** endpoints (faucet, submit_tx): 10 requests/minute per IP.
//!
//! Uses a sliding-window counter backed by an in-memory `HashMap`.
//!
//! ## SEC-FIX-8: Multi-Instance Limitations
//!
//! **WARNING**: This in-memory rate limiter has known limitations:
//! - **Multi-process**: If multiple API instances run behind a load balancer,
//!   each has its own bucket map. An attacker can spread requests across
//!   instances to exceed the intended limit.
//! - **Restart**: All counters reset on process restart. A bot can detect
//!   restarts and exploit the clean slate.
//! - **No tarpit**: Rate-limited clients receive an immediate 429, making
//!   it easy to retry at the exact window boundary.
//!
//! For mainnet public API, replace with Redis-backed rate limiting:
//! - Shared store (Redis INCR + EXPIRE)
//! - Key schema: `rl:{ip}:{path}:{method}`
//! - Two-tier: burst (10/sec) + sustained (100/min)
//! - Consider tarpit (artificial delay) before 429
//!
//! # Idempotency
//!
//! `POST /v1/tx/submit` accepts an `X-Idempotency-Key` header.
//! If the same key is seen within a configurable TTL, the cached
//! response is returned without re-processing (prevents double-broadcast).
//!
//! # Timeouts
//!
//! All upstream RPC calls are wrapped with a configurable timeout
//! (default 5s). Prevents the API thread pool from hanging if the
//! node is unresponsive.

use axum::body::Body;
use axum::http::HeaderValue;
use axum::http::{Request, Response, StatusCode};
use axum::middleware::Next;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

// ═══════════════════════════════════════════════════════════════
//  Rate Limiter Backend Trait (SEC-FIX-3)
// ═══════════════════════════════════════════════════════════════

/// Backend trait for rate limiting storage.
///
/// # SEC-FIX-3: Shared Backend Abstraction
///
/// The in-memory rate limiter has known limitations (see module docs).
/// This trait allows swapping the storage backend without touching the
/// middleware layer. Implementations:
///
/// - `InMemoryBackend` (current): single-process, reset on restart.
/// - Future `RedisBackend`: shared across instances, persistent counters.
///
/// Key schema: `rl:{ip}:{tier}` with INCR + EXPIRE semantics.
#[async_trait::async_trait]
pub trait RateLimiterBackend: Send + Sync + 'static {
    /// Increment the counter for (ip, tier). Returns Ok(remaining) or Err(retry_after_secs).
    async fn check_and_increment(
        &self,
        ip: IpAddr,
        tier: RateTier,
        limit: u32,
        window: Duration,
    ) -> Result<u32, u64>;
}

/// In-memory rate limiter backend (single-process).
struct InMemoryBackend {
    state: Mutex<RateLimiterState>,
}

struct RateLimiterState {
    general: HashMap<IpAddr, (Instant, u32)>,
    sensitive: HashMap<IpAddr, (Instant, u32)>,
    last_cleanup: Instant,
}

impl InMemoryBackend {
    fn new() -> Self {
        Self {
            state: Mutex::new(RateLimiterState {
                general: HashMap::new(),
                sensitive: HashMap::new(),
                last_cleanup: Instant::now(),
            }),
        }
    }
}

#[async_trait::async_trait]
impl RateLimiterBackend for InMemoryBackend {
    async fn check_and_increment(
        &self,
        ip: IpAddr,
        tier: RateTier,
        limit: u32,
        window: Duration,
    ) -> Result<u32, u64> {
        let mut state = self.state.lock().await;

        // Periodic cleanup (every 5 minutes)
        if state.last_cleanup.elapsed() > Duration::from_secs(300) {
            let cutoff = Instant::now() - window * 2;
            state.general.retain(|_, (start, _)| *start > cutoff);
            state.sensitive.retain(|_, (start, _)| *start > cutoff);
            state.last_cleanup = Instant::now();
        }

        let map = match tier {
            RateTier::General => &mut state.general,
            RateTier::Sensitive => &mut state.sensitive,
        };

        let now = Instant::now();
        let entry = map.entry(ip).or_insert((now, 0));

        // Reset window if expired
        if now.duration_since(entry.0) >= window {
            *entry = (now, 0);
        }

        entry.1 += 1;

        if entry.1 > limit {
            let elapsed = now.duration_since(entry.0);
            let retry_after = window.saturating_sub(elapsed).as_secs().max(1);
            Err(retry_after)
        } else {
            Ok(limit - entry.1)
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Rate Limiter
// ═══════════════════════════════════════════════════════════════

/// Per-IP sliding window rate limiter.
#[derive(Clone)]
pub struct RateLimiter {
    backend: Arc<dyn RateLimiterBackend>,
    /// Maximum requests per window for general endpoints.
    pub general_limit: u32,
    /// Maximum requests per window for sensitive endpoints.
    pub sensitive_limit: u32,
    /// Window size.
    pub window: Duration,
    /// SEC-M2: Whether to trust X-Forwarded-For header for IP extraction.
    /// MUST only be true when behind a trusted reverse proxy.
    pub trust_proxy: bool,
}

/// Rate limit tier for an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateTier {
    /// Standard rate limit (100/min default).
    General,
    /// Strict rate limit (10/min default).
    Sensitive,
}

fn read_trust_proxy() -> bool {
    std::env::var("MISAKA_TRUST_PROXY")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

/// SEC-FIX: Read trusted proxy CIDR ranges from environment.
///
/// When `MISAKA_TRUST_PROXY=true`, only trust X-Forwarded-For from IPs
/// within these CIDR ranges. Without this, any client can spoof their IP
/// via the X-Forwarded-For header and bypass rate limiting entirely.
///
/// Format: comma-separated CIDR notation, e.g. `10.0.0.0/8,172.16.0.0/12`
fn read_trusted_proxy_cidrs() -> Vec<(IpAddr, u8)> {
    let cidrs_str = match std::env::var("MISAKA_TRUSTED_PROXY_CIDR") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            if read_trust_proxy() {
                // SEC-FIX: Upgraded from warning to error. Without CIDR restriction,
                // ip_in_trusted_cidrs() returns false (FIX 29), effectively disabling
                // X-Forwarded-For trust. But the operator expects it to work.
                // This is a configuration error — fail loudly.
                tracing::error!(
                    "MISAKA_TRUST_PROXY=true but MISAKA_TRUSTED_PROXY_CIDR is not set. \
                     X-Forwarded-For will NOT be trusted (CIDR required). \
                     Set MISAKA_TRUSTED_PROXY_CIDR=10.0.0.0/8 or similar, or disable TRUST_PROXY."
                );
            }
            return Vec::new();
        }
    };

    cidrs_str
        .split(',')
        .filter_map(|cidr| {
            let cidr = cidr.trim();
            let parts: Vec<&str> = cidr.split('/').collect();
            if parts.len() != 2 {
                tracing::warn!("Invalid CIDR in MISAKA_TRUSTED_PROXY_CIDR: {}", cidr);
                return None;
            }
            let ip: IpAddr = match parts[0].parse() {
                Ok(ip) => ip,
                Err(_) => {
                    tracing::warn!("Invalid IP in MISAKA_TRUSTED_PROXY_CIDR: {}", cidr);
                    return None;
                }
            };
            let prefix: u8 = match parts[1].parse() {
                Ok(p) => p,
                Err(_) => {
                    tracing::warn!("Invalid prefix in MISAKA_TRUSTED_PROXY_CIDR: {}", cidr);
                    return None;
                }
            };
            Some((ip, prefix))
        })
        .collect()
}

/// Check if an IP falls within any of the trusted CIDR ranges.
///
/// SEC-FIX: Returns `false` when no CIDRs are configured. Previously returned
/// `true` (trust all), allowing any client to spoof IP via X-Forwarded-For.
fn ip_in_trusted_cidrs(ip: IpAddr, cidrs: &[(IpAddr, u8)]) -> bool {
    if cidrs.is_empty() {
        return false; // No CIDR restriction — do NOT trust X-Forwarded-For
    }
    for &(net_ip, prefix) in cidrs {
        match (ip, net_ip) {
            (IpAddr::V4(client), IpAddr::V4(net)) => {
                let mask = if prefix >= 32 {
                    u32::MAX
                } else {
                    u32::MAX << (32 - prefix)
                };
                if u32::from(client) & mask == u32::from(net) & mask {
                    return true;
                }
            }
            (IpAddr::V6(client), IpAddr::V6(net)) => {
                let mask = if prefix >= 128 {
                    u128::MAX
                } else {
                    u128::MAX << (128 - prefix)
                };
                if u128::from(client) & mask == u128::from(net) & mask {
                    return true;
                }
            }
            _ => {} // v4/v6 mismatch — skip
        }
    }
    false
}

impl RateLimiter {
    /// SEC-FIX: Resolve effective trust_proxy setting.
    /// If MISAKA_TRUST_PROXY=true but MISAKA_TRUSTED_PROXY_CIDR is not set,
    /// force trust_proxy to false. Previously this was a warning only,
    /// allowing X-Forwarded-For spoofing to bypass rate limits.
    fn effective_trust_proxy() -> bool {
        let want_trust = read_trust_proxy();
        if want_trust {
            let cidrs = read_trusted_proxy_cidrs();
            if cidrs.is_empty() {
                tracing::error!(
                    "MISAKA_TRUST_PROXY=true but MISAKA_TRUSTED_PROXY_CIDR is not set. \
                     Forcing trust_proxy=false to prevent X-Forwarded-For spoofing. \
                     Set MISAKA_TRUSTED_PROXY_CIDR to enable proxy trust."
                );
                return false;
            }
        }
        want_trust
    }

    /// Create a new rate limiter with default settings (in-memory backend).
    pub fn new() -> Self {
        Self {
            backend: Arc::new(InMemoryBackend::new()),
            general_limit: 100,
            sensitive_limit: 10,
            window: Duration::from_secs(60),
            trust_proxy: Self::effective_trust_proxy(),
        }
    }

    /// Create with custom limits (in-memory backend).
    pub fn with_limits(general: u32, sensitive: u32, window_secs: u64) -> Self {
        Self {
            backend: Arc::new(InMemoryBackend::new()),
            general_limit: general,
            sensitive_limit: sensitive,
            window: Duration::from_secs(window_secs),
            trust_proxy: Self::effective_trust_proxy(),
        }
    }

    /// Create with a custom backend (e.g., Redis).
    pub fn with_backend(
        backend: Arc<dyn RateLimiterBackend>,
        general: u32,
        sensitive: u32,
        window_secs: u64,
    ) -> Self {
        Self {
            backend,
            general_limit: general,
            sensitive_limit: sensitive,
            window: Duration::from_secs(window_secs),
            trust_proxy: read_trust_proxy(),
        }
    }

    /// Check if a request from `ip` is allowed under the given tier.
    /// Returns `Ok(remaining)` or `Err(retry_after_secs)`.
    pub async fn check(&self, ip: IpAddr, tier: RateTier) -> Result<u32, u64> {
        let limit = match tier {
            RateTier::General => self.general_limit,
            RateTier::Sensitive => self.sensitive_limit,
        };
        self.backend
            .check_and_increment(ip, tier, limit, self.window)
            .await
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Rate Limit Middleware (axum)
// ═══════════════════════════════════════════════════════════════

/// Extract client IP from request.
///
/// # SEC-M2: X-Forwarded-For Trust Policy
///
/// `X-Forwarded-For` is only trusted when `trust_proxy` is true.
/// Without a reverse proxy, an attacker can set `X-Forwarded-For: 1.2.3.4`
/// to spoof their IP and bypass per-IP rate limiting.
///
/// Enable via `MISAKA_TRUST_PROXY=true` environment variable.
/// SEC-FIX: Returns `Option<IpAddr>` instead of falling back to 127.0.0.1.
///
/// When ConnectInfo is unavailable, returns None. The middleware should
/// reject requests with a 500 error rather than sharing a rate limit bucket.
fn extract_ip(req: &Request<Body>, trust_proxy: bool) -> Option<IpAddr> {
    // Read the real socket IP from ConnectInfo<SocketAddr>.
    let socket_ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip());

    // SEC-FIX: When behind a trusted proxy, use X-Forwarded-For BUT only
    // if the connecting socket IP is within trusted CIDR ranges.
    if trust_proxy {
        let trusted_cidrs = read_trusted_proxy_cidrs();
        let socket_trusted = socket_ip
            .map(|ip| ip_in_trusted_cidrs(ip, &trusted_cidrs))
            .unwrap_or(false);

        if socket_trusted {
            if let Some(forwarded) = req
                .headers()
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
            {
                if let Some(first_ip) = forwarded.split(',').next() {
                    if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                        return Some(ip);
                    }
                }
            }
        } else if let Some(sip) = socket_ip {
            tracing::debug!(
                "extract_ip: trust_proxy=true but socket IP {} not in trusted CIDRs — ignoring X-Forwarded-For",
                sip
            );
        }
    }

    if socket_ip.is_none() {
        tracing::error!(
            "extract_ip: ConnectInfo unavailable — server may be misconfigured \
             (missing into_make_service_with_connect_info)"
        );
    }

    socket_ip
}

/// Determine the rate tier for a request path.
fn path_to_tier(path: &str) -> RateTier {
    // Sensitive endpoints
    if path.contains("/faucet")
        || path.contains("/submit")
        || path.contains("/submit_tx")
        || path.contains("/submit_ct_tx")
    {
        RateTier::Sensitive
    } else {
        RateTier::General
    }
}

/// Axum middleware: apply rate limiting per IP.
///
/// Usage:
/// ```ignore
/// let limiter = RateLimiter::new();
/// let app = Router::new()
///     .route("/api/submit_tx", post(handler))
///     .route_layer(axum::middleware::from_fn_with_state(
///         limiter,
///         rate_limit_middleware,
///     ));
/// ```
pub async fn rate_limit_middleware(
    axum::extract::State(limiter): axum::extract::State<RateLimiter>,
    req: Request<Body>,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    // SEC-FIX: extract_ip now returns Option — reject if IP unavailable.
    let ip = match extract_ip(&req, limiter.trust_proxy) {
        Some(ip) => ip,
        None => {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    let tier = path_to_tier(req.uri().path());

    match limiter.check(ip, tier).await {
        Ok(remaining) => {
            let mut resp = next.run(req).await;
            // Add rate limit headers
            if let Ok(value) = HeaderValue::from_str(&remaining.to_string()) {
                resp.headers_mut().insert("X-RateLimit-Remaining", value);
            }
            Ok(resp)
        }
        Err(retry_after) => {
            let mut resp = Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .body(Body::from(
                    serde_json::json!({
                        "error": {
                            "code": "RATE_LIMITED",
                            "message": format!("rate limit exceeded, retry after {}s", retry_after),
                            "retryAfter": retry_after
                        }
                    })
                    .to_string(),
                ))
                .unwrap_or_default();
            if let Ok(value) = HeaderValue::from_str(&retry_after.to_string()) {
                resp.headers_mut().insert("Retry-After", value);
            }
            Ok(resp)
        }
    }
}

/// Add baseline security headers for all public API responses.
pub async fn security_headers_middleware(req: Request<Body>, next: Next) -> Response<Body> {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    headers.insert("Referrer-Policy", HeaderValue::from_static("no-referrer"));
    headers.insert("Cache-Control", HeaderValue::from_static("no-store"));
    headers.insert(
        "X-Permitted-Cross-Domain-Policies",
        HeaderValue::from_static("none"),
    );
    resp
}

// ═══════════════════════════════════════════════════════════════
//  Idempotency Cache
// ═══════════════════════════════════════════════════════════════

/// Cached response for idempotent requests.
#[derive(Clone)]
struct CachedResponse {
    status: u16,
    body: String,
    cached_at: Instant,
}

/// SEC-FIX: Maximum idempotency key length to prevent memory exhaustion.
const MAX_IDEMPOTENCY_KEY_LEN: usize = 64;

/// In-memory idempotency cache.
#[derive(Clone)]
pub struct IdempotencyCache {
    state: Arc<Mutex<HashMap<String, CachedResponse>>>,
    /// TTL for cached responses.
    pub ttl: Duration,
}

impl IdempotencyCache {
    /// Create with a given TTL.
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(HashMap::new())),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Look up a cached response by idempotency key.
    pub async fn get(&self, key: &str) -> Option<(u16, String)> {
        // SEC-FIX: Reject oversized keys without acquiring lock.
        if key.len() > MAX_IDEMPOTENCY_KEY_LEN {
            return None;
        }
        let state = self.state.lock().await;
        state.get(key).and_then(|entry| {
            if entry.cached_at.elapsed() < self.ttl {
                Some((entry.status, entry.body.clone()))
            } else {
                None
            }
        })
    }

    /// Store a response for an idempotency key.
    pub async fn set(&self, key: String, status: u16, body: String) {
        // SEC-FIX: Reject oversized keys to prevent memory exhaustion.
        if key.len() > MAX_IDEMPOTENCY_KEY_LEN {
            return;
        }
        let mut state = self.state.lock().await;

        // Periodic cleanup
        if state.len() > 10_000 {
            let cutoff = Instant::now() - self.ttl;
            state.retain(|_, v| v.cached_at > cutoff);
        }

        state.insert(
            key,
            CachedResponse {
                status,
                body,
                cached_at: Instant::now(),
            },
        );
    }
}

impl Default for IdempotencyCache {
    fn default() -> Self {
        Self::new(300) // 5 minutes
    }
}

// ═══════════════════════════════════════════════════════════════
//  Request Timeout Wrapper
// ═══════════════════════════════════════════════════════════════

/// Wrap an async operation with a timeout.
///
/// Returns `Err(StatusCode::GATEWAY_TIMEOUT)` if the operation exceeds
/// the deadline. Prevents API threads from hanging on unresponsive nodes.
pub async fn with_timeout<F, T>(future: F, timeout: Duration) -> Result<T, StatusCode>
where
    F: std::future::Future<Output = T>,
{
    match tokio::time::timeout(timeout, future).await {
        Ok(result) => Ok(result),
        Err(_) => Err(StatusCode::GATEWAY_TIMEOUT),
    }
}

/// Default RPC call timeout.
pub const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(5);

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};

    #[tokio::test]
    async fn test_rate_limiter_allows_within_limit() {
        let limiter = RateLimiter::with_limits(3, 1, 60);
        let ip: IpAddr = "1.2.3.4".parse().expect("test: parse ip");

        let r1 = limiter.check(ip, RateTier::General).await;
        assert!(r1.is_ok());
        assert_eq!(r1.expect("test: ok"), 2); // 3 - 1 = 2 remaining

        let r2 = limiter.check(ip, RateTier::General).await;
        assert!(r2.is_ok());
        assert_eq!(r2.expect("test: ok"), 1);

        let r3 = limiter.check(ip, RateTier::General).await;
        assert!(r3.is_ok());
        assert_eq!(r3.expect("test: ok"), 0);

        // 4th request should be rate limited
        let r4 = limiter.check(ip, RateTier::General).await;
        assert!(r4.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_separate_ips() {
        let limiter = RateLimiter::with_limits(1, 1, 60);
        let ip1: IpAddr = "1.1.1.1".parse().expect("test: parse");
        let ip2: IpAddr = "2.2.2.2".parse().expect("test: parse");

        // Both should be allowed
        assert!(limiter.check(ip1, RateTier::General).await.is_ok());
        assert!(limiter.check(ip2, RateTier::General).await.is_ok());

        // Both should be blocked on second request
        assert!(limiter.check(ip1, RateTier::General).await.is_err());
        assert!(limiter.check(ip2, RateTier::General).await.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_sensitive_vs_general() {
        let limiter = RateLimiter::with_limits(10, 1, 60);
        let ip: IpAddr = "1.2.3.4".parse().expect("test: parse");

        // Sensitive: 1 request allowed
        assert!(limiter.check(ip, RateTier::Sensitive).await.is_ok());
        assert!(limiter.check(ip, RateTier::Sensitive).await.is_err());

        // General: still has capacity (separate counter)
        assert!(limiter.check(ip, RateTier::General).await.is_ok());
    }

    #[tokio::test]
    async fn test_idempotency_cache_hit() {
        let cache = IdempotencyCache::new(60);

        cache.set("key1".into(), 200, "{\"ok\":true}".into()).await;

        let result = cache.get("key1").await;
        assert!(result.is_some());
        let (status, body) = result.expect("test: cached");
        assert_eq!(status, 200);
        assert!(body.contains("ok"));
    }

    #[tokio::test]
    async fn test_idempotency_cache_miss() {
        let cache = IdempotencyCache::new(60);
        let result = cache.get("nonexistent").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_idempotency_cache_expired() {
        let cache = IdempotencyCache::new(0); // 0-second TTL = immediate expiry

        cache.set("key1".into(), 200, "{}".into()).await;

        // Should be expired immediately
        tokio::time::sleep(Duration::from_millis(10)).await;
        let result = cache.get("key1").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_with_timeout_success() {
        let result = with_timeout(async { 42 }, Duration::from_secs(1)).await;
        assert_eq!(result, Ok(42));
    }

    #[tokio::test]
    async fn test_with_timeout_exceeded() {
        let result = with_timeout(
            async {
                tokio::time::sleep(Duration::from_secs(10)).await;
                42
            },
            Duration::from_millis(10),
        )
        .await;
        assert_eq!(result, Err(StatusCode::GATEWAY_TIMEOUT));
    }

    #[test]
    fn test_path_to_tier() {
        assert_eq!(path_to_tier("/v1/chain/info"), RateTier::General);
        assert_eq!(path_to_tier("/v1/tx/submit"), RateTier::Sensitive);
        assert_eq!(path_to_tier("/v1/faucet"), RateTier::Sensitive);
        assert_eq!(path_to_tier("/api/submit_tx"), RateTier::Sensitive);
        assert_eq!(path_to_tier("/health"), RateTier::General);
    }

    #[tokio::test]
    async fn test_security_headers_middleware_sets_headers() {
        use axum::{routing::get, Router};
        use tower::ServiceExt;

        let app = Router::new()
            .route("/health", get(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn(security_headers_middleware));

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("test: request"),
            )
            .await
            .expect("test: response");
        assert_eq!(
            resp.headers()
                .get("X-Content-Type-Options")
                .expect("nosniff"),
            "nosniff"
        );
        assert_eq!(
            resp.headers().get("X-Frame-Options").expect("frame"),
            "DENY"
        );
        assert_eq!(
            resp.headers().get("Referrer-Policy").expect("referrer"),
            "no-referrer"
        );
        assert_eq!(
            resp.headers().get("Cache-Control").expect("cache"),
            "no-store"
        );
    }

    #[test]
    fn test_extract_ip_ignores_x_forwarded_for_when_proxy_untrusted() {
        let mut req = Request::builder()
            .uri("/api/v1/tx/submit")
            .header("x-forwarded-for", "203.0.113.10, 198.51.100.9")
            .body(Body::empty())
            .expect("request");
        req.extensions_mut().insert(axum::extract::ConnectInfo(
            "127.0.0.1:3001"
                .parse::<std::net::SocketAddr>()
                .expect("socket addr"),
        ));

        let ip = extract_ip(&req, false);
        assert_eq!(ip, Some("127.0.0.1".parse::<IpAddr>().expect("loopback")));
    }

    #[test]
    fn test_extract_ip_uses_first_x_forwarded_for_when_proxy_trusted() {
        // SEC-FIX: X-Forwarded-For is only trusted when the connecting
        // socket is inside a CIDR listed in MISAKA_TRUSTED_PROXY_CIDR.
        // The test proxy is 127.0.0.1, so allow the loopback range.
        std::env::set_var("MISAKA_TRUSTED_PROXY_CIDR", "127.0.0.0/8");

        let mut req = Request::builder()
            .uri("/api/v1/tx/submit")
            .header("x-forwarded-for", "203.0.113.10, 198.51.100.9")
            .body(Body::empty())
            .expect("request");
        req.extensions_mut().insert(axum::extract::ConnectInfo(
            "127.0.0.1:3001"
                .parse::<std::net::SocketAddr>()
                .expect("socket addr"),
        ));

        let ip = extract_ip(&req, true);
        assert_eq!(ip, Some("203.0.113.10".parse::<IpAddr>().expect("forwarded")));

        std::env::remove_var("MISAKA_TRUSTED_PROXY_CIDR");
    }
}
