//! MISAKA Network — Public REST API Server
//!
//! Reverse-proxy to a misaka-node RPC endpoint with:
//! - RESTful GET-based reads (vs node's POST-based RPC)
//! - CORS (fail-closed: localhost-only by default)
//! - IP-based rate limiting (general 100/min, sensitive 10/min)
//! - Request body size limit (128KB)
//! - Request logging with tracing
//! - Swagger UI at /docs

mod proxy;
mod routes;
pub mod middleware;

use anyhow::Result;
use axum::Router;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn, Level};

#[derive(Parser)]
#[command(name = "misaka-api", version, about = "MISAKA Network REST API")]
struct Cli {
    /// Upstream misaka-node RPC URL
    #[arg(long, default_value = "http://127.0.0.1:3001")]
    node: String,

    /// API server listen port
    #[arg(long, default_value = "4000")]
    port: u16,

    /// Listen address
    #[arg(long, default_value = "0.0.0.0")]
    host: String,

    /// Allowed CORS origins (comma-separated). REQUIRED for non-localhost access.
    /// If unset, only localhost origins are allowed (secure default).
    #[arg(long, env = "MISAKA_API_CORS_ORIGINS")]
    cors_origins: Option<String>,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Rate limit: requests per minute for general endpoints (default: 100)
    #[arg(long, default_value = "100")]
    rate_limit_general: u32,

    /// Rate limit: requests per minute for sensitive endpoints (default: 10)
    #[arg(long, default_value = "10")]
    rate_limit_sensitive: u32,
}

#[derive(Clone)]
pub struct AppState {
    pub proxy: Arc<proxy::NodeProxy>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_max_level(cli.log_level.parse::<Level>().unwrap_or(Level::INFO))
        .init();

    info!("MISAKA API starting");
    info!("  Upstream node: {}", cli.node);
    info!("  Listen: {}:{}", cli.host, cli.port);

    let proxy = proxy::NodeProxy::new(&cli.node)?;

    // Verify upstream is reachable
    match proxy.get("/health").await {
        Ok(h) => info!("  Upstream health: {}", h),
        Err(e) => warn!("  Upstream not reachable: {} (will retry on requests)", e),
    }

    let state = AppState { proxy };

    // ── CORS (fail-closed: localhost-only unless explicitly configured) ──
    // FIX-G: No more AllowOrigin::any(). Default is localhost-only.
    let cors = {
        match &cli.cors_origins {
            Some(origins) if !origins.trim().is_empty() => {
                let allowed: Vec<axum::http::HeaderValue> = origins
                    .split(',')
                    .filter(|o| !o.trim().is_empty())
                    .filter_map(|o| o.trim().parse().ok())
                    .collect();
                if allowed.is_empty() {
                    anyhow::bail!(
                        "MISAKA_API_CORS_ORIGINS is set but contains no valid origins: '{}'. \
                         Fix the value or unset for localhost-only default.",
                        origins
                    );
                }
                info!("  CORS: {} configured origins", allowed.len());
                CorsLayer::new()
                    .allow_origin(allowed)
                    .allow_methods([
                        axum::http::Method::GET,
                        axum::http::Method::POST,
                        axum::http::Method::OPTIONS,
                    ])
                    .allow_headers([
                        axum::http::header::CONTENT_TYPE,
                        axum::http::header::AUTHORIZATION,
                    ])
            }
            _ => {
                // SECURE DEFAULT: localhost only. No permissive allow-all.
                info!("  CORS: localhost-only (set MISAKA_API_CORS_ORIGINS for custom)");
                #[allow(clippy::unwrap_used)] // static string parse
                CorsLayer::new()
                    .allow_origin([
                        "http://localhost:3000".parse().expect("static origin"),
                        "http://localhost:3001".parse().expect("static origin"),
                        "http://localhost:4000".parse().expect("static origin"),
                        "http://127.0.0.1:3000".parse().expect("static origin"),
                        "http://127.0.0.1:3001".parse().expect("static origin"),
                        "http://127.0.0.1:4000".parse().expect("static origin"),
                    ])
                    .allow_methods([
                        axum::http::Method::GET,
                        axum::http::Method::POST,
                        axum::http::Method::OPTIONS,
                    ])
                    .allow_headers([
                        axum::http::header::CONTENT_TYPE,
                        axum::http::header::AUTHORIZATION,
                    ])
            }
        }
    };

    // ── Rate limiter (connected to all routes) ──
    // FIX-F: Actually wire the middleware, not just define it.
    let rate_limiter = middleware::RateLimiter::with_limits(
        cli.rate_limit_general,
        cli.rate_limit_sensitive,
        60,
    );
    info!(
        "  Rate limit: general={}/min, sensitive={}/min",
        cli.rate_limit_general, cli.rate_limit_sensitive
    );

    // ── Faucet service (queue-based, separate state) ──
    let faucet_config = routes::faucet::FaucetConfig::default();
    let faucet_state = routes::faucet::FaucetState::new(faucet_config, state.proxy.clone());
    info!("  Faucet: queue-based, 24h cooldown per IP/address");

    // ── Swagger UI ──
    let docs_routes = Router::new()
        .route("/docs", axum::routing::get(swagger_ui))
        .route(
            "/api/openapi.yaml",
            axum::routing::get(|| async {
                #[allow(clippy::unwrap_used)] // static response builder
                axum::response::Response::builder()
                    .header("content-type", "text/yaml")
                    .body(axum::body::Body::from(include_str!(
                    "../../../docs/api/openapi.yaml"
                    )))
                    .unwrap()
            }),
        );

    // ── Assemble (ALL middleware connected) ──
    let app = Router::new()
        .merge(routes::chain::router())
        .merge(routes::wallet::router())
        .merge(routes::tx::router())
        .merge(routes::explorer::router())
        .merge(routes::faucet::router(faucet_state))
        .merge(docs_routes)
        .with_state(state)
        // FIX-F: Rate limiting middleware CONNECTED to all routes
        .layer(axum::middleware::from_fn_with_state(
            rate_limiter,
            middleware::rate_limit_middleware,
        ))
        .layer(cors)
        .layer(RequestBodyLimitLayer::new(131_072))
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = format!("{}:{}", cli.host, cli.port).parse()?;
    info!("MISAKA API listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    // SEC-FIX-1: Enable ConnectInfo<SocketAddr> so middleware and handlers
    // can extract the real client socket IP. Without this, extract_ip()
    // falls back to 127.0.0.1 and rate limits become a global bucket.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn swagger_ui() -> axum::response::Html<&'static str> {
    // SEC-FIX-2: Swagger UI loads JS/CSS from unpkg.com CDN.
    // A CDN compromise (supply chain attack) could inject malicious code
    // into every operator's browser that visits /docs.
    //
    // Production mitigation:
    // - The /docs endpoint shows a notice directing operators to the
    //   static OpenAPI spec at /api/openapi.yaml instead.
    // - Operators can use local Swagger UI or Redoc to render the spec.
    // - The full CDN-backed Swagger UI is only available with --features swagger-cdn.
    #[cfg(feature = "swagger-cdn")]
    {
        axum::response::Html(
            r#"<!DOCTYPE html>
<html><head>
<title>MISAKA API (dev)</title>
<meta charset="utf-8"/>
<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"/>
</head><body>
<div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>
SwaggerUIBundle({
  url: '/api/openapi.yaml',
  dom_id: '#swagger-ui',
  deepLinking: true,
  presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
  layout: 'BaseLayout',
});
</script>
</body></html>"#,
        )
    }
    #[cfg(not(feature = "swagger-cdn"))]
    {
        axum::response::Html(
            r#"<!DOCTYPE html>
<html><head>
<title>MISAKA API — Documentation</title>
<meta charset="utf-8"/>
<style>
body { font-family: system-ui, sans-serif; max-width: 600px; margin: 80px auto; padding: 0 20px; color: #333; }
h1 { font-size: 1.4em; }
a { color: #0066cc; }
code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }
.note { background: #fff3cd; border: 1px solid #ffc107; padding: 12px; border-radius: 4px; margin: 16px 0; }
</style>
</head><body>
<h1>MISAKA Network API</h1>
<p>The OpenAPI specification is available at <a href="/api/openapi.yaml"><code>/api/openapi.yaml</code></a>.</p>
<p>To browse interactively, use a local Swagger UI or Redoc instance:</p>
<pre><code>npx @redocly/cli preview-docs http://HOST:PORT/api/openapi.yaml</code></pre>
<div class="note">
  Interactive Swagger UI is disabled in production builds to avoid
  loading JavaScript from external CDNs. Enable with <code>--features swagger-cdn</code> for development.
</div>
</body></html>"#,
        )
    }
}
