//! Abstraction over Solana burn event sources.
//!
//! Current: Direct Solana RPC polling (getSignaturesForAddress)
//! Future: Helius webhooks, Triton, custom indexer, etc.

use crate::config::RelayerConfig;
use crate::message::BurnEvent;
use std::fmt;
use std::future::Future;
use std::pin::Pin;

// ═══════════════════════════════════════════════════════════════
//  Error Type
// ═══════════════════════════════════════════════════════════════

/// Errors from burn event sources.
#[derive(Debug)]
pub enum BurnSourceError {
    /// Underlying RPC call failed.
    RpcError(String),
    /// Failed to parse burn event data.
    ParseError(String),
    /// Rate limited by the source.
    RateLimited,
    /// Could not connect to the source.
    ConnectionFailed(String),
}

impl fmt::Display for BurnSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RpcError(msg) => write!(f, "rpc error: {}", msg),
            Self::ParseError(msg) => write!(f, "parse error: {}", msg),
            Self::RateLimited => write!(f, "rate limited"),
            Self::ConnectionFailed(msg) => write!(f, "connection failed: {}", msg),
        }
    }
}

impl std::error::Error for BurnSourceError {}

// ═══════════════════════════════════════════════════════════════
//  Trait (manual async — no async_trait dependency)
// ═══════════════════════════════════════════════════════════════

/// Abstraction for polling burn events from Solana.
///
/// Uses manual Pin<Box<Future>> instead of async_trait to avoid
/// adding a dependency.
pub trait BurnEventSource: Send + Sync {
    /// Poll for new burn events since the given cursor.
    ///
    /// Returns a list of new burn events and an updated cursor.
    /// The cursor is opaque to callers — each implementation defines
    /// its own cursor format (e.g., Solana signature for RPC polling,
    /// webhook sequence number for Helius, etc.).
    fn poll_burns(
        &self,
        cursor: Option<&str>,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<(Vec<BurnEvent>, Option<String>), BurnSourceError>>
                + Send
                + '_,
        >,
    >;

    /// Name of this source (for logging).
    fn name(&self) -> &str;
}

// ═══════════════════════════════════════════════════════════════
//  SolanaRpcBurnSource
// ═══════════════════════════════════════════════════════════════

/// Burn event source using direct Solana RPC polling.
///
/// Wraps the existing `solana_watcher::poll_burn_events` logic
/// into the `BurnEventSource` trait.
pub struct SolanaRpcBurnSource {
    config: RelayerConfig,
    /// Consecutive RPC failure counter (interior mutability for trait compat).
    consecutive_failures: std::sync::Mutex<u32>,
}

impl SolanaRpcBurnSource {
    pub fn new(config: RelayerConfig) -> Self {
        Self {
            config,
            consecutive_failures: std::sync::Mutex::new(0),
        }
    }

    /// Get the current consecutive failure count.
    pub fn consecutive_failures(&self) -> u32 {
        *self.consecutive_failures.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl BurnEventSource for SolanaRpcBurnSource {
    fn poll_burns(
        &self,
        cursor: Option<&str>,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<(Vec<BurnEvent>, Option<String>), BurnSourceError>>
                + Send
                + '_,
        >,
    > {
        let cursor_owned = cursor.map(String::from);
        Box::pin(async move {
            // Copy the failure count out so we don't hold the guard across await.
            let mut failures = {
                let guard = self
                    .consecutive_failures
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                *guard
            };

            let result = crate::solana_watcher::poll_burn_events(
                &self.config,
                cursor_owned.as_deref(),
                &mut failures,
            )
            .await;

            // Write back the updated failure count.
            {
                let mut guard = self
                    .consecutive_failures
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                *guard = failures;
            }

            match result {
                Ok((events, new_cursor)) => Ok((events, new_cursor)),
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("CIRCUIT BREAKER") {
                        Err(BurnSourceError::ConnectionFailed(msg))
                    } else if msg.contains("rate") || msg.contains("429") {
                        Err(BurnSourceError::RateLimited)
                    } else {
                        Err(BurnSourceError::RpcError(msg))
                    }
                }
            }
        })
    }

    fn name(&self) -> &str {
        "solana-rpc"
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{BurnEvent, BurnStatus};

    /// A mock burn source for testing.
    pub struct MockBurnSource {
        events: Vec<BurnEvent>,
    }

    impl MockBurnSource {
        pub fn new(events: Vec<BurnEvent>) -> Self {
            Self { events }
        }
    }

    impl BurnEventSource for MockBurnSource {
        fn poll_burns(
            &self,
            _cursor: Option<&str>,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<(Vec<BurnEvent>, Option<String>), BurnSourceError>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async {
                let cursor = if self.events.is_empty() {
                    None
                } else {
                    Some(self.events.last().unwrap().solana_tx_signature.clone())
                };
                Ok((self.events.clone(), cursor))
            })
        }

        fn name(&self) -> &str {
            "mock"
        }
    }

    #[tokio::test]
    async fn test_mock_burn_source_empty() {
        let source = MockBurnSource::new(vec![]);
        let (events, cursor) = source.poll_burns(None).await.unwrap();
        assert!(events.is_empty());
        assert!(cursor.is_none());
    }

    #[tokio::test]
    async fn test_mock_burn_source_with_events() {
        let events = vec![
            BurnEvent {
                id: "event-001".to_string(),
                solana_tx_signature: "txsig-001".to_string(),
                mint_address: "mint111".to_string(),
                wallet_address: "wallet111".to_string(),
                burn_amount_raw: 1_000_000,
                slot: 100,
                block_time: 1700000000,
                status: BurnStatus::Detected,
            },
            BurnEvent {
                id: "event-002".to_string(),
                solana_tx_signature: "txsig-002".to_string(),
                mint_address: "mint111".to_string(),
                wallet_address: "wallet222".to_string(),
                burn_amount_raw: 2_000_000,
                slot: 101,
                block_time: 1700000015,
                status: BurnStatus::Detected,
            },
        ];

        let source = MockBurnSource::new(events);
        let (result_events, cursor) = source.poll_burns(None).await.unwrap();
        assert_eq!(result_events.len(), 2);
        assert_eq!(cursor, Some("txsig-002".to_string()));
        assert_eq!(result_events[0].burn_amount_raw, 1_000_000);
        assert_eq!(result_events[1].burn_amount_raw, 2_000_000);
    }

    #[tokio::test]
    async fn test_mock_burn_source_name() {
        let source = MockBurnSource::new(vec![]);
        assert_eq!(source.name(), "mock");
    }

    #[test]
    fn test_burn_source_error_display() {
        let err = BurnSourceError::RpcError("timeout".to_string());
        assert!(err.to_string().contains("timeout"));

        let err = BurnSourceError::RateLimited;
        assert!(err.to_string().contains("rate limited"));

        let err = BurnSourceError::ConnectionFailed("refused".to_string());
        assert!(err.to_string().contains("refused"));
    }
}
