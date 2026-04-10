//! Trait-based mint execution on the target chain.
//!
//! Implementations:
//! - `MockMintExecutor`: for testing (always succeeds)
//! - `MisakaRpcMintExecutor`: calls MISAKA chain RPC (current behavior, extracted)
//! - Future: `DirectChainMintExecutor` (sign + broadcast TX directly)

use crate::config::RelayerConfig;
use crate::store::BurnRequestRow;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use tracing::error;

// ═══════════════════════════════════════════════════════════════
//  Types
// ═══════════════════════════════════════════════════════════════

/// A request to mint tokens on the target chain.
pub struct MintRequest {
    pub burn_id: String,
    pub recipient_address: String,
    pub amount_raw: u64,
    pub solana_tx_signature: String,
    /// Attestation signatures (for N-of-M verification on-chain).
    pub attestations: Vec<Vec<u8>>,
}

/// Result of a successful mint submission.
pub struct MintResult {
    pub mint_tx_id: String,
    pub status: MintStatus,
}

/// Status of a mint operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintStatus {
    Pending,
    Confirmed,
    Failed(String),
}

/// Errors from mint execution.
#[derive(Debug)]
pub enum MintError {
    NetworkError(String),
    InsufficientAttestations,
    InvalidRecipient(String),
    AmountOverflow,
    AlreadyMinted(String),
    ChainError(String),
}

impl fmt::Display for MintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NetworkError(msg) => write!(f, "network error: {}", msg),
            Self::InsufficientAttestations => write!(f, "insufficient attestations for mint"),
            Self::InvalidRecipient(addr) => write!(f, "invalid recipient address: {}", addr),
            Self::AmountOverflow => write!(f, "mint amount overflow"),
            Self::AlreadyMinted(id) => write!(f, "already minted: {}", id),
            Self::ChainError(msg) => write!(f, "chain error: {}", msg),
        }
    }
}

impl std::error::Error for MintError {}

// ═══════════════════════════════════════════════════════════════
//  Trait (manual async — no async_trait dependency)
// ═══════════════════════════════════════════════════════════════

/// Trait for mint execution on the target chain.
///
/// Uses manual Pin<Box<Future>> instead of async_trait to avoid
/// adding a dependency.
pub trait MintExecutor: Send + Sync {
    /// Execute a mint operation on the target chain.
    fn execute_mint(
        &self,
        request: MintRequest,
    ) -> Pin<Box<dyn Future<Output = Result<MintResult, MintError>> + Send + '_>>;

    /// Check the status of a previously submitted mint.
    fn check_mint_status(
        &self,
        mint_tx_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<MintStatus, MintError>> + Send + '_>>;

    /// Name of this executor (for logging).
    fn name(&self) -> &str;
}

// ═══════════════════════════════════════════════════════════════
//  MockMintExecutor
// ═══════════════════════════════════════════════════════════════

/// Mock executor for testing — always returns success with a fake tx_id.
pub struct MockMintExecutor;

impl MintExecutor for MockMintExecutor {
    fn execute_mint(
        &self,
        request: MintRequest,
    ) -> Pin<Box<dyn Future<Output = Result<MintResult, MintError>> + Send + '_>> {
        Box::pin(async move {
            let tx_id = format!("mock-mint-{}", &request.burn_id);
            Ok(MintResult {
                mint_tx_id: tx_id,
                status: MintStatus::Confirmed,
            })
        })
    }

    fn check_mint_status(
        &self,
        _mint_tx_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<MintStatus, MintError>> + Send + '_>> {
        Box::pin(async { Ok(MintStatus::Confirmed) })
    }

    fn name(&self) -> &str {
        "mock"
    }
}

// ═══════════════════════════════════════════════════════════════
//  MisakaRpcMintExecutor
// ═══════════════════════════════════════════════════════════════

/// Executor that submits mints via MISAKA chain RPC.
///
/// Extracts the logic from `misaka_watcher::submit_mint_for_burn`
/// into a trait implementation.
pub struct MisakaRpcMintExecutor {
    config: RelayerConfig,
}

impl MisakaRpcMintExecutor {
    pub fn new(config: RelayerConfig) -> Self {
        Self { config }
    }
}

impl MintExecutor for MisakaRpcMintExecutor {
    fn execute_mint(
        &self,
        request: MintRequest,
    ) -> Pin<Box<dyn Future<Output = Result<MintResult, MintError>> + Send + '_>> {
        Box::pin(async move {
            let url = format!("{}/api/bridge/submit_mint", self.config.misaka_rpc_url);
            let body = serde_json::json!({
                "burn_event_id": request.burn_id,
                "source_chain": 1,  // Solana
                "amount": request.amount_raw,
                "misaka_recipient": request.recipient_address,
                "solana_tx_signature": request.solana_tx_signature,
                "attestation_signatures": request.attestations.iter()
                    .map(|s| hex::encode(s))
                    .collect::<Vec<_>>(),
            });

            let resp = http_post(&url, &body).await.map_err(|e| {
                MintError::NetworkError(format!("mint RPC to {}: {}", url, e))
            })?;

            let receipt_id = resp["receiptId"]
                .as_str()
                .ok_or_else(|| {
                    error!(
                        "Mint response from {} missing 'receiptId' field: {:?}",
                        url, resp
                    );
                    MintError::ChainError("mint response missing receiptId".to_string())
                })?
                .to_string();

            Ok(MintResult {
                mint_tx_id: receipt_id,
                status: MintStatus::Pending,
            })
        })
    }

    fn check_mint_status(
        &self,
        mint_tx_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<MintStatus, MintError>> + Send + '_>> {
        let tx_id = mint_tx_id.to_string();
        Box::pin(async move {
            let url = format!(
                "{}/api/bridge/mint_status/{}",
                self.config.misaka_rpc_url, tx_id
            );

            let resp = http_get(&url).await.map_err(|e| {
                MintError::NetworkError(format!("status check {}: {}", url, e))
            })?;

            let status_str = resp["status"].as_str().unwrap_or("unknown");
            match status_str {
                "confirmed" => Ok(MintStatus::Confirmed),
                "pending" => Ok(MintStatus::Pending),
                "failed" => {
                    let reason = resp["reason"]
                        .as_str()
                        .unwrap_or("unknown")
                        .to_string();
                    Ok(MintStatus::Failed(reason))
                }
                other => Ok(MintStatus::Failed(format!("unknown status: {}", other))),
            }
        })
    }

    fn name(&self) -> &str {
        "misaka-rpc"
    }
}

// ═══════════════════════════════════════════════════════════════
//  Helper: Build MintRequest from BurnRequestRow
// ═══════════════════════════════════════════════════════════════

impl MintRequest {
    /// Create a MintRequest from a BurnRequestRow and optional attestation signatures.
    pub fn from_burn_row(burn: &BurnRequestRow, attestations: Vec<Vec<u8>>) -> Self {
        Self {
            burn_id: burn.id.clone(),
            recipient_address: burn.misaka_receive_address.clone(),
            amount_raw: burn.burn_amount_raw,
            solana_tx_signature: burn.solana_tx_signature.clone(),
            attestations,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  HTTP Helpers
// ═══════════════════════════════════════════════════════════════

async fn http_post(url: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("http client build: {}", e))?;

    let resp = client
        .post(url)
        .json(body)
        .send()
        .await
        .map_err(|e| format!("http post to {}: {}", url, e))?;

    let status = resp.status();
    if !status.is_success() {
        let body_text = resp.text().await.unwrap_or_default();
        return Err(format!(
            "HTTP {} from {}: {}",
            status,
            url,
            &body_text[..200.min(body_text.len())]
        ));
    }

    resp.json::<serde_json::Value>()
        .await
        .map_err(|e| format!("json parse from {}: {}", url, e))
}

async fn http_get(url: &str) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("http client build: {}", e))?;

    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("http get {}: {}", url, e))?;

    let status = resp.status();
    if !status.is_success() {
        let body_text = resp.text().await.unwrap_or_default();
        return Err(format!(
            "HTTP {} from {}: {}",
            status,
            url,
            &body_text[..200.min(body_text.len())]
        ));
    }

    resp.json::<serde_json::Value>()
        .await
        .map_err(|e| format!("json parse from {}: {}", url, e))
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_executor_succeeds() {
        let executor = MockMintExecutor;
        assert_eq!(executor.name(), "mock");

        let request = MintRequest {
            burn_id: "burn-test-001".to_string(),
            recipient_address: "msk1recipient111111111111111111".to_string(),
            amount_raw: 1_000_000_000,
            solana_tx_signature: "txsig111111111111111111111111111111111111111111".to_string(),
            attestations: vec![],
        };

        let result = executor.execute_mint(request).await.unwrap();
        assert_eq!(result.mint_tx_id, "mock-mint-burn-test-001");
        assert_eq!(result.status, MintStatus::Confirmed);
    }

    #[tokio::test]
    async fn test_mock_executor_status_check() {
        let executor = MockMintExecutor;
        let status = executor.check_mint_status("mock-tx-123").await.unwrap();
        assert_eq!(status, MintStatus::Confirmed);
    }

    #[test]
    fn test_mint_request_from_burn_row() {
        let row = BurnRequestRow {
            id: "burn-from-row".to_string(),
            wallet_address: "wallet111".to_string(),
            misaka_receive_address: "msk1recv111".to_string(),
            mint_address: "mint111".to_string(),
            burn_amount_raw: 500_000,
            solana_tx_signature: "txsig111".to_string(),
            slot: 100,
            block_time: 1700000000,
            status: "verified".to_string(),
            error_message: None,
            attempt_count: 0,
            created_at: "2024-01-01".to_string(),
            updated_at: "2024-01-01".to_string(),
        };

        let attestations = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let req = MintRequest::from_burn_row(&row, attestations.clone());
        assert_eq!(req.burn_id, "burn-from-row");
        assert_eq!(req.recipient_address, "msk1recv111");
        assert_eq!(req.amount_raw, 500_000);
        assert_eq!(req.attestations.len(), 2);
    }

    #[test]
    fn test_mint_error_display() {
        let err = MintError::NetworkError("timeout".to_string());
        assert!(err.to_string().contains("timeout"));

        let err = MintError::AlreadyMinted("burn-123".to_string());
        assert!(err.to_string().contains("burn-123"));
    }
}
