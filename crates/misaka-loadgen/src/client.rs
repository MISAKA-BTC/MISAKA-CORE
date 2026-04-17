// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! LoadgenClient trait and mock implementation.

use std::time::Duration;

use crate::error::LoadgenError;

/// Accepted tx response.
#[derive(Debug, Clone)]
pub struct TxAccepted {
    pub tx_hash: [u8; 32],
}

/// Trait for submitting transactions to a MISAKA node.
///
/// The loadgen uses this to decouple from the actual transport.
/// Production: HttpJsonRpcClient. Tests: MockClient.
#[async_trait::async_trait]
pub trait LoadgenClient: Send + Sync {
    async fn submit_tx(&self, tx_bytes: Vec<u8>) -> Result<TxAccepted, LoadgenError>;
}

/// Mock client for unit testing (no network).
pub struct MockClient {
    pub accept_rate: f64, // 0.0 = reject all, 1.0 = accept all
    pub latency: Duration,
    seed: u64,
}

impl MockClient {
    pub fn new(accept_rate: f64, latency: Duration) -> Self {
        Self {
            accept_rate,
            latency,
            seed: 0,
        }
    }

    pub fn always_accept() -> Self {
        Self::new(1.0, Duration::from_millis(1))
    }

    pub fn reject_half() -> Self {
        Self::new(0.5, Duration::from_millis(1))
    }
}

#[async_trait::async_trait]
impl LoadgenClient for MockClient {
    async fn submit_tx(&self, tx_bytes: Vec<u8>) -> Result<TxAccepted, LoadgenError> {
        if !self.latency.is_zero() {
            tokio::time::sleep(self.latency).await;
        }

        // Deterministic accept/reject based on SHA3 of tx bytes
        use sha3::{Digest, Sha3_256};
        let hash = Sha3_256::digest(&tx_bytes);
        let hash_byte = hash[0];
        let threshold = (self.accept_rate * 256.0) as u8;
        if hash_byte < threshold {
            let mut tx_hash = [0u8; 32];
            tx_hash[..tx_bytes.len().min(32)].copy_from_slice(&tx_bytes[..tx_bytes.len().min(32)]);
            Ok(TxAccepted { tx_hash })
        } else {
            Err(LoadgenError::TxRejected {
                reason: "mock rejection".into(),
            })
        }
    }
}
