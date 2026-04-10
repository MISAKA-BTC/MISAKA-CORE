// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! SyncFetcher — async network layer for block synchronization.
//!
//! Executes `SyncRequest`s produced by the `Synchronizer` by fetching
//! blocks from peers via the HTTP sync RPC protocol.
//!
//! Peers are addressed by authority index, mapped to HTTP endpoints.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::metrics::ConsensusMetrics;
use super::synchronizer::{SyncRequest, Synchronizer, SynchronizerConfig};
use crate::narwhal_types::block::*;
use crate::narwhal_types::committee::Committee;

/// Peer endpoint information.
#[derive(Clone, Debug)]
pub struct PeerEndpoint {
    /// Authority index.
    pub authority: AuthorityIndex,
    /// HTTP base URL (e.g., "http://163.43.225.27:3001").
    pub url: String,
}

/// Configuration for the sync fetcher.
#[derive(Clone, Debug)]
pub struct SyncFetcherConfig {
    /// HTTP request timeout.
    pub request_timeout: Duration,
    /// Maximum concurrent fetch tasks.
    pub max_concurrent_fetches: usize,
    /// Interval between sync ticks (ms).
    pub sync_interval_ms: u64,
}

impl Default for SyncFetcherConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(10),
            max_concurrent_fetches: 10,
            sync_interval_ms: 1000,
        }
    }
}

/// Async block fetcher — executes sync requests over HTTP.
pub struct SyncFetcher {
    /// Peer endpoints indexed by authority.
    peers: HashMap<AuthorityIndex, PeerEndpoint>,
    /// HTTP client.
    client: reqwest::Client,
    /// Config.
    config: SyncFetcherConfig,
    /// Metrics.
    metrics: Arc<ConsensusMetrics>,
}

impl SyncFetcher {
    pub fn new(
        peers: Vec<PeerEndpoint>,
        config: SyncFetcherConfig,
        metrics: Arc<ConsensusMetrics>,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .build()
            .unwrap_or_default();

        let peer_map: HashMap<AuthorityIndex, PeerEndpoint> =
            peers.into_iter().map(|p| (p.authority, p)).collect();

        Self {
            peers: peer_map,
            client,
            config,
            metrics,
        }
    }

    /// Fetch blocks for a sync request from a specific peer.
    ///
    /// Returns the raw block JSON responses.
    pub async fn fetch_blocks(
        &self,
        request: &SyncRequest,
    ) -> Result<Vec<serde_json::Value>, SyncFetchError> {
        let peer = self
            .peers
            .get(&request.peer)
            .ok_or(SyncFetchError::UnknownPeer(request.peer))?;

        // Build query: request blocks by their digests
        let digests: Vec<String> = request
            .missing_refs
            .iter()
            .map(|r| hex::encode(r.digest.0))
            .collect();

        let url = format!("{}/api/sync/blocks", peer.url);
        debug!(
            "Fetching {} blocks from {} ({})",
            digests.len(),
            peer.url,
            peer.authority
        );

        let resp = self
            .client
            .post(&url)
            .json(&serde_json::json!({
                "digests": digests,
                "since": request.missing_refs.iter().map(|r| r.round).min().unwrap_or(0),
                "limit": request.missing_refs.len(),
            }))
            .send()
            .await
            .map_err(|e| SyncFetchError::Network(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(SyncFetchError::HttpError(resp.status().as_u16()));
        }

        let data: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SyncFetchError::ParseError(e.to_string()))?;

        let blocks = data["blocks"].as_array().cloned().unwrap_or_default();

        ConsensusMetrics::inc(&self.metrics.sync_fetches_completed);
        debug!("Received {} blocks from {}", blocks.len(), peer.url);

        Ok(blocks)
    }

    /// Fetch blocks from multiple peers, preferring the block's author.
    /// Falls back to other peers on failure.
    pub async fn fetch_with_fallback(
        &self,
        request: &SyncRequest,
    ) -> Result<Vec<serde_json::Value>, SyncFetchError> {
        // Try primary peer (block author)
        match self.fetch_blocks(request).await {
            Ok(blocks) if !blocks.is_empty() => return Ok(blocks),
            Ok(_) => {
                debug!(
                    "Primary peer {} returned no blocks, trying fallback",
                    request.peer
                );
            }
            Err(e) => {
                warn!(
                    "Primary peer {} failed: {}, trying fallback",
                    request.peer, e
                );
                ConsensusMetrics::inc(&self.metrics.sync_fetches_failed);
            }
        }

        // Fallback: try other peers
        for (&authority, _peer) in &self.peers {
            if authority == request.peer {
                continue;
            }

            let fallback_request = SyncRequest {
                peer: authority,
                ..request.clone()
            };

            match self.fetch_blocks(&fallback_request).await {
                Ok(blocks) if !blocks.is_empty() => return Ok(blocks),
                Ok(_) => continue,
                Err(_) => {
                    ConsensusMetrics::inc(&self.metrics.sync_fetches_failed);
                    continue;
                }
            }
        }

        Err(SyncFetchError::AllPeersFailed)
    }

    /// Broadcast a block to all peers.
    pub async fn broadcast_block(&self, block_json: &serde_json::Value) {
        for peer in self.peers.values() {
            let url = format!("{}/api/sync/submit_block", peer.url);
            match self.client.post(&url).json(block_json).send().await {
                Ok(_) => debug!("Broadcast block to {}", peer.url),
                Err(e) => warn!("Failed to broadcast to {}: {}", peer.url, e),
            }
        }
    }

    /// Relay a transaction to all peers.
    pub async fn relay_transaction(&self, tx_hex: &str) {
        for peer in self.peers.values() {
            let url = format!("{}/api/sync/relay_tx", peer.url);
            let _ = self
                .client
                .post(&url)
                .json(&serde_json::json!({"tx": tx_hex}))
                .send()
                .await;
        }
    }

    /// Number of known peers.
    pub fn num_peers(&self) -> usize {
        self.peers.len()
    }

    /// Get peer URL for an authority.
    pub fn peer_url(&self, authority: AuthorityIndex) -> Option<&str> {
        self.peers.get(&authority).map(|p| p.url.as_str())
    }
}

/// Sync fetch errors.
#[derive(Debug, thiserror::Error)]
pub enum SyncFetchError {
    #[error("unknown peer: authority {0}")]
    UnknownPeer(AuthorityIndex),
    #[error("network error: {0}")]
    Network(String),
    #[error("HTTP error: {0}")]
    HttpError(u16),
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("all peers failed")]
    AllPeersFailed,
}

/// Runs the sync loop — periodically checks for missing blocks and fetches them.
///
/// Integrates Synchronizer (state tracking) with SyncFetcher (network).
pub async fn run_sync_loop(
    mut synchronizer: Synchronizer,
    fetcher: Arc<SyncFetcher>,
    missing_rx: mpsc::Receiver<Vec<BlockRef>>,
    block_tx: mpsc::Sender<super::runtime::ConsensusMessage>,
    config: SyncFetcherConfig,
) {
    let mut missing_rx = missing_rx;
    let interval = Duration::from_millis(config.sync_interval_ms);

    info!("Sync loop started ({} peers)", fetcher.num_peers());

    loop {
        tokio::select! {
            // Receive new missing blocks from block manager
            missing = missing_rx.recv() => {
                match missing {
                    Some(refs) => {
                        let requests = synchronizer.schedule_fetch(&refs);
                        for request in requests {
                            let fetcher = fetcher.clone();
                            let block_tx = block_tx.clone();
                            tokio::spawn(async move {
                                match fetcher.fetch_with_fallback(&request).await {
                                    Ok(blocks) => {
                                        debug!("Sync fetched {} blocks", blocks.len());
                                        for block_json in blocks {
                                            match serde_json::from_value::<crate::narwhal_types::block::Block>(block_json) {
                                                Ok(block) => {
                                                    // SEC: Block from sync peer — not yet verified.
                                                    // core_engine::process_block verifies at step 1.
                                                    let vb = crate::narwhal_types::block::VerifiedBlock::new_pending_verification(block);
                                                    if block_tx.try_send(
                                                        super::runtime::ConsensusMessage::NewBlock(vb)
                                                    ).is_err() {
                                                        warn!("Sync: consensus message channel closed");
                                                        return;
                                                    }
                                                }
                                                Err(e) => {
                                                    warn!("Sync: failed to parse block: {}", e);
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Sync fetch failed: {}", e);
                                    }
                                }
                            });
                        }
                    }
                    None => {
                        info!("Sync loop: missing channel closed, stopping");
                        break;
                    }
                }
            }

            // Periodic timeout expiry
            _ = tokio::time::sleep(interval) => {
                let expired = synchronizer.expire_timed_out();
                if !expired.is_empty() {
                    debug!("Sync: {} requests timed out, will retry", expired.len());
                    let requests = synchronizer.schedule_fetch(&expired);
                    for request in requests {
                        let fetcher = fetcher.clone();
                        tokio::spawn(async move {
                            let _ = fetcher.fetch_with_fallback(&request).await;
                        });
                    }
                }
            }
        }
    }

    info!("Sync loop stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_endpoint() {
        let metrics = Arc::new(ConsensusMetrics::new());
        let fetcher = SyncFetcher::new(
            vec![
                PeerEndpoint {
                    authority: 0,
                    url: "http://localhost:3001".to_string(),
                },
                PeerEndpoint {
                    authority: 1,
                    url: "http://localhost:3002".to_string(),
                },
            ],
            SyncFetcherConfig::default(),
            metrics,
        );
        assert_eq!(fetcher.num_peers(), 2);
        assert_eq!(fetcher.peer_url(0), Some("http://localhost:3001"));
        assert_eq!(fetcher.peer_url(99), None);
    }
}
