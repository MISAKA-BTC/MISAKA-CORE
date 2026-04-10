// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Network protocol layer for Narwhal consensus.
//!
//! Sui equivalent: consensus/core/network.rs + authority_service.rs (~2,500 lines)
//!
//! Defines the consensus network protocol as async traits, with an
//! HTTP/JSON implementation (aligned with MISAKA's existing sync RPC).
//! Can be replaced with gRPC/anemo for production.
//!
//! ## Protocol Messages
//!
//! | Endpoint | Direction | Description |
//! |----------|-----------|-------------|
//! | SendBlock | Authority → All | Broadcast proposed block |
//! | FetchBlocks | Authority → Authority | Request missing blocks |
//! | FetchCommits | Authority → Authority | Request missing commits |
//! | SubscribeBlocks | Bidirectional | Stream new blocks |

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

use super::metrics::ConsensusMetrics;
use crate::narwhal_types::block::*;
use crate::narwhal_types::commit::*;
use crate::narwhal_types::committee::Committee;

// ═══════════════════════════════════════════════════════════
//  Network trait
// ═══════════════════════════════════════════════════════════

/// Consensus network service — defines the protocol interface.
///
/// Implemented as concrete methods on `HttpNetworkService`.
/// Future: can be made into a trait with `async-trait` crate for
/// gRPC/anemo implementations.
///
/// Protocol methods:
/// - `send_block_to`: Send block to specific peer
/// - `broadcast_block_to_all`: Broadcast to all reachable peers
/// - `fetch_blocks_from`: Fetch blocks by round range
/// - `fetch_commits_from`: Fetch commits by index range
/// - `relay_transaction`: Relay TX to all peers

/// Network errors.
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("peer not found: authority {0}")]
    PeerNotFound(AuthorityIndex),
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("request timeout")]
    Timeout,
    #[error("peer returned error: {status} {body}")]
    PeerError { status: u16, body: String },
    #[error("deserialization error: {0}")]
    DeserializationError(String),
    #[error("channel closed")]
    ChannelClosed,
}

// ═══════════════════════════════════════════════════════════
//  Peer info
// ═══════════════════════════════════════════════════════════

/// Signed peer record for verified peer discovery.
///
/// Contains the peer's transport public key for MITM protection.
/// Gossiped between peers to populate transport_pubkey for verified dials.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PeerRecord {
    /// Authority index of this peer.
    pub authority: AuthorityIndex,
    /// HTTP/TCP endpoint URL.
    pub endpoint: String,
    /// ML-DSA-65 transport public key (1952 bytes).
    /// Used for MITM-protected dials (SEC-C1).
    pub transport_pubkey: Vec<u8>,
    /// Epoch when this record was created.
    pub epoch: u64,
    /// ML-DSA-65 signature over (authority || endpoint || transport_pubkey || epoch).
    pub signature: Vec<u8>,
}

impl PeerRecord {
    /// Compute the signing payload.
    /// SEC-FIX: Added domain separation prefix and length-prefixed fields.
    /// Previously raw-concatenated without domain tag, allowing potential
    /// cross-context collision (short endpoint + long pubkey = long endpoint + short pubkey).
    pub fn signing_payload(&self) -> Vec<u8> {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:peer_record:v2:");
        h.update(&self.authority.to_le_bytes());
        h.update(&(self.endpoint.len() as u32).to_le_bytes());
        h.update(self.endpoint.as_bytes());
        h.update(&(self.transport_pubkey.len() as u32).to_le_bytes());
        h.update(&self.transport_pubkey);
        h.update(&self.epoch.to_le_bytes());
        h.finalize().to_vec()
    }
}

/// Peer connection info.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    /// Authority index.
    pub authority: AuthorityIndex,
    /// HTTP endpoint URL.
    pub endpoint: String,
    /// Whether this peer is currently reachable.
    pub is_reachable: bool,
    /// Number of successful requests.
    pub successes: u64,
    /// Number of failed requests.
    pub failures: u64,
    /// Transport public key (from PeerRecord gossip, if available).
    /// When set, outbound connections can verify the peer's identity.
    pub transport_pubkey: Option<Vec<u8>>,
}

impl PeerInfo {
    pub fn new(authority: AuthorityIndex, endpoint: String) -> Self {
        Self {
            authority,
            endpoint,
            is_reachable: true,
            successes: 0,
            failures: 0,
            transport_pubkey: None,
        }
    }

    /// Create from a verified PeerRecord.
    pub fn from_peer_record(record: &PeerRecord) -> Self {
        Self {
            authority: record.authority,
            endpoint: record.endpoint.clone(),
            is_reachable: true,
            successes: 0,
            failures: 0,
            transport_pubkey: Some(record.transport_pubkey.clone()),
        }
    }

    /// Peer quality score (0.0 = terrible, 1.0 = perfect).
    pub fn quality(&self) -> f64 {
        let total = self.successes + self.failures;
        if total == 0 {
            return 0.5;
        }
        self.successes as f64 / total as f64
    }
}

// ═══════════════════════════════════════════════════════════
//  HTTP Network Service
// ═══════════════════════════════════════════════════════════

/// HTTP/JSON network service — implements the consensus protocol
/// over MISAKA's existing sync RPC layer.
pub struct HttpNetworkService {
    /// Peer connection info, indexed by authority.
    peers: RwLock<HashMap<AuthorityIndex, PeerInfo>>,
    /// HTTP client with connection pooling.
    client: reqwest::Client,
    /// Metrics.
    metrics: Arc<ConsensusMetrics>,
    /// Our authority index (to exclude self from broadcast).
    our_authority: AuthorityIndex,
}

impl HttpNetworkService {
    pub fn new(
        our_authority: AuthorityIndex,
        peers: Vec<(AuthorityIndex, String)>,
        metrics: Arc<ConsensusMetrics>,
        timeout: Duration,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .pool_max_idle_per_host(5)
            .build()
            .unwrap_or_default();

        let peer_map: HashMap<AuthorityIndex, PeerInfo> = peers
            .into_iter()
            .map(|(auth, url)| (auth, PeerInfo::new(auth, url)))
            .collect();

        Self {
            peers: RwLock::new(peer_map),
            client,
            metrics,
            our_authority,
        }
    }

    async fn get_peer_url(&self, peer: AuthorityIndex) -> Result<String, NetworkError> {
        let peers = self.peers.read().await;
        peers
            .get(&peer)
            .map(|p| p.endpoint.clone())
            .ok_or(NetworkError::PeerNotFound(peer))
    }

    async fn record_success(&self, peer: AuthorityIndex) {
        let mut peers = self.peers.write().await;
        if let Some(p) = peers.get_mut(&peer) {
            p.successes += 1;
            p.is_reachable = true;
        }
    }

    /// Handle a received PeerRecord — update peer info with transport public key.
    ///
    /// This enables MITM-protected dials to the peer.
    pub async fn handle_peer_record(
        &self,
        record: &PeerRecord,
        verifier: &dyn crate::narwhal_types::block::SignatureVerifier,
    ) -> Result<(), NetworkError> {
        // Verify the PeerRecord signature
        let payload = record.signing_payload();
        verifier
            .verify(&record.transport_pubkey, &payload, &record.signature)
            .map_err(|e| {
                NetworkError::ConnectionFailed(format!("PeerRecord signature invalid: {}", e))
            })?;

        // Update or insert peer info
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(&record.authority) {
            peer.transport_pubkey = Some(record.transport_pubkey.clone());
            peer.endpoint = record.endpoint.clone();
            info!(
                "PeerRecord: updated transport_pubkey for authority {}",
                record.authority
            );
        } else {
            peers.insert(record.authority, PeerInfo::from_peer_record(record));
            info!(
                "PeerRecord: discovered new peer authority {} at {}",
                record.authority, record.endpoint
            );
        }

        Ok(())
    }

    async fn record_failure(&self, peer: AuthorityIndex) {
        let mut peers = self.peers.write().await;
        if let Some(p) = peers.get_mut(&peer) {
            p.failures += 1;
            if p.failures > 10 && p.quality() < 0.3 {
                p.is_reachable = false;
            }
        }
    }

    /// Get peers sorted by quality (best first).
    pub async fn peers_by_quality(&self) -> Vec<PeerInfo> {
        let peers = self.peers.read().await;
        let mut sorted: Vec<PeerInfo> = peers.values().cloned().collect();
        sorted.sort_by(|a, b| {
            b.quality()
                .partial_cmp(&a.quality())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        sorted
    }

    /// Ban a peer (mark as unreachable).
    pub async fn ban_peer(&self, peer: AuthorityIndex) {
        let mut peers = self.peers.write().await;
        if let Some(p) = peers.get_mut(&peer) {
            p.is_reachable = false;
            warn!("Peer {} banned (quality: {:.2})", peer, p.quality());
        }
    }

    /// Unban a peer.
    pub async fn unban_peer(&self, peer: AuthorityIndex) {
        let mut peers = self.peers.write().await;
        if let Some(p) = peers.get_mut(&peer) {
            p.is_reachable = true;
            p.failures = 0;
            info!("Peer {} unbanned", peer);
        }
    }
}

// We can't use async_trait without the crate, so implement manually with boxed futures
// For now, provide concrete async methods (not trait impl) since async_trait isn't in deps
impl HttpNetworkService {
    /// Send a block to a specific peer.
    pub async fn send_block_to(
        &self,
        peer: AuthorityIndex,
        block: &Block,
    ) -> Result<(), NetworkError> {
        let url = self.get_peer_url(peer).await?;
        let endpoint = format!("{}/api/sync/submit_block", url);

        match self
            .client
            .post(&endpoint)
            .json(&serde_json::json!({
                "block": block,
            }))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                self.record_success(peer).await;
                ConsensusMetrics::inc(&self.metrics.sync_fetches_completed);
                Ok(())
            }
            Ok(resp) => {
                self.record_failure(peer).await;
                Err(NetworkError::PeerError {
                    status: resp.status().as_u16(),
                    body: resp.text().await.unwrap_or_default(),
                })
            }
            Err(e) => {
                self.record_failure(peer).await;
                ConsensusMetrics::inc(&self.metrics.sync_fetches_failed);
                if e.is_timeout() {
                    Err(NetworkError::Timeout)
                } else {
                    Err(NetworkError::ConnectionFailed(e.to_string()))
                }
            }
        }
    }

    /// Broadcast a block to all reachable peers.
    pub async fn broadcast_block_to_all(
        &self,
        block: &Block,
    ) -> Vec<(AuthorityIndex, Result<(), NetworkError>)> {
        let peers: Vec<(AuthorityIndex, String)> = {
            let peers = self.peers.read().await;
            peers
                .values()
                .filter(|p| p.is_reachable && p.authority != self.our_authority)
                .map(|p| (p.authority, p.endpoint.clone()))
                .collect()
        };

        let mut results = Vec::new();
        let mut handles = Vec::new();

        for (authority, url) in peers {
            let client = self.client.clone();
            let block_json = serde_json::to_value(block).unwrap_or_default();
            let metrics = self.metrics.clone();

            handles.push((
                authority,
                tokio::spawn(async move {
                    let endpoint = format!("{}/api/sync/submit_block", url);
                    match client
                        .post(&endpoint)
                        .json(&serde_json::json!({"block": block_json}))
                        .send()
                        .await
                    {
                        Ok(resp) if resp.status().is_success() => {
                            ConsensusMetrics::inc(&metrics.sync_fetches_completed);
                            Ok(())
                        }
                        Ok(resp) => Err(NetworkError::PeerError {
                            status: resp.status().as_u16(),
                            body: String::new(),
                        }),
                        Err(e) => {
                            ConsensusMetrics::inc(&metrics.sync_fetches_failed);
                            Err(NetworkError::ConnectionFailed(e.to_string()))
                        }
                    }
                }),
            ));
        }

        for (authority, handle) in handles {
            let result = match handle.await {
                Ok(r) => {
                    if r.is_ok() {
                        self.record_success(authority).await;
                    } else {
                        self.record_failure(authority).await;
                    }
                    r
                }
                Err(_) => Err(NetworkError::ConnectionFailed("task panicked".into())),
            };
            results.push((authority, result));
        }

        results
    }

    /// Fetch blocks from a peer by round range.
    pub async fn fetch_blocks_from(
        &self,
        peer: AuthorityIndex,
        since_round: Round,
        limit: usize,
    ) -> Result<Vec<Block>, NetworkError> {
        let url = self.get_peer_url(peer).await?;
        let endpoint = format!(
            "{}/api/sync/blocks?since={}&limit={}",
            url, since_round, limit
        );

        let resp = self.client.get(&endpoint).send().await.map_err(|e| {
            ConsensusMetrics::inc(&self.metrics.sync_fetches_failed);
            if e.is_timeout() {
                NetworkError::Timeout
            } else {
                NetworkError::ConnectionFailed(e.to_string())
            }
        })?;

        if !resp.status().is_success() {
            self.record_failure(peer).await;
            return Err(NetworkError::PeerError {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        let data: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| NetworkError::DeserializationError(e.to_string()))?;

        let blocks: Vec<Block> = data["blocks"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| serde_json::from_value(v.clone()).ok())
                    .collect()
            })
            .unwrap_or_default();

        self.record_success(peer).await;
        ConsensusMetrics::inc(&self.metrics.sync_fetches_completed);
        debug!(
            "Fetched {} blocks from peer {} (since round {})",
            blocks.len(),
            peer,
            since_round
        );

        Ok(blocks)
    }

    /// Fetch commits from a peer.
    pub async fn fetch_commits_from(
        &self,
        peer: AuthorityIndex,
        since_index: CommitIndex,
        limit: usize,
    ) -> Result<Vec<CommittedSubDag>, NetworkError> {
        let url = self.get_peer_url(peer).await?;
        let endpoint = format!(
            "{}/api/sync/commits?since={}&limit={}",
            url, since_index, limit
        );

        let resp = self
            .client
            .get(&endpoint)
            .send()
            .await
            .map_err(|e| NetworkError::ConnectionFailed(e.to_string()))?;

        if !resp.status().is_success() {
            self.record_failure(peer).await;
            return Err(NetworkError::PeerError {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        let data: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| NetworkError::DeserializationError(e.to_string()))?;

        let commits: Vec<CommittedSubDag> = data["commits"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| serde_json::from_value(v.clone()).ok())
                    .collect()
            })
            .unwrap_or_default();

        self.record_success(peer).await;
        Ok(commits)
    }

    /// Relay a transaction to all peers.
    pub async fn relay_transaction(&self, tx_hex: &str) {
        let peers: Vec<String> = {
            let peers = self.peers.read().await;
            peers
                .values()
                .filter(|p| p.is_reachable && p.authority != self.our_authority)
                .map(|p| p.endpoint.clone())
                .collect()
        };

        for url in peers {
            let client = self.client.clone();
            let tx = tx_hex.to_string();
            tokio::spawn(async move {
                let endpoint = format!("{}/api/sync/relay_tx", url);
                let _ = client
                    .post(&endpoint)
                    .json(&serde_json::json!({"tx": tx}))
                    .send()
                    .await;
            });
        }
    }
    /// Broadcast equivocation evidence to all reachable peers (WP8).
    ///
    /// Evidence is sent as a JSON array to `/api/sync/equivocation_evidence`.
    /// Receivers must verify both signatures before merging into their
    /// local `SlotEquivocationLedger`.
    pub async fn broadcast_equivocation_evidence(
        &self,
        evidence: &[super::slot_equivocation_ledger::SlotEquivocationEvidence],
    ) {
        if evidence.is_empty() {
            return;
        }

        let peers: Vec<String> = {
            let peers = self.peers.read().await;
            peers
                .values()
                .filter(|p| p.is_reachable && p.authority != self.our_authority)
                .map(|p| p.endpoint.clone())
                .collect()
        };

        let evidence_json = serde_json::to_value(evidence).unwrap_or_default();
        let num_peers = peers.len();

        for url in peers {
            let client = self.client.clone();
            let payload = evidence_json.clone();
            tokio::spawn(async move {
                let endpoint = format!("{}/api/sync/equivocation_evidence", url);
                let _ = client
                    .post(&endpoint)
                    .json(&serde_json::json!({"evidence": payload}))
                    .send()
                    .await;
            });
        }

        info!(
            count = evidence.len(),
            "Broadcast equivocation evidence to {} peers", num_peers
        );
    }
}

// ═══════════════════════════════════════════════════════════
//  Authority service (inbound handler)
// ═══════════════════════════════════════════════════════════

/// Handles incoming consensus messages from peers.
///
/// Sui equivalent: authority_service.rs (~600 lines)
///
/// Plugs into the node's axum RPC server to handle:
/// - POST /api/sync/submit_block
/// - GET  /api/sync/blocks?since=N&limit=M
/// - GET  /api/sync/commits?since=N&limit=M
pub struct AuthorityService {
    /// Channel to forward received blocks to the consensus runtime.
    block_tx: mpsc::Sender<super::runtime::ConsensusMessage>,
    /// DAG state (read-only access for serving block/commit requests).
    dag_state: Arc<RwLock<super::dag_state::DagState>>,
    /// Metrics.
    metrics: Arc<ConsensusMetrics>,
}

impl AuthorityService {
    pub fn new(
        block_tx: mpsc::Sender<super::runtime::ConsensusMessage>,
        dag_state: Arc<RwLock<super::dag_state::DagState>>,
        metrics: Arc<ConsensusMetrics>,
    ) -> Self {
        Self {
            block_tx,
            dag_state,
            metrics,
        }
    }

    /// Handle an incoming block from a peer.
    ///
    /// SEC-FIX: blocks_accepted metric is NOT incremented here — it was
    /// previously counted before verification, allowing attackers to inflate
    /// the metric with forged blocks. The runtime's process_block now owns
    /// the metric after successful verification.
    pub fn handle_block(&self, block: Block) -> Result<(), NetworkError> {
        let vb = VerifiedBlock::new_pending_verification(block);
        self.block_tx
            .try_send(super::runtime::ConsensusMessage::NewBlock(vb))
            .map_err(|_| NetworkError::ChannelClosed)?;
        Ok(())
    }

    /// Handle a blocks request.
    pub async fn handle_fetch_blocks(&self, since_round: Round, limit: usize) -> Vec<Block> {
        let dag = self.dag_state.read().await;
        let mut blocks = Vec::new();
        let highest = dag.highest_accepted_round();
        let limit = limit.min(1000); // cap

        for round in since_round..=highest {
            for block in dag.get_blocks_at_round(round) {
                blocks.push(block.inner().clone());
                if blocks.len() >= limit {
                    return blocks;
                }
            }
        }

        blocks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_info_quality() {
        let mut p = PeerInfo::new(0, "http://localhost:3000".into());
        assert_eq!(p.quality(), 0.5); // no data

        p.successes = 8;
        p.failures = 2;
        assert!((p.quality() - 0.8).abs() < 0.01);

        p.successes = 0;
        p.failures = 10;
        assert!((p.quality() - 0.0).abs() < 0.01);
    }

    #[test]
    fn test_http_network_service_creation() {
        let metrics = Arc::new(ConsensusMetrics::new());
        let service = HttpNetworkService::new(
            0,
            vec![
                (1, "http://peer1:3000".into()),
                (2, "http://peer2:3000".into()),
            ],
            metrics,
            Duration::from_secs(10),
        );
        // our_authority is 0, peers are 1 and 2
        assert_eq!(service.our_authority, 0);
    }

    #[tokio::test]
    async fn test_peer_scoring() {
        let metrics = Arc::new(ConsensusMetrics::new());
        let service = HttpNetworkService::new(
            0,
            vec![
                (1, "http://peer1:3000".into()),
                (2, "http://peer2:3000".into()),
            ],
            metrics,
            Duration::from_secs(10),
        );

        // Record some successes and failures
        for _ in 0..10 {
            service.record_success(1).await;
        }
        for _ in 0..3 {
            service.record_failure(2).await;
        }
        for _ in 0..7 {
            service.record_success(2).await;
        }

        let sorted = service.peers_by_quality().await;
        assert_eq!(sorted[0].authority, 1); // 10/10 = 1.0
        assert_eq!(sorted[1].authority, 2); // 7/10 = 0.7
    }

    #[tokio::test]
    async fn test_ban_unban_peer() {
        let metrics = Arc::new(ConsensusMetrics::new());
        let service = HttpNetworkService::new(
            0,
            vec![(1, "http://peer1:3000".into())],
            metrics,
            Duration::from_secs(10),
        );

        service.ban_peer(1).await;
        {
            let peers = service.peers.read().await;
            assert!(!peers[&1].is_reachable);
        }

        service.unban_peer(1).await;
        {
            let peers = service.peers.read().await;
            assert!(peers[&1].is_reachable);
        }
    }
}
