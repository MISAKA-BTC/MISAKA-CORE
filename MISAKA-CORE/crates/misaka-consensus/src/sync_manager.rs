//! Consensus sync manager — coordinates initial block download (IBD)
//! and ongoing block synchronization.
//!
//! # Sync States
//! 1. IBD Headers: Download block headers from peers
//! 2. IBD Bodies: Download block bodies for validated headers
//! 3. IBD UTXO: Download UTXO set snapshot (if pruning point available)
//! 4. Normal: Process new blocks as they arrive

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};

/// Sync state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncPhase {
    Idle,
    HeadersFirst,
    BodiesDownload,
    UtxoSetDownload,
    Normal,
    Stalled,
}

/// Sync progress tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusSyncProgress {
    pub phase: SyncPhase,
    pub headers_received: u64,
    pub bodies_received: u64,
    pub utxo_entries_received: u64,
    pub target_daa_score: u64,
    pub current_daa_score: u64,
    pub progress_percent: f64,
    pub peers_syncing_from: usize,
    pub estimated_remaining_secs: u64,
    pub bytes_downloaded: u64,
    pub download_rate_bps: f64,
}

/// Peer sync state.
#[derive(Debug, Clone)]
pub struct PeerSyncState {
    pub peer_id: String,
    pub their_daa_score: u64,
    pub their_blue_score: u64,
    pub is_syncing: bool,
    pub headers_requested: u64,
    pub headers_received: u64,
    pub bodies_requested: u64,
    pub bodies_received: u64,
    pub last_request_time: Instant,
    pub avg_response_ms: f64,
    pub error_count: u32,
    pub stall_count: u32,
}

/// IBD request tracking.
pub struct IBDRequest {
    pub request_id: u64,
    pub peer_id: String,
    pub hashes: Vec<[u8; 32]>,
    pub sent_at: Instant,
    pub request_type: IBDRequestType,
}

#[derive(Debug, Clone, Copy)]
pub enum IBDRequestType {
    Headers,
    Bodies,
    UtxoSet,
    PruningProof,
}

/// Consensus sync manager.
pub struct ConsensusSyncManager {
    phase: SyncPhase,
    peers: HashMap<String, PeerSyncState>,
    pending_requests: HashMap<u64, IBDRequest>,
    next_request_id: u64,
    config: SyncManagerConfig,
    start_time: Option<Instant>,
    bytes_downloaded: u64,
    headers_received: u64,
    bodies_received: u64,
    stall_detector: StallDetector,
}

#[derive(Debug, Clone)]
pub struct SyncManagerConfig {
    pub max_headers_per_request: u32,
    pub max_bodies_per_request: u32,
    pub request_timeout: Duration,
    pub max_concurrent_requests: usize,
    pub max_retries: u32,
    pub stall_timeout: Duration,
    pub preferred_peers: usize,
}

impl Default for SyncManagerConfig {
    fn default() -> Self {
        Self {
            max_headers_per_request: 2000,
            max_bodies_per_request: 100,
            request_timeout: Duration::from_secs(30),
            max_concurrent_requests: 8,
            max_retries: 3,
            stall_timeout: Duration::from_secs(120),
            preferred_peers: 3,
        }
    }
}

struct StallDetector {
    last_progress_time: Instant,
    last_progress_score: u64,
    stall_timeout: Duration,
}

impl StallDetector {
    fn new(timeout: Duration) -> Self {
        Self {
            last_progress_time: Instant::now(),
            last_progress_score: 0,
            stall_timeout: timeout,
        }
    }

    fn record_progress(&mut self, score: u64) {
        if score > self.last_progress_score {
            self.last_progress_time = Instant::now();
            self.last_progress_score = score;
        }
    }

    fn is_stalled(&self) -> bool {
        self.last_progress_time.elapsed() > self.stall_timeout
    }
}

impl ConsensusSyncManager {
    pub fn new(config: SyncManagerConfig) -> Self {
        let stall_timeout = config.stall_timeout;
        Self {
            phase: SyncPhase::Idle,
            peers: HashMap::new(),
            pending_requests: HashMap::new(),
            next_request_id: 1,
            config,
            start_time: None,
            bytes_downloaded: 0,
            headers_received: 0,
            bodies_received: 0,
            stall_detector: StallDetector::new(stall_timeout),
        }
    }

    /// Register a peer for sync.
    pub fn add_peer(&mut self, peer_id: String, daa_score: u64, blue_score: u64) {
        self.peers.insert(peer_id.clone(), PeerSyncState {
            peer_id,
            their_daa_score: daa_score,
            their_blue_score: blue_score,
            is_syncing: false,
            headers_requested: 0,
            headers_received: 0,
            bodies_requested: 0,
            bodies_received: 0,
            last_request_time: Instant::now(),
            avg_response_ms: 0.0,
            error_count: 0,
            stall_count: 0,
        });
    }

    /// Remove a peer.
    pub fn remove_peer(&mut self, peer_id: &str) {
        self.peers.remove(peer_id);
        self.pending_requests.retain(|_, r| r.peer_id != peer_id);
    }

    /// Start initial block download.
    pub fn start_ibd(&mut self, our_daa_score: u64) {
        self.phase = SyncPhase::HeadersFirst;
        self.start_time = Some(Instant::now());
        tracing::info!("Starting IBD from DAA score {}", our_daa_score);
    }

    /// Transition to normal sync.
    pub fn transition_to_normal(&mut self) {
        self.phase = SyncPhase::Normal;
        if let Some(start) = self.start_time {
            tracing::info!("IBD complete in {:.1}s", start.elapsed().as_secs_f64());
        }
    }

    /// Record received headers.
    pub fn record_headers(&mut self, count: u64, from_peer: &str, bytes: u64) {
        self.headers_received += count;
        self.bytes_downloaded += bytes;
        if let Some(peer) = self.peers.get_mut(from_peer) {
            peer.headers_received += count;
        }
    }

    /// Record received bodies.
    pub fn record_bodies(&mut self, count: u64, from_peer: &str, bytes: u64) {
        self.bodies_received += count;
        self.bytes_downloaded += bytes;
        if let Some(peer) = self.peers.get_mut(from_peer) {
            peer.bodies_received += count;
        }
    }

    /// Get sync progress.
    pub fn progress(&self, current_score: u64, target_score: u64) -> ConsensusSyncProgress {
        let progress = if target_score > 0 {
            (current_score as f64 / target_score as f64 * 100.0).min(100.0)
        } else { 100.0 };

        let elapsed = self.start_time.map(|s| s.elapsed().as_secs_f64()).unwrap_or(1.0);
        let rate = self.bytes_downloaded as f64 / elapsed;
        let remaining_score = target_score.saturating_sub(current_score);
        let est_remaining = if self.headers_received > 0 {
            (remaining_score as f64 / (current_score as f64 / elapsed)) as u64
        } else { 0 };

        ConsensusSyncProgress {
            phase: self.phase,
            headers_received: self.headers_received,
            bodies_received: self.bodies_received,
            utxo_entries_received: 0,
            target_daa_score: target_score,
            current_daa_score: current_score,
            progress_percent: progress,
            peers_syncing_from: self.peers.values().filter(|p| p.is_syncing).count(),
            estimated_remaining_secs: est_remaining,
            bytes_downloaded: self.bytes_downloaded,
            download_rate_bps: rate,
        }
    }

    /// Check for timed-out requests.
    pub fn check_timeouts(&mut self) -> Vec<u64> {
        let timeout = self.config.request_timeout;
        let timed_out: Vec<u64> = self.pending_requests.iter()
            .filter(|(_, r)| r.sent_at.elapsed() > timeout)
            .map(|(id, _)| *id)
            .collect();

        for id in &timed_out {
            if let Some(req) = self.pending_requests.remove(id) {
                if let Some(peer) = self.peers.get_mut(&req.peer_id) {
                    peer.stall_count += 1;
                    peer.error_count += 1;
                }
            }
        }
        timed_out
    }

    /// Get best peers for syncing (sorted by score and responsiveness).
    pub fn best_peers(&self, count: usize) -> Vec<String> {
        let mut peers: Vec<_> = self.peers.values().collect();
        peers.sort_by(|a, b| {
            b.their_daa_score.cmp(&a.their_daa_score)
                .then(a.avg_response_ms.partial_cmp(&b.avg_response_ms).unwrap_or(std::cmp::Ordering::Equal))
                .then(a.error_count.cmp(&b.error_count))
        });
        peers.iter().take(count).map(|p| p.peer_id.clone()).collect()
    }

    pub fn phase(&self) -> SyncPhase { self.phase }
    pub fn peer_count(&self) -> usize { self.peers.len() }
    pub fn pending_request_count(&self) -> usize { self.pending_requests.len() }
}
