//! Stratum-compatible mining protocol for MISAKA.
//!
//! While MISAKA uses PoS, this module provides stratum compatibility
//! for the heavy hash PoW component used in hybrid consensus periods.
//! Also used for CPU mining during initial network bootstrap.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Stratum server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StratumConfig {
    pub listen_addr: String,
    pub max_connections: usize,
    pub target_update_interval_ms: u64,
    pub share_difficulty: f64,
    pub vardiff_enabled: bool,
    pub vardiff_target_shares_per_min: f64,
    pub vardiff_min: f64,
    pub vardiff_max: f64,
}

impl Default for StratumConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:16112".to_string(),
            max_connections: 10_000,
            target_update_interval_ms: 500,
            share_difficulty: 1.0,
            vardiff_enabled: true,
            vardiff_target_shares_per_min: 20.0,
            vardiff_min: 0.001,
            vardiff_max: 1_000_000.0,
        }
    }
}

/// Stratum protocol messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StratumRequest {
    pub id: u64,
    pub method: String,
    pub params: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StratumResponse {
    pub id: u64,
    pub result: serde_json::Value,
    pub error: Option<StratumError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StratumError {
    pub code: i32,
    pub message: String,
}

/// Connected miner session.
pub struct MinerSession {
    pub id: u64,
    pub worker_name: String,
    pub address: String,
    pub difficulty: f64,
    pub shares_accepted: u64,
    pub shares_rejected: u64,
    pub shares_stale: u64,
    pub hashrate_estimate: f64,
    pub connected_at: u64,
    pub last_share_at: u64,
    pub extra_nonce: u32,
    pub subscribed: bool,
    pub authorized: bool,
}

/// Mining job for stratum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningJob {
    pub job_id: String,
    pub prev_hash: String,
    pub coinbase_prefix: String,
    pub coinbase_suffix: String,
    pub merkle_branches: Vec<String>,
    pub version: String,
    pub nbits: String,
    pub ntime: String,
    pub clean_jobs: bool,
}

/// Share submitted by a miner.
#[derive(Debug, Clone)]
pub struct ShareSubmission {
    pub worker_name: String,
    pub job_id: String,
    pub nonce: String,
    pub ntime: String,
    pub extra_nonce2: String,
}

/// Share validation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareResult {
    Accepted,
    AcceptedBlock, // Share also found a block
    Rejected(ShareRejectReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareRejectReason {
    Stale,
    DuplicateShare,
    LowDifficulty,
    InvalidNonce,
    InvalidJob,
    Unauthorized,
}

/// Stratum server state.
pub struct StratumServer {
    config: StratumConfig,
    sessions: RwLock<HashMap<u64, MinerSession>>,
    current_job: RwLock<Option<MiningJob>>,
    next_session_id: std::sync::atomic::AtomicU64,
    next_extra_nonce: std::sync::atomic::AtomicU32,
    total_shares: std::sync::atomic::AtomicU64,
    total_blocks: std::sync::atomic::AtomicU64,
    #[allow(dead_code)]
    job_counter: std::sync::atomic::AtomicU64,
}

impl StratumServer {
    pub fn new(config: StratumConfig) -> Self {
        Self {
            config,
            sessions: RwLock::new(HashMap::new()),
            current_job: RwLock::new(None),
            next_session_id: std::sync::atomic::AtomicU64::new(1),
            next_extra_nonce: std::sync::atomic::AtomicU32::new(1),
            total_shares: std::sync::atomic::AtomicU64::new(0),
            total_blocks: std::sync::atomic::AtomicU64::new(0),
            job_counter: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Handle a new miner connection.
    pub fn connect(&self) -> Option<u64> {
        let sessions = self.sessions.read();
        if sessions.len() >= self.config.max_connections {
            return None;
        }
        drop(sessions);

        let id = self
            .next_session_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let extra_nonce = self
            .next_extra_nonce
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        self.sessions.write().insert(
            id,
            MinerSession {
                id,
                worker_name: String::new(),
                address: String::new(),
                difficulty: self.config.share_difficulty,
                shares_accepted: 0,
                shares_rejected: 0,
                shares_stale: 0,
                hashrate_estimate: 0.0,
                connected_at: now_secs(),
                last_share_at: 0,
                extra_nonce,
                subscribed: false,
                authorized: false,
            },
        );
        Some(id)
    }

    /// Handle mining.subscribe.
    pub fn handle_subscribe(&self, session_id: u64) -> Option<(u32, u32)> {
        let mut sessions = self.sessions.write();
        let session = sessions.get_mut(&session_id)?;
        session.subscribed = true;
        Some((session.extra_nonce, 4)) // extra_nonce1, extra_nonce2_size
    }

    /// Handle mining.authorize.
    pub fn handle_authorize(&self, session_id: u64, worker: &str, _password: &str) -> bool {
        let mut sessions = self.sessions.write();
        if let Some(session) = sessions.get_mut(&session_id) {
            // Parse worker name: address.worker_name
            let parts: Vec<&str> = worker.splitn(2, '.').collect();
            if parts.is_empty() {
                return false;
            }
            session.address = parts[0].to_string();
            session.worker_name = parts.get(1).unwrap_or(&"default").to_string();
            session.authorized = true;
            // Validate address format
            session.address.starts_with("misaka")
        } else {
            false
        }
    }

    /// Handle mining.submit (share submission).
    pub fn handle_submit(&self, session_id: u64, share: ShareSubmission) -> ShareResult {
        let mut sessions = self.sessions.write();
        let session = match sessions.get_mut(&session_id) {
            Some(s) => s,
            None => return ShareResult::Rejected(ShareRejectReason::Unauthorized),
        };

        if !session.authorized {
            return ShareResult::Rejected(ShareRejectReason::Unauthorized);
        }

        // Validate job
        let current_job = self.current_job.read();
        if current_job
            .as_ref()
            .map_or(true, |j| j.job_id != share.job_id)
        {
            session.shares_stale += 1;
            return ShareResult::Rejected(ShareRejectReason::Stale);
        }

        // Validate share difficulty (stub)
        session.shares_accepted += 1;
        session.last_share_at = now_secs();
        self.total_shares
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Update hashrate estimate
        let elapsed = now_secs().saturating_sub(session.connected_at).max(1);
        session.hashrate_estimate =
            session.shares_accepted as f64 * session.difficulty / elapsed as f64;

        ShareResult::Accepted
    }

    /// Update the current mining job.
    pub fn update_job(&self, job: MiningJob) {
        *self.current_job.write() = Some(job);
    }

    /// Disconnect a miner.
    pub fn disconnect(&self, session_id: u64) {
        self.sessions.write().remove(&session_id);
    }

    /// Get server statistics.
    pub fn stats(&self) -> StratumStats {
        let sessions = self.sessions.read();
        let connected = sessions.len();
        let authorized = sessions.values().filter(|s| s.authorized).count();
        let total_hashrate: f64 = sessions.values().map(|s| s.hashrate_estimate).sum();
        let total_accepted: u64 = sessions.values().map(|s| s.shares_accepted).sum();
        let total_rejected: u64 = sessions.values().map(|s| s.shares_rejected).sum();

        StratumStats {
            connected_miners: connected,
            authorized_miners: authorized,
            total_hashrate,
            total_shares_accepted: total_accepted,
            total_shares_rejected: total_rejected,
            total_blocks_found: self.total_blocks.load(std::sync::atomic::Ordering::Relaxed),
            has_current_job: self.current_job.read().is_some(),
        }
    }

    /// Variable difficulty adjustment for a session.
    pub fn adjust_difficulty(&self, session_id: u64) -> Option<f64> {
        if !self.config.vardiff_enabled {
            return None;
        }
        let mut sessions = self.sessions.write();
        let session = sessions.get_mut(&session_id)?;

        let elapsed = now_secs().saturating_sub(session.connected_at).max(60);
        let shares_per_min = session.shares_accepted as f64 / (elapsed as f64 / 60.0);

        let target = self.config.vardiff_target_shares_per_min;
        let ratio = shares_per_min / target;

        let new_diff = if ratio > 2.0 {
            (session.difficulty * ratio * 0.8).min(self.config.vardiff_max)
        } else if ratio < 0.5 {
            (session.difficulty * ratio * 1.2).max(self.config.vardiff_min)
        } else {
            return None; // No adjustment needed
        };

        session.difficulty = new_diff;
        Some(new_diff)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StratumStats {
    pub connected_miners: usize,
    pub authorized_miners: usize,
    pub total_hashrate: f64,
    pub total_shares_accepted: u64,
    pub total_shares_rejected: u64,
    pub total_blocks_found: u64,
    pub has_current_job: bool,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
