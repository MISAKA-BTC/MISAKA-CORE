//! Consensus manager: coordinates consensus lifecycle across
//! multiple consensus instances during IBD, pruning, and chain switches.

use std::sync::Arc;
use parking_lot::RwLock;

/// Consensus processing status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusStatus {
    /// Initial Block Download in progress.
    Syncing,
    /// Fully synced and processing new blocks.
    Steady,
    /// Performing a pruning operation.
    Pruning,
    /// Performing a chain reorganization.
    Reorganizing,
    /// Consensus is stopped.
    Stopped,
}

/// Consensus session — represents a snapshot of consensus state.
#[derive(Debug, Clone)]
pub struct ConsensusSession {
    pub id: u64,
    pub status: ConsensusStatus,
    pub virtual_daa_score: u64,
    pub sink_blue_score: u64,
    pub tip_count: usize,
    pub header_count: u64,
    pub block_count: u64,
}

/// Manages consensus instances and orchestrates processing.
pub struct ConsensusManager {
    status: RwLock<ConsensusStatus>,
    current_session: RwLock<Option<ConsensusSession>>,
    session_counter: std::sync::atomic::AtomicU64,
}

impl ConsensusManager {
    pub fn new() -> Self {
        Self {
            status: RwLock::new(ConsensusStatus::Stopped),
            current_session: RwLock::new(None),
            session_counter: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Start a new consensus session.
    pub fn start_session(&self) -> u64 {
        let id = self.session_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        *self.status.write() = ConsensusStatus::Syncing;
        *self.current_session.write() = Some(ConsensusSession {
            id,
            status: ConsensusStatus::Syncing,
            virtual_daa_score: 0,
            sink_blue_score: 0,
            tip_count: 0,
            header_count: 0,
            block_count: 0,
        });
        id
    }

    /// Transition to steady state.
    pub fn mark_synced(&self) {
        *self.status.write() = ConsensusStatus::Steady;
        if let Some(ref mut session) = *self.current_session.write() {
            session.status = ConsensusStatus::Steady;
        }
    }

    /// Get current status.
    pub fn status(&self) -> ConsensusStatus {
        *self.status.read()
    }

    /// Get current session info.
    pub fn session(&self) -> Option<ConsensusSession> {
        self.current_session.read().clone()
    }

    /// Update session stats.
    pub fn update_stats(&self, daa_score: u64, blue_score: u64, tips: usize, headers: u64, blocks: u64) {
        if let Some(ref mut session) = *self.current_session.write() {
            session.virtual_daa_score = daa_score;
            session.sink_blue_score = blue_score;
            session.tip_count = tips;
            session.header_count = headers;
            session.block_count = blocks;
        }
    }

    /// Check if consensus is ready for new blocks.
    pub fn is_ready(&self) -> bool {
        matches!(*self.status.read(), ConsensusStatus::Steady)
    }

    /// Begin a pruning operation.
    pub fn begin_pruning(&self) -> bool {
        let mut status = self.status.write();
        if *status != ConsensusStatus::Steady { return false; }
        *status = ConsensusStatus::Pruning;
        true
    }

    /// End a pruning operation.
    pub fn end_pruning(&self) {
        *self.status.write() = ConsensusStatus::Steady;
    }

    /// Stop consensus.
    pub fn stop(&self) {
        *self.status.write() = ConsensusStatus::Stopped;
        *self.current_session.write() = None;
    }
}

impl Default for ConsensusManager {
    fn default() -> Self { Self::new() }
}
