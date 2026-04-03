//! Weak Subjectivity — long-range attack prevention for PoS.
//!
//! # Problem
//!
//! In PoS, old validators who have exited and withdrawn their stake can
//! retroactively create an alternative chain from a point in the past.
//! This is costless because they no longer have stake to slash.
//!
//! BTC doesn't have this problem because PoW requires ongoing energy expenditure.
//! Kaspa's DAG makes it even harder because parallel blocks are merged.
//!
//! # Solution: Weak Subjectivity Checkpoints
//!
//! 1. Nodes joining the network MUST provide a trusted checkpoint
//! 2. Blocks below the checkpoint are unconditionally accepted
//! 3. Alternative chains branching before the checkpoint are rejected
//! 4. The checkpoint must be within the "weak subjectivity period"
//!
//! # Weak Subjectivity Period
//!
//! The maximum number of epochs a node can be offline and still safely
//! sync without a new checkpoint. After this period, the node MUST
//! obtain a fresh checkpoint from a trusted source.
//!
//! `ws_period ≈ unbonding_period × safety_margin`
//!
//! During unbonding, validators are still subject to slashing.
//! After unbonding completes, they can create costless alternative chains.
//! Therefore, ws_period ≤ unbonding_period.
//!
//! # Trust Model
//!
//! - User obtains checkpoint from multiple independent sources
//! - Block explorer (misakascan.com), official channels, peer nodes
//! - If all sources agree, the checkpoint is trusted
//! - This is the same trust model as downloading the Bitcoin client

use serde::{Deserialize, Serialize};

use super::economic_finality::FinalityCheckpoint;

// ═══════════════════════════════════════════════════════════════
//  Weak Subjectivity Checkpoint
// ═══════════════════════════════════════════════════════════════

/// A trusted checkpoint for weak subjectivity.
///
/// New nodes MUST configure this before starting sync.
/// It anchors the node's view of the canonical chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeakSubjectivityCheckpoint {
    /// The finality checkpoint hash.
    pub block_hash: [u8; 32],
    /// Epoch of the checkpoint.
    pub epoch: u64,
    /// State root at the checkpoint.
    pub state_root: [u8; 32],
}

impl WeakSubjectivityCheckpoint {
    /// Genesis weak subjectivity checkpoint (no prior history needed).
    pub fn genesis(genesis_hash: [u8; 32]) -> Self {
        Self {
            block_hash: genesis_hash,
            epoch: 0,
            state_root: [0u8; 32],
        }
    }

    /// Create from a finality checkpoint.
    pub fn from_finality_checkpoint(cp: &FinalityCheckpoint) -> Self {
        Self {
            block_hash: cp.block_hash,
            epoch: cp.epoch,
            state_root: cp.state_root,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Weak Subjectivity Validator
// ═══════════════════════════════════════════════════════════════

/// Validates blocks against weak subjectivity constraints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeakSubjectivityGuard {
    /// The trusted checkpoint.
    checkpoint: WeakSubjectivityCheckpoint,
    /// Weak subjectivity period (epochs).
    /// A node offline longer than this MUST obtain a new checkpoint.
    pub ws_period_epochs: u64,
    /// Whether the guard is enabled (disabled for genesis node / first sync).
    pub enabled: bool,
}

impl WeakSubjectivityGuard {
    /// Create a guard with a trusted checkpoint.
    pub fn new(checkpoint: WeakSubjectivityCheckpoint, ws_period_epochs: u64) -> Self {
        Self {
            checkpoint,
            ws_period_epochs,
            enabled: true,
        }
    }

    /// Create a disabled guard (for genesis bootstrapping).
    pub fn disabled() -> Self {
        Self {
            checkpoint: WeakSubjectivityCheckpoint::genesis([0u8; 32]),
            ws_period_epochs: 0,
            enabled: false,
        }
    }

    /// Default mainnet configuration.
    /// ws_period = unbonding_period = 10080 epochs (≈7 days).
    pub fn mainnet(checkpoint: WeakSubjectivityCheckpoint) -> Self {
        Self::new(checkpoint, 10_080)
    }

    /// Check if a block is below the weak subjectivity boundary.
    ///
    /// Returns `Err` if the block attempts to rewrite history before
    /// the trusted checkpoint.
    pub fn validate_block_epoch(&self, block_epoch: u64) -> Result<(), WeakSubjectivityError> {
        if !self.enabled {
            return Ok(());
        }

        // Blocks at or below checkpoint epoch must match the checkpoint
        if block_epoch < self.checkpoint.epoch {
            return Err(WeakSubjectivityError::BelowCheckpoint {
                block_epoch,
                checkpoint_epoch: self.checkpoint.epoch,
            });
        }

        Ok(())
    }

    /// Check if a finality checkpoint is consistent with our trusted checkpoint.
    ///
    /// If the incoming checkpoint is at the same epoch, hashes must match.
    /// If at a higher epoch, it's accepted (will be validated by BFT).
    pub fn validate_checkpoint(
        &self,
        incoming: &FinalityCheckpoint,
    ) -> Result<(), WeakSubjectivityError> {
        if !self.enabled {
            return Ok(());
        }

        if incoming.epoch == self.checkpoint.epoch
            && incoming.block_hash != self.checkpoint.block_hash
        {
            return Err(WeakSubjectivityError::CheckpointConflict {
                epoch: incoming.epoch,
                expected: hex::encode(self.checkpoint.block_hash),
                got: hex::encode(incoming.block_hash),
            });
        }

        if incoming.epoch < self.checkpoint.epoch {
            return Err(WeakSubjectivityError::BelowCheckpoint {
                block_epoch: incoming.epoch,
                checkpoint_epoch: self.checkpoint.epoch,
            });
        }

        Ok(())
    }

    /// Check if our checkpoint is still within the weak subjectivity period.
    ///
    /// `current_epoch`: the latest known epoch from peers.
    /// If current_epoch - checkpoint.epoch > ws_period, the node needs
    /// a fresh checkpoint before it can safely sync.
    pub fn is_checkpoint_stale(&self, current_epoch: u64) -> bool {
        if !self.enabled || self.ws_period_epochs == 0 {
            return false;
        }
        current_epoch.saturating_sub(self.checkpoint.epoch) > self.ws_period_epochs
    }

    /// Update the trusted checkpoint (after verifying a newer BFT finality).
    pub fn update_checkpoint(&mut self, new_checkpoint: WeakSubjectivityCheckpoint) {
        if new_checkpoint.epoch > self.checkpoint.epoch {
            self.checkpoint = new_checkpoint;
        }
    }

    pub fn checkpoint(&self) -> &WeakSubjectivityCheckpoint {
        &self.checkpoint
    }
}

// ═══════════════════════════════════════════════════════════════
//  Errors
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum WeakSubjectivityError {
    #[error("block epoch {block_epoch} is below weak subjectivity checkpoint (epoch {checkpoint_epoch})")]
    BelowCheckpoint {
        block_epoch: u64,
        checkpoint_epoch: u64,
    },
    #[error("checkpoint conflict at epoch {epoch}: expected {expected}, got {got}")]
    CheckpointConflict {
        epoch: u64,
        expected: String,
        got: String,
    },
    #[error("weak subjectivity checkpoint is stale — obtain a fresh checkpoint")]
    StaleCheckpoint,
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cp(epoch: u64, hash_byte: u8) -> FinalityCheckpoint {
        FinalityCheckpoint {
            epoch,
            block_hash: [hash_byte; 32],
            blue_score: epoch * 100,
            state_root: [0; 32],
            cumulative_txs: epoch * 50,
        }
    }

    #[test]
    fn test_genesis_accepts_everything() {
        let guard = WeakSubjectivityGuard::disabled();
        assert!(guard.validate_block_epoch(0).is_ok());
        assert!(guard.validate_block_epoch(999).is_ok());
    }

    #[test]
    fn test_reject_below_checkpoint() {
        let ws_cp = WeakSubjectivityCheckpoint {
            block_hash: [0xAA; 32],
            epoch: 100,
            state_root: [0; 32],
        };
        let guard = WeakSubjectivityGuard::new(ws_cp, 10_080);

        assert!(guard.validate_block_epoch(99).is_err());
        assert!(guard.validate_block_epoch(100).is_ok());
        assert!(guard.validate_block_epoch(101).is_ok());
    }

    #[test]
    fn test_checkpoint_conflict() {
        let ws_cp = WeakSubjectivityCheckpoint {
            block_hash: [0xAA; 32],
            epoch: 100,
            state_root: [0; 32],
        };
        let guard = WeakSubjectivityGuard::new(ws_cp, 10_080);

        // Same epoch, different hash → conflict
        let conflicting = make_cp(100, 0xBB);
        assert!(guard.validate_checkpoint(&conflicting).is_err());

        // Same epoch, same hash → ok
        let matching = make_cp(100, 0xAA);
        assert!(guard.validate_checkpoint(&matching).is_ok());

        // Higher epoch → ok (will be validated by BFT)
        let future = make_cp(200, 0xCC);
        assert!(guard.validate_checkpoint(&future).is_ok());
    }

    #[test]
    fn test_stale_checkpoint() {
        let ws_cp = WeakSubjectivityCheckpoint {
            block_hash: [0xAA; 32],
            epoch: 100,
            state_root: [0; 32],
        };
        let guard = WeakSubjectivityGuard::new(ws_cp, 1000);

        assert!(!guard.is_checkpoint_stale(500));
        assert!(!guard.is_checkpoint_stale(1100));
        assert!(guard.is_checkpoint_stale(1101)); // 1101 - 100 = 1001 > 1000
    }

    #[test]
    fn test_update_checkpoint() {
        let ws_cp = WeakSubjectivityCheckpoint {
            block_hash: [0xAA; 32],
            epoch: 100,
            state_root: [0; 32],
        };
        let mut guard = WeakSubjectivityGuard::new(ws_cp, 1000);

        let new_cp = WeakSubjectivityCheckpoint {
            block_hash: [0xBB; 32],
            epoch: 200,
            state_root: [1; 32],
        };
        guard.update_checkpoint(new_cp);
        assert_eq!(guard.checkpoint().epoch, 200);

        // Older checkpoint should not replace newer
        let old_cp = WeakSubjectivityCheckpoint {
            block_hash: [0xCC; 32],
            epoch: 150,
            state_root: [2; 32],
        };
        guard.update_checkpoint(old_cp);
        assert_eq!(guard.checkpoint().epoch, 200); // unchanged
    }
}
