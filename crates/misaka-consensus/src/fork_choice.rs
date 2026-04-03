//! Hybrid Fork Choice — GhostDAG + BFT Finality Anchor.
//!
//! # Architecture
//!
//! ```text
//! ┌───────────────────────────────────────────────────┐
//! │                  Fork Choice                      │
//! │                                                   │
//! │  ┌──────────────┐    ┌─────────────────────────┐  │
//! │  │  BFT Finality │    │   GhostDAG Ordering     │  │
//! │  │  (absolute)   │    │   (probabilistic)       │  │
//! │  │               │    │                         │  │
//! │  │  Checkpoints  │───►│  SPC above finality tip │  │
//! │  │  are forever  │    │  Reorgs allowed here    │  │
//! │  └──────────────┘    └─────────────────────────┘  │
//! │                                                   │
//! │  Rule priority:                                   │
//! │  1. BFT finalized → absolute (never reorg)        │
//! │  2. GhostDAG SPC → blue_score weighted            │
//! │  3. Tiebreaker → block_hash lexicographic          │
//! └───────────────────────────────────────────────────┘
//! ```
//!
//! # Security Properties
//!
//! | Attack | Defense |
//! |--------|---------|
//! | Long-range | BFT checkpoint = reorg boundary. Cannot rewrite past finality. |
//! | Balancing | GhostDAG k-cluster + honest majority → longest blue chain. |
//! | Nothing-at-stake | BFT equivocation → slash. Single vote per (slot, round). |
//! | Sybil | PoS: 10M MISAKA minimum stake. Proportional representation. |
//!
//! # Integration Points
//!
//! - `misaka-dag::ghostdag_v2` — DAG ordering (Selected Parent Chain)
//! - `misaka-consensus::economic_finality` — BFT finality checkpoints
//! - `misaka-consensus::bft_state_machine` — BFT commit events

use serde::{Deserialize, Serialize};

use super::bft_types::{BftCommit, Hash};
use super::economic_finality::FinalityCheckpoint;

// ═══════════════════════════════════════════════════════════════
//  Fork Choice State
// ═══════════════════════════════════════════════════════════════

/// Hybrid fork choice state.
///
/// Maintains the finality boundary and provides the fork choice rule
/// for blocks above the boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkChoiceState {
    /// Latest BFT-finalized checkpoint. All blocks at or below this
    /// blue_score are irreversible.
    pub finalized_checkpoint: FinalityCheckpoint,

    /// Current chain tip (highest blue_score on the Selected Parent Chain).
    pub chain_tip: ChainTip,

    /// Justified checkpoint — highest checkpoint with prevote polka
    /// but not yet finalized. Used for Casper FFG justification.
    pub justified_checkpoint: Option<FinalityCheckpoint>,
}

/// Current chain tip information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainTip {
    pub block_hash: Hash,
    pub blue_score: u64,
    pub slot: u64,
    pub height: u64,
}

impl ForkChoiceState {
    /// Create initial fork choice state from genesis.
    pub fn genesis(genesis_hash: Hash) -> Self {
        let genesis_checkpoint = FinalityCheckpoint {
            epoch: 0,
            block_hash: genesis_hash,
            blue_score: 0,
            state_root: [0u8; 32],
            cumulative_txs: 0,
        };
        Self {
            finalized_checkpoint: genesis_checkpoint,
            chain_tip: ChainTip {
                block_hash: genesis_hash,
                blue_score: 0,
                slot: 0,
                height: 0,
            },
            justified_checkpoint: None,
        }
    }

    /// Whether a block is below the finality boundary.
    ///
    /// Blocks at or below `finalized_checkpoint.blue_score` are irreversible.
    /// Any attempt to reorg below this point MUST be rejected.
    pub fn is_below_finality(&self, blue_score: u64) -> bool {
        blue_score <= self.finalized_checkpoint.blue_score
    }

    /// Reference to the current finalized checkpoint.
    pub fn finalized_checkpoint_ref(&self) -> Option<&FinalityCheckpoint> {
        if self.finalized_checkpoint.epoch == 0 && self.finalized_checkpoint.blue_score == 0 {
            None // Genesis — no real finality yet
        } else {
            Some(&self.finalized_checkpoint)
        }
    }

    /// Simplified finality update from a FinalityCheckpoint directly.
    ///
    /// Used by the BFT driver when it has a pre-built checkpoint.
    pub fn on_bft_finality(&mut self, checkpoint: FinalityCheckpoint) {
        if checkpoint.blue_score > self.finalized_checkpoint.blue_score {
            self.finalized_checkpoint = checkpoint;
            self.justified_checkpoint = None;
        }
    }

    /// Update finality after a BFT commit.
    ///
    /// # Invariants
    ///
    /// - New checkpoint epoch MUST be > current finalized epoch.
    /// - New checkpoint blue_score MUST be > current finalized blue_score.
    /// - The commit's precommit QC must have been verified before calling this.
    ///
    /// # Returns
    ///
    /// The old finalized checkpoint (for pruning).
    pub fn on_bft_commit(
        &mut self,
        commit: &BftCommit,
        state_root: Hash,
        cumulative_txs: u64,
    ) -> Result<FinalityCheckpoint, ForkChoiceError> {
        let new_checkpoint = FinalityCheckpoint {
            epoch: self.finalized_checkpoint.epoch + 1,
            block_hash: commit.block_hash,
            blue_score: commit.dag_checkpoint.blue_score,
            state_root,
            cumulative_txs,
        };

        // Monotonicity check
        if new_checkpoint.blue_score <= self.finalized_checkpoint.blue_score {
            return Err(ForkChoiceError::FinalityRegression {
                current_score: self.finalized_checkpoint.blue_score,
                proposed_score: new_checkpoint.blue_score,
            });
        }

        let old = self.finalized_checkpoint.clone();
        self.finalized_checkpoint = new_checkpoint;

        // Promote justified → finalized if applicable
        self.justified_checkpoint = None;

        Ok(old)
    }

    /// Update chain tip from GhostDAG.
    ///
    /// The new tip must be above the finality boundary.
    pub fn update_chain_tip(&mut self, tip: ChainTip) -> Result<(), ForkChoiceError> {
        if self.is_below_finality(tip.blue_score) {
            return Err(ForkChoiceError::TipBelowFinality {
                tip_score: tip.blue_score,
                finality_score: self.finalized_checkpoint.blue_score,
            });
        }
        self.chain_tip = tip;
        Ok(())
    }

    /// Fork choice comparison between two candidate tips.
    ///
    /// # Rules (in priority order)
    ///
    /// 1. Both must be above finality boundary
    /// 2. Higher blue_score wins (GhostDAG rule)
    /// 3. Tiebreaker: lexicographically smaller block_hash wins (deterministic)
    pub fn compare_tips(a: &ChainTip, b: &ChainTip) -> std::cmp::Ordering {
        // Higher blue_score is preferred
        match a.blue_score.cmp(&b.blue_score) {
            std::cmp::Ordering::Equal => {
                // Tiebreaker: smaller hash wins (Kaspa convention)
                b.block_hash.cmp(&a.block_hash)
            }
            other => other,
        }
    }

    /// Check if a block should be accepted.
    ///
    /// Rejects blocks that would conflict with finality.
    pub fn should_accept_block(
        &self,
        block_hash: Hash,
        blue_score: u64,
        parents: &[Hash],
    ) -> Result<(), ForkChoiceError> {
        // Block itself must be above finality
        if blue_score <= self.finalized_checkpoint.blue_score {
            return Err(ForkChoiceError::BlockBelowFinality {
                block_hash,
                block_score: blue_score,
                finality_score: self.finalized_checkpoint.blue_score,
            });
        }

        // At least one parent must be above or at finality tip
        // (allows blocks that reference the finalized tip as parent)
        // In GhostDAG, blocks can have multiple parents, so we just need
        // the selected parent to be above finality.
        // The detailed parent validation is done by GhostDAG itself.

        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════
//  Weak Subjectivity
// ═══════════════════════════════════════════════════════════════

/// Weak subjectivity checkpoint for initial sync.
///
/// A new node MUST be bootstrapped with a trusted checkpoint.
/// Without this, a long-range attack can present a fake chain
/// to the new node.
///
/// # Distribution
///
/// Operators should obtain checkpoints from:
/// 1. misakascan.com (block explorer)
/// 2. Multiple independent node operators
/// 3. The MISAKA project's official channels
///
/// # Expiry
///
/// A weak subjectivity checkpoint expires after `WEAK_SUBJECTIVITY_PERIOD`.
/// This period must be <= unbonding_period (10,080 epochs ≈ 7 days).
/// After expiry, a new checkpoint must be obtained.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeakSubjectivityCheckpoint {
    pub epoch: u64,
    pub block_hash: Hash,
    pub state_root: Hash,
}

/// Weak subjectivity period in epochs.
///
/// This MUST be <= unbonding_period to prevent long-range attacks.
/// Validators who have exited cannot create fake chains after this period
/// because their unbonding is complete and they have no stake to slash.
pub const WEAK_SUBJECTIVITY_PERIOD: u64 = 10_080; // matches unbonding_period

impl WeakSubjectivityCheckpoint {
    /// Validate that a checkpoint is not expired.
    pub fn is_valid(&self, current_epoch: u64) -> bool {
        current_epoch <= self.epoch + WEAK_SUBJECTIVITY_PERIOD
    }

    /// Verify initial sync against this checkpoint.
    ///
    /// The synced state's finalized checkpoint must match or extend
    /// the weak subjectivity checkpoint.
    pub fn verify_sync_state(
        &self,
        synced_finalized: &FinalityCheckpoint,
    ) -> Result<(), ForkChoiceError> {
        // The synced state must be at or beyond our checkpoint
        if synced_finalized.epoch < self.epoch {
            return Err(ForkChoiceError::WeakSubjectivityViolation {
                ws_epoch: self.epoch,
                synced_epoch: synced_finalized.epoch,
            });
        }

        // If at the same epoch, block hashes must match
        if synced_finalized.epoch == self.epoch
            && synced_finalized.block_hash != self.block_hash
        {
            return Err(ForkChoiceError::WeakSubjectivityConflict {
                ws_hash: self.block_hash,
                synced_hash: synced_finalized.block_hash,
            });
        }

        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════
//  Errors
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum ForkChoiceError {
    #[error("finality regression: current blue_score={current_score}, proposed={proposed_score}")]
    FinalityRegression {
        current_score: u64,
        proposed_score: u64,
    },
    #[error("chain tip below finality: tip={tip_score}, finality={finality_score}")]
    TipBelowFinality {
        tip_score: u64,
        finality_score: u64,
    },
    #[error(
        "block {} below finality: score={block_score}, finality={finality_score}",
        hex::encode(block_hash)
    )]
    BlockBelowFinality {
        block_hash: Hash,
        block_score: u64,
        finality_score: u64,
    },
    #[error("weak subjectivity violation: ws_epoch={ws_epoch}, synced={synced_epoch}")]
    WeakSubjectivityViolation {
        ws_epoch: u64,
        synced_epoch: u64,
    },
    #[error(
        "weak subjectivity conflict: ws_hash={}, synced_hash={}",
        hex::encode(ws_hash),
        hex::encode(synced_hash)
    )]
    WeakSubjectivityConflict {
        ws_hash: Hash,
        synced_hash: Hash,
    },
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::bft_types::*;
    use misaka_types::validator::DagCheckpointTarget;

    fn genesis_state() -> ForkChoiceState {
        ForkChoiceState::genesis([0x00; 32])
    }

    fn make_commit(slot: u64, blue_score: u64, hash: Hash) -> BftCommit {
        BftCommit {
            slot,
            round: 0,
            block_hash: hash,
            dag_checkpoint: DagCheckpointTarget {
                block_hash: hash,
                blue_score,
                utxo_root: [0; 32],
                total_key_images: 0,
                total_applied_txs: 0,
            },
            precommit_qc: QuorumCertificate {
                qc_type: QcType::Precommit,
                slot,
                round: 0,
                block_hash: Some(hash),
                votes: vec![],
                total_weight: 1000,
            },
        }
    }

    #[test]
    fn test_genesis_state() {
        let state = genesis_state();
        assert_eq!(state.finalized_checkpoint.epoch, 0);
        assert_eq!(state.finalized_checkpoint.blue_score, 0);
        assert!(!state.is_below_finality(1)); // score 1 is above genesis
        assert!(state.is_below_finality(0));  // score 0 is at genesis
    }

    #[test]
    fn test_on_bft_commit_advances_finality() {
        let mut state = genesis_state();
        let commit = make_commit(100, 500, [0xAA; 32]);

        let old = state
            .on_bft_commit(&commit, [0xBB; 32], 1000)
            .expect("commit should succeed");

        assert_eq!(old.epoch, 0);
        assert_eq!(state.finalized_checkpoint.epoch, 1);
        assert_eq!(state.finalized_checkpoint.blue_score, 500);
        assert_eq!(state.finalized_checkpoint.block_hash, [0xAA; 32]);
    }

    #[test]
    fn test_finality_regression_rejected() {
        let mut state = genesis_state();
        state.on_bft_commit(&make_commit(100, 500, [0xAA; 32]), [0; 32], 0)
            .unwrap();

        // Try to commit at a lower blue_score → must fail
        let result = state.on_bft_commit(&make_commit(101, 400, [0xBB; 32]), [0; 32], 0);
        assert!(matches!(
            result,
            Err(ForkChoiceError::FinalityRegression { .. })
        ));
    }

    #[test]
    fn test_block_below_finality_rejected() {
        let mut state = genesis_state();
        state.on_bft_commit(&make_commit(100, 500, [0xAA; 32]), [0; 32], 0)
            .unwrap();

        // Block at blue_score 300 → below finality
        let result = state.should_accept_block([0xCC; 32], 300, &[]);
        assert!(matches!(
            result,
            Err(ForkChoiceError::BlockBelowFinality { .. })
        ));

        // Block at blue_score 600 → above finality → accepted
        assert!(state.should_accept_block([0xDD; 32], 600, &[]).is_ok());
    }

    #[test]
    fn test_compare_tips_higher_score_wins() {
        let a = ChainTip {
            block_hash: [0xAA; 32],
            blue_score: 100,
            slot: 100,
            height: 100,
        };
        let b = ChainTip {
            block_hash: [0xBB; 32],
            blue_score: 200,
            slot: 200,
            height: 200,
        };
        assert_eq!(
            ForkChoiceState::compare_tips(&b, &a),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn test_compare_tips_tiebreaker() {
        let a = ChainTip {
            block_hash: [0x01; 32], // smaller hash
            blue_score: 100,
            slot: 100,
            height: 100,
        };
        let b = ChainTip {
            block_hash: [0xFF; 32], // larger hash
            blue_score: 100,
            slot: 100,
            height: 100,
        };
        // Smaller hash wins
        assert_eq!(
            ForkChoiceState::compare_tips(&a, &b),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn test_weak_subjectivity_valid() {
        let ws = WeakSubjectivityCheckpoint {
            epoch: 100,
            block_hash: [0xAA; 32],
            state_root: [0xBB; 32],
        };
        assert!(ws.is_valid(100)); // same epoch
        assert!(ws.is_valid(100 + WEAK_SUBJECTIVITY_PERIOD)); // at boundary
        assert!(!ws.is_valid(100 + WEAK_SUBJECTIVITY_PERIOD + 1)); // expired
    }

    #[test]
    fn test_weak_subjectivity_verify_sync() {
        let ws = WeakSubjectivityCheckpoint {
            epoch: 100,
            block_hash: [0xAA; 32],
            state_root: [0xBB; 32],
        };

        // Synced state at epoch 200 → valid (beyond ws checkpoint)
        let synced = FinalityCheckpoint {
            epoch: 200,
            block_hash: [0xCC; 32],
            blue_score: 1000,
            state_root: [0xDD; 32],
            cumulative_txs: 5000,
        };
        assert!(ws.verify_sync_state(&synced).is_ok());

        // Synced state at same epoch with same hash → valid
        let synced_same = FinalityCheckpoint {
            epoch: 100,
            block_hash: [0xAA; 32],
            blue_score: 500,
            state_root: [0xBB; 32],
            cumulative_txs: 2000,
        };
        assert!(ws.verify_sync_state(&synced_same).is_ok());

        // Synced state at same epoch with different hash → conflict
        let synced_conflict = FinalityCheckpoint {
            epoch: 100,
            block_hash: [0xFF; 32], // different!
            blue_score: 500,
            state_root: [0xBB; 32],
            cumulative_txs: 2000,
        };
        assert!(matches!(
            ws.verify_sync_state(&synced_conflict),
            Err(ForkChoiceError::WeakSubjectivityConflict { .. })
        ));

        // Synced state below ws epoch → violation
        let synced_old = FinalityCheckpoint {
            epoch: 50,
            block_hash: [0x01; 32],
            blue_score: 100,
            state_root: [0x02; 32],
            cumulative_txs: 500,
        };
        assert!(matches!(
            ws.verify_sync_state(&synced_old),
            Err(ForkChoiceError::WeakSubjectivityViolation { .. })
        ));
    }

    #[test]
    fn test_update_chain_tip() {
        let mut state = genesis_state();
        state.on_bft_commit(&make_commit(100, 500, [0xAA; 32]), [0; 32], 0)
            .unwrap();

        // Tip above finality → ok
        assert!(state
            .update_chain_tip(ChainTip {
                block_hash: [0xBB; 32],
                blue_score: 600,
                slot: 600,
                height: 600,
            })
            .is_ok());

        // Tip below finality → rejected
        assert!(state
            .update_chain_tip(ChainTip {
                block_hash: [0xCC; 32],
                blue_score: 300,
                slot: 300,
                height: 300,
            })
            .is_err());
    }
}
