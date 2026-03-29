//! Equivocation Detection — automatic slashing evidence generation.
//!
//! # Detection Model
//!
//! The detector runs as a passive observer on all BFT messages.
//! When it sees two conflicting messages from the same validator,
//! it generates `EquivocationEvidence` for on-chain slashing.
//!
//! ```text
//! P2P Message Stream
//!       │
//!       ▼
//! ┌─────────────────┐     ┌──────────────────┐
//! │  SlashDetector   │────►│ EquivocationEvidence │
//! │  (seen cache)    │     │  (broadcast to P2P)  │
//! └─────────────────┘     └──────────────────┘
//!       │                          │
//!       ▼                          ▼
//! StakingRegistry::slash()    Reporter Reward
//! ```
//!
//! # Detected Violations
//!
//! | Type | Rule | Severity |
//! |------|------|----------|
//! | DoubleProposal | Two proposals for same (slot, round) | Severe (20%) |
//! | DoublePrevote | Two prevotes for same (slot, round), different block | Severe (20%) |
//! | DoublePrecommit | Two precommits for same (slot, round), different block | Severe (20%) |
//! | SurroundVote | Attestation A surrounds attestation B (Casper FFG) | Severe (20%) |
//!
//! # Memory Management
//!
//! The cache has a configurable maximum size. When full, oldest entries
//! are evicted (LRU). This prevents memory exhaustion from P2P spam.

use std::collections::HashMap;

use super::bft_types::*;
use misaka_types::validator::ValidatorId;

// ═══════════════════════════════════════════════════════════════
//  Detector Configuration
// ═══════════════════════════════════════════════════════════════

/// Slash detector configuration.
pub struct SlashDetectorConfig {
    /// Maximum cached entries per category (proposals, prevotes, precommits).
    pub max_cache_entries: usize,
    /// Maximum epochs to keep for surround vote detection.
    pub surround_vote_lookback_epochs: u64,
}

impl Default for SlashDetectorConfig {
    fn default() -> Self {
        Self {
            max_cache_entries: 100_000,
            surround_vote_lookback_epochs: 100,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Cache Key
// ═══════════════════════════════════════════════════════════════

/// Uniquely identifies a (slot, round, validator) triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct MessageKey {
    slot: u64,
    round: u32,
    validator_id: ValidatorId,
}

/// Stored proposal summary (hash + full message for evidence).
#[derive(Debug, Clone)]
struct CachedProposal {
    block_hash: Hash,
    proposal: BftProposal,
}

/// Stored vote summary.
#[derive(Debug, Clone)]
struct CachedVote {
    block_hash: Option<Hash>,
    vote: BftVote,
}

/// Stored epoch attestation for surround vote detection (Casper FFG).
#[derive(Debug, Clone)]
struct CachedAttestation {
    source_epoch: u64,
    target_epoch: u64,
    block_hash: Hash,
    signature: Vec<u8>,
}

// ═══════════════════════════════════════════════════════════════
//  Slash Detector
// ═══════════════════════════════════════════════════════════════

/// Passive equivocation detector.
///
/// Feed all received BFT messages into `check_*` methods.
/// Any returned `EquivocationEvidence` should be broadcast to the network
/// and included in the next block.
pub struct SlashDetector {
    proposals: HashMap<MessageKey, CachedProposal>,
    prevotes: HashMap<MessageKey, CachedVote>,
    precommits: HashMap<MessageKey, CachedVote>,
    /// Per-validator epoch attestation history for surround vote detection.
    attestations: HashMap<ValidatorId, Vec<CachedAttestation>>,
    config: SlashDetectorConfig,
}

impl SlashDetector {
    pub fn new(config: SlashDetectorConfig) -> Self {
        Self {
            proposals: HashMap::new(),
            prevotes: HashMap::new(),
            precommits: HashMap::new(),
            attestations: HashMap::new(),
            config,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(SlashDetectorConfig::default())
    }

    // ─── Proposal Check ─────────────────────────────────────

    /// Check a proposal for equivocation (DoubleProposal).
    ///
    /// Returns evidence if the same validator has already proposed
    /// a different block for the same (slot, round).
    pub fn check_proposal(
        &mut self,
        proposal: &BftProposal,
    ) -> Option<EquivocationEvidence> {
        let key = MessageKey {
            slot: proposal.slot,
            round: proposal.round,
            validator_id: proposal.proposer,
        };

        if let Some(existing) = self.proposals.get(&key) {
            if existing.block_hash != proposal.block_hash {
                return Some(EquivocationEvidence::DoubleProposal {
                    validator_id: proposal.proposer,
                    proposal_a: existing.proposal.clone(),
                    proposal_b: proposal.clone(),
                });
            }
            return None; // Same proposal, not equivocation
        }

        // Evict if at capacity
        self.maybe_evict_proposals();

        self.proposals.insert(
            key,
            CachedProposal {
                block_hash: proposal.block_hash,
                proposal: proposal.clone(),
            },
        );
        None
    }

    // ─── Prevote Check ──────────────────────────────────────

    /// Check a prevote for equivocation (DoublePrevote).
    pub fn check_prevote(
        &mut self,
        vote: &BftVote,
    ) -> Option<EquivocationEvidence> {
        let key = MessageKey {
            slot: vote.slot,
            round: vote.round,
            validator_id: vote.voter,
        };

        if let Some(existing) = self.prevotes.get(&key) {
            if existing.block_hash != vote.block_hash {
                return Some(EquivocationEvidence::DoublePrevote {
                    validator_id: vote.voter,
                    vote_a: existing.vote.clone(),
                    vote_b: vote.clone(),
                });
            }
            return None;
        }

        self.maybe_evict_prevotes();

        self.prevotes.insert(
            key,
            CachedVote {
                block_hash: vote.block_hash,
                vote: vote.clone(),
            },
        );
        None
    }

    // ─── Precommit Check ────────────────────────────────────

    /// Check a precommit for equivocation (DoublePrecommit).
    pub fn check_precommit(
        &mut self,
        vote: &BftVote,
    ) -> Option<EquivocationEvidence> {
        let key = MessageKey {
            slot: vote.slot,
            round: vote.round,
            validator_id: vote.voter,
        };

        if let Some(existing) = self.precommits.get(&key) {
            if existing.block_hash != vote.block_hash {
                return Some(EquivocationEvidence::DoublePrecommit {
                    validator_id: vote.voter,
                    vote_a: existing.vote.clone(),
                    vote_b: vote.clone(),
                });
            }
            return None;
        }

        self.maybe_evict_precommits();

        self.precommits.insert(
            key,
            CachedVote {
                block_hash: vote.block_hash,
                vote: vote.clone(),
            },
        );
        None
    }

    // ─── Surround Vote Check (Casper FFG) ───────────────────

    /// Check an epoch attestation for surround vote violation.
    ///
    /// Casper FFG slashing conditions:
    /// - RULE 1: No double vote — same target epoch, different block (caught by check_precommit)
    /// - RULE 2: No surround — attestation A surrounds B if:
    ///   `source_A < source_B && target_A > target_B`
    ///
    /// This detects long-range attack attempts where a validator
    /// tries to finalize a conflicting chain.
    pub fn check_surround_vote(
        &mut self,
        validator_id: &ValidatorId,
        source_epoch: u64,
        target_epoch: u64,
        block_hash: Hash,
        signature: Vec<u8>,
    ) -> Option<EquivocationEvidence> {
        let history = self.attestations.entry(*validator_id).or_default();

        for existing in history.iter() {
            // Check if new attestation surrounds existing
            if source_epoch < existing.source_epoch
                && target_epoch > existing.target_epoch
            {
                return Some(EquivocationEvidence::SurroundVote {
                    validator_id: *validator_id,
                    outer: SurroundAttestationPair {
                        source_epoch,
                        target_epoch,
                        block_hash,
                        signature: misaka_types::validator::ValidatorSignature {
                            bytes: signature.clone(),
                        },
                    },
                    inner: SurroundAttestationPair {
                        source_epoch: existing.source_epoch,
                        target_epoch: existing.target_epoch,
                        block_hash: existing.block_hash,
                        signature: misaka_types::validator::ValidatorSignature {
                            bytes: existing.signature.clone(),
                        },
                    },
                });
            }

            // Check if existing surrounds new
            if existing.source_epoch < source_epoch
                && existing.target_epoch > target_epoch
            {
                return Some(EquivocationEvidence::SurroundVote {
                    validator_id: *validator_id,
                    outer: SurroundAttestationPair {
                        source_epoch: existing.source_epoch,
                        target_epoch: existing.target_epoch,
                        block_hash: existing.block_hash,
                        signature: misaka_types::validator::ValidatorSignature {
                            bytes: existing.signature.clone(),
                        },
                    },
                    inner: SurroundAttestationPair {
                        source_epoch,
                        target_epoch,
                        block_hash,
                        signature: misaka_types::validator::ValidatorSignature {
                            bytes: signature.clone(),
                        },
                    },
                });
            }
        }

        // Store for future comparison
        history.push(CachedAttestation {
            source_epoch,
            target_epoch,
            block_hash,
            signature,
        });

        // Prune old attestations
        let cutoff = target_epoch.saturating_sub(self.config.surround_vote_lookback_epochs);
        history.retain(|a| a.target_epoch >= cutoff);

        None
    }

    // ─── BFT Message Dispatch ───────────────────────────────

    /// Check any BFT message for equivocation. Convenience method.
    pub fn check_message(
        &mut self,
        msg: &BftMessage,
    ) -> Option<EquivocationEvidence> {
        match msg {
            BftMessage::Proposal(p) => self.check_proposal(p),
            BftMessage::Prevote(v) => self.check_prevote(v),
            BftMessage::Precommit(v) => self.check_precommit(v),
        }
    }

    // ─── Cache Eviction ─────────────────────────────────────

    fn maybe_evict_proposals(&mut self) {
        if self.proposals.len() >= self.config.max_cache_entries {
            // Evict oldest by slot
            if let Some(oldest_key) = self
                .proposals
                .keys()
                .min_by_key(|k| (k.slot, k.round))
                .copied()
            {
                self.proposals.remove(&oldest_key);
            }
        }
    }

    fn maybe_evict_prevotes(&mut self) {
        if self.prevotes.len() >= self.config.max_cache_entries {
            if let Some(oldest_key) = self
                .prevotes
                .keys()
                .min_by_key(|k| (k.slot, k.round))
                .copied()
            {
                self.prevotes.remove(&oldest_key);
            }
        }
    }

    fn maybe_evict_precommits(&mut self) {
        if self.precommits.len() >= self.config.max_cache_entries {
            if let Some(oldest_key) = self
                .precommits
                .keys()
                .min_by_key(|k| (k.slot, k.round))
                .copied()
            {
                self.precommits.remove(&oldest_key);
            }
        }
    }

    // ─── Metrics ────────────────────────────────────────────

    /// Total cached entries across all categories.
    pub fn cache_size(&self) -> usize {
        self.proposals.len() + self.prevotes.len() + self.precommits.len()
    }

    /// Purge all entries for slots below the given slot (after finality).
    pub fn purge_below_slot(&mut self, slot: u64) {
        self.proposals.retain(|k, _| k.slot >= slot);
        self.prevotes.retain(|k, _| k.slot >= slot);
        self.precommits.retain(|k, _| k.slot >= slot);
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_types::validator::ValidatorSignature;

    fn make_proposal(slot: u64, round: u32, proposer: [u8; 32], hash: [u8; 32]) -> BftProposal {
        BftProposal {
            slot,
            round,
            proposer,
            block_hash: hash,
            dag_checkpoint: DagCheckpointTarget {
                block_hash: hash,
                blue_score: 0,
                utxo_root: [0; 32],
                total_key_images: 0,
                total_applied_txs: 0,
            },
            vrf_proof: VrfOutput {
                proof: vec![0; 3309],
                hash: [0; 32],
            },
            valid_round: u32::MAX,
            signature: ValidatorSignature { bytes: vec![0; 3309] },
        }
    }

    fn make_vote(slot: u64, round: u32, voter: [u8; 32], hash: Option<Hash>) -> BftVote {
        BftVote {
            slot,
            round,
            voter,
            block_hash: hash,
            signature: ValidatorSignature { bytes: vec![0; 3309] },
        }
    }

    #[test]
    fn test_no_equivocation_same_block() {
        let mut det = SlashDetector::with_defaults();
        let vid = [0x01; 20];
        let hash = [0xAA; 32];

        assert!(det.check_proposal(&make_proposal(1, 0, vid, hash)).is_none());
        // Same block again → not equivocation
        assert!(det.check_proposal(&make_proposal(1, 0, vid, hash)).is_none());
    }

    #[test]
    fn test_double_proposal_detected() {
        let mut det = SlashDetector::with_defaults();
        let vid = [0x01; 20];

        assert!(det.check_proposal(&make_proposal(1, 0, vid, [0xAA; 32])).is_none());
        let evidence = det.check_proposal(&make_proposal(1, 0, vid, [0xBB; 32]));
        assert!(evidence.is_some());
        assert!(matches!(
            evidence.unwrap(),
            EquivocationEvidence::DoubleProposal { .. }
        ));
    }

    #[test]
    fn test_different_round_not_equivocation() {
        let mut det = SlashDetector::with_defaults();
        let vid = [0x01; 20];

        assert!(det.check_proposal(&make_proposal(1, 0, vid, [0xAA; 32])).is_none());
        // Different round → different proposals are fine
        assert!(det.check_proposal(&make_proposal(1, 1, vid, [0xBB; 32])).is_none());
    }

    #[test]
    fn test_double_prevote_detected() {
        let mut det = SlashDetector::with_defaults();
        let vid = [0x01; 20];

        assert!(det.check_prevote(&make_vote(1, 0, vid, Some([0xAA; 32]))).is_none());
        let evidence = det.check_prevote(&make_vote(1, 0, vid, Some([0xBB; 32])));
        assert!(matches!(
            evidence.unwrap(),
            EquivocationEvidence::DoublePrevote { .. }
        ));
    }

    #[test]
    fn test_double_precommit_detected() {
        let mut det = SlashDetector::with_defaults();
        let vid = [0x01; 20];

        assert!(det.check_precommit(&make_vote(1, 0, vid, Some([0xAA; 32]))).is_none());
        let evidence = det.check_precommit(&make_vote(1, 0, vid, Some([0xBB; 32])));
        assert!(matches!(
            evidence.unwrap(),
            EquivocationEvidence::DoublePrecommit { .. }
        ));
    }

    #[test]
    fn test_surround_vote_outer() {
        let mut det = SlashDetector::with_defaults();
        let vid = [0x01; 20];

        // Attestation 1: source=5, target=10
        assert!(det.check_surround_vote(&vid, 5, 10, [0xAA; 32], vec![0; 100]).is_none());

        // Attestation 2: source=3, target=12 → surrounds attestation 1
        let evidence = det.check_surround_vote(&vid, 3, 12, [0xBB; 32], vec![1; 100]);
        assert!(matches!(
            evidence.unwrap(),
            EquivocationEvidence::SurroundVote { .. }
        ));
    }

    #[test]
    fn test_surround_vote_inner() {
        let mut det = SlashDetector::with_defaults();
        let vid = [0x01; 20];

        // Attestation 1: source=3, target=12 (wide)
        assert!(det.check_surround_vote(&vid, 3, 12, [0xAA; 32], vec![0; 100]).is_none());

        // Attestation 2: source=5, target=10 → surrounded by attestation 1
        let evidence = det.check_surround_vote(&vid, 5, 10, [0xBB; 32], vec![1; 100]);
        assert!(matches!(
            evidence.unwrap(),
            EquivocationEvidence::SurroundVote { .. }
        ));
    }

    #[test]
    fn test_non_overlapping_attestations_ok() {
        let mut det = SlashDetector::with_defaults();
        let vid = [0x01; 20];

        assert!(det.check_surround_vote(&vid, 1, 5, [0xAA; 32], vec![0]).is_none());
        assert!(det.check_surround_vote(&vid, 5, 10, [0xBB; 32], vec![1]).is_none());
        assert!(det.check_surround_vote(&vid, 10, 15, [0xCC; 32], vec![2]).is_none());
    }

    #[test]
    fn test_purge_below_slot() {
        let mut det = SlashDetector::with_defaults();
        det.check_proposal(&make_proposal(1, 0, [0x01; 20], [0xAA; 32]));
        det.check_proposal(&make_proposal(5, 0, [0x02; 20], [0xBB; 32]));
        det.check_proposal(&make_proposal(10, 0, [0x03; 20], [0xCC; 32]));

        det.purge_below_slot(5);
        assert_eq!(det.proposals.len(), 2); // slot 5 and 10 remain
    }

    #[test]
    fn test_check_message_dispatch() {
        let mut det = SlashDetector::with_defaults();
        let vid = [0x01; 20];

        let msg = BftMessage::Prevote(make_vote(1, 0, vid, Some([0xAA; 32])));
        assert!(det.check_message(&msg).is_none());

        let msg2 = BftMessage::Prevote(make_vote(1, 0, vid, Some([0xBB; 32])));
        assert!(det.check_message(&msg2).is_some());
    }
}
