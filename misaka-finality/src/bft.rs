//! HotStuff-inspired BFT for SR checkpoint voting.
//!
//! All vote signatures are cryptographically verified via the injected
//! `SignatureVerifier` (ML-DSA-65 in production, structural in tests).
use crate::Checkpoint;
#[cfg(test)]
use crate::CheckpointDigest;
use misaka_dag_types::block::SignatureVerifier;
use std::collections::HashMap;
use std::sync::Arc;

/// Finality threshold — derived from committee size at runtime.
/// For SR15: quorum = 2*floor((15-1)/3)+1 = 2*4+1 = 9+1 = 10
/// For SR21: quorum = 2*floor((21-1)/3)+1 = 2*6+1 = 13+1 = 14
///
/// Legacy constant kept for backward compatibility.
/// New code should use `CommitteePolicy::finality_threshold()`.
/// BFT finality threshold: ceil(2*15/3) = 10 for SR15.
/// Standard 2/3 supermajority. Updated via CommitteePolicy for SR18/SR21.
pub const FINALITY_THRESHOLD: usize = 10;

#[derive(Debug, Clone, PartialEq)]
pub enum BftPhase {
    Propose,
    Prevote,
    Precommit,
    Committed,
}

#[derive(Clone, Debug)]
pub struct VoteEquivocation {
    pub voter: [u8; 32],
    pub phase: String,
    pub digest_a: [u8; 32],
    pub digest_b: [u8; 32],
}

pub struct BftRound {
    pub phase: BftPhase,
    pub checkpoint: Option<Checkpoint>,
    pub prevotes: HashMap<[u8; 32], Vec<u8>>,   // voter -> signature
    pub precommits: HashMap<[u8; 32], Vec<u8>>,
    /// Track which checkpoint digest each voter prevoted for (equivocation detection).
    prevote_digests: HashMap<[u8; 32], [u8; 32]>,
    precommit_digests: HashMap<[u8; 32], [u8; 32]>,
    /// Detected vote equivocations.
    pub vote_equivocations: Vec<VoteEquivocation>,
    /// Voter public keys: voter_id (32 bytes) -> ML-DSA-65 public key.
    voter_pubkeys: HashMap<[u8; 32], Vec<u8>>,
    /// Cryptographic signature verifier.
    verifier: Arc<dyn SignatureVerifier>,
}

impl BftRound {
    /// Create a new BFT round.
    ///
    /// * `voter_pubkeys` — map from voter identifier (32 bytes) to ML-DSA-65
    ///   public key (1952 bytes). Votes from unknown voters are rejected.
    /// * `verifier` — cryptographic verifier (MlDsa65Verifier in production).
    pub fn new(
        voter_pubkeys: HashMap<[u8; 32], Vec<u8>>,
        verifier: Arc<dyn SignatureVerifier>,
    ) -> Self {
        Self {
            phase: BftPhase::Propose,
            checkpoint: None,
            prevotes: HashMap::new(),
            precommits: HashMap::new(),
            prevote_digests: HashMap::new(),
            precommit_digests: HashMap::new(),
            vote_equivocations: Vec::new(),
            voter_pubkeys,
            verifier,
        }
    }

    pub fn propose(&mut self, checkpoint: Checkpoint) {
        self.checkpoint = Some(checkpoint);
        self.phase = BftPhase::Prevote;
    }

    pub fn add_prevote(&mut self, voter: [u8; 32], signature: Vec<u8>, checkpoint_digest: [u8; 32]) -> bool {
        if self.phase != BftPhase::Prevote { return false; }

        // Look up voter's public key
        let pubkey = match self.voter_pubkeys.get(&voter) {
            Some(pk) => pk.clone(),
            None => return false, // Unknown voter
        };

        // Cryptographic signature verification (ML-DSA-65 in production)
        // Signing payload: domain-separated prevote message
        let mut signing_payload = Vec::with_capacity(64 + 7);
        signing_payload.extend_from_slice(b"prevote:");
        signing_payload.extend_from_slice(&checkpoint_digest);
        signing_payload.extend_from_slice(&voter);
        if self.verifier.verify(&pubkey, &signing_payload, &signature).is_err() {
            return false;
        }

        // Equivocation detection
        if let Some(prev_digest) = self.prevote_digests.get(&voter) {
            if *prev_digest != checkpoint_digest {
                self.vote_equivocations.push(VoteEquivocation {
                    voter,
                    phase: "prevote".to_string(),
                    digest_a: *prev_digest,
                    digest_b: checkpoint_digest,
                });
                return false; // Reject equivocating vote
            }
            return false; // Duplicate, already counted
        }

        self.prevote_digests.insert(voter, checkpoint_digest);
        self.prevotes.insert(voter, signature);
        if self.prevotes.len() >= FINALITY_THRESHOLD {
            self.phase = BftPhase::Precommit;
            return true;
        }
        false
    }

    pub fn add_precommit(&mut self, voter: [u8; 32], signature: Vec<u8>, checkpoint_digest: [u8; 32]) -> bool {
        if self.phase != BftPhase::Precommit { return false; }

        // Look up voter's public key
        let pubkey = match self.voter_pubkeys.get(&voter) {
            Some(pk) => pk.clone(),
            None => return false, // Unknown voter
        };

        // Cryptographic signature verification (ML-DSA-65 in production)
        let mut signing_payload = Vec::with_capacity(64 + 10);
        signing_payload.extend_from_slice(b"precommit:");
        signing_payload.extend_from_slice(&checkpoint_digest);
        signing_payload.extend_from_slice(&voter);
        if self.verifier.verify(&pubkey, &signing_payload, &signature).is_err() {
            return false;
        }

        // Equivocation detection
        if let Some(prev_digest) = self.precommit_digests.get(&voter) {
            if *prev_digest != checkpoint_digest {
                self.vote_equivocations.push(VoteEquivocation {
                    voter,
                    phase: "precommit".to_string(),
                    digest_a: *prev_digest,
                    digest_b: checkpoint_digest,
                });
                return false; // Reject equivocating vote
            }
            return false; // Duplicate, already counted
        }

        self.precommit_digests.insert(voter, checkpoint_digest);
        self.precommits.insert(voter, signature);
        if self.precommits.len() >= FINALITY_THRESHOLD {
            self.phase = BftPhase::Committed;
            return true;
        }
        false
    }

    pub fn is_committed(&self) -> bool { self.phase == BftPhase::Committed }
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_dag_types::block::StructuralVerifier;

    /// Helper: create voter pubkeys + StructuralVerifier for tests.
    fn test_bft_round(num_voters: u8) -> BftRound {
        let mut pubkeys = HashMap::new();
        for i in 0..num_voters {
            pubkeys.insert([i; 32], vec![0xAA; 1952]);
        }
        BftRound::new(pubkeys, Arc::new(StructuralVerifier))
    }

    #[test]
    fn test_bft_full_flow() {
        let mut round = test_bft_round(21);
        let cp = Checkpoint {
            epoch: 0, sequence: 1, last_committed_round: 100,
            tx_merkle_root: [1; 32], state_root: [2; 32],
            tx_count: 500, timestamp: 1000,
            previous: CheckpointDigest([0; 32]),
            digest: CheckpointDigest([3; 32]),
        };
        round.propose(cp.clone());
        assert_eq!(round.phase, BftPhase::Prevote);
        for i in 0..15u8 {
            let advanced = round.add_prevote([i; 32], vec![0xAA; 64], cp.digest.0);
            if i < 14 { assert!(!advanced); }
            else { assert!(advanced); }
        }
        assert_eq!(round.phase, BftPhase::Precommit);
        for i in 0..15u8 {
            let committed = round.add_precommit([i; 32], vec![0xBB; 64], cp.digest.0);
            if i < 14 { assert!(!committed); }
            else { assert!(committed); }
        }
        assert!(round.is_committed());
    }

    #[test]
    fn test_bft_vote_equivocation_detected() {
        let mut round = test_bft_round(21);
        let cp = Checkpoint {
            epoch: 0, sequence: 1, last_committed_round: 100,
            tx_merkle_root: [1; 32], state_root: [2; 32],
            tx_count: 500, timestamp: 1000,
            previous: CheckpointDigest([0; 32]),
            digest: CheckpointDigest([3; 32]),
        };
        round.propose(cp);

        // First prevote for digest A
        round.add_prevote([1; 32], vec![0xAA; 64], [0x11; 32]);
        // Same voter, different digest — equivocation!
        round.add_prevote([1; 32], vec![0xBB; 64], [0x22; 32]);

        assert_eq!(round.vote_equivocations.len(), 1);
        assert_eq!(round.vote_equivocations[0].voter, [1; 32]);
    }

    #[test]
    fn test_unknown_voter_rejected() {
        let mut round = test_bft_round(3);
        let cp = Checkpoint {
            epoch: 0, sequence: 1, last_committed_round: 100,
            tx_merkle_root: [1; 32], state_root: [2; 32],
            tx_count: 500, timestamp: 1000,
            previous: CheckpointDigest([0; 32]),
            digest: CheckpointDigest([3; 32]),
        };
        round.propose(cp.clone());

        // Voter [99; 32] is NOT in the pubkey map
        let result = round.add_prevote([99; 32], vec![0xAA; 64], cp.digest.0);
        assert!(!result);
        assert!(round.prevotes.is_empty());
    }
}
