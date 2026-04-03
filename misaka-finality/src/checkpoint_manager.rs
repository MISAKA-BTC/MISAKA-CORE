use crate::{Checkpoint, CheckpointDigest, CheckpointVote, FinalizedCheckpoint};
use misaka_dag_types::block::{Epoch, SignatureVerifier};
use misaka_dag_types::commit::CommittedSubDag;
use std::collections::HashMap;
use std::sync::Arc;

/// SR count — initial mainnet committee size.
/// This is a default; actual size comes from CommitteePolicy.
pub const SR_COUNT: usize = 15;
/// SR quorum threshold: 2*floor((15-1)/3)+1 = 10 for SR15.
pub const SR_THRESHOLD: usize = 10;

pub struct CheckpointManager {
    pub epoch: Epoch,
    pub sequence: u64,
    pub last_committed_round: u64,
    pending_votes: HashMap<CheckpointDigest, Vec<CheckpointVote>>,
    /// Store actual checkpoint data for finalization.
    pending_checkpoints: HashMap<CheckpointDigest, Checkpoint>,
    finalized: Vec<FinalizedCheckpoint>,
    pub last_checkpoint_digest: CheckpointDigest,
    /// Voter public keys: voter_id (32 bytes) -> ML-DSA-65 public key.
    voter_pubkeys: HashMap<[u8; 32], Vec<u8>>,
    /// Cryptographic signature verifier.
    verifier: Arc<dyn SignatureVerifier>,
}

impl CheckpointManager {
    /// Create a new CheckpointManager.
    ///
    /// * `voter_pubkeys` — map from voter identifier to ML-DSA-65 public key.
    /// * `verifier` — ML-DSA-65 verifier (production) or StructuralVerifier (tests).
    pub fn new(
        epoch: Epoch,
        voter_pubkeys: HashMap<[u8; 32], Vec<u8>>,
        verifier: Arc<dyn SignatureVerifier>,
    ) -> Self {
        Self {
            epoch,
            sequence: 0,
            last_committed_round: 0,
            pending_votes: HashMap::new(),
            pending_checkpoints: HashMap::new(),
            finalized: Vec::new(),
            last_checkpoint_digest: CheckpointDigest([0; 32]),
            voter_pubkeys,
            verifier,
        }
    }

    /// Create a checkpoint from a committed sub-DAG.
    pub fn create_checkpoint_from_commit(
        &mut self,
        commit: &CommittedSubDag,
        state_root: [u8; 32],
        previous: CheckpointDigest,
    ) -> Checkpoint {
        self.sequence += 1;
        let tx_count = commit.blocks.len() as u64;
        let mut tx_hasher = blake3::Hasher::new();
        for b in &commit.blocks {
            tx_hasher.update(&b.digest.0);
        }
        let tx_merkle_root = *tx_hasher.finalize().as_bytes();

        let mut cp = Checkpoint {
            epoch: self.epoch,
            sequence: self.sequence,
            last_committed_round: commit.leader.round,
            tx_merkle_root,
            state_root,
            tx_count,
            timestamp: commit.timestamp_ms,
            previous,
            digest: CheckpointDigest([0; 32]),
        };
        cp.digest = cp.compute_digest();
        self.last_committed_round = commit.leader.round;
        self.pending_checkpoints.insert(cp.digest, cp.clone());
        self.last_checkpoint_digest = cp.digest;
        cp
    }

    /// Legacy method: create checkpoint from raw parameters.
    pub fn create_checkpoint(
        &mut self,
        last_committed_round: u64,
        tx_merkle_root: [u8; 32],
        state_root: [u8; 32],
        tx_count: u64,
        previous: CheckpointDigest,
    ) -> Checkpoint {
        self.sequence += 1;
        let mut cp = Checkpoint {
            epoch: self.epoch,
            sequence: self.sequence,
            last_committed_round,
            tx_merkle_root,
            state_root,
            tx_count,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default().as_millis() as u64,
            previous,
            digest: CheckpointDigest([0; 32]),
        };
        cp.digest = cp.compute_digest();
        self.last_committed_round = last_committed_round;
        self.pending_checkpoints.insert(cp.digest, cp.clone());
        self.last_checkpoint_digest = cp.digest;
        cp
    }

    pub fn add_vote(&mut self, vote: CheckpointVote, voter_stake: u128) -> Option<FinalizedCheckpoint> {
        let votes = self.pending_votes.entry(vote.checkpoint_digest).or_default();

        // Duplicate voter check
        if votes.iter().any(|v| v.voter == vote.voter) { return None; }

        // Look up voter's ML-DSA-65 public key
        let pubkey = match self.voter_pubkeys.get(&vote.voter) {
            Some(pk) => pk.clone(),
            None => {
                tracing::warn!(
                    "Checkpoint vote from {:?} rejected: unknown voter",
                    hex::encode(&vote.voter[..4])
                );
                return None;
            }
        };

        // Cryptographic signature verification (ML-DSA-65 in production)
        // Signing payload: domain-separated checkpoint vote
        let signing_payload = {
            let mut h = blake3::Hasher::new();
            h.update(b"MISAKA:checkpoint_vote:v1:");
            h.update(&vote.checkpoint_digest.0);
            h.update(&vote.voter);
            h.finalize().as_bytes().to_vec()
        };

        if let Err(e) = self.verifier.verify(&pubkey, &signing_payload, &vote.signature) {
            tracing::warn!(
                "Checkpoint vote from {:?} rejected: {}",
                hex::encode(&vote.voter[..4]), e
            );
            return None;
        }

        votes.push(vote.clone());
        if votes.len() >= SR_THRESHOLD {
            let total_stake = voter_stake * votes.len() as u128;
            // Use the stored checkpoint data (not a zeroed reconstruction)
            let checkpoint = self.pending_checkpoints.remove(&vote.checkpoint_digest)
                .unwrap_or_else(|| Checkpoint {
                    // Fallback if checkpoint data was lost
                    epoch: self.epoch, sequence: self.sequence,
                    last_committed_round: self.last_committed_round,
                    tx_merkle_root: [0; 32], state_root: [0; 32],
                    tx_count: 0, timestamp: 0,
                    previous: CheckpointDigest([0; 32]),
                    digest: vote.checkpoint_digest,
                });
            let finalized = FinalizedCheckpoint {
                checkpoint,
                votes: votes.clone(),
                total_vote_stake: total_stake,
            };
            self.finalized.push(finalized.clone());
            self.pending_votes.remove(&vote.checkpoint_digest);
            return Some(finalized);
        }
        None
    }

    pub fn last_finalized(&self) -> Option<&FinalizedCheckpoint> {
        self.finalized.last()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_dag_types::block::StructuralVerifier;

    fn test_checkpoint_mgr(num_voters: u8) -> CheckpointManager {
        let mut pubkeys = HashMap::new();
        for i in 0..num_voters {
            pubkeys.insert([i; 32], vec![0xAA; 1952]);
        }
        CheckpointManager::new(0, pubkeys, Arc::new(StructuralVerifier))
    }

    #[test]
    fn test_checkpoint_finalization() {
        let mut mgr = test_checkpoint_mgr(21);
        let cp = mgr.create_checkpoint(100, [1; 32], [2; 32], 500, CheckpointDigest([0; 32]));
        for i in 0..SR_THRESHOLD {
            let vote = CheckpointVote {
                checkpoint_digest: cp.digest,
                voter: [i as u8; 32],
                signature: vec![0xAA; 64],
            };
            let result = mgr.add_vote(vote, 1_000_000);
            if i < SR_THRESHOLD - 1 { assert!(result.is_none()); }
            else { assert!(result.is_some()); }
        }
    }

    #[test]
    fn test_unknown_voter_rejected() {
        let mut mgr = test_checkpoint_mgr(3);
        let cp = mgr.create_checkpoint(100, [1; 32], [2; 32], 500, CheckpointDigest([0; 32]));
        // Voter [99; 32] is NOT in the pubkey map
        let vote = CheckpointVote {
            checkpoint_digest: cp.digest,
            voter: [99; 32],
            signature: vec![0xAA; 64],
        };
        assert!(mgr.add_vote(vote, 1_000_000).is_none());
    }
}
