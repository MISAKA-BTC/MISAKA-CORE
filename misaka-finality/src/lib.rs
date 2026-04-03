//! MISAKA Finality — 21 SR BFT checkpoint consensus.
//!
//! Consumes CommittedSubDag from the ordering layer and produces
//! finalized checkpoints via BFT voting among SRs.
pub mod checkpoint_manager;
pub mod bft;

use misaka_dag_types::block::{Round, Epoch};

/// Checkpoint types (previously in misaka-dag-types::checkpoint).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Checkpoint {
    pub epoch: Epoch,
    pub sequence: u64,
    pub last_committed_round: Round,
    pub tx_merkle_root: [u8; 32],
    pub state_root: [u8; 32],
    pub tx_count: u64,
    pub timestamp: u64,
    pub previous: CheckpointDigest,
    pub digest: CheckpointDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CheckpointDigest(pub [u8; 32]);

impl Checkpoint {
    pub fn compute_digest(&self) -> CheckpointDigest {
        let mut h = blake3::Hasher::new();
        h.update(b"MISAKA:checkpoint:v1:");
        h.update(&self.epoch.to_le_bytes());
        h.update(&self.sequence.to_le_bytes());
        h.update(&self.last_committed_round.to_le_bytes());
        h.update(&self.tx_merkle_root);
        h.update(&self.state_root);
        h.update(&self.tx_count.to_le_bytes());
        h.update(&self.timestamp.to_le_bytes());
        h.update(&self.previous.0);
        CheckpointDigest(*h.finalize().as_bytes())
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CheckpointVote {
    pub checkpoint_digest: CheckpointDigest,
    pub voter: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FinalizedCheckpoint {
    pub checkpoint: Checkpoint,
    pub votes: Vec<CheckpointVote>,
    pub total_vote_stake: u128,
}
