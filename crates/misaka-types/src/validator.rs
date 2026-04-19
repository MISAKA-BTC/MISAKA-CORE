//! Public PoS validator types — PQ-only (ML-DSA-65).
//!
//! ECC (Ed25519) is COMPLETELY EXCLUDED.
//! Validator signatures are ML-DSA-65 only (FIPS 204).

use crate::mcs1;

pub type ValidatorId = [u8; 32];

/// Validator public key (ML-DSA-65 only, 1952 bytes).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ValidatorPublicKey {
    pub bytes: Vec<u8>, // 1952 bytes (ML-DSA-65)
}

impl ValidatorPublicKey {
    pub const SIZE: usize = 1952;

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() != Self::SIZE {
            return Err("invalid validator public key length (expected 1952)");
        }
        Ok(Self {
            bytes: data.to_vec(),
        })
    }

    pub fn is_valid(&self) -> bool {
        self.bytes.len() == Self::SIZE
    }
}

/// Validator signature (ML-DSA-65 only, 3309 bytes).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ValidatorSignature {
    pub bytes: Vec<u8>, // 3309 bytes (ML-DSA-65)
}

impl ValidatorSignature {
    pub const SIZE: usize = 3309;

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() != Self::SIZE {
            return Err("invalid validator signature length (expected 3309)");
        }
        Ok(Self {
            bytes: data.to_vec(),
        })
    }

    pub fn is_valid(&self) -> bool {
        self.bytes.len() == Self::SIZE
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ValidatorIdentity {
    pub validator_id: ValidatorId,
    pub stake_weight: u128,
    pub public_key: ValidatorPublicKey,
    pub is_active: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Proposal {
    pub slot: u64,
    pub proposer: ValidatorId,
    pub block_hash: [u8; 32],
    pub signature: ValidatorSignature,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CommitteeVote {
    pub slot: u64,
    pub voter: ValidatorId,
    pub block_hash: [u8; 32],
    pub signature: ValidatorSignature,
    /// SEC-FIX: Epoch binding prevents cross-epoch vote replay.
    /// Without this, a vote for slot 100 in epoch 1 is valid in epoch 2.
    #[serde(default)]
    pub epoch: u64,
    /// SEC-FIX: Chain ID binding prevents cross-chain vote replay.
    #[serde(default)]
    pub chain_id: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FinalityProof {
    pub slot: u64,
    pub block_hash: [u8; 32],
    pub commits: Vec<CommitteeVote>,
}

/// Deterministic validator signing target for a GhostDAG-ordered checkpoint.
///
/// `timestamp_ms` is intentionally excluded because it is a local observation,
/// not consensus state. Validators sign the ordered state commitment itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct DagCheckpointTarget {
    pub block_hash: [u8; 32],
    pub blue_score: u64,
    pub utxo_root: [u8; 32],
    pub total_spent_count: u64,
    pub total_applied_txs: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DagCheckpointVote {
    pub voter: ValidatorId,
    pub target: DagCheckpointTarget,
    pub signature: ValidatorSignature,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DagCheckpointFinalityProof {
    pub target: DagCheckpointTarget,
    pub commits: Vec<DagCheckpointVote>,
}

impl Proposal {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(60);
        buf.extend_from_slice(b"MISAKA:proposal:v2:");
        mcs1::write_u64(&mut buf, self.slot);
        mcs1::write_fixed(&mut buf, &self.proposer);
        mcs1::write_fixed(&mut buf, &self.block_hash);
        buf
    }
}

impl CommitteeVote {
    /// SEC-FIX: signing_bytes now includes epoch and chain_id (v3).
    /// v2 only had slot + voter + block_hash, allowing cross-epoch replay.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(80);
        buf.extend_from_slice(b"MISAKA:vote:v3:");
        mcs1::write_u64(&mut buf, self.epoch);
        mcs1::write_u64(&mut buf, self.slot);
        mcs1::write_fixed(&mut buf, &self.voter);
        mcs1::write_fixed(&mut buf, &self.block_hash);
        buf.extend_from_slice(&self.chain_id.to_le_bytes());
        buf
    }
}

impl DagCheckpointTarget {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(b"MISAKA:dag-checkpoint-target:v1:");
        mcs1::write_fixed(&mut buf, &self.block_hash);
        mcs1::write_u64(&mut buf, self.blue_score);
        mcs1::write_fixed(&mut buf, &self.utxo_root);
        mcs1::write_u64(&mut buf, self.total_spent_count);
        mcs1::write_u64(&mut buf, self.total_applied_txs);
        buf
    }
}

impl DagCheckpointVote {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let target_bytes = self.target.signing_bytes();
        let mut buf = Vec::with_capacity(64 + target_bytes.len());
        buf.extend_from_slice(b"MISAKA:dag-checkpoint-vote:v1:");
        mcs1::write_fixed(&mut buf, &self.voter);
        buf.extend_from_slice(&target_bytes);
        buf
    }
}

// ── Epoch transition proof (Phase 4-1: light client trust chain) ──

/// Individual vote attesting to an epoch transition.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EpochTransitionVote {
    pub voter: ValidatorId,
    pub signature: ValidatorSignature,
}

/// Epoch transition proof: 2f+1 ML-DSA-65 signatures from the outgoing
/// committee attesting to the new committee for the next epoch.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EpochTransitionProof {
    pub old_epoch: u64,
    pub new_epoch: u64,
    /// SHA3-256 hash of the new committee.
    pub new_committee_hash: [u8; 32],
    /// The new committee validators.
    pub new_committee: Vec<ValidatorIdentity>,
    /// Votes from outgoing committee members.
    pub transition_votes: Vec<EpochTransitionVote>,
}

impl EpochTransitionProof {
    /// Deterministic signing bytes for epoch transition attestation.
    pub fn signing_bytes(old_epoch: u64, new_epoch: u64, committee_hash: &[u8; 32]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(b"MISAKA:epoch-transition:v1:");
        mcs1::write_u64(&mut buf, old_epoch);
        mcs1::write_u64(&mut buf, new_epoch);
        mcs1::write_fixed(&mut buf, committee_hash);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::{ValidatorPublicKey, ValidatorSignature};

    #[test]
    fn test_validator_public_key_length_validation() {
        assert!(ValidatorPublicKey::from_bytes(&[0u8; ValidatorPublicKey::SIZE]).is_ok());
        assert!(ValidatorPublicKey::from_bytes(&[0u8; ValidatorPublicKey::SIZE - 1]).is_err());
    }

    #[test]
    fn test_validator_signature_length_validation() {
        assert!(ValidatorSignature::from_bytes(&[0u8; ValidatorSignature::SIZE]).is_ok());
        assert!(ValidatorSignature::from_bytes(&[0u8; ValidatorSignature::SIZE - 1]).is_err());
    }
}
