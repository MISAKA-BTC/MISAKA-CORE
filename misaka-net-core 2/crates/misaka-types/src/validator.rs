//! Public PoS validator types — Hybrid signature (Ed25519 + ML-DSA-65).

use crate::mcs1;

pub type ValidatorId = [u8; 20];

/// Validator public key (hybrid: Ed25519 32B + ML-DSA 1952B).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ValidatorPublicKey {
    pub bytes: Vec<u8>, // 1984 bytes (32 + 1952)
}

/// Validator signature (hybrid: Ed25519 64B + ML-DSA 3309B).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ValidatorSignature {
    pub bytes: Vec<u8>, // 3373 bytes (64 + 3309)
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
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FinalityProof {
    pub slot: u64,
    pub block_hash: [u8; 32],
    pub commits: Vec<CommitteeVote>,
}

impl Proposal {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(60);
        buf.extend_from_slice(b"MISAKA:proposal:v1:");
        mcs1::write_u64(&mut buf, self.slot);
        mcs1::write_fixed(&mut buf, &self.proposer);
        mcs1::write_fixed(&mut buf, &self.block_hash);
        buf
    }
}

impl CommitteeVote {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(60);
        buf.extend_from_slice(b"MISAKA:vote:v1:");
        mcs1::write_u64(&mut buf, self.slot);
        mcs1::write_fixed(&mut buf, &self.voter);
        mcs1::write_fixed(&mut buf, &self.block_hash);
        buf
    }
}
