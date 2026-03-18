//! Public PoS validator types — PQ-only (ML-DSA-65).
//!
//! ECC (Ed25519) is COMPLETELY EXCLUDED.
//! Validator signatures are ML-DSA-65 only (FIPS 204).

use crate::mcs1;

pub type ValidatorId = [u8; 20];

/// Validator public key (ML-DSA-65 only, 1952 bytes).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ValidatorPublicKey {
    pub bytes: Vec<u8>, // 1952 bytes (ML-DSA-65)
}

/// Validator signature (ML-DSA-65 only, 3309 bytes).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ValidatorSignature {
    pub bytes: Vec<u8>, // 3309 bytes (ML-DSA-65)
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
        buf.extend_from_slice(b"MISAKA:proposal:v2:");
        mcs1::write_u64(&mut buf, self.slot);
        mcs1::write_fixed(&mut buf, &self.proposer);
        mcs1::write_fixed(&mut buf, &self.block_hash);
        buf
    }
}

impl CommitteeVote {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(60);
        buf.extend_from_slice(b"MISAKA:vote:v2:");
        mcs1::write_u64(&mut buf, self.slot);
        mcs1::write_fixed(&mut buf, &self.voter);
        mcs1::write_fixed(&mut buf, &self.block_hash);
        buf
    }
}
