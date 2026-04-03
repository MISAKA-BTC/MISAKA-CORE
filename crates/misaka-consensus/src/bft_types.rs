//! BFT Consensus Message Types — Tendermint/HotStuff hybrid for MISAKA DAG+PoS.
//!
//! # Protocol Overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │  Slot N, Round R                                    │
//! │                                                     │
//! │  ┌──────────┐    ┌──────────┐    ┌───────────┐     │
//! │  │ Propose  │───►│ Prevote  │───►│ Precommit │──┐  │
//! │  └──────────┘    └──────────┘    └───────────┘  │  │
//! │       │               │               │         │  │
//! │       │ timeout        │ timeout        │ timeout │  │
//! │       ▼               ▼               ▼         │  │
//! │  Round R+1        Round R+1       Round R+1     │  │
//! │                                                  │  │
//! │  On 2/3+ precommit: ────────────────────────────┘  │
//! │  ┌────────┐                                        │
//! │  │ Commit │ → FinalityCheckpoint → Irreversible    │
//! │  └────────┘                                        │
//! └─────────────────────────────────────────────────────┘
//! ```
//!
//! # Security Properties
//!
//! - **Safety**: No two honest validators commit different blocks for the same slot.
//!   Requires `f < n/3` Byzantine validators.
//! - **Liveness**: Progress guaranteed after GST with `f < n/3` faults.
//!   Uses round-based timeout escalation.
//! - **Accountability**: Equivocation (double-vote) generates on-chain slashing evidence.
//!
//! # Integration with GhostDAG
//!
//! The BFT layer finalizes DAG checkpoints. GhostDAG determines transaction ordering
//! within and between checkpoints. BFT provides the irreversibility boundary.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use misaka_types::validator::{
    DagCheckpointTarget, ValidatorId, ValidatorPublicKey, ValidatorSignature,
};

pub type Hash = [u8; 32];

// ═══════════════════════════════════════════════════════════════
//  VRF Output (for proposer election)
// ═══════════════════════════════════════════════════════════════

/// VRF proof output — used for unpredictable proposer selection.
///
/// # Construction (ML-DSA-65 based)
///
/// ML-DSA-65 is a deterministic signature scheme (FIPS 204).
/// Given the same (secret_key, message), it produces the same signature.
/// This deterministic property makes it usable as a VRF:
///
/// ```text
/// vrf_input  = H("MISAKA:VRF:v1:" || slot || round || epoch_randomness)
/// vrf_proof  = ML-DSA-65.Sign(sk, vrf_input)
/// vrf_hash   = SHA3-256(vrf_proof)
/// ```
///
/// Verification: anyone with the public key can verify the proof
/// and derive the same hash, but cannot predict it without the secret key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VrfOutput {
    /// ML-DSA-65 signature over the VRF input (3309 bytes).
    pub proof: Vec<u8>,
    /// SHA3-256 hash of the proof — used for proposer selection.
    pub hash: Hash,
}

impl VrfOutput {
    /// Compute the VRF input message for a given slot, round, and epoch randomness.
    pub fn vrf_input(slot: u64, round: u32, epoch_randomness: &Hash) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(b"MISAKA:VRF:v1:");
        buf.extend_from_slice(&slot.to_le_bytes());
        buf.extend_from_slice(&round.to_le_bytes());
        buf.extend_from_slice(epoch_randomness);
        buf
    }

    /// Derive the VRF hash from the proof bytes.
    pub fn hash_from_proof(proof: &[u8]) -> Hash {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:VRF-HASH:v1:");
        h.update(proof);
        h.finalize().into()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Epoch Randomness
// ═══════════════════════════════════════════════════════════════

/// Accumulated epoch randomness (RANDAO-style).
///
/// Each epoch's randomness is derived from all proposers' VRF outputs
/// in the previous epoch. As long as 1 honest proposer contributed,
/// the randomness is unpredictable.
///
/// ```text
/// epoch_randomness[e] = SHA3-256(
///     "MISAKA:EPOCH-RAND:v1:"
///     || epoch
///     || vrf_hash_1 || vrf_hash_2 || ... || vrf_hash_n
/// )
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochRandomness {
    pub epoch: u64,
    pub randomness: Hash,
    /// Number of VRF contributions aggregated.
    pub contributor_count: u32,
}

impl EpochRandomness {
    /// Genesis epoch randomness (deterministic seed).
    pub fn genesis() -> Self {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:GENESIS-RAND:v1:2026");
        Self {
            epoch: 0,
            randomness: h.finalize().into(),
            contributor_count: 0,
        }
    }

    /// Accumulate a new VRF hash into a running state.
    pub fn accumulate(epoch: u64, vrf_hashes: &[Hash]) -> Self {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:EPOCH-RAND:v1:");
        h.update(epoch.to_le_bytes());
        for vh in vrf_hashes {
            h.update(vh);
        }
        Self {
            epoch,
            randomness: h.finalize().into(),
            contributor_count: vrf_hashes.len() as u32,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  BFT Message Envelope
// ═══════════════════════════════════════════════════════════════

/// Core BFT protocol messages.
///
/// All messages are signed by the sender's ML-DSA-65 key.
/// Domain separation ensures cross-type replay is impossible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BftMessage {
    /// Phase 1: Block proposal from VRF-selected leader.
    Proposal(BftProposal),
    /// Phase 2: Prevote (lock-step agreement).
    Prevote(BftVote),
    /// Phase 3: Precommit (finalization vote).
    Precommit(BftVote),
}

impl BftMessage {
    pub fn slot(&self) -> u64 {
        match self {
            Self::Proposal(p) => p.slot,
            Self::Prevote(v) | Self::Precommit(v) => v.slot,
        }
    }

    pub fn round(&self) -> u32 {
        match self {
            Self::Proposal(p) => p.round,
            Self::Prevote(v) | Self::Precommit(v) => v.round,
        }
    }

    pub fn sender(&self) -> &ValidatorId {
        match self {
            Self::Proposal(p) => &p.proposer,
            Self::Prevote(v) | Self::Precommit(v) => &v.voter,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Proposal
// ═══════════════════════════════════════════════════════════════

/// BFT Proposal — sent by the VRF-elected leader for (slot, round).
///
/// The proposal includes:
/// - The block hash being proposed (output of the block producer)
/// - The DAG checkpoint target (GhostDAG state at this point)
/// - VRF proof demonstrating leader election
/// - Proposer's ML-DSA-65 signature
///
/// # Locked Value Rule (Tendermint)
///
/// If the proposer has a `locked_value` from a previous round's polka
/// (2/3+ prevotes), they MUST re-propose that value. This ensures safety
/// across round transitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BftProposal {
    /// Slot number (monotonically increasing, 1 block per slot).
    pub slot: u64,
    /// Round within this slot (0-indexed, increments on timeout).
    pub round: u32,
    /// Proposer's validator ID.
    pub proposer: ValidatorId,
    /// Hash of the proposed block.
    pub block_hash: Hash,
    /// DAG checkpoint state being finalized.
    pub dag_checkpoint: DagCheckpointTarget,
    /// VRF proof of leader election.
    pub vrf_proof: VrfOutput,
    /// Round of the locked value, if re-proposing a locked block.
    /// -1 (u32::MAX) means no lock.
    pub valid_round: u32,
    /// ML-DSA-65 signature over signing_bytes().
    pub signature: ValidatorSignature,
}

impl BftProposal {
    /// Canonical signing bytes — domain-separated, deterministic.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(b"MISAKA:BFT-PROPOSAL:v1:");
        buf.extend_from_slice(&self.slot.to_le_bytes());
        buf.extend_from_slice(&self.round.to_le_bytes());
        buf.extend_from_slice(&self.proposer);
        buf.extend_from_slice(&self.block_hash);
        buf.extend_from_slice(&self.dag_checkpoint.signing_bytes());
        buf.extend_from_slice(&self.vrf_proof.hash);
        buf.extend_from_slice(&self.valid_round.to_le_bytes());
        buf
    }
}

// ═══════════════════════════════════════════════════════════════
//  Vote (Prevote / Precommit)
// ═══════════════════════════════════════════════════════════════

/// BFT Vote — used for both Prevote and Precommit phases.
///
/// The vote type (Prevote vs Precommit) is determined by context
/// and included in the domain separation tag for signing.
///
/// # Nil Vote
///
/// `block_hash = None` indicates a nil vote (no valid proposal received
/// before timeout). Nil votes contribute to round advancement but
/// do not lock any value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BftVote {
    /// Slot number.
    pub slot: u64,
    /// Round within slot.
    pub round: u32,
    /// Voter's validator ID.
    pub voter: ValidatorId,
    /// Block hash being voted for. None = nil vote.
    pub block_hash: Option<Hash>,
    /// ML-DSA-65 signature over signing_bytes().
    pub signature: ValidatorSignature,
}

impl BftVote {
    /// Canonical signing bytes for Prevote.
    pub fn prevote_signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(b"MISAKA:BFT-PREVOTE:v1:");
        buf.extend_from_slice(&self.slot.to_le_bytes());
        buf.extend_from_slice(&self.round.to_le_bytes());
        buf.extend_from_slice(&self.voter);
        match &self.block_hash {
            Some(h) => {
                buf.push(0x01);
                buf.extend_from_slice(h);
            }
            None => buf.push(0x00),
        }
        buf
    }

    /// Canonical signing bytes for Precommit.
    pub fn precommit_signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(b"MISAKA:BFT-PRECOMMIT:v1:");
        buf.extend_from_slice(&self.slot.to_le_bytes());
        buf.extend_from_slice(&self.round.to_le_bytes());
        buf.extend_from_slice(&self.voter);
        match &self.block_hash {
            Some(h) => {
                buf.push(0x01);
                buf.extend_from_slice(h);
            }
            None => buf.push(0x00),
        }
        buf
    }
}

// ═══════════════════════════════════════════════════════════════
//  Quorum Certificate (QC)
// ═══════════════════════════════════════════════════════════════

/// Quorum Certificate — aggregated proof of 2/3+ validator agreement.
///
/// A QC proves that at least 2/3 of total stake has voted for the same
/// block in a given (slot, round). Used as:
/// - **Prevote QC**: triggers precommit phase (Tendermint "polka")
/// - **Precommit QC**: triggers commit (block is finalized)
/// - **Nil QC**: 2/3+ nil votes → advance to next round
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumCertificate {
    /// QC type: Prevote or Precommit.
    pub qc_type: QcType,
    /// Slot number.
    pub slot: u64,
    /// Round number.
    pub round: u32,
    /// Block hash that achieved quorum. None for nil QC.
    pub block_hash: Option<Hash>,
    /// Aggregated votes with signatures.
    pub votes: Vec<BftVote>,
    /// Total stake weight of the votes.
    pub total_weight: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QcType {
    Prevote,
    Precommit,
}

impl QuorumCertificate {
    /// Check if this QC has sufficient weight for quorum.
    pub fn has_quorum(&self, total_stake: u128) -> bool {
        // BPS threshold from constants.rs: 6667 = 66.67%
        let threshold_bps = misaka_types::constants::QUORUM_THRESHOLD_BPS as u128;
        let required = (total_stake * threshold_bps + 9999) / 10000;
        self.total_weight >= required
    }

    /// Number of distinct voters.
    pub fn voter_count(&self) -> usize {
        self.votes.len()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Commit (Finality)
// ═══════════════════════════════════════════════════════════════

/// BFT Commit — a finalized block with precommit QC.
///
/// Once a Commit is produced, the block is irreversible.
/// The commit QC is stored alongside the finality checkpoint
/// and can be verified by light clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BftCommit {
    pub slot: u64,
    pub round: u32,
    pub block_hash: Hash,
    pub dag_checkpoint: DagCheckpointTarget,
    /// The precommit QC that triggered this commit.
    pub precommit_qc: QuorumCertificate,
}

// ═══════════════════════════════════════════════════════════════
//  Slashing Evidence
// ═══════════════════════════════════════════════════════════════

/// On-chain evidence of validator equivocation.
///
/// Any validator can submit evidence. If verified, the offending
/// validator is slashed (20% for double-vote, Severe severity).
/// The reporter receives 10% of the slashed amount.
///
/// # Evidence Types
///
/// 1. **DoubleProposal**: two proposals for the same (slot, round)
/// 2. **DoublePrevote**: two prevotes for the same (slot, round) with different block_hash
/// 3. **DoublePrecommit**: two precommits for the same (slot, round) with different block_hash
/// 4. **SurroundVote**: attestation A surrounds attestation B (Casper FFG rule)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EquivocationEvidence {
    DoubleProposal {
        validator_id: ValidatorId,
        proposal_a: BftProposal,
        proposal_b: BftProposal,
    },
    DoublePrevote {
        validator_id: ValidatorId,
        vote_a: BftVote,
        vote_b: BftVote,
    },
    DoublePrecommit {
        validator_id: ValidatorId,
        vote_a: BftVote,
        vote_b: BftVote,
    },
    SurroundVote {
        validator_id: ValidatorId,
        /// The outer attestation (lower source, higher target).
        outer: SurroundAttestationPair,
        /// The inner attestation (higher source, lower target).
        inner: SurroundAttestationPair,
    },
}

/// Attestation pair for surround vote detection (Casper FFG style).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurroundAttestationPair {
    pub source_epoch: u64,
    pub target_epoch: u64,
    pub block_hash: Hash,
    pub signature: ValidatorSignature,
}

impl EquivocationEvidence {
    /// Extract the offending validator's ID.
    pub fn validator_id(&self) -> &ValidatorId {
        match self {
            Self::DoubleProposal { validator_id, .. } => validator_id,
            Self::DoublePrevote { validator_id, .. } => validator_id,
            Self::DoublePrecommit { validator_id, .. } => validator_id,
            Self::SurroundVote { validator_id, .. } => validator_id,
        }
    }

    /// Canonical signing bytes for on-chain inclusion.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);
        buf.extend_from_slice(b"MISAKA:EQUIVOCATION:v1:");
        match self {
            Self::DoubleProposal {
                validator_id,
                proposal_a,
                proposal_b,
            } => {
                buf.push(0x01);
                buf.extend_from_slice(validator_id);
                buf.extend_from_slice(&proposal_a.signing_bytes());
                buf.extend_from_slice(&proposal_a.signature.bytes);
                buf.extend_from_slice(&proposal_b.signing_bytes());
                buf.extend_from_slice(&proposal_b.signature.bytes);
            }
            Self::DoublePrevote {
                validator_id,
                vote_a,
                vote_b,
            } => {
                buf.push(0x02);
                buf.extend_from_slice(validator_id);
                buf.extend_from_slice(&vote_a.prevote_signing_bytes());
                buf.extend_from_slice(&vote_a.signature.bytes);
                buf.extend_from_slice(&vote_b.prevote_signing_bytes());
                buf.extend_from_slice(&vote_b.signature.bytes);
            }
            Self::DoublePrecommit {
                validator_id,
                vote_a,
                vote_b,
            } => {
                buf.push(0x03);
                buf.extend_from_slice(validator_id);
                buf.extend_from_slice(&vote_a.precommit_signing_bytes());
                buf.extend_from_slice(&vote_a.signature.bytes);
                buf.extend_from_slice(&vote_b.precommit_signing_bytes());
                buf.extend_from_slice(&vote_b.signature.bytes);
            }
            Self::SurroundVote {
                validator_id,
                outer,
                inner,
            } => {
                buf.push(0x04);
                buf.extend_from_slice(validator_id);
                buf.extend_from_slice(&outer.source_epoch.to_le_bytes());
                buf.extend_from_slice(&outer.target_epoch.to_le_bytes());
                buf.extend_from_slice(&inner.source_epoch.to_le_bytes());
                buf.extend_from_slice(&inner.target_epoch.to_le_bytes());
            }
        }
        buf
    }
}

// ═══════════════════════════════════════════════════════════════
//  Timeout
// ═══════════════════════════════════════════════════════════════

/// Adaptive timeout configuration.
///
/// `timeout(round) = base_ms + round * increment_ms`, capped at `max_ms`.
///
/// This ensures:
/// - Fast finality in normal conditions (base_ms ≈ 3s)
/// - Graceful degradation under network stress
/// - DoS resistance (max_ms caps timeout growth)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// Base timeout for round 0 (milliseconds).
    pub base_ms: u64,
    /// Increment per round (milliseconds).
    pub increment_ms: u64,
    /// Maximum timeout (milliseconds).
    pub max_ms: u64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            base_ms: 3_000,
            increment_ms: 1_000,
            max_ms: 30_000,
        }
    }
}

impl TimeoutConfig {
    /// Compute timeout for a given round.
    pub fn timeout_ms(&self, round: u32) -> u64 {
        let raw = self.base_ms.saturating_add(self.increment_ms.saturating_mul(round as u64));
        raw.min(self.max_ms)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vrf_input_deterministic() {
        let rand = [0xAA; 32];
        let a = VrfOutput::vrf_input(100, 0, &rand);
        let b = VrfOutput::vrf_input(100, 0, &rand);
        assert_eq!(a, b);
    }

    #[test]
    fn test_vrf_input_differs_by_slot() {
        let rand = [0xAA; 32];
        let a = VrfOutput::vrf_input(100, 0, &rand);
        let b = VrfOutput::vrf_input(101, 0, &rand);
        assert_ne!(a, b);
    }

    #[test]
    fn test_vrf_input_differs_by_round() {
        let rand = [0xAA; 32];
        let a = VrfOutput::vrf_input(100, 0, &rand);
        let b = VrfOutput::vrf_input(100, 1, &rand);
        assert_ne!(a, b);
    }

    #[test]
    fn test_timeout_config() {
        let cfg = TimeoutConfig::default();
        assert_eq!(cfg.timeout_ms(0), 3_000);
        assert_eq!(cfg.timeout_ms(5), 8_000);
        assert_eq!(cfg.timeout_ms(100), 30_000); // capped
    }

    #[test]
    fn test_vote_signing_bytes_domain_separation() {
        let vote = BftVote {
            slot: 42,
            round: 0,
            voter: [0x01; 20],
            block_hash: Some([0xBB; 32]),
            signature: ValidatorSignature { bytes: vec![0; 3309] },
        };
        let prevote_bytes = vote.prevote_signing_bytes();
        let precommit_bytes = vote.precommit_signing_bytes();
        // Domain tags differ → signing bytes differ
        assert_ne!(prevote_bytes, precommit_bytes);
    }

    #[test]
    fn test_nil_vote_signing_bytes() {
        let vote = BftVote {
            slot: 1,
            round: 0,
            voter: [0x01; 20],
            block_hash: None,
            signature: ValidatorSignature { bytes: vec![0; 3309] },
        };
        let bytes = vote.prevote_signing_bytes();
        // Nil vote has 0x00 tag
        assert!(bytes.contains(&0x00));
    }

    #[test]
    fn test_epoch_randomness_genesis() {
        let r = EpochRandomness::genesis();
        assert_eq!(r.epoch, 0);
        assert_eq!(r.contributor_count, 0);
        assert_ne!(r.randomness, [0u8; 32]);
    }

    #[test]
    fn test_epoch_randomness_accumulate() {
        let hashes = vec![[0xAA; 32], [0xBB; 32], [0xCC; 32]];
        let r = EpochRandomness::accumulate(1, &hashes);
        assert_eq!(r.epoch, 1);
        assert_eq!(r.contributor_count, 3);
        // Different inputs → different randomness
        let r2 = EpochRandomness::accumulate(1, &[[0xDD; 32]]);
        assert_ne!(r.randomness, r2.randomness);
    }

    #[test]
    fn test_proposal_signing_bytes_deterministic() {
        let checkpoint = DagCheckpointTarget {
            block_hash: [0xC1; 32],
            blue_score: 99,
            utxo_root: [0xC2; 32],
            total_key_images: 15,
            total_applied_txs: 30,
        };
        let proposal = BftProposal {
            slot: 42,
            round: 0,
            proposer: [0x01; 20],
            block_hash: [0xBB; 32],
            dag_checkpoint: checkpoint,
            vrf_proof: VrfOutput {
                proof: vec![0; 3309],
                hash: [0xDD; 32],
            },
            valid_round: u32::MAX,
            signature: ValidatorSignature { bytes: vec![0; 3309] },
        };
        let a = proposal.signing_bytes();
        let b = proposal.signing_bytes();
        assert_eq!(a, b);
    }

    #[test]
    fn test_equivocation_evidence_signing_bytes_differ_by_type() {
        let vid = [0x01; 20];
        let sig = ValidatorSignature { bytes: vec![0; 3309] };
        let vote = BftVote {
            slot: 1,
            round: 0,
            voter: vid,
            block_hash: Some([0xAA; 32]),
            signature: sig.clone(),
        };
        let e1 = EquivocationEvidence::DoublePrevote {
            validator_id: vid,
            vote_a: vote.clone(),
            vote_b: vote.clone(),
        };
        let e2 = EquivocationEvidence::DoublePrecommit {
            validator_id: vid,
            vote_a: vote.clone(),
            vote_b: vote,
        };
        // Type tag 0x02 vs 0x03 → different bytes
        assert_ne!(e1.signing_bytes(), e2.signing_bytes());
    }

    #[test]
    fn test_qc_quorum_check() {
        let qc = QuorumCertificate {
            qc_type: QcType::Precommit,
            slot: 1,
            round: 0,
            block_hash: Some([0xAA; 32]),
            votes: vec![],
            total_weight: 200,
        };
        // total_stake = 300, threshold = 6667 BPS → need ≈ 201
        assert!(!qc.has_quorum(300));
        let qc2 = QuorumCertificate { total_weight: 201, ..qc };
        assert!(qc2.has_quorum(300));
    }
}
