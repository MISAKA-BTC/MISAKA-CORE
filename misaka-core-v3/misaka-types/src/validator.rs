//! Public PoS validator types — PQ-only (ML-DSA-65).
//!
//! # Validator Lifecycle (misakastake.com → on-chain)
//!
//! 1. Operator registers at misakastake.com
//! 2. Registration creates a signed `ValidatorRegistration` message
//! 3. Registration is submitted as a transaction to the chain
//! 4. After governance/multisig approval → status becomes `Pending`
//! 5. At next epoch boundary, if stake >= minimum → `Active`
//! 6. Active validators participate in consensus
//! 7. Slashable offences → `Jailed` or `Tombstoned`
//! 8. Voluntary exit → `Unbonding` (locked for unbonding period)
//!
//! # Security
//!
//! - ECC (Ed25519) is COMPLETELY EXCLUDED.
//! - Validator signatures are ML-DSA-65 only (FIPS 204).
//! - No dev bypass. No mock verifier. No unverified handshake.

use crate::mcs1;

pub type ValidatorId = [u8; 20];

/// Minimum self-stake to become Active (in base units).
pub const MINIMUM_SELF_STAKE: u128 = 100_000_000; // 100 MISAKA

/// Unbonding duration in epochs.
pub const UNBONDING_EPOCHS: u64 = 14; // ~7 days at 720 blocks/epoch, 60s blocks

/// Maximum commission rate (basis points, 10000 = 100%).
pub const MAX_COMMISSION_BPS: u16 = 5000; // 50%

/// Maximum jail duration in epochs before auto-tombstoning.
pub const MAX_JAIL_EPOCHS: u64 = 100;

// ─── Validator Status ──────────────────────────────────────

/// Validator lifecycle status.
///
/// State transitions:
/// ```text
/// Pending ──(epoch + stake ok)──► Active
/// Active  ──(voluntary exit)────► Unbonding
/// Active  ──(minor offence)─────► Jailed
/// Jailed  ──(unjail + penalty)──► Active
/// Jailed  ──(max jail exceeded)─► Tombstoned
/// Active  ──(critical offence)──► Tombstoned
/// Unbonding ──(period elapsed)──► (removed from set)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ValidatorStatus {
    /// Registered but not yet eligible for consensus.
    Pending,
    /// Participating in consensus (proposing, voting).
    Active,
    /// Temporarily excluded due to misbehavior. Can unjail.
    Jailed,
    /// Permanently excluded. Stake may be partially slashed.
    Tombstoned,
    /// Voluntarily exiting. Cannot participate in consensus.
    Unbonding,
}

impl ValidatorStatus {
    /// Whether this validator can participate in consensus.
    pub fn is_consensus_eligible(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Whether this validator's stake is still locked.
    pub fn is_stake_locked(&self) -> bool {
        !matches!(self, Self::Tombstoned)
    }
}

// ─── Core Validator Types ──────────────────────────────────

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

/// Slash record for tracking penalties.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SlashRecord {
    pub epoch: u64,
    pub reason: SlashReason,
    pub amount: u128,
}

/// Reason for slashing.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum SlashReason {
    DoubleSign,
    InvalidProposal,
    Downtime,
    Equivocation,
}

/// Complete validator identity with lifecycle state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ValidatorIdentity {
    pub validator_id: ValidatorId,
    pub stake_weight: u128,
    pub public_key: ValidatorPublicKey,
    pub status: ValidatorStatus,
    pub commission_bps: u16,
    pub moniker: String,
    pub bonded_at_epoch: u64,
    pub activated_at_epoch: u64,
    pub unbonding_ends_epoch: u64,
    pub jailed_at_epoch: u64,
    pub slashes: Vec<SlashRecord>,
    pub payout_address: Vec<u8>,
    // Backward compat helper — DEPRECATED, use status instead
    #[serde(skip)]
    _compat: (),
}

impl ValidatorIdentity {
    /// Whether this validator is active for consensus.
    pub fn is_active(&self) -> bool {
        self.status.is_consensus_eligible()
    }

    /// Backward-compat field accessor (used by existing consensus code).
    /// Returns true iff status is Active.
    #[inline]
    pub fn is_active_compat(&self) -> bool {
        self.status == ValidatorStatus::Active
    }

    /// Whether this validator meets the minimum stake requirement.
    pub fn meets_minimum_stake(&self) -> bool {
        self.stake_weight >= MINIMUM_SELF_STAKE
    }

    pub fn total_slashed(&self) -> u128 {
        self.slashes.iter().map(|s| s.amount).sum()
    }

    /// Create a minimal ValidatorIdentity for testing/genesis.
    pub fn new_active(validator_id: ValidatorId, stake_weight: u128, public_key: ValidatorPublicKey) -> Self {
        Self {
            validator_id,
            stake_weight,
            public_key,
            status: ValidatorStatus::Active,
            commission_bps: 0,
            moniker: String::new(),
            bonded_at_epoch: 0,
            activated_at_epoch: 0,
            unbonding_ends_epoch: 0,
            jailed_at_epoch: 0,
            slashes: Vec::new(),
            payout_address: Vec::new(),
            _compat: (),
        }
    }

    /// Create a Pending validator (pre-activation).
    pub fn new_pending(validator_id: ValidatorId, stake_weight: u128, public_key: ValidatorPublicKey, bonded_at_epoch: u64) -> Self {
        Self {
            validator_id,
            stake_weight,
            public_key,
            status: ValidatorStatus::Pending,
            commission_bps: 0,
            moniker: String::new(),
            bonded_at_epoch,
            activated_at_epoch: 0,
            unbonding_ends_epoch: 0,
            jailed_at_epoch: 0,
            slashes: Vec::new(),
            payout_address: Vec::new(),
            _compat: (),
        }
    }
}

// ─── Validator Registration ────────────────────────────────

/// Signed validator registration (from misakastake.com).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ValidatorRegistration {
    pub consensus_pubkey: ValidatorPublicKey,
    pub initial_stake: u128,
    pub commission_bps: u16,
    pub moniker: String,
    pub payout_address: Vec<u8>,
    pub proof_of_possession: ValidatorSignature,
    pub chain_id: u32,
    pub registration_epoch: u64,
}

impl ValidatorRegistration {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(b"MISAKA:validator_registration:v1:");
        buf.extend_from_slice(&self.chain_id.to_le_bytes());
        buf.extend_from_slice(&self.registration_epoch.to_le_bytes());
        buf.extend_from_slice(&self.consensus_pubkey.bytes);
        buf.extend_from_slice(&self.initial_stake.to_le_bytes());
        buf.extend_from_slice(&self.commission_bps.to_le_bytes());
        buf.extend_from_slice(self.moniker.as_bytes());
        buf.extend_from_slice(&self.payout_address);
        buf
    }
}

// ─── Epoch Validator Snapshot ──────────────────────────────

/// Snapshot of the validator set at a specific epoch boundary.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EpochValidatorSnapshot {
    pub epoch: u64,
    pub validators: Vec<ValidatorIdentity>,
    pub set_hash: [u8; 32],
}

// ─── Consensus Messages (unchanged) ────────────────────────

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
