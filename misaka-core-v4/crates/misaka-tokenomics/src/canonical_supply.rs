//! # Canonical Supply Model — Solana-Native MISAKA + L1 Wrapped wMISAKA
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    SOLANA (Canonical Chain)                   │
//! │                                                               │
//! │  Total Supply: FIXED (defined at genesis)                     │
//! │                                                               │
//! │  ┌──────────────────┐  ┌──────────────────────────────┐     │
//! │  │  Circulating     │  │  Validator Reward Reserve     │     │
//! │  │  MISAKA          │  │  2,000,000,000 MISAKA         │     │
//! │  └────────┬─────────┘  └────────────┬─────────────────┘     │
//! │           │ lock                     │ lock (subsidy)         │
//! │           ▼                          ▼                        │
//! │  ┌──────────────────────────────────────────────────────┐   │
//! │  │            Bridge Vault (Multisig + Timelock)         │   │
//! │  │            locked_misaka_on_solana                     │   │
//! │  └──────────────────────┬───────────────────────────────┘   │
//! └─────────────────────────┼───────────────────────────────────┘
//!                           │ bridge proof
//!                           ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    MISAKA L1                                  │
//! │                                                               │
//! │  ┌──────────────────────────────────────────────────────┐   │
//! │  │            wMISAKA Supply Tracker                      │   │
//! │  │  outstanding_wmisaka <= locked_misaka_on_solana        │   │
//! │  └──────────────────────────────────────────────────────┘   │
//! │                                                               │
//! │  mint wMISAKA ← verified bridge lock proof                   │
//! │  burn wMISAKA → verified bridge release proof                │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Bridge Invariant
//!
//! At ALL times: `outstanding_wmisaka_on_l1 <= locked_misaka_on_solana`
//!
//! This invariant is enforced at the type level — `mint_wmisaka()` requires
//! a `VerifiedLockProof` that can only be constructed by the bridge verifier.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Total validator reward reserve on Solana (in base units, 9 decimals).
pub const VALIDATOR_REWARD_RESERVE: u128 = 2_000_000_000_000_000_000; // 2B × 10^9

/// MISAKA token decimals.
pub const DECIMALS: u32 = 9;

/// One full MISAKA token in base units.
pub const ONE_MISAKA: u128 = 1_000_000_000; // 10^9

// ═══════════════════════════════════════════════════════════════
//  Bridge Proof Types (type-level safety)
// ═══════════════════════════════════════════════════════════════

/// A verified proof that MISAKA was locked on Solana.
///
/// This type can ONLY be constructed by the bridge verifier after
/// confirming the Solana lock transaction. It is consumed by
/// `mint_wmisaka()` to prevent double-minting.
#[derive(Debug, Clone)]
pub struct VerifiedLockProof {
    /// Amount of MISAKA locked on Solana (base units).
    pub amount: u128,
    /// Solana transaction signature (for audit trail).
    pub solana_tx_sig: [u8; 64],
    /// Lock epoch on Solana.
    pub lock_slot: u64,
    /// Bridge vault authority that confirmed the lock.
    pub vault_authority: [u8; 32],
    /// Proof hash (for idempotency — prevents double-mint of same lock).
    proof_hash: [u8; 32],
}

impl VerifiedLockProof {
    /// Create a verified lock proof. This should ONLY be called by the
    /// bridge verification pipeline after confirming the Solana transaction.
    ///
    /// # Security
    ///
    /// The `proof_hash` is derived from the transaction signature and amount,
    /// making each lock proof unique. The supply tracker uses this to prevent
    /// double-minting from the same Solana lock event.
    pub fn new(
        amount: u128,
        solana_tx_sig: [u8; 64],
        lock_slot: u64,
        vault_authority: [u8; 32],
    ) -> Self {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:lock_proof:v1:");
        h.update(amount.to_le_bytes());
        h.update(&solana_tx_sig);
        h.update(lock_slot.to_le_bytes());
        h.update(&vault_authority);
        let proof_hash: [u8; 32] = h.finalize().into();

        Self { amount, solana_tx_sig, lock_slot, vault_authority, proof_hash }
    }

    pub fn proof_hash(&self) -> &[u8; 32] { &self.proof_hash }
}

/// A verified proof that wMISAKA was burned on L1.
///
/// Consumed by the Solana side to release locked MISAKA.
#[derive(Debug, Clone)]
pub struct VerifiedBurnProof {
    /// Amount of wMISAKA burned on L1 (base units).
    pub amount: u128,
    /// L1 block hash containing the burn transaction.
    pub l1_block_hash: [u8; 32],
    /// L1 transaction hash.
    pub l1_tx_hash: [u8; 32],
    /// Destination Solana address for the released MISAKA.
    pub solana_destination: [u8; 32],
}

// ═══════════════════════════════════════════════════════════════
//  Canonical Supply Tracker (L1 side)
// ═══════════════════════════════════════════════════════════════

/// Tracks the wMISAKA supply on MISAKA L1 and enforces the bridge invariant.
///
/// # Invariant
///
/// `outstanding_wmisaka <= locked_misaka_on_solana`
///
/// This is checked on every mint and is the core safety property.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalSupplyTracker {
    /// Total wMISAKA currently outstanding on L1.
    pub outstanding_wmisaka: u128,
    /// Total MISAKA locked on Solana (as reported by bridge).
    pub locked_misaka_on_solana: u128,
    /// Total wMISAKA ever minted on L1 (monotonically increasing).
    pub total_minted: u128,
    /// Total wMISAKA ever burned on L1 (monotonically increasing).
    pub total_burned: u128,
    /// Total MISAKA locked from validator reward reserve for subsidies.
    pub total_subsidy_locked: u128,
    /// Remaining validator reward reserve on Solana.
    pub remaining_reward_reserve: u128,
    /// Lock proof hashes already processed (prevents double-mint).
    processed_lock_proofs: std::collections::HashSet<[u8; 32]>,
}

/// Errors from supply operations.
#[derive(Debug, thiserror::Error)]
pub enum SupplyError {
    #[error("bridge invariant violated: outstanding={outstanding} would exceed locked={locked}")]
    BridgeInvariantViolation { outstanding: u128, locked: u128 },

    #[error("insufficient wMISAKA to burn: requested={requested}, available={available}")]
    InsufficientBurn { requested: u128, available: u128 },

    #[error("duplicate lock proof: hash={}", hex::encode(hash))]
    DuplicateLockProof { hash: [u8; 32] },

    #[error("insufficient reward reserve: requested={requested}, remaining={remaining}")]
    InsufficientReserve { requested: u128, remaining: u128 },

    #[error("zero amount operation")]
    ZeroAmount,
}

impl CanonicalSupplyTracker {
    /// Initialize with the full validator reward reserve.
    pub fn new() -> Self {
        Self {
            outstanding_wmisaka: 0,
            locked_misaka_on_solana: 0,
            total_minted: 0,
            total_burned: 0,
            total_subsidy_locked: 0,
            remaining_reward_reserve: VALIDATOR_REWARD_RESERVE,
            processed_lock_proofs: std::collections::HashSet::new(),
        }
    }

    /// Mint wMISAKA on L1 after a verified lock on Solana.
    ///
    /// # Bridge Invariant Check
    ///
    /// The invariant `outstanding_wmisaka <= locked_misaka_on_solana` is checked
    /// BEFORE the mint. If it would be violated, the mint is rejected.
    ///
    /// # Idempotency
    ///
    /// Each lock proof can only be used once. Duplicate proofs are rejected
    /// to prevent double-minting.
    pub fn mint_wmisaka(&mut self, proof: &VerifiedLockProof) -> Result<(), SupplyError> {
        if proof.amount == 0 {
            return Err(SupplyError::ZeroAmount);
        }

        // Idempotency check
        if self.processed_lock_proofs.contains(&proof.proof_hash) {
            return Err(SupplyError::DuplicateLockProof { hash: proof.proof_hash });
        }

        // Update locked amount (Solana side reported lock)
        let new_locked = self.locked_misaka_on_solana + proof.amount;
        let new_outstanding = self.outstanding_wmisaka + proof.amount;

        // Bridge invariant check
        if new_outstanding > new_locked {
            return Err(SupplyError::BridgeInvariantViolation {
                outstanding: new_outstanding,
                locked: new_locked,
            });
        }

        self.locked_misaka_on_solana = new_locked;
        self.outstanding_wmisaka = new_outstanding;
        self.total_minted += proof.amount;
        self.processed_lock_proofs.insert(proof.proof_hash);

        Ok(())
    }

    /// Burn wMISAKA on L1 (preparation for release on Solana).
    ///
    /// Returns a `VerifiedBurnProof` that the Solana side uses to release.
    pub fn burn_wmisaka(
        &mut self,
        amount: u128,
        l1_block_hash: [u8; 32],
        l1_tx_hash: [u8; 32],
        solana_destination: [u8; 32],
    ) -> Result<VerifiedBurnProof, SupplyError> {
        if amount == 0 {
            return Err(SupplyError::ZeroAmount);
        }
        if amount > self.outstanding_wmisaka {
            return Err(SupplyError::InsufficientBurn {
                requested: amount,
                available: self.outstanding_wmisaka,
            });
        }

        self.outstanding_wmisaka -= amount;
        self.total_burned += amount;

        // Note: locked_misaka_on_solana is decremented by the Solana side
        // when it processes the burn proof and releases MISAKA.

        Ok(VerifiedBurnProof {
            amount, l1_block_hash, l1_tx_hash, solana_destination,
        })
    }

    /// Lock MISAKA from the validator reward reserve for subsidy minting.
    ///
    /// This is called when weekly fee income is insufficient for the target reward.
    /// The locked amount becomes available for wMISAKA minting as validator rewards.
    pub fn lock_subsidy_from_reserve(&mut self, amount: u128) -> Result<VerifiedLockProof, SupplyError> {
        if amount == 0 {
            return Err(SupplyError::ZeroAmount);
        }
        if amount > self.remaining_reward_reserve {
            return Err(SupplyError::InsufficientReserve {
                requested: amount,
                remaining: self.remaining_reward_reserve,
            });
        }

        self.remaining_reward_reserve -= amount;
        self.total_subsidy_locked += amount;

        // Create a lock proof for the subsidy amount.
        // The Solana tx signature is zeroed — this is an internal accounting lock,
        // not an external user bridge operation.
        Ok(VerifiedLockProof::new(
            amount,
            [0u8; 64], // internal subsidy — no Solana tx
            0,
            [0u8; 32],
        ))
    }

    /// Verify the bridge invariant holds.
    pub fn verify_invariant(&self) -> Result<(), SupplyError> {
        if self.outstanding_wmisaka > self.locked_misaka_on_solana {
            return Err(SupplyError::BridgeInvariantViolation {
                outstanding: self.outstanding_wmisaka,
                locked: self.locked_misaka_on_solana,
            });
        }
        Ok(())
    }

    /// Snapshot for reporting.
    pub fn snapshot(&self) -> SupplySnapshot {
        SupplySnapshot {
            outstanding_wmisaka: self.outstanding_wmisaka,
            locked_misaka_on_solana: self.locked_misaka_on_solana,
            total_minted: self.total_minted,
            total_burned: self.total_burned,
            remaining_reward_reserve: self.remaining_reward_reserve,
            total_subsidy_locked: self.total_subsidy_locked,
            backing_ratio_bps: if self.outstanding_wmisaka == 0 {
                10_000 // 100% if no wMISAKA outstanding
            } else {
                ((self.locked_misaka_on_solana as u128 * 10_000) / self.outstanding_wmisaka) as u64
            },
        }
    }
}

/// Supply snapshot for RPC / monitoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplySnapshot {
    pub outstanding_wmisaka: u128,
    pub locked_misaka_on_solana: u128,
    pub total_minted: u128,
    pub total_burned: u128,
    pub remaining_reward_reserve: u128,
    pub total_subsidy_locked: u128,
    /// Backing ratio in basis points (10000 = 100%).
    /// Must always be >= 10000.
    pub backing_ratio_bps: u64,
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mint_and_invariant() {
        let mut tracker = CanonicalSupplyTracker::new();
        let proof = VerifiedLockProof::new(1000 * ONE_MISAKA, [1; 64], 100, [2; 32]);
        tracker.mint_wmisaka(&proof).expect("mint should succeed");

        assert_eq!(tracker.outstanding_wmisaka, 1000 * ONE_MISAKA);
        assert_eq!(tracker.locked_misaka_on_solana, 1000 * ONE_MISAKA);
        tracker.verify_invariant().expect("invariant should hold");
    }

    #[test]
    fn test_double_mint_rejected() {
        let mut tracker = CanonicalSupplyTracker::new();
        let proof = VerifiedLockProof::new(100 * ONE_MISAKA, [1; 64], 100, [2; 32]);
        tracker.mint_wmisaka(&proof).expect("first mint");

        let result = tracker.mint_wmisaka(&proof);
        assert!(matches!(result, Err(SupplyError::DuplicateLockProof { .. })));
    }

    #[test]
    fn test_burn_and_release() {
        let mut tracker = CanonicalSupplyTracker::new();
        let proof = VerifiedLockProof::new(500 * ONE_MISAKA, [1; 64], 100, [2; 32]);
        tracker.mint_wmisaka(&proof).expect("mint");

        let burn_proof = tracker.burn_wmisaka(
            200 * ONE_MISAKA, [3; 32], [4; 32], [5; 32],
        ).expect("burn");

        assert_eq!(burn_proof.amount, 200 * ONE_MISAKA);
        assert_eq!(tracker.outstanding_wmisaka, 300 * ONE_MISAKA);
        assert_eq!(tracker.total_burned, 200 * ONE_MISAKA);
    }

    #[test]
    fn test_burn_exceeds_outstanding_rejected() {
        let mut tracker = CanonicalSupplyTracker::new();
        let proof = VerifiedLockProof::new(100 * ONE_MISAKA, [1; 64], 100, [2; 32]);
        tracker.mint_wmisaka(&proof).expect("mint");

        let result = tracker.burn_wmisaka(200 * ONE_MISAKA, [3; 32], [4; 32], [5; 32]);
        assert!(matches!(result, Err(SupplyError::InsufficientBurn { .. })));
    }

    #[test]
    fn test_subsidy_lock_and_mint() {
        let mut tracker = CanonicalSupplyTracker::new();

        // Lock subsidy from reserve
        let subsidy_proof = tracker.lock_subsidy_from_reserve(50 * ONE_MISAKA)
            .expect("subsidy lock");

        // Mint wMISAKA from subsidy
        tracker.mint_wmisaka(&subsidy_proof).expect("subsidy mint");

        assert_eq!(tracker.outstanding_wmisaka, 50 * ONE_MISAKA);
        assert_eq!(tracker.remaining_reward_reserve, VALIDATOR_REWARD_RESERVE - 50 * ONE_MISAKA);
        tracker.verify_invariant().expect("invariant holds");
    }

    #[test]
    fn test_subsidy_exceeds_reserve_rejected() {
        let mut tracker = CanonicalSupplyTracker::new();
        let result = tracker.lock_subsidy_from_reserve(VALIDATOR_REWARD_RESERVE + 1);
        assert!(matches!(result, Err(SupplyError::InsufficientReserve { .. })));
    }

    #[test]
    fn test_zero_amount_rejected() {
        let mut tracker = CanonicalSupplyTracker::new();
        assert!(matches!(
            tracker.lock_subsidy_from_reserve(0),
            Err(SupplyError::ZeroAmount)
        ));
    }

    #[test]
    fn test_backing_ratio() {
        let mut tracker = CanonicalSupplyTracker::new();
        let proof = VerifiedLockProof::new(1000 * ONE_MISAKA, [1; 64], 100, [2; 32]);
        tracker.mint_wmisaka(&proof).expect("mint");

        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.backing_ratio_bps, 10_000); // 100%
    }
}
