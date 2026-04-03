//! Inactivity Leak & Correlation Penalty — PoS economic safety mechanisms.
//!
//! # Inactivity Leak (Ethereum-inspired)
//!
//! When the chain fails to finalize (< 2/3 online), inactive validators
//! gradually lose stake. This reduces total active stake until the
//! remaining honest validators can form a 2/3 quorum again.
//!
//! ```text
//! Epoch N:   100 validators, 30 offline → no finality
//! Epoch N+1: 30 offline validators lose X% stake each
//! ...
//! Epoch N+K: total active stake reduced enough for 70 to reach 2/3
//! ```
//!
//! # Correlation Penalty (Casper-inspired)
//!
//! If multiple validators are slashed in the same epoch, the penalty
//! increases super-linearly. This makes coordinated attacks extremely costly.
//!
//! `penalty = base × (slashed_count / total_count)²`
//!
//! One rogue validator: minor penalty. 10% colluding: devastating penalty.
//!
//! # Nothing-at-Stake Defense
//!
//! These mechanisms complement the BFT slash detector:
//! - Slash detector: catches equivocation (active misbehavior)
//! - Inactivity leak: punishes non-participation (passive attack)
//! - Correlation penalty: amplifies coordinated attacks (collusion)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use misaka_types::validator::ValidatorId;

// ═══════════════════════════════════════════════════════════════
//  Configuration
// ═══════════════════════════════════════════════════════════════

/// Configuration for inactivity leak and correlation penalties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InactivityConfig {
    /// Number of consecutive non-finalizing epochs before leak starts.
    pub leak_activation_threshold: u64,
    /// Per-epoch leak rate (BPS). 10 = 0.1% per epoch.
    pub leak_rate_bps: u64,
    /// Maximum cumulative leak (BPS). 5000 = 50% max loss from inactivity.
    pub max_leak_bps: u64,
    /// Correlation penalty exponent numerator (squared by default).
    /// penalty_multiplier = (slashed_in_epoch / total_validators) ^ exponent
    pub correlation_exponent: u32,
    /// Maximum correlation penalty multiplier (BPS). 10000 = 100%.
    pub max_correlation_penalty_bps: u64,
}

impl Default for InactivityConfig {
    fn default() -> Self {
        Self {
            leak_activation_threshold: 4, // 4 epochs without finality
            leak_rate_bps: 10,            // 0.1% per epoch
            max_leak_bps: 5000,           // max 50% loss
            correlation_exponent: 2,      // quadratic
            max_correlation_penalty_bps: 10000, // up to 100%
        }
    }
}

impl InactivityConfig {
    pub fn testnet() -> Self {
        Self {
            leak_activation_threshold: 2,
            leak_rate_bps: 50,  // 0.5% per epoch (faster for testing)
            max_leak_bps: 5000,
            correlation_exponent: 2,
            max_correlation_penalty_bps: 10000,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Inactivity Tracker
// ═══════════════════════════════════════════════════════════════

/// Tracks chain finality state and applies inactivity penalties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InactivityTracker {
    config: InactivityConfig,
    /// Number of consecutive epochs without finalization.
    pub non_finalizing_epochs: u64,
    /// Whether the inactivity leak is currently active.
    pub leak_active: bool,
    /// Per-validator cumulative leak applied (BPS).
    cumulative_leak: HashMap<ValidatorId, u64>,
    /// Per-validator participation bitmap for current epoch.
    /// true = participated (voted), false = absent.
    participation: HashMap<ValidatorId, bool>,
    /// Validators slashed in the current epoch (for correlation).
    slashed_this_epoch: Vec<ValidatorId>,
}

impl InactivityTracker {
    pub fn new(config: InactivityConfig) -> Self {
        Self {
            config,
            non_finalizing_epochs: 0,
            leak_active: false,
            cumulative_leak: HashMap::new(),
            participation: HashMap::new(),
            slashed_this_epoch: Vec::new(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(InactivityConfig::default())
    }

    // ─── Epoch Events ───────────────────────────────────────

    /// Record that a validator participated in this epoch (voted/proposed).
    pub fn record_participation(&mut self, validator_id: &ValidatorId) {
        self.participation.insert(*validator_id, true);
    }

    /// Register a validator for participation tracking.
    pub fn register_validator(&mut self, validator_id: &ValidatorId) {
        self.participation.entry(*validator_id).or_insert(false);
    }

    /// Record that a validator was slashed this epoch (for correlation).
    pub fn record_slash(&mut self, validator_id: &ValidatorId) {
        if !self.slashed_this_epoch.contains(validator_id) {
            self.slashed_this_epoch.push(*validator_id);
        }
    }

    /// Called at epoch boundary. Returns penalties to apply.
    ///
    /// `finalized_this_epoch`: whether the chain produced a finalized checkpoint
    /// `active_validator_count`: total active validators
    pub fn on_epoch_boundary(
        &mut self,
        finalized_this_epoch: bool,
        active_validator_count: u64,
    ) -> EpochPenalties {
        let mut penalties = EpochPenalties::default();

        // ─── Inactivity Leak ────────────────────────────────

        if finalized_this_epoch {
            // Chain is healthy — reset leak counter
            self.non_finalizing_epochs = 0;
            self.leak_active = false;
        } else {
            self.non_finalizing_epochs += 1;
            if self.non_finalizing_epochs >= self.config.leak_activation_threshold {
                self.leak_active = true;
            }
        }

        if self.leak_active {
            // Apply leak to all non-participating validators
            for (vid, participated) in &self.participation {
                if !participated {
                    let cumulative = self.cumulative_leak.entry(*vid).or_insert(0);
                    let new_leak = (*cumulative + self.config.leak_rate_bps)
                        .min(self.config.max_leak_bps);
                    let epoch_leak = new_leak - *cumulative;
                    *cumulative = new_leak;

                    if epoch_leak > 0 {
                        penalties.inactivity_penalties.push(InactivityPenalty {
                            validator_id: *vid,
                            penalty_bps: epoch_leak,
                            cumulative_bps: new_leak,
                            non_finalizing_epochs: self.non_finalizing_epochs,
                        });
                    }
                } else {
                    // Participating validators slowly recover
                    if let Some(cumulative) = self.cumulative_leak.get_mut(vid) {
                        *cumulative = cumulative.saturating_sub(self.config.leak_rate_bps / 2);
                    }
                }
            }
        }

        // ─── Correlation Penalty ────────────────────────────

        if !self.slashed_this_epoch.is_empty() && active_validator_count > 0 {
            let slash_fraction_bps = (self.slashed_this_epoch.len() as u128 * 10_000
                / active_validator_count as u128) as u64;

            // penalty_multiplier = (slash_fraction)^exponent × 10000
            let multiplier = self.compute_correlation_multiplier(slash_fraction_bps);

            if multiplier > 0 {
                for vid in &self.slashed_this_epoch {
                    penalties.correlation_penalties.push(CorrelationPenalty {
                        validator_id: *vid,
                        multiplier_bps: multiplier,
                        slashed_count: self.slashed_this_epoch.len() as u32,
                        total_validators: active_validator_count as u32,
                    });
                }
            }
        }

        // Reset per-epoch state
        for v in self.participation.values_mut() {
            *v = false;
        }
        self.slashed_this_epoch.clear();

        penalties
    }

    /// Compute correlation penalty multiplier.
    ///
    /// multiplier = (fraction / 10000)^exponent × 10000
    /// With exponent=2: 1% of validators → 0.01% penalty
    ///                   10% of validators → 1% penalty
    ///                   33% of validators → 10.89% penalty
    fn compute_correlation_multiplier(&self, fraction_bps: u64) -> u64 {
        if fraction_bps == 0 {
            return 0;
        }

        // Integer exponentiation: (fraction_bps)^exp / 10000^(exp-1)
        let mut result: u128 = fraction_bps as u128;
        for _ in 1..self.config.correlation_exponent {
            result = result * fraction_bps as u128 / 10_000;
        }

        result.min(self.config.max_correlation_penalty_bps as u128) as u64
    }

    // ─── Queries ────────────────────────────────────────────

    /// Whether the inactivity leak is currently active.
    pub fn is_leak_active(&self) -> bool {
        self.leak_active
    }

    /// Cumulative leak for a validator (BPS).
    pub fn cumulative_leak_bps(&self, validator_id: &ValidatorId) -> u64 {
        self.cumulative_leak.get(validator_id).copied().unwrap_or(0)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Penalty Types
// ═══════════════════════════════════════════════════════════════

/// Penalties computed at epoch boundary.
#[derive(Debug, Default)]
pub struct EpochPenalties {
    pub inactivity_penalties: Vec<InactivityPenalty>,
    pub correlation_penalties: Vec<CorrelationPenalty>,
}

impl EpochPenalties {
    pub fn is_empty(&self) -> bool {
        self.inactivity_penalties.is_empty() && self.correlation_penalties.is_empty()
    }
}

/// Inactivity penalty for a single validator.
#[derive(Debug, Clone)]
pub struct InactivityPenalty {
    pub validator_id: ValidatorId,
    /// This epoch's leak (BPS).
    pub penalty_bps: u64,
    /// Total cumulative leak (BPS).
    pub cumulative_bps: u64,
    /// How many epochs without finality.
    pub non_finalizing_epochs: u64,
}

/// Correlation penalty for a slashed validator.
#[derive(Debug, Clone)]
pub struct CorrelationPenalty {
    pub validator_id: ValidatorId,
    /// Penalty multiplier (BPS). Applied on top of base slash.
    pub multiplier_bps: u64,
    /// Number of validators slashed this epoch.
    pub slashed_count: u32,
    /// Total active validators.
    pub total_validators: u32,
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vid(n: u8) -> ValidatorId {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    #[test]
    fn test_no_penalty_when_finalizing() {
        let mut tracker = InactivityTracker::with_defaults();
        tracker.register_validator(&make_vid(1));
        let penalties = tracker.on_epoch_boundary(true, 10);
        assert!(penalties.is_empty());
        assert!(!tracker.is_leak_active());
    }

    #[test]
    fn test_leak_activates_after_threshold() {
        let config = InactivityConfig {
            leak_activation_threshold: 3,
            leak_rate_bps: 100,
            ..Default::default()
        };
        let mut tracker = InactivityTracker::new(config);
        tracker.register_validator(&make_vid(1));

        // Epochs 1-2: no finality, no leak yet
        tracker.on_epoch_boundary(false, 10);
        assert!(!tracker.is_leak_active());
        tracker.on_epoch_boundary(false, 10);
        assert!(!tracker.is_leak_active());

        // Epoch 3: leak activates
        let penalties = tracker.on_epoch_boundary(false, 10);
        assert!(tracker.is_leak_active());
        assert_eq!(penalties.inactivity_penalties.len(), 1);
        assert_eq!(penalties.inactivity_penalties[0].penalty_bps, 100);
    }

    #[test]
    fn test_participating_validators_not_leaked() {
        let config = InactivityConfig {
            leak_activation_threshold: 1,
            leak_rate_bps: 100,
            ..Default::default()
        };
        let mut tracker = InactivityTracker::new(config);
        tracker.register_validator(&make_vid(1)); // will participate
        tracker.register_validator(&make_vid(2)); // will NOT participate

        // Activate leak
        tracker.on_epoch_boundary(false, 10);

        // Only vid 1 participates
        tracker.record_participation(&make_vid(1));
        let penalties = tracker.on_epoch_boundary(false, 10);

        // Only vid 2 should be penalized
        assert_eq!(penalties.inactivity_penalties.len(), 1);
        assert_eq!(penalties.inactivity_penalties[0].validator_id, make_vid(2));
    }

    #[test]
    fn test_leak_capped_at_max() {
        let config = InactivityConfig {
            leak_activation_threshold: 1,
            leak_rate_bps: 2000, // 20% per epoch
            max_leak_bps: 5000,  // 50% max
            ..Default::default()
        };
        let mut tracker = InactivityTracker::new(config);
        tracker.register_validator(&make_vid(1));

        // Activate leak
        tracker.on_epoch_boundary(false, 10);

        // Epoch 2: 20%
        tracker.on_epoch_boundary(false, 10);
        assert_eq!(tracker.cumulative_leak_bps(&make_vid(1)), 2000);

        // Epoch 3: 40%
        tracker.on_epoch_boundary(false, 10);
        assert_eq!(tracker.cumulative_leak_bps(&make_vid(1)), 4000);

        // Epoch 4: capped at 50%
        tracker.on_epoch_boundary(false, 10);
        assert_eq!(tracker.cumulative_leak_bps(&make_vid(1)), 5000);

        // Epoch 5: still 50% (capped)
        let penalties = tracker.on_epoch_boundary(false, 10);
        assert_eq!(tracker.cumulative_leak_bps(&make_vid(1)), 5000);
        // No new penalty since cumulative is already at max
        let vid1_penalty: Vec<_> = penalties
            .inactivity_penalties
            .iter()
            .filter(|p| p.validator_id == make_vid(1))
            .collect();
        assert!(
            vid1_penalty.is_empty() || vid1_penalty[0].penalty_bps == 0,
            "No additional penalty when at max"
        );
    }

    #[test]
    fn test_finality_resets_leak() {
        let config = InactivityConfig {
            leak_activation_threshold: 1,
            leak_rate_bps: 100,
            ..Default::default()
        };
        let mut tracker = InactivityTracker::new(config);
        tracker.register_validator(&make_vid(1));

        // Activate leak
        tracker.on_epoch_boundary(false, 10);
        tracker.on_epoch_boundary(false, 10);
        assert!(tracker.is_leak_active());

        // Finality restored
        tracker.on_epoch_boundary(true, 10);
        assert!(!tracker.is_leak_active());
        assert_eq!(tracker.non_finalizing_epochs, 0);
    }

    #[test]
    fn test_correlation_penalty_single_slash() {
        let mut tracker = InactivityTracker::with_defaults();
        tracker.record_slash(&make_vid(1));

        let penalties = tracker.on_epoch_boundary(true, 100);
        assert_eq!(penalties.correlation_penalties.len(), 1);
        // 1/100 = 100 BPS → 100² / 10000 = 1 BPS (negligible)
        assert_eq!(penalties.correlation_penalties[0].multiplier_bps, 1);
    }

    #[test]
    fn test_correlation_penalty_many_slashes() {
        let mut tracker = InactivityTracker::with_defaults();
        // 33 out of 100 slashed
        for i in 0..33u8 {
            tracker.record_slash(&make_vid(i));
        }

        let penalties = tracker.on_epoch_boundary(true, 100);
        assert_eq!(penalties.correlation_penalties.len(), 33);
        // 33/100 = 3300 BPS → 3300² / 10000 = 1089 BPS ≈ 10.89%
        assert_eq!(penalties.correlation_penalties[0].multiplier_bps, 1089);
    }

    #[test]
    fn test_correlation_penalty_capped() {
        let mut tracker = InactivityTracker::with_defaults();
        // All 10 validators slashed
        for i in 0..10u8 {
            tracker.record_slash(&make_vid(i));
        }

        let penalties = tracker.on_epoch_boundary(true, 10);
        // 10/10 = 10000 BPS → 10000² / 10000 = 10000 BPS = 100%
        assert_eq!(penalties.correlation_penalties[0].multiplier_bps, 10000);
    }

    #[test]
    fn test_no_correlation_penalty_without_slashes() {
        let mut tracker = InactivityTracker::with_defaults();
        let penalties = tracker.on_epoch_boundary(true, 100);
        assert!(penalties.correlation_penalties.is_empty());
    }
}
