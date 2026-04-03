//! Dynamic Role Scoring — automatic weight assignment from runtime metrics.
//!
//! # RoleScore Formula
//!
//! ```text
//! R_i = f(reachability, latency, uptime, cpu, ram, bandwidth, history)
//!
//! Normalized components (each 0-10000 BPS):
//!   reach_score   = 10000 if reachable, 5000 if LOCAL with >=2 relays, 0 otherwise
//!   latency_score = max(0, 10000 - latency_ms * 20)     // 500ms → 0
//!   uptime_score  = uptime_bps                            // direct pass-through
//!   cpu_score     = node.cpu_score                        // direct pass-through
//!   ram_score     = min(10000, ram_mb * 10000 / 16384)   // 16GB → max
//!   bw_score      = min(10000, bw_bps * 10000 / 100Mbps) // 100Mbps → max
//!   hist_score    = history_bps                            // direct pass-through
//!
//! R_i = Σ(w_k * component_k) / Σ(w_k)
//! ```
//!
//! # Weight Assignment
//!
//! From R_i, compute per-role weights:
//!
//! ```text
//! vote_weight     = R_i * stake_factor         // everyone votes proportional to R_i
//! relay_weight    = R_i * reachability_factor   // VPS nodes relay more
//! verify_weight   = R_i * cpu_factor            // based on compute capacity
//! producer_weight = R_i * eligibility_factor    // 0 unless E_i > threshold
//! ```
//!
//! # Hysteresis
//!
//! Role weights only update when:
//! 1. At least `role_recalc_interval_secs` has passed since last update
//! 2. The change exceeds `hysteresis_threshold_bps`

use serde::{Deserialize, Serialize};

use super::unified_node::{ConnectionMode, NodeCapabilities, RoleWeights, UnifiedNodeConfig};

// ═══════════════════════════════════════════════════════════════
//  Scoring Weights
// ═══════════════════════════════════════════════════════════════

/// Weights for each component in the RoleScore calculation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleScoringWeights {
    pub reachability: u32,
    pub latency: u32,
    pub uptime: u32,
    pub cpu: u32,
    pub ram: u32,
    pub bandwidth: u32,
    pub history: u32,
}

impl Default for RoleScoringWeights {
    fn default() -> Self {
        Self {
            reachability: 20,
            latency: 15,
            uptime: 25,
            cpu: 10,
            ram: 5,
            bandwidth: 10,
            history: 15,
        }
    }
}

impl RoleScoringWeights {
    pub fn total(&self) -> u32 {
        self.reachability
            + self.latency
            + self.uptime
            + self.cpu
            + self.ram
            + self.bandwidth
            + self.history
    }
}

// ═══════════════════════════════════════════════════════════════
//  RoleScore Computation
// ═══════════════════════════════════════════════════════════════

/// Raw RoleScore — intermediate computation result.
///
/// Each component is 0-10000 BPS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleScoreComponents {
    pub reachability: u32,
    pub latency: u32,
    pub uptime: u32,
    pub cpu: u32,
    pub ram: u32,
    pub bandwidth: u32,
    pub history: u32,
    /// Weighted aggregate (0-10000 BPS).
    pub aggregate: u32,
}

/// Compute the individual score components from node capabilities.
pub fn compute_score_components(
    caps: &NodeCapabilities,
    config: &UnifiedNodeConfig,
) -> RoleScoreComponents {
    // Reachability
    let reachability = if caps.is_reachable {
        10_000
    } else if caps.mode == ConnectionMode::Local
        && caps.connected_relays >= config.min_relays_local
    {
        5_000 // LOCAL with sufficient relays
    } else {
        0
    };

    // Latency: 0ms → 10000, 500ms → 0, linear interpolation
    let latency = if caps.avg_latency_ms >= 500 {
        0
    } else {
        10_000u32.saturating_sub(caps.avg_latency_ms * 20)
    };

    // Uptime: direct pass-through (already BPS)
    let uptime = caps.uptime_bps.min(10_000);

    // CPU: direct pass-through
    let cpu = caps.cpu_score.min(10_000);

    // RAM: 16GB → 10000
    let ram = (caps.ram_mb as u64 * 10_000 / 16_384).min(10_000) as u32;

    // Bandwidth: 100 Mbps → 10000
    let bandwidth = (caps.bandwidth_bps * 10_000 / 100_000_000).min(10_000) as u32;

    // History: direct pass-through
    let history = caps.history_bps.min(10_000);

    RoleScoreComponents {
        reachability,
        latency,
        uptime,
        cpu,
        ram,
        bandwidth,
        history,
        aggregate: 0, // Computed separately
    }
}

/// Compute the weighted aggregate RoleScore from components.
pub fn compute_role_score(
    components: &mut RoleScoreComponents,
    weights: &RoleScoringWeights,
) -> u32 {
    let total_weight = weights.total();
    if total_weight == 0 {
        components.aggregate = 0;
        return 0;
    }

    let weighted_sum = components.reachability as u64 * weights.reachability as u64
        + components.latency as u64 * weights.latency as u64
        + components.uptime as u64 * weights.uptime as u64
        + components.cpu as u64 * weights.cpu as u64
        + components.ram as u64 * weights.ram as u64
        + components.bandwidth as u64 * weights.bandwidth as u64
        + components.history as u64 * weights.history as u64;

    let aggregate = (weighted_sum / total_weight as u64).min(10_000) as u32;
    components.aggregate = aggregate;
    aggregate
}

// ═══════════════════════════════════════════════════════════════
//  Weight Assignment (RoleScore → RoleWeights)
// ═══════════════════════════════════════════════════════════════

/// Compute dynamic role weights from RoleScore and node state.
///
/// # Arguments
///
/// * `role_score` - Aggregate RoleScore (0-10000 BPS)
/// * `caps` - Node capabilities
/// * `is_eligible` - Whether E_i > producer threshold (from eligibility module)
/// * `config` - Unified node config
pub fn compute_role_weights(
    role_score: u32,
    caps: &NodeCapabilities,
    is_eligible: bool,
    config: &UnifiedNodeConfig,
) -> RoleWeights {
    // Vote weight: proportional to role_score, everyone votes
    // Minimum 2000 BPS (20%) if node is active at all
    let vote_weight = if role_score > 0 {
        (role_score).max(2000)
    } else {
        0
    };

    // Relay weight: VPS nodes relay more, LOCAL can still relay via their relays
    let relay_weight = if caps.is_reachable {
        // VPS: high relay weight
        (role_score * 8 / 10).max(3000)
    } else if caps.connected_relays >= config.min_relays_local {
        // LOCAL with relays: reduced relay weight (relay through relay nodes)
        role_score * 3 / 10
    } else {
        0
    };

    // Verify weight: proportional to CPU capability
    let verify_weight = (role_score as u64 * caps.cpu_score as u64 / 10_000).min(10_000) as u32;

    // Producer weight: 0 unless eligible, then proportional to role_score
    let producer_weight = if is_eligible {
        (role_score * 9 / 10).max(1000)
    } else {
        0
    };

    RoleWeights {
        vote_weight,
        relay_weight,
        verify_weight,
        producer_weight,
    }
}

/// Apply hysteresis — only update weights if change exceeds threshold.
///
/// Returns the new weights if threshold is exceeded, or None if current
/// weights should be kept.
pub fn apply_hysteresis(
    current: &RoleWeights,
    proposed: &RoleWeights,
    threshold_bps: u32,
) -> Option<RoleWeights> {
    let changed = abs_diff(current.vote_weight, proposed.vote_weight) > threshold_bps
        || abs_diff(current.relay_weight, proposed.relay_weight) > threshold_bps
        || abs_diff(current.verify_weight, proposed.verify_weight) > threshold_bps
        || abs_diff(current.producer_weight, proposed.producer_weight) > threshold_bps;

    if changed {
        Some(*proposed)
    } else {
        None
    }
}

fn abs_diff(a: u32, b: u32) -> u32 {
    if a > b { a - b } else { b - a }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vps_higher_score_than_local() {
        let vps_caps = NodeCapabilities::vps_default();
        let local_caps = NodeCapabilities::local_default();
        let config = UnifiedNodeConfig::default();

        let mut vps_components = compute_score_components(&vps_caps, &config);
        let mut local_components = compute_score_components(&local_caps, &config);

        let vps_score = compute_role_score(&mut vps_components, &RoleScoringWeights::default());
        let local_score =
            compute_role_score(&mut local_components, &RoleScoringWeights::default());

        assert!(
            vps_score > local_score,
            "VPS ({}) should score higher than LOCAL ({})",
            vps_score,
            local_score
        );
    }

    #[test]
    fn test_local_with_relays_gets_reachability_score() {
        let mut caps = NodeCapabilities::local_default();
        caps.connected_relays = 2;
        let config = UnifiedNodeConfig::default();

        let components = compute_score_components(&caps, &config);
        assert_eq!(components.reachability, 5000);
    }

    #[test]
    fn test_local_without_relays_zero_reachability() {
        let mut caps = NodeCapabilities::local_default();
        caps.connected_relays = 0;
        let config = UnifiedNodeConfig::default();

        let components = compute_score_components(&caps, &config);
        assert_eq!(components.reachability, 0);
    }

    #[test]
    fn test_high_latency_zero_score() {
        let mut caps = NodeCapabilities::vps_default();
        caps.avg_latency_ms = 600;
        let config = UnifiedNodeConfig::default();

        let components = compute_score_components(&caps, &config);
        assert_eq!(components.latency, 0);
    }

    #[test]
    fn test_zero_latency_max_score() {
        let mut caps = NodeCapabilities::vps_default();
        caps.avg_latency_ms = 0;
        let config = UnifiedNodeConfig::default();

        let components = compute_score_components(&caps, &config);
        assert_eq!(components.latency, 10_000);
    }

    #[test]
    fn test_producer_weight_zero_when_ineligible() {
        let caps = NodeCapabilities::vps_default();
        let weights = compute_role_weights(8000, &caps, false, &UnifiedNodeConfig::default());
        assert_eq!(weights.producer_weight, 0);
    }

    #[test]
    fn test_producer_weight_positive_when_eligible() {
        let caps = NodeCapabilities::vps_default();
        let weights = compute_role_weights(8000, &caps, true, &UnifiedNodeConfig::default());
        assert!(weights.producer_weight > 0);
    }

    #[test]
    fn test_hysteresis_blocks_small_changes() {
        let current = RoleWeights {
            vote_weight: 5000,
            relay_weight: 3000,
            verify_weight: 4000,
            producer_weight: 0,
        };
        let proposed = RoleWeights {
            vote_weight: 5100, // Only +100 BPS change
            relay_weight: 3050,
            verify_weight: 4020,
            producer_weight: 0,
        };
        assert!(apply_hysteresis(&current, &proposed, 500).is_none());
    }

    #[test]
    fn test_hysteresis_allows_large_changes() {
        let current = RoleWeights {
            vote_weight: 5000,
            relay_weight: 3000,
            verify_weight: 4000,
            producer_weight: 0,
        };
        let proposed = RoleWeights {
            vote_weight: 7000, // +2000 BPS change
            relay_weight: 3000,
            verify_weight: 4000,
            producer_weight: 0,
        };
        assert!(apply_hysteresis(&current, &proposed, 500).is_some());
    }

    #[test]
    fn test_producer_weight_change_always_passes_hysteresis() {
        let current = RoleWeights {
            vote_weight: 5000,
            relay_weight: 3000,
            verify_weight: 4000,
            producer_weight: 0,
        };
        let proposed = RoleWeights {
            vote_weight: 5000,
            relay_weight: 3000,
            verify_weight: 4000,
            producer_weight: 5000, // 0 → 5000 change
        };
        assert!(apply_hysteresis(&current, &proposed, 500).is_some());
    }
}
