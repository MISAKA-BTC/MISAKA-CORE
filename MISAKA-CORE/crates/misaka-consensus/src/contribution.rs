//! Contribution Scoring & Producer Eligibility.
//!
//! # Contribution Score (C_i)
//!
//! ```text
//! C_i = 0.35 × uptime
//!     + 0.25 × vote_success
//!     + 0.20 × proposal_success
//!     + 0.10 × relay_contribution
//!     + 0.10 × network_quality
//! ```
//!
//! All components are peer-observed or protocol-measured (NO self-reporting).
//!
//! # Producer Eligibility (E_i)
//!
//! ```text
//! E_i = S_i × U_i × H_i × N_i
//!
//! Where:
//!   S_i = stake (base units, linear — NOT sqrt, NOT log)
//!   U_i = uptime score (0.0-1.0)
//!   H_i = historical success rate (0.0-1.0)
//!   N_i = network quality (0.0-1.0)
//! ```
//!
//! If E_i > threshold → node becomes "producer candidate"
//!
//! LOCAL nodes CAN become producers IF:
//! - connected to >= 2 relays
//! - latency below threshold
//! - uptime above threshold

use serde::{Deserialize, Serialize};

use super::unified_node::ConnectionMode;

// ═══════════════════════════════════════════════════════════════
//  Contribution Score
// ═══════════════════════════════════════════════════════════════

/// Per-epoch contribution metrics for a single node.
///
/// All values are BPS (0-10000 = 0%-100%).
/// IMPORTANT: These are peer-observed, NOT self-reported.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContributionMetrics {
    /// Uptime: % of epoch the node was online and responsive.
    /// Measured by: missed heartbeats, missed vote slots, peer observation.
    pub uptime_bps: u32,

    /// Vote success: valid votes / expected votes.
    /// Measured by: consensus vote counting (BFT state machine).
    pub vote_success_bps: u32,

    /// Proposal success: accepted proposals / proposal attempts.
    /// Measured by: block validation pipeline.
    pub proposal_success_bps: u32,

    /// Relay contribution: VALID forwarded data ratio.
    /// Measured by: relay session stats (valid_messages / total_messages).
    /// For non-relay nodes: 0 (does not penalize).
    pub relay_contribution_bps: u32,

    /// Network quality: latency + failure rate composite.
    /// Measured by: P2P ping/pong latency + message delivery rate.
    pub network_quality_bps: u32,
}

/// Contribution scoring weights (BPS, must sum to 10000).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributionWeights {
    pub uptime: u32,
    pub vote_success: u32,
    pub proposal_success: u32,
    pub relay_contribution: u32,
    pub network_quality: u32,
}

impl Default for ContributionWeights {
    fn default() -> Self {
        Self {
            uptime: 3500,            // 35%
            vote_success: 2500,       // 25%
            proposal_success: 2000,   // 20%
            relay_contribution: 1000, // 10%
            network_quality: 1000,    // 10%
        }
    }
}

impl ContributionWeights {
    pub fn total(&self) -> u32 {
        self.uptime
            + self.vote_success
            + self.proposal_success
            + self.relay_contribution
            + self.network_quality
    }
}

/// Compute contribution score C_i (0-10000 BPS).
///
/// ```text
/// C_i = Σ(weight_k × metric_k) / Σ(weight_k)
/// ```
pub fn compute_contribution_score(
    metrics: &ContributionMetrics,
    weights: &ContributionWeights,
) -> u32 {
    let total_weight = weights.total();
    if total_weight == 0 {
        return 0;
    }

    let weighted_sum = metrics.uptime_bps as u64 * weights.uptime as u64
        + metrics.vote_success_bps as u64 * weights.vote_success as u64
        + metrics.proposal_success_bps as u64 * weights.proposal_success as u64
        + metrics.relay_contribution_bps as u64 * weights.relay_contribution as u64
        + metrics.network_quality_bps as u64 * weights.network_quality as u64;

    (weighted_sum / total_weight as u64).min(10_000) as u32
}

// ═══════════════════════════════════════════════════════════════
//  Producer Eligibility
// ═══════════════════════════════════════════════════════════════

/// Eligibility configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EligibilityConfig {
    /// Minimum stake to be considered (base units).
    pub min_stake: u64,
    /// Minimum uptime (BPS) to be eligible.
    pub min_uptime_bps: u32,
    /// Minimum historical success rate (BPS).
    pub min_history_bps: u32,
    /// Minimum network quality (BPS).
    pub min_network_quality_bps: u32,
    /// Maximum latency for LOCAL nodes (ms).
    pub max_local_latency_ms: u32,
    /// Minimum relays for LOCAL nodes.
    pub min_local_relays: u32,
    /// Eligibility score threshold: E_i must exceed this to become a producer.
    /// Units: stake_units × 10^6 (to avoid floating point).
    pub eligibility_threshold: u128,
}

impl Default for EligibilityConfig {
    fn default() -> Self {
        Self {
            min_stake: 10_000_000_000, // 10K MISAKA
            min_uptime_bps: 7000,       // 70%
            min_history_bps: 3000,      // 30% (lenient for new nodes)
            min_network_quality_bps: 5000, // 50%
            max_local_latency_ms: 300,
            min_local_relays: 2,
            eligibility_threshold: 1_000_000_000_000, // 10K MISAKA × 0.7 × 0.3 × 0.5 × 10^6
        }
    }
}

impl EligibilityConfig {
    pub fn testnet() -> Self {
        Self {
            min_stake: 1_000_000,       // 1 MISAKA
            min_uptime_bps: 5000,       // 50%
            min_history_bps: 0,         // No history required on testnet
            min_network_quality_bps: 3000, // 30%
            max_local_latency_ms: 500,
            min_local_relays: 1,
            eligibility_threshold: 0,   // No threshold on testnet
        }
    }
}

/// Eligibility check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EligibilityResult {
    /// Whether the node is eligible for block production.
    pub eligible: bool,
    /// Raw eligibility score (E_i).
    pub score: u128,
    /// Reasons for ineligibility (empty if eligible).
    pub rejection_reasons: Vec<String>,
}

/// Compute producer eligibility.
///
/// ```text
/// E_i = S_i × U_i × H_i × N_i
/// ```
///
/// Where all factors are in BPS (0-10000), and E_i is in
/// stake_units × BPS^3 / 10^12.
pub fn compute_eligibility(
    stake: u64,
    uptime_bps: u32,
    history_bps: u32,
    network_quality_bps: u32,
    mode: ConnectionMode,
    connected_relays: u32,
    avg_latency_ms: u32,
    config: &EligibilityConfig,
) -> EligibilityResult {
    let mut reasons = Vec::new();

    // Pre-checks
    if stake < config.min_stake {
        reasons.push(format!(
            "stake {} < minimum {}",
            stake, config.min_stake
        ));
    }
    if uptime_bps < config.min_uptime_bps {
        reasons.push(format!(
            "uptime {}bps < minimum {}bps",
            uptime_bps, config.min_uptime_bps
        ));
    }
    if history_bps < config.min_history_bps {
        reasons.push(format!(
            "history {}bps < minimum {}bps",
            history_bps, config.min_history_bps
        ));
    }
    if network_quality_bps < config.min_network_quality_bps {
        reasons.push(format!(
            "network quality {}bps < minimum {}bps",
            network_quality_bps, config.min_network_quality_bps
        ));
    }

    // LOCAL-specific checks
    if mode == ConnectionMode::Local {
        if connected_relays < config.min_local_relays {
            reasons.push(format!(
                "relays {} < minimum {} for LOCAL mode",
                connected_relays, config.min_local_relays
            ));
        }
        if avg_latency_ms > config.max_local_latency_ms {
            reasons.push(format!(
                "latency {}ms > maximum {}ms for LOCAL mode",
                avg_latency_ms, config.max_local_latency_ms
            ));
        }
    }

    // Compute E_i = S × U × H × N (all in BPS, result scaled to avoid FP)
    // E_i = stake × (uptime/10000) × (history/10000) × (network/10000) × 10^6
    // Using integer arithmetic to maintain determinism:
    let score = stake as u128
        * uptime_bps as u128
        * history_bps.max(1) as u128
        * network_quality_bps as u128
        / 1_000_000_000; // Normalize: 10000^3 / 10^6 = 10^6

    let eligible = reasons.is_empty() && score >= config.eligibility_threshold;

    EligibilityResult {
        eligible,
        score,
        rejection_reasons: reasons,
    }
}

// ═══════════════════════════════════════════════════════════════
//  Producer Score (P_i)
// ═══════════════════════════════════════════════════════════════

/// Per-epoch block production performance.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProducerMetrics {
    /// Number of blocks successfully proposed and accepted.
    pub accepted_blocks: u64,
    /// Number of blocks proposed but rejected.
    pub rejected_blocks: u64,
    /// Total slots where this node was elected proposer.
    pub assigned_slots: u64,
}

impl ProducerMetrics {
    /// Producer score P_i: accepted blocks weighted by success rate.
    ///
    /// P_i = accepted_blocks × (accepted / (accepted + rejected))
    ///
    /// Penalizes nodes that propose many invalid blocks.
    pub fn producer_score(&self) -> u64 {
        let total = self.accepted_blocks + self.rejected_blocks;
        if total == 0 {
            return 0;
        }
        // P_i in BPS-weighted units
        self.accepted_blocks * self.accepted_blocks / total
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contribution_score_perfect() {
        let metrics = ContributionMetrics {
            uptime_bps: 10_000,
            vote_success_bps: 10_000,
            proposal_success_bps: 10_000,
            relay_contribution_bps: 10_000,
            network_quality_bps: 10_000,
        };
        let score = compute_contribution_score(&metrics, &ContributionWeights::default());
        assert_eq!(score, 10_000);
    }

    #[test]
    fn test_contribution_score_zero() {
        let metrics = ContributionMetrics::default();
        let score = compute_contribution_score(&metrics, &ContributionWeights::default());
        assert_eq!(score, 0);
    }

    #[test]
    fn test_contribution_score_mixed() {
        let metrics = ContributionMetrics {
            uptime_bps: 9000,          // 90%
            vote_success_bps: 8000,    // 80%
            proposal_success_bps: 7000, // 70%
            relay_contribution_bps: 0,  // Not a relay
            network_quality_bps: 6000, // 60%
        };
        let score = compute_contribution_score(&metrics, &ContributionWeights::default());
        // 0.35*9000 + 0.25*8000 + 0.20*7000 + 0.10*0 + 0.10*6000
        // = 3150 + 2000 + 1400 + 0 + 600 = 7150
        assert_eq!(score, 7150);
    }

    #[test]
    fn test_eligibility_basic_vps() {
        let result = compute_eligibility(
            10_000_000_000, // 10K MISAKA
            9000,           // 90% uptime
            5000,           // 50% history
            8000,           // 80% network
            ConnectionMode::Vps,
            0,
            50,
            &EligibilityConfig::default(),
        );
        assert!(result.eligible, "VPS with good metrics should be eligible: {:?}", result.rejection_reasons);
    }

    #[test]
    fn test_eligibility_insufficient_stake() {
        let result = compute_eligibility(
            1_000, // Way too low
            9000,
            5000,
            8000,
            ConnectionMode::Vps,
            0,
            50,
            &EligibilityConfig::default(),
        );
        assert!(!result.eligible);
        assert!(result.rejection_reasons.iter().any(|r| r.contains("stake")));
    }

    #[test]
    fn test_eligibility_local_needs_relays() {
        let result = compute_eligibility(
            10_000_000_000,
            9000,
            5000,
            8000,
            ConnectionMode::Local,
            0, // No relays
            100,
            &EligibilityConfig::default(),
        );
        assert!(!result.eligible);
        assert!(result.rejection_reasons.iter().any(|r| r.contains("relay")));
    }

    #[test]
    fn test_eligibility_local_with_relays() {
        let result = compute_eligibility(
            10_000_000_000,
            9000,
            5000,
            8000,
            ConnectionMode::Local,
            3,   // 3 relays (>= min 2)
            150, // 150ms (< max 300ms)
            &EligibilityConfig::default(),
        );
        assert!(result.eligible, "LOCAL with relays should be eligible: {:?}", result.rejection_reasons);
    }

    #[test]
    fn test_eligibility_local_high_latency() {
        let result = compute_eligibility(
            10_000_000_000,
            9000,
            5000,
            8000,
            ConnectionMode::Local,
            3,
            500, // Too high
            &EligibilityConfig::default(),
        );
        assert!(!result.eligible);
        assert!(result.rejection_reasons.iter().any(|r| r.contains("latency")));
    }

    #[test]
    fn test_producer_score_perfect() {
        let metrics = ProducerMetrics {
            accepted_blocks: 100,
            rejected_blocks: 0,
            assigned_slots: 100,
        };
        assert_eq!(metrics.producer_score(), 100);
    }

    #[test]
    fn test_producer_score_with_rejections() {
        let metrics = ProducerMetrics {
            accepted_blocks: 80,
            rejected_blocks: 20,
            assigned_slots: 100,
        };
        // P_i = 80 * 80 / 100 = 64
        assert_eq!(metrics.producer_score(), 64);
    }

    #[test]
    fn test_producer_score_zero() {
        let metrics = ProducerMetrics::default();
        assert_eq!(metrics.producer_score(), 0);
    }

    #[test]
    fn test_testnet_config_lenient() {
        let config = EligibilityConfig::testnet();
        let result = compute_eligibility(
            1_000_000, // 1 MISAKA
            5000,
            0, // No history
            3000,
            ConnectionMode::Local,
            1,
            200,
            &config,
        );
        assert!(result.eligible, "Testnet should be lenient: {:?}", result.rejection_reasons);
    }
}
