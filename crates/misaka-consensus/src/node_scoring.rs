//! Node scoring for SR candidate ranking and promotion.
//!
//! Score formula: score = sqrt(stake) * uptime * latency_factor * reputation
//!
//! Used to:
//! - Rank candidate nodes for SR promotion
//! - Select backup SR nodes
//! - Replace underperforming SR nodes

/// Scoring configuration.
#[derive(Clone, Debug)]
pub struct ScoringConfig {
    /// Minimum score to enter SR candidate pool.
    pub min_candidate_score: u64,
    /// Minimum score to be eligible for SR promotion.
    pub min_promotion_score: u64,
    /// Maximum SR replacements per epoch (safety bound).
    pub max_replacements_per_epoch: usize,
    /// Uptime threshold below which SR is demoted (basis points, e.g., 9500 = 95%).
    pub min_sr_uptime_bps: u64,
    /// Weight factors for scoring components.
    pub uptime_weight: f64,
    pub latency_weight: f64,
    pub reputation_weight: f64,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            min_candidate_score: 1_000,
            min_promotion_score: 5_000,
            max_replacements_per_epoch: 3, // max 3 SR changes per epoch
            min_sr_uptime_bps: 9500,       // 95% uptime
            uptime_weight: 0.30,
            latency_weight: 0.20,
            reputation_weight: 0.50,
        }
    }
}

/// Metrics tracked per node for scoring.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct NodeMetrics {
    pub node_id: [u8; 32],
    /// Stake amount (in base units).
    pub stake: u64,
    /// Uptime in basis points (0-10000). 10000 = 100%.
    pub uptime_bps: u64,
    /// Average response latency in milliseconds.
    pub avg_latency_ms: u64,
    /// Number of correct validations.
    pub correct_validations: u64,
    /// Total validation attempts.
    pub total_validations: u64,
    /// Number of restarts in the current epoch.
    pub restart_count: u32,
    /// Data propagation participation score (0-10000).
    pub propagation_score: u64,
    /// Reputation score (0-10000). Based on historical behavior.
    pub reputation: u64,
    /// Whether currently an SR.
    pub is_sr: bool,
    /// Current role.
    pub role: String,
}

/// Computed score for a node.
#[derive(Clone, Debug)]
pub struct NodeScore {
    pub node_id: [u8; 32],
    pub total_score: u64,
    pub stake_factor: f64,
    pub uptime_factor: f64,
    pub latency_factor: f64,
    pub reputation_factor: f64,
}

/// Compute score for a single node.
/// Formula: score = sqrt(stake) * uptime * latency_factor * reputation
pub fn compute_score(metrics: &NodeMetrics, config: &ScoringConfig) -> NodeScore {
    // sqrt(stake) -- diminishing returns for whale concentration
    let stake_factor = (metrics.stake as f64).sqrt();

    // Uptime factor: 0.0 to 1.0
    let uptime_factor = (metrics.uptime_bps as f64 / 10000.0).min(1.0);

    // Latency factor: lower latency = higher score. 1.0 at 0ms, 0.1 at 1000ms.
    let latency_factor = if metrics.avg_latency_ms == 0 {
        1.0
    } else {
        (1000.0 / (metrics.avg_latency_ms as f64 + 1000.0)).max(0.1)
    };

    // Reputation: 0.0 to 1.0
    let reputation_factor = (metrics.reputation as f64 / 10000.0).min(1.0);

    // Restart penalty: each restart reduces score by 5%
    let restart_penalty = (1.0 - 0.05 * metrics.restart_count as f64).max(0.5);

    // Validation accuracy bonus
    let accuracy = if metrics.total_validations > 0 {
        metrics.correct_validations as f64 / metrics.total_validations as f64
    } else {
        0.5 // neutral if no data
    };

    let total = stake_factor
        * (uptime_factor * config.uptime_weight
            + latency_factor * config.latency_weight
            + reputation_factor * config.reputation_weight)
        * restart_penalty
        * accuracy;

    NodeScore {
        node_id: metrics.node_id,
        total_score: total as u64,
        stake_factor,
        uptime_factor,
        latency_factor,
        reputation_factor,
    }
}

/// Rank all candidates and determine promotion/demotion.
pub struct PromotionResult {
    /// Candidates promoted to SR.
    pub promoted: Vec<[u8; 32]>,
    /// SRs demoted (underperforming).
    pub demoted: Vec<[u8; 32]>,
    /// Ranked candidate list (best first).
    pub ranked_candidates: Vec<NodeScore>,
}

/// Compute promotion/demotion for an epoch transition.
pub fn compute_promotion(
    all_metrics: &[NodeMetrics],
    config: &ScoringConfig,
) -> PromotionResult {
    let mut sr_scores: Vec<NodeScore> = Vec::new();
    let mut candidate_scores: Vec<NodeScore> = Vec::new();

    for m in all_metrics {
        let score = compute_score(m, config);
        if m.is_sr {
            sr_scores.push(score);
        } else {
            candidate_scores.push(score);
        }
    }

    // Sort candidates by score (descending)
    candidate_scores.sort_by(|a, b| b.total_score.cmp(&a.total_score));

    // Find underperforming SRs (below min uptime or score)
    let mut demoted = Vec::new();
    for sr in &sr_scores {
        let Some(metrics) = all_metrics.iter().find(|m| m.node_id == sr.node_id) else {
            // SR without metrics entry — treat as underperforming (defensive, no panic)
            demoted.push(sr.node_id);
            continue;
        };
        if metrics.uptime_bps < config.min_sr_uptime_bps
            || sr.total_score < config.min_candidate_score
        {
            demoted.push(sr.node_id);
        }
    }

    // Limit demotions per epoch
    demoted.truncate(config.max_replacements_per_epoch);

    // Promote top candidates to fill vacancies
    let mut promoted = Vec::new();
    for candidate in &candidate_scores {
        if promoted.len() >= demoted.len() {
            break;
        }
        if candidate.total_score >= config.min_promotion_score {
            promoted.push(candidate.node_id);
        }
    }

    PromotionResult {
        promoted,
        demoted,
        ranked_candidates: candidate_scores,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_score_computation() {
        let metrics = NodeMetrics {
            node_id: [1; 32],
            stake: 10_000_000_000_000_000, // 10M MISAKA
            uptime_bps: 9800,              // 98%
            avg_latency_ms: 50,
            correct_validations: 990,
            total_validations: 1000,
            restart_count: 0,
            propagation_score: 8000,
            reputation: 8500,
            is_sr: false,
            role: "candidate".into(),
        };
        let config = ScoringConfig::default();
        let score = compute_score(&metrics, &config);
        assert!(score.total_score > 0);
        assert!(score.uptime_factor > 0.9);
        assert!(score.latency_factor > 0.9);
    }

    #[test]
    fn test_promotion_demotion() {
        let metrics = vec![
            // SR with low uptime -- should be demoted
            NodeMetrics {
                node_id: [1; 32],
                stake: 10_000_000,
                uptime_bps: 5000,
                avg_latency_ms: 100,
                correct_validations: 500,
                total_validations: 1000,
                restart_count: 5,
                propagation_score: 3000,
                reputation: 3000,
                is_sr: true,
                role: "sr".into(),
            },
            // Candidate with high score -- should be promoted
            NodeMetrics {
                node_id: [2; 32],
                stake: 10_000_000_000_000_000, // 10M MISAKA (9 decimals)
                uptime_bps: 9900,
                avg_latency_ms: 20,
                correct_validations: 999,
                total_validations: 1000,
                restart_count: 0,
                propagation_score: 9000,
                reputation: 9500,
                is_sr: false,
                role: "candidate".into(),
            },
        ];
        let result = compute_promotion(&metrics, &ScoringConfig::default());
        assert_eq!(result.demoted.len(), 1);
        assert_eq!(result.demoted[0], [1; 32]);
        assert_eq!(result.promoted.len(), 1);
        assert_eq!(result.promoted[0], [2; 32]);
    }

    #[test]
    fn test_max_replacements_bounded() {
        // 5 bad SRs but max_replacements = 3
        let mut metrics = Vec::new();
        for i in 0..5 {
            metrics.push(NodeMetrics {
                node_id: [i; 32],
                stake: 1_000_000,
                uptime_bps: 1000,
                avg_latency_ms: 500,
                correct_validations: 100,
                total_validations: 1000,
                restart_count: 10,
                propagation_score: 1000,
                reputation: 1000,
                is_sr: true,
                role: "sr".into(),
            });
        }
        for i in 10..15 {
            metrics.push(NodeMetrics {
                node_id: [i; 32],
                stake: 10_000_000,
                uptime_bps: 9900,
                avg_latency_ms: 20,
                correct_validations: 999,
                total_validations: 1000,
                restart_count: 0,
                propagation_score: 9000,
                reputation: 9500,
                is_sr: false,
                role: "candidate".into(),
            });
        }
        let result = compute_promotion(&metrics, &ScoringConfig::default());
        assert!(result.demoted.len() <= 3); // bounded by max_replacements_per_epoch
    }
}
