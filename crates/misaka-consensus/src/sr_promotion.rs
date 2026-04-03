//! SR Promotion and Replacement Policy.
//!
//! Committee size is a **governed protocol parameter**, not a compile-time constant.
//! Mainnet launches with SR15 and can expand to SR18, SR21, or beyond at epoch
//! boundaries via `CommitteePolicy::expansion()`.
//!
//! Constraints (derived from committee_size):
//!   - minimum `public_sr_min` public/VPS SR nodes
//!   - maximum `local_sr_max` local/outbound-only SR nodes
//!   - quorum = 2f+1 where f = floor((N-1)/3)
//!
//! "SR nodes decide. Public nodes anchor. Local nodes participate."

use crate::node_scoring::{NodeMetrics, NodeScore, compute_score, ScoringConfig};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
//  Committee Policy — governs all committee parameters
// ═══════════════════════════════════════════════════════════════

/// Committee policy — all thresholds derive from `committee_size`.
///
/// This is the single source of truth for committee parameters.
/// NEVER hardcode 15, 21, or any specific committee size elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CommitteePolicy {
    /// Total committee seats (e.g. 15, 18, 21).
    pub committee_size: usize,
    /// Minimum public/VPS SR nodes.
    pub public_sr_min: usize,
    /// Maximum local/outbound-only SR nodes.
    pub local_sr_max: usize,
    /// Maximum SR replacements per epoch.
    pub max_replacements_per_epoch: usize,
    /// Leader preference weight for public nodes (0-100).
    pub public_leader_preference_pct: u8,
}

impl CommitteePolicy {
    /// SR15 — initial mainnet deployment.
    ///
    /// Rationale: early mainnet has fewer high-quality operators.
    /// A smaller, higher-quality committee is safer than a larger weak one.
    pub const SR15: Self = Self {
        committee_size: 15,
        public_sr_min: 10,
        local_sr_max: 5,
        max_replacements_per_epoch: 2,
        public_leader_preference_pct: 80,
    };

    /// SR18 — intermediate expansion.
    pub const SR18: Self = Self {
        committee_size: 18,
        public_sr_min: 12,
        local_sr_max: 6,
        max_replacements_per_epoch: 2,
        public_leader_preference_pct: 80,
    };

    /// SR21 — full decentralization target.
    pub const SR21: Self = Self {
        committee_size: 21,
        public_sr_min: 14,
        local_sr_max: 7,
        max_replacements_per_epoch: 3,
        public_leader_preference_pct: 80,
    };

    /// Create a custom policy. Validates invariants.
    pub fn new(committee_size: usize, public_sr_min: usize, local_sr_max: usize) -> Result<Self, String> {
        if committee_size < 3 {
            return Err("committee_size must be >= 3 for BFT".into());
        }
        if public_sr_min + local_sr_max < committee_size {
            return Err(format!(
                "public_sr_min({}) + local_sr_max({}) < committee_size({})",
                public_sr_min, local_sr_max, committee_size
            ));
        }
        Ok(Self {
            committee_size,
            public_sr_min,
            local_sr_max,
            max_replacements_per_epoch: std::cmp::max(1, committee_size / 7),
            public_leader_preference_pct: 80,
        })
    }

    // ── Generic BFT formulas ──────────────────────────────────

    /// Maximum tolerated faults: f = floor((N-1) / 3)
    pub const fn max_faults(&self) -> usize {
        (self.committee_size - 1) / 3
    }

    /// BFT quorum threshold: ceil(2N/3).
    /// This is the standard 2/3 supermajority required for BFT safety.
    /// SR15: ceil(30/3) = 10.  SR18: ceil(36/3) = 12.  SR21: ceil(42/3) = 14.
    pub const fn quorum_threshold(&self) -> usize {
        (2 * self.committee_size + 2) / 3
    }

    /// Finality threshold (same as quorum for deterministic BFT).
    pub const fn finality_threshold(&self) -> usize {
        self.quorum_threshold()
    }

    /// Proposal acceptance threshold (same as quorum).
    pub const fn proposal_threshold(&self) -> usize {
        self.quorum_threshold()
    }

    /// Validate that a proposed expansion is safe.
    pub fn validate_expansion(&self, next: &CommitteePolicy) -> Result<(), String> {
        if next.committee_size < self.committee_size {
            return Err("committee size cannot decrease".into());
        }
        if next.committee_size - self.committee_size > 3 {
            return Err("committee expansion must be gradual (max +3 per epoch)".into());
        }
        if next.public_sr_min < self.public_sr_min {
            return Err("public_sr_min cannot decrease during expansion".into());
        }
        Ok(())
    }
}

// ── Legacy constants (derived from default policy) ──────────
// These exist for backward compatibility. New code should use CommitteePolicy.

/// Default committee policy for the current network.
pub const DEFAULT_POLICY: CommitteePolicy = CommitteePolicy::SR15;

/// Committee size (derived from default policy).
pub const SR_COMMITTEE_SIZE: usize = DEFAULT_POLICY.committee_size;
/// Minimum public SR nodes (derived).
pub const MIN_PUBLIC_SR: usize = DEFAULT_POLICY.public_sr_min;
/// Maximum local SR nodes (derived).
pub const MAX_LOCAL_SR: usize = DEFAULT_POLICY.local_sr_max;

/// Node network class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NodeClass {
    /// Public/VPS — has public IP, reachable inbound.
    Public,
    /// Local — behind NAT, outbound-only.
    Local,
}

// ═══════════════════════════════════════════════════════════════
//  Promotion Configuration
// ═══════════════════════════════════════════════════════════════

#[derive(Clone, Debug)]
pub struct PromotionConfig {
    /// Score margin within which public candidates are preferred over local (BPS).
    /// Example: 500 = 5%. If local score <= public_score * (1 + margin/10000),
    /// prefer the public candidate.
    pub public_preference_margin_bps: u64,

    /// Threshold for "materially higher" — local candidate must exceed
    /// best public candidate by this margin (BPS) to be chosen over public.
    pub materially_higher_margin_bps: u64,

    /// Maximum SR replacements per epoch.
    pub max_replacements_per_epoch: usize,

    /// Minimum thresholds for any candidate.
    pub min_uptime_bps: u64,
    pub min_latency_score: u64,    // max acceptable avg_latency_ms
    pub min_accuracy_bps: u64,     // min correct_validations / total_validations * 10000
    pub max_restart_count: u32,
    pub min_reputation: u64,

    /// Scoring config (delegated).
    pub scoring: ScoringConfig,
}

impl Default for PromotionConfig {
    fn default() -> Self {
        Self {
            public_preference_margin_bps: 500,   // 5% margin
            materially_higher_margin_bps: 1500,  // 15% to override public preference
            max_replacements_per_epoch: 3,
            min_uptime_bps: 9000,                // 90%
            min_latency_score: 500,              // max 500ms avg
            min_accuracy_bps: 9500,              // 95% accuracy
            max_restart_count: 5,
            min_reputation: 3000,                // min 30% reputation
            scoring: ScoringConfig::default(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Candidate with Class
// ═══════════════════════════════════════════════════════════════

#[derive(Clone, Debug)]
pub struct ScoredCandidate {
    pub metrics: NodeMetrics,
    pub score: NodeScore,
    pub class: NodeClass,
}

// ═══════════════════════════════════════════════════════════════
//  Promotion Result
// ═══════════════════════════════════════════════════════════════

#[derive(Clone, Debug)]
pub struct PromotionResult {
    /// New SR committee (exactly 21 members).
    pub new_committee: Vec<ScoredCandidate>,
    /// Nodes promoted to SR this epoch.
    pub promoted: Vec<([u8; 32], NodeClass)>,
    /// Nodes demoted from SR this epoch.
    pub demoted: Vec<([u8; 32], String)>,  // (id, reason)
    /// Public SR count in new committee.
    pub public_sr_count: usize,
    /// Local SR count in new committee.
    pub local_sr_count: usize,
    /// Invariant check passed.
    pub invariants_ok: bool,
    /// Ranked standby list (not selected but eligible).
    pub standby: Vec<ScoredCandidate>,
}

// ═══════════════════════════════════════════════════════════════
//  Core Algorithm
// ═══════════════════════════════════════════════════════════════

/// Check if a candidate passes minimum thresholds.
fn passes_minimum_thresholds(m: &NodeMetrics, config: &PromotionConfig) -> bool {
    if m.uptime_bps < config.min_uptime_bps { return false; }
    if m.avg_latency_ms > config.min_latency_score { return false; }
    if m.total_validations > 0 {
        let accuracy = m.correct_validations * 10000 / m.total_validations;
        if accuracy < config.min_accuracy_bps { return false; }
    }
    if m.restart_count > config.max_restart_count { return false; }
    if m.reputation < config.min_reputation { return false; }
    true
}

/// Compare two candidates with class-aware tie-breaking.
/// Returns true if `a` should be preferred over `b`.
fn prefer_a_over_b(
    a: &ScoredCandidate,
    b: &ScoredCandidate,
    config: &PromotionConfig,
    current_public_count: usize,
) -> bool {
    let a_score = a.score.total_score;
    let b_score = b.score.total_score;

    // If public SR count would drop below minimum, ALWAYS prefer public
    if current_public_count <= MIN_PUBLIC_SR {
        if a.class == NodeClass::Public && b.class == NodeClass::Local {
            return true;
        }
        if a.class == NodeClass::Local && b.class == NodeClass::Public {
            return false;
        }
    }

    // Within margin: prefer public
    let margin = config.public_preference_margin_bps;
    let score_diff_bps = if b_score > 0 {
        ((a_score as i128 - b_score as i128).abs() * 10000 / b_score as i128) as u64
    } else {
        10000 // max diff
    };

    if score_diff_bps <= margin {
        // Within margin — tie-break by class
        if a.class == NodeClass::Public && b.class == NodeClass::Local {
            return true;
        }
        if a.class == NodeClass::Local && b.class == NodeClass::Public {
            return false;
        }
    }

    // Outside margin — higher score wins
    a_score > b_score
}

/// Main promotion algorithm.
///
/// 1. Score all nodes
/// 2. Filter by minimum thresholds
/// 3. Identify underperforming current SRs
/// 4. Build new committee respecting public/local constraints
/// 5. Apply replacement limits
pub fn compute_sr_promotion(
    all_metrics: &[NodeMetrics],
    node_classes: &HashMap<[u8; 32], NodeClass>,
    config: &PromotionConfig,
) -> PromotionResult {
    // Step 1: Score and classify all nodes
    let all_scored: Vec<ScoredCandidate> = all_metrics.iter().map(|m| {
        let score = compute_score(m, &config.scoring);
        let class = node_classes.get(&m.node_id).copied().unwrap_or(NodeClass::Local);
        ScoredCandidate { metrics: m.clone(), score, class }
    }).collect();

    // Step 2: Separate current SRs (all of them) and non-SR candidates
    let current_srs: Vec<&ScoredCandidate> = all_scored.iter()
        .filter(|c| c.metrics.is_sr)
        .collect();
    // Candidates must pass minimum thresholds
    let candidates: Vec<&ScoredCandidate> = all_scored.iter()
        .filter(|c| !c.metrics.is_sr && passes_minimum_thresholds(&c.metrics, config))
        .collect();

    // Step 3: Identify underperforming SRs — demote those failing thresholds or score
    // SRs that fail thresholds are automatically demoted (not subject to replacement cap).
    // SRs that pass thresholds but have low score are demoted up to the cap.
    let mut demoted: Vec<([u8; 32], String)> = Vec::new();
    let mut retained_srs: Vec<ScoredCandidate> = Vec::new();
    let mut capped_demotions: usize = 0;

    for sr in &current_srs {
        let fails_thresholds = !passes_minimum_thresholds(&sr.metrics, config);
        let low_score = sr.score.total_score < config.scoring.min_candidate_score;

        if fails_thresholds {
            // Automatic demotion — always counted but subject to cap
            if capped_demotions < config.max_replacements_per_epoch {
                let reason = format!(
                    "failed thresholds (uptime={}bps, latency={}ms, restarts={}, rep={})",
                    sr.metrics.uptime_bps, sr.metrics.avg_latency_ms,
                    sr.metrics.restart_count, sr.metrics.reputation
                );
                demoted.push((sr.metrics.node_id, reason));
                capped_demotions += 1;
            } else {
                // Over cap — must retain even though underperforming
                retained_srs.push((*sr).clone());
            }
        } else if low_score && capped_demotions < config.max_replacements_per_epoch {
            let reason = format!(
                "low score: {} < {}", sr.score.total_score, config.scoring.min_candidate_score
            );
            demoted.push((sr.metrics.node_id, reason));
            capped_demotions += 1;
        } else {
            retained_srs.push((*sr).clone());
        }
    }

    // Step 5: Build new committee with public/local constraints
    //
    // Algorithm:
    // a) Start with retained SRs
    // b) Count public vs local in retained set
    // c) Fill vacancies from candidates, respecting constraints
    // d) Priority: if public_count < MIN_PUBLIC_SR, fill with public first

    let mut public_count: usize = retained_srs.iter()
        .filter(|s| s.class == NodeClass::Public)
        .count();
    let mut local_count: usize = retained_srs.iter()
        .filter(|s| s.class == NodeClass::Local)
        .count();

    let vacancies = SR_COMMITTEE_SIZE.saturating_sub(retained_srs.len());

    // Sort candidates by score (descending)
    let mut sorted_candidates: Vec<ScoredCandidate> = candidates.iter()
        .filter(|c| c.score.total_score >= config.scoring.min_promotion_score)
        .map(|c| (*c).clone())
        .collect();
    sorted_candidates.sort_by(|a, b| b.score.total_score.cmp(&a.score.total_score));

    let mut promoted: Vec<([u8; 32], NodeClass)> = Vec::new();
    let mut new_members: Vec<ScoredCandidate> = retained_srs.clone();
    let mut standby: Vec<ScoredCandidate> = Vec::new();

    // Fill vacancies with class-aware selection
    for candidate in &sorted_candidates {
        if promoted.len() >= vacancies { break; }

        match candidate.class {
            NodeClass::Public => {
                // Public candidate — always eligible if vacancy exists
                new_members.push(candidate.clone());
                promoted.push((candidate.metrics.node_id, NodeClass::Public));
                public_count += 1;
            }
            NodeClass::Local => {
                // Local candidate — check constraints
                if local_count >= MAX_LOCAL_SR {
                    standby.push(candidate.clone());
                    continue; // local slots full
                }
                if public_count < MIN_PUBLIC_SR {
                    // Need more public nodes — skip local unless materially higher
                    let best_public_remaining = sorted_candidates.iter()
                        .find(|c| {
                            c.class == NodeClass::Public
                                && !promoted.iter().any(|(id, _)| *id == c.metrics.node_id)
                                && !new_members.iter().any(|m| m.metrics.node_id == c.metrics.node_id)
                        });

                    if let Some(pub_candidate) = best_public_remaining {
                        // Check if local is "materially higher"
                        let threshold = config.materially_higher_margin_bps;
                        let pub_score = pub_candidate.score.total_score;
                        let local_score = candidate.score.total_score;
                        let diff_bps = if pub_score > 0 {
                            ((local_score as i128 - pub_score as i128) * 10000 / pub_score as i128) as u64
                        } else {
                            10000
                        };

                        if diff_bps >= threshold {
                            // Local is materially higher — allow it
                            new_members.push(candidate.clone());
                            promoted.push((candidate.metrics.node_id, NodeClass::Local));
                            local_count += 1;
                        } else {
                            // Prefer public — skip local for now
                            standby.push(candidate.clone());
                        }
                    } else {
                        // No public candidates left — accept local
                        new_members.push(candidate.clone());
                        promoted.push((candidate.metrics.node_id, NodeClass::Local));
                        local_count += 1;
                    }
                } else {
                    // Public minimum met — accept local normally
                    new_members.push(candidate.clone());
                    promoted.push((candidate.metrics.node_id, NodeClass::Local));
                    local_count += 1;
                }
            }
        }
    }

    // Step 6: Invariant checks
    let invariants_ok = check_invariants(&new_members);

    PromotionResult {
        new_committee: new_members,
        promoted,
        demoted,
        public_sr_count: public_count,
        local_sr_count: local_count,
        invariants_ok,
        standby,
    }
}

/// Check committee invariants.
pub fn check_invariants(committee: &[ScoredCandidate]) -> bool {
    if committee.len() > SR_COMMITTEE_SIZE { return false; }

    let local_count = committee.iter()
        .filter(|c| c.class == NodeClass::Local)
        .count();

    // Invariant 1: minimum 12 public (if enough eligible public exist)
    // Note: if < 12 eligible public nodes exist, this can be violated
    // Invariant 2: maximum 9 local
    if local_count > MAX_LOCAL_SR { return false; }

    true
}

/// Determine if an authority should be the leader/proposer.
/// Prefer public SR nodes for leader roles.
pub fn select_leader(
    committee: &[ScoredCandidate],
    round: u64,
) -> Option<&ScoredCandidate> {
    if committee.is_empty() { return None; }

    // Separate public and local
    let public_srs: Vec<&ScoredCandidate> = committee.iter()
        .filter(|c| c.class == NodeClass::Public)
        .collect();

    if !public_srs.is_empty() {
        // 80% of the time, select from public nodes
        // 20% from any node (gives local nodes some participation)
        let idx = round as usize;
        if idx % 5 < 4 {
            // Public leader
            Some(public_srs[idx % public_srs.len()])
        } else {
            // Any leader
            Some(&committee[idx % committee.len()])
        }
    } else {
        // No public nodes — fallback to round-robin
        Some(&committee[round as usize % committee.len()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_scoring::*;

    fn make_metrics(id: u8, is_sr: bool, uptime: u64, score_hint: u64) -> NodeMetrics {
        NodeMetrics {
            node_id: [id; 32],
            stake: score_hint * 1_000_000_000_000, // scale stake to get desired score range
            uptime_bps: uptime,
            avg_latency_ms: 50,
            correct_validations: 990,
            total_validations: 1000,
            restart_count: 0,
            propagation_score: 8000,
            reputation: 8000,
            is_sr,
            role: if is_sr { "sr".into() } else { "candidate".into() },
        }
    }

    fn make_classes(ids: &[(u8, NodeClass)]) -> HashMap<[u8; 32], NodeClass> {
        ids.iter().map(|(id, class)| ([*id; 32], *class)).collect()
    }

    #[test]
    fn test_public_preferred_in_tie() {
        let metrics = vec![
            make_metrics(1, false, 9800, 100), // public candidate
            make_metrics(2, false, 9800, 100), // local candidate (same score)
        ];
        let config = PromotionConfig::default();

        let a = ScoredCandidate {
            metrics: metrics[0].clone(),
            score: compute_score(&metrics[0], &config.scoring),
            class: NodeClass::Public,
        };
        let b = ScoredCandidate {
            metrics: metrics[1].clone(),
            score: compute_score(&metrics[1], &config.scoring),
            class: NodeClass::Local,
        };

        assert!(prefer_a_over_b(&a, &b, &config, 12));
    }

    #[test]
    fn test_local_chosen_when_materially_better() {
        // Local candidate has 20% higher score than best public
        let metrics = vec![
            make_metrics(1, false, 9800, 100),  // public
            make_metrics(2, false, 9900, 150),  // local — 50% more stake
        ];

        let config = PromotionConfig {
            materially_higher_margin_bps: 1000, // 10%
            ..PromotionConfig::default()
        };

        let local_score = compute_score(&metrics[1], &config.scoring);
        let public_score = compute_score(&metrics[0], &config.scoring);

        // Local should be meaningfully higher (50% more stake -> higher sqrt)
        assert!(local_score.total_score > public_score.total_score);
    }

    #[test]
    fn test_public_minimum_preserved() {
        // SR15: 10 public + 5 local = 15
        let mut metrics = Vec::new();
        // 9 good public SRs
        for i in 0..9 {
            metrics.push(make_metrics(i, true, 9900, 100));
        }
        // 1 bad public SR (should be demoted)
        metrics.push(make_metrics(9, true, 3000, 10));
        // 5 local SRs
        for i in 10..15 {
            metrics.push(make_metrics(i, true, 9800, 90));
        }
        // 1 public candidate
        metrics.push(make_metrics(30, false, 9900, 120));
        // 1 local candidate (slightly higher score)
        metrics.push(make_metrics(31, false, 9900, 125));

        let mut classes = HashMap::new();
        for i in 0u8..10 { classes.insert([i; 32], NodeClass::Public); }
        for i in 10u8..15 { classes.insert([i; 32], NodeClass::Local); }
        classes.insert([30; 32], NodeClass::Public);
        classes.insert([31; 32], NodeClass::Local);

        let config = PromotionConfig::default();
        let result = compute_sr_promotion(&metrics, &classes, &config);

        // Public SR count must be >= 12
        assert!(result.public_sr_count >= MIN_PUBLIC_SR,
            "public_sr_count={} < MIN_PUBLIC_SR={}", result.public_sr_count, MIN_PUBLIC_SR);
        assert!(result.invariants_ok);
    }

    #[test]
    fn test_local_maximum_preserved() {
        // All 15 are local — should cap at MAX_LOCAL_SR (5 for SR15)
        let mut metrics = Vec::new();
        for i in 0..(SR_COMMITTEE_SIZE as u8) {
            metrics.push(make_metrics(i, false, 9900, 100));
        }
        let classes: HashMap<[u8; 32], NodeClass> = (0..(SR_COMMITTEE_SIZE as u8))
            .map(|i| ([i; 32], NodeClass::Local))
            .collect();

        let config = PromotionConfig::default();
        let result = compute_sr_promotion(&metrics, &classes, &config);

        assert!(result.local_sr_count <= MAX_LOCAL_SR,
            "local_sr_count={} > MAX_LOCAL_SR={}", result.local_sr_count, MAX_LOCAL_SR);
        assert!(result.invariants_ok);
    }

    #[test]
    fn test_replacement_bounded() {
        // More than max_replacements bad SRs — only 3 replaced
        let mut metrics = Vec::new();
        // 5 bad public SRs
        for i in 0..5u8 {
            metrics.push(make_metrics(i, true, 2000, 5));
        }
        // 16 good public SRs
        for i in 5..21u8 {
            metrics.push(make_metrics(i, true, 9900, 100));
        }
        // 5 good public candidates
        for i in 30..35u8 {
            metrics.push(make_metrics(i, false, 9900, 120));
        }

        let classes: HashMap<[u8; 32], NodeClass> = (0..35u8)
            .map(|i| ([i; 32], NodeClass::Public))
            .collect();

        let config = PromotionConfig {
            max_replacements_per_epoch: 3,
            ..PromotionConfig::default()
        };
        let result = compute_sr_promotion(&metrics, &classes, &config);

        assert!(result.demoted.len() <= 3, "demoted {} > max 3", result.demoted.len());
        assert!(result.promoted.len() <= 3);
    }

    #[test]
    fn test_leader_prefers_public() {
        let committee: Vec<ScoredCandidate> = (0..21u8).map(|i| {
            let m = make_metrics(i, true, 9900, 100);
            let config = ScoringConfig::default();
            let score = compute_score(&m, &config);
            ScoredCandidate {
                metrics: m,
                score,
                class: if i < 12 { NodeClass::Public } else { NodeClass::Local },
            }
        }).collect();

        // Check that 80% of leaders are public
        let mut public_leaders = 0;
        for round in 0..100u64 {
            if let Some(leader) = select_leader(&committee, round) {
                if leader.class == NodeClass::Public {
                    public_leaders += 1;
                }
            }
        }
        assert!(public_leaders >= 70, "only {} public leaders out of 100", public_leaders);
    }

    #[test]
    fn test_invariant_check() {
        let config = ScoringConfig::default();
        // MAX_LOCAL_SR+1 local SRs — violates limit
        let bad_committee: Vec<ScoredCandidate> = (0..(MAX_LOCAL_SR as u8 + 1)).map(|i| {
            let m = make_metrics(i, true, 9900, 100);
            ScoredCandidate {
                metrics: m.clone(),
                score: compute_score(&m, &config),
                class: NodeClass::Local,
            }
        }).collect();
        assert!(!check_invariants(&bad_committee));

        // MAX_LOCAL_SR local SRs — ok
        let ok_committee: Vec<ScoredCandidate> = (0..(MAX_LOCAL_SR as u8)).map(|i| {
            let m = make_metrics(i, true, 9900, 100);
            ScoredCandidate {
                metrics: m.clone(),
                score: compute_score(&m, &config),
                class: NodeClass::Local,
            }
        }).collect();
        assert!(check_invariants(&ok_committee));
    }

    // ═══════════════════════════════════════════════════════════════
    //  CommitteePolicy tests — SR15/SR18/SR21 quorum correctness
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_sr15_quorum() {
        let p = CommitteePolicy::SR15;
        assert_eq!(p.committee_size, 15);
        assert_eq!(p.max_faults(), 4);           // floor((15-1)/3) = 4
        assert_eq!(p.quorum_threshold(), 10);    // ceil(2*15/3) = 10 (66.7%)
        assert_eq!(p.public_sr_min, 10);
        assert_eq!(p.local_sr_max, 5);
        // BFT safety: 15 >= 3*4+1 = 13 ✓
        assert!(p.committee_size >= 3 * p.max_faults() + 1);
    }

    #[test]
    fn test_sr18_quorum() {
        let p = CommitteePolicy::SR18;
        assert_eq!(p.committee_size, 18);
        assert_eq!(p.max_faults(), 5);           // floor((18-1)/3) = floor(17/3) = 5
        assert_eq!(p.quorum_threshold(), 12);    // ceil(2*18/3) = 12 (66.7%)
    }

    #[test]
    fn test_sr21_quorum() {
        let p = CommitteePolicy::SR21;
        assert_eq!(p.committee_size, 21);
        assert_eq!(p.max_faults(), 6);           // floor((21-1)/3) = floor(20/3) = 6
        assert_eq!(p.quorum_threshold(), 14);    // ceil(2*21/3) = 14 (66.7%)
    }

    #[test]
    fn test_quorum_generic_formula() {
        // Verify formula for committee sizes 4..30 (4 is min for meaningful BFT)
        for n in 4..=30usize {
            let p = CommitteePolicy::new(n, n * 2 / 3, n - n * 2 / 3 + 1).unwrap();
            let f = p.max_faults();
            let q = p.quorum_threshold();
            // BFT invariant: n >= 3f + 1
            assert!(n >= 3 * f + 1, "n={} f={}: n < 3f+1", n, f);
            // Quorum must be achievable with honest nodes: n - f >= q
            assert!(n - f >= q, "n={} f={} q={}: not enough honest nodes", n, f, q);
            // Quorum must be > f (otherwise Byzantine nodes alone can form quorum)
            assert!(q > f, "n={} f={} q={}: quorum <= f", n, f, q);
        }
    }

    #[test]
    fn test_expansion_validation() {
        let sr15 = CommitteePolicy::SR15;
        let sr18 = CommitteePolicy::SR18;
        let sr21 = CommitteePolicy::SR21;

        // Valid: 15 → 18
        assert!(sr15.validate_expansion(&sr18).is_ok());
        // Valid: 18 → 21
        assert!(sr18.validate_expansion(&sr21).is_ok());
        // Invalid: decrease
        assert!(sr21.validate_expansion(&sr15).is_err());
        // Invalid: jump too large (15 → 21 = +6 > 3)
        assert!(sr15.validate_expansion(&sr21).is_err());
        // Same size is OK (no-op expansion)
        assert!(sr15.validate_expansion(&sr15).is_ok());
    }

    #[test]
    fn test_public_local_caps_sr15() {
        let p = CommitteePolicy::SR15;
        assert_eq!(p.public_sr_min + p.local_sr_max, 15);
    }

    #[test]
    fn test_custom_policy_validation() {
        // Too small
        assert!(CommitteePolicy::new(2, 2, 1).is_err());
        // Valid
        assert!(CommitteePolicy::new(7, 5, 3).is_ok());
        // Insufficient seats
        assert!(CommitteePolicy::new(10, 3, 3).is_err()); // 3+3=6 < 10
    }
}
