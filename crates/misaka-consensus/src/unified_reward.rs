//! Unified Reward Model — three-pool distribution with linear stake.
//!
//! # Design
//!
//! ```text
//! Total Epoch Reward = Inflation Emission + Fee Pool
//!
//! ┌──────────────────────────────────────────────────────┐
//! │                                                      │
//! │  ┌─────────────┐  ┌──────────────┐  ┌────────────┐ │
//! │  │  BasePool    │  │  ServicePool  │  │ ProducerPool│ │
//! │  │  (40%)       │  │  (35%)        │  │  (25%)     │ │
//! │  │              │  │               │  │            │ │
//! │  │  Proportional│  │  Contribution  │  │  Blocks    │ │
//! │  │  to STAKE    │  │  based (C_i)  │  │  produced  │ │
//! │  │  (linear)    │  │               │  │  (P_i)     │ │
//! │  └─────────────┘  └──────────────┘  └────────────┘ │
//! └──────────────────────────────────────────────────────┘
//! ```
//!
//! # Stake Model
//!
//! IMPORTANT: Stake directly represents trust (Ethereum model).
//!
//! `S_i = stake_i` (NO sqrt, NO log)
//!
//! This means a validator with 2× stake gets 2× base reward.
//! The Service and Producer pools compensate small stakers
//! who contribute more work relative to their stake.
//!
//! # Final Reward Formula
//!
//! ```text
//! Reward_i = BasePool × (S_i / ΣS)
//!          + ServicePool × (C_i / ΣC)
//!          + ProducerPool × (P_i / ΣP)
//! ```
//!
//! Where:
//! - S_i = stake (linear, base units)
//! - C_i = contribution score (0-10000 BPS)
//! - P_i = producer score (accepted blocks)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use misaka_types::validator::ValidatorId;

// ═══════════════════════════════════════════════════════════════
//  Pool Configuration
// ═══════════════════════════════════════════════════════════════

/// Pool allocation — how the total epoch reward is split.
///
/// All values are BPS (must sum to 10000).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
    /// Base pool: distributed proportional to stake (linear).
    pub base_pool_bps: u32,
    /// Service pool: distributed proportional to contribution score.
    pub service_pool_bps: u32,
    /// Producer pool: distributed proportional to blocks produced.
    pub producer_pool_bps: u32,
    /// Treasury pool: protocol development fund.
    pub treasury_bps: u32,
    /// Burn pool: deflationary pressure.
    pub burn_bps: u32,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            base_pool_bps: 3500,     // 35% — stake-proportional
            service_pool_bps: 3000,  // 30% — contribution-based
            producer_pool_bps: 2000, // 20% — block production
            treasury_bps: 500,       // 5% — treasury
            burn_bps: 1000,          // 10% — burn
        }
    }
}

impl PoolConfig {
    pub fn total(&self) -> u32 {
        self.base_pool_bps
            + self.service_pool_bps
            + self.producer_pool_bps
            + self.treasury_bps
            + self.burn_bps
    }

    /// Validate that pool allocations sum to 10000 BPS.
    pub fn validate(&self) -> Result<(), String> {
        let total = self.total();
        if total != 10_000 {
            return Err(format!(
                "pool allocations must sum to 10000 BPS, got {}",
                total
            ));
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════
//  Node Reward Input
// ═══════════════════════════════════════════════════════════════

/// Per-node input for reward calculation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRewardInput {
    /// Node identifier.
    pub node_id: [u8; 32],
    /// Stake amount (base units, linear — NOT sqrt/log).
    pub stake: u64,
    /// Contribution score C_i (0-10000 BPS).
    pub contribution_score: u32,
    /// Producer score P_i (accepted blocks, weighted).
    pub producer_score: u64,
}

// ═══════════════════════════════════════════════════════════════
//  Epoch Reward Distribution
// ═══════════════════════════════════════════════════════════════

/// Per-node reward breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeReward {
    pub node_id: [u8; 32],
    /// Reward from base pool (stake-proportional).
    pub base_reward: u64,
    /// Reward from service pool (contribution-proportional).
    pub service_reward: u64,
    /// Reward from producer pool (production-proportional).
    pub producer_reward: u64,
    /// Total reward.
    pub total_reward: u64,
}

/// Full epoch reward distribution result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochRewardResult {
    /// Per-node rewards.
    pub node_rewards: Vec<NodeReward>,
    /// Amount sent to treasury.
    pub treasury_amount: u64,
    /// Amount burned.
    pub burn_amount: u64,
    /// Dust (rounding remainder) — carried to next epoch.
    pub dust: u64,
    /// Total distributed (excluding treasury + burn + dust).
    pub total_distributed: u64,
}

/// Compute epoch reward distribution for all nodes.
///
/// # Arguments
///
/// * `total_reward` - Total reward for this epoch (inflation + fees)
/// * `nodes` - All participating nodes with their metrics
/// * `pool_config` - Pool allocation configuration
///
/// # Returns
///
/// Per-node rewards + treasury + burn amounts.
///
/// # Integer Arithmetic
///
/// All computations use u128 intermediate values to prevent overflow.
/// No floating point is used anywhere (consensus-safe).
pub fn distribute_epoch_rewards(
    total_reward: u64,
    nodes: &[NodeRewardInput],
    pool_config: &PoolConfig,
) -> EpochRewardResult {
    if nodes.is_empty() || total_reward == 0 {
        return EpochRewardResult {
            node_rewards: vec![],
            treasury_amount: 0,
            burn_amount: 0,
            dust: total_reward,
            total_distributed: 0,
        };
    }

    let total = total_reward as u128;

    // Compute pool sizes
    let base_pool = total * pool_config.base_pool_bps as u128 / 10_000;
    let service_pool = total * pool_config.service_pool_bps as u128 / 10_000;
    let producer_pool = total * pool_config.producer_pool_bps as u128 / 10_000;
    let treasury = total * pool_config.treasury_bps as u128 / 10_000;
    let burn = total * pool_config.burn_bps as u128 / 10_000;

    // Compute totals for proportional distribution
    let total_stake: u128 = nodes.iter().map(|n| n.stake as u128).sum();
    let total_contribution: u128 = nodes.iter().map(|n| n.contribution_score as u128).sum();
    let total_production: u128 = nodes.iter().map(|n| n.producer_score as u128).sum();

    // Distribute to each node
    let mut node_rewards = Vec::with_capacity(nodes.len());
    let mut total_distributed: u128 = 0;

    for node in nodes {
        // Base reward: proportional to stake (linear)
        let base_reward = if total_stake > 0 {
            base_pool * node.stake as u128 / total_stake
        } else {
            0
        };

        // Service reward: proportional to contribution score
        let service_reward = if total_contribution > 0 {
            service_pool * node.contribution_score as u128 / total_contribution
        } else {
            0
        };

        // Producer reward: proportional to producer score
        let producer_reward = if total_production > 0 {
            producer_pool * node.producer_score as u128 / total_production
        } else {
            0
        };

        let node_total = base_reward + service_reward + producer_reward;
        total_distributed += node_total;

        node_rewards.push(NodeReward {
            node_id: node.node_id,
            base_reward: base_reward as u64,
            service_reward: service_reward as u64,
            producer_reward: producer_reward as u64,
            total_reward: node_total as u64,
        });
    }

    // Dust = total - (distributed + treasury + burn)
    let accounted = total_distributed + treasury + burn;
    let dust = if total > accounted {
        total - accounted
    } else {
        0
    };

    EpochRewardResult {
        node_rewards,
        treasury_amount: treasury as u64,
        burn_amount: burn as u64,
        dust: dust as u64,
        total_distributed: total_distributed as u64,
    }
}

// ═══════════════════════════════════════════════════════════════
//  Reward Estimation (for user dashboard)
// ═══════════════════════════════════════════════════════════════

/// Estimate rewards for a single node (for display purposes only).
///
/// This is an approximation — actual rewards depend on all other nodes'
/// participation in the epoch.
pub fn estimate_reward(
    my_stake: u64,
    my_contribution: u32,
    total_stake: u64,
    avg_contribution: u32,
    total_epoch_reward: u64,
    pool_config: &PoolConfig,
) -> u64 {
    if total_stake == 0 || total_epoch_reward == 0 {
        return 0;
    }

    let total = total_epoch_reward as u128;

    // Estimate base reward
    let base_pool = total * pool_config.base_pool_bps as u128 / 10_000;
    let base_estimate = base_pool * my_stake as u128 / total_stake as u128;

    // Estimate service reward (assume average contribution for others)
    let service_pool = total * pool_config.service_pool_bps as u128 / 10_000;
    let service_estimate = if avg_contribution > 0 {
        service_pool * my_contribution as u128
            / (my_contribution as u128 + avg_contribution as u128 * 99) // Assume ~100 nodes
    } else {
        0
    };

    (base_estimate + service_estimate).min(total) as u64
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(id: u8, stake: u64, contribution: u32, production: u64) -> NodeRewardInput {
        let mut node_id = [0u8; 32];
        node_id[0] = id;
        NodeRewardInput {
            node_id,
            stake,
            contribution_score: contribution,
            producer_score: production,
        }
    }

    #[test]
    fn test_pool_config_validation() {
        let config = PoolConfig::default();
        assert!(config.validate().is_ok());

        let bad = PoolConfig {
            base_pool_bps: 5000,
            service_pool_bps: 5000,
            producer_pool_bps: 5000,
            treasury_bps: 0,
            burn_bps: 0,
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn test_basic_distribution() {
        let nodes = vec![
            make_node(1, 100, 5000, 10),
            make_node(2, 200, 5000, 10),
            make_node(3, 300, 5000, 10),
        ];
        let result = distribute_epoch_rewards(10_000, &nodes, &PoolConfig::default());

        // Base pool (35%): 3500 total, split 1:2:3
        // Node 1: 3500 * 100/600 = 583
        // Node 2: 3500 * 200/600 = 1166
        // Node 3: 3500 * 300/600 = 1750
        assert_eq!(result.node_rewards[0].base_reward, 583);
        assert_eq!(result.node_rewards[1].base_reward, 1166);
        assert_eq!(result.node_rewards[2].base_reward, 1750);

        // Service pool (30%): 3000 total, equal contribution
        assert_eq!(result.node_rewards[0].service_reward, 1000);
        assert_eq!(result.node_rewards[1].service_reward, 1000);
        assert_eq!(result.node_rewards[2].service_reward, 1000);

        // Producer pool (20%): 2000 total, equal production
        assert_eq!(result.node_rewards[0].producer_reward, 666);

        // Treasury: 5%
        assert_eq!(result.treasury_amount, 500);

        // Burn: 10%
        assert_eq!(result.burn_amount, 1000);
    }

    #[test]
    fn test_stake_proportional_linear() {
        // Node A: 2× stake of Node B → 2× base reward
        let nodes = vec![
            make_node(1, 1000, 0, 0),
            make_node(2, 2000, 0, 0),
        ];
        let result = distribute_epoch_rewards(10_000, &nodes, &PoolConfig::default());

        let ratio = result.node_rewards[1].base_reward as f64
            / result.node_rewards[0].base_reward as f64;
        assert!(
            (ratio - 2.0).abs() < 0.01,
            "2× stake should yield 2× base reward, got {:.2}×",
            ratio
        );
    }

    #[test]
    fn test_high_contributor_gets_more_service_reward() {
        let nodes = vec![
            make_node(1, 1000, 9000, 0), // High contributor
            make_node(2, 1000, 1000, 0), // Low contributor
        ];
        let result = distribute_epoch_rewards(10_000, &nodes, &PoolConfig::default());

        assert!(
            result.node_rewards[0].service_reward > result.node_rewards[1].service_reward,
            "High contributor should get more service reward"
        );
        // 9:1 ratio
        let ratio = result.node_rewards[0].service_reward as f64
            / result.node_rewards[1].service_reward as f64;
        assert!(
            (ratio - 9.0).abs() < 0.1,
            "Service reward ratio should be ~9:1, got {:.1}",
            ratio
        );
    }

    #[test]
    fn test_producer_gets_producer_reward() {
        let nodes = vec![
            make_node(1, 1000, 5000, 50),  // Active producer
            make_node(2, 1000, 5000, 0),   // Non-producer
        ];
        let result = distribute_epoch_rewards(10_000, &nodes, &PoolConfig::default());

        assert!(result.node_rewards[0].producer_reward > 0);
        assert_eq!(result.node_rewards[1].producer_reward, 0);
    }

    #[test]
    fn test_empty_nodes_returns_dust() {
        let result = distribute_epoch_rewards(10_000, &[], &PoolConfig::default());
        assert_eq!(result.dust, 10_000);
        assert!(result.node_rewards.is_empty());
    }

    #[test]
    fn test_reward_conservation() {
        let nodes = vec![
            make_node(1, 500, 8000, 20),
            make_node(2, 1500, 6000, 30),
            make_node(3, 3000, 4000, 50),
        ];
        let total = 1_000_000u64;
        let result = distribute_epoch_rewards(total, &nodes, &PoolConfig::default());

        let sum = result.total_distributed
            + result.treasury_amount
            + result.burn_amount
            + result.dust;
        assert_eq!(
            sum, total,
            "Total must be conserved: distributed={} + treasury={} + burn={} + dust={} = {} (expected {})",
            result.total_distributed,
            result.treasury_amount,
            result.burn_amount,
            result.dust,
            sum,
            total
        );
    }

    #[test]
    fn test_small_staker_compensated_by_contribution() {
        // Small staker with high contribution vs large staker with low contribution
        let nodes = vec![
            make_node(1, 100, 9000, 10),   // Small stake, high contribution
            make_node(2, 10000, 1000, 10), // Large stake, low contribution
        ];
        let result = distribute_epoch_rewards(100_000, &nodes, &PoolConfig::default());

        // Node 1 should get less base reward but much more service reward
        assert!(result.node_rewards[0].base_reward < result.node_rewards[1].base_reward);
        assert!(result.node_rewards[0].service_reward > result.node_rewards[1].service_reward);

        // The service reward should partially compensate
        let node1_total = result.node_rewards[0].total_reward;
        let node2_total = result.node_rewards[1].total_reward;
        // Node 1 won't exceed node 2 (100:1 stake ratio is too large)
        // but it should be significantly more than pure stake-proportional
        assert!(
            node1_total > result.node_rewards[0].base_reward * 2,
            "Small staker's total should be > 2× their base reward"
        );
    }
}
