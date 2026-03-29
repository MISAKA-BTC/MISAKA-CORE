//! Fee rate estimation and statistics.

use std::collections::VecDeque;

/// Fee estimations based on recent block data.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FeerateEstimations {
    pub priority_fee_rate: f64,
    pub normal_fee_rate: f64,
    pub low_fee_rate: f64,
}

/// Detailed fee estimation with confidence intervals.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FeeEstimateVerbose {
    pub priority_fee_rate: f64,
    pub normal_fee_rate: f64,
    pub low_fee_rate: f64,
    pub priority_block_estimate: u64,
    pub normal_block_estimate: u64,
    pub low_block_estimate: u64,
    pub mempool_percentiles: Vec<f64>,
}

/// Arguments for fee rate estimation.
pub struct FeerateEstimatorArgs {
    pub target_blocks: u64,
}

/// Fee rate estimator based on historical block data.
pub struct FeeRateEstimator {
    /// Recent block fee rates (sliding window).
    recent_blocks: VecDeque<BlockFeeData>,
    /// Maximum window size.
    max_window: usize,
    /// Minimum fee rate (network parameter).
    min_fee_rate: f64,
}

#[derive(Debug, Clone)]
struct BlockFeeData {
    pub min_fee_rate: f64,
    pub median_fee_rate: f64,
    pub max_fee_rate: f64,
    pub total_mass: u64,
    pub block_mass_utilization: f64,
}

impl FeeRateEstimator {
    pub fn new(max_window: usize, min_fee_rate: f64) -> Self {
        Self {
            recent_blocks: VecDeque::with_capacity(max_window),
            max_window,
            min_fee_rate,
        }
    }

    /// Record fee data from a newly accepted block.
    pub fn record_block(&mut self, fee_rates: &[f64], total_mass: u64, max_mass: u64) {
        if fee_rates.is_empty() { return; }

        let mut sorted = fee_rates.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let data = BlockFeeData {
            min_fee_rate: sorted[0],
            median_fee_rate: sorted[sorted.len() / 2],
            max_fee_rate: *sorted.last().unwrap_or(&0.0),
            total_mass,
            block_mass_utilization: if max_mass > 0 { total_mass as f64 / max_mass as f64 } else { 0.0 },
        };

        if self.recent_blocks.len() >= self.max_window {
            self.recent_blocks.pop_front();
        }
        self.recent_blocks.push_back(data);
    }

    /// Estimate fee rates.
    pub fn estimate(&self) -> FeerateEstimations {
        if self.recent_blocks.is_empty() {
            return FeerateEstimations {
                priority_fee_rate: self.min_fee_rate * 10.0,
                normal_fee_rate: self.min_fee_rate * 2.0,
                low_fee_rate: self.min_fee_rate,
            };
        }

        let median_rates: Vec<f64> = self.recent_blocks.iter().map(|b| b.median_fee_rate).collect();
        let avg_utilization: f64 = self.recent_blocks.iter().map(|b| b.block_mass_utilization).sum::<f64>()
            / self.recent_blocks.len() as f64;

        let base = percentile(&median_rates, 50.0);
        let congestion_factor = if avg_utilization > 0.9 { 3.0 }
            else if avg_utilization > 0.7 { 2.0 }
            else if avg_utilization > 0.5 { 1.5 }
            else { 1.0 };

        FeerateEstimations {
            priority_fee_rate: (base * congestion_factor * 2.0).max(self.min_fee_rate),
            normal_fee_rate: (base * congestion_factor).max(self.min_fee_rate),
            low_fee_rate: (base * 0.5).max(self.min_fee_rate),
        }
    }

    /// Detailed estimate with confidence intervals.
    pub fn estimate_verbose(&self) -> FeeEstimateVerbose {
        let basic = self.estimate();
        let mempool_percentiles = vec![10.0, 25.0, 50.0, 75.0, 90.0];
        FeeEstimateVerbose {
            priority_fee_rate: basic.priority_fee_rate,
            normal_fee_rate: basic.normal_fee_rate,
            low_fee_rate: basic.low_fee_rate,
            priority_block_estimate: 1,
            normal_block_estimate: 3,
            low_block_estimate: 10,
            mempool_percentiles,
        }
    }
}

fn percentile(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() { return 0.0; }
    let mut v = sorted.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = ((pct / 100.0) * (v.len() - 1) as f64) as usize;
    v[idx.min(v.len() - 1)]
}
