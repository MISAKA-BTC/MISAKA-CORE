//! Fee-rate frontier: ordered set of transactions for greedy selection.

use std::cmp::Ordering as CmpOrdering;
use std::collections::{BTreeSet, HashMap};

/// Key for ordering transactions by fee rate in the frontier.
#[derive(Debug, Clone)]
pub struct FeeRateKey {
    pub fee_rate: f64,
    pub tx_id: [u8; 32],
    pub mass: u64,
}

impl PartialEq for FeeRateKey {
    fn eq(&self, other: &Self) -> bool { self.tx_id == other.tx_id }
}
impl Eq for FeeRateKey {}

impl PartialOrd for FeeRateKey {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> { Some(self.cmp(other)) }
}

impl Ord for FeeRateKey {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        // Higher fee rate first
        other.fee_rate.partial_cmp(&self.fee_rate)
            .unwrap_or(CmpOrdering::Equal)
            .then_with(|| self.tx_id.cmp(&other.tx_id))
    }
}

/// The fee-rate frontier is an ordered set of ready-to-mine transactions.
pub struct FeeRateFrontier {
    tree: BTreeSet<FeeRateKey>,
    total_mass: u64,
    total_fees: u64,
}

impl FeeRateFrontier {
    pub fn new() -> Self {
        Self { tree: BTreeSet::new(), total_mass: 0, total_fees: 0 }
    }

    pub fn insert(&mut self, key: FeeRateKey, fee: u64) -> bool {
        if self.tree.insert(key.clone()) {
            self.total_mass += key.mass;
            self.total_fees += fee;
            true
        } else {
            false
        }
    }

    pub fn remove(&mut self, key: &FeeRateKey) -> bool {
        if self.tree.remove(key) {
            self.total_mass = self.total_mass.saturating_sub(key.mass);
            true
        } else {
            false
        }
    }

    /// Select transactions greedily by fee rate up to max_mass.
    pub fn select(&self, max_mass: u64) -> Vec<FeeRateKey> {
        let mut selected = Vec::new();
        let mut remaining_mass = max_mass;
        for key in &self.tree {
            if key.mass <= remaining_mass {
                selected.push(key.clone());
                remaining_mass -= key.mass;
            }
            if remaining_mass == 0 { break; }
        }
        selected
    }

    pub fn len(&self) -> usize { self.tree.len() }
    pub fn is_empty(&self) -> bool { self.tree.is_empty() }
    pub fn total_mass(&self) -> u64 { self.total_mass }
    pub fn total_fees(&self) -> u64 { self.total_fees }

    /// Get the minimum fee rate in the frontier.
    pub fn min_fee_rate(&self) -> f64 {
        self.tree.iter().next_back().map_or(0.0, |k| k.fee_rate)
    }

    /// Get the maximum fee rate.
    pub fn max_fee_rate(&self) -> f64 {
        self.tree.iter().next().map_or(0.0, |k| k.fee_rate)
    }
}

impl Default for FeeRateFrontier {
    fn default() -> Self { Self::new() }
}
