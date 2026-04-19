//! Reward history ring, bounded by `--reward-history-epochs`.
//!
//! Records per-address epoch rewards. Used by the `getrewards` /
//! `getstakinghistory` RPC endpoints.
//!
//! # Pattern B
//!
//! The existing `RewardEpochTracker` in `reward_epoch.rs` continues to
//! reset its per-epoch accumulators per design. This ring is an
//! **observer**: the node's epoch-boundary hook pushes finalised reward
//! entries into this store. `RewardEpochTracker` itself is untouched.
//!
//! Determinism: uses `BTreeMap` (not `HashMap`) so snapshot ordering is
//! stable across runs and platforms.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};

/// 32-byte address type (validator id or reward address, depending on
/// the keyspace chosen by the caller).
pub type Address = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardHistoryEntry {
    pub epoch: u64,
    pub amount: u64,
    /// The validator whose activity produced this reward. In the v0.8.0
    /// self-stake-only model this is identical to the recipient address;
    /// the field is retained so future hybrid-DPoS rewards (from
    /// delegated stake) can be attributed correctly without schema churn.
    pub validator: Address,
    pub was_claimed: bool,
    pub claimed_at_block: Option<u64>,
}

pub struct RewardHistory {
    /// Per-address history, bounded by `retention_epochs`.
    per_address: RwLock<BTreeMap<Address, VecDeque<RewardHistoryEntry>>>,
    retention_epochs: u64,
}

impl RewardHistory {
    /// Build a new ring with the given retention. `0` is normalised to
    /// `1` so the current epoch is always retained.
    pub fn new(retention_epochs: u64) -> Self {
        Self {
            per_address: RwLock::new(BTreeMap::new()),
            retention_epochs: retention_epochs.max(1),
        }
    }

    pub fn retention_epochs(&self) -> u64 {
        self.retention_epochs
    }

    /// Record a reward at an epoch boundary. Evicts the oldest entries
    /// whose `epoch` is more than `retention_epochs` older than the
    /// newly appended entry.
    pub fn record(&self, address: Address, entry: RewardHistoryEntry) {
        let mut map = self.per_address.write();
        let history = map.entry(address).or_default();
        history.push_back(entry);
        let newest_epoch = history.back().map(|e| e.epoch).unwrap_or(0);
        let cutoff_epoch = newest_epoch.saturating_sub(self.retention_epochs);
        while let Some(front) = history.front() {
            if front.epoch < cutoff_epoch {
                history.pop_front();
            } else {
                break;
            }
        }
    }

    /// Mark an entry as claimed.
    pub fn mark_claimed(&self, address: &Address, epoch: u64, block: u64) -> bool {
        let mut map = self.per_address.write();
        if let Some(h) = map.get_mut(address) {
            for e in h.iter_mut().rev() {
                if e.epoch == epoch && !e.was_claimed {
                    e.was_claimed = true;
                    e.claimed_at_block = Some(block);
                    return true;
                }
            }
        }
        false
    }

    /// Inclusive range query. `from_epoch > to_epoch` yields an empty
    /// vector without error.
    pub fn history(
        &self,
        address: &Address,
        from_epoch: u64,
        to_epoch: u64,
    ) -> Vec<RewardHistoryEntry> {
        if from_epoch > to_epoch {
            return Vec::new();
        }
        self.per_address
            .read()
            .get(address)
            .map(|h| {
                h.iter()
                    .filter(|e| e.epoch >= from_epoch && e.epoch <= to_epoch)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Every entry currently retained for `address`.
    pub fn full_history(&self, address: &Address) -> Vec<RewardHistoryEntry> {
        self.per_address
            .read()
            .get(address)
            .map(|h| h.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn unclaimed(&self, address: &Address) -> u64 {
        self.per_address
            .read()
            .get(address)
            .map(|h| h.iter().filter(|e| !e.was_claimed).map(|e| e.amount).sum())
            .unwrap_or(0)
    }

    pub fn total_claimed(&self, address: &Address) -> u64 {
        self.per_address
            .read()
            .get(address)
            .map(|h| h.iter().filter(|e| e.was_claimed).map(|e| e.amount).sum())
            .unwrap_or(0)
    }

    pub fn total_earned(&self, address: &Address) -> u64 {
        self.per_address
            .read()
            .get(address)
            .map(|h| h.iter().map(|e| e.amount).sum())
            .unwrap_or(0)
    }

    /// Known addresses in deterministic order. Used by
    /// `getstakinghistory` when no address filter is supplied.
    pub fn known_addresses(&self) -> Vec<Address> {
        self.per_address.read().keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> Address {
        [n; 32]
    }

    fn entry(epoch: u64, amount: u64, claimed: bool) -> RewardHistoryEntry {
        RewardHistoryEntry {
            epoch,
            amount,
            validator: addr(1),
            was_claimed: claimed,
            claimed_at_block: if claimed { Some(epoch * 1000) } else { None },
        }
    }

    #[test]
    fn zero_retention_normalised_to_one() {
        let h = RewardHistory::new(0);
        assert_eq!(h.retention_epochs(), 1);
        h.record(addr(1), entry(0, 100, false));
        h.record(addr(1), entry(1, 200, false));
        // retention=1, newest=1 → keep entries with epoch >= (1 - 1) = 0.
        // Both epochs 0 and 1 qualify, so 2 entries remain.
        assert_eq!(h.full_history(&addr(1)).len(), 2);
        h.record(addr(1), entry(2, 300, false));
        // Newest=2, cutoff = 2 - 1 = 1 → epoch 0 evicted.
        let full = h.full_history(&addr(1));
        assert_eq!(full.len(), 2);
        assert_eq!(full[0].epoch, 1);
        assert_eq!(full[1].epoch, 2);
    }

    #[test]
    fn retention_window_enforced() {
        let h = RewardHistory::new(10);
        for e in 0..15 {
            h.record(addr(1), entry(e, 100, false));
        }
        let full = h.full_history(&addr(1));
        // Newest=14, cutoff=4 → epochs 4..=14 retained = 11 entries.
        assert_eq!(full.len(), 11);
        assert_eq!(full.first().unwrap().epoch, 4);
        assert_eq!(full.last().unwrap().epoch, 14);
    }

    #[test]
    fn history_inclusive_range() {
        let h = RewardHistory::new(100);
        for e in 0..10 {
            h.record(addr(1), entry(e, 10 * e + 1, false));
        }
        let slice = h.history(&addr(1), 3, 7);
        assert_eq!(slice.len(), 5);
        assert_eq!(slice.first().unwrap().epoch, 3);
        assert_eq!(slice.last().unwrap().epoch, 7);
    }

    #[test]
    fn history_empty_range() {
        let h = RewardHistory::new(100);
        h.record(addr(1), entry(5, 100, false));
        assert!(h.history(&addr(1), 9, 3).is_empty());
    }

    #[test]
    fn unclaimed_claimed_total_sums() {
        let h = RewardHistory::new(100);
        h.record(addr(1), entry(0, 100, true));
        h.record(addr(1), entry(1, 200, false));
        h.record(addr(1), entry(2, 300, true));
        assert_eq!(h.total_earned(&addr(1)), 600);
        assert_eq!(h.total_claimed(&addr(1)), 400);
        assert_eq!(h.unclaimed(&addr(1)), 200);
    }

    #[test]
    fn mark_claimed_flips_flag() {
        let h = RewardHistory::new(100);
        h.record(addr(1), entry(5, 100, false));
        assert_eq!(h.unclaimed(&addr(1)), 100);
        assert!(h.mark_claimed(&addr(1), 5, 12345));
        assert_eq!(h.unclaimed(&addr(1)), 0);
        assert_eq!(h.total_claimed(&addr(1)), 100);
        // Second call is a no-op.
        assert!(!h.mark_claimed(&addr(1), 5, 67890));
    }

    #[test]
    fn known_addresses_are_sorted() {
        let h = RewardHistory::new(100);
        h.record(addr(3), entry(0, 10, false));
        h.record(addr(1), entry(0, 10, false));
        h.record(addr(2), entry(0, 10, false));
        let addrs = h.known_addresses();
        assert_eq!(addrs, vec![addr(1), addr(2), addr(3)]);
    }

    #[test]
    fn unknown_address_is_zero() {
        let h = RewardHistory::new(100);
        assert_eq!(h.total_earned(&addr(7)), 0);
        assert_eq!(h.unclaimed(&addr(7)), 0);
        assert!(h.full_history(&addr(7)).is_empty());
    }
}
