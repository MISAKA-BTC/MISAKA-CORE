//! Balance manager — tracks UTXO balances across accounts with maturity handling.
//!
//! Features:
//! - Per-account balance tracking with pending/confirmed/immature splits
//! - UTXO maturity enforcement (coinbase maturity, confirmation depth)
//! - Compound UTXO operations (merge small UTXOs to reduce future fees)
//! - Balance change event emission for UI updates
//! - Thread-safe concurrent access from sync and user threads

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Minimum confirmations for a UTXO to be considered confirmed.
pub const MIN_CONFIRMATIONS: u64 = 10;

/// Coinbase maturity (DAA score depth).
pub const COINBASE_MATURITY: u64 = 100;

/// Dust threshold — UTXOs below this are not worth spending.
pub const DUST_THRESHOLD: u64 = 546;

/// Maximum number of UTXOs to track per account.
pub const MAX_UTXOS_PER_ACCOUNT: usize = 100_000;

/// A tracked UTXO with full metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedUtxo {
    pub outpoint: Outpoint,
    pub amount: u64,
    pub script_public_key: Vec<u8>,
    pub address: String,
    pub account_id: u64,
    pub block_daa_score: u64,
    pub is_coinbase: bool,
    pub is_confirmed: bool,
    pub is_mature: bool,
    pub is_spent: bool,
    pub is_locked: bool,
    pub spending_tx_id: Option<[u8; 32]>,
    pub first_seen_timestamp: u64,
    pub confirmed_timestamp: Option<u64>,
}

/// Outpoint = (tx_id, output_index).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Outpoint {
    pub tx_id: [u8; 32],
    pub index: u32,
}

impl Outpoint {
    pub fn to_bytes(&self) -> [u8; 36] {
        let mut bytes = [0u8; 36];
        bytes[..32].copy_from_slice(&self.tx_id);
        bytes[32..36].copy_from_slice(&self.index.to_le_bytes());
        bytes
    }
}

/// Detailed balance breakdown.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DetailedBalance {
    /// Total balance across all states.
    pub total: u64,
    /// Confirmed and mature, available for spending.
    pub available: u64,
    /// Pending (unconfirmed) balance.
    pub pending: u64,
    /// Immature coinbase balance (below maturity threshold).
    pub immature: u64,
    /// Locked for pending outgoing transactions.
    pub locked: u64,
    /// Number of spendable UTXOs.
    pub spendable_utxo_count: usize,
    /// Total number of tracked UTXOs.
    pub total_utxo_count: usize,
    /// Number of dust UTXOs.
    pub dust_utxo_count: usize,
    /// Dust total value.
    pub dust_total: u64,
}

/// Balance change event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceChangeEvent {
    pub account_id: u64,
    pub change_type: BalanceChangeType,
    pub amount: u64,
    pub new_balance: DetailedBalance,
    pub timestamp: u64,
    pub tx_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BalanceChangeType {
    UtxoReceived,
    UtxoSpent,
    UtxoConfirmed,
    UtxoMatured,
    UtxoLocked,
    UtxoUnlocked,
    Compounded,
}

/// Thread-safe balance manager.
pub struct BalanceManager {
    utxos: RwLock<HashMap<Outpoint, TrackedUtxo>>,
    by_account: RwLock<HashMap<u64, Vec<Outpoint>>>,
    by_address: RwLock<HashMap<String, Vec<Outpoint>>>,
    balance_cache: RwLock<HashMap<u64, DetailedBalance>>,
    event_log: RwLock<Vec<BalanceChangeEvent>>,
    current_daa_score: std::sync::atomic::AtomicU64,
    max_event_log: usize,
}

impl BalanceManager {
    pub fn new() -> Self {
        Self {
            utxos: RwLock::new(HashMap::new()),
            by_account: RwLock::new(HashMap::new()),
            by_address: RwLock::new(HashMap::new()),
            balance_cache: RwLock::new(HashMap::new()),
            event_log: RwLock::new(Vec::new()),
            current_daa_score: std::sync::atomic::AtomicU64::new(0),
            max_event_log: 10_000,
        }
    }

    /// Update the current DAA score (called on each new block).
    pub fn update_daa_score(&self, score: u64) {
        let old_score = self
            .current_daa_score
            .swap(score, std::sync::atomic::Ordering::Relaxed);
        if score > old_score {
            self.refresh_maturity(score);
        }
    }

    /// Add a new UTXO.
    pub fn add_utxo(&self, utxo: TrackedUtxo) -> bool {
        let outpoint = utxo.outpoint;
        let account_id = utxo.account_id;
        let address = utxo.address.clone();
        let amount = utxo.amount;

        {
            let account_utxos = self.by_account.read();
            if let Some(list) = account_utxos.get(&account_id) {
                if list.len() >= MAX_UTXOS_PER_ACCOUNT {
                    tracing::warn!("Account {} has {} UTXOs, at limit", account_id, list.len());
                    return false;
                }
            }
        }

        self.utxos.write().insert(outpoint, utxo);
        self.by_account
            .write()
            .entry(account_id)
            .or_default()
            .push(outpoint);
        self.by_address
            .write()
            .entry(address)
            .or_default()
            .push(outpoint);

        self.invalidate_cache(account_id);
        self.emit_event(account_id, BalanceChangeType::UtxoReceived, amount, None);
        true
    }

    /// Mark a UTXO as spent.
    pub fn mark_spent(&self, outpoint: &Outpoint, spending_tx: [u8; 32]) -> Option<u64> {
        let mut utxos = self.utxos.write();
        if let Some(utxo) = utxos.get_mut(outpoint) {
            if utxo.is_spent {
                return None;
            }
            utxo.is_spent = true;
            utxo.spending_tx_id = Some(spending_tx);
            let account_id = utxo.account_id;
            let amount = utxo.amount;
            drop(utxos);
            self.invalidate_cache(account_id);
            self.emit_event(
                account_id,
                BalanceChangeType::UtxoSpent,
                amount,
                Some(hex::encode(spending_tx)),
            );
            Some(amount)
        } else {
            None
        }
    }

    /// Mark a UTXO as confirmed.
    pub fn mark_confirmed(&self, outpoint: &Outpoint, block_score: u64) {
        let mut utxos = self.utxos.write();
        if let Some(utxo) = utxos.get_mut(outpoint) {
            utxo.is_confirmed = true;
            utxo.block_daa_score = block_score;
            utxo.confirmed_timestamp = Some(now_secs());
            let account_id = utxo.account_id;
            let amount = utxo.amount;
            drop(utxos);
            self.invalidate_cache(account_id);
            self.emit_event(account_id, BalanceChangeType::UtxoConfirmed, amount, None);
        }
    }

    /// Lock UTXOs for a pending transaction.
    pub fn lock_utxos(&self, outpoints: &[Outpoint]) -> Result<(), String> {
        let mut utxos = self.utxos.write();
        let mut touched_accounts = Vec::new();
        // Verify all are available
        for op in outpoints {
            let utxo = utxos.get(op).ok_or("UTXO not found")?;
            if utxo.is_spent {
                return Err("UTXO already spent".into());
            }
            if utxo.is_locked {
                return Err("UTXO already locked".into());
            }
            touched_accounts.push(utxo.account_id);
        }
        // Lock all
        for op in outpoints {
            if let Some(utxo) = utxos.get_mut(op) {
                utxo.is_locked = true;
            }
        }
        drop(utxos);
        for account_id in touched_accounts {
            self.invalidate_cache(account_id);
        }
        Ok(())
    }

    /// Unlock UTXOs (e.g., transaction failed or cancelled).
    pub fn unlock_utxos(&self, outpoints: &[Outpoint]) {
        let mut utxos = self.utxos.write();
        let mut touched_accounts = Vec::new();
        for op in outpoints {
            if let Some(utxo) = utxos.get_mut(op) {
                touched_accounts.push(utxo.account_id);
                utxo.is_locked = false;
            }
        }
        drop(utxos);
        for account_id in touched_accounts {
            self.invalidate_cache(account_id);
        }
    }

    /// Get detailed balance for an account.
    pub fn get_balance(&self, account_id: u64) -> DetailedBalance {
        // Check cache
        if let Some(cached) = self.balance_cache.read().get(&account_id) {
            return cached.clone();
        }

        let balance = self.compute_balance(account_id);
        self.balance_cache
            .write()
            .insert(account_id, balance.clone());
        balance
    }

    fn compute_balance(&self, account_id: u64) -> DetailedBalance {
        let utxos = self.utxos.read();
        let by_account = self.by_account.read();
        let current_score = self
            .current_daa_score
            .load(std::sync::atomic::Ordering::Relaxed);

        let outpoints = match by_account.get(&account_id) {
            Some(ops) => ops,
            None => return DetailedBalance::default(),
        };

        let mut balance = DetailedBalance::default();
        for op in outpoints {
            if let Some(utxo) = utxos.get(op) {
                if utxo.is_spent {
                    continue;
                }

                balance.total += utxo.amount;
                balance.total_utxo_count += 1;

                if utxo.amount < DUST_THRESHOLD {
                    balance.dust_utxo_count += 1;
                    balance.dust_total += utxo.amount;
                }

                if utxo.is_locked {
                    balance.locked += utxo.amount;
                } else if !utxo.is_confirmed {
                    balance.pending += utxo.amount;
                } else if utxo.is_coinbase {
                    let depth = current_score.saturating_sub(utxo.block_daa_score);
                    if depth < COINBASE_MATURITY {
                        balance.immature += utxo.amount;
                    } else {
                        balance.available += utxo.amount;
                        balance.spendable_utxo_count += 1;
                    }
                } else {
                    let depth = current_score.saturating_sub(utxo.block_daa_score);
                    if depth >= MIN_CONFIRMATIONS {
                        balance.available += utxo.amount;
                        balance.spendable_utxo_count += 1;
                    } else {
                        balance.pending += utxo.amount;
                    }
                }
            }
        }
        balance
    }

    /// Get spendable UTXOs for an account, sorted by amount (largest first).
    pub fn get_spendable_utxos(&self, account_id: u64) -> Vec<TrackedUtxo> {
        let utxos = self.utxos.read();
        let by_account = self.by_account.read();
        let current_score = self
            .current_daa_score
            .load(std::sync::atomic::Ordering::Relaxed);

        let mut result: Vec<TrackedUtxo> = by_account
            .get(&account_id)
            .map(|ops| {
                ops.iter()
                    .filter_map(|op| utxos.get(op))
                    .filter(|u| {
                        !u.is_spent
                            && !u.is_locked
                            && u.is_confirmed
                            && (!u.is_coinbase
                                || current_score.saturating_sub(u.block_daa_score)
                                    >= COINBASE_MATURITY)
                            && current_score.saturating_sub(u.block_daa_score) >= MIN_CONFIRMATIONS
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();

        result.sort_by(|a, b| b.amount.cmp(&a.amount));
        result
    }

    /// Get UTXOs suitable for compounding (many small UTXOs → fewer large ones).
    pub fn get_compound_candidates(&self, account_id: u64, max_inputs: usize) -> Vec<TrackedUtxo> {
        let mut spendable = self.get_spendable_utxos(account_id);
        // Sort by amount ascending (smallest first for compounding)
        spendable.sort_by_key(|u| u.amount);
        spendable.truncate(max_inputs);
        spendable
    }

    /// Get all UTXOs for a specific address.
    pub fn get_utxos_by_address(&self, address: &str) -> Vec<TrackedUtxo> {
        let utxos = self.utxos.read();
        let by_address = self.by_address.read();
        by_address
            .get(address)
            .map(|ops| ops.iter().filter_map(|op| utxos.get(op)).cloned().collect())
            .unwrap_or_default()
    }

    /// Refresh maturity status after DAA score change.
    fn refresh_maturity(&self, current_score: u64) {
        let mut utxos = self.utxos.write();
        let mut matured_accounts = Vec::new();

        for utxo in utxos.values_mut() {
            if !utxo.is_mature && utxo.is_confirmed && !utxo.is_spent {
                let depth = current_score.saturating_sub(utxo.block_daa_score);
                let required = if utxo.is_coinbase {
                    COINBASE_MATURITY
                } else {
                    MIN_CONFIRMATIONS
                };
                if depth >= required {
                    utxo.is_mature = true;
                    matured_accounts.push((utxo.account_id, utxo.amount));
                }
            }
        }
        drop(utxos);

        for (account_id, amount) in matured_accounts {
            self.invalidate_cache(account_id);
            self.emit_event(account_id, BalanceChangeType::UtxoMatured, amount, None);
        }
    }

    /// Remove spent UTXOs older than retention period.
    pub fn cleanup_spent(&self, max_age_scores: u64) -> usize {
        let current_score = self
            .current_daa_score
            .load(std::sync::atomic::Ordering::Relaxed);
        let cutoff = current_score.saturating_sub(max_age_scores);

        let mut utxos = self.utxos.write();
        let _before = utxos.len();
        let to_remove: Vec<Outpoint> = utxos
            .iter()
            .filter(|(_, u)| u.is_spent && u.block_daa_score < cutoff)
            .map(|(op, _)| *op)
            .collect();

        for op in &to_remove {
            utxos.remove(op);
        }
        drop(utxos);

        // Clean index maps
        let mut by_account = self.by_account.write();
        for list in by_account.values_mut() {
            list.retain(|op| !to_remove.contains(op));
        }

        let mut by_address = self.by_address.write();
        for list in by_address.values_mut() {
            list.retain(|op| !to_remove.contains(op));
        }

        to_remove.len()
    }

    fn invalidate_cache(&self, account_id: u64) {
        self.balance_cache.write().remove(&account_id);
    }

    fn emit_event(
        &self,
        account_id: u64,
        change_type: BalanceChangeType,
        amount: u64,
        tx_id: Option<String>,
    ) {
        let balance = self.compute_balance(account_id);
        let event = BalanceChangeEvent {
            account_id,
            change_type,
            amount,
            new_balance: balance,
            timestamp: now_secs(),
            tx_id,
        };
        let mut log = self.event_log.write();
        if log.len() >= self.max_event_log {
            log.drain(..self.max_event_log / 2);
        }
        log.push(event);
    }

    /// Get recent balance change events.
    pub fn recent_events(&self, count: usize) -> Vec<BalanceChangeEvent> {
        let log = self.event_log.read();
        log.iter().rev().take(count).cloned().collect()
    }

    /// Get total UTXO count across all accounts.
    pub fn total_utxo_count(&self) -> usize {
        self.utxos.read().len()
    }

    /// Get account count.
    pub fn account_count(&self) -> usize {
        self.by_account.read().len()
    }
}

impl Default for BalanceManager {
    fn default() -> Self {
        Self::new()
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_utxo(id: u8, amount: u64, account: u64, score: u64, coinbase: bool) -> TrackedUtxo {
        TrackedUtxo {
            outpoint: Outpoint {
                tx_id: [id; 32],
                index: 0,
            },
            amount,
            script_public_key: vec![],
            address: format!("misaka1{}", "a".repeat(40)),
            account_id: account,
            block_daa_score: score,
            is_coinbase: coinbase,
            is_confirmed: true,
            is_mature: false,
            is_spent: false,
            is_locked: false,
            spending_tx_id: None,
            first_seen_timestamp: 0,
            confirmed_timestamp: Some(0),
        }
    }

    #[test]
    fn test_balance_computation() {
        let mgr = BalanceManager::new();
        mgr.update_daa_score(1000);

        mgr.add_utxo(make_utxo(1, 5000, 1, 900, false));
        mgr.add_utxo(make_utxo(2, 3000, 1, 995, false)); // Only 5 confirms

        let balance = mgr.get_balance(1);
        assert_eq!(balance.total, 8000);
        assert_eq!(balance.available, 5000); // Only first has 100+ confirms
        assert_eq!(balance.pending, 3000);
    }

    #[test]
    fn test_coinbase_maturity() {
        let mgr = BalanceManager::new();
        mgr.update_daa_score(150);

        mgr.add_utxo(make_utxo(1, 10000, 1, 100, true)); // 50 confirms, immature
        mgr.add_utxo(make_utxo(2, 10000, 1, 40, true)); // 110 confirms, mature

        let balance = mgr.get_balance(1);
        assert_eq!(balance.immature, 10000);
        assert_eq!(balance.available, 10000);
    }

    #[test]
    fn test_lock_unlock() {
        let mgr = BalanceManager::new();
        mgr.update_daa_score(1000);
        mgr.add_utxo(make_utxo(1, 5000, 1, 800, false));

        let op = Outpoint {
            tx_id: [1; 32],
            index: 0,
        };
        mgr.lock_utxos(&[op]).unwrap();

        let balance = mgr.get_balance(1);
        assert_eq!(balance.locked, 5000);
        assert_eq!(balance.available, 0);

        mgr.unlock_utxos(&[op]);
        let balance = mgr.get_balance(1);
        assert_eq!(balance.locked, 0);
        assert_eq!(balance.available, 5000);
    }
}
