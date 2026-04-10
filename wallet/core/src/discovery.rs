//! Account and address discovery — scan blockchain for owned UTXOs.
//!
//! Implements the gap-limit-based address discovery algorithm:
//! 1. Generate addresses up to the gap limit
//! 2. Query node for UTXOs at those addresses
//! 3. If any address has activity, extend the scan window
//! 4. Repeat until gap limit consecutive unused addresses found
//! 5. Track all discovered addresses for future monitoring

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// Default address gap limit.
pub const DEFAULT_GAP_LIMIT: u32 = 20;

/// Discovery configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    pub gap_limit: u32,
    pub batch_size: u32,
    pub max_addresses_per_account: u32,
    pub scan_both_chains: bool,
    pub include_change_addresses: bool,
    pub concurrent_queries: usize,
    pub query_timeout_ms: u64,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            gap_limit: DEFAULT_GAP_LIMIT,
            batch_size: 50,
            max_addresses_per_account: 10_000,
            scan_both_chains: true,
            include_change_addresses: true,
            concurrent_queries: 4,
            query_timeout_ms: 30_000,
        }
    }
}

/// Discovery state for a single account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountDiscoveryState {
    pub account_id: u64,
    pub receive_scanned_to: u32,
    pub change_scanned_to: u32,
    pub receive_last_used: u32,
    pub change_last_used: u32,
    pub total_addresses_found: usize,
    pub total_utxos_found: usize,
    pub total_balance_found: u64,
    pub is_complete: bool,
}

/// Discovery result for a batch of addresses.
#[derive(Debug, Clone)]
pub struct DiscoveryBatchResult {
    pub addresses_queried: usize,
    pub addresses_with_activity: usize,
    pub utxos_found: Vec<DiscoveredUtxo>,
    pub highest_used_index: Option<u32>,
    pub scan_complete: bool,
}

/// A UTXO discovered during scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredUtxo {
    pub address: String,
    pub address_index: u32,
    pub is_change: bool,
    pub outpoint_tx_id: String,
    pub outpoint_index: u32,
    pub amount: u64,
    pub script_public_key: String,
    pub block_daa_score: u64,
    pub is_coinbase: bool,
}

/// Address discovery manager.
pub struct DiscoveryManager {
    config: DiscoveryConfig,
    account_states: HashMap<u64, AccountDiscoveryState>,
    discovered_addresses: HashSet<String>,
    #[allow(dead_code)]
    pending_queries: VecDeque<DiscoveryQuery>,
    total_queries: u64,
    total_utxos: u64,
}

/// Pending query for address discovery.
#[allow(dead_code)]
struct DiscoveryQuery {
    account_id: u64,
    addresses: Vec<(String, u32, bool)>,
    submitted_at: u64,
}

impl DiscoveryManager {
    pub fn new(config: DiscoveryConfig) -> Self {
        Self {
            config,
            account_states: HashMap::new(),
            discovered_addresses: HashSet::new(),
            pending_queries: VecDeque::new(),
            total_queries: 0,
            total_utxos: 0,
        }
    }

    /// Initialize discovery for an account.
    pub fn init_account(&mut self, account_id: u64) {
        self.account_states.insert(
            account_id,
            AccountDiscoveryState {
                account_id,
                receive_scanned_to: 0,
                change_scanned_to: 0,
                receive_last_used: 0,
                change_last_used: 0,
                total_addresses_found: 0,
                total_utxos_found: 0,
                total_balance_found: 0,
                is_complete: false,
            },
        );
    }

    /// Generate the next batch of addresses to scan.
    pub fn next_batch(&mut self, account_id: u64) -> Option<Vec<(String, u32, bool)>> {
        let state = self.account_states.get_mut(&account_id)?;
        if state.is_complete {
            return None;
        }

        let mut batch = Vec::new();
        let batch_size = self.config.batch_size;

        // Receive addresses
        let receive_start = state.receive_scanned_to;
        let receive_end = (receive_start + batch_size).min(self.config.max_addresses_per_account);
        for i in receive_start..receive_end {
            let addr = format!("misaka1_receive_{}_{}", account_id, i);
            batch.push((addr, i, false));
        }
        state.receive_scanned_to = receive_end;

        // Change addresses
        if self.config.include_change_addresses {
            let change_start = state.change_scanned_to;
            let change_end =
                (change_start + batch_size / 2).min(self.config.max_addresses_per_account);
            for i in change_start..change_end {
                let addr = format!("misaka1_change_{}_{}", account_id, i);
                batch.push((addr, i, true));
            }
            state.change_scanned_to = change_end;
        }

        if batch.is_empty() {
            None
        } else {
            Some(batch)
        }
    }

    /// Process results from a batch query.
    pub fn process_results(&mut self, account_id: u64, result: DiscoveryBatchResult) {
        if let Some(state) = self.account_states.get_mut(&account_id) {
            state.total_addresses_found += result.addresses_with_activity;
            state.total_utxos_found += result.utxos_found.len();
            state.total_balance_found += result.utxos_found.iter().map(|u| u.amount).sum::<u64>();

            // Update highest used indices
            for utxo in &result.utxos_found {
                if utxo.is_change {
                    state.change_last_used = state.change_last_used.max(utxo.address_index);
                } else {
                    state.receive_last_used = state.receive_last_used.max(utxo.address_index);
                }
                self.discovered_addresses.insert(utxo.address.clone());
            }

            // Check if discovery is complete (gap limit reached)
            let receive_gap = state
                .receive_scanned_to
                .saturating_sub(state.receive_last_used);
            let change_gap = state
                .change_scanned_to
                .saturating_sub(state.change_last_used);

            if receive_gap >= self.config.gap_limit && change_gap >= self.config.gap_limit {
                state.is_complete = true;
                tracing::info!(
                    "Discovery complete for account {}: {} addresses, {} UTXOs, balance {}",
                    account_id,
                    state.total_addresses_found,
                    state.total_utxos_found,
                    state.total_balance_found,
                );
            }

            self.total_utxos += result.utxos_found.len() as u64;
        }
        self.total_queries += 1;
    }

    /// Check if all accounts have been fully discovered.
    pub fn is_complete(&self) -> bool {
        self.account_states.values().all(|s| s.is_complete)
    }

    /// Get discovery progress for an account.
    pub fn get_progress(&self, account_id: u64) -> Option<&AccountDiscoveryState> {
        self.account_states.get(&account_id)
    }

    /// Get all discovered addresses.
    pub fn all_discovered_addresses(&self) -> &HashSet<String> {
        &self.discovered_addresses
    }

    pub fn total_queries(&self) -> u64 {
        self.total_queries
    }
    pub fn total_utxos_discovered(&self) -> u64 {
        self.total_utxos
    }
    pub fn account_count(&self) -> usize {
        self.account_states.len()
    }
}

/// Discovery statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryStats {
    pub accounts_scanning: usize,
    pub accounts_complete: usize,
    pub total_addresses: usize,
    pub total_utxos: u64,
    pub total_balance: u64,
    pub total_queries: u64,
}

impl DiscoveryManager {
    pub fn stats(&self) -> DiscoveryStats {
        DiscoveryStats {
            accounts_scanning: self
                .account_states
                .values()
                .filter(|s| !s.is_complete)
                .count(),
            accounts_complete: self
                .account_states
                .values()
                .filter(|s| s.is_complete)
                .count(),
            total_addresses: self.discovered_addresses.len(),
            total_utxos: self.total_utxos,
            total_balance: self
                .account_states
                .values()
                .map(|s| s.total_balance_found)
                .sum(),
            total_queries: self.total_queries,
        }
    }
}
