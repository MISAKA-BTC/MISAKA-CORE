//! Address management: generation, tracking, and gap limit handling.

use std::collections::{HashMap, HashSet};
use serde::{Serialize, Deserialize};

/// Address entry in the wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressEntry {
    pub address: String,
    pub index: u32,
    pub account_id: u64,
    pub is_change: bool,
    pub is_used: bool,
    pub label: Option<String>,
    pub created_at: u64,
}

/// Address gap limit: how many unused addresses to scan ahead.
pub const DEFAULT_GAP_LIMIT: u32 = 20;

/// Manages all addresses across accounts.
pub struct AddressManager {
    /// All known addresses.
    addresses: HashMap<String, AddressEntry>,
    /// Index: account_id -> addresses.
    by_account: HashMap<u64, Vec<String>>,
    /// Gap limit for address discovery.
    gap_limit: u32,
    /// Maximum address index seen per account + change flag.
    max_indices: HashMap<(u64, bool), u32>,
}

impl AddressManager {
    pub fn new(gap_limit: u32) -> Self {
        Self {
            addresses: HashMap::new(),
            by_account: HashMap::new(),
            gap_limit,
            max_indices: HashMap::new(),
        }
    }

    pub fn register(&mut self, entry: AddressEntry) {
        let addr = entry.address.clone();
        let account_id = entry.account_id;
        let key = (account_id, entry.is_change);

        let current_max = self.max_indices.entry(key).or_insert(0);
        if entry.index > *current_max {
            *current_max = entry.index;
        }

        self.by_account.entry(account_id).or_default().push(addr.clone());
        self.addresses.insert(addr, entry);
    }

    pub fn mark_used(&mut self, address: &str) -> bool {
        if let Some(entry) = self.addresses.get_mut(address) {
            entry.is_used = true;
            true
        } else {
            false
        }
    }

    pub fn get(&self, address: &str) -> Option<&AddressEntry> {
        self.addresses.get(address)
    }

    pub fn contains(&self, address: &str) -> bool {
        self.addresses.contains_key(address)
    }

    pub fn get_by_account(&self, account_id: u64) -> Vec<&AddressEntry> {
        self.by_account.get(&account_id)
            .map_or(Vec::new(), |addrs| {
                addrs.iter().filter_map(|a| self.addresses.get(a)).collect()
            })
    }

    /// Check if we need to generate more addresses (gap limit).
    pub fn needs_more_addresses(&self, account_id: u64, is_change: bool) -> bool {
        let key = (account_id, is_change);
        let max_index = self.max_indices.get(&key).copied().unwrap_or(0);
        let used_count = self.by_account.get(&account_id).map_or(0, |addrs| {
            addrs.iter().filter(|a| {
                self.addresses.get(*a).map_or(false, |e| e.is_change == is_change && e.is_used)
            }).count()
        });

        // Need more if less than gap_limit unused addresses ahead
        let unused_ahead = (max_index + 1).saturating_sub(used_count as u32);
        unused_ahead < self.gap_limit
    }

    pub fn total_addresses(&self) -> usize { self.addresses.len() }
    pub fn used_addresses(&self) -> usize {
        self.addresses.values().filter(|e| e.is_used).count()
    }

    /// Set label for an address.
    pub fn set_label(&mut self, address: &str, label: String) -> bool {
        if let Some(entry) = self.addresses.get_mut(address) {
            entry.label = Some(label);
            true
        } else {
            false
        }
    }

    /// Search addresses by label.
    pub fn search_by_label(&self, query: &str) -> Vec<&AddressEntry> {
        self.addresses.values()
            .filter(|e| e.label.as_deref().map_or(false, |l| l.contains(query)))
            .collect()
    }
}

impl Default for AddressManager {
    fn default() -> Self { Self::new(DEFAULT_GAP_LIMIT) }
}
