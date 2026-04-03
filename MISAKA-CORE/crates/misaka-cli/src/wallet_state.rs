//! Wallet state — tracks UTXOs, spent key images, and child key derivation.
//!
//! # DEPRECATION NOTICE (Fix K)
//!
//! This module is the **legacy** CLI-local wallet state. It will be
//! phased out in favor of `misaka-wallet-core` which provides:
//!
//! - `wallet::core::tx_state::TxTracker` — TX lifecycle + UTXO locking
//! - `wallet::core::storage` — Checksummed, versioned, migrateable storage
//! - `wallet::core::coin_select` — Advanced multi-strategy coin selection
//!
//! New features should be added to `wallet/core`, NOT here.
//! Existing CLI commands should be migrated to use `wallet/core` APIs.
//!
//! # Current functionality (retained for backward compat)
//!
//! - **Atomic save**: Write to `.tmp` → fsync → rename → dir fsync.
//! - **File backup**: Previous state kept as `.state.bak.json`.
//! - **Multi-UTXO selection**: `select_utxos_multi()` combines UTXOs.
//! - **State validation**: `validate()` checks for duplicates/inconsistencies.
//! - **Bounded history**: Prune spent UTXOs older than threshold.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Maximum spent UTXOs to retain for historical reference before pruning.
const MAX_SPENT_HISTORY: usize = 1000;

/// A UTXO owned by this wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnedUtxo {
    /// Transaction hash that created this output.
    pub tx_hash: String,
    /// Output index within the transaction.
    pub output_index: u32,
    /// Amount in base units.
    pub amount: u64,
    /// Child key index (0 = master key, 1+ = derived child).
    pub child_index: u32,
    /// Key image for this UTXO's spending key (hex).
    pub key_image: String,
    /// Address associated with this child key.
    pub address: String,
    /// Whether this UTXO has been spent.
    pub spent: bool,
}

/// Persistent wallet state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletState {
    /// Wallet version.
    pub version: u32,
    /// Wallet name (matches key file).
    pub wallet_name: String,
    /// Master address (child_index=0).
    pub master_address: String,
    /// Next child key index to use for change/receive outputs.
    pub next_child_index: u32,
    /// All known UTXOs (spent and unspent).
    pub utxos: Vec<OwnedUtxo>,
    /// Total balance (sum of unspent UTXOs).
    pub balance: u64,
    /// Shielded pool balance (sum of unspent notes detected by scanner).
    /// P0: always 0. P1: populated by note scanner.
    #[serde(default)]
    pub shielded_balance: u64,
}

impl WalletState {
    /// Create a new wallet state.
    pub fn new(wallet_name: &str, master_address: &str) -> Self {
        Self {
            version: 1,
            wallet_name: wallet_name.to_string(),
            master_address: master_address.to_string(),
            next_child_index: 1, // 0 is master
            utxos: Vec::new(),
            balance: 0,
            shielded_balance: 0,
        }
    }

    /// State file path for a given key file path.
    pub fn state_path(key_path: &str) -> PathBuf {
        let p = Path::new(key_path);
        let stem = p.file_stem().unwrap_or_default().to_string_lossy();
        // wallet1.key.json → wallet1.state.json
        let name = stem.strip_suffix(".key").unwrap_or(&stem);
        p.with_file_name(format!("{}.state.json", name))
    }

    /// Backup file path.
    fn backup_path(key_path: &str) -> PathBuf {
        let p = Path::new(key_path);
        let stem = p.file_stem().unwrap_or_default().to_string_lossy();
        let name = stem.strip_suffix(".key").unwrap_or(&stem);
        p.with_file_name(format!("{}.state.bak.json", name))
    }

    /// Load wallet state from file. Returns error if file does not exist.
    pub fn load(key_path: &str) -> Result<Self> {
        let state_path = Self::state_path(key_path);
        let json = std::fs::read_to_string(&state_path)
            .with_context(|| format!("wallet state not found: {}", state_path.display()))?;
        let mut state: WalletState =
            serde_json::from_str(&json).with_context(|| "failed to parse wallet state JSON")?;
        state.recalculate_balance();
        Ok(state)
    }

    /// Load from file, or create new if not found.
    pub fn load_or_create(key_path: &str, wallet_name: &str, master_address: &str) -> Result<Self> {
        let state_path = Self::state_path(key_path);
        if state_path.exists() {
            let json = std::fs::read_to_string(&state_path).with_context(|| {
                format!("failed to read wallet state: {}", state_path.display())
            })?;
            let mut state: WalletState =
                serde_json::from_str(&json).with_context(|| "failed to parse wallet state JSON")?;
            state.recalculate_balance();
            Ok(state)
        } else {
            let mut state = Self::new(wallet_name, master_address);
            state.save(key_path)?;
            Ok(state)
        }
    }

    /// Save to file atomically (write .tmp → file fsync → backup → rename → dir fsync).
    pub fn save(&mut self, key_path: &str) -> Result<()> {
        // Prune old spent UTXOs before saving to keep file bounded
        self.prune_spent();

        let state_path = Self::state_path(key_path);
        let tmp_path = state_path.with_extension("json.tmp");
        let backup_path = Self::backup_path(key_path);

        let json =
            serde_json::to_string_pretty(self).context("failed to serialize wallet state")?;

        // Write to temp file first
        std::fs::write(&tmp_path, &json)
            .with_context(|| format!("failed to write temp state: {}", tmp_path.display()))?;

        // File fsync — ensure data hits disk before rename
        if let Ok(file) = std::fs::File::open(&tmp_path) {
            let _ = file.sync_all();
        }

        // Backup existing state if it exists
        if state_path.exists() {
            // Best-effort backup — don't fail the save if backup fails
            let _ = std::fs::copy(&state_path, &backup_path);
        }

        // Atomic rename
        std::fs::rename(&tmp_path, &state_path).with_context(|| {
            format!(
                "failed to rename {} → {}",
                tmp_path.display(),
                state_path.display()
            )
        })?;

        // Dir fsync — ensure the rename (directory entry) is durable
        #[cfg(unix)]
        {
            if let Some(parent) = state_path.parent() {
                if let Ok(dir) = std::fs::File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
        }

        Ok(())
    }

    /// Register a new UTXO (from faucet or change output).
    pub fn register_utxo(
        &mut self,
        tx_hash: &str,
        output_index: u32,
        amount: u64,
        child_index: u32,
        key_image: &str,
        address: &str,
    ) {
        // Check if already registered
        if self
            .utxos
            .iter()
            .any(|u| u.tx_hash == tx_hash && u.output_index == output_index)
        {
            return;
        }

        self.utxos.push(OwnedUtxo {
            tx_hash: tx_hash.to_string(),
            output_index,
            amount,
            child_index,
            key_image: key_image.to_string(),
            address: address.to_string(),
            spent: false,
        });
        self.recalculate_balance();
    }

    /// Get unspent UTXOs.
    pub fn unspent_utxos(&self) -> Vec<&OwnedUtxo> {
        self.utxos.iter().filter(|u| !u.spent).collect()
    }

    /// Find best UTXO to spend (largest unspent that covers amount + fee).
    pub fn select_utxo(&self, amount: u64, fee: u64) -> Result<&OwnedUtxo> {
        let needed = amount
            .checked_add(fee)
            .ok_or_else(|| anyhow::anyhow!("amount + fee overflow"))?;
        let mut candidates: Vec<&OwnedUtxo> = self
            .unspent_utxos()
            .into_iter()
            .filter(|u| u.amount >= needed)
            .collect();

        if candidates.is_empty() {
            let total_unspent: u64 = self.unspent_utxos().iter().map(|u| u.amount).sum();
            if total_unspent >= needed {
                bail!(
                    "insufficient single UTXO: need {} (amount={} + fee={}), \
                     total across {} UTXOs = {}. Use multi-input transaction.",
                    needed,
                    amount,
                    fee,
                    self.unspent_utxos().len(),
                    total_unspent
                );
            }
            bail!(
                "insufficient funds: need {} (amount={} + fee={}), have {} across {} UTXOs",
                needed,
                amount,
                fee,
                total_unspent,
                self.unspent_utxos().len()
            );
        }

        // Pick smallest sufficient UTXO to minimize change
        candidates.sort_by_key(|u| u.amount);
        Ok(candidates[0])
    }

    /// Multi-UTXO coin selection: combine multiple UTXOs to cover `amount + fee`.
    ///
    /// Uses largest-first strategy. Returns the selected UTXOs and total change.
    /// This is needed when no single UTXO is large enough.
    pub fn select_utxos_multi(&self, amount: u64, fee: u64) -> Result<(Vec<&OwnedUtxo>, u64)> {
        let needed = amount
            .checked_add(fee)
            .ok_or_else(|| anyhow::anyhow!("amount + fee overflow"))?;

        // First try single-UTXO (more efficient, less on-chain data)
        if let Ok(single) = self.select_utxo(amount, fee) {
            let change = single.amount - needed;
            return Ok((vec![single], change));
        }

        // Fall back to multi-UTXO selection (largest-first)
        let mut available: Vec<&OwnedUtxo> = self.unspent_utxos();
        available.sort_by(|a, b| b.amount.cmp(&a.amount));

        let mut selected = Vec::new();
        let mut accumulated: u64 = 0;

        for utxo in &available {
            if accumulated >= needed {
                break;
            }
            selected.push(*utxo);
            accumulated = accumulated.saturating_add(utxo.amount);
        }

        if accumulated < needed {
            bail!(
                "insufficient funds: need {} (amount={} + fee={}), have {} across {} UTXOs",
                needed,
                amount,
                fee,
                accumulated,
                self.unspent_utxos().len()
            );
        }

        let change = accumulated - needed;
        Ok((selected, change))
    }

    /// Mark a UTXO as spent by key image.
    pub fn mark_spent(&mut self, key_image: &str) {
        for utxo in &mut self.utxos {
            if utxo.key_image == key_image {
                utxo.spent = true;
            }
        }
        self.recalculate_balance();
    }

    /// Get and increment the next child index.
    pub fn next_child(&mut self) -> u32 {
        let idx = self.next_child_index;
        self.next_child_index = self.next_child_index.saturating_add(1);
        idx
    }

    pub fn recalculate_balance(&mut self) {
        self.balance = self
            .utxos
            .iter()
            .filter(|u| !u.spent)
            .map(|u| u.amount)
            .sum();
    }

    /// Prune old spent UTXOs to keep state file bounded.
    /// Retains the most recent `MAX_SPENT_HISTORY` spent UTXOs.
    pub fn prune_spent(&mut self) {
        let spent_count = self.utxos.iter().filter(|u| u.spent).count();
        if spent_count <= MAX_SPENT_HISTORY {
            return;
        }

        // Keep all unspent + last MAX_SPENT_HISTORY spent
        let to_remove = spent_count - MAX_SPENT_HISTORY;
        let mut removed = 0;
        self.utxos.retain(|u| {
            if u.spent && removed < to_remove {
                removed += 1;
                false
            } else {
                true
            }
        });
    }

    /// Validate internal consistency. Returns a list of warnings.
    pub fn validate(&self) -> Vec<String> {
        let mut warnings = Vec::new();

        // Check for duplicate UTXOs
        let mut seen = std::collections::HashSet::new();
        for utxo in &self.utxos {
            let key = format!("{}:{}", utxo.tx_hash, utxo.output_index);
            if !seen.insert(key.clone()) {
                warnings.push(format!("duplicate UTXO: {}", key));
            }
        }

        // Check balance consistency
        let computed: u64 = self
            .utxos
            .iter()
            .filter(|u| !u.spent)
            .map(|u| u.amount)
            .sum();
        if computed != self.balance {
            warnings.push(format!(
                "balance mismatch: stored={}, computed={}",
                self.balance, computed
            ));
        }

        // Check for absurdly high child index (possible corruption)
        if self.next_child_index > 100_000 {
            warnings.push(format!(
                "unusually high next_child_index: {}",
                self.next_child_index
            ));
        }

        warnings
    }
}
