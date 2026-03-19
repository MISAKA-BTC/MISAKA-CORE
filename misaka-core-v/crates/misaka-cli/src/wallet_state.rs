//! Wallet state — tracks UTXOs, spent key images, and child key derivation.
//!
//! Enables UTXO reuse: each faucet drip or change output gets a unique
//! child spending key, so the wallet can transact multiple times.

use anyhow::{Result, bail};
use serde::{Serialize, Deserialize};
use std::path::{Path, PathBuf};

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

    /// Load from file, or create new if not found.
    pub fn load_or_create(key_path: &str, wallet_name: &str, master_address: &str) -> Result<Self> {
        let state_path = Self::state_path(key_path);
        if state_path.exists() {
            let json = std::fs::read_to_string(&state_path)?;
            let state: WalletState = serde_json::from_str(&json)?;
            Ok(state)
        } else {
            let state = Self::new(wallet_name, master_address);
            state.save(key_path)?;
            Ok(state)
        }
    }

    /// Save to file.
    pub fn save(&self, key_path: &str) -> Result<()> {
        let state_path = Self::state_path(key_path);
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&state_path, json)?;
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
        if self.utxos.iter().any(|u| u.tx_hash == tx_hash && u.output_index == output_index) {
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
        let needed = amount + fee;
        let mut candidates: Vec<&OwnedUtxo> = self.unspent_utxos()
            .into_iter()
            .filter(|u| u.amount >= needed)
            .collect();

        if candidates.is_empty() {
            let total_unspent: u64 = self.unspent_utxos().iter().map(|u| u.amount).sum();
            bail!(
                "insufficient funds: need {} (amount={} + fee={}), have {} across {} UTXOs",
                needed, amount, fee, total_unspent, self.unspent_utxos().len()
            );
        }

        // Pick smallest sufficient UTXO to minimize change
        candidates.sort_by_key(|u| u.amount);
        Ok(candidates[0])
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
        self.next_child_index += 1;
        idx
    }

    pub fn recalculate_balance(&mut self) {
        self.balance = self.utxos.iter().filter(|u| !u.spent).map(|u| u.amount).sum();
    }
}
