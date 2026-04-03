//! UTXO index: maps script public keys (addresses) to their UTXOs.

pub mod stores;

use parking_lot::RwLock;
use serde_with::serde_as;
use std::collections::HashMap;

/// Outpoint: tx_id (32 bytes) + output_index (4 bytes).
pub type Outpoint = [u8; 36];

/// A UTXO entry.
#[serde_as]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UtxoEntry {
    #[serde_as(as = "[_; 36]")]
    pub outpoint: Outpoint,
    pub amount: u64,
    pub script_public_key: Vec<u8>,
    pub block_daa_score: u64,
    pub is_coinbase: bool,
}

/// In-memory UTXO index keyed by script public key.
pub struct UtxoIndex {
    by_script: RwLock<HashMap<Vec<u8>, HashMap<Outpoint, UtxoEntry>>>,
    entry_count: std::sync::atomic::AtomicU64,
    synced: std::sync::atomic::AtomicBool,
}

impl UtxoIndex {
    pub fn new() -> Self {
        Self {
            by_script: RwLock::new(HashMap::new()),
            entry_count: std::sync::atomic::AtomicU64::new(0),
            synced: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Add a UTXO entry.
    pub fn add(&self, entry: UtxoEntry) {
        let mut idx = self.by_script.write();
        let outpoint = entry.outpoint;
        let script = entry.script_public_key.clone();
        idx.entry(script).or_default().insert(outpoint, entry);
        self.entry_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Remove a UTXO entry.
    pub fn remove(&self, script: &[u8], outpoint: &Outpoint) -> Option<UtxoEntry> {
        let mut idx = self.by_script.write();
        let entry = idx.get_mut(script).and_then(|map| map.remove(outpoint));
        if entry.is_some() {
            self.entry_count
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
        // Clean up empty maps
        if idx.get(script).map_or(false, |m| m.is_empty()) {
            idx.remove(script);
        }
        entry
    }

    /// Get all UTXOs for a script public key.
    pub fn get_utxos_by_script(&self, script: &[u8]) -> Vec<UtxoEntry> {
        self.by_script
            .read()
            .get(script)
            .map_or_else(Vec::new, |map| map.values().cloned().collect())
    }

    /// Get balance for a script public key.
    pub fn get_balance(&self, script: &[u8]) -> u64 {
        self.by_script
            .read()
            .get(script)
            .map_or(0, |map| map.values().map(|e| e.amount).sum())
    }

    /// Apply a batch of changes from a new block.
    pub fn apply_block_changes(&self, added: Vec<UtxoEntry>, removed: Vec<(Vec<u8>, Outpoint)>) {
        for entry in added {
            self.add(entry);
        }
        for (script, outpoint) in removed {
            self.remove(&script, &outpoint);
        }
    }

    pub fn entry_count(&self) -> u64 {
        self.entry_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn set_synced(&self, synced: bool) {
        self.synced
            .store(synced, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_synced(&self) -> bool {
        self.synced.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Default for UtxoIndex {
    fn default() -> Self {
        Self::new()
    }
}
