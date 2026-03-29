//! Owner-grouped transaction tracking.

use std::collections::{HashMap, HashSet};

/// Script public key for output ownership.
pub type ScriptPublicKey = Vec<u8>;
pub type ScriptPublicKeySet = HashSet<ScriptPublicKey>;

/// Transactions grouped by owner (script public key).
pub struct GroupedOwnerTransactions {
    /// Map from script public key to transaction IDs.
    by_owner: HashMap<ScriptPublicKey, HashSet<[u8; 32]>>,
}

impl GroupedOwnerTransactions {
    pub fn new() -> Self {
        Self { by_owner: HashMap::new() }
    }

    pub fn add(&mut self, owner: ScriptPublicKey, tx_id: [u8; 32]) {
        self.by_owner.entry(owner).or_default().insert(tx_id);
    }

    pub fn remove_tx(&mut self, tx_id: &[u8; 32]) {
        self.by_owner.retain(|_, txs| {
            txs.remove(tx_id);
            !txs.is_empty()
        });
    }

    pub fn get_txs(&self, owner: &ScriptPublicKey) -> Option<&HashSet<[u8; 32]>> {
        self.by_owner.get(owner)
    }

    pub fn owner_count(&self) -> usize { self.by_owner.len() }
    pub fn total_txs(&self) -> usize {
        self.by_owner.values().map(|s| s.len()).sum()
    }
}

impl Default for GroupedOwnerTransactions {
    fn default() -> Self { Self::new() }
}
