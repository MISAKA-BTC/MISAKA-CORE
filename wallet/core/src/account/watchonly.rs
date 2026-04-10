//! Watch-only account: can track balance but cannot sign transactions.

use super::{Account, AccountId, AccountKind, AccountMeta};
use serde::{Deserialize, Serialize};

/// Watch-only account that tracks public keys without spending capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchOnlyAccount {
    pub meta: AccountMeta,
    /// Public key(s) to track.
    pub tracked_pubkeys: Vec<Vec<u8>>,
    /// Derived addresses.
    pub addresses: Vec<String>,
    /// Optional label for each address.
    pub labels: Vec<String>,
}

impl WatchOnlyAccount {
    pub fn new(id: AccountId, name: String, pubkeys: Vec<Vec<u8>>) -> Self {
        let addresses: Vec<String> = pubkeys
            .iter()
            .map(|pk| {
                use sha3::{Digest, Sha3_256};
                let mut h = Sha3_256::new();
                h.update(b"MISAKA:addr:pk:");
                h.update(pk);
                let hash: [u8; 32] = h.finalize().into();
                let mut addr = [0u8; 20];
                addr.copy_from_slice(&hash[..20]);
                crate::encode_address(&addr)
            })
            .collect();

        let labels = vec!["".to_string(); addresses.len()];

        Self {
            meta: AccountMeta::new(id, name, AccountKind::WatchOnly),
            tracked_pubkeys: pubkeys,
            addresses,
            labels,
        }
    }

    pub fn add_address(&mut self, pubkey: Vec<u8>, label: String) {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:addr:pk:");
        h.update(&pubkey);
        let hash: [u8; 32] = h.finalize().into();
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[..20]);
        self.addresses.push(crate::encode_address(&addr));
        self.tracked_pubkeys.push(pubkey);
        self.labels.push(label);
    }
}

impl Account for WatchOnlyAccount {
    fn meta(&self) -> &AccountMeta {
        &self.meta
    }
    fn kind(&self) -> AccountKind {
        AccountKind::WatchOnly
    }
    fn receive_address(&self) -> String {
        self.addresses.first().cloned().unwrap_or_default()
    }
    fn change_address(&self) -> String {
        self.receive_address()
    }
    fn next_receive_address(&mut self) -> String {
        self.receive_address()
    }
    fn next_change_address(&mut self) -> String {
        self.receive_address()
    }
    fn can_sign(&self) -> bool {
        false
    }
}
