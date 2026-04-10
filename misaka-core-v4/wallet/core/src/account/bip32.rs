//! BIP32-style hierarchical deterministic account.
//!
//! Key derivation path: m/44'/MISAKA_COIN_TYPE'/account'/change/index
//! Where MISAKA_COIN_TYPE = 0x4D534B (MSK in ASCII).

use super::{Account, AccountId, AccountKind, AccountMeta};
use serde::{Deserialize, Serialize};

/// MISAKA coin type for BIP44 derivation.
pub const MISAKA_COIN_TYPE: u32 = 0x4D534B;

/// BIP32 key derivation path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivationPath {
    pub purpose: u32,
    pub coin_type: u32,
    pub account: u32,
    pub change: u32,
    pub address_index: u32,
}

impl DerivationPath {
    pub fn standard(account: u32, change: u32, index: u32) -> Self {
        Self {
            purpose: 44,
            coin_type: MISAKA_COIN_TYPE,
            account,
            change,
            address_index: index,
        }
    }

    pub fn to_string_path(&self) -> String {
        format!(
            "m/{}'/{}'/{}'/{}'/{}",
            self.purpose, self.coin_type, self.account, self.change, self.address_index,
        )
    }
}

/// Extended key for HD derivation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedKey {
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: u32,
    pub chain_code: [u8; 32],
    pub key_data: Vec<u8>,
}

impl ExtendedKey {
    /// Derive a child extended key using HKDF.
    pub fn derive_child(&self, index: u32) -> Self {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(b"MISAKA:hd:child:");
        hasher.update(&self.chain_code);
        hasher.update(&self.key_data);
        hasher.update(&index.to_be_bytes());
        let derived: [u8; 32] = hasher.finalize().into();

        // Split into key material and new chain code
        let mut new_chain_code = [0u8; 32];
        let mut new_key = Vec::with_capacity(32);

        let mut h2 = Sha3_256::new();
        h2.update(b"MISAKA:hd:chain:");
        h2.update(&derived);
        new_chain_code.copy_from_slice(&h2.finalize());

        let mut h3 = Sha3_256::new();
        h3.update(b"MISAKA:hd:key:");
        h3.update(&derived);
        h3.update(&self.key_data);
        new_key.extend_from_slice(&h3.finalize());

        // Fingerprint = first 4 bytes of SHA3(parent key)
        let mut fp = [0u8; 4];
        let mut h4 = Sha3_256::new();
        h4.update(&self.key_data);
        fp.copy_from_slice(&h4.finalize()[..4]);

        ExtendedKey {
            depth: self.depth + 1,
            parent_fingerprint: fp,
            child_number: index,
            chain_code: new_chain_code,
            key_data: new_key,
        }
    }

    /// Create a master key from seed.
    pub fn from_seed(seed: &[u8]) -> Self {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(b"MISAKA:hd:master:");
        hasher.update(seed);
        let master: [u8; 32] = hasher.finalize().into();

        let mut chain_code = [0u8; 32];
        let mut h2 = Sha3_256::new();
        h2.update(b"MISAKA:hd:master:chain:");
        h2.update(seed);
        chain_code.copy_from_slice(&h2.finalize());

        ExtendedKey {
            depth: 0,
            parent_fingerprint: [0; 4],
            child_number: 0,
            chain_code,
            key_data: master.to_vec(),
        }
    }

    /// Derive the full path: m/44'/coin'/account'/change/index
    pub fn derive_path(&self, path: &DerivationPath) -> Self {
        self.derive_child(path.purpose | 0x80000000)
            .derive_child(path.coin_type | 0x80000000)
            .derive_child(path.account | 0x80000000)
            .derive_child(path.change)
            .derive_child(path.address_index)
    }
}

/// BIP32-style HD wallet account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bip32Account {
    pub meta: AccountMeta,
    pub master_xpub: ExtendedKey,
    pub account_index: u32,
    /// Cached derived addresses.
    pub receive_addresses: Vec<String>,
    pub change_addresses: Vec<String>,
}

impl Bip32Account {
    pub fn new(id: AccountId, name: String, master_xpub: ExtendedKey, account_index: u32) -> Self {
        Self {
            meta: AccountMeta::new(id, name, AccountKind::Bip32),
            master_xpub,
            account_index,
            receive_addresses: Vec::new(),
            change_addresses: Vec::new(),
        }
    }

    fn derive_address(&self, change: u32, index: u32) -> String {
        let path = DerivationPath::standard(self.account_index, change, index);
        let derived = self.master_xpub.derive_path(&path);
        let addr_bytes: [u8; 20] = {
            use sha3::{Digest, Sha3_256};
            let mut h = Sha3_256::new();
            h.update(&derived.key_data);
            let hash: [u8; 32] = h.finalize().into();
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&hash[..20]);
            addr
        };
        crate::encode_address(&addr_bytes)
    }
}

impl Account for Bip32Account {
    fn meta(&self) -> &AccountMeta {
        &self.meta
    }
    fn kind(&self) -> AccountKind {
        AccountKind::Bip32
    }
    fn receive_address(&self) -> String {
        self.derive_address(0, self.meta.receive_address_index)
    }
    fn change_address(&self) -> String {
        self.derive_address(1, self.meta.change_address_index)
    }
    fn next_receive_address(&mut self) -> String {
        self.meta.receive_address_index += 1;
        let addr = self.receive_address();
        self.receive_addresses.push(addr.clone());
        addr
    }
    fn next_change_address(&mut self) -> String {
        self.meta.change_address_index += 1;
        let addr = self.change_address();
        self.change_addresses.push(addr.clone());
        addr
    }
    fn can_sign(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hd_derivation_determinism() {
        let seed = [42u8; 32];
        let master = ExtendedKey::from_seed(&seed);
        let child1 = master.derive_child(0);
        let child2 = master.derive_child(0);
        assert_eq!(child1.key_data, child2.key_data);
    }

    #[test]
    fn test_different_paths_different_keys() {
        let seed = [42u8; 32];
        let master = ExtendedKey::from_seed(&seed);
        let a = master.derive_child(0);
        let b = master.derive_child(1);
        assert_ne!(a.key_data, b.key_data);
    }

    #[test]
    fn test_bip32_account_addresses() {
        let master = ExtendedKey::from_seed(&[99u8; 64]);
        let account = Bip32Account::new(1, "Test".into(), master, 0);
        let addr1 = account.receive_address();
        assert!(addr1.starts_with("misaka1"));
    }
}
