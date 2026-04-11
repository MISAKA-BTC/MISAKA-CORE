//! # PQ HD Key Derivation — Lattice-Based Hierarchical Deterministic Keys
//!
//! Since ML-DSA-65 and ML-KEM-768 don't support BIP32-style derivation
//! (no scalar multiplication on lattice points), we use a seed-based
//! approach:
//!
//! 1. Master seed (32 bytes from CSPRNG or mnemonic)
//! 2. Child key = ML-DSA-65::keygen(HKDF(master_seed, path))
//! 3. Path format: m / purpose' / chain_id' / account' / index
//!
//! This provides the same UX as BIP32 HD wallets while being fully
//! post-quantum secure.

use sha3::{Digest, Sha3_256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use serde::{Deserialize, Serialize};

/// MISAKA HD derivation purpose (analogous to BIP44 purpose=44').
pub const HD_PURPOSE: u32 = 44;

/// MISAKA coin type (registered namespace, like Kaspa's 111111').
pub const HD_COIN_TYPE: u32 = 888888;

/// Maximum derivation depth.
pub const MAX_DEPTH: usize = 8;

/// Derivation path component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathComponent {
    pub index: u32,
    pub hardened: bool,
}

impl PathComponent {
    pub fn hardened(index: u32) -> Self {
        Self {
            index,
            hardened: true,
        }
    }

    pub fn normal(index: u32) -> Self {
        Self {
            index,
            hardened: false,
        }
    }

    /// Encode for HKDF info: index bytes + hardened flag.
    pub fn to_bytes(&self) -> [u8; 5] {
        let mut out = [0u8; 5];
        out[..4].copy_from_slice(&self.index.to_le_bytes());
        out[4] = if self.hardened { 1 } else { 0 };
        out
    }
}

/// Full derivation path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivationPath {
    pub components: Vec<PathComponent>,
}

impl DerivationPath {
    /// Standard MISAKA path: m / 44' / 888888' / account' / index
    pub fn standard(account: u32, index: u32) -> Self {
        Self {
            components: vec![
                PathComponent::hardened(HD_PURPOSE),
                PathComponent::hardened(HD_COIN_TYPE),
                PathComponent::hardened(account),
                PathComponent::normal(index),
            ],
        }
    }

    /// Parse from string: "m/44'/888888'/0'/0"
    pub fn parse(path: &str) -> Result<Self, String> {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.is_empty() || parts[0] != "m" {
            return Err("path must start with 'm'".into());
        }
        if parts.len() > MAX_DEPTH + 1 {
            return Err(format!("path too deep (max {})", MAX_DEPTH));
        }

        let mut components = Vec::with_capacity(parts.len() - 1);
        for part in &parts[1..] {
            let (idx_str, hardened) = if let Some(stripped) = part.strip_suffix('\'') {
                (stripped, true)
            } else {
                (*part, false)
            };
            let index: u32 = idx_str
                .parse()
                .map_err(|_| format!("invalid index: {}", idx_str))?;
            components.push(PathComponent { index, hardened });
        }

        Ok(Self { components })
    }

    /// Format as string.
    pub fn to_string_path(&self) -> String {
        let mut s = "m".to_string();
        for c in &self.components {
            s.push('/');
            s.push_str(&c.index.to_string());
            if c.hardened {
                s.push('\'');
            }
        }
        s
    }
}

/// HD seed — the root of the key hierarchy.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HdSeed {
    seed: [u8; 32],
}

impl HdSeed {
    /// Create from raw 32-byte seed.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { seed: bytes }
    }

    /// Create from CSPRNG.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        Self { seed }
    }

    /// Derive a child seed for the given path using HKDF-SHA3-256.
    ///
    /// This child seed is then used as the input to ML-DSA-65/ML-KEM-768
    /// key generation.
    pub fn derive_child_seed(&self, path: &DerivationPath) -> [u8; 32] {
        use zeroize::Zeroize;
        let mut current = self.seed;

        for component in &path.components {
            let mut hasher = Sha3_256::new();
            hasher.update(b"MISAKA-HD-v1:");
            hasher.update(&current);
            hasher.update(&component.to_bytes());
            let result = hasher.finalize();
            current.copy_from_slice(&result);
        }

        // SEC-FIX: Return the derived seed but keep a copy that we'll zeroize.
        // The intermediate values during iteration are overwritten each loop,
        // but the final `current` value on the stack should be zeroized on return.
        let output = current;
        current.zeroize();
        output
    }

    /// Derive a spending keypair (ML-DSA-65) at the given path.
    ///
    /// Returns (public_key, secret_key) as raw byte vectors.
    /// The actual ML-DSA-65 keygen is delegated to `misaka-pqc`.
    pub fn derive_spending_seed(&self, path: &DerivationPath) -> [u8; 32] {
        let child = self.derive_child_seed(path);
        let mut hasher = Sha3_256::new();
        hasher.update(b"MISAKA-SPEND:");
        hasher.update(&child);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Derive a view key seed (ML-KEM-768) at the given path.
    pub fn derive_view_seed(&self, path: &DerivationPath) -> [u8; 32] {
        let child = self.derive_child_seed(path);
        let mut hasher = Sha3_256::new();
        hasher.update(b"MISAKA-VIEW:");
        hasher.update(&child);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

/// Account types (Kaspa-aligned).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountKind {
    /// Standard HD account with spending + view keys.
    Standard,
    /// Watch-only: only has public keys (view key for scanning).
    WatchOnly,
    /// Multi-signature account (threshold of PQ signers).
    Multisig { threshold: u8, total: u8 },
    /// Single keypair (imported, non-HD).
    Keypair,
    /// Resident key (hardware wallet / secure enclave).
    Resident,
}

/// Account descriptor stored in wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountDescriptor {
    /// Account kind.
    pub kind: AccountKind,
    /// Account index in the HD hierarchy.
    pub account_index: u32,
    /// Human-readable name.
    pub name: String,
    /// The derivation path used.
    pub derivation_path: String,
    /// ML-DSA-65 public key (spending).
    pub spending_public_key: Vec<u8>,
    /// ML-KEM-768 public key (view).
    pub view_public_key: Vec<u8>,
    /// For multisig: list of co-signer public keys.
    #[serde(default)]
    pub cosigner_public_keys: Vec<Vec<u8>>,
    /// Timestamp of creation.
    pub created_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derivation_path_parse() {
        let path = DerivationPath::parse("m/44'/888888'/0'/0").expect("parse");
        assert_eq!(path.components.len(), 4);
        assert_eq!(path.components[0], PathComponent::hardened(44));
        assert_eq!(path.components[1], PathComponent::hardened(888888));
        assert_eq!(path.components[2], PathComponent::hardened(0));
        assert_eq!(path.components[3], PathComponent::normal(0));
        assert_eq!(path.to_string_path(), "m/44'/888888'/0'/0");
    }

    #[test]
    fn test_child_derivation_deterministic() {
        let seed = HdSeed::from_bytes([42u8; 32]);
        let path = DerivationPath::standard(0, 0);
        let child1 = seed.derive_child_seed(&path);
        let child2 = seed.derive_child_seed(&path);
        assert_eq!(child1, child2);
    }

    #[test]
    fn test_different_paths_different_keys() {
        let seed = HdSeed::from_bytes([42u8; 32]);
        let path0 = DerivationPath::standard(0, 0);
        let path1 = DerivationPath::standard(0, 1);
        let child0 = seed.derive_child_seed(&path0);
        let child1 = seed.derive_child_seed(&path1);
        assert_ne!(child0, child1);
    }
}
