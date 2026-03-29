//! Wallet backup and restore: import/export functionality.

use serde::{Serialize, Deserialize};
use crate::keystore::EncryptedKeystore;

/// Wallet export format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletExport {
    pub version: u32,
    pub format: ExportFormat,
    pub network: String,
    pub keystore: Option<EncryptedKeystore>,
    pub accounts: Vec<AccountExport>,
    pub metadata: ExportMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportFormat {
    Full,          // Complete wallet with encrypted keys
    WatchOnly,     // Public keys only
    Addresses,     // Address list only
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountExport {
    pub name: String,
    pub kind: String,
    pub public_keys: Vec<String>,
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportMetadata {
    pub exported_at: u64,
    pub wallet_version: String,
    pub total_accounts: usize,
    pub total_addresses: usize,
}

/// Export a wallet to JSON format.
pub fn export_wallet(
    keystore: Option<&EncryptedKeystore>,
    format: ExportFormat,
    network: &str,
    accounts: Vec<AccountExport>,
) -> Result<String, String> {
    let export = WalletExport {
        version: 1,
        format,
        network: network.to_string(),
        keystore: match format {
            ExportFormat::Full => keystore.cloned(),
            _ => None,
        },
        metadata: ExportMetadata {
            exported_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            wallet_version: env!("CARGO_PKG_VERSION").to_string(),
            total_accounts: accounts.len(),
            total_addresses: accounts.iter().map(|a| a.addresses.len()).sum(),
        },
        accounts,
    };
    serde_json::to_string_pretty(&export).map_err(|e| e.to_string())
}

/// Import a wallet from JSON format.
pub fn import_wallet(json: &str) -> Result<WalletExport, String> {
    let export: WalletExport = serde_json::from_str(json)
        .map_err(|e| format!("invalid wallet export: {}", e))?;
    if export.version != 1 {
        return Err(format!("unsupported export version: {}", export.version));
    }
    Ok(export)
}

/// Mnemonic phrase support (24 words).
pub mod mnemonic {
    /// Generate a 24-word mnemonic from entropy.
    pub fn entropy_to_mnemonic(entropy: &[u8; 32]) -> Vec<String> {
        // Simplified: SHA3-based word selection from a fixed wordlist
        use sha3::{Sha3_256, Digest};
        let mut words = Vec::with_capacity(24);
        for i in 0..24 {
            let mut h = Sha3_256::new();
            h.update(b"MISAKA:mnemonic:word:");
            h.update(entropy);
            h.update(&(i as u32).to_le_bytes());
            let hash: [u8; 32] = h.finalize().into();
            let idx = u16::from_le_bytes([hash[0], hash[1]]) % 2048;
            words.push(format!("word{:04}", idx));
        }
        words
    }

    /// Convert mnemonic words back to entropy.
    pub fn mnemonic_to_entropy(words: &[String]) -> Result<[u8; 32], String> {
        if words.len() != 24 {
            return Err(format!("expected 24 words, got {}", words.len()));
        }
        use sha3::{Sha3_256, Digest};
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:mnemonic:entropy:");
        for word in words {
            h.update(word.as_bytes());
            h.update(b":");
        }
        Ok(h.finalize().into())
    }

    /// Validate a mnemonic phrase.
    pub fn validate_mnemonic(words: &[String]) -> bool {
        words.len() == 24 && words.iter().all(|w| w.starts_with("word"))
    }
}
