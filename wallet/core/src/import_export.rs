//! Wallet backup and restore: import/export functionality.

use crate::keystore::EncryptedKeystore;
use serde::{Deserialize, Serialize};

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
    Full,      // Complete wallet with encrypted keys
    WatchOnly, // Public keys only
    Addresses, // Address list only
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
    let export: WalletExport =
        serde_json::from_str(json).map_err(|e| format!("invalid wallet export: {}", e))?;
    if export.version != 1 {
        return Err(format!("unsupported export version: {}", export.version));
    }
    Ok(export)
}

/// Mnemonic phrase support (24 words).
///
/// SEC-FIX CRITICAL: Previous implementation was NON-REVERSIBLE.
/// `entropy_to_mnemonic()` generated pseudo-words ("word0042") by hashing entropy,
/// but `mnemonic_to_entropy()` hashed the word strings — a completely different
/// operation. Round-trip was impossible: users could NOT recover wallets from
/// their written-down recovery phrases.
///
/// New implementation uses a direct encoding scheme:
/// - 256 bits of entropy → 24 words (11 bits per word, truncated)
/// - Words are indices into a fixed 2048-word list
/// - `mnemonic_to_entropy()` reverses the encoding exactly
/// - Round-trip: entropy → mnemonic → entropy is guaranteed
///
/// SEC-FIX NM-9: This is a CUSTOM mnemonic scheme, NOT BIP-39 compatible.
/// Wallets created with this scheme cannot be imported into standard wallets
/// and vice versa. MUST be replaced with the `bip39` crate before mainnet.
///
/// TODO(MAINNET-BLOCKER): Replace with `bip39` crate for standard BIP-39 compatibility.
#[deprecated(note = "Custom mnemonic — NOT BIP-39 compatible. Replace before mainnet.")]
pub mod mnemonic {
    /// Fixed wordlist (numbered for simplicity — replace with BIP-39 English words).
    fn word_for_index(idx: u16) -> String {
        format!("word{:04}", idx)
    }

    fn index_for_word(word: &str) -> Result<u16, String> {
        word.strip_prefix("word")
            .and_then(|n| n.parse::<u16>().ok())
            .filter(|&n| n < 2048)
            .ok_or_else(|| format!("invalid mnemonic word: {}", word))
    }

    /// Generate a 24-word mnemonic from 32 bytes of entropy.
    /// Each word encodes ~11 bits. 24 words = 264 bits (256 entropy + 8 checksum).
    pub fn entropy_to_mnemonic(entropy: &[u8; 32]) -> Vec<String> {
        use sha3::{Digest, Sha3_256};
        // Checksum: first byte of SHA3-256(entropy)
        let checksum = Sha3_256::digest(entropy)[0];
        // 33 bytes = 264 bits → 24 × 11-bit words
        let mut bits = Vec::with_capacity(264);
        for byte in entropy.iter() {
            for bit in (0..8).rev() {
                bits.push((byte >> bit) & 1);
            }
        }
        for bit in (0..8).rev() {
            bits.push((checksum >> bit) & 1);
        }

        let mut words = Vec::with_capacity(24);
        for chunk in bits.chunks(11) {
            let mut idx: u16 = 0;
            for &b in chunk {
                idx = (idx << 1) | b as u16;
            }
            words.push(word_for_index(idx));
        }
        words
    }

    /// Convert mnemonic words back to entropy (reversible).
    pub fn mnemonic_to_entropy(words: &[String]) -> Result<[u8; 32], String> {
        if words.len() != 24 {
            return Err(format!("expected 24 words, got {}", words.len()));
        }
        // Decode 24 words → 264 bits
        let mut bits = Vec::with_capacity(264);
        for word in words {
            let idx = index_for_word(word)?;
            for bit in (0..11).rev() {
                bits.push(((idx >> bit) & 1) as u8);
            }
        }

        // First 256 bits = entropy, last 8 = checksum
        let mut entropy = [0u8; 32];
        for (i, byte_bits) in bits[..256].chunks(8).enumerate() {
            let mut byte = 0u8;
            for &b in byte_bits {
                byte = (byte << 1) | b;
            }
            entropy[i] = byte;
        }

        // Verify checksum
        use sha3::{Digest, Sha3_256};
        let expected_checksum = Sha3_256::digest(&entropy)[0];
        let mut actual_checksum = 0u8;
        for &b in &bits[256..264] {
            actual_checksum = (actual_checksum << 1) | b;
        }
        if expected_checksum != actual_checksum {
            return Err("mnemonic checksum verification failed".into());
        }

        Ok(entropy)
    }

    /// Validate a mnemonic phrase (format + checksum).
    pub fn validate_mnemonic(words: &[String]) -> bool {
        mnemonic_to_entropy(words).is_ok()
    }
}
