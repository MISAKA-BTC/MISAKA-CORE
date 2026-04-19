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

/// BIP-39 mnemonic phrase support (24 words, 256-bit entropy).
///
/// BLOCKER C history: the first implementation was non-reversible
/// (`entropy_to_mnemonic` generated "word0042"-style synthetic tokens
/// while `mnemonic_to_entropy` hashed the words — a round-trip was
/// impossible). A follow-up made round-tripping work but used the
/// synthetic word list and a SHA3-based checksum, so it was NOT BIP-39
/// compatible: users could not move their seed between MISAKA and any
/// standard wallet. Both issues are fixed here by switching to the
/// canonical English BIP-39 wordlist and the SHA-256 checksum via the
/// `bip39` crate — matching BIP-39 official test vectors bit-for-bit.
///
/// Semantics:
/// - `entropy_to_mnemonic(&[u8; 32]) -> Vec<String>` — 24-word phrase.
/// - `mnemonic_to_entropy(&[String]) -> Result<[u8; 32], String>`.
/// - `validate_mnemonic(&[String]) -> bool` — format + checksum.
///
/// The UI layer constructs the space-joined string form by
/// `words.join(" ")` as before; no API break beyond the switch from
/// the synthetic words to real English BIP-39 words in the output.
pub mod mnemonic {
    use bip39::Mnemonic;

    /// BIP-39 mnemonic from 32 bytes of entropy → 24 English words.
    ///
    /// Entropy length is fixed at 256 bits, which is BIP-39's maximum
    /// and gives a 24-word phrase. This is a deterministic
    /// `Entropy → Mnemonic` encoding — the bytes fully determine the
    /// phrase and vice versa.
    pub fn entropy_to_mnemonic(entropy: &[u8; 32]) -> Vec<String> {
        // Safety: BIP-39 accepts any 128/160/192/224/256-bit input.
        // 32 bytes = 256 bits is always valid, so `from_entropy`
        // cannot fail in practice — the `expect` is protecting
        // against an upstream API change.
        let m = Mnemonic::from_entropy(entropy)
            .expect("256-bit entropy is a valid BIP-39 input length");
        m.words().map(str::to_string).collect()
    }

    /// Convert a 24-word BIP-39 mnemonic back to 32 bytes of entropy.
    ///
    /// Enforces:
    /// - word count (24)
    /// - every word is in the English wordlist
    /// - the BIP-39 checksum byte(s) match
    ///
    /// Returns a human-readable error string on any failure.
    pub fn mnemonic_to_entropy(words: &[String]) -> Result<[u8; 32], String> {
        if words.len() != 24 {
            return Err(format!(
                "expected 24 words (256-bit entropy), got {}",
                words.len()
            ));
        }
        let phrase = words.join(" ");
        let m = Mnemonic::parse_in_normalized(bip39::Language::English, &phrase)
            .map_err(|e| format!("invalid BIP-39 mnemonic: {}", e))?;
        let (buf, len) = m.to_entropy_array();
        if len != 32 {
            return Err(format!(
                "BIP-39 decoded to {}-byte entropy; expected 32 bytes",
                len
            ));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&buf[..32]);
        Ok(out)
    }

    /// Validate a mnemonic phrase (word-list membership + checksum).
    ///
    /// Strictly BIP-39: unknown words, wrong word count, or a bad
    /// checksum all yield `false`.
    pub fn validate_mnemonic(words: &[String]) -> bool {
        mnemonic_to_entropy(words).is_ok()
    }

    // ─── Tests: BIP-39 official vectors ───────────────────────────
    //
    // Vectors from
    //   https://github.com/trezor/python-mnemonic/blob/master/vectors.json
    // (Trezor reference), trimmed to the 256-bit (24-word) entries that
    // MISAKA actually emits. Each vector is `(entropy_hex, mnemonic)`.
    // The seed column is intentionally ignored — wallets here do not
    // derive PBKDF2 seeds from the phrase (key material is generated by
    // the PQ scheme, not BIP-32), so only the entropy round-trip is
    // consensus-relevant.
    #[cfg(test)]
    mod tests {
        use super::*;

        const OFFICIAL_256_BIT_VECTORS: &[(&str, &str)] = &[
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon \
                 abandon abandon abandon abandon abandon abandon abandon abandon \
                 abandon abandon abandon abandon abandon abandon abandon art",
            ),
            (
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner \
                 thank year wave sausage worth useful legal winner thank year \
                 wave sausage worth title",
            ),
            (
                "8080808080808080808080808080808080808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter \
                 advice cage absurd amount doctor acoustic avoid letter advice \
                 cage absurd amount doctor acoustic bless",
            ),
            (
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
                 zoo zoo zoo zoo zoo zoo zoo vote",
            ),
        ];

        fn entropy_from_hex(s: &str) -> [u8; 32] {
            let bytes = hex::decode(s).expect("valid hex in test vector");
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            out
        }

        fn words_from_phrase(p: &str) -> Vec<String> {
            // The constant's implicit line-joining inserts extra
            // whitespace — normalise it.
            p.split_whitespace().map(str::to_string).collect()
        }

        #[test]
        fn official_bip39_vectors_encode_matches() {
            for (entropy_hex, expected_phrase) in OFFICIAL_256_BIT_VECTORS {
                let entropy = entropy_from_hex(entropy_hex);
                let words = entropy_to_mnemonic(&entropy);
                let expected = words_from_phrase(expected_phrase);
                assert_eq!(
                    words, expected,
                    "encoding mismatch for entropy {}",
                    entropy_hex
                );
            }
        }

        #[test]
        fn official_bip39_vectors_decode_matches() {
            for (entropy_hex, phrase) in OFFICIAL_256_BIT_VECTORS {
                let expected = entropy_from_hex(entropy_hex);
                let words = words_from_phrase(phrase);
                let decoded = mnemonic_to_entropy(&words).expect("valid vector must decode");
                assert_eq!(
                    decoded,
                    expected,
                    "decoded entropy mismatch for phrase starting {:?}",
                    words.first()
                );
            }
        }

        #[test]
        fn round_trip_preserves_entropy_for_arbitrary_bytes() {
            // Exercise boundary patterns and a pseudo-random sample.
            for seed in [[0u8; 32], [0xFFu8; 32], [0xA5u8; 32], {
                let mut e = [0u8; 32];
                for (i, b) in e.iter_mut().enumerate() {
                    *b = i as u8;
                }
                e
            }] {
                let words = entropy_to_mnemonic(&seed);
                assert_eq!(words.len(), 24);
                let back = mnemonic_to_entropy(&words).expect("round-trip decode");
                assert_eq!(back, seed, "round-trip failed for seed {:?}", &seed[..4]);
            }
        }

        #[test]
        fn wrong_word_count_is_rejected() {
            let mut words = entropy_to_mnemonic(&[0u8; 32]);
            words.pop();
            assert!(
                mnemonic_to_entropy(&words).is_err(),
                "23-word phrase must fail fast"
            );
        }

        #[test]
        fn non_wordlist_token_is_rejected() {
            let mut words = entropy_to_mnemonic(&[0u8; 32]);
            // The prior implementation used "word0042"-style synthetic
            // tokens. They are not in the BIP-39 English wordlist and
            // must therefore be rejected by the replacement impl.
            words[0] = "word0042".to_string();
            assert!(!validate_mnemonic(&words));
            assert!(mnemonic_to_entropy(&words).is_err());
        }

        #[test]
        fn corrupted_checksum_is_rejected() {
            // Take a valid phrase, swap the last word for another
            // English wordlist entry at a different index — that breaks
            // the checksum without breaking word-list membership.
            let entropy = [0u8; 32];
            let mut words = entropy_to_mnemonic(&entropy);
            let last = words.last().cloned().unwrap();
            let replacement = if last == "art" {
                "ability".to_string()
            } else {
                "art".to_string()
            };
            *words.last_mut().unwrap() = replacement;
            assert!(!validate_mnemonic(&words));
            assert!(mnemonic_to_entropy(&words).is_err());
        }
    }
}
