//! Storage encryption at rest.
//!
//! Encrypts all database values using ChaCha20-Poly1305 with per-column-family
//! key derivation. Provides transparent encrypt/decrypt at the storage layer.
//!
//! # Key Hierarchy
//! ```text
//! Master Key (user password → Argon2id)
//!   ├── CF Key "headers" (HKDF-SHA3)
//!   ├── CF Key "blocks" (HKDF-SHA3)
//!   ├── CF Key "utxo" (HKDF-SHA3)
//!   └── CF Key "wallet" (HKDF-SHA3)
//! ```

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};
use sha3::{Sha3_256, Digest};
use std::collections::HashMap;
use parking_lot::RwLock;

/// Storage encryption configuration.
#[derive(Debug, Clone)]
pub struct EncryptionConfig {
    pub enabled: bool,
    pub algorithm: String,
    pub key_rotation_interval: u64,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            algorithm: "chacha20-poly1305".to_string(),
            key_rotation_interval: 86400 * 30, // 30 days
        }
    }
}

/// Transparent storage encryption layer.
pub struct StorageEncryption {
    master_key: [u8; 32],
    cf_keys: RwLock<HashMap<String, [u8; 32]>>,
    enabled: bool,
}

impl StorageEncryption {
    /// Create from a master key.
    pub fn new(master_key: [u8; 32], enabled: bool) -> Self {
        Self {
            master_key,
            cf_keys: RwLock::new(HashMap::new()),
            enabled,
        }
    }

    /// Create disabled (passthrough) encryption.
    pub fn disabled() -> Self {
        Self::new([0; 32], false)
    }

    /// Derive a key for a specific column family.
    fn get_cf_key(&self, cf_name: &str) -> [u8; 32] {
        {
            let keys = self.cf_keys.read();
            if let Some(key) = keys.get(cf_name) {
                return *key;
            }
        }

        let key = derive_cf_key(&self.master_key, cf_name);
        self.cf_keys.write().insert(cf_name.to_string(), key);
        key
    }

    /// Encrypt a value for storage.
    pub fn encrypt(&self, cf_name: &str, plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if !self.enabled {
            return Ok(plaintext.to_vec());
        }

        let cf_key = self.get_cf_key(cf_name);
        let key = Key::from_slice(&cf_key);
        let cipher = ChaCha20Poly1305::new(key);

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|e| EncryptionError::EncryptFailed(e.to_string()))?;

        // Format: nonce (12 bytes) || ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt a value from storage.
    pub fn decrypt(&self, cf_name: &str, encrypted: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if !self.enabled {
            return Ok(encrypted.to_vec());
        }

        if encrypted.len() < 12 + 16 {
            return Err(EncryptionError::DataTooShort(encrypted.len()));
        }

        let cf_key = self.get_cf_key(cf_name);
        let key = Key::from_slice(&cf_key);
        let cipher = ChaCha20Poly1305::new(key);

        let nonce = Nonce::from_slice(&encrypted[..12]);
        let ciphertext = &encrypted[12..];

        cipher.decrypt(nonce, ciphertext)
            .map_err(|_| EncryptionError::DecryptFailed)
    }

    pub fn is_enabled(&self) -> bool { self.enabled }
}

/// Derive a per-column-family encryption key.
fn derive_cf_key(master: &[u8; 32], cf_name: &str) -> [u8; 32] {
    let hk = hkdf::Hkdf::<Sha3_256>::new(Some(b"MISAKA:storage:cf:v1"), master);
    let mut key = [0u8; 32];
    hk.expand(cf_name.as_bytes(), &mut key).expect("valid length");
    key
}

#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("encryption failed: {0}")]
    EncryptFailed(String),
    #[error("decryption failed (wrong key or corrupted data)")]
    DecryptFailed,
    #[error("encrypted data too short: {0} bytes")]
    DataTooShort(usize),
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let enc = StorageEncryption::new([42u8; 32], true);
        let plaintext = b"hello misaka world";
        let encrypted = enc.encrypt("test_cf", plaintext).unwrap();
        assert_ne!(&encrypted, plaintext);
        let decrypted = enc.decrypt("test_cf", &encrypted).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_different_cf_different_keys() {
        let enc = StorageEncryption::new([42u8; 32], true);
        let plaintext = b"same data";
        let e1 = enc.encrypt("cf_a", plaintext).unwrap();
        let e2 = enc.encrypt("cf_b", plaintext).unwrap();
        // Different CFs produce different ciphertexts (different nonces + keys)
        assert_ne!(e1, e2);
    }

    #[test]
    fn test_disabled_passthrough() {
        let enc = StorageEncryption::disabled();
        let data = b"plaintext";
        let result = enc.encrypt("test", data).unwrap();
        assert_eq!(&result, data);
    }

    #[test]
    fn test_wrong_cf_fails_decrypt() {
        let enc = StorageEncryption::new([42u8; 32], true);
        let encrypted = enc.encrypt("cf_a", b"secret").unwrap();
        assert!(enc.decrypt("cf_b", &encrypted).is_err());
    }
}
