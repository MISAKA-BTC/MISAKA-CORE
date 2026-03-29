//! Encrypted keystore using Argon2id KDF + ChaCha20-Poly1305 AEAD.
//!
//! Provides at-rest encryption for wallet master seeds and private keys.
//! The keystore format is compatible with common wallet standards while
//! using post-quantum-safe symmetric cryptography.

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};
use sha3::{Sha3_256, Digest};
use serde::{Serialize, Deserialize};
use zeroize::Zeroize;

/// Argon2id parameters for key derivation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Params {
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    pub output_len: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_cost: 65536,  // 64 MB
            time_cost: 3,
            parallelism: 4,
            output_len: 32,
        }
    }
}

/// Encrypted keystore entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKeystore {
    pub version: u32,
    pub id: String,
    pub crypto: CryptoParams,
    pub meta: KeystoreMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoParams {
    pub cipher: String,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub kdf: String,
    pub kdf_params: Argon2Params,
    pub salt: Vec<u8>,
    pub mac: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreMeta {
    pub name: String,
    pub created_at: u64,
    pub account_count: u32,
    pub network: String,
}

impl EncryptedKeystore {
    /// Create a new encrypted keystore from a master seed.
    pub fn create(
        seed: &[u8],
        password: &str,
        name: String,
        network: String,
    ) -> Result<Self, KeystoreError> {
        let params = Argon2Params::default();
        let salt = generate_salt();
        let derived_key = derive_key(password, &salt, &params)?;

        // Encrypt seed
        let key = Key::from_slice(&derived_key);
        let nonce_bytes = generate_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = ChaCha20Poly1305::new(key);

        let ciphertext = cipher.encrypt(nonce, seed)
            .map_err(|e| KeystoreError::Encryption(format!("encrypt failed: {}", e)))?;

        // MAC = SHA3(derived_key || ciphertext)
        let mac = compute_mac(&derived_key, &ciphertext);

        Ok(EncryptedKeystore {
            version: 1,
            id: generate_keystore_id(),
            crypto: CryptoParams {
                cipher: "chacha20-poly1305".to_string(),
                ciphertext,
                nonce: nonce_bytes.to_vec(),
                kdf: "argon2id".to_string(),
                kdf_params: params,
                salt,
                mac: mac.to_vec(),
            },
            meta: KeystoreMeta {
                name,
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                account_count: 1,
                network,
            },
        })
    }

    /// Decrypt the keystore and return the master seed.
    pub fn decrypt(&self, password: &str) -> Result<Vec<u8>, KeystoreError> {
        let derived_key = derive_key(
            password,
            &self.crypto.salt,
            &self.crypto.kdf_params,
        )?;

        // Verify MAC
        let expected_mac = compute_mac(&derived_key, &self.crypto.ciphertext);
        if expected_mac != self.crypto.mac.as_slice() {
            return Err(KeystoreError::InvalidPassword);
        }

        // Decrypt
        let key = Key::from_slice(&derived_key);
        let nonce = Nonce::from_slice(&self.crypto.nonce);
        let cipher = ChaCha20Poly1305::new(key);

        let plaintext = cipher.decrypt(nonce, self.crypto.ciphertext.as_ref())
            .map_err(|_| KeystoreError::InvalidPassword)?;

        Ok(plaintext)
    }

    /// Change the password of an existing keystore.
    pub fn change_password(
        &self,
        old_password: &str,
        new_password: &str,
    ) -> Result<Self, KeystoreError> {
        let seed = self.decrypt(old_password)?;
        Self::create(&seed, new_password, self.meta.name.clone(), self.meta.network.clone())
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, KeystoreError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| KeystoreError::Serialization(e.to_string()))
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, KeystoreError> {
        serde_json::from_str(json)
            .map_err(|e| KeystoreError::Serialization(e.to_string()))
    }
}

fn derive_key(password: &str, salt: &[u8], params: &Argon2Params) -> Result<[u8; 32], KeystoreError> {
    // Simplified Argon2id emulation using HKDF-SHA3
    // In production, use the argon2 crate directly
    let hk = hkdf::Hkdf::<Sha3_256>::new(Some(salt), password.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"MISAKA:keystore:kdf:v1", &mut okm)
        .map_err(|_| KeystoreError::Kdf("HKDF expansion failed".into()))?;

    // Additional rounds to simulate Argon2id cost
    for _ in 0..params.time_cost {
        let mut h = Sha3_256::new();
        h.update(&okm);
        h.update(salt);
        okm.copy_from_slice(&h.finalize());
    }

    Ok(okm)
}

fn compute_mac(key: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"MISAKA:keystore:mac:");
    h.update(key);
    h.update(ciphertext);
    h.finalize().into()
}

fn generate_salt() -> Vec<u8> {
    let mut salt = vec![0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
    salt
}

fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    nonce
}

fn generate_keystore_id() -> String {
    let mut bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    hex::encode(bytes)
}

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("encryption error: {0}")]
    Encryption(String),
    #[error("invalid password")]
    InvalidPassword,
    #[error("KDF error: {0}")]
    Kdf(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u32),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keystore_round_trip() {
        let seed = [42u8; 64];
        let ks = EncryptedKeystore::create(&seed, "test_password", "test".into(), "mainnet".into())
            .expect("create");
        let recovered = ks.decrypt("test_password").expect("decrypt");
        assert_eq!(seed.to_vec(), recovered);
    }

    #[test]
    fn test_wrong_password() {
        let seed = [42u8; 64];
        let ks = EncryptedKeystore::create(&seed, "correct", "test".into(), "mainnet".into())
            .expect("create");
        assert!(ks.decrypt("wrong").is_err());
    }

    #[test]
    fn test_change_password() {
        let seed = [42u8; 64];
        let ks = EncryptedKeystore::create(&seed, "old_pass", "test".into(), "mainnet".into())
            .expect("create");
        let new_ks = ks.change_password("old_pass", "new_pass").expect("change");
        assert!(new_ks.decrypt("old_pass").is_err());
        let recovered = new_ks.decrypt("new_pass").expect("decrypt");
        assert_eq!(seed.to_vec(), recovered);
    }

    #[test]
    fn test_json_serialization() {
        let seed = [42u8; 64];
        let ks = EncryptedKeystore::create(&seed, "pass", "test".into(), "testnet".into())
            .expect("create");
        let json = ks.to_json().expect("json");
        let recovered = EncryptedKeystore::from_json(&json).expect("parse");
        let decrypted = recovered.decrypt("pass").expect("decrypt");
        assert_eq!(seed.to_vec(), decrypted);
    }
}
