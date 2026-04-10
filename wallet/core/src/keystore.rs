//! Encrypted keystore using Argon2id KDF + ChaCha20-Poly1305 AEAD.
//!
//! Provides at-rest encryption for wallet master seeds and private keys.
//! The keystore format is compatible with common wallet standards while
//! using post-quantum-safe symmetric cryptography.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
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
        // Audit R8: Increased from 64MB/3/4 to 256MB/4/2 (aligned with validator keystore)
        Self {
            memory_cost: 262144, // 256 MB
            time_cost: 4,
            parallelism: 2,
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
        let mut derived_key = derive_key(password, &salt, &params)?;

        // Encrypt seed
        let key = Key::from_slice(&derived_key);
        let nonce_bytes = generate_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = ChaCha20Poly1305::new(key);

        let ciphertext = cipher
            .encrypt(nonce, seed)
            .map_err(|e| KeystoreError::Encryption(format!("encrypt failed: {}", e)))?;

        // MAC = SHA3(derived_key || ciphertext)
        let mac = compute_mac(&derived_key, &ciphertext);

        // SEC-FIX NM-8: Zeroize derived key after use
        derived_key.zeroize();

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
        // SEC-FIX T3-H5: Validate KDF parameters before use to prevent downgrade attacks.
        const MIN_M_COST: u32 = 16 * 1024; // 16 MiB minimum
        const MIN_T_COST: u32 = 2;
        if self.crypto.kdf_params.memory_cost < MIN_M_COST {
            return Err(KeystoreError::Kdf(format!(
                "KDF memory_cost {} below minimum {}",
                self.crypto.kdf_params.memory_cost, MIN_M_COST
            )));
        }
        if self.crypto.kdf_params.time_cost < MIN_T_COST {
            return Err(KeystoreError::Kdf(format!(
                "KDF time_cost {} below minimum {}",
                self.crypto.kdf_params.time_cost, MIN_T_COST
            )));
        }
        if self.crypto.salt.len() < 16 {
            return Err(KeystoreError::Kdf(format!(
                "salt length {} below minimum 16",
                self.crypto.salt.len()
            )));
        }

        let mut derived_key = derive_key(password, &self.crypto.salt, &self.crypto.kdf_params)?;

        let key = Key::from_slice(&derived_key);
        let nonce = Nonce::from_slice(&self.crypto.nonce);
        let cipher = ChaCha20Poly1305::new(key);

        let plaintext = cipher
            .decrypt(nonce, self.crypto.ciphertext.as_ref())
            .map_err(|_| KeystoreError::InvalidPassword);

        // SEC-FIX T3-H6: Zeroize derived key after use (regardless of success/failure)
        derived_key.zeroize();

        plaintext
    }

    /// Change the password of an existing keystore.
    pub fn change_password(
        &self,
        old_password: &str,
        new_password: &str,
    ) -> Result<Self, KeystoreError> {
        let mut seed = self.decrypt(old_password)?;
        let result = Self::create(
            &seed,
            new_password,
            self.meta.name.clone(),
            self.meta.network.clone(),
        );
        // Audit R8: Zeroize seed bytes to prevent memory residue
        use zeroize::Zeroize;
        seed.zeroize();
        result
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, KeystoreError> {
        serde_json::to_string_pretty(self).map_err(|e| KeystoreError::Serialization(e.to_string()))
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, KeystoreError> {
        serde_json::from_str(json).map_err(|e| KeystoreError::Serialization(e.to_string()))
    }
}

fn derive_key(
    password: &str,
    salt: &[u8],
    params: &Argon2Params,
) -> Result<[u8; 32], KeystoreError> {
    // SEC-FIX CRITICAL: Replaced HKDF-SHA3 "emulation" with real Argon2id.
    // The previous implementation used HKDF + SHA3 loops which provided
    // NO memory-hard protection. GPU cracking was >1M hash/sec vs Argon2id's
    // <1 hash/sec with proper parameters. This directly endangered all wallet
    // private keys if keystore files were exfiltrated.
    use argon2::{Argon2, Algorithm, Version, Params};

    let argon2_params = Params::new(
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        Some(32),
    ).map_err(|e| KeystoreError::Kdf(format!("argon2 params: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut okm = [0u8; 32];
    argon2.hash_password_into(
        password.as_bytes(),
        salt,
        &mut okm,
    ).map_err(|e| KeystoreError::Kdf(format!("argon2id hash failed: {}", e)))?;

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
