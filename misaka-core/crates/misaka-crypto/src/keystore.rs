//! Encrypted Keystore — ChaCha20-Poly1305 + HKDF-SHA3 for validator keys.
//!
//! # Security Model
//!
//! Validator secret keys are encrypted at rest using:
//! - **KDF**: HKDF-SHA3-256 with 32-byte random salt
//! - **AEAD**: ChaCha20-Poly1305 (12-byte nonce, 16-byte tag)
//!
//! # Upgrade Path
//!
//! HKDF is an extract-then-expand KDF designed for key material with
//! high entropy. For password-based encryption (low entropy), production
//! deployments SHOULD upgrade to argon2id (version field = 2).
//! The current version (1) is a significant improvement over plaintext
//! but does not provide brute-force resistance for weak passwords.
//!
//! # File Format
//!
//! ```json
//! {
//!   "version": 1,
//!   "kdf": "hkdf-sha3-256",
//!   "salt_hex": "...",
//!   "nonce_hex": "...",
//!   "ciphertext_hex": "...",
//!   "public_key_hex": "...",
//!   "validator_id_hex": "...",
//!   "stake_weight": 1000000
//! }
//! ```

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha3::Sha3_256;
use zeroize::Zeroize;

/// Current keystore format version.
pub const KEYSTORE_VERSION: u32 = 1;

/// Domain separation for HKDF key derivation.
const HKDF_INFO: &[u8] = b"MISAKA_KEYSTORE_V1:chacha20poly1305";

/// Salt length in bytes.
const SALT_LEN: usize = 32;

/// Nonce length for ChaCha20-Poly1305.
const NONCE_LEN: usize = 12;

/// Encrypted keystore file format.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedKeystore {
    /// Format version (currently 1).
    pub version: u32,
    /// KDF algorithm identifier.
    pub kdf: String,
    /// Random salt (hex-encoded, 32 bytes).
    pub salt_hex: String,
    /// AEAD nonce (hex-encoded, 12 bytes).
    pub nonce_hex: String,
    /// Encrypted secret key + AEAD tag (hex-encoded).
    pub ciphertext_hex: String,
    /// Public key (hex-encoded, unencrypted — needed for identity without decryption).
    pub public_key_hex: String,
    /// Validator ID derived from public key (hex-encoded).
    pub validator_id_hex: String,
    /// Stake weight (unencrypted metadata).
    pub stake_weight: u128,
}

/// Errors from keystore operations.
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("decryption failed — wrong password or corrupt keystore")]
    DecryptionFailed,
    #[error("unsupported keystore version: {0}")]
    UnsupportedVersion(u32),
    #[error("invalid keystore format: {0}")]
    InvalidFormat(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Derive a 32-byte encryption key from a passphrase + salt using HKDF-SHA3-256.
///
/// NOTE: HKDF is NOT a password-based KDF. It does not provide
/// brute-force resistance for low-entropy passwords. For mainnet,
/// upgrade to argon2id (set version=2 in keystore format).
fn derive_key(passphrase: &[u8], salt: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha3_256>::new(Some(salt), passphrase);
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key)
        .expect("HKDF expand with 32-byte output should never fail");
    key
}

/// Encrypt a secret key and produce an `EncryptedKeystore`.
///
/// # Arguments
///
/// - `secret_key_bytes`: Raw secret key bytes (will be encrypted)
/// - `public_key_hex`: Hex-encoded public key (stored unencrypted)
/// - `validator_id_hex`: Hex-encoded validator ID (stored unencrypted)
/// - `stake_weight`: Stake weight metadata
/// - `passphrase`: Encryption passphrase (zeroized after use)
pub fn encrypt_keystore(
    secret_key_bytes: &[u8],
    public_key_hex: &str,
    validator_id_hex: &str,
    stake_weight: u128,
    passphrase: &[u8],
) -> Result<EncryptedKeystore, KeystoreError> {
    // Generate random salt and nonce
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce_bytes);

    // Derive encryption key
    let mut key = derive_key(passphrase, &salt);

    // Encrypt
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| KeystoreError::EncryptionFailed(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, secret_key_bytes)
        .map_err(|e| KeystoreError::EncryptionFailed(e.to_string()))?;

    // Zeroize key material
    key.zeroize();

    Ok(EncryptedKeystore {
        version: KEYSTORE_VERSION,
        kdf: "hkdf-sha3-256".into(),
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce_bytes),
        ciphertext_hex: hex::encode(ciphertext),
        public_key_hex: public_key_hex.to_string(),
        validator_id_hex: validator_id_hex.to_string(),
        stake_weight,
    })
}

/// Decrypt a secret key from an `EncryptedKeystore`.
///
/// Returns the raw secret key bytes. The caller is responsible for
/// zeroizing the returned bytes when done.
pub fn decrypt_keystore(
    keystore: &EncryptedKeystore,
    passphrase: &[u8],
) -> Result<Vec<u8>, KeystoreError> {
    if keystore.version != KEYSTORE_VERSION {
        return Err(KeystoreError::UnsupportedVersion(keystore.version));
    }

    let salt = hex::decode(&keystore.salt_hex)
        .map_err(|e| KeystoreError::InvalidFormat(format!("bad salt hex: {}", e)))?;
    let nonce_bytes = hex::decode(&keystore.nonce_hex)
        .map_err(|e| KeystoreError::InvalidFormat(format!("bad nonce hex: {}", e)))?;
    let ciphertext = hex::decode(&keystore.ciphertext_hex)
        .map_err(|e| KeystoreError::InvalidFormat(format!("bad ciphertext hex: {}", e)))?;

    if salt.len() != SALT_LEN {
        return Err(KeystoreError::InvalidFormat(format!(
            "salt length {}, expected {}",
            salt.len(),
            SALT_LEN
        )));
    }
    if nonce_bytes.len() != NONCE_LEN {
        return Err(KeystoreError::InvalidFormat(format!(
            "nonce length {}, expected {}",
            nonce_bytes.len(),
            NONCE_LEN
        )));
    }

    // Derive decryption key
    let mut key = derive_key(passphrase, &salt);

    // Decrypt
    let cipher =
        ChaCha20Poly1305::new_from_slice(&key).map_err(|_| KeystoreError::DecryptionFailed)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| KeystoreError::DecryptionFailed)?;

    // Zeroize key material
    key.zeroize();

    Ok(plaintext)
}

/// Save an encrypted keystore to a file.
pub fn save_keystore(
    path: &std::path::Path,
    keystore: &EncryptedKeystore,
) -> Result<(), KeystoreError> {
    let json = serde_json::to_string_pretty(keystore)
        .map_err(|e| KeystoreError::InvalidFormat(format!("serialize: {}", e)))?;

    // Atomic write
    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, json.as_bytes())?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Load an encrypted keystore from a file.
pub fn load_keystore(path: &std::path::Path) -> Result<EncryptedKeystore, KeystoreError> {
    let data = std::fs::read(path)?;
    let keystore: EncryptedKeystore = serde_json::from_slice(&data)
        .map_err(|e| KeystoreError::InvalidFormat(format!("deserialize: {}", e)))?;
    Ok(keystore)
}

/// Check if a file is in the old plaintext format (for migration).
pub fn is_plaintext_keyfile(path: &std::path::Path) -> bool {
    if let Ok(data) = std::fs::read_to_string(path) {
        // Old format has "secret_key_hex" as a direct field
        data.contains("\"secret_key_hex\"") && !data.contains("\"ciphertext_hex\"")
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let secret = b"this is a test secret key of 32b";
        let passphrase = b"strong_passphrase_123";

        let keystore =
            encrypt_keystore(secret, "aabbccdd", "11223344", 1_000_000, passphrase).unwrap();

        assert_eq!(keystore.version, KEYSTORE_VERSION);
        assert_eq!(keystore.public_key_hex, "aabbccdd");
        assert_eq!(keystore.validator_id_hex, "11223344");

        let decrypted = decrypt_keystore(&keystore, passphrase).unwrap();
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let secret = b"secret_key_material_here_32bytes";
        let keystore =
            encrypt_keystore(secret, "pubkey", "valid", 100, b"correct_password").unwrap();

        let result = decrypt_keystore(&keystore, b"wrong_password");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            KeystoreError::DecryptionFailed
        ));
    }

    #[test]
    fn test_different_salts_produce_different_ciphertexts() {
        let secret = b"same_secret_key_material_32byte";
        let pass = b"same_password";

        let ks1 = encrypt_keystore(secret, "pk", "id", 1, pass).unwrap();
        let ks2 = encrypt_keystore(secret, "pk", "id", 1, pass).unwrap();

        // Salt is random → ciphertexts differ even with same inputs
        assert_ne!(ks1.ciphertext_hex, ks2.ciphertext_hex);

        // Both decrypt to the same plaintext
        let d1 = decrypt_keystore(&ks1, pass).unwrap();
        let d2 = decrypt_keystore(&ks2, pass).unwrap();
        assert_eq!(d1, d2);
        assert_eq!(d1, secret);
    }

    #[test]
    fn test_file_roundtrip() {
        let tmp = std::env::temp_dir().join("misaka_keystore_test.json");
        let secret = b"file_roundtrip_secret_key_32byte";
        let pass = b"file_test_pass";

        let keystore = encrypt_keystore(secret, "pk_hex", "val_id", 500, pass).unwrap();
        save_keystore(&tmp, &keystore).unwrap();

        let loaded = load_keystore(&tmp).unwrap();
        let decrypted = decrypt_keystore(&loaded, pass).unwrap();
        assert_eq!(decrypted, secret);

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_unsupported_version() {
        let mut keystore = encrypt_keystore(b"key", "pk", "id", 1, b"pass").unwrap();
        keystore.version = 99;
        let result = decrypt_keystore(&keystore, b"pass");
        assert!(matches!(
            result.unwrap_err(),
            KeystoreError::UnsupportedVersion(99)
        ));
    }
}
