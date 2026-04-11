//! Encrypted Keystore — ChaCha20-Poly1305 + KDF for validator keys.
//!
//! # Security Model
//!
//! Validator secret keys are encrypted at rest using:
//! - **v2 (default)**: Argon2id + ChaCha20-Poly1305 (brute-force resistant)
//! - **v1 (legacy)**:  HKDF-SHA3-256 + ChaCha20-Poly1305 (NOT password-hard)
//!
//! # SEC-FIX-5: Argon2id Upgrade
//!
//! HKDF is an extract-then-expand KDF designed for key material with
//! high entropy. For password-based encryption (low entropy), it provides
//! no brute-force resistance. New keystores default to v2 (argon2id).
//! v1 keystores can be decrypted (for migration) but new encryption
//! always uses v2.
//!
//! # File Format (v2)
//!
//! ```json
//! {
//!   "version": 2,
//!   "kdf": "argon2id",
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
/// SEC-FIX-5: Bumped to 2 (argon2id). v1 (HKDF) is read-only for migration.
pub const KEYSTORE_VERSION: u32 = 2;

/// Legacy keystore version (HKDF, read-only).
pub const KEYSTORE_VERSION_LEGACY: u32 = 1;

/// Domain separation for HKDF key derivation (v1 legacy).
const HKDF_INFO: &[u8] = b"MISAKA_KEYSTORE_V1:chacha20poly1305";

/// Salt length in bytes.
const SALT_LEN: usize = 32;

/// Nonce length for ChaCha20-Poly1305.
const NONCE_LEN: usize = 12;

/// Argon2id parameters — tuned for validator key protection.
/// memory_cost: 256 MiB (262144 KiB), time_cost: 4 passes, parallelism: 2.
const ARGON2_M_COST: u32 = 262_144;
const ARGON2_T_COST: u32 = 4;
const ARGON2_P_COST: u32 = 2;

/// Encrypted keystore file format.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedKeystore {
    /// Format version: 1 = HKDF (legacy, read-only), 2 = argon2id (current).
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

/// Derive a 32-byte encryption key using Argon2id (v2, password-hard).
///
/// SEC-FIX-5: Argon2id provides memory-hard brute-force resistance
/// for low-entropy passphrases. This is the default for all new keystores.
fn derive_key_argon2id(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32], KeystoreError> {
    use argon2::Argon2;

    let params = argon2::Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| KeystoreError::EncryptionFailed(format!("argon2 params: {}", e)))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| KeystoreError::EncryptionFailed(format!("argon2 hash: {}", e)))?;
    Ok(key)
}

/// Derive a 32-byte encryption key from a passphrase + salt using HKDF-SHA3-256.
///
/// NOTE: HKDF is NOT a password-based KDF. This is retained ONLY for
/// decrypting v1 keystores during migration. New keystores use argon2id.
#[allow(clippy::unwrap_used)] // HKDF expand with 32-byte output is infallible for SHA3-256
fn derive_key_hkdf(passphrase: &[u8], salt: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha3_256>::new(Some(salt), passphrase);
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key)
        .expect("INVARIANT: HKDF-SHA3 expand to 32 bytes is infallible (output ≤ 255*HashLen)");
    key
}

/// Encrypt a secret key and produce an `EncryptedKeystore` (always v2 / argon2id).
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
    // SEC-FIX N-L5: Uses OsRng directly for key material generation
    // instead of thread_rng() (ChaCha-buffered). OsRng reads from the
    // OS CSPRNG without intermediate buffering.
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce_bytes);

    // SEC-FIX-5: Always use argon2id for new keystores
    let mut key = derive_key_argon2id(passphrase, &salt)?;

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
        kdf: "argon2id".into(),
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
/// Supports both v2 (argon2id) and v1 (HKDF, legacy migration).
/// Returns the raw secret key bytes. The caller is responsible for
/// zeroizing the returned bytes when done.
pub fn decrypt_keystore(
    keystore: &EncryptedKeystore,
    passphrase: &[u8],
) -> Result<Vec<u8>, KeystoreError> {
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

    // SEC-FIX-5: Derive key based on keystore version
    let mut key = match keystore.version {
        KEYSTORE_VERSION => {
            // v2: argon2id (current, password-hard)
            derive_key_argon2id(passphrase, &salt)?
        }
        KEYSTORE_VERSION_LEGACY => {
            // v1: HKDF (legacy, read-only — allows migration)
            derive_key_hkdf(passphrase, &salt)
        }
        v => return Err(KeystoreError::UnsupportedVersion(v)),
    };

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

/// Migrate a v1 (HKDF) keystore to v2 (argon2id) in place.
///
/// Decrypts with the old KDF, re-encrypts with argon2id, and saves.
/// Returns the new keystore on success.
pub fn migrate_keystore_v1_to_v2(
    keystore: &EncryptedKeystore,
    passphrase: &[u8],
) -> Result<EncryptedKeystore, KeystoreError> {
    if keystore.version != KEYSTORE_VERSION_LEGACY {
        return Err(KeystoreError::InvalidFormat(format!(
            "migrate expects v1, got v{}",
            keystore.version
        )));
    }
    let mut secret = decrypt_keystore(keystore, passphrase)?;
    let new_ks = encrypt_keystore(
        &secret,
        &keystore.public_key_hex,
        &keystore.validator_id_hex,
        keystore.stake_weight,
        passphrase,
    )?;
    secret.zeroize();
    Ok(new_ks)
}

/// Save an encrypted keystore to a file.
pub fn save_keystore(
    path: &std::path::Path,
    keystore: &EncryptedKeystore,
) -> Result<(), KeystoreError> {
    let json = serde_json::to_string_pretty(keystore)
        .map_err(|e| KeystoreError::InvalidFormat(format!("serialize: {}", e)))?;

    // SEC-FIX: Create temp file with restrictive permissions BEFORE writing
    // secrets, eliminating the window where other users could read the file.
    let tmp_path = path.with_extension("tmp");

    std::fs::write(&tmp_path, json.as_bytes())?;

    // SEC-FIX N-L6: If set_permissions fails, clean up the temp file
    // so unprotected key material does not persist on disk.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))
        {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e.into());
        }
    }

    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e.into());
    }
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

/// Check if a keystore needs migration from v1 to v2.
pub fn needs_migration(keystore: &EncryptedKeystore) -> bool {
    keystore.version == KEYSTORE_VERSION_LEGACY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip_v2() {
        let secret = b"this is a test secret key of 32b";
        let passphrase = b"strong_passphrase_123";

        let keystore =
            encrypt_keystore(secret, "aabbccdd", "11223344", 1_000_000, passphrase).unwrap();

        assert_eq!(keystore.version, KEYSTORE_VERSION);
        assert_eq!(keystore.kdf, "argon2id");
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
        let tmp = std::env::temp_dir().join("misaka_keystore_test_v2.json");
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

    #[test]
    fn test_legacy_v1_decryption_still_works() {
        // Simulate a v1 keystore (HKDF)
        let secret = b"legacy_secret_key_material_32byt";
        let pass = b"legacy_password";

        let mut salt = [0u8; SALT_LEN];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce_bytes);

        let key = derive_key_hkdf(pass, &salt);
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, secret.as_ref()).unwrap();

        let v1_keystore = EncryptedKeystore {
            version: KEYSTORE_VERSION_LEGACY,
            kdf: "hkdf-sha3-256".into(),
            salt_hex: hex::encode(salt),
            nonce_hex: hex::encode(nonce_bytes),
            ciphertext_hex: hex::encode(ciphertext),
            public_key_hex: "pk".into(),
            validator_id_hex: "id".into(),
            stake_weight: 100,
        };

        // Decrypt with v1 path
        let decrypted = decrypt_keystore(&v1_keystore, pass).unwrap();
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn test_migrate_v1_to_v2() {
        let secret = b"migrate_me_to_argon2id_32_bytes!";
        let pass = b"migration_test_pass";

        // Create a v1 keystore manually
        let mut salt = [0u8; SALT_LEN];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce_bytes);

        let key = derive_key_hkdf(pass, &salt);
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, secret.as_ref()).unwrap();

        let v1_ks = EncryptedKeystore {
            version: KEYSTORE_VERSION_LEGACY,
            kdf: "hkdf-sha3-256".into(),
            salt_hex: hex::encode(salt),
            nonce_hex: hex::encode(nonce_bytes),
            ciphertext_hex: hex::encode(ciphertext),
            public_key_hex: "pk".into(),
            validator_id_hex: "id".into(),
            stake_weight: 999,
        };

        assert!(needs_migration(&v1_ks));

        let v2_ks = migrate_keystore_v1_to_v2(&v1_ks, pass).unwrap();
        assert_eq!(v2_ks.version, KEYSTORE_VERSION);
        assert_eq!(v2_ks.kdf, "argon2id");
        assert!(!needs_migration(&v2_ks));

        let decrypted = decrypt_keystore(&v2_ks, pass).unwrap();
        assert_eq!(decrypted, secret);
    }
}
