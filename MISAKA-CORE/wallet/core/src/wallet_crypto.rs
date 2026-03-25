//! Wallet Key Encryption — Argon2id + XChaCha20-Poly1305.
//!
//! # SEC-WALLET: Secret Key Protection
//!
//! Wallet secret keys (spending_secret, view_secret) MUST NOT be stored
//! in plaintext. This module provides password-based encryption using:
//!
//! - **KDF**: Argon2id (m=64MiB, t=3, p=1) — memory-hard, GPU-resistant
//! - **Cipher**: XChaCha20-Poly1305 — 24-byte nonce (no reuse risk), AEAD
//! - **Zeroization**: All intermediary key material is zeroized on drop
//!
//! # Format
//!
//! ```json
//! {
//!   "version": 1,
//!   "kdf": "argon2id",
//!   "kdf_params": { "m_cost": 65536, "t_cost": 3, "p_cost": 1 },
//!   "salt": "<hex 32 bytes>",
//!   "nonce": "<hex 24 bytes>",
//!   "ciphertext": "<hex N bytes>"
//! }
//! ```
//!
//! The plaintext is the JSON serialization of the secret fields
//! (spending_secret + view_secret). Public keys and address are
//! stored alongside in cleartext for scanning without decryption.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

// ═══════════════════════════════════════════════════════════════
//  KDF Parameters
// ═══════════════════════════════════════════════════════════════

/// Argon2id memory cost (KiB). 64 MiB — balance between security and
/// mobile/WASM usability. Desktop wallets may increase to 256 MiB.
const ARGON2_M_COST: u32 = 65_536; // 64 MiB
/// Argon2id time cost (iterations).
const ARGON2_T_COST: u32 = 3;
/// Argon2id parallelism.
const ARGON2_P_COST: u32 = 1;
/// Salt size (bytes).
const SALT_SIZE: usize = 32;
/// XChaCha20 nonce size (bytes).
const NONCE_SIZE: usize = 24;

// ═══════════════════════════════════════════════════════════════
//  Encrypted Envelope
// ═══════════════════════════════════════════════════════════════

/// Encrypted secret key envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSecrets {
    /// Format version (for future migration).
    pub version: u32,
    /// KDF algorithm name.
    pub kdf: String,
    /// KDF parameters (for reproducibility on decrypt).
    pub kdf_params: KdfParams,
    /// Random salt (hex-encoded).
    pub salt: String,
    /// XChaCha20 nonce (hex-encoded).
    pub nonce: String,
    /// Encrypted secrets (hex-encoded ciphertext + AEAD tag).
    pub ciphertext: String,
}

/// KDF parameters stored alongside the ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

/// Secrets that get encrypted (zeroized on drop).
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct WalletSecrets {
    pub spending_secret: Vec<u8>,
    pub view_secret: Vec<u8>,
}

/// Errors from wallet crypto operations.
#[derive(Debug, thiserror::Error)]
pub enum WalletCryptoError {
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("decryption failed: wrong password or corrupted data")]
    DecryptionFailed,
    #[error("KDF failed: {0}")]
    KdfFailed(String),
    #[error("invalid format: {0}")]
    InvalidFormat(String),
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u32),
}

// ═══════════════════════════════════════════════════════════════
//  Encrypt / Decrypt
// ═══════════════════════════════════════════════════════════════

/// Encrypt wallet secrets with a passphrase.
///
/// Returns an `EncryptedSecrets` envelope ready for JSON serialization.
/// The passphrase is NOT stored — only the derived key is used.
pub fn encrypt_secrets(
    secrets: &WalletSecrets,
    passphrase: &[u8],
) -> Result<EncryptedSecrets, WalletCryptoError> {
    use rand::RngCore;

    // Generate random salt and nonce
    let mut salt = [0u8; SALT_SIZE];
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    // Derive encryption key via Argon2id
    let mut key = derive_key(passphrase, &salt)?;

    // Serialize secrets to JSON
    let plaintext = serde_json::to_vec(secrets)
        .map_err(|e| WalletCryptoError::EncryptionFailed(e.to_string()))?;

    // Encrypt with XChaCha20-Poly1305
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| WalletCryptoError::EncryptionFailed(e.to_string()))?;
    let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| WalletCryptoError::EncryptionFailed(e.to_string()))?;

    // Zeroize key material
    key.zeroize();

    Ok(EncryptedSecrets {
        version: 1,
        kdf: "argon2id".to_string(),
        kdf_params: KdfParams {
            m_cost: ARGON2_M_COST,
            t_cost: ARGON2_T_COST,
            p_cost: ARGON2_P_COST,
        },
        salt: hex::encode(salt),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    })
}

/// Decrypt wallet secrets with a passphrase.
///
/// Returns the decrypted `WalletSecrets` (zeroized on drop).
/// Returns `DecryptionFailed` if the passphrase is wrong.
pub fn decrypt_secrets(
    envelope: &EncryptedSecrets,
    passphrase: &[u8],
) -> Result<WalletSecrets, WalletCryptoError> {
    if envelope.version != 1 {
        return Err(WalletCryptoError::UnsupportedVersion(envelope.version));
    }

    let salt = hex::decode(&envelope.salt)
        .map_err(|e| WalletCryptoError::InvalidFormat(format!("salt: {}", e)))?;
    let nonce_bytes = hex::decode(&envelope.nonce)
        .map_err(|e| WalletCryptoError::InvalidFormat(format!("nonce: {}", e)))?;
    let ciphertext = hex::decode(&envelope.ciphertext)
        .map_err(|e| WalletCryptoError::InvalidFormat(format!("ciphertext: {}", e)))?;

    if nonce_bytes.len() != NONCE_SIZE {
        return Err(WalletCryptoError::InvalidFormat(format!(
            "nonce must be {} bytes, got {}",
            NONCE_SIZE,
            nonce_bytes.len()
        )));
    }

    // Derive key using stored KDF params
    let mut key = derive_key_with_params(
        passphrase,
        &salt,
        envelope.kdf_params.m_cost,
        envelope.kdf_params.t_cost,
        envelope.kdf_params.p_cost,
    )?;

    // Decrypt
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| WalletCryptoError::DecryptionFailed)?;
    let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| WalletCryptoError::DecryptionFailed)?;

    key.zeroize();

    // Deserialize secrets
    let secrets: WalletSecrets = serde_json::from_slice(&plaintext)
        .map_err(|_| WalletCryptoError::DecryptionFailed)?;

    Ok(secrets)
}

// ═══════════════════════════════════════════════════════════════
//  KDF
// ═══════════════════════════════════════════════════════════════

fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32], WalletCryptoError> {
    derive_key_with_params(passphrase, salt, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST)
}

fn derive_key_with_params(
    passphrase: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<[u8; 32], WalletCryptoError> {
    use argon2::Argon2;

    let params = argon2::Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| WalletCryptoError::KdfFailed(format!("argon2 params: {}", e)))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| WalletCryptoError::KdfFailed(format!("argon2 hash: {}", e)))?;

    Ok(key)
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_secrets() -> WalletSecrets {
        WalletSecrets {
            spending_secret: vec![0xAA; 64],
            view_secret: vec![0xBB; 32],
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let secrets = sample_secrets();
        let passphrase = b"correct horse battery staple";

        let envelope = encrypt_secrets(&secrets, passphrase).expect("encrypt");
        assert_eq!(envelope.version, 1);
        assert_eq!(envelope.kdf, "argon2id");

        let decrypted = decrypt_secrets(&envelope, passphrase).expect("decrypt");
        assert_eq!(decrypted.spending_secret, secrets.spending_secret);
        assert_eq!(decrypted.view_secret, secrets.view_secret);
    }

    #[test]
    fn test_wrong_password_fails() {
        let secrets = sample_secrets();
        let envelope = encrypt_secrets(&secrets, b"correct").expect("encrypt");

        let result = decrypt_secrets(&envelope, b"wrong");
        assert!(matches!(result, Err(WalletCryptoError::DecryptionFailed)));
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let secrets = sample_secrets();
        let mut envelope = encrypt_secrets(&secrets, b"pass").expect("encrypt");

        // Tamper with ciphertext
        let mut ct = hex::decode(&envelope.ciphertext).unwrap();
        if !ct.is_empty() {
            ct[0] ^= 0xFF;
        }
        envelope.ciphertext = hex::encode(ct);

        let result = decrypt_secrets(&envelope, b"pass");
        assert!(matches!(result, Err(WalletCryptoError::DecryptionFailed)));
    }

    #[test]
    fn test_different_encryptions_produce_different_output() {
        let secrets = sample_secrets();
        let e1 = encrypt_secrets(&secrets, b"pass").expect("encrypt1");
        let e2 = encrypt_secrets(&secrets, b"pass").expect("encrypt2");

        // Different salt + nonce → different ciphertext
        assert_ne!(e1.salt, e2.salt);
        assert_ne!(e1.nonce, e2.nonce);
        assert_ne!(e1.ciphertext, e2.ciphertext);
    }

    #[test]
    fn test_envelope_serializes_to_json() {
        let secrets = sample_secrets();
        let envelope = encrypt_secrets(&secrets, b"pass").expect("encrypt");
        let json = serde_json::to_string_pretty(&envelope).expect("serialize");
        assert!(json.contains("argon2id"));
        assert!(json.contains("ciphertext"));

        // Roundtrip through JSON
        let parsed: EncryptedSecrets = serde_json::from_str(&json).expect("parse");
        let decrypted = decrypt_secrets(&parsed, b"pass").expect("decrypt");
        assert_eq!(decrypted.spending_secret, secrets.spending_secret);
    }

    #[test]
    fn test_unsupported_version_rejected() {
        let mut envelope = encrypt_secrets(&sample_secrets(), b"pass").expect("encrypt");
        envelope.version = 99;
        let result = decrypt_secrets(&envelope, b"pass");
        assert!(matches!(result, Err(WalletCryptoError::UnsupportedVersion(99))));
    }
}
