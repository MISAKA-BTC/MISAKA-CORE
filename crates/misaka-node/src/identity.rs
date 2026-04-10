// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Validator identity management — persistent ML-DSA-65 keypair.
//!
//! The keypair is loaded from disk on startup. On first startup it is
//! generated and persisted with restrictive file permissions.
//!
//! See docs/design/VALIDATOR_IDENTITY.md for design rationale.

use sha3::{Digest, Sha3_256};
use std::path::Path;
use zeroize::Zeroize;

/// File magic bytes for validator.key.
const KEY_MAGIC: &[u8; 4] = b"MKEY";
/// File version.
const KEY_VERSION: u32 = 1;
/// ML-DSA-65 secret key length.
const SK_LEN: usize = 4032;
/// ML-DSA-65 public key length.
const PK_LEN: usize = 1952;
/// Expected file size: magic(4) + version(4) + sk(4032) + pk(1952) + fingerprint(32).
const KEY_FILE_SIZE: usize = 4 + 4 + SK_LEN + PK_LEN + 32;

/// Validator identity error.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("key file has wrong magic: expected MKEY")]
    BadMagic,
    #[error("key file has unsupported version: {0}")]
    UnsupportedVersion(u32),
    #[error("key file has wrong size: expected {expected}, got {actual}")]
    WrongSize { expected: usize, actual: usize },
    #[error("key file fingerprint mismatch (file may be corrupted)")]
    FingerprintMismatch,
    #[error("key file permissions too permissive (expected 0o600): {0}")]
    InsecurePermissions(String),
    #[error("ML-DSA-65 key parse error: {0}")]
    KeyParse(String),
    #[error("signing failed: {0}")]
    SignFailed(String),
}

/// Persistent validator identity backed by ML-DSA-65 keypair.
///
/// SECURITY: The secret key is zeroized on drop. The public key and
/// fingerprint are retained for logging and committee matching.
pub struct ValidatorIdentity {
    /// Raw secret key bytes (zeroized on drop).
    sk_bytes: Vec<u8>,
    /// Public key bytes (1952 bytes).
    pk_bytes: Vec<u8>,
    /// SHA3-256 fingerprint of public key (for logging, not crypto).
    fingerprint: [u8; 32],
}

impl Drop for ValidatorIdentity {
    fn drop(&mut self) {
        self.sk_bytes.zeroize();
    }
}

impl ValidatorIdentity {
    /// Load an existing keypair or create a new one.
    ///
    /// On first startup (file does not exist): generates and persists.
    /// On subsequent startups: loads and validates.
    pub fn load_or_create(path: &Path) -> Result<Self, IdentityError> {
        if path.exists() {
            Self::load(path)
        } else {
            Self::create_and_persist(path)
        }
    }

    /// Load an existing keypair from disk.
    pub fn load(path: &Path) -> Result<Self, IdentityError> {
        // Check permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(path)?;
            let mode = meta.permissions().mode() & 0o777;
            if mode != 0o600 {
                return Err(IdentityError::InsecurePermissions(format!(
                    "got 0o{:o}, expected 0o600; run: chmod 600 {}",
                    mode,
                    path.display()
                )));
            }
        }

        let data = std::fs::read(path)?;
        if data.len() != KEY_FILE_SIZE {
            return Err(IdentityError::WrongSize {
                expected: KEY_FILE_SIZE,
                actual: data.len(),
            });
        }

        // Parse
        if &data[0..4] != KEY_MAGIC {
            return Err(IdentityError::BadMagic);
        }
        let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
        if version != KEY_VERSION {
            return Err(IdentityError::UnsupportedVersion(version));
        }

        let sk_bytes = data[8..8 + SK_LEN].to_vec();
        let pk_bytes = data[8 + SK_LEN..8 + SK_LEN + PK_LEN].to_vec();
        let stored_fp: [u8; 32] = data[8 + SK_LEN + PK_LEN..].try_into().unwrap();

        // Verify fingerprint
        let computed_fp = Self::compute_fingerprint(&pk_bytes);
        if stored_fp != computed_fp {
            return Err(IdentityError::FingerprintMismatch);
        }

        Ok(Self {
            sk_bytes,
            pk_bytes,
            fingerprint: computed_fp,
        })
    }

    /// Generate a new keypair and persist to disk.
    fn create_and_persist(path: &Path) -> Result<Self, IdentityError> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Generate keypair
        let kp = misaka_pqc::pq_sign::MlDsaKeypair::generate();
        let pk_bytes = kp.public_key.as_bytes().to_vec();
        let sk_bytes = kp.secret_key.with_bytes(|b| b.to_vec());
        let fingerprint = Self::compute_fingerprint(&pk_bytes);

        // Serialize
        let mut data = Vec::with_capacity(KEY_FILE_SIZE);
        data.extend_from_slice(KEY_MAGIC);
        data.extend_from_slice(&KEY_VERSION.to_le_bytes());
        data.extend_from_slice(&sk_bytes);
        data.extend_from_slice(&pk_bytes);
        data.extend_from_slice(&fingerprint);
        assert_eq!(data.len(), KEY_FILE_SIZE);

        // Write with restrictive permissions
        std::fs::write(path, &data)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }

        tracing::info!(
            fingerprint = %hex::encode(fingerprint),
            path = %path.display(),
            "Generated new validator identity"
        );

        Ok(Self {
            sk_bytes,
            pk_bytes,
            fingerprint,
        })
    }

    /// Public key bytes (1952 bytes).
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.pk_bytes
    }

    /// SHA3-256 fingerprint of public key.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// Public key as the validator transport type used by `misaka-p2p`.
    pub fn validator_public_key(
        &self,
    ) -> Result<misaka_crypto::validator_sig::ValidatorPqPublicKey, IdentityError> {
        misaka_crypto::validator_sig::ValidatorPqPublicKey::from_bytes(&self.pk_bytes)
            .map_err(|e| IdentityError::KeyParse(e.to_string()))
    }

    /// Secret key as the validator transport type used by `misaka-p2p`.
    pub fn validator_secret_key(
        &self,
    ) -> Result<misaka_crypto::validator_sig::ValidatorPqSecretKey, IdentityError> {
        if self.sk_bytes.len() != misaka_pqc::pq_sign::ML_DSA_SK_LEN {
            return Err(IdentityError::KeyParse(format!(
                "invalid validator secret key length: expected {}, got {}",
                misaka_pqc::pq_sign::ML_DSA_SK_LEN,
                self.sk_bytes.len()
            )));
        }
        misaka_crypto::validator_sig::ValidatorPqSecretKey::from_bytes(&self.sk_bytes).ok_or_else(
            || {
                IdentityError::KeyParse(format!(
                    "secret key must be 4032 bytes, got {}",
                    self.sk_bytes.len()
                ))
            },
        )
    }

    /// Sign a block digest with the validator's ML-DSA-65 secret key.
    ///
    /// Phase 2c-B D5a: domain prefix removed (was block domain tag).
    /// Block digest already provides uniqueness; no cross-protocol replay
    /// risk because IntentMessage-based signing handles domain separation
    /// at the transaction layer.
    pub fn sign_block(&self, block_digest: &[u8]) -> Result<Vec<u8>, IdentityError> {
        let sk = misaka_pqc::pq_sign::MlDsaSecretKey::from_bytes(&self.sk_bytes)
            .map_err(|e| IdentityError::KeyParse(e.to_string()))?;
        let sig = misaka_pqc::pq_sign::ml_dsa_sign_raw(&sk, block_digest)
            .map_err(|e| IdentityError::SignFailed(e.to_string()))?;
        Ok(sig.as_bytes().to_vec())
    }

    /// Sign an arbitrary message (raw, no domain prefix).
    ///
    /// Phase 2c-B D5a: domain parameter removed. Callers that need domain
    /// separation should incorporate it into the message hash upstream.
    pub fn sign_raw(&self, msg: &[u8]) -> Result<Vec<u8>, IdentityError> {
        let sk = misaka_pqc::pq_sign::MlDsaSecretKey::from_bytes(&self.sk_bytes)
            .map_err(|e| IdentityError::KeyParse(e.to_string()))?;
        let sig = misaka_pqc::pq_sign::ml_dsa_sign_raw(&sk, msg)
            .map_err(|e| IdentityError::SignFailed(e.to_string()))?;
        Ok(sig.as_bytes().to_vec())
    }

    fn compute_fingerprint(pk: &[u8]) -> [u8; 32] {
        Sha3_256::digest(pk).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("validator.key");

        // Create
        let id1 = ValidatorIdentity::create_and_persist(&path).unwrap();
        assert_eq!(id1.public_key().len(), PK_LEN);

        // Load
        let id2 = ValidatorIdentity::load(&path).unwrap();
        assert_eq!(id1.public_key(), id2.public_key());
        assert_eq!(id1.fingerprint(), id2.fingerprint());
    }

    #[test]
    fn test_load_or_create_generates_on_first_run() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("validator.key");
        assert!(!path.exists());

        let id = ValidatorIdentity::load_or_create(&path).unwrap();
        assert!(path.exists());
        assert_eq!(id.public_key().len(), PK_LEN);
    }

    #[test]
    fn test_load_or_create_reuses_on_second_run() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("validator.key");

        let id1 = ValidatorIdentity::load_or_create(&path).unwrap();
        let id2 = ValidatorIdentity::load_or_create(&path).unwrap();
        assert_eq!(
            id1.fingerprint(),
            id2.fingerprint(),
            "REGRESSION: second startup must use same identity"
        );
    }

    #[test]
    fn test_corrupted_file_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("validator.key");
        std::fs::write(&path, b"garbage data").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(ValidatorIdentity::load(&path).is_err());
    }

    #[test]
    fn test_bad_magic_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("validator.key");
        let mut data = vec![0u8; KEY_FILE_SIZE];
        data[0..4].copy_from_slice(b"BADM"); // wrong magic
        std::fs::write(&path, &data).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(matches!(
            ValidatorIdentity::load(&path),
            Err(IdentityError::BadMagic)
        ));
    }

    #[test]
    fn test_sign_block_produces_valid_signature() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("validator.key");
        let id = ValidatorIdentity::create_and_persist(&path).unwrap();
        let sig = id.sign_block(b"test block digest").unwrap();
        assert!(!sig.is_empty());
        // Verify the signature with raw (no domain) verify
        let pk = misaka_pqc::pq_sign::MlDsaPublicKey::from_bytes(id.public_key()).unwrap();
        let sig_obj = misaka_pqc::pq_sign::MlDsaSignature::from_bytes(&sig).unwrap();
        misaka_pqc::pq_sign::ml_dsa_verify_raw(&pk, b"test block digest", &sig_obj)
            .expect("block signature must verify with raw verify");
    }

    #[cfg(unix)]
    #[test]
    fn test_insecure_permissions_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("validator.key");
        ValidatorIdentity::create_and_persist(&path).unwrap();
        // Make world-readable
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            ValidatorIdentity::load(&path),
            Err(IdentityError::InsecurePermissions(_))
        ));
    }
}
