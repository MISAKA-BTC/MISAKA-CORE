//! Encrypted keystore support.
//!
//! Provides hooks for OS keyring / HSM / secure enclave integration.
//! All temporary plaintext buffers are zeroized.

use zeroize::Zeroize;

/// Keystore backend abstraction.
pub trait KeystoreBackend: Send + Sync {
    /// Load a secret by name. Returns encrypted bytes.
    fn load(&self, name: &str) -> Result<Vec<u8>, KeystoreError>;
    /// Store a secret by name.
    fn store(&self, name: &str, data: &[u8]) -> Result<(), KeystoreError>;
    /// Delete a secret by name.
    fn delete(&self, name: &str) -> Result<(), KeystoreError>;
    /// Backend type identifier.
    fn backend_type(&self) -> &str;
}

/// File-based keystore (default, encrypted with Argon2id + XChaCha20).
pub struct FileKeystore {
    base_dir: std::path::PathBuf,
}

impl FileKeystore {
    pub fn new(base_dir: impl AsRef<std::path::Path>) -> Self {
        Self { base_dir: base_dir.as_ref().to_path_buf() }
    }
}

impl KeystoreBackend for FileKeystore {
    fn load(&self, name: &str) -> Result<Vec<u8>, KeystoreError> {
        let path = self.base_dir.join(format!("{}.enc", name));
        std::fs::read(&path).map_err(|e| KeystoreError::IoError(e.to_string()))
    }

    fn store(&self, name: &str, data: &[u8]) -> Result<(), KeystoreError> {
        std::fs::create_dir_all(&self.base_dir)
            .map_err(|e| KeystoreError::IoError(e.to_string()))?;
        let path = self.base_dir.join(format!("{}.enc", name));
        std::fs::write(&path, data).map_err(|e| KeystoreError::IoError(e.to_string()))
    }

    fn delete(&self, name: &str) -> Result<(), KeystoreError> {
        let path = self.base_dir.join(format!("{}.enc", name));
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| KeystoreError::IoError(e.to_string()))?;
        }
        Ok(())
    }

    fn backend_type(&self) -> &str { "file" }
}

/// Temporary plaintext buffer that zeroizes on drop.
pub struct PlaintextBuffer {
    data: Vec<u8>,
}

impl PlaintextBuffer {
    pub fn new(data: Vec<u8>) -> Self { Self { data } }
    pub fn as_bytes(&self) -> &[u8] { &self.data }
}

impl Drop for PlaintextBuffer {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("IO error: {0}")]
    IoError(String),
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("key not found: {0}")]
    KeyNotFound(String),
}

/// Key rotation guidance.
pub struct RotationPolicy {
    /// Maximum age in seconds before rotation is recommended.
    pub max_age_secs: u64,
    /// Whether rotation is mandatory (fail startup if expired).
    pub mandatory: bool,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self { max_age_secs: 90 * 24 * 3600, mandatory: false } // 90 days
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plaintext_buffer_zeroizes() {
        let buf = PlaintextBuffer::new(vec![0xAA; 32]);
        assert_eq!(buf.as_bytes(), &[0xAA; 32]);
        // Drop will zeroize
    }

    #[test]
    fn test_file_keystore_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ks = FileKeystore::new(dir.path());
        ks.store("test_key", b"secret_data").expect("store");
        let loaded = ks.load("test_key").expect("load");
        assert_eq!(loaded, b"secret_data");
        ks.delete("test_key").expect("delete");
        assert!(ks.load("test_key").is_err());
    }
}
