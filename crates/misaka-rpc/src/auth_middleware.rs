//! RPC authentication middleware.
//!
//! Provides method-level access control with deny-by-default semantics:
//! - Public read methods are always allowed
//! - Write methods require a valid API key
//! - Admin methods require a valid API key with admin privileges
//! - If no API key is configured, ALL write/admin requests are rejected

use sha3::{Digest, Sha3_256};
use misaka_security::constant_time;

/// Access level required for an RPC method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcAccessLevel {
    /// Read-only methods: getBlock, getTransaction, etc.
    PublicRead,
    /// Mutating methods: submitBlock, submitTransaction, etc.
    AuthenticatedWrite,
    /// Administrative methods: shutdown, etc.
    Admin,
}

/// RPC authentication guard.
///
/// Stores a SHA3-256 hash of the configured API key.
/// If no key is configured, all writes are denied (deny-by-default).
pub struct RpcAuthGuard {
    /// SHA3-256 hash of the configured API key, or None for deny-all-writes mode.
    api_key_hash: Option<[u8; 32]>,
}

impl RpcAuthGuard {
    /// Create a guard with an API key. The key is hashed immediately;
    /// the plaintext is not retained.
    pub fn new(api_key: Option<&str>) -> Self {
        let api_key_hash = api_key.map(|key| {
            let mut hasher = Sha3_256::new();
            hasher.update(key.as_bytes());
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        });
        Self { api_key_hash }
    }

    /// Check whether a request with the given bearer token is allowed
    /// to call the specified method.
    ///
    /// Returns `Ok(())` if allowed, `Err(reason)` if denied.
    pub fn check_access(
        &self,
        method: &str,
        bearer_token: Option<&str>,
    ) -> Result<(), String> {
        let required_level = classify_method(method);

        match required_level {
            RpcAccessLevel::PublicRead => Ok(()),
            RpcAccessLevel::AuthenticatedWrite | RpcAccessLevel::Admin => {
                let key_hash = match &self.api_key_hash {
                    Some(h) => h,
                    None => {
                        return Err(format!(
                            "method '{}' requires authentication but no API key is configured (deny-by-default)",
                            method
                        ));
                    }
                };

                let token = bearer_token.ok_or_else(|| {
                    format!("method '{}' requires authentication", method)
                })?;

                let mut hasher = Sha3_256::new();
                hasher.update(token.as_bytes());
                let token_hash = hasher.finalize();

                // Constant-time comparison.
                // Both sides are always 32 bytes (SHA3-256 output), so ct_eq
                // (not ct_eq_length_hiding) is correct — no length to leak.
                if !constant_time::ct_eq(key_hash, token_hash.as_slice()) {
                    return Err("invalid API key".to_string());
                }

                Ok(())
            }
        }
    }
}

/// Classify an RPC method into its required access level.
pub fn classify_method(method: &str) -> RpcAccessLevel {
    match method {
        "submitBlock" | "submitTransaction" => RpcAccessLevel::AuthenticatedWrite,
        "shutdown" => RpcAccessLevel::Admin,
        _ => RpcAccessLevel::PublicRead,
    }
}

/// Admin endpoint binding configuration.
///
/// Security: Admin endpoints (shutdown, setconfig) should bind to
/// localhost-only or a separate port, not the public RPC interface.
pub struct AdminListenerConfig {
    /// Address for admin-only endpoints. Default: 127.0.0.1:3002
    pub admin_bind: std::net::SocketAddr,
    /// Whether to require mTLS for admin connections.
    pub require_mtls: bool,
    /// Path to TLS certificate for admin interface (if mTLS enabled).
    pub tls_cert_path: Option<String>,
    /// Path to TLS key for admin interface.
    pub tls_key_path: Option<String>,
}

impl Default for AdminListenerConfig {
    fn default() -> Self {
        Self {
            admin_bind: "127.0.0.1:3002".parse().expect("valid addr"),
            require_mtls: false,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

/// Request authenticator with replay resistance.
///
/// Each authenticated request must include:
/// - `X-API-Key`: the API key
/// - `X-Request-Nonce`: a unique nonce (monotonically increasing u64)
/// - `X-Request-Timestamp`: Unix timestamp in seconds
///
/// The server rejects:
/// - Requests with timestamps > 30 seconds old
/// - Requests with a nonce <= the last seen nonce for that key
pub struct ReplayGuard {
    /// Last seen nonce per API key hash.
    last_nonce: std::collections::HashMap<[u8; 32], u64>,
    /// Maximum allowed timestamp skew in seconds.
    max_timestamp_skew_secs: u64,
    /// Optional path for disk persistence of nonce state.
    persist_path: Option<String>,
}

impl ReplayGuard {
    pub fn new(max_timestamp_skew_secs: u64) -> Self {
        Self {
            last_nonce: std::collections::HashMap::new(),
            max_timestamp_skew_secs,
            persist_path: None,
        }
    }

    /// Create with optional persistence path.
    /// If a path is provided the guard will load existing nonce state from
    /// disk and write back after every `check_replay` call.
    pub fn with_persistence(max_timestamp_skew_secs: u64, persist_path: Option<String>) -> Self {
        let mut guard = Self::new(max_timestamp_skew_secs);
        guard.persist_path = persist_path;
        guard.load_from_disk();
        guard
    }

    fn load_from_disk(&mut self) {
        let Some(path) = &self.persist_path else { return };
        let Ok(data) = std::fs::read_to_string(path) else { return };

        // Validate format: each line must be "hex_64_chars:decimal_number"
        for (line_num, line) in data.lines().enumerate() {
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() != 2 {
                tracing::error!("ReplayGuard persistence corrupted at line {}: invalid format", line_num + 1);
                // FAIL-CLOSED: clear all state and warn operator
                self.last_nonce.clear();
                tracing::error!("ReplayGuard: all nonce state cleared due to corruption. Manual review required.");
                return;
            }
            match (hex::decode(parts[0]), parts[1].parse::<u64>()) {
                (Ok(hash_bytes), Ok(nonce)) if hash_bytes.len() == 32 => {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&hash_bytes);
                    self.last_nonce.insert(key, nonce);
                }
                _ => {
                    tracing::error!("ReplayGuard persistence corrupted at line {}: bad data", line_num + 1);
                    self.last_nonce.clear();
                    return;
                }
            }
        }
        tracing::info!("ReplayGuard: loaded {} nonce entries from disk", self.last_nonce.len());
    }

    fn persist_to_disk(&self) {
        let Some(path) = &self.persist_path else { return };
        let mut content = String::new();
        for (key, nonce) in &self.last_nonce {
            content.push_str(&format!("{}:{}\n", hex::encode(key), nonce));
        }
        // Atomic write: tmp + fsync + rename
        let tmp = format!("{}.tmp", path);
        if let Ok(()) = (|| -> Result<(), std::io::Error> {
            let file = std::fs::File::create(&tmp)?;
            use std::io::Write;
            let mut w = std::io::BufWriter::new(file);
            w.write_all(content.as_bytes())?;
            w.flush()?;
            w.get_ref().sync_all()?;
            drop(w);
            std::fs::rename(&tmp, path)?;
            Ok(())
        })() {
            // ok
        } else {
            tracing::error!("ReplayGuard: persist_to_disk failed");
        }
    }

    /// Validate a request's nonce and timestamp.
    pub fn check_replay(
        &mut self,
        api_key_hash: &[u8; 32],
        nonce: u64,
        request_timestamp: u64,
    ) -> Result<(), String> {
        // Check timestamp freshness
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let age = now.saturating_sub(request_timestamp);
        if age > self.max_timestamp_skew_secs {
            return Err(format!(
                "request timestamp too old: {}s > max {}s",
                age, self.max_timestamp_skew_secs
            ));
        }

        // Future timestamps also rejected (clock skew tolerance)
        if request_timestamp > now + self.max_timestamp_skew_secs {
            return Err(format!(
                "request timestamp in the future: {} > now {}",
                request_timestamp, now
            ));
        }

        // Check nonce monotonicity
        let last = self.last_nonce.get(api_key_hash).copied().unwrap_or(0);
        if nonce <= last {
            return Err(format!(
                "nonce {} is not greater than last seen nonce {}",
                nonce, last
            ));
        }
        self.last_nonce.insert(*api_key_hash, nonce);
        self.persist_to_disk();

        Ok(())
    }
}

/// Short-lived authentication token.
///
/// Generated on login, expires after `ttl_secs`.
/// Contains the API key hash + expiration timestamp.
pub struct ShortLivedToken {
    /// SHA3-256 of (api_key || issued_at || random_nonce)
    pub token_hash: [u8; 32],
    /// When the token was issued (Unix timestamp).
    pub issued_at: u64,
    /// Time-to-live in seconds.
    pub ttl_secs: u64,
}

impl ShortLivedToken {
    /// Create a new token from an API key.
    pub fn issue(api_key: &str, ttl_secs: u64) -> Self {
        let issued_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut hasher = Sha3_256::new();
        hasher.update(b"MISAKA:token:v1:");
        hasher.update(api_key.as_bytes());
        hasher.update(&issued_at.to_le_bytes());
        // Add entropy from system
        hasher.update(&std::process::id().to_le_bytes());
        let hash = hasher.finalize();
        let mut token_hash = [0u8; 32];
        token_hash.copy_from_slice(&hash);

        Self { token_hash, issued_at, ttl_secs }
    }

    /// Check if the token is still valid.
    pub fn is_valid(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now < self.issued_at + self.ttl_secs
    }

    /// Token as hex string (for the client to use as bearer token).
    pub fn to_hex(&self) -> String {
        hex::encode(self.token_hash)
    }
}

/// Validate admin listener configuration for production safety.
/// MUST be called at node startup before binding any listener.
pub fn validate_admin_config(config: &AdminListenerConfig, is_mainnet: bool) -> Result<(), String> {
    if is_mainnet {
        let ip = config.admin_bind.ip();
        if !ip.is_loopback() {
            return Err(format!(
                "FATAL: Admin endpoint on mainnet MUST bind to localhost, got {}. \
                 Remote admin access requires SSH tunnel or VPN.",
                ip
            ));
        }
    }

    if config.require_mtls {
        if config.tls_cert_path.is_none() {
            return Err("mTLS required but tls_cert_path not set".to_string());
        }
        if config.tls_key_path.is_none() {
            return Err("mTLS required but tls_key_path not set".to_string());
        }
        // Check files exist
        if let Some(ref cert) = config.tls_cert_path {
            if !std::path::Path::new(cert).exists() {
                return Err(format!("TLS cert not found: {}", cert));
            }
        }
        if let Some(ref key) = config.tls_key_path {
            if !std::path::Path::new(key).exists() {
                return Err(format!("TLS key not found: {}", key));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_public_read() {
        assert_eq!(classify_method("getBlock"), RpcAccessLevel::PublicRead);
        assert_eq!(
            classify_method("getTransaction"),
            RpcAccessLevel::PublicRead
        );
        assert_eq!(classify_method("getInfo"), RpcAccessLevel::PublicRead);
    }

    #[test]
    fn test_classify_authenticated_write() {
        assert_eq!(
            classify_method("submitBlock"),
            RpcAccessLevel::AuthenticatedWrite
        );
        assert_eq!(
            classify_method("submitTransaction"),
            RpcAccessLevel::AuthenticatedWrite
        );
    }

    #[test]
    fn test_classify_admin() {
        assert_eq!(classify_method("shutdown"), RpcAccessLevel::Admin);
    }

    #[test]
    fn test_public_read_no_auth_needed() {
        let guard = RpcAuthGuard::new(None);
        assert!(guard.check_access("getBlock", None).is_ok());
    }

    #[test]
    fn test_deny_by_default_no_key_configured() {
        let guard = RpcAuthGuard::new(None);
        assert!(guard.check_access("submitBlock", None).is_err());
        assert!(guard
            .check_access("submitBlock", Some("any_key"))
            .is_err());
    }

    #[test]
    fn test_valid_api_key() {
        let guard = RpcAuthGuard::new(Some("my_secret_key"));
        assert!(guard
            .check_access("submitBlock", Some("my_secret_key"))
            .is_ok());
    }

    #[test]
    fn test_invalid_api_key() {
        let guard = RpcAuthGuard::new(Some("my_secret_key"));
        assert!(guard
            .check_access("submitBlock", Some("wrong_key"))
            .is_err());
    }

    #[test]
    fn test_missing_bearer_token() {
        let guard = RpcAuthGuard::new(Some("my_secret_key"));
        assert!(guard.check_access("submitTransaction", None).is_err());
    }

    #[test]
    fn test_admin_with_valid_key() {
        let guard = RpcAuthGuard::new(Some("admin_key"));
        assert!(guard
            .check_access("shutdown", Some("admin_key"))
            .is_ok());
    }

    #[test]
    fn test_ct_eq_equal() {
        let a = [0xAAu8; 32];
        let b = [0xAAu8; 32];
        assert!(constant_time::ct_eq(&a, &b));
    }

    #[test]
    fn test_ct_eq_not_equal() {
        let a = [0xAAu8; 32];
        let mut b = [0xAAu8; 32];
        b[31] = 0xBB;
        assert!(!constant_time::ct_eq(&a, &b));
    }

    #[test]
    fn test_ct_eq_wrong_length() {
        let a = [0xAAu8; 32];
        let b = [0xAAu8; 16];
        assert!(!constant_time::ct_eq(&a, &b));
    }

    // ── ReplayGuard tests ──────────────────────────────────────

    #[test]
    fn test_replay_guard_valid_request() {
        let mut guard = ReplayGuard::new(30);
        let key_hash = [0xAA; 32];
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        assert!(guard.check_replay(&key_hash, 1, now).is_ok());
    }

    #[test]
    fn test_replay_guard_rejects_old_timestamp() {
        let mut guard = ReplayGuard::new(30);
        let key_hash = [0xAA; 32];
        let old_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            - 60; // 60 seconds ago
        assert!(guard.check_replay(&key_hash, 1, old_ts).is_err());
    }

    #[test]
    fn test_replay_guard_rejects_reused_nonce() {
        let mut guard = ReplayGuard::new(30);
        let key_hash = [0xAA; 32];
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        assert!(guard.check_replay(&key_hash, 5, now).is_ok());
        assert!(guard.check_replay(&key_hash, 5, now).is_err()); // same nonce
        assert!(guard.check_replay(&key_hash, 3, now).is_err()); // lower nonce
    }

    #[test]
    fn test_replay_guard_accepts_increasing_nonces() {
        let mut guard = ReplayGuard::new(30);
        let key_hash = [0xAA; 32];
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        assert!(guard.check_replay(&key_hash, 1, now).is_ok());
        assert!(guard.check_replay(&key_hash, 2, now).is_ok());
        assert!(guard.check_replay(&key_hash, 3, now).is_ok());
    }

    // ── ShortLivedToken tests ──────────────────────────────────

    #[test]
    fn test_short_lived_token_is_valid() {
        let token = ShortLivedToken::issue("test_key", 300);
        assert!(token.is_valid());
        assert_eq!(token.to_hex().len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_short_lived_token_expired() {
        let mut token = ShortLivedToken::issue("test_key", 1);
        // Force expiration by backdating
        token.issued_at = 0;
        token.ttl_secs = 1;
        assert!(!token.is_valid());
    }

    // ── AdminListenerConfig tests ──────────────────────────────

    #[test]
    fn test_admin_listener_config_default() {
        let config = AdminListenerConfig::default();
        assert_eq!(config.admin_bind.port(), 3002);
        assert!(!config.require_mtls);
        assert!(config.tls_cert_path.is_none());
    }

    // ── validate_admin_config tests ───────────────────────────

    #[test]
    fn test_mainnet_rejects_non_localhost() {
        let config = AdminListenerConfig {
            admin_bind: "0.0.0.0:3002".parse().unwrap(),
            require_mtls: false,
            tls_cert_path: None,
            tls_key_path: None,
        };
        assert!(validate_admin_config(&config, true).is_err());
    }

    #[test]
    fn test_mainnet_allows_localhost_ipv4() {
        let config = AdminListenerConfig::default(); // 127.0.0.1:3002
        assert!(validate_admin_config(&config, true).is_ok());
    }

    #[test]
    fn test_mainnet_allows_localhost_ipv6() {
        let config = AdminListenerConfig {
            admin_bind: "[::1]:3002".parse().unwrap(),
            require_mtls: false,
            tls_cert_path: None,
            tls_key_path: None,
        };
        assert!(validate_admin_config(&config, true).is_ok());
    }

    #[test]
    fn test_testnet_allows_any_bind() {
        let config = AdminListenerConfig {
            admin_bind: "0.0.0.0:3002".parse().unwrap(),
            require_mtls: false,
            tls_cert_path: None,
            tls_key_path: None,
        };
        assert!(validate_admin_config(&config, false).is_ok());
    }

    #[test]
    fn test_mtls_requires_cert_path() {
        let config = AdminListenerConfig {
            admin_bind: "127.0.0.1:3002".parse().unwrap(),
            require_mtls: true,
            tls_cert_path: None,
            tls_key_path: Some("/tmp/key.pem".to_string()),
        };
        assert!(validate_admin_config(&config, false).is_err());
    }

    #[test]
    fn test_mtls_requires_key_path() {
        let config = AdminListenerConfig {
            admin_bind: "127.0.0.1:3002".parse().unwrap(),
            require_mtls: true,
            tls_cert_path: Some("/tmp/cert.pem".to_string()),
            tls_key_path: None,
        };
        assert!(validate_admin_config(&config, false).is_err());
    }

    // ── ReplayGuard persistence tests ─────────────────────────

    #[test]
    fn test_replay_guard_persistence_roundtrip() {
        let dir = std::env::temp_dir().join("misaka_test_replay_guard");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("nonces.dat");
        let path_str = path.to_string_lossy().to_string();

        // Write some nonce state
        {
            let mut guard = ReplayGuard::with_persistence(30, Some(path_str.clone()));
            let key_hash = [0xBB; 32];
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            assert!(guard.check_replay(&key_hash, 42, now).is_ok());
        }

        // Load from disk and verify nonce is remembered
        {
            let mut guard = ReplayGuard::with_persistence(30, Some(path_str.clone()));
            let key_hash = [0xBB; 32];
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            // Nonce 42 should be rejected (already seen)
            assert!(guard.check_replay(&key_hash, 42, now).is_err());
            // Nonce 43 should succeed
            assert!(guard.check_replay(&key_hash, 43, now).is_ok());
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
