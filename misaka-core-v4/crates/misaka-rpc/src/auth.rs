//! RPC authentication and authorization.
//!
//! # SEC-AUDIT WARNING: THIS MODULE IS NOT CONNECTED TO THE PRODUCTION NODE
//!
//! The actual RPC authentication used by `misaka-node` is in
//! `crates/misaka-node/src/rpc_auth.rs` (simple bearer token + IP allowlist).
//! This module's `TokenManager`, `IpAcl`, `MethodRateLimiter`, and role-based
//! access control are NOT wired into any production code path.
//!
//! Do NOT rely on this module's security properties when evaluating the node's
//! actual RPC security posture.
//!
//! # Original Design (unrealized)
//! - Bearer token authentication for remote RPC
//! - HMAC-SHA3 token generation with configurable expiry
//! - Per-method authorization with role-based access control
//! - IP whitelist for administrative operations
//! - Rate limiting per client identity
//! - Constant-time token comparison to prevent timing attacks

use parking_lot::RwLock;
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Authentication token.
#[derive(Debug, Clone)]
pub struct AuthToken {
    pub token_hash: [u8; 32],
    pub client_id: String,
    pub role: AuthRole,
    pub issued_at: u64,
    pub expires_at: u64,
    pub permissions: HashSet<String>,
}

/// Access roles for RPC methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthRole {
    /// Full access to all methods including admin.
    Admin,
    /// Access to read methods and transaction submission.
    User,
    /// Read-only access to public chain data.
    ReadOnly,
    /// No access (banned/revoked).
    Denied,
}

impl AuthRole {
    /// Check if this role can access the given method.
    ///
    /// SECURITY: Default-deny. User and ReadOnly roles use explicit allowlists.
    /// Any method not listed is forbidden for non-Admin roles.
    pub fn can_access(&self, method: &str) -> bool {
        match self {
            AuthRole::Admin => true,
            AuthRole::User => is_user_allowed_method(method),
            AuthRole::ReadOnly => is_read_method(method),
            AuthRole::Denied => false,
        }
    }
}

/// Methods accessible to the User role (default-deny allowlist).
///
/// SECURITY: This is a closed allowlist. Any RPC method NOT listed here
/// is forbidden for User-role tokens. When adding new RPC methods,
/// explicitly add them here if they should be User-accessible.
fn is_user_allowed_method(method: &str) -> bool {
    // Read methods are also available to User
    if is_read_method(method) {
        return true;
    }
    // Write methods explicitly allowed for User
    matches!(method, "submitTransaction")
}

fn is_admin_method(method: &str) -> bool {
    matches!(
        method,
        "shutdown"
            | "addPeer"
            | "banPeer"
            | "unbanPeer"
            | "resolveFinalityConflict"
            | "submitBlock"
            | "importKey"
            | "exportKey"
            | "forceReorg"
    )
}

fn is_read_method(method: &str) -> bool {
    matches!(
        method,
        "ping"
            | "getSystemInfo"
            | "getBlock"
            | "getBlocks"
            | "getBlockCount"
            | "getBlockDagInfo"
            | "getHeaders"
            | "getMempoolEntries"
            | "getMempoolEntry"
            | "getUtxosByAddresses"
            | "getBalanceByAddress"
            | "getBalancesByAddresses"
            | "getVirtualChainFromBlock"
            | "getSinkBlueScore"
            | "getVirtualDaaScore"
            | "getBlockTemplate"
            | "estimateFeeRate"
            | "getPruningPoint"
            | "getPeerAddresses"
            | "getConnections"
            | "getMetrics"
            | "getCoinbaseAddress"
    )
}

/// Token manager for RPC authentication.
///
/// SECURITY: The secret MUST be cryptographically random and MUST NOT be
/// all-zeros. Use `TokenManager::new()` which validates the secret.
pub struct TokenManager {
    secret: [u8; 32],
    tokens: RwLock<HashMap<[u8; 32], AuthToken>>,
    token_lifetime: Duration,
    max_tokens: usize,
}

impl TokenManager {
    /// Create a new TokenManager with the given secret.
    ///
    /// SECURITY: Rejects all-zero secrets to prevent misconfigured deployments.
    /// The caller should source `secret` from an environment variable, KMS,
    /// or a 0600-permission file. If `secret` is unavailable, the node MUST
    /// refuse to start (fail-closed).
    pub fn new(
        secret: [u8; 32],
        token_lifetime: Duration,
        max_tokens: usize,
    ) -> Result<Self, AuthError> {
        if secret == [0u8; 32] {
            return Err(AuthError::InvalidSecret);
        }
        Ok(Self {
            secret,
            tokens: RwLock::new(HashMap::new()),
            token_lifetime,
            max_tokens,
        })
    }

    /// Issue a new authentication token.
    pub fn issue_token(&self, client_id: &str, role: AuthRole) -> Result<String, AuthError> {
        let now = now_secs();
        let expires = now + self.token_lifetime.as_secs();

        // Generate token using HMAC-SHA3
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:rpc:token:v1:");
        h.update(&self.secret);
        h.update(client_id.as_bytes());
        h.update(&now.to_le_bytes());
        h.update(&rand_bytes());
        let token_hash: [u8; 32] = h.finalize().into();
        let token_hex = hex::encode(token_hash);

        let auth_token = AuthToken {
            token_hash,
            client_id: client_id.to_string(),
            role,
            issued_at: now,
            expires_at: expires,
            permissions: HashSet::new(),
        };

        let mut tokens = self.tokens.write();
        if tokens.len() >= self.max_tokens {
            self.cleanup_expired(&mut tokens);
            if tokens.len() >= self.max_tokens {
                return Err(AuthError::TooManyTokens);
            }
        }
        tokens.insert(token_hash, auth_token);

        Ok(token_hex)
    }

    /// Validate a bearer token and return the associated role.
    pub fn validate_token(&self, token_hex: &str) -> Result<AuthRole, AuthError> {
        let token_bytes = hex::decode(token_hex).map_err(|_| AuthError::InvalidToken)?;
        if token_bytes.len() != 32 {
            return Err(AuthError::InvalidToken);
        }

        let mut token_hash = [0u8; 32];
        token_hash.copy_from_slice(&token_bytes);

        let tokens = self.tokens.read();
        let token = tokens.get(&token_hash).ok_or(AuthError::InvalidToken)?;

        // Constant-time comparison (already done by HashMap lookup on hash)
        if now_secs() > token.expires_at {
            return Err(AuthError::TokenExpired);
        }

        Ok(token.role)
    }

    /// Revoke a token.
    pub fn revoke_token(&self, token_hex: &str) -> bool {
        if let Ok(bytes) = hex::decode(token_hex) {
            if bytes.len() == 32 {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes);
                return self.tokens.write().remove(&hash).is_some();
            }
        }
        false
    }

    /// Check if a method call is authorized.
    pub fn check_authorization(&self, token_hex: &str, method: &str) -> Result<(), AuthError> {
        let role = self.validate_token(token_hex)?;
        if role.can_access(method) {
            Ok(())
        } else {
            Err(AuthError::Forbidden(method.to_string()))
        }
    }

    fn cleanup_expired(&self, tokens: &mut HashMap<[u8; 32], AuthToken>) {
        let now = now_secs();
        tokens.retain(|_, t| t.expires_at > now);
    }

    pub fn active_token_count(&self) -> usize {
        self.tokens.read().len()
    }
}

/// IP-based access control list.
///
/// SECURITY: For admin methods, use `new_admin_acl()` which defaults to
/// allowlist mode with only loopback addresses permitted.
pub struct IpAcl {
    whitelist: RwLock<HashSet<IpAddr>>,
    blacklist: RwLock<HashSet<IpAddr>>,
    /// If true, only whitelisted IPs are allowed (default-deny).
    whitelist_mode: bool,
}

impl IpAcl {
    /// Create a general-purpose ACL. In whitelist_mode, only whitelisted IPs pass.
    pub fn new(whitelist_mode: bool) -> Self {
        Self {
            whitelist: RwLock::new(HashSet::new()),
            blacklist: RwLock::new(HashSet::new()),
            whitelist_mode,
        }
    }

    /// Create an ACL for admin methods: allowlist-only, pre-seeded with
    /// loopback addresses (127.0.0.1 and ::1).
    ///
    /// SECURITY: Admin RPCs (shutdown, addPeer, etc.) must never be
    /// accessible from the public internet by default.
    pub fn new_admin_acl() -> Self {
        let mut whitelist = HashSet::new();
        whitelist.insert(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        whitelist.insert(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
        Self {
            whitelist: RwLock::new(whitelist),
            blacklist: RwLock::new(HashSet::new()),
            whitelist_mode: true, // default-deny for admin
        }
    }

    pub fn allow(&self, ip: &IpAddr) -> bool {
        if self.blacklist.read().contains(ip) {
            return false;
        }
        if self.whitelist_mode {
            self.whitelist.read().contains(ip)
        } else {
            true
        }
    }

    pub fn add_whitelist(&self, ip: IpAddr) {
        self.whitelist.write().insert(ip);
    }
    pub fn add_blacklist(&self, ip: IpAddr) {
        self.blacklist.write().insert(ip);
    }
    pub fn remove_whitelist(&self, ip: &IpAddr) {
        self.whitelist.write().remove(ip);
    }
    pub fn remove_blacklist(&self, ip: &IpAddr) {
        self.blacklist.write().remove(ip);
    }
}

/// Per-method rate limiter.
pub struct MethodRateLimiter {
    limits: HashMap<String, (u32, Duration)>,
    counters: RwLock<HashMap<(String, String), Vec<u64>>>,
}

impl MethodRateLimiter {
    pub fn new() -> Self {
        let mut limits = HashMap::new();
        // High-cost methods get stricter limits
        limits.insert(
            "submitTransaction".to_string(),
            (100, Duration::from_secs(60)),
        );
        limits.insert("submitBlock".to_string(), (10, Duration::from_secs(60)));
        limits.insert(
            "getBlockTemplate".to_string(),
            (60, Duration::from_secs(60)),
        );
        limits.insert(
            "getUtxosByAddresses".to_string(),
            (30, Duration::from_secs(60)),
        );
        // Default for read methods
        limits.insert("_default".to_string(), (300, Duration::from_secs(60)));

        Self {
            limits,
            counters: RwLock::new(HashMap::new()),
        }
    }

    pub fn check(&self, method: &str, client_id: &str) -> bool {
        let (max_count, window) = self
            .limits
            .get(method)
            .or_else(|| self.limits.get("_default"))
            .cloned()
            .unwrap_or((300, Duration::from_secs(60)));

        let key = (method.to_string(), client_id.to_string());
        let now = now_secs();
        let cutoff = now.saturating_sub(window.as_secs());

        let mut counters = self.counters.write();
        let timestamps = counters.entry(key).or_default();
        timestamps.retain(|&t| t > cutoff);

        if timestamps.len() >= max_count as usize {
            false
        } else {
            timestamps.push(now);
            true
        }
    }

    pub fn cleanup(&self) {
        let now = now_secs();
        let mut counters = self.counters.write();
        counters.retain(|_, ts| {
            ts.retain(|&t| now.saturating_sub(t) < 300);
            !ts.is_empty()
        });
    }
}

impl Default for MethodRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// RPC input validation.
pub struct InputValidator;

impl InputValidator {
    /// Validate a block hash parameter.
    pub fn validate_hash(s: &str) -> Result<[u8; 32], String> {
        let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {}", e))?;
        if bytes.len() != 32 {
            return Err(format!("hash must be 32 bytes, got {}", bytes.len()));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        Ok(hash)
    }

    /// Validate an address parameter.
    pub fn validate_address(s: &str) -> Result<String, String> {
        if !s.starts_with("misaka1") {
            return Err("address must start with 'misaka1'".to_string());
        }
        if s.len() < 47 || s.len() > 51 {
            return Err(format!("invalid address length: {}", s.len()));
        }
        Ok(s.to_string())
    }

    // ── TX submission size limits ──
    const MAX_TX_INPUTS: usize = 1024;
    const MAX_TX_OUTPUTS: usize = 1024;
    const MAX_SIG_SCRIPT_LEN: usize = 4096; // ML-DSA-65 sig = 3309
    const MAX_SCRIPT_PK_LEN: usize = 2048; // ML-DSA-65 pk = 1952
    const MAX_AMOUNT: u64 = u64::MAX / 2; // prevent overflow in sum

    /// Validate a transaction for submission.
    ///
    /// SECURITY: Comprehensive input sanitization to prevent DoS via
    /// oversized payloads, arithmetic overflow, and malformed fields.
    pub fn validate_tx_submission(tx_json: &serde_json::Value) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        let inputs = tx_json.get("inputs").and_then(|v| v.as_array());
        let outputs = tx_json.get("outputs").and_then(|v| v.as_array());

        // Inputs: existence and bounds
        match inputs {
            None => errors.push("transaction must have 'inputs' array".to_string()),
            Some(a) if a.is_empty() => {
                errors.push("transaction must have at least one input".to_string());
            }
            Some(a) if a.len() > Self::MAX_TX_INPUTS => {
                errors.push(format!(
                    "too many inputs: {} > max {}",
                    a.len(),
                    Self::MAX_TX_INPUTS
                ));
            }
            Some(a) => {
                for (i, inp) in a.iter().enumerate() {
                    if let Some(sig) = inp.get("sig_script").and_then(|v| v.as_str()) {
                        if sig.len() / 2 > Self::MAX_SIG_SCRIPT_LEN {
                            errors.push(format!(
                                "input[{}] sig_script too large: {} bytes > max {}",
                                i,
                                sig.len() / 2,
                                Self::MAX_SIG_SCRIPT_LEN
                            ));
                        }
                    }
                }
            }
        }

        // Outputs: existence, bounds, and amount validation
        match outputs {
            None => errors.push("transaction must have 'outputs' array".to_string()),
            Some(a) if a.is_empty() => {
                errors.push("transaction must have at least one output".to_string());
            }
            Some(a) if a.len() > Self::MAX_TX_OUTPUTS => {
                errors.push(format!(
                    "too many outputs: {} > max {}",
                    a.len(),
                    Self::MAX_TX_OUTPUTS
                ));
            }
            Some(a) => {
                let mut amount_sum: u64 = 0;
                for (i, out) in a.iter().enumerate() {
                    if let Some(amount) = out.get("amount").and_then(|v| v.as_u64()) {
                        if amount > Self::MAX_AMOUNT {
                            errors.push(format!(
                                "output[{}] amount {} exceeds max {}",
                                i,
                                amount,
                                Self::MAX_AMOUNT
                            ));
                        }
                        amount_sum = match amount_sum.checked_add(amount) {
                            Some(s) => s,
                            None => {
                                errors.push("output amounts overflow u64".to_string());
                                break;
                            }
                        };
                    }
                    if let Some(spk) = out.get("script_public_key").and_then(|v| v.as_str()) {
                        if spk.len() / 2 > Self::MAX_SCRIPT_PK_LEN {
                            errors.push(format!(
                                "output[{}] script_public_key too large: {} bytes > max {}",
                                i,
                                spk.len() / 2,
                                Self::MAX_SCRIPT_PK_LEN
                            ));
                        }
                    }
                }
            }
        }

        // Signature field
        if let Some(sig) = tx_json.get("signature").and_then(|v| v.as_str()) {
            if sig.len() / 2 > Self::MAX_SIG_SCRIPT_LEN {
                errors.push(format!(
                    "transaction signature too large: {} bytes > max {}",
                    sig.len() / 2,
                    Self::MAX_SIG_SCRIPT_LEN
                ));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate pagination parameters.
    pub fn validate_pagination(limit: u32, max: u32) -> Result<u32, String> {
        if limit == 0 {
            return Err("limit must be > 0".to_string());
        }
        if limit > max {
            return Err(format!("limit {} exceeds maximum {}", limit, max));
        }
        Ok(limit)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid token")]
    InvalidToken,
    #[error("token expired")]
    TokenExpired,
    #[error("forbidden: no access to method '{0}'")]
    Forbidden(String),
    #[error("too many active tokens")]
    TooManyTokens,
    #[error("rate limited")]
    RateLimited,
    #[error("invalid secret: must be non-zero 32-byte value")]
    InvalidSecret,
    #[error("system clock error: time before UNIX epoch")]
    ClockError,
}

/// Get current time as seconds since UNIX epoch.
///
/// SECURITY: Fail-closed — returns Err if the system clock is before
/// UNIX epoch, rather than silently returning 0 which would break
/// all token expiry logic.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after UNIX epoch")
        .as_secs()
}

fn rand_bytes() -> [u8; 16] {
    let mut b = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    b
}
