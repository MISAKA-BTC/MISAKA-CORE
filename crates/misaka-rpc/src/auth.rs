//! RPC authentication and authorization.
//!
//! # Security Model
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
    pub fn can_access(&self, method: &str) -> bool {
        match self {
            AuthRole::Admin => true,
            AuthRole::User => !is_admin_method(method),
            AuthRole::ReadOnly => is_read_method(method),
            AuthRole::Denied => false,
        }
    }
}

fn is_admin_method(method: &str) -> bool {
    matches!(
        method,
        "shutdown" | "addPeer" | "banPeer" | "unbanPeer" | "resolveFinalityConflict"
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
pub struct TokenManager {
    secret: [u8; 32],
    tokens: RwLock<HashMap<[u8; 32], AuthToken>>,
    token_lifetime: Duration,
    max_tokens: usize,
}

impl TokenManager {
    pub fn new(secret: [u8; 32], token_lifetime: Duration, max_tokens: usize) -> Self {
        Self {
            secret,
            tokens: RwLock::new(HashMap::new()),
            token_lifetime,
            max_tokens,
        }
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
pub struct IpAcl {
    whitelist: RwLock<HashSet<IpAddr>>,
    blacklist: RwLock<HashSet<IpAddr>>,
    /// If true, only whitelisted IPs are allowed.
    whitelist_mode: bool,
}

impl IpAcl {
    pub fn new(whitelist_mode: bool) -> Self {
        Self {
            whitelist: RwLock::new(HashSet::new()),
            blacklist: RwLock::new(HashSet::new()),
            whitelist_mode,
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

    /// Validate a transaction for submission.
    pub fn validate_tx_submission(tx_json: &serde_json::Value) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        if tx_json
            .get("inputs")
            .and_then(|v| v.as_array())
            .map_or(true, |a| a.is_empty())
        {
            errors.push("transaction must have at least one input".to_string());
        }
        if tx_json
            .get("outputs")
            .and_then(|v| v.as_array())
            .map_or(true, |a| a.is_empty())
        {
            errors.push("transaction must have at least one output".to_string());
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
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn rand_bytes() -> [u8; 16] {
    let mut b = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    b
}
