//! RPC input validation and per-method rate limiting helpers.
//!
//! # Scope note (SEC-AUDIT cleanup)
//!
//! This module historically contained an elaborate, unused RBAC / token
//! manager / IP allowlist implementation. That code was never wired into
//! any running server — the production RPC authentication path lives in
//! `crates/misaka-node/src/rpc_auth.rs` (chain-aware bearer token + IP
//! allowlist with constant-time SHA3-256 comparison and a fail-closed
//! mainnet guard).
//!
//! The dead types (`AuthToken`, `AuthRole`, `TokenManager`, `IpAcl`,
//! `AuthError`) were deleted so that security audits and reviewers are not
//! misled by sophisticated-looking but unreachable code. Only the two
//! helpers that `service_impl.rs` actually consumes are retained:
//!
//! - [`MethodRateLimiter`]: per-(method, client) sliding-window limiter
//!   used by the in-process JSON-RPC service to cap expensive methods.
//! - [`InputValidator`]: defensive input sanitisation (hash / address /
//!   pagination / transaction shape) used at the service layer before
//!   untrusted JSON reaches the DAG.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ═══════════════════════════════════════════════════════════════════════
// Per-method rate limiter
// ═══════════════════════════════════════════════════════════════════════

/// Per-method, per-client sliding window rate limiter.
///
/// Not shared across processes; intended as an additional in-process guard
/// alongside the network-level rate limiting in `misaka-api`.
///
/// SEC-FIX N-M2: Maximum number of tracked (method, client) pairs.
/// Beyond this limit, new clients are rejected until cleanup runs.
const MAX_RATE_LIMITER_ENTRIES: usize = 100_000;

pub struct MethodRateLimiter {
    limits: HashMap<String, (u32, Duration)>,
    counters: RwLock<HashMap<(String, String), Vec<u64>>>,
    last_cleanup: RwLock<u64>,
    rejections: std::sync::atomic::AtomicU64,
    accepts: std::sync::atomic::AtomicU64,
}

impl MethodRateLimiter {
    pub fn new() -> Self {
        let mut limits = HashMap::new();
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
        limits.insert("_default".to_string(), (300, Duration::from_secs(60)));

        Self {
            limits,
            counters: RwLock::new(HashMap::new()),
            last_cleanup: RwLock::new(now_secs()),
            rejections: std::sync::atomic::AtomicU64::new(0),
            accepts: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Total rate-limit rejections since process start.
    pub fn rejection_count(&self) -> u64 {
        self.rejections.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Total rate-limit accepts since process start.
    pub fn accept_count(&self) -> u64 {
        self.accepts.load(std::sync::atomic::Ordering::Relaxed)
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

        // SEC-FIX N-M2: Auto-cleanup every 5 minutes to prevent unbounded growth
        {
            let mut last = self.last_cleanup.write();
            if now.saturating_sub(*last) > 300 {
                counters.retain(|_, ts| {
                    ts.retain(|&t| now.saturating_sub(t) < 300);
                    !ts.is_empty()
                });
                *last = now;
            }
        }

        // SEC-FIX N-M2: Reject if map is at capacity (prevents OOM from rotating client IDs)
        if !counters.contains_key(&key) && counters.len() >= MAX_RATE_LIMITER_ENTRIES {
            self.rejections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return false;
        }

        let timestamps = counters.entry(key).or_default();
        timestamps.retain(|&t| t > cutoff);

        if timestamps.len() >= max_count as usize {
            self.rejections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            false
        } else {
            timestamps.push(now);
            self.accepts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
        *self.last_cleanup.write() = now;
    }
}

impl Default for MethodRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Input validation
// ═══════════════════════════════════════════════════════════════════════

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
                let _ = amount_sum; // prevent unused warning in release builds
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

// ═══════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════

/// Get current time as seconds since UNIX epoch.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
