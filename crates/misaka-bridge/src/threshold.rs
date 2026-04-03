//! Bridge withdrawal rate limiting and threshold signature verification.
//!
//! Provides:
//! - Per-address and global withdrawal rate limits with anomaly detection
//! - 2/3 committee threshold verification with ML-DSA-65 signatures

use std::collections::HashMap;

/// Errors from rate limiting.
#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("per-address limit exceeded for {address}: {amount} exceeds remaining {remaining}")]
    PerAddressLimitExceeded {
        address: String,
        amount: u64,
        remaining: u64,
    },
    #[error("global limit exceeded: {amount} exceeds remaining {remaining}")]
    GlobalLimitExceeded { amount: u64, remaining: u64 },
    #[error("anomaly detected: withdrawal of {amount} is >{pct}% of global limit")]
    AnomalyDetected { amount: u64, pct: u64 },
}

/// Errors from threshold verification.
#[derive(Debug, thiserror::Error)]
pub enum ThresholdError {
    #[error("not enough signatures: got {got}, need {need}")]
    InsufficientSignatures { got: usize, need: usize },
    #[error("duplicate signer: {0}")]
    DuplicateSigner(String),
    #[error("unknown signer: {0}")]
    UnknownSigner(String),
    #[error("invalid signature from signer {0}")]
    InvalidSignature(String),
}

// ═══════════════════════════════════════════════════════════════
//  CRIT-3 FIX: Time-based auto-reset withdrawal rate limiter
//
//  Previous version required manual reset_window() calls from an
//  external keeper. If the keeper stopped, windows never reset,
//  permanently blocking all withdrawals OR disabling limits entirely.
//
//  New version: windows auto-expire based on elapsed time.
//  No external keeper required.
// ═══════════════════════════════════════════════════════════════

/// Default window duration: 1 hour (3600 seconds).
pub const DEFAULT_RATE_WINDOW_SECS: u64 = 3600;

/// Per-address and global withdrawal rate limiter with:
/// - **Time-based auto-reset** (CRIT-3 FIX) — no external keeper needed
/// - Anomaly detection (single large withdrawal rejection)
/// - Per-address limits
/// - Global limits
pub struct WithdrawalRateLimiter {
    /// Maximum withdrawal per address in a single window.
    per_address_limit: u64,
    /// Maximum total withdrawals across all addresses in a single window.
    global_limit: u64,
    /// Accumulated withdrawals per address: (window_start_ms, amount).
    per_address_used: HashMap<String, (u64, u64)>,
    /// Global: (window_start_ms, total_amount).
    global_window_start_ms: u64,
    global_used: u64,
    /// Window duration in milliseconds.
    window_ms: u64,
    /// Anomaly threshold: reject if a single withdrawal exceeds this fraction
    /// of the global limit (expressed as percentage, e.g., 50 = 50%).
    anomaly_pct: u64,
}

impl WithdrawalRateLimiter {
    /// Create a new rate limiter with default 1-hour window.
    pub fn new(per_address_limit: u64, global_limit: u64) -> Self {
        Self {
            per_address_limit,
            global_limit,
            per_address_used: HashMap::new(),
            global_window_start_ms: 0,
            global_used: 0,
            window_ms: DEFAULT_RATE_WINDOW_SECS * 1000,
            anomaly_pct: 50,
        }
    }

    /// Create with custom anomaly percentage and window duration.
    pub fn with_anomaly_pct(per_address_limit: u64, global_limit: u64, anomaly_pct: u64) -> Self {
        Self {
            per_address_limit,
            global_limit,
            per_address_used: HashMap::new(),
            global_window_start_ms: 0,
            global_used: 0,
            window_ms: DEFAULT_RATE_WINDOW_SECS * 1000,
            anomaly_pct,
        }
    }

    /// Create with explicit window duration (seconds).
    pub fn with_window(per_address_limit: u64, global_limit: u64, window_secs: u64) -> Self {
        Self {
            per_address_limit,
            global_limit,
            per_address_used: HashMap::new(),
            global_window_start_ms: 0,
            global_used: 0,
            window_ms: window_secs * 1000,
            anomaly_pct: 50,
        }
    }

    /// CRIT-3: Auto-prune expired windows based on current time.
    /// Called internally before every check — no external keeper needed.
    fn auto_prune(&mut self, now_ms: u64) {
        // Global window auto-reset
        if now_ms.saturating_sub(self.global_window_start_ms) >= self.window_ms {
            self.global_used = 0;
            self.global_window_start_ms = now_ms;
        }

        // Per-address window auto-reset
        self.per_address_used.retain(|_, (start, _)| {
            now_ms.saturating_sub(*start) < self.window_ms
        });
    }

    /// Attempt to record a withdrawal. Returns `Ok(())` if allowed.
    ///
    /// `now_ms` is the current unix timestamp in milliseconds.
    pub fn check_and_record(
        &mut self,
        address: &str,
        amount: u64,
        now_ms: u64,
    ) -> Result<(), RateLimitError> {
        self.auto_prune(now_ms);

        // Anomaly detection
        let anomaly_threshold = self.global_limit * self.anomaly_pct / 100;
        if amount > anomaly_threshold {
            return Err(RateLimitError::AnomalyDetected {
                amount,
                pct: self.anomaly_pct,
            });
        }

        // Per-address check
        let addr_used = self.per_address_used.get(address)
            .map(|(_, amt)| *amt).unwrap_or(0);
        let addr_remaining = self.per_address_limit.saturating_sub(addr_used);
        if amount > addr_remaining {
            return Err(RateLimitError::PerAddressLimitExceeded {
                address: address.to_string(),
                amount,
                remaining: addr_remaining,
            });
        }

        // Global check
        let global_remaining = self.global_limit.saturating_sub(self.global_used);
        if amount > global_remaining {
            return Err(RateLimitError::GlobalLimitExceeded {
                amount,
                remaining: global_remaining,
            });
        }

        // Record
        let entry = self.per_address_used
            .entry(address.to_string())
            .or_insert((now_ms, 0));
        entry.1 += amount;
        self.global_used += amount;

        Ok(())
    }

    /// Check if a withdrawal would be allowed (without recording it).
    pub fn check_withdrawal(
        &self,
        address: &str,
        amount: u64,
    ) -> Result<(), RateLimitError> {
        // Note: check_withdrawal uses current state without auto_prune.
        // For accurate checks, use check_and_record with now_ms.

        // Anomaly detection
        let anomaly_threshold = self.global_limit * self.anomaly_pct / 100;
        if amount > anomaly_threshold {
            return Err(RateLimitError::AnomalyDetected {
                amount,
                pct: self.anomaly_pct,
            });
        }

        // Per-address check
        let addr_used = self.per_address_used.get(address)
            .map(|(_, amt)| *amt).unwrap_or(0);
        let addr_remaining = self.per_address_limit.saturating_sub(addr_used);
        if amount > addr_remaining {
            return Err(RateLimitError::PerAddressLimitExceeded {
                address: address.to_string(),
                amount,
                remaining: addr_remaining,
            });
        }

        // Global check
        let global_remaining = self.global_limit.saturating_sub(self.global_used);
        if amount > global_remaining {
            return Err(RateLimitError::GlobalLimitExceeded {
                amount,
                remaining: global_remaining,
            });
        }

        Ok(())
    }

    /// Record a withdrawal for rate tracking (call after successful execution).
    pub fn record_withdrawal(&mut self, address: &str, amount: u64) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let entry = self.per_address_used
            .entry(address.to_string())
            .or_insert((now_ms, 0));
        entry.1 += amount;
        self.global_used += amount;
    }

    /// Legacy: manual reset. Still available but no longer required.
    pub fn reset_window(&mut self) {
        self.per_address_used.clear();
        self.global_used = 0;
        self.global_window_start_ms = 0;
    }
}

/// A committee member for threshold verification.
#[derive(Clone)]
pub struct ThresholdMember {
    /// Unique identifier (e.g., hex-encoded public key hash).
    pub id: String,
    /// ML-DSA-65 public key bytes.
    pub public_key: Vec<u8>,
}

/// A signature from a committee member.
pub struct ThresholdSignature {
    /// Signer's identifier (must match a `ThresholdMember::id`).
    pub signer_id: String,
    /// Raw ML-DSA-65 signature bytes.
    pub signature: Vec<u8>,
}

/// Verifies that at least 2/3 of committee members have signed a message.
pub struct ThresholdVerifier {
    /// Committee members indexed by id.
    members: HashMap<String, ThresholdMember>,
    /// Total committee size.
    total: usize,
    /// Required signatures (ceil(2/3 * total)).
    threshold: usize,
}

impl ThresholdVerifier {
    /// Create a new threshold verifier.
    ///
    /// `threshold_numerator` / `threshold_denominator` defines the fraction
    /// (typically 2/3).
    pub fn new(members: Vec<ThresholdMember>) -> Result<Self, ThresholdError> {
        let total = members.len();
        // ceil(2/3 * total) = (2 * total + 2) / 3
        let threshold = (2 * total + 2) / 3;
        let map: HashMap<String, ThresholdMember> = members
            .into_iter()
            .map(|m| (m.id.clone(), m))
            .collect();
        Ok(Self {
            members: map,
            total,
            threshold,
        })
    }

    /// Required number of signatures.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Total committee size.
    pub fn total(&self) -> usize {
        self.total
    }

    /// Verify that enough valid, non-duplicate signatures exist for `message`.
    ///
    /// Uses ML-DSA-65 signature verification via `misaka-crypto`.
    pub fn verify(
        &self,
        message: &[u8],
        signatures: &[ThresholdSignature],
    ) -> Result<(), ThresholdError> {
        if signatures.len() < self.threshold {
            return Err(ThresholdError::InsufficientSignatures {
                got: signatures.len(),
                need: self.threshold,
            });
        }

        let mut seen_signers: HashMap<&str, bool> = HashMap::new();
        let mut valid_count = 0usize;

        for sig in signatures {
            // Duplicate detection
            if seen_signers.contains_key(sig.signer_id.as_str()) {
                return Err(ThresholdError::DuplicateSigner(sig.signer_id.clone()));
            }
            seen_signers.insert(&sig.signer_id, true);

            // Lookup member
            let member = self
                .members
                .get(&sig.signer_id)
                .ok_or_else(|| ThresholdError::UnknownSigner(sig.signer_id.clone()))?;

            // Verify ML-DSA-65 signature (skip if empty — counted as invalid)
            if !sig.signature.is_empty() && !member.public_key.is_empty() {
                let valid = verify_ml_dsa_65(&member.public_key, message, &sig.signature);
                if !valid {
                    return Err(ThresholdError::InvalidSignature(sig.signer_id.clone()));
                }
                valid_count += 1;
            }
        }

        if valid_count < self.threshold {
            return Err(ThresholdError::InsufficientSignatures {
                got: valid_count,
                need: self.threshold,
            });
        }

        Ok(())
    }
}

/// Verify an ML-DSA-65 signature using `misaka-pqc`.
///
/// Returns `true` if the signature is valid.
fn verify_ml_dsa_65(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use misaka_pqc::pq_sign::{ml_dsa_verify_raw, MlDsaPublicKey, MlDsaSignature};
    let pk = match MlDsaPublicKey::from_bytes(public_key) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let sig = match MlDsaSignature::from_bytes(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    ml_dsa_verify_raw(&pk, message, &sig).is_ok()
}

/// Emergency pause state for the bridge.
///
/// When paused, ALL withdrawals are rejected.
/// Only the committee can unpause via threshold signature.
pub struct BridgeCircuitBreaker {
    /// Whether the bridge is currently paused.
    paused: bool,
    /// Reason for the pause (human-readable).
    pause_reason: Option<String>,
    /// Timestamp when the bridge was paused.
    paused_at: Option<u64>,
    /// Minimum committee signatures required to unpause.
    unpause_threshold: usize,
}

impl BridgeCircuitBreaker {
    pub fn new(unpause_threshold: usize) -> Self {
        Self {
            paused: false,
            pause_reason: None,
            paused_at: None,
            unpause_threshold,
        }
    }

    /// Trigger emergency pause. Any single committee member can pause.
    pub fn pause(&mut self, reason: &str) {
        self.paused = true;
        self.pause_reason = Some(reason.to_string());
        self.paused_at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
    }

    /// Attempt to unpause. Requires threshold signatures.
    pub fn unpause(&mut self, signature_count: usize) -> Result<(), String> {
        if !self.paused {
            return Err("bridge is not paused".to_string());
        }
        if signature_count < self.unpause_threshold {
            return Err(format!(
                "insufficient signatures to unpause: {}/{}",
                signature_count, self.unpause_threshold
            ));
        }
        self.paused = false;
        self.pause_reason = None;
        self.paused_at = None;
        Ok(())
    }

    /// Check if the bridge is operational.
    pub fn check(&self) -> Result<(), String> {
        if self.paused {
            Err(format!(
                "bridge is paused: {}",
                self.pause_reason.as_deref().unwrap_or("no reason given")
            ))
        } else {
            Ok(())
        }
    }

    pub fn is_paused(&self) -> bool { self.paused }
    pub fn pause_reason(&self) -> Option<&str> { self.pause_reason.as_deref() }
}

/// Manual approval queue for large withdrawals.
///
/// Withdrawals above `auto_approve_limit` are queued for manual review
/// by the committee instead of being processed automatically.
pub struct ManualApprovalQueue {
    /// Maximum amount for automatic withdrawal.
    auto_approve_limit: u64,
    /// Pending withdrawals awaiting approval.
    pending: Vec<PendingWithdrawal>,
    /// Maximum queue size (DoS protection).
    max_queue_size: usize,
    /// Optional persistence path. If set, queue auto-persists after mutations.
    persist_path: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingWithdrawal {
    pub id: [u8; 32],
    pub recipient: [u8; 32],
    pub amount: u64,
    pub submitted_at: u64,
    pub approvals: Vec<String>, // committee member IDs
}

impl ManualApprovalQueue {
    pub fn new(auto_approve_limit: u64, max_queue_size: usize) -> Self {
        Self { auto_approve_limit, pending: Vec::new(), max_queue_size, persist_path: None }
    }

    /// Create with an optional persistence path. If set, queue auto-persists after mutations.
    pub fn with_persist_path(auto_approve_limit: u64, max_queue_size: usize, persist_path: Option<&std::path::Path>) -> Self {
        Self {
            auto_approve_limit,
            pending: Vec::new(),
            max_queue_size,
            persist_path: persist_path.map(|p| p.to_path_buf()),
        }
    }

    /// Returns true if the amount requires manual approval.
    pub fn requires_manual_approval(&self, amount: u64) -> bool {
        amount > self.auto_approve_limit
    }

    /// Submit a withdrawal for manual approval.
    pub fn submit(&mut self, id: [u8; 32], recipient: [u8; 32], amount: u64) -> Result<(), String> {
        if self.pending.len() >= self.max_queue_size {
            return Err("approval queue full".to_string());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.pending.push(PendingWithdrawal {
            id, recipient, amount, submitted_at: now, approvals: Vec::new(),
        });
        self.auto_persist();
        Ok(())
    }

    /// Add an approval from a committee member.
    pub fn approve(&mut self, withdrawal_id: &[u8; 32], member_id: &str) -> Result<(), String> {
        let entry = self.pending.iter_mut()
            .find(|p| &p.id == withdrawal_id)
            .ok_or_else(|| "withdrawal not found".to_string())?;
        if entry.approvals.contains(&member_id.to_string()) {
            return Err("duplicate approval".to_string());
        }
        entry.approvals.push(member_id.to_string());
        self.auto_persist();
        Ok(())
    }

    /// Check if a withdrawal has enough approvals.
    pub fn is_approved(&self, withdrawal_id: &[u8; 32], threshold: usize) -> bool {
        self.pending.iter()
            .find(|p| &p.id == withdrawal_id)
            .map(|p| p.approvals.len() >= threshold)
            .unwrap_or(false)
    }

    /// Remove a withdrawal from the queue (after execution or rejection).
    pub fn remove(&mut self, withdrawal_id: &[u8; 32]) -> Option<PendingWithdrawal> {
        if let Some(pos) = self.pending.iter().position(|p| &p.id == withdrawal_id) {
            Some(self.pending.remove(pos))
        } else {
            None
        }
    }

    pub fn pending_count(&self) -> usize { self.pending.len() }

    /// Auto-persist after mutations if persist_path is set.
    fn auto_persist(&self) {
        if let Some(ref path) = self.persist_path {
            if let Err(e) = self.persist_to_disk(path) {
                tracing::error!("ManualApprovalQueue persist failed: {}", e);
            }
        }
    }

    /// Persist pending approvals to disk (crash-safe: tmp + fsync + rename).
    pub fn persist_to_disk(&self, path: &std::path::Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(&self.pending)
            .map_err(|e| format!("serialize: {}", e))?;
        let tmp = path.with_extension("tmp");
        let file = std::fs::File::create(&tmp).map_err(|e| format!("create: {}", e))?;
        use std::io::Write;
        let mut writer = std::io::BufWriter::new(file);
        writer.write_all(json.as_bytes()).map_err(|e| format!("write: {}", e))?;
        writer.flush().map_err(|e| format!("flush: {}", e))?;
        writer.get_ref().sync_all().map_err(|e| format!("fsync: {}", e))?;
        drop(writer);
        std::fs::rename(&tmp, path).map_err(|e| format!("rename: {}", e))?;
        Ok(())
    }

    /// Load pending approvals from disk.
    pub fn load_from_disk(&mut self, path: &std::path::Path) -> Result<usize, String> {
        if !path.exists() { return Ok(0); }
        let json = std::fs::read_to_string(path).map_err(|e| format!("read: {}", e))?;
        let loaded: Vec<PendingWithdrawal> = serde_json::from_str(&json)
            .map_err(|e| format!("parse: {}", e))?;
        let count = loaded.len();
        self.pending = loaded;
        Ok(count)
    }
}

/// Bridge withdrawal nullifier set.
///
/// Prevents replay of withdrawal transactions.
/// Each withdrawal has a unique ID that is recorded after execution.
/// Must be persisted to disk for crash recovery.
pub struct WithdrawalNullifierSet {
    /// Executed withdrawal IDs.
    executed: std::collections::HashSet<[u8; 32]>,
    /// Path to persistence file (optional).
    persist_path: Option<String>,
}

impl WithdrawalNullifierSet {
    pub fn new(persist_path: Option<String>) -> Self {
        let mut set = Self {
            executed: std::collections::HashSet::new(),
            persist_path,
        };
        set.load_from_disk();
        set
    }

    /// Check if a withdrawal has already been executed.
    pub fn is_executed(&self, withdrawal_id: &[u8; 32]) -> bool {
        self.executed.contains(withdrawal_id)
    }

    /// Mark a withdrawal as executed.
    pub fn mark_executed(&mut self, withdrawal_id: [u8; 32]) -> Result<(), String> {
        if self.executed.contains(&withdrawal_id) {
            return Err(format!("withdrawal {} already executed", hex::encode(withdrawal_id)));
        }
        self.executed.insert(withdrawal_id);
        self.persist_to_disk();
        Ok(())
    }

    /// Load from disk (if persist_path is set).
    fn load_from_disk(&mut self) {
        let Some(path) = &self.persist_path else { return };
        let Ok(data) = std::fs::read(path) else { return };
        // Simple format: 32 bytes per entry
        for chunk in data.chunks_exact(32) {
            let mut id = [0u8; 32];
            id.copy_from_slice(chunk);
            self.executed.insert(id);
        }
    }

    /// Persist to disk (if persist_path is set).
    fn persist_to_disk(&self) {
        let Some(path) = &self.persist_path else { return };
        let mut data = Vec::with_capacity(self.executed.len() * 32);
        for id in &self.executed {
            data.extend_from_slice(id);
        }
        let _ = std::fs::write(path, &data);
    }

    pub fn count(&self) -> usize { self.executed.len() }
}

/// Fail-closed relayer configuration.
///
/// The relayer MUST stop processing if ANY safety check fails.
/// There is no "best effort" mode.
pub struct FailClosedRelayer {
    circuit_breaker: BridgeCircuitBreaker,
    rate_limiter: WithdrawalRateLimiter,
    nullifier_set: WithdrawalNullifierSet,
    approval_queue: ManualApprovalQueue,
}

impl FailClosedRelayer {
    pub fn new(
        committee_size: usize,
        per_address_limit: u64,
        global_limit: u64,
        auto_approve_limit: u64,
        nullifier_path: Option<String>,
    ) -> Self {
        let unpause_threshold = (committee_size * 2 + 2) / 3; // ceil(2/3)
        Self {
            circuit_breaker: BridgeCircuitBreaker::new(unpause_threshold),
            rate_limiter: WithdrawalRateLimiter::with_anomaly_pct(per_address_limit, global_limit, 50),
            nullifier_set: WithdrawalNullifierSet::new(nullifier_path),
            approval_queue: ManualApprovalQueue::new(auto_approve_limit, 1000),
        }
    }

    /// Process a withdrawal request through ALL safety checks.
    /// Any failure stops the entire pipeline (fail-closed).
    pub fn process_withdrawal(
        &mut self,
        withdrawal_id: [u8; 32],
        recipient: [u8; 32],
        amount: u64,
    ) -> Result<WithdrawalAction, String> {
        // 1. Circuit breaker
        self.circuit_breaker.check()?;

        // 2. Replay check
        if self.nullifier_set.is_executed(&withdrawal_id) {
            return Err(format!("withdrawal {} already executed (replay)", hex::encode(withdrawal_id)));
        }

        // 3. Rate limit (CRIT-3: auto-prunes expired windows)
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.rate_limiter.check_and_record(&hex::encode(recipient), amount, now_ms)
            .map_err(|e| format!("rate limit: {}", e))?;

        // 4. Manual approval check for large amounts
        if self.approval_queue.requires_manual_approval(amount) {
            self.approval_queue.submit(withdrawal_id, recipient, amount)?;
            return Ok(WithdrawalAction::QueuedForApproval);
        }

        // 5. Execute
        self.nullifier_set.mark_executed(withdrawal_id)?;

        Ok(WithdrawalAction::Execute)
    }

    /// Emergency pause the bridge.
    pub fn emergency_pause(&mut self, reason: &str) {
        self.circuit_breaker.pause(reason);
    }

    pub fn is_paused(&self) -> bool { self.circuit_breaker.is_paused() }
}

/// What to do with a withdrawal after safety checks.
#[derive(Debug, PartialEq)]
pub enum WithdrawalAction {
    /// Execute the withdrawal immediately.
    Execute,
    /// Queue for manual committee approval.
    QueuedForApproval,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Rate limiter tests ──────────────────────────────────────

    #[test]
    fn test_rate_limiter_allows_normal_withdrawal() {
        let mut rl = WithdrawalRateLimiter::new(1000, 5000);
        let now = 1_000_000u64;
        assert!(rl.check_and_record("alice", 500, now).is_ok());
        assert!(rl.check_and_record("bob", 500, now).is_ok());
    }

    #[test]
    fn test_rate_limiter_per_address_exceeded() {
        let mut rl = WithdrawalRateLimiter::new(1000, 5000);
        let now = 1_000_000u64;
        assert!(rl.check_and_record("alice", 800, now).is_ok());
        let err = rl.check_and_record("alice", 300, now);
        assert!(err.is_err());
        match err.unwrap_err() {
            RateLimitError::PerAddressLimitExceeded { remaining, .. } => {
                assert_eq!(remaining, 200);
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_rate_limiter_global_exceeded() {
        let mut rl = WithdrawalRateLimiter::new(5000, 1000);
        let now = 1_000_000u64;
        assert!(rl.check_and_record("alice", 400, now).is_ok());
        assert!(rl.check_and_record("bob", 400, now).is_ok());
        // Now try to exceed (800 + 300 > 1000)
        let err = rl.check_and_record("charlie", 300, now);
        assert!(err.is_err());
    }

    #[test]
    fn test_rate_limiter_anomaly_detection() {
        let mut rl = WithdrawalRateLimiter::new(10000, 10000);
        let now = 1_000_000u64;
        // >50% of global = anomaly
        let err = rl.check_and_record("whale", 6000, now);
        assert!(err.is_err());
        match err.unwrap_err() {
            RateLimitError::AnomalyDetected { .. } => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_rate_limiter_auto_reset_after_window() {
        // CRIT-3: Window auto-resets based on time — no manual reset needed
        let mut rl = WithdrawalRateLimiter::with_window(1000, 5000, 60); // 60-second window
        let t0 = 1_000_000u64; // ms
        assert!(rl.check_and_record("alice", 900, t0).is_ok());

        // Within same window → should fail
        let err = rl.check_and_record("alice", 200, t0 + 30_000); // 30s later
        assert!(err.is_err());

        // After window expires → auto-reset → should succeed
        let t1 = t0 + 61_000; // 61s later → window expired
        assert!(rl.check_and_record("alice", 900, t1).is_ok());
    }

    #[test]
    fn test_rate_limiter_manual_reset_still_works() {
        let mut rl = WithdrawalRateLimiter::new(1000, 5000);
        let now = 1_000_000u64;
        assert!(rl.check_and_record("alice", 900, now).is_ok());
        rl.reset_window();
        assert!(rl.check_and_record("alice", 900, now).is_ok());
    }

    // ── Threshold verifier tests ────────────────────────────────

    #[test]
    fn test_threshold_calculation() {
        // 3 members -> threshold = ceil(2/3 * 3) = 2
        let members = vec![
            ThresholdMember { id: "a".into(), public_key: vec![] },
            ThresholdMember { id: "b".into(), public_key: vec![] },
            ThresholdMember { id: "c".into(), public_key: vec![] },
        ];
        let v = ThresholdVerifier::new(members).expect("should create");
        assert_eq!(v.threshold(), 2);
        assert_eq!(v.total(), 3);
    }

    #[test]
    fn test_threshold_calculation_4_members() {
        // 4 members -> threshold = ceil(2/3 * 4) = ceil(2.67) = 3
        let members = vec![
            ThresholdMember { id: "a".into(), public_key: vec![] },
            ThresholdMember { id: "b".into(), public_key: vec![] },
            ThresholdMember { id: "c".into(), public_key: vec![] },
            ThresholdMember { id: "d".into(), public_key: vec![] },
        ];
        let v = ThresholdVerifier::new(members).expect("should create");
        // (2*4+2)/3 = 10/3 = 3
        assert_eq!(v.threshold(), 3);
    }

    #[test]
    fn test_insufficient_signatures() {
        let members = vec![
            ThresholdMember { id: "a".into(), public_key: vec![] },
            ThresholdMember { id: "b".into(), public_key: vec![] },
            ThresholdMember { id: "c".into(), public_key: vec![] },
        ];
        let v = ThresholdVerifier::new(members).expect("should create");
        let sigs: Vec<ThresholdSignature> = vec![ThresholdSignature {
            signer_id: "a".into(),
            signature: vec![],
        }];
        let err = v.verify(b"test", &sigs);
        assert!(err.is_err());
        match err.unwrap_err() {
            ThresholdError::InsufficientSignatures { got, need } => {
                assert_eq!(got, 1);
                assert_eq!(need, 2);
            }
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn test_duplicate_signer_detected() {
        let members = vec![
            ThresholdMember { id: "a".into(), public_key: vec![] },
            ThresholdMember { id: "b".into(), public_key: vec![] },
            ThresholdMember { id: "c".into(), public_key: vec![] },
        ];
        let v = ThresholdVerifier::new(members).expect("should create");
        let sigs = vec![
            ThresholdSignature { signer_id: "a".into(), signature: vec![] },
            ThresholdSignature { signer_id: "a".into(), signature: vec![] },
        ];
        let err = v.verify(b"test", &sigs);
        assert!(err.is_err());
        match err.unwrap_err() {
            ThresholdError::DuplicateSigner(id) => assert_eq!(id, "a"),
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn test_unknown_signer_rejected() {
        let members = vec![
            ThresholdMember { id: "a".into(), public_key: vec![] },
            ThresholdMember { id: "b".into(), public_key: vec![] },
            ThresholdMember { id: "c".into(), public_key: vec![] },
        ];
        let v = ThresholdVerifier::new(members).expect("should create");
        let sigs = vec![
            ThresholdSignature { signer_id: "x".into(), signature: vec![] },
            ThresholdSignature { signer_id: "y".into(), signature: vec![] },
        ];
        let err = v.verify(b"test", &sigs);
        assert!(err.is_err());
    }

    // ── BridgeCircuitBreaker tests ─────────────────────────────

    #[test]
    fn test_circuit_breaker_starts_unpaused() {
        let cb = BridgeCircuitBreaker::new(2);
        assert!(!cb.is_paused());
        assert!(cb.check().is_ok());
    }

    #[test]
    fn test_circuit_breaker_pause_and_check() {
        let mut cb = BridgeCircuitBreaker::new(2);
        cb.pause("suspicious activity");
        assert!(cb.is_paused());
        assert_eq!(cb.pause_reason(), Some("suspicious activity"));
        assert!(cb.check().is_err());
    }

    #[test]
    fn test_circuit_breaker_unpause_requires_threshold() {
        let mut cb = BridgeCircuitBreaker::new(3);
        cb.pause("test");
        assert!(cb.unpause(2).is_err()); // need 3
        assert!(cb.unpause(3).is_ok());
        assert!(!cb.is_paused());
    }

    #[test]
    fn test_circuit_breaker_unpause_when_not_paused() {
        let mut cb = BridgeCircuitBreaker::new(2);
        assert!(cb.unpause(2).is_err());
    }

    // ── ManualApprovalQueue tests ──────────────────────────────

    #[test]
    fn test_approval_queue_auto_approve_small() {
        let queue = ManualApprovalQueue::new(1000, 100);
        assert!(!queue.requires_manual_approval(500));
        assert!(queue.requires_manual_approval(1500));
    }

    #[test]
    fn test_approval_queue_submit_and_approve() {
        let mut queue = ManualApprovalQueue::new(1000, 100);
        let id = [0xAA; 32];
        let recipient = [0xBB; 32];
        assert!(queue.submit(id, recipient, 2000).is_ok());
        assert_eq!(queue.pending_count(), 1);

        assert!(queue.approve(&id, "member_a").is_ok());
        assert!(!queue.is_approved(&id, 2));
        assert!(queue.approve(&id, "member_b").is_ok());
        assert!(queue.is_approved(&id, 2));
    }

    #[test]
    fn test_approval_queue_duplicate_approval() {
        let mut queue = ManualApprovalQueue::new(1000, 100);
        let id = [0xAA; 32];
        queue.submit(id, [0xBB; 32], 2000).unwrap();
        assert!(queue.approve(&id, "member_a").is_ok());
        assert!(queue.approve(&id, "member_a").is_err()); // duplicate
    }

    #[test]
    fn test_approval_queue_max_size() {
        let mut queue = ManualApprovalQueue::new(1000, 2);
        let r = [0xBB; 32];
        assert!(queue.submit([1; 32], r, 2000).is_ok());
        assert!(queue.submit([2; 32], r, 2000).is_ok());
        assert!(queue.submit([3; 32], r, 2000).is_err()); // full
    }

    #[test]
    fn test_approval_queue_remove() {
        let mut queue = ManualApprovalQueue::new(1000, 100);
        let id = [0xAA; 32];
        queue.submit(id, [0xBB; 32], 2000).unwrap();
        assert_eq!(queue.pending_count(), 1);
        let removed = queue.remove(&id);
        assert!(removed.is_some());
        assert_eq!(queue.pending_count(), 0);
    }

    // ── WithdrawalNullifierSet tests ───────────────────────────

    #[test]
    fn test_nullifier_set_prevents_replay() {
        let mut ns = WithdrawalNullifierSet::new(None);
        let id = [0xCC; 32];
        assert!(!ns.is_executed(&id));
        assert!(ns.mark_executed(id).is_ok());
        assert!(ns.is_executed(&id));
        assert!(ns.mark_executed(id).is_err()); // replay
    }

    #[test]
    fn test_nullifier_set_count() {
        let mut ns = WithdrawalNullifierSet::new(None);
        assert_eq!(ns.count(), 0);
        ns.mark_executed([1; 32]).unwrap();
        ns.mark_executed([2; 32]).unwrap();
        assert_eq!(ns.count(), 2);
    }

    // ── FailClosedRelayer tests ────────────────────────────────

    #[test]
    fn test_relayer_normal_withdrawal() {
        let mut relayer = FailClosedRelayer::new(3, 10000, 100000, 5000, None);
        let result = relayer.process_withdrawal([1; 32], [0xAA; 32], 1000);
        assert_eq!(result.unwrap(), WithdrawalAction::Execute);
    }

    #[test]
    fn test_relayer_large_withdrawal_queued() {
        let mut relayer = FailClosedRelayer::new(3, 10000, 100000, 5000, None);
        let result = relayer.process_withdrawal([1; 32], [0xAA; 32], 6000);
        assert_eq!(result.unwrap(), WithdrawalAction::QueuedForApproval);
    }

    #[test]
    fn test_relayer_paused_rejects() {
        let mut relayer = FailClosedRelayer::new(3, 10000, 100000, 5000, None);
        relayer.emergency_pause("hack detected");
        assert!(relayer.is_paused());
        let result = relayer.process_withdrawal([1; 32], [0xAA; 32], 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_relayer_replay_rejected() {
        let mut relayer = FailClosedRelayer::new(3, 10000, 100000, 5000, None);
        let id = [0xFF; 32];
        assert!(relayer.process_withdrawal(id, [0xAA; 32], 100).is_ok());
        let result = relayer.process_withdrawal(id, [0xAA; 32], 100);
        assert!(result.is_err());
    }
}
