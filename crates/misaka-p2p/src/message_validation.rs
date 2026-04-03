//! P2P message validation — defense against malformed/malicious messages.
//!
//! Every message received from peers is validated before processing:
//! - Size limits prevent memory exhaustion
//! - Structure validation prevents parsing attacks
//! - Rate limiting per message type prevents flooding
//! - Nonce tracking prevents replay attacks

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Maximum size of any single P2P message.
pub const MAX_MESSAGE_SIZE: usize = 32 * 1024 * 1024; // 32 MB

/// Maximum block message size.
pub const MAX_BLOCK_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Maximum transaction message size.
pub const MAX_TX_MESSAGE_SIZE: usize = 1 * 1024 * 1024;

/// Maximum address list size.
pub const MAX_ADDR_COUNT: usize = 1000;

/// Maximum headers in a single message.
pub const MAX_HEADERS_COUNT: usize = 2000;

/// Maximum inv items per message.
pub const MAX_INV_COUNT: usize = 50_000;

/// Message type rate limits (max per minute).
pub fn message_rate_limits() -> HashMap<&'static str, u32> {
    let mut limits = HashMap::new();
    limits.insert("block", 120);
    limits.insert("tx", 5000);
    limits.insert("inv", 500);
    limits.insert("getblocks", 30);
    limits.insert("getheaders", 30);
    limits.insert("getdata", 200);
    limits.insert("addr", 10);
    limits.insert("ping", 60);
    limits.insert("version", 1);
    limits
}

/// Validate a raw message before deserialization.
pub fn validate_raw_message(msg_type: &str, payload: &[u8]) -> Result<(), MessageValidationError> {
    // 1. Global size limit
    if payload.len() > MAX_MESSAGE_SIZE {
        return Err(MessageValidationError::TooLarge {
            msg_type: msg_type.to_string(),
            size: payload.len(),
            max: MAX_MESSAGE_SIZE,
        });
    }

    // 2. Per-type size limits
    match msg_type {
        "block" | "blockwithtrustdata" => {
            if payload.len() > MAX_BLOCK_MESSAGE_SIZE {
                return Err(MessageValidationError::TooLarge {
                    msg_type: msg_type.to_string(),
                    size: payload.len(),
                    max: MAX_BLOCK_MESSAGE_SIZE,
                });
            }
        }
        "tx" | "transactionnotfound" => {
            if payload.len() > MAX_TX_MESSAGE_SIZE {
                return Err(MessageValidationError::TooLarge {
                    msg_type: msg_type.to_string(),
                    size: payload.len(),
                    max: MAX_TX_MESSAGE_SIZE,
                });
            }
        }
        _ => {}
    }

    // 3. Minimum size check (prevent empty messages for types that need data)
    match msg_type {
        "block" | "tx" | "version" if payload.is_empty() => {
            return Err(MessageValidationError::EmptyPayload(msg_type.to_string()));
        }
        _ => {}
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
//  D1: Per-peer byte bandwidth limit (Red Team audit fix)
//
//  Message rate limits (count/min) alone are insufficient:
//  10 peers × 100 msg/sec × 1 MB = 1 GB/sec bandwidth attack.
//  This adds a per-peer bytes/sec sliding-window enforcer.
// ═══════════════════════════════════════════════════════════════

/// Maximum bytes per peer per second (10 MB/s default).
/// At 10 MB/s per peer × 48 inbound = 480 MB/s theoretical max —
/// well above normal operation (~1 MB/s) but prevents single-peer
/// bandwidth exhaustion attacks.
pub const MAX_BYTES_PER_PEER_PER_SEC: usize = 10 * 1024 * 1024; // 10 MB/s

/// Bandwidth tracking window (seconds).
const BANDWIDTH_WINDOW_SECS: u64 = 10;

/// Per-peer bandwidth tracker.
/// Uses a sliding-window approach: track cumulative bytes received in
/// the current window. If exceeded, reject until window rotates.
pub struct PeerBandwidthTracker {
    /// (window_start, bytes_in_window)
    window_start: Instant,
    bytes_in_window: usize,
    /// Per-second limit.
    limit_bytes_per_sec: usize,
}

impl PeerBandwidthTracker {
    pub fn new() -> Self {
        Self::with_limit(MAX_BYTES_PER_PEER_PER_SEC)
    }

    pub fn with_limit(limit_bytes_per_sec: usize) -> Self {
        Self {
            window_start: Instant::now(),
            bytes_in_window: 0,
            limit_bytes_per_sec,
        }
    }

    /// Record incoming bytes and check if bandwidth limit is exceeded.
    ///
    /// Returns `Ok(())` if within budget, `Err(BandwidthExceeded)` if not.
    pub fn record_bytes(&mut self, payload_len: usize) -> Result<(), BandwidthExceeded> {
        let now = Instant::now();
        let elapsed = now.duration_since(self.window_start);

        // Reset window if expired
        if elapsed.as_secs() >= BANDWIDTH_WINDOW_SECS {
            self.window_start = now;
            self.bytes_in_window = 0;
        }

        let window_budget = self.limit_bytes_per_sec
            .saturating_mul(BANDWIDTH_WINDOW_SECS as usize);

        self.bytes_in_window = self.bytes_in_window.saturating_add(payload_len);

        if self.bytes_in_window > window_budget {
            Err(BandwidthExceeded {
                bytes_in_window: self.bytes_in_window,
                window_budget,
                window_secs: BANDWIDTH_WINDOW_SECS,
            })
        } else {
            Ok(())
        }
    }

    /// Current bytes consumed in the active window.
    pub fn current_usage(&self) -> usize {
        self.bytes_in_window
    }
}

impl Default for PeerBandwidthTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Bandwidth limit exceeded error.
#[derive(Debug)]
pub struct BandwidthExceeded {
    pub bytes_in_window: usize,
    pub window_budget: usize,
    pub window_secs: u64,
}

impl std::fmt::Display for BandwidthExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "bandwidth exceeded: {} bytes in {}s window (budget: {} bytes)",
            self.bytes_in_window, self.window_secs, self.window_budget
        )
    }
}

/// Per-peer message rate tracker.
pub struct MessageRateTracker {
    counters: HashMap<String, Vec<Instant>>,
    limits: HashMap<String, u32>,
    window: Duration,
    /// D1: Per-peer byte bandwidth tracker.
    pub bandwidth: PeerBandwidthTracker,
}

impl MessageRateTracker {
    pub fn new() -> Self {
        Self {
            counters: HashMap::new(),
            limits: message_rate_limits()
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            window: Duration::from_secs(60),
            bandwidth: PeerBandwidthTracker::new(),
        }
    }

    /// Record a message and check BOTH rate limit AND bandwidth limit.
    ///
    /// Call this with the raw payload size BEFORE deserialization.
    pub fn check_rate_and_bandwidth(
        &mut self,
        msg_type: &str,
        payload_len: usize,
    ) -> RateCheckResult {
        // D1: Bandwidth check first (cheapest — no HashMap lookup)
        if let Err(e) = self.bandwidth.record_bytes(payload_len) {
            return RateCheckResult::BandwidthExceeded {
                msg_type: msg_type.to_string(),
                bytes_in_window: e.bytes_in_window,
                budget: e.window_budget,
            };
        }

        // Then message-count rate check
        self.check_rate(msg_type)
    }

    /// Record a message and check if rate limit is exceeded (count only).
    pub fn check_rate(&mut self, msg_type: &str) -> RateCheckResult {
        let limit = self.limits.get(msg_type).copied().unwrap_or(300);
        let now = Instant::now();
        let cutoff = now - self.window;

        let timestamps = self.counters.entry(msg_type.to_string()).or_default();
        timestamps.retain(|t| *t > cutoff);

        if timestamps.len() >= limit as usize {
            RateCheckResult::Exceeded {
                msg_type: msg_type.to_string(),
                count: timestamps.len(),
                limit: limit as usize,
            }
        } else {
            timestamps.push(now);
            RateCheckResult::Ok
        }
    }

    /// Cleanup old entries.
    pub fn cleanup(&mut self) {
        let cutoff = Instant::now() - self.window;
        self.counters.retain(|_, v| {
            v.retain(|t| *t > cutoff);
            !v.is_empty()
        });
    }
}

impl Default for MessageRateTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Nonce tracking for replay prevention.
pub struct NonceTracker {
    seen: HashMap<[u8; 16], Instant>,
    max_age: Duration,
    max_entries: usize,
}

impl NonceTracker {
    pub fn new(max_age: Duration, max_entries: usize) -> Self {
        Self {
            seen: HashMap::new(),
            max_age,
            max_entries,
        }
    }

    /// Check if a nonce has been seen before.
    pub fn check_and_record(&mut self, nonce: [u8; 16]) -> bool {
        let now = Instant::now();

        // Cleanup old entries
        if self.seen.len() >= self.max_entries {
            let cutoff = now - self.max_age;
            self.seen.retain(|_, t| *t > cutoff);
        }

        if self.seen.contains_key(&nonce) {
            false // Replay detected
        } else {
            self.seen.insert(nonce, now);
            true // New nonce
        }
    }

    pub fn seen_count(&self) -> usize {
        self.seen.len()
    }
}

/// Handshake validation.
pub struct HandshakeValidator {
    pub min_protocol_version: u32,
    pub max_protocol_version: u32,
    pub required_services: u64,
    pub network_id: [u8; 4],
}

impl HandshakeValidator {
    pub fn validate_version_message(
        &self,
        protocol_version: u32,
        services: u64,
        network_id: [u8; 4],
        user_agent: &str,
    ) -> Result<(), HandshakeError> {
        if protocol_version < self.min_protocol_version {
            return Err(HandshakeError::ProtocolTooOld {
                got: protocol_version,
                min: self.min_protocol_version,
            });
        }
        if protocol_version > self.max_protocol_version {
            return Err(HandshakeError::ProtocolTooNew {
                got: protocol_version,
                max: self.max_protocol_version,
            });
        }
        if network_id != self.network_id {
            return Err(HandshakeError::WrongNetwork {
                got: hex::encode(network_id),
                expected: hex::encode(self.network_id),
            });
        }
        if services & self.required_services != self.required_services {
            return Err(HandshakeError::MissingServices {
                got: services,
                required: self.required_services,
            });
        }
        if user_agent.len() > 256 {
            return Err(HandshakeError::UserAgentTooLong(user_agent.len()));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum RateCheckResult {
    Ok,
    /// Message count rate limit exceeded.
    Exceeded {
        msg_type: String,
        count: usize,
        limit: usize,
    },
    /// D1: Per-peer byte bandwidth limit exceeded.
    BandwidthExceeded {
        msg_type: String,
        bytes_in_window: usize,
        budget: usize,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum MessageValidationError {
    #[error("{msg_type} too large: {size} > {max}")]
    TooLarge {
        msg_type: String,
        size: usize,
        max: usize,
    },
    #[error("empty payload for {0}")]
    EmptyPayload(String),
    #[error("malformed message: {0}")]
    Malformed(String),
    #[error("unknown message type: {0}")]
    UnknownType(String),
}

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("protocol too old: {got} < {min}")]
    ProtocolTooOld { got: u32, min: u32 },
    #[error("protocol too new: {got} > {max}")]
    ProtocolTooNew { got: u32, max: u32 },
    #[error("wrong network: got {got}, expected {expected}")]
    WrongNetwork { got: String, expected: String },
    #[error("missing services: got {got:#x}, required {required:#x}")]
    MissingServices { got: u64, required: u64 },
    #[error("user agent too long: {0}")]
    UserAgentTooLong(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bandwidth_tracker_allows_within_budget() {
        let mut bt = PeerBandwidthTracker::with_limit(1_000_000); // 1 MB/s
        // 10-second window → 10 MB budget
        assert!(bt.record_bytes(5_000_000).is_ok()); // 5 MB OK
        assert!(bt.record_bytes(4_000_000).is_ok()); // 9 MB OK
    }

    #[test]
    fn test_bandwidth_tracker_rejects_over_budget() {
        let mut bt = PeerBandwidthTracker::with_limit(1_000_000); // 1 MB/s
        // 10-second window → 10 MB budget
        assert!(bt.record_bytes(10_000_000).is_ok()); // 10 MB exactly OK
        assert!(bt.record_bytes(1).is_err()); // 10 MB + 1 → over budget
    }

    #[test]
    fn test_bandwidth_tracker_saturating_add() {
        let mut bt = PeerBandwidthTracker::with_limit(100);
        // Should not panic on enormous values
        assert!(bt.record_bytes(usize::MAX / 2).is_err());
    }

    #[test]
    fn test_rate_and_bandwidth_combined() {
        // Use a tracker with a small bandwidth limit to test the combined path
        let mut tracker = MessageRateTracker::new();
        // Override bandwidth with tight limit: 1 MB/s × 10s window = 10 MB budget
        tracker.bandwidth = PeerBandwidthTracker::with_limit(1_000_000);

        // Send 9 × 1 MB messages — within both rate and bandwidth
        for _ in 0..9 {
            let result = tracker.check_rate_and_bandwidth("tx", 1_000_000);
            assert!(matches!(result, RateCheckResult::Ok));
        }

        // 10th MB message pushes over 10 MB budget → bandwidth exceeded
        let result = tracker.check_rate_and_bandwidth("tx", 2_000_000);
        assert!(matches!(result, RateCheckResult::BandwidthExceeded { .. }));
    }

    #[test]
    fn test_validate_raw_message_sizes() {
        // Normal TX
        assert!(validate_raw_message("tx", &[0u8; 1000]).is_ok());
        // Oversized TX
        assert!(validate_raw_message("tx", &[0u8; MAX_TX_MESSAGE_SIZE + 1]).is_err());
        // Oversized block
        assert!(validate_raw_message("block", &[0u8; MAX_BLOCK_MESSAGE_SIZE + 1]).is_err());
        // Empty block
        assert!(validate_raw_message("block", &[]).is_err());
    }

    #[test]
    fn test_rate_limit_exceeded() {
        let mut tracker = MessageRateTracker::new();
        // version: limit 1/min
        assert!(matches!(tracker.check_rate("version"), RateCheckResult::Ok));
        assert!(matches!(tracker.check_rate("version"), RateCheckResult::Exceeded { .. }));
    }

    #[test]
    fn test_nonce_tracker_replay_prevention() {
        let mut nt = NonceTracker::new(Duration::from_secs(60), 1000);
        let nonce = [0xAA; 16];
        assert!(nt.check_and_record(nonce)); // first time: OK
        assert!(!nt.check_and_record(nonce)); // replay: rejected
    }
}
