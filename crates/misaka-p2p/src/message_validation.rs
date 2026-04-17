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

/// Maximum inv items per message.
///
/// SEC-FIX M-17: Reduced from 50,000 to 5,000 to limit memory amplification.
/// With ~100 nodes each sending max INV messages, 50K items * 32 bytes * 100 peers
/// = ~160 MB per broadcast cycle — excessive for a 100-node network.
/// 5,000 items per message is sufficient for normal operation.
pub const MAX_INV_COUNT: usize = 5_000;

/// Message type rate limits (max per minute).
///
/// R4-M2 FIX: Keys must match the `Debug` output of `MisakaPayloadType`
/// (e.g. `"Addresses"` not `"addr"`), since `router.rs` uses
/// `format!("{:?}", msg_type)` as the rate-limit key.
pub fn message_rate_limits() -> HashMap<&'static str, u32> {
    let mut limits = HashMap::new();
    limits.insert("RelayBlock", 120);
    limits.insert("Transaction", 5000);
    limits.insert("InvRelayBlock", 500);
    limits.insert("InvTransactions", 500);
    limits.insert("RequestRelayBlocks", 30);
    limits.insert("RequestHeaders", 30);
    limits.insert("RequestTransactions", 200);
    limits.insert("Addresses", 10);
    limits.insert("RequestAddresses", 10);
    limits.insert("Ping", 60);
    limits.insert("Hello", 1);
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

/// Per-peer message rate tracker.
pub struct MessageRateTracker {
    counters: HashMap<String, Vec<Instant>>,
    limits: HashMap<String, u32>,
    window: Duration,
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
        }
    }

    /// Record a message and check if rate limit is exceeded.
    pub fn check_rate(&mut self, msg_type: &str) -> RateCheckResult {
        // R7 L-5: Conservative default for unknown message types (was 300)
        let limit = self.limits.get(msg_type).copied().unwrap_or(60);
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
        // R7 M-4: Hard cap — if retain didn't free enough, evict oldest
        while self.seen.len() >= self.max_entries {
            let oldest_key = self.seen.iter().min_by_key(|(_, t)| *t).map(|(k, _)| *k);
            if let Some(k) = oldest_key {
                self.seen.remove(&k);
            } else {
                break;
            }
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
    Exceeded {
        msg_type: String,
        count: usize,
        limit: usize,
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
