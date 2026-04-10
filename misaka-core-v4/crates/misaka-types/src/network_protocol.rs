// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Network protocol types — Mochimo-inspired packet validation.
//!
//! Mochimo enforces 4-layer packet validation:
//! 1. CRC16 checksum
//! 2. Protocol version check
//! 3. Trailer magic check
//! 4. Handshake ID binding
//!
//! This module provides equivalent validation for MISAKA's P2P protocol.

use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════
//  Protocol constants
// ═══════════════════════════════════════════════════════════

/// Protocol magic bytes.
pub const PROTOCOL_MAGIC: u32 = 0x4D534B41; // "MSKA"

/// Current protocol version.
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum message payload size (1 MB).
pub const MAX_PAYLOAD_SIZE: u32 = 1_048_576;

/// Minimum message size (header only).
pub const MIN_MESSAGE_SIZE: usize = 24; // header

/// End-of-transmission marker (Mochimo: 0xABCD).
pub const EOT_MARKER: u16 = 0xABCD;

// ═══════════════════════════════════════════════════════════
//  Message header
// ═══════════════════════════════════════════════════════════

/// P2P message header — validated before any payload processing.
///
/// Mochimo-inspired 4-layer validation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageHeader {
    /// Protocol magic (must be PROTOCOL_MAGIC).
    pub magic: u32,
    /// Protocol version (must match PROTOCOL_VERSION).
    pub version: u16,
    /// Sender handshake ID (bound at connection time).
    pub sender_id: u16,
    /// Receiver handshake ID.
    pub receiver_id: u16,
    /// Operation code.
    pub opcode: u16,
    /// Payload length in bytes.
    pub payload_len: u32,
    /// CRC16 of the payload.
    pub payload_crc16: u16,
    /// End-of-transmission marker.
    pub eot: u16,
}

impl MessageHeader {
    /// Validate the header (layers 1-4).
    pub fn validate(&self, expected_sender_id: u16) -> Result<(), PacketError> {
        // Layer 1: Magic
        if self.magic != PROTOCOL_MAGIC {
            return Err(PacketError::InvalidMagic(self.magic));
        }
        // Layer 2: Version
        if self.version != PROTOCOL_VERSION {
            return Err(PacketError::VersionMismatch {
                got: self.version,
                expected: PROTOCOL_VERSION,
            });
        }
        // Layer 3: EOT marker
        if self.eot != EOT_MARKER {
            return Err(PacketError::InvalidEot(self.eot));
        }
        // Layer 4: Handshake ID (skip for hello/hello_ack)
        if self.opcode >= OpCode::SubmitTx as u16 {
            if self.sender_id != expected_sender_id {
                return Err(PacketError::HandshakeIdMismatch {
                    got: self.sender_id,
                    expected: expected_sender_id,
                });
            }
        }
        // Payload size check
        if self.payload_len > MAX_PAYLOAD_SIZE {
            return Err(PacketError::PayloadTooLarge(self.payload_len));
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════
//  Operation codes
// ═══════════════════════════════════════════════════════════

/// P2P operation codes.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OpCode {
    /// Connection handshake.
    Hello = 0,
    /// Handshake acknowledgment.
    HelloAck = 1,
    /// Ping/keepalive.
    Ping = 2,
    /// Submit a transaction (first opcode requiring authenticated handshake).
    SubmitTx = 3,
    /// Announce a new block.
    AnnounceBlock = 4,
    /// Request block by hash.
    GetBlock = 5,
    /// Response with block data.
    BlockData = 6,
    /// Request blocks since round.
    GetBlocksSince = 7,
    /// Request peer list.
    GetPeers = 8,
    /// Peer list response.
    PeerList = 9,
    /// Balance query.
    GetBalance = 10,
    /// Balance response.
    BalanceData = 11,
    /// Consensus block (Narwhal).
    ConsensusBlock = 12,
    /// Commit sync request.
    GetCommits = 13,
    /// Commit data response.
    CommitData = 14,
    /// Block subscription request.
    Subscribe = 15,
}

// ═══════════════════════════════════════════════════════════
//  Packet errors
// ═══════════════════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum PacketError {
    #[error("invalid magic: 0x{0:08X}")]
    InvalidMagic(u32),
    #[error("protocol version mismatch: got {got}, expected {expected}")]
    VersionMismatch { got: u16, expected: u16 },
    #[error("invalid EOT marker: 0x{0:04X}")]
    InvalidEot(u16),
    #[error("handshake ID mismatch: got {got}, expected {expected}")]
    HandshakeIdMismatch { got: u16, expected: u16 },
    #[error("payload too large: {0} bytes")]
    PayloadTooLarge(u32),
    #[error("CRC16 mismatch: got 0x{got:04X}, expected 0x{expected:04X}")]
    Crc16Mismatch { got: u16, expected: u16 },
    #[error("unknown opcode: {0}")]
    UnknownOpcode(u16),
}

// ═══════════════════════════════════════════════════════════
//  CRC16 (CCITT)
// ═══════════════════════════════════════════════════════════

/// Compute CRC16-CCITT over a byte slice.
///
/// Mochimo uses CRC16 for packet integrity.
pub fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Validate CRC16 of a payload against expected value.
pub fn validate_crc16(payload: &[u8], expected: u16) -> Result<(), PacketError> {
    let computed = crc16_ccitt(payload);
    if computed != expected {
        return Err(PacketError::Crc16Mismatch {
            got: computed,
            expected,
        });
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════
//  Peer reputation (Mochimo-inspired)
// ═══════════════════════════════════════════════════════════

/// Peer reputation score for ban/unban decisions.
///
/// Mochimo uses escalating "pink lists":
/// - Minor infractions → ephemeral ban (in-memory)
/// - Repeated/severe → persistent ban (on-disk)
#[derive(Clone, Debug)]
pub struct PeerReputation {
    /// Total good interactions.
    pub good: u64,
    /// Total bad interactions.
    pub bad: u64,
    /// Consecutive bad interactions.
    pub consecutive_bad: u32,
    /// Whether this peer is banned.
    pub banned: bool,
    /// Ban expiry (epoch). 0 = permanent.
    pub ban_until_epoch: u64,
}

/// Threshold for ephemeral ban (consecutive bad).
pub const EPHEMERAL_BAN_THRESHOLD: u32 = 5;

/// Threshold for persistent ban (total bad).
pub const PERSISTENT_BAN_THRESHOLD: u64 = 20;

impl PeerReputation {
    pub fn new() -> Self {
        Self {
            good: 0,
            bad: 0,
            consecutive_bad: 0,
            banned: false,
            ban_until_epoch: 0,
        }
    }

    /// Record a good interaction.
    pub fn record_good(&mut self) {
        self.good += 1;
        self.consecutive_bad = 0;
    }

    /// Record a bad interaction. Returns true if peer should be banned.
    pub fn record_bad(&mut self) -> bool {
        self.bad += 1;
        self.consecutive_bad += 1;

        if self.consecutive_bad >= EPHEMERAL_BAN_THRESHOLD {
            self.banned = true;
            return true;
        }
        if self.bad >= PERSISTENT_BAN_THRESHOLD {
            self.banned = true;
            return true;
        }
        false
    }

    /// Quality score (0.0 = terrible, 1.0 = perfect).
    pub fn quality(&self) -> f64 {
        let total = self.good + self.bad;
        if total == 0 {
            return 0.5;
        }
        self.good as f64 / total as f64
    }

    /// Check if the peer is currently banned.
    pub fn is_banned(&self, current_epoch: u64) -> bool {
        self.banned && (self.ban_until_epoch == 0 || current_epoch < self.ban_until_epoch)
    }

    /// Unban the peer.
    pub fn unban(&mut self) {
        self.banned = false;
        self.ban_until_epoch = 0;
        self.consecutive_bad = 0;
    }
}

// ═══════════════════════════════════════════════════════════
//  Sync / Recovery types (Mochimo-inspired)
// ═══════════════════════════════════════════════════════════

/// Sync state for a node.
///
/// Mochimo's sync.c tracks chain state and recovery progress.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncState {
    /// Our current block height / round.
    pub current_height: u64,
    /// Our current block hash.
    pub current_hash: [u8; 32],
    /// Cumulative weight (Mochimo: from trailer file).
    pub cumulative_weight: u64,
    /// Sync target height (from best peer).
    pub target_height: u64,
    /// Number of blocks downloaded.
    pub blocks_downloaded: u64,
    /// Number of blocks validated.
    pub blocks_validated: u64,
    /// Number of blocks failed validation.
    pub blocks_failed: u64,
    /// Whether we are in catchup mode.
    pub is_catching_up: bool,
}

impl SyncState {
    pub fn new() -> Self {
        Self {
            current_height: 0,
            current_hash: [0; 32],
            cumulative_weight: 0,
            target_height: 0,
            blocks_downloaded: 0,
            blocks_validated: 0,
            blocks_failed: 0,
            is_catching_up: false,
        }
    }

    /// Sync progress as percentage.
    pub fn progress_percent(&self) -> f64 {
        if self.target_height == 0 {
            return 100.0;
        }
        (self.current_height as f64 / self.target_height as f64 * 100.0).min(100.0)
    }

    /// Whether sync is complete.
    pub fn is_synced(&self) -> bool {
        self.current_height >= self.target_height
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_validation_valid() {
        let h = MessageHeader {
            magic: PROTOCOL_MAGIC,
            version: PROTOCOL_VERSION,
            sender_id: 42,
            receiver_id: 0,
            opcode: OpCode::Ping as u16,
            payload_len: 0,
            payload_crc16: 0,
            eot: EOT_MARKER,
        };
        assert!(h.validate(42).is_ok());
    }

    #[test]
    fn test_header_invalid_magic() {
        let h = MessageHeader {
            magic: 0xDEADBEEF,
            version: PROTOCOL_VERSION,
            sender_id: 0,
            receiver_id: 0,
            opcode: 0,
            payload_len: 0,
            payload_crc16: 0,
            eot: EOT_MARKER,
        };
        assert!(matches!(h.validate(0), Err(PacketError::InvalidMagic(_))));
    }

    #[test]
    fn test_header_version_mismatch() {
        let h = MessageHeader {
            magic: PROTOCOL_MAGIC,
            version: 99,
            sender_id: 0,
            receiver_id: 0,
            opcode: 0,
            payload_len: 0,
            payload_crc16: 0,
            eot: EOT_MARKER,
        };
        assert!(matches!(
            h.validate(0),
            Err(PacketError::VersionMismatch { .. })
        ));
    }

    #[test]
    fn test_header_invalid_eot() {
        let h = MessageHeader {
            magic: PROTOCOL_MAGIC,
            version: PROTOCOL_VERSION,
            sender_id: 0,
            receiver_id: 0,
            opcode: 0,
            payload_len: 0,
            payload_crc16: 0,
            eot: 0x0000,
        };
        assert!(matches!(h.validate(0), Err(PacketError::InvalidEot(_))));
    }

    #[test]
    fn test_header_handshake_mismatch() {
        let h = MessageHeader {
            magic: PROTOCOL_MAGIC,
            version: PROTOCOL_VERSION,
            sender_id: 99, // wrong
            receiver_id: 0,
            opcode: OpCode::SubmitTx as u16, // authenticated
            payload_len: 0,
            payload_crc16: 0,
            eot: EOT_MARKER,
        };
        assert!(matches!(
            h.validate(42),
            Err(PacketError::HandshakeIdMismatch { .. })
        ));
    }

    #[test]
    fn test_crc16() {
        let data = b"Hello, MISAKA!";
        let crc = crc16_ccitt(data);
        assert!(validate_crc16(data, crc).is_ok());
        assert!(validate_crc16(data, crc + 1).is_err());
    }

    #[test]
    fn test_peer_reputation_escalation() {
        let mut rep = PeerReputation::new();
        for _ in 0..4 {
            assert!(!rep.record_bad()); // not yet banned
        }
        assert!(rep.record_bad()); // 5th bad → banned
        assert!(rep.is_banned(0));
    }

    #[test]
    fn test_peer_reputation_good_resets() {
        let mut rep = PeerReputation::new();
        rep.record_bad();
        rep.record_bad();
        rep.record_good(); // resets consecutive
        assert_eq!(rep.consecutive_bad, 0);
        assert!(!rep.is_banned(0));
    }

    #[test]
    fn test_sync_state_progress() {
        let mut state = SyncState::new();
        state.current_height = 50;
        state.target_height = 100;
        assert!((state.progress_percent() - 50.0).abs() < 0.01);
        assert!(!state.is_synced());

        state.current_height = 100;
        assert!(state.is_synced());
    }
}
