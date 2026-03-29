//! DAG P2P Wire Protocol — Binary message format for block/TX distribution.
//!
//! # Message Types
//!
//! | ID | Name              | Direction  | Purpose                          |
//! |----|-------------------|------------|----------------------------------|
//! | 01 | GetTips           | Req        | Request current DAG tips         |
//! | 02 | Tips              | Resp       | Reply with tip hashes            |
//! | 03 | GetBlocks         | Req        | Request blocks by hash           |
//! | 04 | Block             | Push/Resp  | Full DAG block with TXs          |
//! | 05 | NewBlock          | Push       | Announce new block (header only) |
//! | 06 | GetBlockTxs       | Req        | Request TXs for a block hash     |
//! | 07 | BlockTxs          | Resp       | Full TX list for a block         |
//! | 08 | NewTx             | Push       | Announce new confidential TX     |
//! | 09 | GetNullifierStatus| Req        | Check if nullifiers are spent    |
//! | 0A | NullifierStatus   | Resp       | Spent/unspent for each nullifier |
//!
//! # Wire Format
//!
//! ```text
//! Message:
//!   magic:    [4] "MSKD"
//!   version:  [1] 0x01
//!   msg_type: [1] message ID
//!   length:   [4] LE u32 payload length
//!   payload:  [length] message-specific data
//!   checksum: [4] first 4 bytes of SHA3-256(payload)
//! ```
//!
//! # DoS Protection
//!
//! - Maximum message size: 4 MB
//! - Maximum hashes per request: 256
//! - Rate limiting is handled by the transport layer (see dag_p2p.rs)

use crate::dag_block::{DagBlockHeader, Hash, ZERO_HASH};
use sha3::{Digest, Sha3_256};

// ═══════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════

/// Protocol magic bytes.
pub const MAGIC: [u8; 4] = [0x4D, 0x53, 0x4B, 0x44]; // "MSKD"
/// Wire protocol version.
pub const WIRE_VERSION: u8 = 0x01;
/// Maximum payload size (4 MB).
pub const MAX_PAYLOAD_SIZE: u32 = 4 * 1024 * 1024;
/// Maximum hashes per GetBlocks request.
pub const MAX_HASHES_PER_REQ: usize = 256;
/// Message header size: magic(4) + version(1) + type(1) + length(4) = 10.
pub const HEADER_SIZE: usize = 10;
/// Checksum size: 4 bytes.
pub const CHECKSUM_SIZE: usize = 4;

// ═══════════════════════════════════════════════════════════════
//  Message Types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WireMessageType {
    GetTips = 0x01,
    Tips = 0x02,
    GetBlocks = 0x03,
    Block = 0x04,
    NewBlock = 0x05,
    GetBlockTxs = 0x06,
    BlockTxs = 0x07,
    NewTx = 0x08,
    GetNullifierStatus = 0x09,
    NullifierStatus = 0x0A,
}

impl WireMessageType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::GetTips),
            0x02 => Some(Self::Tips),
            0x03 => Some(Self::GetBlocks),
            0x04 => Some(Self::Block),
            0x05 => Some(Self::NewBlock),
            0x06 => Some(Self::GetBlockTxs),
            0x07 => Some(Self::BlockTxs),
            0x08 => Some(Self::NewTx),
            0x09 => Some(Self::GetNullifierStatus),
            0x0A => Some(Self::NullifierStatus),
            _ => None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Wire Message
// ═══════════════════════════════════════════════════════════════

/// A framed wire message with header + payload + checksum.
#[derive(Debug, Clone)]
pub struct WireMessage {
    pub msg_type: WireMessageType,
    pub payload: Vec<u8>,
}

impl WireMessage {
    /// Serialize to wire format.
    pub fn encode(&self) -> Vec<u8> {
        // Guard: payload must fit in u32 length field
        let payload_len = self.payload.len();
        let len = if payload_len > u32::MAX as usize {
            tracing::error!("wire payload exceeds u32::MAX ({} bytes), truncating length field", payload_len);
            u32::MAX
        } else {
            payload_len as u32
        };
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.payload.len() + CHECKSUM_SIZE);

        // Header
        buf.extend_from_slice(&MAGIC);
        buf.push(WIRE_VERSION);
        buf.push(self.msg_type as u8);
        buf.extend_from_slice(&len.to_le_bytes());

        // Payload
        buf.extend_from_slice(&self.payload);

        // Checksum: first 4 bytes of SHA3-256(payload)
        let hash = Sha3_256::digest(&self.payload);
        buf.extend_from_slice(&hash[..CHECKSUM_SIZE]);

        buf
    }

    /// Deserialize from wire format.
    pub fn decode(data: &[u8]) -> Result<Self, WireError> {
        if data.len() < HEADER_SIZE + CHECKSUM_SIZE {
            return Err(WireError::TooShort);
        }

        // Magic
        if data[..4] != MAGIC {
            return Err(WireError::BadMagic);
        }

        // Version
        if data[4] != WIRE_VERSION {
            return Err(WireError::UnsupportedVersion(data[4]));
        }

        // Type
        let msg_type =
            WireMessageType::from_u8(data[5]).ok_or(WireError::UnknownMessageType(data[5]))?;

        // Length
        let len = u32::from_le_bytes([data[6], data[7], data[8], data[9]]);
        if len > MAX_PAYLOAD_SIZE {
            return Err(WireError::PayloadTooLarge(len));
        }

        let total_expected = HEADER_SIZE + len as usize + CHECKSUM_SIZE;
        if data.len() < total_expected {
            return Err(WireError::TooShort);
        }

        // Payload
        let payload = data[HEADER_SIZE..HEADER_SIZE + len as usize].to_vec();

        // Checksum
        let hash = Sha3_256::digest(&payload);
        let expected_checksum = &hash[..CHECKSUM_SIZE];
        let actual_checksum = &data[HEADER_SIZE + len as usize..total_expected];
        if expected_checksum != actual_checksum {
            return Err(WireError::ChecksumMismatch);
        }

        Ok(Self { msg_type, payload })
    }
}

// ═══════════════════════════════════════════════════════════════
//  Payload Builders
// ═══════════════════════════════════════════════════════════════

/// Encode a list of hashes as payload.
pub fn encode_hash_list(hashes: &[Hash]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + hashes.len() * 32);
    buf.extend_from_slice(&(hashes.len() as u32).to_le_bytes());
    for h in hashes {
        buf.extend_from_slice(h);
    }
    buf
}

/// Decode a list of hashes from payload.
pub fn decode_hash_list(data: &[u8]) -> Result<Vec<Hash>, WireError> {
    if data.len() < 4 {
        return Err(WireError::TooShort);
    }
    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if count > MAX_HASHES_PER_REQ {
        return Err(WireError::TooManyHashes(count));
    }
    if data.len() != 4 + count * 32 {
        return Err(WireError::TooShort);
    }
    let mut hashes = Vec::with_capacity(count);
    for i in 0..count {
        let mut h = [0u8; 32];
        h.copy_from_slice(&data[4 + i * 32..4 + (i + 1) * 32]);
        hashes.push(h);
    }
    Ok(hashes)
}

/// Encode a block header announcement (NewBlock).
pub fn encode_new_block(header: &DagBlockHeader, block_hash: &Hash) -> Vec<u8> {
    let header_json = serde_json::to_vec(header).unwrap_or_default();
    let mut buf = Vec::with_capacity(32 + 4 + header_json.len());
    buf.extend_from_slice(block_hash);
    buf.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
    buf.extend_from_slice(&header_json);
    buf
}

/// Encode nullifier status response.
pub fn encode_nullifier_status(statuses: &[([u8; 32], bool)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + statuses.len() * 33);
    buf.extend_from_slice(&(statuses.len() as u32).to_le_bytes());
    for (null, spent) in statuses {
        buf.extend_from_slice(null);
        buf.push(if *spent { 1 } else { 0 });
    }
    buf
}

// ═══════════════════════════════════════════════════════════════
//  Error Types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("message too short")]
    TooShort,
    #[error("bad magic bytes")]
    BadMagic,
    #[error("unsupported wire version: 0x{0:02x}")]
    UnsupportedVersion(u8),
    #[error("unknown message type: 0x{0:02x}")]
    UnknownMessageType(u8),
    #[error("payload too large: {0} bytes > {MAX_PAYLOAD_SIZE}")]
    PayloadTooLarge(u32),
    #[error("checksum mismatch")]
    ChecksumMismatch,
    #[error("too many hashes: {0} > {MAX_HASHES_PER_REQ}")]
    TooManyHashes(usize),
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_message_roundtrip() {
        let msg = WireMessage {
            msg_type: WireMessageType::GetTips,
            payload: vec![],
        };
        let encoded = msg.encode();
        let decoded = WireMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.msg_type, WireMessageType::GetTips);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn test_wire_message_with_payload() {
        let payload = vec![0xAA; 100];
        let msg = WireMessage {
            msg_type: WireMessageType::Tips,
            payload: payload.clone(),
        };
        let encoded = msg.encode();
        let decoded = WireMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_wire_bad_magic_rejected() {
        let mut encoded = WireMessage {
            msg_type: WireMessageType::GetTips,
            payload: vec![],
        }
        .encode();
        encoded[0] = 0xFF;
        assert!(WireMessage::decode(&encoded).is_err());
    }

    #[test]
    fn test_wire_bad_checksum_rejected() {
        let mut encoded = WireMessage {
            msg_type: WireMessageType::GetTips,
            payload: vec![1, 2, 3],
        }
        .encode();
        let last = encoded.len() - 1;
        encoded[last] ^= 0xFF;
        assert!(matches!(
            WireMessage::decode(&encoded),
            Err(WireError::ChecksumMismatch)
        ));
    }

    #[test]
    fn test_wire_oversized_rejected() {
        let mut data = vec![0u8; HEADER_SIZE + CHECKSUM_SIZE];
        data[..4].copy_from_slice(&MAGIC);
        data[4] = WIRE_VERSION;
        data[5] = 0x01; // GetTips
        let huge: u32 = MAX_PAYLOAD_SIZE + 1;
        data[6..10].copy_from_slice(&huge.to_le_bytes());
        assert!(matches!(
            WireMessage::decode(&data),
            Err(WireError::PayloadTooLarge(_))
        ));
    }

    #[test]
    fn test_hash_list_roundtrip() {
        let hashes = vec![[0x11; 32], [0x22; 32], [0x33; 32]];
        let encoded = encode_hash_list(&hashes);
        let decoded = decode_hash_list(&encoded).unwrap();
        assert_eq!(decoded, hashes);
    }

    #[test]
    fn test_hash_list_too_many_rejected() {
        let mut data = vec![0u8; 4];
        let too_many: u32 = (MAX_HASHES_PER_REQ + 1) as u32;
        data[..4].copy_from_slice(&too_many.to_le_bytes());
        assert!(matches!(
            decode_hash_list(&data),
            Err(WireError::TooManyHashes(_))
        ));
    }

    #[test]
    fn test_all_message_types_valid() {
        for id in 0x01..=0x0Au8 {
            assert!(
                WireMessageType::from_u8(id).is_some(),
                "message type 0x{:02x} should be valid",
                id
            );
        }
        assert!(WireMessageType::from_u8(0x00).is_none());
        assert!(WireMessageType::from_u8(0xFF).is_none());
    }
}
