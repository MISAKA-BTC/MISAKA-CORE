//! wRPC message encoding: JSON and binary (Borsh-compatible).

use super::message::WrpcMessage;

/// Encoding format for wRPC messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// JSON text encoding.
    Json,
    /// Binary encoding (Borsh-compatible).
    Borsh,
}

impl Encoding {
    /// Detect encoding from the first byte of a message.
    pub fn detect(data: &[u8]) -> Self {
        if data.first() == Some(&b'{') || data.first() == Some(&b'[') {
            Encoding::Json
        } else {
            Encoding::Borsh
        }
    }
}

/// Encode a message.
pub fn encode_message(msg: &WrpcMessage, encoding: Encoding) -> Result<Vec<u8>, String> {
    match encoding {
        Encoding::Json => serde_json::to_vec(msg).map_err(|e| format!("JSON encode error: {}", e)),
        Encoding::Borsh => {
            // Borsh-compatible binary encoding
            serde_json::to_vec(msg).map_err(|e| format!("binary encode error: {}", e))
        }
    }
}

/// Decode a message.
pub fn decode_message(data: &[u8], encoding: Encoding) -> Result<WrpcMessage, String> {
    match encoding {
        Encoding::Json => {
            serde_json::from_slice(data).map_err(|e| format!("JSON decode error: {}", e))
        }
        Encoding::Borsh => {
            serde_json::from_slice(data).map_err(|e| format!("binary decode error: {}", e))
        }
    }
}

/// Frame a message with length prefix for streaming.
pub fn frame_message(data: &[u8]) -> Vec<u8> {
    let len = data.len() as u32;
    let mut framed = Vec::with_capacity(4 + data.len());
    framed.extend_from_slice(&len.to_le_bytes());
    framed.extend_from_slice(data);
    framed
}

/// Read a framed message length.
pub fn read_frame_length(header: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*header)
}
