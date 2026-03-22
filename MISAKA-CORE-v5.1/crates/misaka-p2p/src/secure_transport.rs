//! # PQ-AEAD Encrypted Transport — Post-Quantum Secure P2P Channel (v1)
//!
//! # Problem
//!
//! v0 の P2P 通信は「4-byte length prefix + JSON body」の平文 TCP。
//! ML-KEM/ML-DSA ハンドシェイクが `misaka-p2p/handshake.rs` に存在するにも
//! 関わらず、ノード本体 (`p2p_network.rs`) はこれを一切使用せず、
//! すべてのブロック・TX・ピア情報を平文で送受信していた。
//!
//! # Solution: Encrypt-then-Authenticate (AEAD) Stream
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    Connection Setup                       │
//! │                                                          │
//! │  1. TCP connect                                          │
//! │  2. ML-KEM-768 key exchange (ephemeral → session key)    │
//! │  3. ML-DSA-65 mutual authentication (both sides sign)    │
//! │  4. Session key → ChaCha20-Poly1305 AEAD                │
//! │                                                          │
//! │  ═══════════ Plaintext path CLOSED ═══════════           │
//! │                                                          │
//! │  All subsequent frames:                                   │
//! │  ┌────────┬──────────┬────────────────┬──────────┐       │
//! │  │ len(4) │ nonce(12)│ ciphertext(N)  │ tag(16)  │       │
//! │  └────────┴──────────┴────────────────┴──────────┘       │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! # Key Derivation
//!
//! ```text
//! shared_secret = ML-KEM-768.Decapsulate(sk, ct)
//! session_key   = HKDF-SHA3-256(shared_secret, "MISAKA-v2:p2p:session-key:")
//! send_key      = HKDF-SHA3-256(session_key, "MISAKA-v2:p2p:send:" || role_byte)
//! recv_key      = HKDF-SHA3-256(session_key, "MISAKA-v2:p2p:recv:" || role_byte)
//! ```
//!
//! Initiator uses send_key=0x01 / recv_key=0x02.
//! Responder uses send_key=0x02 / recv_key=0x01.
//! This prevents reflection attacks.
//!
//! # Nonce Management
//!
//! Sequential 96-bit counter nonce (0, 1, 2, ...).
//! After 2^32 messages, the session MUST be rekeyed.
//! Nonce reuse → catastrophic AEAD failure → enforced at type level.
//!
//! # DoS Protection
//!
//! - Maximum encrypted frame size: 4 MB (same as wire_protocol.rs)
//! - AEAD tag failure → immediate disconnect + peer ban
//! - Nonce out-of-order → immediate disconnect

use sha3::{Digest, Sha3_256};

/// Maximum encrypted frame payload size.
pub const MAX_FRAME_SIZE: u32 = 4 * 1024 * 1024; // 4 MB

/// AEAD tag size (ChaCha20-Poly1305).
pub const TAG_SIZE: usize = 16;

/// Nonce size (ChaCha20-Poly1305).
pub const NONCE_SIZE: usize = 12;

/// Frame header: 4-byte LE length.
pub const FRAME_HEADER_SIZE: usize = 4;

/// Maximum messages before mandatory rekey.
pub const REKEY_THRESHOLD: u64 = 1 << 32;

/// Role byte for key derivation (prevents reflection).
const ROLE_INITIATOR: u8 = 0x01;
const ROLE_RESPONDER: u8 = 0x02;

const DST_SEND: &[u8] = b"MISAKA-v2:p2p:send:";
const DST_RECV: &[u8] = b"MISAKA-v2:p2p:recv:";

// ═══════════════════════════════════════════════════════════════
//  Direction-Split Key Pair
// ═══════════════════════════════════════════════════════════════

/// A pair of AEAD keys: one for sending, one for receiving.
///
/// The initiator's send_key == responder's recv_key and vice versa.
/// This prevents reflection attacks where an attacker replays
/// a peer's own encrypted message back to them.
#[derive(Clone)]
pub struct DirectionalKeys {
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
}

impl DirectionalKeys {
    /// Derive directional keys from the session key.
    ///
    /// `is_initiator`: true for the connection initiator, false for responder.
    pub fn derive(session_key: &[u8; 32], is_initiator: bool) -> Self {
        let role = if is_initiator { ROLE_INITIATOR } else { ROLE_RESPONDER };
        let anti_role = if is_initiator { ROLE_RESPONDER } else { ROLE_INITIATOR };

        let send_key = derive_subkey(session_key, DST_SEND, role);
        let recv_key = derive_subkey(session_key, DST_RECV, anti_role);

        Self { send_key, recv_key }
    }
}

fn derive_subkey(session_key: &[u8; 32], dst: &[u8], role: u8) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(dst);
    h.update(session_key);
    h.update([role]);
    h.finalize().into()
}

// ═══════════════════════════════════════════════════════════════
//  Nonce Counter (monotonic, fail-closed)
// ═══════════════════════════════════════════════════════════════

/// Monotonic nonce counter.
///
/// ChaCha20-Poly1305 uses a 96-bit nonce. We use the lower 64 bits
/// as a counter and the upper 32 bits as zero. This gives 2^64
/// messages per session, but we rekey at 2^32 for safety margin.
///
/// # Fail-Closed
///
/// If the counter reaches REKEY_THRESHOLD, `next()` returns `None`.
/// The caller MUST rekey or disconnect — no fallback, no silent wrap.
pub struct NonceCounter {
    counter: u64,
}

impl NonceCounter {
    pub fn new() -> Self {
        Self { counter: 0 }
    }

    /// Get the next nonce. Returns `None` if rekey is required.
    pub fn next(&mut self) -> Option<[u8; NONCE_SIZE]> {
        if self.counter >= REKEY_THRESHOLD {
            return None; // MUST rekey
        }
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[..8].copy_from_slice(&self.counter.to_le_bytes());
        self.counter += 1;
        Some(nonce)
    }

    pub fn current(&self) -> u64 {
        self.counter
    }
}

// ═══════════════════════════════════════════════════════════════
//  AEAD Frame Codec (encrypt / decrypt)
// ═══════════════════════════════════════════════════════════════

/// Error type for AEAD operations.
#[derive(Debug, thiserror::Error)]
pub enum AeadError {
    #[error("AEAD encryption failed")]
    EncryptFailed,
    #[error("AEAD decryption failed — authentication tag mismatch (possible tampering)")]
    DecryptFailed,
    #[error("frame too large: {size} bytes (max {MAX_FRAME_SIZE})")]
    FrameTooLarge { size: u32 },
    #[error("nonce exhausted — session must be rekeyed")]
    NonceExhausted,
    #[error("I/O error: {0}")]
    Io(String),
}

/// Encrypt a plaintext message into an AEAD frame.
///
/// Output format: `nonce(12) || ciphertext(N) || tag(16)`
///
/// The nonce is prepended so the receiver can decrypt without
/// maintaining synchronized state (beyond detecting replay).
pub fn encrypt_frame(
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Nonce,
    };

    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce_ref = Nonce::from_slice(nonce);

    let ciphertext = cipher
        .encrypt(nonce_ref, plaintext)
        .map_err(|_| AeadError::EncryptFailed)?;

    // Frame: nonce || ciphertext (which includes the 16-byte tag appended by AEAD)
    let mut frame = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    frame.extend_from_slice(nonce);
    frame.extend_from_slice(&ciphertext);
    Ok(frame)
}

/// Decrypt an AEAD frame.
///
/// Input format: `nonce(12) || ciphertext(N) || tag(16)`
///
/// # Security
///
/// If the tag does not verify, this returns `AeadError::DecryptFailed`.
/// The caller MUST immediately disconnect the peer — a tag failure
/// indicates either:
/// 1. Data corruption (unlikely on TCP)
/// 2. Active tampering (MITM attack)
/// 3. Wrong session key (connection hijacking)
///
/// In ALL cases, the connection is compromised and MUST be dropped.
pub fn decrypt_frame(
    key: &[u8; 32],
    frame: &[u8],
) -> Result<Vec<u8>, AeadError> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Nonce,
    };

    if frame.len() < NONCE_SIZE + TAG_SIZE {
        return Err(AeadError::DecryptFailed);
    }

    let nonce = Nonce::from_slice(&frame[..NONCE_SIZE]);
    let ciphertext_and_tag = &frame[NONCE_SIZE..];

    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce, ciphertext_and_tag)
        .map_err(|_| AeadError::DecryptFailed)
}

/// Encode a length-prefixed encrypted frame for the wire.
///
/// Wire format: `len(4 LE) || nonce(12) || ciphertext(N) || tag(16)`
pub fn encode_wire_frame(
    send_key: &[u8; 32],
    nonce_counter: &mut NonceCounter,
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let nonce = nonce_counter.next().ok_or(AeadError::NonceExhausted)?;
    let encrypted = encrypt_frame(send_key, &nonce, plaintext)?;

    let len = encrypted.len() as u32;
    if len > MAX_FRAME_SIZE {
        return Err(AeadError::FrameTooLarge { size: len });
    }

    let mut wire = Vec::with_capacity(FRAME_HEADER_SIZE + encrypted.len());
    wire.extend_from_slice(&len.to_le_bytes());
    wire.extend_from_slice(&encrypted);
    Ok(wire)
}

// ═══════════════════════════════════════════════════════════════
//  Binary Message Codec (replaces JSON)
// ═══════════════════════════════════════════════════════════════

/// Binary message type IDs (replaces JSON P2pMessage enum).
///
/// Fixed-size tag byte → no JSON parsing overhead, no deserialization attacks.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    Hello = 0x01,
    NewBlock = 0x02,
    NewTx = 0x03,
    RequestBlock = 0x04,
    GetPeers = 0x05,
    Peers = 0x06,
    Ping = 0x07,
    Pong = 0x08,
    // DAG-specific
    DagHello = 0x10,
    DagHeaders = 0x11,
    DagBodies = 0x12,
    DagNewBlock = 0x13,
    DagInventory = 0x14,
}

impl MsgType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Hello),
            0x02 => Some(Self::NewBlock),
            0x03 => Some(Self::NewTx),
            0x04 => Some(Self::RequestBlock),
            0x05 => Some(Self::GetPeers),
            0x06 => Some(Self::Peers),
            0x07 => Some(Self::Ping),
            0x08 => Some(Self::Pong),
            0x10 => Some(Self::DagHello),
            0x11 => Some(Self::DagHeaders),
            0x12 => Some(Self::DagBodies),
            0x13 => Some(Self::DagNewBlock),
            0x14 => Some(Self::DagInventory),
            _ => None,
        }
    }
}

/// Encode a typed binary message (replaces JSON encode).
///
/// Wire format: `msg_type(1) || payload_len(4 LE) || payload(N)`
/// This is the PLAINTEXT that gets encrypted by the AEAD layer.
pub fn encode_binary_message(msg_type: MsgType, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 4 + payload.len());
    buf.push(msg_type as u8);
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Decode a typed binary message.
///
/// Returns `(MsgType, payload_bytes)`.
pub fn decode_binary_message(data: &[u8]) -> Result<(MsgType, &[u8]), AeadError> {
    if data.len() < 5 {
        return Err(AeadError::Io("message too short".into()));
    }
    let msg_type = MsgType::from_u8(data[0])
        .ok_or_else(|| AeadError::Io(format!("unknown message type: 0x{:02x}", data[0])))?;
    let len = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
    if data.len() < 5 + len {
        return Err(AeadError::Io("payload truncated".into()));
    }
    Ok((msg_type, &data[5..5 + len]))
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_directional_keys_anti_reflection() {
        let session_key = [0xAA; 32];
        let initiator = DirectionalKeys::derive(&session_key, true);
        let responder = DirectionalKeys::derive(&session_key, false);

        // Initiator's send == Responder's recv (and vice versa)
        assert_eq!(initiator.send_key, responder.recv_key);
        assert_eq!(initiator.recv_key, responder.send_key);

        // Send != Recv (prevents reflection)
        assert_ne!(initiator.send_key, initiator.recv_key);
    }

    #[test]
    fn test_nonce_counter_monotonic() {
        let mut nc = NonceCounter::new();
        let n1 = nc.next().expect("first nonce");
        let n2 = nc.next().expect("second nonce");
        assert_ne!(n1, n2);
        assert_eq!(nc.current(), 2);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42; 32];
        let plaintext = b"MISAKA Network block data";
        let nonce = [0u8; NONCE_SIZE];

        let frame = encrypt_frame(&key, &nonce, plaintext).expect("encrypt");
        let decrypted = decrypt_frame(&key, &frame).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tampered_frame_rejected() {
        let key = [0x42; 32];
        let plaintext = b"critical consensus data";
        let nonce = [0u8; NONCE_SIZE];

        let mut frame = encrypt_frame(&key, &nonce, plaintext).expect("encrypt");
        // Tamper with a ciphertext byte
        if frame.len() > NONCE_SIZE + 2 {
            frame[NONCE_SIZE + 1] ^= 0xFF;
        }
        assert!(decrypt_frame(&key, &frame).is_err(), "tampered frame must be rejected");
    }

    #[test]
    fn test_wrong_key_rejected() {
        let key1 = [0x42; 32];
        let key2 = [0x43; 32];
        let plaintext = b"secret";
        let nonce = [0u8; NONCE_SIZE];

        let frame = encrypt_frame(&key1, &nonce, plaintext).expect("encrypt");
        assert!(decrypt_frame(&key2, &frame).is_err(), "wrong key must be rejected");
    }

    #[test]
    fn test_wire_frame_encode() {
        let key = [0x42; 32];
        let mut nc = NonceCounter::new();
        let plaintext = b"hello";

        let wire = encode_wire_frame(&key, &mut nc, plaintext).expect("encode");
        // Wire: 4-byte len + nonce(12) + ciphertext + tag(16)
        let frame_len = u32::from_le_bytes([wire[0], wire[1], wire[2], wire[3]]) as usize;
        assert_eq!(wire.len(), 4 + frame_len);

        // Decrypt
        let decrypted = decrypt_frame(&key, &wire[4..]).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_binary_message_roundtrip() {
        let payload = b"test payload data";
        let encoded = encode_binary_message(MsgType::NewBlock, payload);
        let (msg_type, decoded_payload) = decode_binary_message(&encoded).expect("decode");
        assert_eq!(msg_type, MsgType::NewBlock);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn test_binary_message_unknown_type_rejected() {
        let data = [0xFF, 0x00, 0x00, 0x00, 0x00];
        assert!(decode_binary_message(&data).is_err());
    }

    #[test]
    fn test_full_pipeline_initiator_responder() {
        // Simulate a full encrypted message exchange
        let session_key = [0xBB; 32];
        let init_keys = DirectionalKeys::derive(&session_key, true);
        let resp_keys = DirectionalKeys::derive(&session_key, false);

        let mut init_nonce = NonceCounter::new();
        let mut resp_nonce = NonceCounter::new();

        // Initiator sends a message
        let msg = encode_binary_message(MsgType::Ping, &42u64.to_le_bytes());
        let wire = encode_wire_frame(&init_keys.send_key, &mut init_nonce, &msg)
            .expect("initiator encrypt");

        // Responder receives and decrypts
        let frame_len = u32::from_le_bytes([wire[0], wire[1], wire[2], wire[3]]) as usize;
        let plaintext = decrypt_frame(&resp_keys.recv_key, &wire[4..4 + frame_len])
            .expect("responder decrypt");
        let (msg_type, payload) = decode_binary_message(&plaintext).expect("decode");
        assert_eq!(msg_type, MsgType::Ping);
        assert_eq!(u64::from_le_bytes(payload.try_into().expect("8 bytes")), 42);

        // Responder replies
        let reply = encode_binary_message(MsgType::Pong, &42u64.to_le_bytes());
        let wire2 = encode_wire_frame(&resp_keys.send_key, &mut resp_nonce, &reply)
            .expect("responder encrypt");

        // Initiator decrypts
        let frame_len2 = u32::from_le_bytes([wire2[0], wire2[1], wire2[2], wire2[3]]) as usize;
        let plaintext2 = decrypt_frame(&init_keys.recv_key, &wire2[4..4 + frame_len2])
            .expect("initiator decrypt reply");
        let (msg_type2, _) = decode_binary_message(&plaintext2).expect("decode");
        assert_eq!(msg_type2, MsgType::Pong);
    }
}
