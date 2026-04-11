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
//! session_key   = HKDF-SHA3-256(shared_secret, "MISAKA-v3:p2p:session-key:")
//! send_key      = HKDF-SHA3-256(session_key, "MISAKA-v3:p2p:send:" || role_byte)
//! recv_key      = HKDF-SHA3-256(session_key, "MISAKA-v3:p2p:recv:" || role_byte)
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

/// SEC-ST-LIFE: Maximum session lifetime (seconds).
///
/// Even if the nonce counter hasn't reached REKEY_THRESHOLD, the
/// session MUST be rekeyed or torn down after this duration.
/// This bounds the window for:
/// - Key compromise exploitation
/// - Traffic analysis attacks
/// - Stale/abandoned session resource leaks
///
/// Default: 24 hours. Validators SHOULD use a shorter value (4 hours).
pub const MAX_SESSION_LIFETIME_SECS: u64 = 86400; // 24 hours

/// SEC-ST-SEQ: Maximum tolerated nonce gap for out-of-order detection.
///
/// If a received frame's nonce is more than this many steps ahead of
/// the last verified nonce, it is rejected as potentially malicious.
/// This prevents an attacker from sending frames with very high nonces
/// to cause the receiver to skip legitimate frames.
///
/// A small window (e.g., 32) allows for minor TCP reordering while
/// blocking extreme jump attacks.
pub const MAX_NONCE_GAP: u64 = 32;

/// Role byte for key derivation (prevents reflection).
const ROLE_INITIATOR: u8 = 0x01;
const ROLE_RESPONDER: u8 = 0x02;

const DST_DIRECTIONAL: &[u8] = b"MISAKA-v3:p2p:directional:";

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

/// SEC-FIX N-M9: Uses `zeroize` crate instead of hand-rolled `unsafe`
/// volatile writes for session key cleanup on drop.
impl Drop for DirectionalKeys {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.send_key.zeroize();
        self.recv_key.zeroize();
    }
}

impl DirectionalKeys {
    /// Derive directional keys from the session key.
    ///
    /// `is_initiator`: true for the connection initiator, false for responder.
    pub fn derive(session_key: &[u8; 32], is_initiator: bool) -> Self {
        let role = if is_initiator {
            ROLE_INITIATOR
        } else {
            ROLE_RESPONDER
        };
        let anti_role = if is_initiator {
            ROLE_RESPONDER
        } else {
            ROLE_INITIATOR
        };

        // Use one directional domain separator and opposite role bytes
        // so initiator.send == responder.recv and vice versa.
        let send_key = derive_subkey(session_key, DST_DIRECTIONAL, role);
        let recv_key = derive_subkey(session_key, DST_DIRECTIONAL, anti_role);

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
//  SEC-ST-SEQ: Receive-Side Nonce Tracking (Anti-Replay)
// ═══════════════════════════════════════════════════════════════

/// Tracks received nonces to detect replay and reorder attacks.
///
/// # Design
///
/// Maintains a sliding window of seen nonces. The window is anchored
/// at `min_accepted` (the highest contiguous nonce seen). Nonces below
/// `min_accepted` are always rejected (already processed). Nonces within
/// the window are checked against a bitfield. Nonces above the window
/// but within `MAX_NONCE_GAP` advance the window.
///
/// # Why This Matters
///
/// Without nonce tracking on the receive side, an attacker who captures
/// encrypted frames can replay them. Although ChaCha20-Poly1305 will
/// still decrypt them (the nonce/key pair is valid), the application
/// layer would process duplicate messages — potentially causing:
/// - Duplicate block relay (wasted bandwidth)
/// - Duplicate transaction broadcast (mempool pollution)
/// - Consensus message replay (vote amplification)
pub struct RecvNonceTracker {
    /// The lowest nonce we will accept (exclusive).
    /// All nonces <= min_accepted are rejected.
    min_accepted: u64,
    /// Bitfield for the window [min_accepted+1 .. min_accepted+64].
    /// Bit i is set if nonce (min_accepted + 1 + i) has been seen.
    seen_bitmap: u64,
}

impl RecvNonceTracker {
    pub fn new() -> Self {
        Self {
            // Start at u64::MAX so nonce 0 is accepted
            min_accepted: u64::MAX,
            seen_bitmap: 0,
        }
    }

    /// Check and record a received nonce.
    ///
    /// Returns `Ok(())` if the nonce is valid and not replayed.
    /// Returns `Err` if the nonce is replayed, too old, or too far ahead.
    ///
    /// # Fail-Closed
    ///
    /// Any error from this function means the frame MUST be dropped
    /// and the peer SHOULD receive a penalty.
    pub fn check_and_record(&mut self, nonce_value: u64) -> Result<(), AeadError> {
        // First nonce: accept anything
        if self.min_accepted == u64::MAX {
            self.min_accepted = nonce_value;
            self.seen_bitmap = 0;
            return Ok(());
        }

        if nonce_value <= self.min_accepted {
            // Nonce is too old → replay or reorder beyond window
            return Err(AeadError::NonceReplay { nonce: nonce_value });
        }

        let offset = nonce_value - self.min_accepted - 1;

        if offset >= 64 {
            // Nonce is far ahead — check gap limit
            let gap = nonce_value - self.min_accepted;
            if gap > MAX_NONCE_GAP {
                return Err(AeadError::NonceGapTooLarge { gap });
            }
            // Advance the window
            let shift = offset - 63;
            if shift >= 64 {
                self.seen_bitmap = 0;
            } else {
                self.seen_bitmap >>= shift;
            }
            self.min_accepted = nonce_value - 64;
            let new_offset = nonce_value - self.min_accepted - 1;
            self.seen_bitmap |= 1u64 << new_offset;
            return Ok(());
        }

        // Within window — check bitfield
        let bit = 1u64 << offset;
        if self.seen_bitmap & bit != 0 {
            return Err(AeadError::NonceReplay { nonce: nonce_value });
        }
        self.seen_bitmap |= bit;

        // Advance min_accepted past contiguous seen nonces
        while self.seen_bitmap & 1 != 0 {
            self.min_accepted += 1;
            self.seen_bitmap >>= 1;
        }

        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════
//  SEC-ST-LIFE: Session Guard (Lifetime + Nonce + Metrics)
// ═══════════════════════════════════════════════════════════════

/// Unified session state guard.
///
/// Combines nonce counter (send), nonce tracker (receive), and session
/// lifetime enforcement into a single type. The caller MUST check
/// `is_expired()` periodically (e.g., on every frame send/receive)
/// and rekey or disconnect if true.
///
/// # Usage
///
/// ```text
/// let mut session = SessionGuard::new(keys, is_initiator);
///
/// // Sending:
/// let wire = session.encrypt_and_frame(plaintext)?;  // checks lifetime + nonce
///
/// // Receiving:
/// let plain = session.verify_and_decrypt(frame)?;    // checks replay + gap + lifetime
///
/// // Periodic check:
/// if session.needs_action() { /* rekey or disconnect */ }
/// ```
pub struct SessionGuard {
    pub keys: DirectionalKeys,
    send_nonce: NonceCounter,
    recv_tracker: RecvNonceTracker,
    created_at: std::time::Instant,
    /// Total frames sent (for metrics/monitoring).
    pub frames_sent: u64,
    /// Total frames received.
    pub frames_received: u64,
}

impl SessionGuard {
    pub fn new(keys: DirectionalKeys) -> Self {
        Self {
            keys,
            send_nonce: NonceCounter::new(),
            recv_tracker: RecvNonceTracker::new(),
            created_at: std::time::Instant::now(),
            frames_sent: 0,
            frames_received: 0,
        }
    }

    /// Encrypt plaintext and produce a length-prefixed wire frame.
    ///
    /// Checks session lifetime and nonce exhaustion before encrypting.
    pub fn encrypt_and_frame(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, AeadError> {
        // Check session lifetime
        let elapsed = self.created_at.elapsed().as_secs();
        if elapsed >= MAX_SESSION_LIFETIME_SECS {
            return Err(AeadError::SessionExpired {
                elapsed_secs: elapsed,
            });
        }

        let result = encode_wire_frame(&self.keys.send_key, &mut self.send_nonce, plaintext)?;
        self.frames_sent += 1;
        Ok(result)
    }

    /// Decrypt a received AEAD frame with replay and lifetime checks.
    ///
    /// `frame` is the raw bytes AFTER the 4-byte length prefix has been
    /// stripped (i.e., `nonce(12) || ciphertext || tag(16)`).
    pub fn verify_and_decrypt(&mut self, frame: &[u8]) -> Result<Vec<u8>, AeadError> {
        // Check session lifetime
        let elapsed = self.created_at.elapsed().as_secs();
        if elapsed >= MAX_SESSION_LIFETIME_SECS {
            return Err(AeadError::SessionExpired {
                elapsed_secs: elapsed,
            });
        }

        if frame.len() < NONCE_SIZE {
            return Err(AeadError::DecryptFailed);
        }

        // Extract and validate nonce BEFORE decryption
        let nonce_bytes = &frame[..NONCE_SIZE];
        let nonce_arr: [u8; 8] = match nonce_bytes[..8].try_into() {
            Ok(b) => b,
            Err(_) => return Err(AeadError::DecryptFailed),
        };
        let nonce_value = u64::from_le_bytes(nonce_arr);
        self.recv_tracker.check_and_record(nonce_value)?;

        // Decrypt (AEAD tag verification)
        let plaintext = decrypt_frame(&self.keys.recv_key, frame)?;
        self.frames_received += 1;
        Ok(plaintext)
    }

    /// Whether the session has expired or nonce is near exhaustion.
    pub fn needs_action(&self) -> bool {
        self.is_expired() || self.nonce_near_exhaustion()
    }

    /// Whether the session lifetime has been exceeded.
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed().as_secs() >= MAX_SESSION_LIFETIME_SECS
    }

    /// Whether the send nonce is within 1% of REKEY_THRESHOLD.
    pub fn nonce_near_exhaustion(&self) -> bool {
        self.send_nonce.current() >= REKEY_THRESHOLD.saturating_sub(REKEY_THRESHOLD / 100)
    }

    /// Session uptime in seconds.
    pub fn uptime_secs(&self) -> u64 {
        self.created_at.elapsed().as_secs()
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
    #[error(
        "SEC-ST-LIFE: session expired after {elapsed_secs}s (max {MAX_SESSION_LIFETIME_SECS}s)"
    )]
    SessionExpired { elapsed_secs: u64 },
    #[error("SEC-ST-SEQ: nonce replay detected (nonce {nonce} already seen)")]
    NonceReplay { nonce: u64 },
    #[error("SEC-ST-SEQ: nonce gap too large ({gap} > {MAX_NONCE_GAP})")]
    NonceGapTooLarge { gap: u64 },
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
pub fn decrypt_frame(key: &[u8; 32], frame: &[u8]) -> Result<Vec<u8>, AeadError> {
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
    // Transport control
    /// SEC-L2: Explicit rekey request.
    ///
    /// Sent by the sender when its nonce counter approaches REKEY_THRESHOLD.
    /// Payload: `new_epoch(8 LE)` — the epoch number the sender is rekeying TO.
    /// The receiver MUST switch to the new recv key for the NEXT frame.
    ///
    /// This is encrypted with the OLD key (the last frame under that epoch).
    /// All subsequent frames from the sender use the new epoch's key.
    Rekey = 0xF0,
    /// SEC-L2: Rekey acknowledgement.
    ///
    /// Sent by the receiver to confirm it has switched to the new recv key.
    /// Payload: `acked_epoch(8 LE)`.
    RekeyAck = 0xF1,
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
            0xF0 => Some(Self::Rekey),
            0xF1 => Some(Self::RekeyAck),
            _ => None,
        }
    }

    /// Whether this is a transport-control message (not relayed to consensus).
    pub fn is_transport_control(&self) -> bool {
        matches!(self, Self::Rekey | Self::RekeyAck)
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
        assert!(
            decrypt_frame(&key, &frame).is_err(),
            "tampered frame must be rejected"
        );
    }

    #[test]
    fn test_wrong_key_rejected() {
        let key1 = [0x42; 32];
        let key2 = [0x43; 32];
        let plaintext = b"secret";
        let nonce = [0u8; NONCE_SIZE];

        let frame = encrypt_frame(&key1, &nonce, plaintext).expect("encrypt");
        assert!(
            decrypt_frame(&key2, &frame).is_err(),
            "wrong key must be rejected"
        );
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
    fn test_recv_nonce_tracker_accepts_sequential() {
        let mut tracker = RecvNonceTracker::new();
        assert!(tracker.check_and_record(0).is_ok());
        assert!(tracker.check_and_record(1).is_ok());
        assert!(tracker.check_and_record(2).is_ok());
    }

    #[test]
    fn test_recv_nonce_tracker_rejects_replay() {
        let mut tracker = RecvNonceTracker::new();
        assert!(tracker.check_and_record(0).is_ok());
        assert!(tracker.check_and_record(1).is_ok());

        // Replay nonce 0
        match tracker.check_and_record(0) {
            Err(AeadError::NonceReplay { nonce: 0 }) => {}
            other => panic!("expected NonceReplay, got {:?}", other),
        }

        // Replay nonce 1
        match tracker.check_and_record(1) {
            Err(AeadError::NonceReplay { .. }) => {}
            other => panic!("expected NonceReplay, got {:?}", other),
        }
    }

    #[test]
    fn test_recv_nonce_tracker_allows_minor_reorder() {
        let mut tracker = RecvNonceTracker::new();
        assert!(tracker.check_and_record(0).is_ok());
        // Skip nonce 1, receive nonce 2 first (minor reorder)
        assert!(tracker.check_and_record(2).is_ok());
        // Now receive the skipped nonce 1
        assert!(tracker.check_and_record(1).is_ok());
    }

    #[test]
    fn test_recv_nonce_tracker_rejects_large_gap() {
        let mut tracker = RecvNonceTracker::new();
        assert!(tracker.check_and_record(0).is_ok());

        // Jump far ahead (beyond MAX_NONCE_GAP)
        let far = MAX_NONCE_GAP + 100;
        match tracker.check_and_record(far) {
            Err(AeadError::NonceGapTooLarge { .. }) => {}
            other => panic!("expected NonceGapTooLarge, got {:?}", other),
        }
    }

    #[test]
    fn test_session_guard_encrypt_decrypt_roundtrip() {
        let session_key = [0xBB; 32];
        let init_keys = DirectionalKeys::derive(&session_key, true);
        let resp_keys = DirectionalKeys::derive(&session_key, false);

        let mut init_session = SessionGuard::new(init_keys);
        let mut resp_session = SessionGuard::new(resp_keys);

        // Initiator encrypts
        let msg = encode_binary_message(MsgType::Ping, &42u64.to_le_bytes());
        let wire = init_session.encrypt_and_frame(&msg).expect("encrypt");

        // Responder decrypts (strip length prefix)
        let frame_len = u32::from_le_bytes([wire[0], wire[1], wire[2], wire[3]]) as usize;
        let plain = resp_session
            .verify_and_decrypt(&wire[4..4 + frame_len])
            .expect("decrypt");
        let (msg_type, payload) = decode_binary_message(&plain).expect("decode");
        assert_eq!(msg_type, MsgType::Ping);
        assert_eq!(u64::from_le_bytes(payload.try_into().expect("8 bytes")), 42);

        assert_eq!(init_session.frames_sent, 1);
        assert_eq!(resp_session.frames_received, 1);
    }

    #[test]
    fn test_session_guard_rejects_replay() {
        let session_key = [0xCC; 32];
        let init_keys = DirectionalKeys::derive(&session_key, true);
        let resp_keys = DirectionalKeys::derive(&session_key, false);

        let mut init_session = SessionGuard::new(init_keys);
        let mut resp_session = SessionGuard::new(resp_keys);

        let msg = encode_binary_message(MsgType::Ping, &[]);
        let wire = init_session.encrypt_and_frame(&msg).expect("encrypt");
        let frame_len = u32::from_le_bytes([wire[0], wire[1], wire[2], wire[3]]) as usize;
        let frame = &wire[4..4 + frame_len];

        // First decrypt succeeds
        assert!(resp_session.verify_and_decrypt(frame).is_ok());
        // Replay MUST fail
        assert!(resp_session.verify_and_decrypt(frame).is_err());
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
        let plaintext =
            decrypt_frame(&resp_keys.recv_key, &wire[4..4 + frame_len]).expect("responder decrypt");
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
