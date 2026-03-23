//! # PeerRecord — Signed Peer Advertisement
//!
//! Each node periodically publishes a `PeerRecord` describing:
//! - Who it is (PeerId + transport public key)
//! - Where it is (network addresses)
//! - What it can do (capabilities + roles)
//! - When this record is valid (issued_at..expires_at)
//!
//! Records are self-signed with the node's ML-DSA-65 key.
//! Unsigned or expired records are REJECTED (fail-closed).

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::peer_id::PeerId;

/// Maximum addresses per peer record (anti-spam).
pub const MAX_ADDRESSES: usize = 8;

/// Maximum total record size in bytes (anti-DoS).
pub const MAX_RECORD_SIZE: usize = 8192;

/// Maximum clock skew tolerance (seconds) for future-dated records.
pub const MAX_CLOCK_SKEW_SECS: u64 = 300; // 5 minutes

/// Default record TTL (seconds).
pub const DEFAULT_TTL_SECS: u64 = 3600; // 1 hour

/// Domain separation for record signing.
const RECORD_SIGN_DST: &[u8] = b"MISAKA_PEER_RECORD_V1:";

// ═══════════════════════════════════════════════════════════════
//  Network Address
// ═══════════════════════════════════════════════════════════════

/// A network address where a peer can be reached.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkAddress {
    /// Protocol (e.g., "tcp", "quic").
    pub protocol: String,
    /// Address string (e.g., "198.51.100.1:6690").
    pub addr: String,
}

// ═══════════════════════════════════════════════════════════════
//  Capability Flags
// ═══════════════════════════════════════════════════════════════

bitflags::bitflags! {
    /// Advertised node capabilities.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct CapabilityFlags: u32 {
        /// Can relay blocks and transactions.
        const RELAY       = 0b0000_0001;
        /// Serves historical blocks (archive node).
        const ARCHIVE     = 0b0000_0010;
        /// Serves peer discovery (bootstrap/seed).
        const DISCOVERY   = 0b0000_0100;
        /// Supports DAG consensus protocol.
        const DAG         = 0b0000_1000;
        /// Supports confidential transaction verification.
        const CT          = 0b0001_0000;
        /// Can serve pruning proofs for IBD.
        const PRUNING     = 0b0010_0000;
    }
}

// ═══════════════════════════════════════════════════════════════
//  Peer Roles
// ═══════════════════════════════════════════════════════════════

/// The role(s) a peer advertises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerRoles {
    /// Is this a validator node?
    pub validator: bool,
    /// Is this a sentry node (front for a validator)?
    pub sentry: bool,
    /// Is this a bootstrap/seed node?
    pub bootstrap: bool,
}

impl PeerRoles {
    pub fn full_node() -> Self {
        Self {
            validator: false,
            sentry: false,
            bootstrap: false,
        }
    }

    pub fn sentry() -> Self {
        Self {
            validator: false,
            sentry: true,
            bootstrap: false,
        }
    }

    pub fn validator() -> Self {
        Self {
            validator: true,
            sentry: false,
            bootstrap: false,
        }
    }

    pub fn bootstrap() -> Self {
        Self {
            validator: false,
            sentry: false,
            bootstrap: true,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Peer Record
// ═══════════════════════════════════════════════════════════════

/// Signed peer advertisement.
///
/// # Security
///
/// - Self-signed by the transport key → tamper-proof
/// - Expiry-checked → stale records are rejected
/// - Chain-bound → cross-network replay impossible
/// - Size-bounded → DoS resistant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    /// Derived PeerId (for fast lookup; verified against transport_pubkey).
    pub peer_id: PeerId,
    /// ML-DSA-65 transport public key (canonical bytes).
    pub transport_pubkey: Vec<u8>,
    /// Reachable network addresses.
    pub addresses: Vec<NetworkAddress>,
    /// Node capabilities.
    pub capabilities: CapabilityFlags,
    /// Node roles.
    pub roles: PeerRoles,
    /// Chain identifier.
    pub chain_id: u32,
    /// Network identifier (e.g., "mainnet", "testnet-v3").
    pub network_id: String,
    /// Unix timestamp (seconds) when this record was created.
    pub issued_at_unix: u64,
    /// Unix timestamp (seconds) when this record expires.
    pub expires_at_unix: u64,
    /// Epoch hint (for epoch-aware peer selection).
    pub epoch_hint: u64,
    /// ML-DSA-65 signature over the canonical record body.
    pub signature: Vec<u8>,
}

impl PeerRecord {
    /// Compute the canonical bytes to sign (excludes the signature field itself).
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(RECORD_SIGN_DST);
        buf.extend_from_slice(&self.peer_id.0);
        buf.extend_from_slice(&(self.transport_pubkey.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.transport_pubkey);

        // Addresses (sorted for determinism)
        let mut addrs: Vec<String> = self
            .addresses
            .iter()
            .map(|a| format!("{}:{}", a.protocol, a.addr))
            .collect();
        addrs.sort();
        buf.extend_from_slice(&(addrs.len() as u32).to_le_bytes());
        for a in &addrs {
            buf.extend_from_slice(&(a.len() as u32).to_le_bytes());
            buf.extend_from_slice(a.as_bytes());
        }

        buf.extend_from_slice(&self.capabilities.bits().to_le_bytes());
        buf.push(self.roles.validator as u8);
        buf.push(self.roles.sentry as u8);
        buf.push(self.roles.bootstrap as u8);
        buf.extend_from_slice(&self.chain_id.to_le_bytes());
        buf.extend_from_slice(&(self.network_id.len() as u32).to_le_bytes());
        buf.extend_from_slice(self.network_id.as_bytes());
        buf.extend_from_slice(&self.issued_at_unix.to_le_bytes());
        buf.extend_from_slice(&self.expires_at_unix.to_le_bytes());
        buf.extend_from_slice(&self.epoch_hint.to_le_bytes());
        buf
    }

    /// Verify this record's structural validity and signature.
    ///
    /// # Fail-Closed Checks
    ///
    /// 1. PeerId matches transport_pubkey + chain_id
    /// 2. Record is not expired (with clock skew tolerance)
    /// 3. Record is not from the future beyond tolerance
    /// 4. Address count within bounds
    /// 5. ML-DSA-65 signature is valid
    pub fn verify(&self, now_unix: u64) -> Result<(), PeerRecordError> {
        // ── Structural bounds ──
        if self.addresses.len() > MAX_ADDRESSES {
            return Err(PeerRecordError::TooManyAddresses {
                count: self.addresses.len(),
            });
        }
        if self.transport_pubkey.is_empty() {
            return Err(PeerRecordError::EmptyPublicKey);
        }
        if self.network_id.len() > 64 {
            return Err(PeerRecordError::NetworkIdTooLong);
        }

        // ── PeerId verification ──
        let expected_id = PeerId::from_pubkey(&self.transport_pubkey, self.chain_id);
        if self.peer_id != expected_id {
            return Err(PeerRecordError::PeerIdMismatch {
                declared: self.peer_id.short_hex(),
                derived: expected_id.short_hex(),
            });
        }

        // ── Expiry checks ──
        if self.expires_at_unix <= self.issued_at_unix {
            return Err(PeerRecordError::InvalidExpiry);
        }
        if now_unix > self.expires_at_unix {
            return Err(PeerRecordError::Expired {
                expires_at: self.expires_at_unix,
                now: now_unix,
            });
        }
        if self.issued_at_unix > now_unix + MAX_CLOCK_SKEW_SECS {
            return Err(PeerRecordError::FutureDated {
                issued_at: self.issued_at_unix,
                now: now_unix,
            });
        }

        // ── ML-DSA-65 signature verification ──
        let msg = self.signing_bytes();
        let pk =
            misaka_crypto::validator_sig::ValidatorPqPublicKey::from_bytes(&self.transport_pubkey)
                .map_err(|e| PeerRecordError::InvalidPublicKey(e.to_string()))?;
        let sig = misaka_crypto::validator_sig::ValidatorPqSignature::from_bytes(&self.signature)
            .map_err(|e| PeerRecordError::InvalidSignature(e.to_string()))?;
        misaka_crypto::validator_sig::validator_verify(&msg, &sig, &pk)
            .map_err(|e| PeerRecordError::SignatureVerificationFailed(e.to_string()))?;

        Ok(())
    }

    /// Create a signed peer record.
    pub fn create_signed(
        transport_pubkey: &[u8],
        identity_sk: &misaka_crypto::validator_sig::ValidatorPqSecretKey,
        addresses: Vec<NetworkAddress>,
        capabilities: CapabilityFlags,
        roles: PeerRoles,
        chain_id: u32,
        network_id: String,
        epoch_hint: u64,
        now_unix: u64,
        ttl_secs: u64,
    ) -> Result<Self, PeerRecordError> {
        let peer_id = PeerId::from_pubkey(transport_pubkey, chain_id);
        let mut record = Self {
            peer_id,
            transport_pubkey: transport_pubkey.to_vec(),
            addresses,
            capabilities,
            roles,
            chain_id,
            network_id,
            issued_at_unix: now_unix,
            expires_at_unix: now_unix + ttl_secs,
            epoch_hint,
            signature: vec![],
        };

        let msg = record.signing_bytes();
        let sig = misaka_crypto::validator_sig::validator_sign(&msg, identity_sk)
            .map_err(|e| PeerRecordError::SigningFailed(e.to_string()))?;
        record.signature = sig.to_bytes();

        Ok(record)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Errors
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum PeerRecordError {
    #[error("too many addresses: {count} > {}", MAX_ADDRESSES)]
    TooManyAddresses { count: usize },
    #[error("empty transport public key")]
    EmptyPublicKey,
    #[error("network_id too long (>64 bytes)")]
    NetworkIdTooLong,
    #[error("peer_id mismatch: declared={declared}, derived={derived}")]
    PeerIdMismatch { declared: String, derived: String },
    #[error("invalid expiry: expires_at <= issued_at")]
    InvalidExpiry,
    #[error("record expired: expires_at={expires_at}, now={now}")]
    Expired { expires_at: u64, now: u64 },
    #[error("record future-dated: issued_at={issued_at}, now={now}")]
    FutureDated { issued_at: u64, now: u64 },
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(String),
    #[error("signing failed: {0}")]
    SigningFailed(String),
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_crypto::validator_sig::generate_validator_keypair;

    fn now_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    #[test]
    fn test_peer_record_sign_and_verify() {
        let kp = generate_validator_keypair();
        let record = PeerRecord::create_signed(
            &kp.public_key.to_bytes(),
            &kp.secret_key,
            vec![NetworkAddress {
                protocol: "tcp".into(),
                addr: "1.2.3.4:6690".into(),
            }],
            CapabilityFlags::RELAY | CapabilityFlags::DAG,
            PeerRoles::full_node(),
            2, // testnet
            "testnet-v3".into(),
            0,
            now_unix(),
            3600,
        )
        .expect("create_signed");

        assert!(record.verify(now_unix()).is_ok());
    }

    #[test]
    fn test_peer_record_expired_rejected() {
        let kp = generate_validator_keypair();
        let past = now_unix() - 7200;
        let record = PeerRecord::create_signed(
            &kp.public_key.to_bytes(),
            &kp.secret_key,
            vec![],
            CapabilityFlags::RELAY,
            PeerRoles::full_node(),
            2,
            "test".into(),
            0,
            past,
            3600, // expired 1 hour ago
        )
        .expect("create_signed");

        let result = record.verify(now_unix());
        assert!(matches!(result, Err(PeerRecordError::Expired { .. })));
    }

    #[test]
    fn test_peer_record_future_dated_rejected() {
        let kp = generate_validator_keypair();
        let future = now_unix() + 600; // 10 minutes in the future (> MAX_CLOCK_SKEW_SECS)
        let record = PeerRecord::create_signed(
            &kp.public_key.to_bytes(),
            &kp.secret_key,
            vec![],
            CapabilityFlags::RELAY,
            PeerRoles::full_node(),
            2,
            "test".into(),
            0,
            future,
            3600,
        )
        .expect("create_signed");

        let result = record.verify(now_unix());
        assert!(matches!(result, Err(PeerRecordError::FutureDated { .. })));
    }

    #[test]
    fn test_peer_record_tampered_signature_rejected() {
        let kp = generate_validator_keypair();
        let mut record = PeerRecord::create_signed(
            &kp.public_key.to_bytes(),
            &kp.secret_key,
            vec![],
            CapabilityFlags::RELAY,
            PeerRoles::full_node(),
            2,
            "test".into(),
            0,
            now_unix(),
            3600,
        )
        .expect("create_signed");

        // Tamper with the record
        record.epoch_hint = 999;
        let result = record.verify(now_unix());
        assert!(matches!(
            result,
            Err(PeerRecordError::SignatureVerificationFailed(_))
        ));
    }

    #[test]
    fn test_peer_record_wrong_chain_id_peer_id_mismatch() {
        let kp = generate_validator_keypair();
        let mut record = PeerRecord::create_signed(
            &kp.public_key.to_bytes(),
            &kp.secret_key,
            vec![],
            CapabilityFlags::RELAY,
            PeerRoles::full_node(),
            2,
            "test".into(),
            0,
            now_unix(),
            3600,
        )
        .expect("create_signed");

        // Change chain_id without re-signing → PeerId mismatch
        record.chain_id = 99;
        let result = record.verify(now_unix());
        assert!(matches!(
            result,
            Err(PeerRecordError::PeerIdMismatch { .. })
        ));
    }

    #[test]
    fn test_peer_record_too_many_addresses() {
        let kp = generate_validator_keypair();
        let addrs: Vec<NetworkAddress> = (0..MAX_ADDRESSES + 1)
            .map(|i| NetworkAddress {
                protocol: "tcp".into(),
                addr: format!("1.2.3.4:{}", 6690 + i),
            })
            .collect();
        let record = PeerRecord::create_signed(
            &kp.public_key.to_bytes(),
            &kp.secret_key,
            addrs,
            CapabilityFlags::RELAY,
            PeerRoles::full_node(),
            2,
            "test".into(),
            0,
            now_unix(),
            3600,
        )
        .expect("create_signed");

        let result = record.verify(now_unix());
        assert!(matches!(
            result,
            Err(PeerRecordError::TooManyAddresses { .. })
        ));
    }
}
