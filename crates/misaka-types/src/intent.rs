//! Intent-based signing model (Phase 2a).
//!
//! Every ML-DSA-65 signature in the system signs an `IntentMessage`.
//! This replaces all ad-hoc domain-separation strings with a single
//! canonical structure that embeds scope, network identity, and payload.
//!
//! See `docs/architecture.md` Section 2.3 for the full specification.

use borsh::{BorshDeserialize, BorshSerialize};
use sha3::{Digest, Sha3_256};

// ────────────────────────────────────────────────────────────────
//  AppId
// ────────────────────────────────────────────────────────────────

/// Uniquely identifies a MISAKA network instance.
///
/// Embedded in every `IntentMessage` to prevent cross-chain and
/// cross-app replay attacks.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AppId {
    /// Chain identifier (mainnet=1, testnet=2, devnet=3, localnet=100, simnet=255).
    pub chain_id: u32,
    /// SHA3-256 of the genesis committee manifest (deterministic).
    pub genesis_hash: [u8; 32],
}

impl AppId {
    /// Mainnet chain_id.
    pub const MAINNET: u32 = 1;
    /// Testnet chain_id.
    pub const TESTNET: u32 = 2;
    /// Devnet chain_id.
    pub const DEVNET: u32 = 3;
    /// Localnet chain_id.
    pub const LOCALNET: u32 = 100;
    /// Simnet chain_id.
    pub const SIMNET: u32 = 255;

    /// Create a new AppId.
    pub fn new(chain_id: u32, genesis_hash: [u8; 32]) -> Self {
        Self {
            chain_id,
            genesis_hash,
        }
    }
}

// ────────────────────────────────────────────────────────────────
//  IntentScope
// ────────────────────────────────────────────────────────────────

/// Categorizes the kind of action being signed.
///
/// Each scope maps 1:1 to a specific signing context, preventing
/// signature replay across different action types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IntentScope {
    TransparentTransfer = 0,
    SystemEmission = 1,
    Faucet = 2,
    StakeDeposit = 3,
    StakeWithdraw = 4,
    SlashEvidence = 5,
    NarwhalBlock = 10,
    BftPrevote = 11,
    BftPrecommit = 12,
    CheckpointVote = 13,
    BridgeAttestation = 20,
    ValidatorRegister = 21,
}

impl BorshSerialize for IntentScope {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&[*self as u8])
    }
}

impl BorshDeserialize for IntentScope {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        match buf[0] {
            0 => Ok(Self::TransparentTransfer),
            1 => Ok(Self::SystemEmission),
            2 => Ok(Self::Faucet),
            3 => Ok(Self::StakeDeposit),
            4 => Ok(Self::StakeWithdraw),
            5 => Ok(Self::SlashEvidence),
            10 => Ok(Self::NarwhalBlock),
            11 => Ok(Self::BftPrevote),
            12 => Ok(Self::BftPrecommit),
            13 => Ok(Self::CheckpointVote),
            20 => Ok(Self::BridgeAttestation),
            21 => Ok(Self::ValidatorRegister),
            other => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown IntentScope tag: {}", other),
            )),
        }
    }
}

// ────────────────────────────────────────────────────────────────
//  IntentMessage
// ────────────────────────────────────────────────────────────────

/// Canonical signing envelope for all ML-DSA-65 signatures.
///
/// Every signature in the MISAKA system signs an `IntentMessage`.
/// The `signing_digest()` method produces the canonical 32-byte
/// hash that is passed to `ml_dsa_sign` / `ml_dsa_verify`.
///
/// # Wire format (borsh)
///
/// ```text
/// [1B scope][4B chain_id][32B genesis_hash][4B payload_len][payload_bytes]
/// ```
///
/// # Domain separation
///
/// The signing digest prefixes borsh(self) with `"MISAKA-INTENT:v1:"`
/// to ensure separation from any other SHA3-256 usage in the system.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct IntentMessage {
    /// What kind of action is being signed.
    pub scope: IntentScope,
    /// Which network instance this intent belongs to.
    pub app_id: AppId,
    /// Scope-specific payload (borsh-serialized inner struct).
    pub payload: Vec<u8>,
}

impl IntentMessage {
    /// Create a new IntentMessage with raw payload bytes.
    pub fn new(scope: IntentScope, app_id: AppId, payload: Vec<u8>) -> Self {
        Self {
            scope,
            app_id,
            payload,
        }
    }

    /// Create an IntentMessage by borsh-serializing a typed payload.
    ///
    /// This is the preferred constructor. It takes any borsh-serializable
    /// payload struct and serializes it into the `payload` field.
    pub fn wrap<T: borsh::BorshSerialize>(
        scope: IntentScope,
        app_id: AppId,
        payload: &T,
    ) -> Self {
        Self {
            scope,
            app_id,
            payload: borsh::to_vec(payload)
                .expect("IntentMessage::wrap payload borsh serialization must not fail"),
        }
    }

    /// Canonical signing digest.
    ///
    /// `SHA3-256("MISAKA-INTENT:v1:" || borsh(self))`
    ///
    /// This is the value passed to `ml_dsa_sign` / `ml_dsa_verify`.
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA-INTENT:v1:");
        h.update(
            &borsh::to_vec(self).expect("IntentMessage borsh serialization must not fail"),
        );
        h.finalize().into()
    }
}

// ────────────────────────────────────────────────────────────────
//  Tests
// ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intent_message_signing_digest_deterministic() {
        let msg = IntentMessage::new(
            IntentScope::TransparentTransfer,
            AppId::new(2, [0xAA; 32]),
            vec![1, 2, 3],
        );
        assert_eq!(msg.signing_digest(), msg.signing_digest());
    }

    #[test]
    fn intent_message_different_scope_different_digest() {
        let app_id = AppId::new(2, [0xAA; 32]);
        let payload = vec![1, 2, 3];
        let msg1 = IntentMessage::new(IntentScope::TransparentTransfer, app_id.clone(), payload.clone());
        let msg2 = IntentMessage::new(IntentScope::StakeDeposit, app_id, payload);
        assert_ne!(msg1.signing_digest(), msg2.signing_digest());
    }

    #[test]
    fn intent_message_different_chain_id_different_digest() {
        let payload = vec![1, 2, 3];
        let msg1 = IntentMessage::new(
            IntentScope::TransparentTransfer,
            AppId::new(1, [0xAA; 32]),
            payload.clone(),
        );
        let msg2 = IntentMessage::new(
            IntentScope::TransparentTransfer,
            AppId::new(2, [0xAA; 32]),
            payload,
        );
        assert_ne!(msg1.signing_digest(), msg2.signing_digest());
    }

    #[test]
    fn intent_message_borsh_roundtrip() {
        let msg = IntentMessage::new(
            IntentScope::BridgeAttestation,
            AppId::new(100, [0xBB; 32]),
            vec![10, 20, 30, 40],
        );
        let encoded = borsh::to_vec(&msg).unwrap();
        let decoded: IntentMessage = borsh::from_slice(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn app_id_borsh_roundtrip() {
        let app_id = AppId::new(255, [0xFF; 32]);
        let encoded = borsh::to_vec(&app_id).unwrap();
        let decoded: AppId = borsh::from_slice(&encoded).unwrap();
        assert_eq!(app_id, decoded);
    }

    #[test]
    fn intent_scope_repr_stable() {
        // Ensure repr(u8) values match architecture.md §2.2
        assert_eq!(IntentScope::TransparentTransfer as u8, 0);
        assert_eq!(IntentScope::SystemEmission as u8, 1);
        assert_eq!(IntentScope::Faucet as u8, 2);
        assert_eq!(IntentScope::NarwhalBlock as u8, 10);
        assert_eq!(IntentScope::BridgeAttestation as u8, 20);
    }
}
