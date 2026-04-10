//! Intent payload types for each IntentScope (Phase 2a/2b).
//!
//! Each struct here is borsh-serialized and used as the `payload`
//! field of `IntentMessage`. One payload type per `IntentScope`.
//!
//! See `docs/architecture.md` Section 2.2 for scope definitions.

use borsh::{BorshDeserialize, BorshSerialize};

/// Payload for `IntentScope::NarwhalBlock`.
///
/// Signed by the block proposer to authenticate block headers.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct NarwhalBlockPayload {
    pub round: u32,
    pub author: u32,
    pub epoch: u64,
    pub timestamp_ms: u64,
    /// SHA3-256 of block content (transactions + ancestors).
    pub content_digest: [u8; 32],
    /// Phase 3 C7: Post-execution state root (MuHash of UTXO set).
    pub state_root: [u8; 32],
}

/// Payload for `IntentScope::BftPrevote`.
///
/// Signed by a validator to cast a prevote in BFT finality.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BftPrevotePayload {
    pub epoch: u64,
    pub round: u64,
    pub checkpoint_digest: [u8; 32],
    pub voter: [u8; 32],
}

/// Payload for `IntentScope::BftPrecommit`.
///
/// Signed by a validator to cast a precommit in BFT finality.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BftPrecommitPayload {
    pub epoch: u64,
    pub round: u64,
    pub checkpoint_digest: [u8; 32],
    pub voter: [u8; 32],
}

/// Payload for `IntentScope::BridgeAttestation`.
///
/// Signed by a relayer to attest a verified burn event on Solana.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BridgeAttestationPayload {
    /// SHA3-256 of the Solana transaction signature.
    pub burn_id: [u8; 32],
    /// Burn amount in base units.
    pub burn_amount: u64,
    /// Solana slot for finality check.
    pub burn_slot: u64,
    /// MISAKA receive address (32 bytes).
    pub misaka_receive_address: [u8; 32],
    /// Replay protection nonce.
    pub nonce: u64,
}

/// Payload for `IntentScope::CheckpointVote`.
///
/// Signed by a validator to vote on a finality checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CheckpointVotePayload {
    pub epoch: u64,
    pub checkpoint_seq: u64,
    pub checkpoint_digest: [u8; 32],
    pub voter: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bft_prevote_payload_borsh_roundtrip() {
        let p = BftPrevotePayload {
            epoch: 42,
            round: 7,
            checkpoint_digest: [0xAA; 32],
            voter: [0xBB; 32],
        };
        let encoded = borsh::to_vec(&p).unwrap();
        let decoded: BftPrevotePayload = borsh::from_slice(&encoded).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn bridge_attestation_payload_borsh_roundtrip() {
        let p = BridgeAttestationPayload {
            burn_id: [0x11; 32],
            burn_amount: 1_000_000_000,
            burn_slot: 12345,
            misaka_receive_address: [0x22; 32],
            nonce: 1,
        };
        let encoded = borsh::to_vec(&p).unwrap();
        let decoded: BridgeAttestationPayload = borsh::from_slice(&encoded).unwrap();
        assert_eq!(p, decoded);
    }
}
