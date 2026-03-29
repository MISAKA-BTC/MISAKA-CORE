//! # MISAKA P2P Payload Types
//!
//! Enumerates every wire message type in the MISAKA protocol.
//! Each message type maps to an overflow policy and a flow subscription.
//!
//! All messages are PQ-AEAD encrypted on the wire; these types describe
//! the *decrypted* inner payload.

use serde::{Deserialize, Serialize};

/// Every distinct message type in the MISAKA P2P protocol.
///
/// Naming convention: `<Noun><Verb>` to match Kaspa's style while
/// covering MISAKA's additional PQ/shielded features.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum MisakaPayloadType {
    // ── Handshake & Session ──
    Hello = 0x0001,
    HelloAck = 0x0002,
    Reject = 0x0003,
    Ping = 0x0004,
    Pong = 0x0005,

    // ── Block Relay ──
    InvRelayBlock = 0x0100,
    RequestRelayBlocks = 0x0101,
    RelayBlock = 0x0102,
    NewBlockTemplate = 0x0103,

    // ── Transaction Relay ──
    InvTransactions = 0x0200,
    RequestTransactions = 0x0201,
    Transaction = 0x0202,
    TransactionNotFound = 0x0203,

    // ── IBD (Initial Block Download) ──
    RequestHeaders = 0x0300,
    Headers = 0x0301,
    RequestIbdBlocks = 0x0302,
    IbdBlock = 0x0303,
    DoneIbdBlocks = 0x0304,
    RequestIbdChainBlockLocator = 0x0305,
    IbdChainBlockLocator = 0x0306,
    RequestPruningPointProof = 0x0307,
    PruningPointProof = 0x0308,
    RequestPruningPointUtxoSet = 0x0309,
    PruningPointUtxoSetChunk = 0x030A,
    DonePruningPointUtxoSet = 0x030B,
    RequestAntipast = 0x030C,
    Antipast = 0x030D,

    // ── Peer Discovery ──
    RequestAddresses = 0x0400,
    Addresses = 0x0401,
    RequestPeerInfo = 0x0402,
    PeerInfo = 0x0403,

    // ── DAG-Specific ──
    RequestDagTips = 0x0500,
    DagTips = 0x0501,
    RequestBlueScore = 0x0502,
    BlueScore = 0x0503,
    NotifyVirtualChange = 0x0504,
    VirtualChange = 0x0505,

    // ── Shielded Pool (PQ-native) ──
    ShieldedTx = 0x0600,
    RequestDecoySet = 0x0601,
    DecoySet = 0x0602,
    ShieldedNullifierBroadcast = 0x0603,

    // ── Validator Network (PQ-authenticated) ──
    ValidatorBftMessage = 0x0700,
    ValidatorHeartbeat = 0x0701,
    ValidatorRotationProposal = 0x0702,
    ValidatorRotationAck = 0x0703,

    // ── PQ Re-Keying ──
    RekeyProposal = 0x0800,
    RekeyComplete = 0x0801,
}

impl MisakaPayloadType {
    /// Classify message for overflow handling in the router.
    ///
    /// - `Drop`: Inventory messages — no harm if some are lost.
    /// - `Disconnect`: Everything else — losing these breaks protocol.
    pub fn overflow_policy(self) -> OverflowPolicy {
        match self {
            MisakaPayloadType::InvRelayBlock | MisakaPayloadType::InvTransactions => {
                OverflowPolicy::Drop
            }
            _ => OverflowPolicy::Disconnect,
        }
    }

    /// Whether this message type requires PQ-AEAD encryption.
    /// Only `Hello` / `HelloAck` travel in plaintext (they establish the session).
    pub fn requires_encryption(self) -> bool {
        !matches!(self, MisakaPayloadType::Hello | MisakaPayloadType::HelloAck)
    }

    /// Whether this is a request that expects a response.
    pub fn is_request(self) -> bool {
        matches!(
            self,
            MisakaPayloadType::Ping
                | MisakaPayloadType::RequestRelayBlocks
                | MisakaPayloadType::RequestTransactions
                | MisakaPayloadType::RequestHeaders
                | MisakaPayloadType::RequestIbdBlocks
                | MisakaPayloadType::RequestIbdChainBlockLocator
                | MisakaPayloadType::RequestPruningPointProof
                | MisakaPayloadType::RequestPruningPointUtxoSet
                | MisakaPayloadType::RequestAntipast
                | MisakaPayloadType::RequestAddresses
                | MisakaPayloadType::RequestPeerInfo
                | MisakaPayloadType::RequestDagTips
                | MisakaPayloadType::RequestBlueScore
                | MisakaPayloadType::RequestDecoySet
        )
    }

    /// Human-readable name for logging.
    pub fn name(self) -> &'static str {
        match self {
            MisakaPayloadType::Hello => "Hello",
            MisakaPayloadType::HelloAck => "HelloAck",
            MisakaPayloadType::Reject => "Reject",
            MisakaPayloadType::Ping => "Ping",
            MisakaPayloadType::Pong => "Pong",
            MisakaPayloadType::InvRelayBlock => "InvRelayBlock",
            MisakaPayloadType::RequestRelayBlocks => "RequestRelayBlocks",
            MisakaPayloadType::RelayBlock => "RelayBlock",
            MisakaPayloadType::NewBlockTemplate => "NewBlockTemplate",
            MisakaPayloadType::InvTransactions => "InvTransactions",
            MisakaPayloadType::RequestTransactions => "RequestTransactions",
            MisakaPayloadType::Transaction => "Transaction",
            MisakaPayloadType::TransactionNotFound => "TransactionNotFound",
            MisakaPayloadType::RequestHeaders => "RequestHeaders",
            MisakaPayloadType::Headers => "Headers",
            MisakaPayloadType::RequestIbdBlocks => "RequestIbdBlocks",
            MisakaPayloadType::IbdBlock => "IbdBlock",
            MisakaPayloadType::DoneIbdBlocks => "DoneIbdBlocks",
            MisakaPayloadType::RequestIbdChainBlockLocator => "RequestIbdChainBlockLocator",
            MisakaPayloadType::IbdChainBlockLocator => "IbdChainBlockLocator",
            MisakaPayloadType::RequestPruningPointProof => "RequestPruningPointProof",
            MisakaPayloadType::PruningPointProof => "PruningPointProof",
            MisakaPayloadType::RequestPruningPointUtxoSet => "RequestPruningPointUtxoSet",
            MisakaPayloadType::PruningPointUtxoSetChunk => "PruningPointUtxoSetChunk",
            MisakaPayloadType::DonePruningPointUtxoSet => "DonePruningPointUtxoSet",
            MisakaPayloadType::RequestAntipast => "RequestAntipast",
            MisakaPayloadType::Antipast => "Antipast",
            MisakaPayloadType::RequestAddresses => "RequestAddresses",
            MisakaPayloadType::Addresses => "Addresses",
            MisakaPayloadType::RequestPeerInfo => "RequestPeerInfo",
            MisakaPayloadType::PeerInfo => "PeerInfo",
            MisakaPayloadType::RequestDagTips => "RequestDagTips",
            MisakaPayloadType::DagTips => "DagTips",
            MisakaPayloadType::RequestBlueScore => "RequestBlueScore",
            MisakaPayloadType::BlueScore => "BlueScore",
            MisakaPayloadType::NotifyVirtualChange => "NotifyVirtualChange",
            MisakaPayloadType::VirtualChange => "VirtualChange",
            MisakaPayloadType::ShieldedTx => "ShieldedTx",
            MisakaPayloadType::RequestDecoySet => "RequestDecoySet",
            MisakaPayloadType::DecoySet => "DecoySet",
            MisakaPayloadType::ShieldedNullifierBroadcast => "ShieldedNullifierBroadcast",
            MisakaPayloadType::ValidatorBftMessage => "ValidatorBftMessage",
            MisakaPayloadType::ValidatorHeartbeat => "ValidatorHeartbeat",
            MisakaPayloadType::ValidatorRotationProposal => "ValidatorRotationProposal",
            MisakaPayloadType::ValidatorRotationAck => "ValidatorRotationAck",
            MisakaPayloadType::RekeyProposal => "RekeyProposal",
            MisakaPayloadType::RekeyComplete => "RekeyComplete",
        }
    }
}

/// Router behaviour when a per-flow channel is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverflowPolicy {
    /// Silently drop the message (safe for inv-type gossip).
    Drop,
    /// Disconnect the peer (critical messages must not be lost).
    Disconnect,
}

/// Wire-format message wrapper.
///
/// After PQ-AEAD decryption, every message is deserialized into this
/// envelope. The `response_id` enables request–response correlation
/// (0 = unsolicited / broadcast).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MisakaMessage {
    /// Message type discriminator.
    pub msg_type: MisakaPayloadType,
    /// For request–response pairing; 0 for broadcasts.
    pub response_id: u32,
    /// Serialized inner payload (bincode or JSON depending on message).
    pub payload: Vec<u8>,
}

/// Sentinel value: no request/response correlation.
pub const BLANK_ROUTE_ID: u32 = 0;

impl MisakaMessage {
    pub fn new(msg_type: MisakaPayloadType, payload: Vec<u8>) -> Self {
        Self {
            msg_type,
            response_id: BLANK_ROUTE_ID,
            payload,
        }
    }

    pub fn with_response_id(mut self, id: u32) -> Self {
        self.response_id = id;
        self
    }

    /// Create a Reject message.
    pub fn reject(reason: &str) -> Self {
        Self::new(
            MisakaPayloadType::Reject,
            reason.as_bytes().to_vec(),
        )
    }
}
