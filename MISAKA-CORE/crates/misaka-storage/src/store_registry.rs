//! # Store Prefix Registry
//!
//! Every distinct data store gets a unique prefix byte for namespacing
//! within a single RocksDB instance. This follows Kaspa's
//! `DatabaseStorePrefixes` pattern.

/// Unique prefix byte for each store type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum StorePrefixes {
    // ── Block Data ──
    Headers = 0x01,
    BlockBodies = 0x02,
    BlockStatus = 0x03,
    BlockTransactions = 0x04,

    // ── DAG Structure ──
    GhostdagData = 0x10,
    GhostdagCompact = 0x11,
    RelationsParents = 0x12,
    RelationsChildren = 0x13,
    Reachability = 0x14,
    ReachabilityTreeChildren = 0x15,
    ReachabilityFutureCovering = 0x16,
    ReachabilityRelations = 0x17,
    DagTips = 0x18,
    SelectedChain = 0x19,

    // ── UTXO ──
    UtxoSet = 0x20,
    UtxoByAddress = 0x21,
    UtxoMultiset = 0x22,
    UtxoDiffs = 0x23,
    UtxoAcceptanceData = 0x24,

    // ── Pruning ──
    PruningPoint = 0x30,
    PruningPointUtxoSet = 0x31,
    PruningProof = 0x32,
    PruningCandidates = 0x33,

    // ── Shielded Pool (PQ) ──
    ShieldedCommitments = 0x40,
    ShieldedNullifiers = 0x41,
    ShieldedMerkleTree = 0x42,
    ShieldedNotes = 0x43,

    // ── Transaction Index ──
    TxIndex = 0x50,
    TxAcceptingBlock = 0x51,

    // ── Validator State ──
    ValidatorRegistry = 0x60,
    ValidatorStake = 0x61,
    ValidatorScores = 0x62,
    ValidatorRotation = 0x63,

    // ── Chain Metadata ──
    VirtualState = 0x70,
    ChainInfo = 0x71,
    ChainCheckpoint = 0x72,

    // ── WAL / Recovery ──
    WriteAheadLog = 0x80,
    JournalIndex = 0x81,

    // ── Separator (used in sub-bucket keys) ──
    Separator = 0xFF,
}

impl From<StorePrefixes> for u8 {
    fn from(p: StorePrefixes) -> u8 {
        p as u8
    }
}

impl TryFrom<u8> for StorePrefixes {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, ()> {
        match value {
            0x01 => Ok(Self::Headers),
            0x02 => Ok(Self::BlockBodies),
            0x03 => Ok(Self::BlockStatus),
            0x04 => Ok(Self::BlockTransactions),
            0x10 => Ok(Self::GhostdagData),
            0x11 => Ok(Self::GhostdagCompact),
            0x12 => Ok(Self::RelationsParents),
            0x13 => Ok(Self::RelationsChildren),
            0x14 => Ok(Self::Reachability),
            0x15 => Ok(Self::ReachabilityTreeChildren),
            0x16 => Ok(Self::ReachabilityFutureCovering),
            0x17 => Ok(Self::ReachabilityRelations),
            0x18 => Ok(Self::DagTips),
            0x19 => Ok(Self::SelectedChain),
            0x20 => Ok(Self::UtxoSet),
            0x21 => Ok(Self::UtxoByAddress),
            0x22 => Ok(Self::UtxoMultiset),
            0x23 => Ok(Self::UtxoDiffs),
            0x24 => Ok(Self::UtxoAcceptanceData),
            0x30 => Ok(Self::PruningPoint),
            0x31 => Ok(Self::PruningPointUtxoSet),
            0x32 => Ok(Self::PruningProof),
            0x33 => Ok(Self::PruningCandidates),
            0x40 => Ok(Self::ShieldedCommitments),
            0x41 => Ok(Self::ShieldedNullifiers),
            0x42 => Ok(Self::ShieldedMerkleTree),
            0x43 => Ok(Self::ShieldedNotes),
            0x50 => Ok(Self::TxIndex),
            0x51 => Ok(Self::TxAcceptingBlock),
            0x60 => Ok(Self::ValidatorRegistry),
            0x61 => Ok(Self::ValidatorStake),
            0x62 => Ok(Self::ValidatorScores),
            0x63 => Ok(Self::ValidatorRotation),
            0x70 => Ok(Self::VirtualState),
            0x71 => Ok(Self::ChainInfo),
            0x72 => Ok(Self::ChainCheckpoint),
            0x80 => Ok(Self::WriteAheadLog),
            0x81 => Ok(Self::JournalIndex),
            0xFF => Ok(Self::Separator),
            _ => Err(()),
        }
    }
}

impl StorePrefixes {
    /// Get the single-byte prefix for DB key construction.
    pub fn prefix_bytes(self) -> Vec<u8> {
        vec![self as u8]
    }
}
