//! Database store prefix registry for MISAKA.
//!
//! Each store gets a unique byte prefix to avoid key collisions
//! within a single RocksDB instance.

pub const SEPARATOR: u8 = u8::MAX;

/// All known store prefixes in MISAKA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DatabaseStorePrefixes {
    // ── Consensus Core ─────────────────────────────────────────
    AcceptanceData = 1,
    BlockTransactions = 2,
    Ghostdag = 5,
    GhostdagCompact = 6,
    HeadersSelectedTip = 7,
    Headers = 8,
    HeadersCompact = 9,
    PastPruningPoints = 10,
    PruningUtxoset = 11,
    PruningUtxosetPosition = 12,
    PruningPoint = 13,
    Reachability = 15,
    ReachabilityReindexRoot = 16,
    ReachabilityRelations = 17,
    RelationsParents = 18,
    RelationsChildren = 19,
    ChainHashByIndex = 20,
    ChainIndexByHash = 21,
    ChainHighestIndex = 22,
    Statuses = 23,
    Tips = 24,
    UtxoDiffs = 25,
    UtxoMultisets = 26,
    VirtualUtxoset = 27,
    VirtualState = 28,
    PruningSamples = 29,
    ReachabilityTreeChildren = 30,
    ReachabilityFutureCoveringSet = 31,
    BlockDepth = 32,
    DaaScores = 33,

    // ── MISAKA-specific ────────────────────────────────────────
    /// Shielded pool spent set
    ShieldedSpendTags = 64,
    /// Shielded commitment tree
    ShieldedCommitments = 65,
    /// Shielded notes
    ShieldedNotes = 66,
    /// Validator set snapshots
    ValidatorSet = 67,
    /// Staking delegations
    Delegations = 68,
    /// PQC key images
    PqcKeyImages = 69,
    /// Governance proposals
    Governance = 70,
    /// Bridge state
    BridgeState = 71,
    /// Key delegation registry (capability system)
    KeyDelegations = 72,
    /// Cryptographic state metadata per address
    CryptoStateMetadata = 73,
    /// Unified spend uniqueness tags (cross-domain)
    SpendUniqueness = 74,

    // ── Components ─────────────────────────────────────────────
    Addresses = 128,
    BannedAddresses = 129,

    // ── Indexes ────────────────────────────────────────────────
    UtxoIndex = 192,
    UtxoIndexTips = 193,
    CirculatingSupply = 194,

    // ── Separator ──────────────────────────────────────────────
    Separator = 255,
}

impl From<DatabaseStorePrefixes> for u8 {
    fn from(p: DatabaseStorePrefixes) -> u8 {
        p as u8
    }
}

impl DatabaseStorePrefixes {
    /// Returns the prefix as a single-byte slice for store construction.
    pub fn as_prefix(&self) -> Vec<u8> {
        vec![*self as u8]
    }

    /// Returns the prefix with a bucket byte appended (for leveled stores).
    pub fn with_bucket(&self, bucket: u8) -> Vec<u8> {
        vec![*self as u8, bucket]
    }
}
