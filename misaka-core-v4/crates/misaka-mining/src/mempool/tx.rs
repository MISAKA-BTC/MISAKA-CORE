//! Transaction handling policies.

/// Whether orphan transactions should be accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Orphan {
    /// Accept orphans and add to orphan pool.
    Allowed,
    /// Reject orphan transactions.
    Forbidden,
}

/// Transaction insertion priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    /// Normal priority (from P2P relay).
    Low,
    /// High priority (from local RPC).
    High,
}

/// Replace-by-fee policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RbfPolicy {
    /// No RBF allowed.
    Forbidden,
    /// Standard RBF (must pay higher fee).
    Allowed,
    /// Full RBF (always replace regardless of opt-in).
    FullRbf,
}

/// Reason for removing a transaction from the mempool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxRemovalReason {
    /// Included in a block.
    BlockInclusion,
    /// Replaced by higher-fee transaction.
    ReplacedByFee,
    /// Evicted for low fee rate.
    Evicted,
    /// Expired (too old).
    Expired,
    /// Double-spend detected.
    DoubleSpend,
    /// Manual removal via RPC.
    Manual,
    /// Reorg invalidation.
    Reorg,
}
