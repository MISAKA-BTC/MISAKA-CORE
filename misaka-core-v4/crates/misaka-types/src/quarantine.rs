//! Quarantine & Finality types — shared across all crates.
//!
//! # No-Rollback Architecture
//!
//! These types form the foundation of MISAKA's quarantine-first,
//! rollback-free design. Instead of reverting chain history,
//! suspicious data is isolated via QuarantineEntry and the chain
//! continues forward.

use serde::{Deserialize, Serialize};

pub type Hash = [u8; 32];

// ═══════════════════════════════════════════════════════════════
//  FinalityLevel — 5-stage confirmation for wallet / RPC / explorer
// ═══════════════════════════════════════════════════════════════

/// Transaction / block confirmation stage.
///
/// Wallet, explorer, and RPC all use this enum consistently.
/// The stages form a strict partial order: each stage implies
/// all previous stages.
///
/// ```text
/// Pending → Seen → Ordered → Confirmed → EconomicallyFinal
///   (0)      (1)     (2)        (3)            (4)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum FinalityLevel {
    /// In mempool, not yet in any DAG block.
    Pending = 0,
    /// Included in a DAG block, but may not be on the SPC.
    Seen = 1,
    /// On the Selected Parent Chain, DAG total order position fixed.
    Ordered = 2,
    /// confirmation_depth >= CONFIRMATION_THRESHOLD (e.g. 10).
    /// Safe for everyday payments.
    Confirmed = 3,
    /// 2/3 validator attestation. Irreversible.
    EconomicallyFinal = 4,
}

impl FinalityLevel {
    /// Default confirmation threshold for `Confirmed` level.
    pub const CONFIRMATION_THRESHOLD: u64 = 10;

    /// Compute finality level from observable state.
    pub fn from_state(
        _in_mempool: bool,
        in_dag_block: bool,
        on_vspc: bool,
        confirmation_depth: u64,
        economically_final: bool,
    ) -> Self {
        if economically_final {
            Self::EconomicallyFinal
        } else if confirmation_depth >= Self::CONFIRMATION_THRESHOLD {
            Self::Confirmed
        } else if on_vspc {
            Self::Ordered
        } else if in_dag_block {
            Self::Seen
        } else {
            Self::Pending
        }
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Seen => "seen",
            Self::Ordered => "ordered",
            Self::Confirmed => "confirmed",
            Self::EconomicallyFinal => "economically_final",
        }
    }

    /// Is this finality level safe for everyday payments?
    pub fn is_safe_for_payment(&self) -> bool {
        *self >= Self::Confirmed
    }

    /// Is this finality level irreversible?
    pub fn is_irreversible(&self) -> bool {
        *self == Self::EconomicallyFinal
    }
}

impl std::fmt::Display for FinalityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ═══════════════════════════════════════════════════════════════
//  QuarantineType
// ═══════════════════════════════════════════════════════════════

/// Category of quarantined entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuarantineType {
    Block,
    Tx,
    Peer,
    BridgeEvent,
    Snapshot,
}

impl std::fmt::Display for QuarantineType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Block => write!(f, "block"),
            Self::Tx => write!(f, "tx"),
            Self::Peer => write!(f, "peer"),
            Self::BridgeEvent => write!(f, "bridge_event"),
            Self::Snapshot => write!(f, "snapshot"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  QuarantineReason — exhaustive quarantine trigger reasons
// ═══════════════════════════════════════════════════════════════

/// Why an entity was quarantined.
///
/// Every variant maps to a specific validation failure.
/// No quarantine happens without an explicit reason.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QuarantineReason {
    // ── Block reasons ──
    HeaderValidationFailed(String),
    GhostDagCalculationError(String),
    KClusterViolation {
        anticone_size: u64,
        k: u64,
    },
    MergesetOverflow {
        size: usize,
        max: usize,
    },
    FutureBlock {
        block_time_ms: u64,
        local_time_ms: u64,
        max_offset_ms: u64,
    },
    ProposerIneligible {
        epoch: u64,
    },
    InvalidStateTransition(String),
    ParentTooOld {
        parent_score: u64,
        header_score: u64,
    },
    DuplicateBlock,

    // ── TX reasons ──
    SpendTagConflict {
        tag_hex: String,
        conflict_source: String,
    },
    ZkpVerificationFailed(String),
    ZkpBudgetExceeded {
        spent_us: u64,
        budget_us: u64,
    },
    DoubleSpendAttempt {
        tag_hex: String,
    },
    TxStructuralError(String),

    // ── Peer reasons ──
    PeerScoreBelowThreshold {
        score: i64,
        threshold: i64,
    },
    PeerProtocolViolation(String),
    PeerStaleChainTip {
        peer_score: u64,
        local_score: u64,
        gap: u64,
    },
    PeerRateLimitExceeded,

    // ── Bridge reasons ──
    BridgeAccountingMismatch {
        expected: u64,
        actual: u64,
    },
    BridgeCommitteeSignatureFailed(String),
    BridgeUnknownAsset(String),
    BridgeReplayDetected(String),

    // ── Snapshot reasons ──
    SnapshotHashMismatch {
        expected: Hash,
        actual: Hash,
    },
    SnapshotSignatureInvalid(String),
    SnapshotStateRootMismatch {
        expected: Hash,
        computed: Hash,
    },

    // ── Operator action ──
    ManualQuarantine {
        reason: String,
        operator: String,
    },
}

impl std::fmt::Display for QuarantineReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeaderValidationFailed(s) => write!(f, "header validation failed: {}", s),
            Self::GhostDagCalculationError(s) => write!(f, "GHOSTDAG error: {}", s),
            Self::KClusterViolation { anticone_size, k } => {
                write!(
                    f,
                    "k-cluster violation: anticone {} > k={}",
                    anticone_size, k
                )
            }
            Self::MergesetOverflow { size, max } => {
                write!(f, "mergeset overflow: {} > {}", size, max)
            }
            Self::FutureBlock {
                block_time_ms,
                local_time_ms,
                max_offset_ms,
            } => {
                write!(
                    f,
                    "future block: block_time={} local={} max_offset={}",
                    block_time_ms, local_time_ms, max_offset_ms
                )
            }
            Self::ProposerIneligible { epoch } => {
                write!(f, "proposer ineligible at epoch {}", epoch)
            }
            Self::InvalidStateTransition(s) => write!(f, "invalid state transition: {}", s),
            Self::ParentTooOld {
                parent_score,
                header_score,
            } => {
                write!(
                    f,
                    "parent too old: parent_score={} header_score={}",
                    parent_score, header_score
                )
            }
            Self::DuplicateBlock => write!(f, "duplicate block"),
            Self::SpendTagConflict {
                tag_hex,
                conflict_source,
            } => {
                write!(
                    f,
                    "spend-tag conflict: {} ({})",
                    tag_hex, conflict_source
                )
            }
            Self::ZkpVerificationFailed(s) => write!(f, "ZKP verification failed: {}", s),
            Self::ZkpBudgetExceeded {
                spent_us,
                budget_us,
            } => {
                write!(f, "ZKP budget exceeded: {}us > {}us", spent_us, budget_us)
            }
            Self::DoubleSpendAttempt { tag_hex } => {
                write!(f, "double-spend attempt: spend-tag {}", tag_hex)
            }
            Self::TxStructuralError(s) => write!(f, "TX structural error: {}", s),
            Self::PeerScoreBelowThreshold { score, threshold } => {
                write!(f, "peer score {} below threshold {}", score, threshold)
            }
            Self::PeerProtocolViolation(s) => write!(f, "peer protocol violation: {}", s),
            Self::PeerStaleChainTip { gap, .. } => write!(f, "peer stale tip: gap={}", gap),
            Self::PeerRateLimitExceeded => write!(f, "peer rate limit exceeded"),
            Self::BridgeAccountingMismatch { expected, actual } => {
                write!(
                    f,
                    "bridge accounting mismatch: expected={} actual={}",
                    expected, actual
                )
            }
            Self::BridgeCommitteeSignatureFailed(s) => {
                write!(f, "bridge committee sig failed: {}", s)
            }
            Self::BridgeUnknownAsset(s) => write!(f, "bridge unknown asset: {}", s),
            Self::BridgeReplayDetected(s) => write!(f, "bridge replay: {}", s),
            Self::SnapshotHashMismatch { .. } => write!(f, "snapshot hash mismatch"),
            Self::SnapshotSignatureInvalid(s) => write!(f, "snapshot signature invalid: {}", s),
            Self::SnapshotStateRootMismatch { .. } => write!(f, "snapshot state root mismatch"),
            Self::ManualQuarantine { reason, operator } => {
                write!(f, "manual quarantine by {}: {}", operator, reason)
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  QuarantineEntry
// ═══════════════════════════════════════════════════════════════

/// A single quarantine record. Persisted to quarantine store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    /// Entity identifier (block hash, tx hash, peer id, etc.)
    pub id: Hash,
    /// What kind of entity is quarantined.
    pub entry_type: QuarantineType,
    /// Why it was quarantined.
    pub reason: QuarantineReason,
    /// Peer that sent the problematic data (if known).
    pub source_peer: Option<Hash>,
    /// When quarantine was applied (unix timestamp ms).
    pub quarantined_at_ms: u64,
    /// Whether an operator has released this entry.
    pub released: bool,
    /// When it was released.
    pub released_at_ms: Option<u64>,
    /// Who released it.
    pub released_by: Option<String>,
    /// Auto-release timestamp (peer bans only).
    pub auto_release_at_ms: Option<u64>,
    /// Cumulative offense count for this entity.
    pub offense_count: u32,
}

impl QuarantineEntry {
    pub fn new(
        id: Hash,
        entry_type: QuarantineType,
        reason: QuarantineReason,
        source_peer: Option<Hash>,
        now_ms: u64,
    ) -> Self {
        Self {
            id,
            entry_type,
            reason,
            source_peer,
            quarantined_at_ms: now_ms,
            released: false,
            released_at_ms: None,
            released_by: None,
            auto_release_at_ms: None,
            offense_count: 1,
        }
    }

    /// Is this entry currently active (not released, not expired)?
    pub fn is_active(&self, now_ms: u64) -> bool {
        if self.released {
            return false;
        }
        if let Some(auto_release) = self.auto_release_at_ms {
            if now_ms >= auto_release {
                return false;
            }
        }
        true
    }
}

// ═══════════════════════════════════════════════════════════════
//  BlockAcceptanceState / TxAcceptanceState
// ═══════════════════════════════════════════════════════════════

/// Block's acceptance state in the DAG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockAcceptanceState {
    /// Received, GhostDAG data computed, in DAG.
    Accepted,
    /// On VSPC, TXs applied to virtual state.
    Applied,
    /// confirmation_depth >= threshold.
    Confirmed { depth: u64 },
    /// In a 2/3-attested checkpoint.
    EconomicallyFinal { epoch: u64 },
    /// In quarantine store.
    Quarantined { reason: String },
    /// Permanently invalid.
    Invalid { reason: String },
}

/// Transaction's acceptance state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TxAcceptanceState {
    /// In mempool.
    Pending,
    /// In a DAG block.
    InBlock { block_hash: Hash },
    /// Accepted by virtual state (no conflict).
    Accepted,
    /// Rejected by virtual state (spend-tag conflict).
    Rejected { reason: String },
    /// In quarantine.
    Quarantined { reason: String },
    /// In a finalized epoch.
    Final { epoch: u64, block_hash: Hash },
}

// ═══════════════════════════════════════════════════════════════
//  BridgeSafetyState
// ═══════════════════════════════════════════════════════════════

/// Bridge operational state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BridgeSafetyState {
    /// Normal operation.
    Active,
    /// Paused by operator or auto-trigger.
    Paused {
        reason: String,
        since_ms: u64,
        origin: PauseOrigin,
    },
    /// Partially degraded (some functions restricted).
    Degraded { issues: Vec<String> },
}

/// Who / what triggered the bridge pause.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PauseOrigin {
    Operator(String),
    AutoAccountingMismatch,
    AutoFinalityLag,
    AutoCommitteeFailure,
    AutoStateCorruption,
}

impl BridgeSafetyState {
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn is_paused(&self) -> bool {
        matches!(self, Self::Paused { .. })
    }
}

// ═══════════════════════════════════════════════════════════════
//  SnapshotTrustState
// ═══════════════════════════════════════════════════════════════

/// Trust state of a downloaded snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SnapshotTrustState {
    /// Hash and signature verified, state root matches.
    Verified {
        verified_at_ms: u64,
        state_root: Hash,
    },
    /// Downloaded but not yet verified.
    Pending { downloaded_at_ms: u64 },
    /// Verification failed.
    Untrusted { reason: String, detected_at_ms: u64 },
    /// No snapshot available.
    Absent,
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finality_level_ordering() {
        assert!(FinalityLevel::Pending < FinalityLevel::Seen);
        assert!(FinalityLevel::Seen < FinalityLevel::Ordered);
        assert!(FinalityLevel::Ordered < FinalityLevel::Confirmed);
        assert!(FinalityLevel::Confirmed < FinalityLevel::EconomicallyFinal);
    }

    #[test]
    fn test_finality_from_state() {
        assert_eq!(
            FinalityLevel::from_state(true, false, false, 0, false),
            FinalityLevel::Pending
        );
        assert_eq!(
            FinalityLevel::from_state(true, true, false, 0, false),
            FinalityLevel::Seen
        );
        assert_eq!(
            FinalityLevel::from_state(true, true, true, 5, false),
            FinalityLevel::Ordered
        );
        assert_eq!(
            FinalityLevel::from_state(true, true, true, 15, false),
            FinalityLevel::Confirmed
        );
        assert_eq!(
            FinalityLevel::from_state(true, true, true, 200, true),
            FinalityLevel::EconomicallyFinal
        );
    }

    #[test]
    fn test_finality_payment_safety() {
        assert!(!FinalityLevel::Pending.is_safe_for_payment());
        assert!(!FinalityLevel::Seen.is_safe_for_payment());
        assert!(!FinalityLevel::Ordered.is_safe_for_payment());
        assert!(FinalityLevel::Confirmed.is_safe_for_payment());
        assert!(FinalityLevel::EconomicallyFinal.is_safe_for_payment());
    }

    #[test]
    fn test_finality_irreversibility() {
        assert!(!FinalityLevel::Confirmed.is_irreversible());
        assert!(FinalityLevel::EconomicallyFinal.is_irreversible());
    }

    #[test]
    fn test_quarantine_entry_active() {
        let entry = QuarantineEntry::new(
            [0xAA; 32],
            QuarantineType::Block,
            QuarantineReason::DuplicateBlock,
            None,
            1000,
        );
        assert!(entry.is_active(2000));
    }

    #[test]
    fn test_quarantine_entry_released() {
        let mut entry = QuarantineEntry::new(
            [0xBB; 32],
            QuarantineType::Tx,
            QuarantineReason::DoubleSpendAttempt {
                tag_hex: "ab".into(),
            },
            None,
            1000,
        );
        entry.released = true;
        assert!(!entry.is_active(2000));
    }

    #[test]
    fn test_quarantine_entry_auto_expired() {
        let mut entry = QuarantineEntry::new(
            [0xCC; 32],
            QuarantineType::Peer,
            QuarantineReason::PeerRateLimitExceeded,
            None,
            1000,
        );
        entry.auto_release_at_ms = Some(5000);
        assert!(entry.is_active(3000));
        assert!(!entry.is_active(6000));
    }

    #[test]
    fn test_bridge_safety_state() {
        let active = BridgeSafetyState::Active;
        assert!(active.is_active());
        assert!(!active.is_paused());

        let paused = BridgeSafetyState::Paused {
            reason: "test".into(),
            since_ms: 0,
            origin: PauseOrigin::Operator("op".into()),
        };
        assert!(!paused.is_active());
        assert!(paused.is_paused());
    }

    #[test]
    fn test_quarantine_reason_display() {
        let reason = QuarantineReason::KClusterViolation {
            anticone_size: 25,
            k: 18,
        };
        let s = format!("{}", reason);
        assert!(s.contains("k-cluster"));
        assert!(s.contains("25"));
    }
}
