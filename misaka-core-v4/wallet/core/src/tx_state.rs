//! Wallet Transaction State Machine — strict lifecycle management.
//!
//! # Design
//!
//! Every wallet transaction goes through a well-defined lifecycle:
//!
//! ```text
//! PendingLocal → PendingBroadcasted → PendingInBlock → Confirmed
//!                       ↓                    ↓
//!                   Dropped              Conflicting
//! ```
//!
//! UTXOs are **locked** when a transaction claims them as inputs.
//! If the transaction fails (Dropped/Conflicting), locks are released
//! and the UTXOs become spendable again.
//!
//! # Sync Protocol
//!
//! On startup or periodically, `sync_with_node()`:
//! 1. Queries the node for all pending TX hashes.
//! 2. Queries the chain for confirmed TX hashes.
//! 3. Reconciles local state — advancing, dropping, or conflicting as needed.
//! 4. Releases UTXO locks for any dropped/conflicting TXs.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
//  Transaction Status
// ═══════════════════════════════════════════════════════════════

/// Strict transaction lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TxStatus {
    /// Created locally, not yet sent to the node.
    PendingLocal,
    /// Sent to the node's mempool, awaiting block inclusion.
    PendingBroadcasted,
    /// Included in a block, waiting for finality confirmations.
    PendingInBlock {
        /// Block height where this TX was included.
        block_height: u64,
        /// Number of confirmations seen so far.
        confirmations: u64,
    },
    /// Finalized — irreversible.
    Confirmed { block_height: u64 },
    /// Expired from mempool or node rejected after broadcast.
    Dropped { reason: DropReason },
    /// Double-spend detected — another TX spent the same inputs.
    Conflicting {
        /// The conflicting TX hash (if known).
        conflicting_tx: Option<[u8; 32]>,
    },
}

/// Reason a transaction was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DropReason {
    /// Mempool TTL expired.
    MempoolExpired,
    /// Node rejected the transaction.
    NodeRejected,
    /// Network failure during broadcast.
    BroadcastFailed,
    /// Manually cancelled by user.
    UserCancelled,
    /// Chain reorg invalidated the TX.
    ReorgInvalidated,
}

impl TxStatus {
    /// Is this a terminal state (no further transitions possible)?
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            TxStatus::Confirmed { .. } | TxStatus::Dropped { .. } | TxStatus::Conflicting { .. }
        )
    }

    /// Is this TX still in-flight (not yet finalized or failed)?
    pub fn is_pending(&self) -> bool {
        matches!(
            self,
            TxStatus::PendingLocal | TxStatus::PendingBroadcasted | TxStatus::PendingInBlock { .. }
        )
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            TxStatus::PendingLocal => "pending_local",
            TxStatus::PendingBroadcasted => "pending_broadcasted",
            TxStatus::PendingInBlock { .. } => "pending_in_block",
            TxStatus::Confirmed { .. } => "confirmed",
            TxStatus::Dropped { .. } => "dropped",
            TxStatus::Conflicting { .. } => "conflicting",
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  State Transitions
// ═══════════════════════════════════════════════════════════════

/// Events that trigger state transitions.
#[derive(Debug, Clone)]
pub enum TxEvent {
    /// TX was successfully broadcast to node mempool.
    Broadcasted,
    /// Node rejected the broadcast.
    BroadcastRejected,
    /// TX appeared in a block at the given height.
    IncludedInBlock { block_height: u64 },
    /// A new block was added, incrementing confirmations.
    NewConfirmation { current_height: u64 },
    /// TX has enough confirmations to be considered final.
    Finalized { block_height: u64 },
    /// TX disappeared from mempool without being included.
    MempoolExpired,
    /// A conflicting TX was detected on-chain.
    ConflictDetected { conflicting_tx: Option<[u8; 32]> },
    /// Chain reorg invalidated the block containing this TX.
    ReorgRollback,
    /// User manually cancelled (only valid for PendingLocal).
    UserCancel,
}

/// Result of a state transition attempt.
#[derive(Debug)]
pub enum TransitionResult {
    /// Transition succeeded — new status applied.
    Ok(TxStatus),
    /// Transition rejected — invalid for current state.
    Invalid {
        current: TxStatus,
        event: &'static str,
    },
}

/// Required confirmations before a TX is considered finalized.
const FINALITY_CONFIRMATIONS: u64 = 6;

/// Apply a state transition. Returns the new status or an error.
///
/// This is a PURE FUNCTION — no side effects, no I/O.
pub fn apply_transition(current: &TxStatus, event: &TxEvent) -> TransitionResult {
    match (current, event) {
        // PendingLocal transitions
        (TxStatus::PendingLocal, TxEvent::Broadcasted) => {
            TransitionResult::Ok(TxStatus::PendingBroadcasted)
        }
        (TxStatus::PendingLocal, TxEvent::BroadcastRejected) => {
            TransitionResult::Ok(TxStatus::Dropped {
                reason: DropReason::NodeRejected,
            })
        }
        (TxStatus::PendingLocal, TxEvent::UserCancel) => TransitionResult::Ok(TxStatus::Dropped {
            reason: DropReason::UserCancelled,
        }),

        // PendingBroadcasted transitions
        (TxStatus::PendingBroadcasted, TxEvent::IncludedInBlock { block_height }) => {
            TransitionResult::Ok(TxStatus::PendingInBlock {
                block_height: *block_height,
                confirmations: 1,
            })
        }
        (TxStatus::PendingBroadcasted, TxEvent::MempoolExpired) => {
            TransitionResult::Ok(TxStatus::Dropped {
                reason: DropReason::MempoolExpired,
            })
        }
        (TxStatus::PendingBroadcasted, TxEvent::ConflictDetected { conflicting_tx }) => {
            TransitionResult::Ok(TxStatus::Conflicting {
                conflicting_tx: *conflicting_tx,
            })
        }

        // PendingInBlock transitions
        (
            TxStatus::PendingInBlock {
                block_height,
                confirmations: _,
            },
            TxEvent::NewConfirmation { current_height },
        ) => {
            let new_confirmations = current_height.saturating_sub(*block_height) + 1;
            if new_confirmations >= FINALITY_CONFIRMATIONS {
                TransitionResult::Ok(TxStatus::Confirmed {
                    block_height: *block_height,
                })
            } else {
                TransitionResult::Ok(TxStatus::PendingInBlock {
                    block_height: *block_height,
                    confirmations: new_confirmations,
                })
            }
        }
        (TxStatus::PendingInBlock { block_height, .. }, TxEvent::Finalized { .. }) => {
            TransitionResult::Ok(TxStatus::Confirmed {
                block_height: *block_height,
            })
        }
        (TxStatus::PendingInBlock { .. }, TxEvent::ReorgRollback) => {
            // Reorg rolled back the block — TX goes back to broadcasted
            TransitionResult::Ok(TxStatus::PendingBroadcasted)
        }
        (TxStatus::PendingInBlock { .. }, TxEvent::ConflictDetected { conflicting_tx }) => {
            TransitionResult::Ok(TxStatus::Conflicting {
                conflicting_tx: *conflicting_tx,
            })
        }

        // Terminal states — no further transitions
        (status, _) if status.is_terminal() => TransitionResult::Invalid {
            current: *current,
            event: "terminal state",
        },

        // Any other combination is invalid
        (_, _) => TransitionResult::Invalid {
            current: *current,
            event: "unhandled",
        },
    }
}

// ═══════════════════════════════════════════════════════════════
//  UTXO Locking
// ═══════════════════════════════════════════════════════════════

/// UTXO locking state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UtxoLock {
    /// Available for spending.
    Free,
    /// Locked by a pending transaction.
    LockedForTx {
        tx_hash: [u8; 32],
        locked_at_ms: u64,
    },
    /// Permanently spent (confirmed on-chain).
    Spent {
        tx_hash: [u8; 32],
        block_height: u64,
    },
}

/// Outpoint identifier.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outpoint {
    pub tx_hash: [u8; 32],
    pub output_index: u32,
}

// ═══════════════════════════════════════════════════════════════
//  Tracked Transaction
// ═══════════════════════════════════════════════════════════════

/// A wallet-tracked transaction with its full lifecycle state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedTx {
    /// Transaction hash.
    pub tx_hash: [u8; 32],
    /// Current lifecycle status.
    pub status: TxStatus,
    /// Input outpoints consumed by this TX.
    pub inputs: Vec<Outpoint>,
    /// Output amount + addresses created by this TX.
    pub output_count: u32,
    /// Fee paid.
    pub fee: u64,
    /// When this TX was created locally (ms since epoch).
    pub created_at_ms: u64,
    /// When the status last changed (ms since epoch).
    pub last_updated_ms: u64,
}

// ═══════════════════════════════════════════════════════════════
//  Wallet TX Tracker
// ═══════════════════════════════════════════════════════════════

/// Manages the lifecycle of all wallet transactions and UTXO locks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxTracker {
    /// All tracked transactions by hash.
    pub transactions: HashMap<[u8; 32], TrackedTx>,
    /// UTXO locks by outpoint.
    pub utxo_locks: HashMap<Outpoint, UtxoLock>,
    /// Lock timeout (ms) — auto-release locks for stuck PendingLocal TXs.
    pub lock_timeout_ms: u64,
}

/// Default lock timeout: 10 minutes.
const DEFAULT_LOCK_TIMEOUT_MS: u64 = 600_000;

impl Default for TxTracker {
    fn default() -> Self {
        Self {
            transactions: HashMap::new(),
            utxo_locks: HashMap::new(),
            lock_timeout_ms: DEFAULT_LOCK_TIMEOUT_MS,
        }
    }
}

impl TxTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new transaction and lock its input UTXOs.
    pub fn register_tx(
        &mut self,
        tx_hash: [u8; 32],
        inputs: Vec<Outpoint>,
        output_count: u32,
        fee: u64,
        now_ms: u64,
    ) -> Result<(), String> {
        // Check for duplicate
        if self.transactions.contains_key(&tx_hash) {
            return Err("transaction already registered".into());
        }

        // Check all inputs are free
        for input in &inputs {
            match self.utxo_locks.get(input) {
                Some(UtxoLock::LockedForTx {
                    tx_hash: locked_by, ..
                }) => {
                    return Err(format!(
                        "UTXO {}:{} already locked by tx {}",
                        hex::encode(&input.tx_hash[..8]),
                        input.output_index,
                        hex::encode(&locked_by[..8])
                    ));
                }
                Some(UtxoLock::Spent { .. }) => {
                    return Err(format!(
                        "UTXO {}:{} already spent",
                        hex::encode(&input.tx_hash[..8]),
                        input.output_index
                    ));
                }
                _ => {}
            }
        }

        // Lock all inputs
        for input in &inputs {
            self.utxo_locks.insert(
                input.clone(),
                UtxoLock::LockedForTx {
                    tx_hash,
                    locked_at_ms: now_ms,
                },
            );
        }

        self.transactions.insert(
            tx_hash,
            TrackedTx {
                tx_hash,
                status: TxStatus::PendingLocal,
                inputs,
                output_count,
                fee,
                created_at_ms: now_ms,
                last_updated_ms: now_ms,
            },
        );

        Ok(())
    }

    /// Apply an event to a tracked transaction.
    pub fn apply_event(
        &mut self,
        tx_hash: &[u8; 32],
        event: &TxEvent,
        now_ms: u64,
    ) -> Result<TxStatus, String> {
        let tracked = self
            .transactions
            .get(tx_hash)
            .ok_or_else(|| "transaction not found".to_string())?;

        let result = apply_transition(&tracked.status, event);

        match result {
            TransitionResult::Ok(new_status) => {
                // Release locks if TX failed
                if matches!(
                    new_status,
                    TxStatus::Dropped { .. } | TxStatus::Conflicting { .. }
                ) {
                    self.release_locks(tx_hash);
                }

                // Mark UTXOs as permanently spent if confirmed
                if let TxStatus::Confirmed { block_height } = new_status {
                    let inputs = self
                        .transactions
                        .get(tx_hash)
                        .map(|t| t.inputs.clone())
                        .unwrap_or_default();
                    for input in inputs {
                        self.utxo_locks.insert(
                            input,
                            UtxoLock::Spent {
                                tx_hash: *tx_hash,
                                block_height,
                            },
                        );
                    }
                }

                // Update status
                if let Some(tracked) = self.transactions.get_mut(tx_hash) {
                    tracked.status = new_status;
                    tracked.last_updated_ms = now_ms;
                }

                Ok(new_status)
            }
            TransitionResult::Invalid { current, event: ev } => Err(format!(
                "invalid transition: {} + {} (current: {:?})",
                ev,
                std::any::type_name::<TxEvent>(),
                current
            )),
        }
    }

    /// Release all UTXO locks held by a transaction.
    fn release_locks(&mut self, tx_hash: &[u8; 32]) {
        let inputs = self
            .transactions
            .get(tx_hash)
            .map(|t| t.inputs.clone())
            .unwrap_or_default();

        for input in inputs {
            if let Some(UtxoLock::LockedForTx {
                tx_hash: locked_by, ..
            }) = self.utxo_locks.get(&input)
            {
                if locked_by == tx_hash {
                    self.utxo_locks.insert(input, UtxoLock::Free);
                }
            }
        }
    }

    /// Release locks that have timed out (stuck PendingLocal TXs).
    pub fn release_expired_locks(&mut self, now_ms: u64) -> Vec<[u8; 32]> {
        let mut released_txs = Vec::new();

        let expired_txs: Vec<[u8; 32]> = self
            .transactions
            .iter()
            .filter(|(_, tx)| {
                tx.status == TxStatus::PendingLocal
                    && now_ms.saturating_sub(tx.created_at_ms) > self.lock_timeout_ms
            })
            .map(|(hash, _)| *hash)
            .collect();

        for tx_hash in expired_txs {
            self.release_locks(&tx_hash);
            if let Some(tracked) = self.transactions.get_mut(&tx_hash) {
                tracked.status = TxStatus::Dropped {
                    reason: DropReason::MempoolExpired,
                };
                tracked.last_updated_ms = now_ms;
            }
            released_txs.push(tx_hash);
        }

        released_txs
    }

    /// Is a given outpoint available for spending?
    pub fn is_utxo_free(&self, outpoint: &Outpoint) -> bool {
        match self.utxo_locks.get(outpoint) {
            None | Some(UtxoLock::Free) => true,
            _ => false,
        }
    }

    /// Get all pending (in-flight) transactions.
    pub fn pending_txs(&self) -> Vec<&TrackedTx> {
        self.transactions
            .values()
            .filter(|tx| tx.status.is_pending())
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Node Sync / Reconciliation
// ═══════════════════════════════════════════════════════════════

/// Information returned by the node about a transaction.
#[derive(Debug, Clone)]
pub enum NodeTxInfo {
    /// TX is in the mempool.
    InMempool,
    /// TX is in a block at the given height with given confirmations.
    InBlock {
        block_height: u64,
        confirmations: u64,
    },
    /// TX is not found (not in mempool or chain).
    NotFound,
    /// A conflicting TX was found instead.
    Conflicted { conflicting_tx: [u8; 32] },
}

/// Result of a sync operation.
#[derive(Debug, Default)]
pub struct SyncResult {
    /// TXs that were advanced to a new status.
    pub advanced: Vec<([u8; 32], TxStatus)>,
    /// TXs that were dropped (missing from node).
    pub dropped: Vec<[u8; 32]>,
    /// TXs that were marked as conflicting.
    pub conflicted: Vec<[u8; 32]>,
    /// UTXOs that were unlocked.
    pub unlocked_utxos: usize,
}

/// Synchronize wallet TX state with the node.
///
/// This is a PURE FUNCTION on the provided node state. The caller
/// is responsible for actually querying the node and passing the
/// results here.
///
/// # Arguments
/// - `tracker`: Mutable wallet TX tracker.
/// - `node_state`: Map of tx_hash → current node status.
/// - `now_ms`: Current timestamp.
pub fn sync_with_node(
    tracker: &mut TxTracker,
    node_state: &HashMap<[u8; 32], NodeTxInfo>,
    now_ms: u64,
) -> SyncResult {
    let mut result = SyncResult::default();

    // Collect pending TX hashes (avoid borrow conflict)
    let pending_hashes: Vec<[u8; 32]> = tracker
        .transactions
        .values()
        .filter(|tx| tx.status.is_pending())
        .map(|tx| tx.tx_hash)
        .collect();

    for tx_hash in pending_hashes {
        let current_status = match tracker.transactions.get(&tx_hash) {
            Some(tx) => tx.status,
            None => continue,
        };

        let node_info = node_state.get(&tx_hash);

        let event = match (current_status, node_info) {
            // PendingBroadcasted but not found on node → dropped
            (TxStatus::PendingBroadcasted, None | Some(NodeTxInfo::NotFound)) => {
                Some(TxEvent::MempoolExpired)
            }

            // PendingBroadcasted and now in block
            (TxStatus::PendingBroadcasted, Some(NodeTxInfo::InBlock { block_height, .. })) => {
                Some(TxEvent::IncludedInBlock {
                    block_height: *block_height,
                })
            }

            // PendingInBlock and confirmations increasing
            (
                TxStatus::PendingInBlock { .. },
                Some(NodeTxInfo::InBlock {
                    block_height,
                    confirmations,
                }),
            ) => {
                if *confirmations >= FINALITY_CONFIRMATIONS {
                    Some(TxEvent::Finalized {
                        block_height: *block_height,
                    })
                } else {
                    Some(TxEvent::NewConfirmation {
                        current_height: block_height + confirmations,
                    })
                }
            }

            // PendingInBlock but TX disappeared (reorg)
            (TxStatus::PendingInBlock { .. }, None | Some(NodeTxInfo::NotFound)) => {
                Some(TxEvent::ReorgRollback)
            }

            // Any pending + conflict
            (_, Some(NodeTxInfo::Conflicted { conflicting_tx })) => {
                Some(TxEvent::ConflictDetected {
                    conflicting_tx: Some(*conflicting_tx),
                })
            }

            // PendingBroadcasted still in mempool — no change
            (TxStatus::PendingBroadcasted, Some(NodeTxInfo::InMempool)) => None,

            // PendingLocal — not yet broadcast, skip
            (TxStatus::PendingLocal, _) => None,

            _ => None,
        };

        if let Some(ev) = event {
            match tracker.apply_event(&tx_hash, &ev, now_ms) {
                Ok(new_status) => {
                    match &new_status {
                        TxStatus::Dropped { .. } => result.dropped.push(tx_hash),
                        TxStatus::Conflicting { .. } => result.conflicted.push(tx_hash),
                        _ => {}
                    }
                    result.advanced.push((tx_hash, new_status));
                }
                Err(_) => {} // Transition was invalid, skip
            }
        }
    }

    // Release expired locks
    let released = tracker.release_expired_locks(now_ms);
    result.unlocked_utxos = released.len();
    result.dropped.extend(released);

    result
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn outpoint(id: u8, idx: u32) -> Outpoint {
        Outpoint {
            tx_hash: [id; 32],
            output_index: idx,
        }
    }

    #[test]
    fn test_happy_path_lifecycle() {
        let mut tracker = TxTracker::new();
        let tx_hash = [0xAA; 32];
        let inputs = vec![outpoint(1, 0)];

        // Register
        tracker
            .register_tx(tx_hash, inputs.clone(), 2, 100, 1000)
            .expect("register");
        assert_eq!(
            tracker.transactions[&tx_hash].status,
            TxStatus::PendingLocal
        );
        assert!(!tracker.is_utxo_free(&inputs[0]));

        // Broadcast
        let status = tracker
            .apply_event(&tx_hash, &TxEvent::Broadcasted, 2000)
            .expect("broadcast");
        assert_eq!(status, TxStatus::PendingBroadcasted);

        // Included in block
        let status = tracker
            .apply_event(
                &tx_hash,
                &TxEvent::IncludedInBlock { block_height: 10 },
                3000,
            )
            .expect("included");
        assert!(matches!(
            status,
            TxStatus::PendingInBlock {
                block_height: 10,
                confirmations: 1
            }
        ));

        // Finalized
        let status = tracker
            .apply_event(&tx_hash, &TxEvent::Finalized { block_height: 10 }, 4000)
            .expect("finalized");
        assert!(matches!(status, TxStatus::Confirmed { block_height: 10 }));

        // UTXO should be permanently spent
        assert!(matches!(
            tracker.utxo_locks[&inputs[0]],
            UtxoLock::Spent { .. }
        ));
    }

    #[test]
    fn test_double_lock_prevention() {
        let mut tracker = TxTracker::new();
        let inputs = vec![outpoint(1, 0)];

        tracker
            .register_tx([0xAA; 32], inputs.clone(), 1, 100, 1000)
            .expect("first");

        let result = tracker.register_tx([0xBB; 32], inputs, 1, 100, 1000);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already locked"));
    }

    #[test]
    fn test_dropped_releases_locks() {
        let mut tracker = TxTracker::new();
        let tx_hash = [0xAA; 32];
        let inputs = vec![outpoint(1, 0)];

        tracker
            .register_tx(tx_hash, inputs.clone(), 1, 100, 1000)
            .expect("register");
        tracker
            .apply_event(&tx_hash, &TxEvent::Broadcasted, 2000)
            .expect("broadcast");

        // TX expires from mempool
        tracker
            .apply_event(&tx_hash, &TxEvent::MempoolExpired, 3000)
            .expect("expire");

        // UTXO should be free again
        assert!(tracker.is_utxo_free(&inputs[0]));
    }

    #[test]
    fn test_conflict_releases_locks() {
        let mut tracker = TxTracker::new();
        let tx_hash = [0xAA; 32];
        let inputs = vec![outpoint(1, 0)];

        tracker
            .register_tx(tx_hash, inputs.clone(), 1, 100, 1000)
            .expect("register");
        tracker
            .apply_event(&tx_hash, &TxEvent::Broadcasted, 2000)
            .expect("broadcast");

        // Conflict detected
        tracker
            .apply_event(
                &tx_hash,
                &TxEvent::ConflictDetected {
                    conflicting_tx: Some([0xBB; 32]),
                },
                3000,
            )
            .expect("conflict");

        assert!(tracker.is_utxo_free(&inputs[0]));
    }

    #[test]
    fn test_reorg_rollback() {
        let mut tracker = TxTracker::new();
        let tx_hash = [0xAA; 32];
        let inputs = vec![outpoint(1, 0)];

        tracker
            .register_tx(tx_hash, inputs.clone(), 1, 100, 1000)
            .expect("register");
        tracker
            .apply_event(&tx_hash, &TxEvent::Broadcasted, 2000)
            .expect("broadcast");
        tracker
            .apply_event(
                &tx_hash,
                &TxEvent::IncludedInBlock { block_height: 10 },
                3000,
            )
            .expect("included");

        // Reorg!
        let status = tracker
            .apply_event(&tx_hash, &TxEvent::ReorgRollback, 4000)
            .expect("reorg");
        assert_eq!(status, TxStatus::PendingBroadcasted);

        // UTXO should still be locked (TX is back in mempool)
        assert!(!tracker.is_utxo_free(&inputs[0]));
    }

    #[test]
    fn test_terminal_states_reject_transitions() {
        let mut tracker = TxTracker::new();
        let tx_hash = [0xAA; 32];

        tracker
            .register_tx(tx_hash, vec![outpoint(1, 0)], 1, 100, 1000)
            .expect("register");
        tracker
            .apply_event(&tx_hash, &TxEvent::Broadcasted, 2000)
            .expect("broadcast");
        tracker
            .apply_event(&tx_hash, &TxEvent::MempoolExpired, 3000)
            .expect("expire");

        // Dropped is terminal — cannot broadcast again
        let result = tracker.apply_event(&tx_hash, &TxEvent::Broadcasted, 4000);
        assert!(result.is_err());
    }

    #[test]
    fn test_expired_locks_auto_release() {
        let mut tracker = TxTracker::new();
        tracker.lock_timeout_ms = 1000; // 1 second for testing

        let tx_hash = [0xAA; 32];
        let inputs = vec![outpoint(1, 0)];

        tracker
            .register_tx(tx_hash, inputs.clone(), 1, 100, 1000)
            .expect("register");

        // Before timeout — still locked
        let released = tracker.release_expired_locks(1500);
        assert!(released.is_empty());
        assert!(!tracker.is_utxo_free(&inputs[0]));

        // After timeout — auto-released
        let released = tracker.release_expired_locks(2500);
        assert_eq!(released.len(), 1);
        assert!(tracker.is_utxo_free(&inputs[0]));
    }

    #[test]
    fn test_sync_with_node_drops_missing_tx() {
        let mut tracker = TxTracker::new();
        let tx_hash = [0xAA; 32];
        let inputs = vec![outpoint(1, 0)];

        tracker
            .register_tx(tx_hash, inputs.clone(), 1, 100, 1000)
            .expect("register");
        tracker
            .apply_event(&tx_hash, &TxEvent::Broadcasted, 2000)
            .expect("broadcast");

        // Node says: TX not found
        let node_state = HashMap::from([(tx_hash, NodeTxInfo::NotFound)]);
        let result = sync_with_node(&mut tracker, &node_state, 3000);

        assert_eq!(result.dropped.len(), 1);
        assert!(tracker.is_utxo_free(&inputs[0]));
    }

    #[test]
    fn test_sync_with_node_advances_to_confirmed() {
        let mut tracker = TxTracker::new();
        let tx_hash = [0xAA; 32];

        tracker
            .register_tx(tx_hash, vec![outpoint(1, 0)], 1, 100, 1000)
            .expect("register");
        tracker
            .apply_event(&tx_hash, &TxEvent::Broadcasted, 2000)
            .expect("broadcast");

        // Node says: TX in block with enough confirmations
        let node_state = HashMap::from([(
            tx_hash,
            NodeTxInfo::InBlock {
                block_height: 10,
                confirmations: 10,
            },
        )]);
        let result = sync_with_node(&mut tracker, &node_state, 3000);

        assert!(!result.advanced.is_empty());
        assert!(matches!(
            tracker.transactions[&tx_hash].status,
            TxStatus::PendingInBlock { .. }
        ));

        let result = sync_with_node(&mut tracker, &node_state, 4000);
        assert!(!result.advanced.is_empty());
        assert!(matches!(
            tracker.transactions[&tx_hash].status,
            TxStatus::Confirmed { .. }
        ));
    }

    #[test]
    fn test_sync_reorg_rollback_and_recovery() {
        let mut tracker = TxTracker::new();
        let tx_hash = [0xAA; 32];

        tracker
            .register_tx(tx_hash, vec![outpoint(1, 0)], 1, 100, 1000)
            .expect("register");
        tracker
            .apply_event(&tx_hash, &TxEvent::Broadcasted, 2000)
            .expect("broadcast");
        tracker
            .apply_event(
                &tx_hash,
                &TxEvent::IncludedInBlock { block_height: 10 },
                3000,
            )
            .expect("included");

        // Reorg: TX disappears
        let node_state = HashMap::from([(tx_hash, NodeTxInfo::NotFound)]);
        let _result = sync_with_node(&mut tracker, &node_state, 4000);

        // Should be rolled back to PendingBroadcasted (not dropped)
        assert!(matches!(
            tracker.transactions[&tx_hash].status,
            TxStatus::PendingBroadcasted
        ));

        // Next sync: TX is back in mempool
        let node_state2 = HashMap::from([(tx_hash, NodeTxInfo::InMempool)]);
        let _result2 = sync_with_node(&mut tracker, &node_state2, 5000);

        // Still PendingBroadcasted (waiting for re-inclusion)
        assert!(matches!(
            tracker.transactions[&tx_hash].status,
            TxStatus::PendingBroadcasted
        ));
    }
}
