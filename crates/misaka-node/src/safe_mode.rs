// SPDX-License-Identifier: Apache-2.0
//! Safe-mode halt flag.
//!
//! When the node detects state divergence (e.g. a committed block's
//! `leader_state_root` disagrees with the value computed by our local
//! executor) it trips `SafeMode`. Once tripped:
//!
//! - the commit loop stops applying further committed sub-dags
//! - the propose loop stops producing new proposals (validators only)
//! - write RPC endpoints return 503 with `safe_mode: true` in the body
//! - `/api/health` and `/api/get_chain_info` surface the halted state
//!
//! Read-only RPC (`/api/get_balance`, `/api/get_utxos`, etc.) keeps
//! working so operators can inspect the divergence point without
//! extending it.
//!
//! The halt is process-global and cannot be cleared from inside the
//! running binary — the operator must restart the node after
//! investigating the divergence. This is intentional: a node that has
//! observed state divergence cannot safely resume signing blocks
//! without a human in the loop.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use parking_lot::RwLock;

/// Process-global safe-mode flag.
///
/// Cheap to poll via `is_halted()`; the expensive path (reading the
/// reason string) is only taken once at /api/health time.
#[derive(Debug, Default)]
pub struct SafeMode {
    halted: AtomicBool,
    halted_at_commit: AtomicU64,
    reason: RwLock<Option<String>>,
}

impl SafeMode {
    pub fn new() -> Self {
        Self::default()
    }

    /// Trip the safe-mode flag. Idempotent: subsequent calls are no-ops
    /// and the first trip's reason is preserved so operators can see
    /// exactly which mismatch caused the halt.
    pub fn trip(&self, commit_index: u64, reason: impl Into<String>) {
        // swap() returns the PREVIOUS value — only write metadata on
        // the first trip.
        if !self.halted.swap(true, Ordering::SeqCst) {
            self.halted_at_commit.store(commit_index, Ordering::SeqCst);
            *self.reason.write() = Some(reason.into());
            tracing::error!(
                "🛑 SAFE MODE ENGAGED at commit {} — all further consensus \
                 participation is frozen. The operator must investigate the \
                 state divergence and restart the node.",
                commit_index
            );
        }
    }

    pub fn is_halted(&self) -> bool {
        self.halted.load(Ordering::SeqCst)
    }

    pub fn halted_at_commit(&self) -> u64 {
        self.halted_at_commit.load(Ordering::SeqCst)
    }

    pub fn reason(&self) -> Option<String> {
        self.reason.read().clone()
    }

    /// Snapshot for RPC responses. Returns `None` if the node is
    /// healthy, `Some((commit_index, reason))` if safe-mode is tripped.
    pub fn status(&self) -> Option<(u64, Option<String>)> {
        if self.is_halted() {
            Some((self.halted_at_commit(), self.reason()))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_safe_mode_is_not_halted() {
        let sm = SafeMode::new();
        assert!(!sm.is_halted());
        assert!(sm.status().is_none());
    }

    #[test]
    fn trip_records_metadata_once() {
        let sm = SafeMode::new();
        sm.trip(42, "first mismatch");
        assert!(sm.is_halted());
        assert_eq!(sm.halted_at_commit(), 42);
        assert_eq!(sm.reason().as_deref(), Some("first mismatch"));
        // Second trip must not overwrite the first reason.
        sm.trip(99, "second mismatch");
        assert_eq!(sm.halted_at_commit(), 42);
        assert_eq!(sm.reason().as_deref(), Some("first mismatch"));
    }

    #[test]
    fn status_reflects_halt() {
        let sm = SafeMode::new();
        assert!(sm.status().is_none());
        sm.trip(7, "boom");
        let (commit, reason) = sm.status().expect("status must be Some after trip");
        assert_eq!(commit, 7);
        assert_eq!(reason.as_deref(), Some("boom"));
    }
}
