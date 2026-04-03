//! Safe Mode — automatic liveness protection for BFT consensus.
//!
//! When the network detects repeated missed rounds (no progress),
//! SafeMode triggers a sequence of protective actions:
//!
//! 1. **Alert** — log + metrics for operator visibility
//! 2. **Block production pause** — stop proposing to avoid wasting resources
//! 3. **Degraded mode** — accept blocks from peers but don't propose
//! 4. **Recovery** — resume normal operation when rounds succeed again

/// Actions that SafeMode can trigger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafeModeAction {
    /// No action — normal operation.
    None,
    /// Alert operators — liveness degrading.
    Alert { missed_rounds: u64, threshold: u64 },
    /// Pause block production — let other validators drive progress.
    PauseBlockProduction,
    /// Enter degraded mode — relay-only, no proposals.
    DegradedMode,
}

/// Operating state of the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeOperatingMode {
    /// Normal — proposing and voting.
    Normal,
    /// Degraded — accepting/relaying blocks but NOT proposing.
    Degraded,
}

pub struct SafeMode {
    pub active: bool,
    pub missed_rounds: u64,
    /// Consecutive missed rounds before alert (default: 3).
    pub alert_threshold: u64,
    /// Consecutive missed rounds before block production pause (default: 5).
    pub pause_threshold: u64,
    /// Consecutive missed rounds before degraded mode (default: 10).
    pub degraded_threshold: u64,
    /// Current operating mode.
    pub mode: NodeOperatingMode,
    /// Accumulated actions for the caller to process.
    pending_actions: Vec<SafeModeAction>,
}

impl SafeMode {
    pub fn new(alert_threshold: u64) -> Self {
        Self {
            active: false,
            missed_rounds: 0,
            alert_threshold,
            pause_threshold: alert_threshold.saturating_add(2),
            degraded_threshold: alert_threshold.saturating_mul(3),
            mode: NodeOperatingMode::Normal,
            pending_actions: Vec::new(),
        }
    }

    /// Record a missed round and return any triggered actions.
    pub fn on_missed_round(&mut self) -> Vec<SafeModeAction> {
        self.missed_rounds += 1;
        self.pending_actions.clear();

        if self.missed_rounds >= self.degraded_threshold {
            self.active = true;
            self.mode = NodeOperatingMode::Degraded;
            self.pending_actions.push(SafeModeAction::DegradedMode);
            tracing::error!(
                "SAFE MODE: Degraded mode activated after {} missed rounds. \
                 Node will relay blocks but NOT propose until recovery.",
                self.missed_rounds
            );
        } else if self.missed_rounds >= self.pause_threshold {
            self.active = true;
            self.pending_actions.push(SafeModeAction::PauseBlockProduction);
            tracing::warn!(
                "SAFE MODE: Block production paused after {} missed rounds",
                self.missed_rounds
            );
        } else if self.missed_rounds >= self.alert_threshold {
            self.pending_actions.push(SafeModeAction::Alert {
                missed_rounds: self.missed_rounds,
                threshold: self.alert_threshold,
            });
            tracing::warn!(
                "SAFE MODE: Alert — {} consecutive missed rounds (threshold: {})",
                self.missed_rounds, self.alert_threshold
            );
        }

        self.pending_actions.clone()
    }

    /// Record a successful round — resets all counters and modes.
    pub fn on_successful_round(&mut self) {
        if self.active {
            tracing::info!(
                "SAFE MODE: Recovered after {} missed rounds. Resuming normal operation.",
                self.missed_rounds
            );
        }
        self.missed_rounds = 0;
        self.active = false;
        self.mode = NodeOperatingMode::Normal;
    }

    /// Whether the node should produce blocks.
    pub fn should_produce_blocks(&self) -> bool {
        self.mode == NodeOperatingMode::Normal
    }

    /// Whether the node is in degraded mode (relay-only).
    pub fn is_degraded(&self) -> bool {
        self.mode == NodeOperatingMode::Degraded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_mode_trigger_sequence() {
        let mut sm = SafeMode::new(3);

        // Below alert threshold — no actions
        assert!(sm.on_missed_round().is_empty());
        assert!(sm.on_missed_round().is_empty());

        // At alert threshold — Alert
        let actions = sm.on_missed_round();
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], SafeModeAction::Alert { .. }));
        assert!(sm.should_produce_blocks()); // still producing

        // More misses — PauseBlockProduction
        sm.on_missed_round();
        let actions = sm.on_missed_round();
        assert!(actions.contains(&SafeModeAction::PauseBlockProduction));
        assert!(sm.active);

        // Recovery
        sm.on_successful_round();
        assert!(!sm.active);
        assert!(sm.should_produce_blocks());
        assert_eq!(sm.missed_rounds, 0);
    }

    #[test]
    fn test_degraded_mode() {
        let mut sm = SafeMode::new(3); // degraded at 3*3=9
        for _ in 0..9 {
            sm.on_missed_round();
        }
        assert!(sm.is_degraded());
        assert!(!sm.should_produce_blocks());

        sm.on_successful_round();
        assert!(!sm.is_degraded());
        assert!(sm.should_produce_blocks());
    }
}
