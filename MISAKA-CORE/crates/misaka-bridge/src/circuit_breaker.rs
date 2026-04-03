//! Bridge Circuit Breaker — auto-pause triggers for bridge safety.
//!
//! # No-Rollback Architecture
//!
//! Bridge incidents are resolved by pausing the bridge, NOT by
//! rolling back the L1 chain. The circuit breaker monitors:
//! - Accounting invariants (mint_total vs lock_total)
//! - Finality lag (too far behind → unsafe to release)
//! - Committee health (consecutive verification failures)
//!
//! When a trigger fires, the bridge automatically pauses and
//! an operator must investigate + resume manually.

use misaka_types::quarantine::{BridgeSafetyState, PauseOrigin};
use tracing::{info, warn};

// ═══════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════

/// Default maximum accounting delta before auto-pause (base units).
pub const DEFAULT_MAX_ACCOUNTING_DELTA: u64 = 1_000_000;

/// Default maximum finality lag (in epochs) before auto-pause.
pub const DEFAULT_MAX_FINALITY_LAG: u64 = 5;

/// Default consecutive committee failures before auto-pause.
pub const DEFAULT_MAX_COMMITTEE_FAILURES: u32 = 3;

/// Default release timelock (in blue_score units).
pub const DEFAULT_RELEASE_TIMELOCK: u64 = 100;

// ═══════════════════════════════════════════════════════════════
//  Circuit Breaker
// ═══════════════════════════════════════════════════════════════

/// Circuit breaker configuration and state.
pub struct CircuitBreaker {
    /// Maximum allowed delta between mint_total and lock_total.
    pub max_accounting_delta: u64,
    /// Maximum finality lag (epochs) before auto-pause.
    pub max_finality_lag: u64,
    /// Maximum consecutive committee verification failures.
    pub max_consecutive_committee_failures: u32,
    /// Current consecutive committee failure count.
    consecutive_committee_failures: u32,
    /// Total auto-pause events triggered.
    pub total_auto_pauses: u64,
}

/// Result of a circuit breaker check.
#[derive(Debug, Clone)]
pub enum CheckResult {
    /// All checks passed.
    Ok,
    /// A trigger fired — bridge should be paused.
    TriggerFired { origin: PauseOrigin, reason: String },
}

impl CircuitBreaker {
    pub fn new() -> Self {
        Self {
            max_accounting_delta: DEFAULT_MAX_ACCOUNTING_DELTA,
            max_finality_lag: DEFAULT_MAX_FINALITY_LAG,
            max_consecutive_committee_failures: DEFAULT_MAX_COMMITTEE_FAILURES,
            consecutive_committee_failures: 0,
            total_auto_pauses: 0,
        }
    }

    /// Create with custom thresholds.
    pub fn with_config(
        max_accounting_delta: u64,
        max_finality_lag: u64,
        max_committee_failures: u32,
    ) -> Self {
        Self {
            max_accounting_delta,
            max_finality_lag,
            max_consecutive_committee_failures: max_committee_failures,
            consecutive_committee_failures: 0,
            total_auto_pauses: 0,
        }
    }

    /// Check accounting invariant: mint_total should closely match lock_total.
    pub fn check_accounting(&self, mint_total: u64, lock_total: u64) -> CheckResult {
        let delta = mint_total.abs_diff(lock_total);
        if delta > self.max_accounting_delta {
            let reason = format!(
                "accounting mismatch: mint_total={} lock_total={} delta={} > max={}",
                mint_total, lock_total, delta, self.max_accounting_delta
            );
            warn!("Circuit breaker: {}", reason);
            CheckResult::TriggerFired {
                origin: PauseOrigin::AutoAccountingMismatch,
                reason,
            }
        } else {
            CheckResult::Ok
        }
    }

    /// Check finality lag: bridge should not operate too far behind finality.
    pub fn check_finality_lag(&self, last_finalized_epoch: u64, current_epoch: u64) -> CheckResult {
        let lag = current_epoch.saturating_sub(last_finalized_epoch);
        if lag > self.max_finality_lag {
            let reason = format!(
                "finality lag: current_epoch={} last_finalized={} lag={} > max={}",
                current_epoch, last_finalized_epoch, lag, self.max_finality_lag
            );
            warn!("Circuit breaker: {}", reason);
            CheckResult::TriggerFired {
                origin: PauseOrigin::AutoFinalityLag,
                reason,
            }
        } else {
            CheckResult::Ok
        }
    }

    /// Report a committee verification failure.
    /// Returns TriggerFired if consecutive failures exceed threshold.
    pub fn on_committee_failure(&mut self) -> CheckResult {
        self.consecutive_committee_failures += 1;
        if self.consecutive_committee_failures >= self.max_consecutive_committee_failures {
            let reason = format!(
                "consecutive committee failures: {} >= {}",
                self.consecutive_committee_failures, self.max_consecutive_committee_failures
            );
            warn!("Circuit breaker: {}", reason);
            CheckResult::TriggerFired {
                origin: PauseOrigin::AutoCommitteeFailure,
                reason,
            }
        } else {
            CheckResult::Ok
        }
    }

    /// Report a successful committee verification (resets failure counter).
    pub fn on_committee_success(&mut self) {
        if self.consecutive_committee_failures > 0 {
            info!(
                "Circuit breaker: committee success, resetting failure count from {}",
                self.consecutive_committee_failures
            );
        }
        self.consecutive_committee_failures = 0;
    }

    /// Record that an auto-pause was triggered.
    pub fn record_auto_pause(&mut self) {
        self.total_auto_pauses += 1;
    }

    /// Current consecutive committee failure count.
    pub fn committee_failure_count(&self) -> u32 {
        self.consecutive_committee_failures
    }

    /// Run all periodic checks. Returns the first trigger that fires, if any.
    pub fn run_periodic_checks(
        &self,
        mint_total: u64,
        lock_total: u64,
        last_finalized_epoch: u64,
        current_epoch: u64,
    ) -> CheckResult {
        // Check accounting first (most critical)
        let accounting = self.check_accounting(mint_total, lock_total);
        if let CheckResult::TriggerFired { .. } = &accounting {
            return accounting;
        }

        // Check finality lag
        let finality = self.check_finality_lag(last_finalized_epoch, current_epoch);
        if let CheckResult::TriggerFired { .. } = &finality {
            return finality;
        }

        CheckResult::Ok
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Bridge State Manager — wraps safety state transitions
// ═══════════════════════════════════════════════════════════════

/// Manages bridge safety state transitions with audit logging.
pub struct BridgeStateManager {
    pub state: BridgeSafetyState,
    pub circuit_breaker: CircuitBreaker,
    /// Cumulative mint total (for accounting checks).
    pub mint_total: u64,
    /// Cumulative burn total.
    pub burn_total: u64,
    /// Release timelock in blue_score units.
    pub release_timelock: u64,
}

impl BridgeStateManager {
    pub fn new() -> Self {
        Self {
            state: BridgeSafetyState::Active,
            circuit_breaker: CircuitBreaker::new(),
            mint_total: 0,
            burn_total: 0,
            release_timelock: DEFAULT_RELEASE_TIMELOCK,
        }
    }

    /// Is the bridge active (accepting mint/burn)?
    pub fn is_active(&self) -> bool {
        self.state.is_active()
    }

    /// Pause the bridge.
    pub fn pause(&mut self, reason: String, origin: PauseOrigin) {
        let now_ms = now_ms();
        self.state = BridgeSafetyState::Paused {
            reason: reason.clone(),
            since_ms: now_ms,
            origin,
        };
        self.circuit_breaker.record_auto_pause();
        warn!("Bridge PAUSED: {}", reason);
    }

    /// Resume the bridge (operator action).
    pub fn resume(&mut self, operator_id: &str) -> Result<(), String> {
        match &self.state {
            BridgeSafetyState::Paused { .. } => {
                self.state = BridgeSafetyState::Active;
                info!("Bridge RESUMED by operator {}", operator_id);
                Ok(())
            }
            BridgeSafetyState::Active => Err("bridge is already active".into()),
            BridgeSafetyState::Degraded { .. } => {
                self.state = BridgeSafetyState::Active;
                info!("Bridge RESUMED from degraded by operator {}", operator_id);
                Ok(())
            }
        }
    }

    /// Record a mint event. Auto-pauses if accounting invariant violated.
    pub fn record_mint(&mut self, amount: u64, lock_total_on_source: u64) {
        self.mint_total = self.mint_total.saturating_add(amount);
        if let CheckResult::TriggerFired { origin, reason } = self
            .circuit_breaker
            .check_accounting(self.mint_total, lock_total_on_source)
        {
            self.pause(reason, origin);
        }
    }

    /// Record a burn event.
    pub fn record_burn(&mut self, amount: u64) {
        self.burn_total = self.burn_total.saturating_add(amount);
    }

    /// Run periodic safety checks.
    pub fn run_periodic_checks(
        &mut self,
        lock_total_on_source: u64,
        last_finalized_epoch: u64,
        current_epoch: u64,
    ) {
        if let CheckResult::TriggerFired { origin, reason } =
            self.circuit_breaker.run_periodic_checks(
                self.mint_total,
                lock_total_on_source,
                last_finalized_epoch,
                current_epoch,
            )
        {
            if self.state.is_active() {
                self.pause(reason, origin);
            }
        }
    }
}

impl Default for BridgeStateManager {
    fn default() -> Self {
        Self::new()
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accounting_check_ok() {
        let cb = CircuitBreaker::new();
        assert!(matches!(cb.check_accounting(100, 100), CheckResult::Ok));
        assert!(matches!(cb.check_accounting(100, 150), CheckResult::Ok));
    }

    #[test]
    fn test_accounting_check_mismatch() {
        let cb = CircuitBreaker::new();
        let result = cb.check_accounting(10_000_000, 0);
        assert!(matches!(result, CheckResult::TriggerFired { .. }));
    }

    #[test]
    fn test_finality_lag_ok() {
        let cb = CircuitBreaker::new();
        assert!(matches!(cb.check_finality_lag(10, 12), CheckResult::Ok));
    }

    #[test]
    fn test_finality_lag_trigger() {
        let cb = CircuitBreaker::new();
        let result = cb.check_finality_lag(5, 20);
        assert!(matches!(result, CheckResult::TriggerFired { .. }));
    }

    #[test]
    fn test_committee_failure_accumulates() {
        let mut cb = CircuitBreaker::new();
        assert!(matches!(cb.on_committee_failure(), CheckResult::Ok));
        assert!(matches!(cb.on_committee_failure(), CheckResult::Ok));
        // Third failure triggers
        assert!(matches!(
            cb.on_committee_failure(),
            CheckResult::TriggerFired { .. }
        ));
    }

    #[test]
    fn test_committee_success_resets() {
        let mut cb = CircuitBreaker::new();
        cb.on_committee_failure();
        cb.on_committee_failure();
        assert_eq!(cb.committee_failure_count(), 2);
        cb.on_committee_success();
        assert_eq!(cb.committee_failure_count(), 0);
    }

    #[test]
    fn test_bridge_state_manager_pause_resume() {
        let mut mgr = BridgeStateManager::new();
        assert!(mgr.is_active());

        mgr.pause("test".into(), PauseOrigin::Operator("op1".into()));
        assert!(!mgr.is_active());

        mgr.resume("op1").unwrap();
        assert!(mgr.is_active());
    }

    #[test]
    fn test_bridge_state_manager_auto_pause_on_mint() {
        let mut mgr = BridgeStateManager::new();
        // Large mint with no lock → accounting mismatch → auto-pause
        mgr.record_mint(5_000_000, 0);
        assert!(!mgr.is_active());
    }

    #[test]
    fn test_bridge_state_manager_normal_mint() {
        let mut mgr = BridgeStateManager::new();
        mgr.record_mint(500, 1000);
        assert!(mgr.is_active()); // delta is small
    }

    #[test]
    fn test_periodic_checks_trigger_on_lag() {
        let mut mgr = BridgeStateManager::new();
        mgr.run_periodic_checks(0, 1, 100);
        assert!(!mgr.is_active()); // finality lag too large
    }

    #[test]
    fn test_periodic_checks_ok() {
        let mut mgr = BridgeStateManager::new();
        mgr.run_periodic_checks(0, 95, 100);
        assert!(mgr.is_active());
    }
}
