//! Validator Cooldown / Jail — manages re-entry restrictions after demotion.
//!
//! - Regular demotion: 1 epoch cooldown (30 days)
//! - Severe offense (double sign, fraud): extended jail (3+ epochs)
//! - During cooldown: cannot be promoted to Active, still earns Backup rewards

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Cooldown configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CooldownConfig {
    /// Normal cooldown after monthly demotion (epochs).
    pub demotion_cooldown_epochs: u64,
    /// Extended jail for severe offenses (epochs).
    pub severe_offense_jail_epochs: u64,
}

impl Default for CooldownConfig {
    fn default() -> Self {
        Self {
            demotion_cooldown_epochs: 1,  // 1 epoch = 30 days
            severe_offense_jail_epochs: 3, // 3 epochs = 90 days
        }
    }
}

/// Reason for cooldown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CooldownReason {
    /// Regular monthly demotion (score too low).
    Demotion,
    /// Double signing detected.
    DoubleSign,
    /// Invalid block proposal.
    InvalidBlock,
    /// Fraudulent QC signature.
    FraudulentSignature,
    /// Fraud proof established.
    FraudProof,
}

impl CooldownReason {
    pub fn is_severe(&self) -> bool {
        !matches!(self, CooldownReason::Demotion)
    }
}

/// Cooldown entry for a single validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CooldownEntry {
    pub validator_id: [u8; 32],
    /// Epoch when cooldown started.
    pub start_epoch: u64,
    /// Epoch when cooldown ends (exclusive — eligible at this epoch).
    pub end_epoch: u64,
    /// Reason for cooldown.
    pub reason: CooldownReason,
}

/// Cooldown registry tracking all validators in cooldown/jail.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CooldownRegistry {
    entries: HashMap<[u8; 32], CooldownEntry>,
}

impl CooldownRegistry {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Place a validator in cooldown.
    pub fn enter_cooldown(
        &mut self,
        validator_id: [u8; 32],
        current_epoch: u64,
        reason: CooldownReason,
        config: &CooldownConfig,
    ) {
        let duration = if reason.is_severe() {
            config.severe_offense_jail_epochs
        } else {
            config.demotion_cooldown_epochs
        };

        self.entries.insert(
            validator_id,
            CooldownEntry {
                validator_id,
                start_epoch: current_epoch,
                end_epoch: current_epoch + duration,
                reason,
            },
        );
    }

    /// Check if a validator is currently in cooldown.
    pub fn is_in_cooldown(&self, validator_id: &[u8; 32], current_epoch: u64) -> bool {
        match self.entries.get(validator_id) {
            Some(entry) => current_epoch < entry.end_epoch,
            None => false,
        }
    }

    /// Get cooldown info for a validator (if any).
    pub fn get(&self, validator_id: &[u8; 32]) -> Option<&CooldownEntry> {
        self.entries.get(validator_id)
    }

    /// Remove expired cooldowns. Call at the start of each epoch.
    pub fn gc_expired(&mut self, current_epoch: u64) {
        self.entries
            .retain(|_, entry| current_epoch < entry.end_epoch);
    }

    /// Get all validators currently in cooldown.
    pub fn all_in_cooldown(&self, current_epoch: u64) -> Vec<&CooldownEntry> {
        self.entries
            .values()
            .filter(|e| current_epoch < e.end_epoch)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_id(n: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    #[test]
    fn test_demotion_cooldown() {
        let config = CooldownConfig::default();
        let mut reg = CooldownRegistry::new();

        reg.enter_cooldown(make_id(1), 5, CooldownReason::Demotion, &config);

        assert!(reg.is_in_cooldown(&make_id(1), 5)); // Same epoch
        assert!(!reg.is_in_cooldown(&make_id(1), 6)); // 5 + 1 = 6, eligible
    }

    #[test]
    fn test_severe_offense_jail() {
        let config = CooldownConfig::default();
        let mut reg = CooldownRegistry::new();

        reg.enter_cooldown(make_id(1), 5, CooldownReason::DoubleSign, &config);

        assert!(reg.is_in_cooldown(&make_id(1), 5));
        assert!(reg.is_in_cooldown(&make_id(1), 6));
        assert!(reg.is_in_cooldown(&make_id(1), 7));
        assert!(!reg.is_in_cooldown(&make_id(1), 8)); // 5 + 3 = 8, eligible
    }

    #[test]
    fn test_gc_expired() {
        let config = CooldownConfig::default();
        let mut reg = CooldownRegistry::new();

        reg.enter_cooldown(make_id(1), 1, CooldownReason::Demotion, &config);
        reg.enter_cooldown(make_id(2), 5, CooldownReason::Demotion, &config);

        assert_eq!(reg.len(), 2);

        reg.gc_expired(3); // epoch 3: id1 expired (end=2), id2 still active (end=6)
        assert_eq!(reg.len(), 1);
        assert!(!reg.is_in_cooldown(&make_id(1), 3));
        assert!(reg.is_in_cooldown(&make_id(2), 3));
    }

    #[test]
    fn test_not_in_cooldown() {
        let reg = CooldownRegistry::new();
        assert!(!reg.is_in_cooldown(&make_id(99), 0));
    }
}
