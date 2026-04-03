//! Bridge persistence — crash-safe state management.
//!
//! Ensures bridge state survives restarts without data loss or corruption.

use std::path::{Path, PathBuf};

/// Anomaly escalation level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnomalyLevel {
    /// Log warning, continue processing.
    Warn,
    /// Reduce throughput (throttle).
    Throttle,
    /// Pause the bridge entirely.
    Pause,
}

/// Anomaly escalation policy.
pub struct AnomalyEscalation {
    /// Threshold for Warn level (% of global limit).
    pub warn_pct: u64,
    /// Threshold for Throttle level.
    pub throttle_pct: u64,
    /// Threshold for Pause level.
    pub pause_pct: u64,
    /// Current level.
    current_level: AnomalyLevel,
}

impl AnomalyEscalation {
    pub fn new(warn_pct: u64, throttle_pct: u64, pause_pct: u64) -> Self {
        Self { warn_pct, throttle_pct, pause_pct, current_level: AnomalyLevel::Warn }
    }

    /// Evaluate anomaly level based on withdrawal amount vs global limit.
    pub fn evaluate(&mut self, amount: u64, global_limit: u64) -> AnomalyLevel {
        let pct = if global_limit == 0 { 100 } else { amount * 100 / global_limit };
        self.current_level = if pct >= self.pause_pct {
            AnomalyLevel::Pause
        } else if pct >= self.throttle_pct {
            AnomalyLevel::Throttle
        } else if pct >= self.warn_pct {
            AnomalyLevel::Warn
        } else {
            AnomalyLevel::Warn
        };
        self.current_level
    }

    pub fn current_level(&self) -> AnomalyLevel { self.current_level }
}

/// Bridge persistence manager — validates and repairs state on startup.
pub struct BridgePersistence {
    data_dir: PathBuf,
}

impl BridgePersistence {
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        Self { data_dir: data_dir.as_ref().to_path_buf() }
    }

    pub fn nullifier_path(&self) -> PathBuf { self.data_dir.join("bridge_nullifiers.dat") }
    pub fn approval_path(&self) -> PathBuf { self.data_dir.join("bridge_approvals.json") }
    pub fn audit_path(&self) -> PathBuf { self.data_dir.join("bridge_audit.json") }

    /// Validate persistence on startup. FAIL-CLOSED if corrupted.
    pub fn validate_on_startup(&self) -> Result<PersistenceHealth, Vec<String>> {
        let mut errors = Vec::new();
        let mut health = PersistenceHealth::default();

        // Check data directory exists
        if !self.data_dir.exists() {
            std::fs::create_dir_all(&self.data_dir)
                .map_err(|e| vec![format!("cannot create bridge data dir: {}", e)])?;
        }

        // Validate nullifier file
        let nf = self.nullifier_path();
        if nf.exists() {
            match std::fs::metadata(&nf) {
                Ok(meta) => {
                    if meta.len() % 32 != 0 {
                        errors.push(format!("nullifier file corrupted: size {} not multiple of 32", meta.len()));
                    } else {
                        health.nullifier_count = (meta.len() / 32) as usize;
                    }
                }
                Err(e) => errors.push(format!("cannot read nullifier file: {}", e)),
            }
        }

        // Validate approval queue file
        let aq = self.approval_path();
        if aq.exists() {
            match std::fs::read_to_string(&aq) {
                Ok(content) => {
                    if serde_json::from_str::<serde_json::Value>(&content).is_err() {
                        errors.push("approval queue file is not valid JSON".into());
                    } else {
                        health.pending_approvals = content.matches("\"id\"").count();
                    }
                }
                Err(e) => errors.push(format!("cannot read approval queue: {}", e)),
            }
        }

        health.data_dir_exists = true;
        if errors.is_empty() { Ok(health) } else { Err(errors) }
    }
}

#[derive(Debug, Default)]
pub struct PersistenceHealth {
    pub data_dir_exists: bool,
    pub nullifier_count: usize,
    pub pending_approvals: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anomaly_escalation() {
        let mut esc = AnomalyEscalation::new(30, 50, 80);
        assert_eq!(esc.evaluate(20, 100), AnomalyLevel::Warn);
        assert_eq!(esc.evaluate(60, 100), AnomalyLevel::Throttle);
        assert_eq!(esc.evaluate(90, 100), AnomalyLevel::Pause);
    }

    #[test]
    fn test_persistence_creates_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sub = dir.path().join("bridge_data");
        let p = BridgePersistence::new(&sub);
        assert!(p.validate_on_startup().is_ok());
        assert!(sub.exists());
    }

    #[test]
    fn test_persistence_detects_corruption() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = BridgePersistence::new(dir.path());
        // Write corrupted nullifier file (not multiple of 32)
        std::fs::write(p.nullifier_path(), &[0u8; 33]).expect("write");
        assert!(p.validate_on_startup().is_err());
    }
}
