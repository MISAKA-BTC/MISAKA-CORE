//! Storage strategy per node role.
//!
//! SR nodes: minimal storage (current state + recent DAG + checkpoints)
//! Archive nodes: full history
//! Candidates: moderate (recent history for scoring)

use crate::config::NodeRole;

/// Storage configuration derived from node role.
pub struct StorageConfig {
    /// Number of recent DAG rounds to retain.
    pub dag_retention_rounds: u64,
    /// Whether to store full transaction history.
    pub store_full_history: bool,
    /// Whether to store checkpoint certificates.
    pub store_certificates: bool,
    /// Whether to serve snapshot sync requests.
    pub serve_snapshots: bool,
    /// Prune interval in seconds.
    pub prune_interval_secs: u64,
    /// Maximum database size (GB). 0 = unlimited.
    pub max_db_size_gb: u64,
}

impl StorageConfig {
    pub fn for_role(role: NodeRole) -> Self {
        match role {
            NodeRole::Sr => Self {
                dag_retention_rounds: 1000,     // ~3 hours at 10 BPS
                store_full_history: false,
                store_certificates: true,
                serve_snapshots: false,
                prune_interval_secs: 300,       // prune every 5 min
                max_db_size_gb: 50,
            },
            NodeRole::Archive => Self {
                dag_retention_rounds: u64::MAX, // keep everything
                store_full_history: true,
                store_certificates: true,
                serve_snapshots: true,
                prune_interval_secs: 3600,
                max_db_size_gb: 0,              // unlimited
            },
            NodeRole::Candidate => Self {
                dag_retention_rounds: 10_000,   // ~30 hours
                store_full_history: false,
                store_certificates: true,
                serve_snapshots: false,
                prune_interval_secs: 600,
                max_db_size_gb: 100,
            },
            NodeRole::Relay => Self {
                dag_retention_rounds: 100,      // minimal
                store_full_history: false,
                store_certificates: false,
                serve_snapshots: false,
                prune_interval_secs: 60,
                max_db_size_gb: 10,
            },
            NodeRole::Observer => Self {
                dag_retention_rounds: 50,
                store_full_history: false,
                store_certificates: false,
                serve_snapshots: false,
                prune_interval_secs: 60,
                max_db_size_gb: 5,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sr_storage_minimal() {
        let cfg = StorageConfig::for_role(NodeRole::Sr);
        assert!(!cfg.store_full_history);
        assert!(cfg.store_certificates);
        assert_eq!(cfg.max_db_size_gb, 50);
    }

    #[test]
    fn test_archive_storage_full() {
        let cfg = StorageConfig::for_role(NodeRole::Archive);
        assert!(cfg.store_full_history);
        assert!(cfg.serve_snapshots);
        assert_eq!(cfg.max_db_size_gb, 0); // unlimited
    }

    #[test]
    fn test_observer_minimal() {
        let cfg = StorageConfig::for_role(NodeRole::Observer);
        assert!(!cfg.store_certificates);
        assert_eq!(cfg.max_db_size_gb, 5);
    }
}
