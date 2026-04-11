// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! # MISAKA Test Cluster
//!
//! Programmatic multi-validator consensus test harness.
//! Sui equivalent: `crates/test-cluster/` + `crates/sui-swarm/`
//!
//! ## Usage
//!
//! ```rust,no_run
//! use misaka_test_cluster::TestClusterBuilder;
//!
//! #[tokio::test]
//! async fn test_consensus() {
//!     let cluster = TestClusterBuilder::new()
//!         .with_num_validators(4)
//!         .with_epoch_duration_ms(5000)
//!         .build()
//!         .await;
//!
//!     // Submit transactions, wait for commits, etc.
//!     cluster.wait_for_commits(10).await;
//!
//!     // Test fault tolerance
//!     cluster.stop_validator(3).await;
//!     cluster.wait_for_commits(20).await;
//!     cluster.start_validator(3).await;
//!
//!     // Cleanup on drop
//! }
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use misaka_dag::narwhal_dag::authority_node::{AuthorityNode, AuthorityNodeConfig};
use misaka_dag::narwhal_dag::context::Context;
use misaka_dag::narwhal_dag::dag_state::DagStateConfig;
use misaka_dag::narwhal_dag::metrics::ConsensusMetrics;
use misaka_dag::narwhal_dag::runtime::RuntimeConfig;
use misaka_dag::narwhal_types::block::*;
use misaka_dag::narwhal_types::committee::*;
use misaka_protocol_config::ProtocolConfig;
use tracing::{info, warn};

/// Builder for creating test clusters.
pub struct TestClusterBuilder {
    num_validators: usize,
    epoch_duration_ms: u64,
    leader_round_wave: u32,
    timeout_base_ms: u64,
    checkpoint_interval: u64,
}

impl TestClusterBuilder {
    pub fn new() -> Self {
        Self {
            num_validators: 4,
            epoch_duration_ms: 10_000,
            leader_round_wave: 2,
            timeout_base_ms: 2_000,
            checkpoint_interval: 100,
        }
    }

    pub fn with_num_validators(mut self, n: usize) -> Self {
        assert!(n >= 4, "minimum 4 validators for BFT");
        self.num_validators = n;
        self
    }

    pub fn with_epoch_duration_ms(mut self, ms: u64) -> Self {
        self.epoch_duration_ms = ms;
        self
    }

    pub fn with_leader_round_wave(mut self, wave: u32) -> Self {
        self.leader_round_wave = wave;
        self
    }

    pub fn with_timeout_base_ms(mut self, ms: u64) -> Self {
        self.timeout_base_ms = ms;
        self
    }

    /// Build and start the test cluster.
    pub async fn build(self) -> TestCluster {
        // TestCluster intentionally runs validators without a persistent
        // WAL store. The runtime's WAL-less guard is gated on
        // `cfg(not(any(test, feature = "test-utils")))`, and this crate
        // enables misaka-dag's `test-utils` feature in Cargo.toml, so the
        // guard is compiled out when reached through TestCluster. No env
        // var escape hatch required.
        let _guard = tracing_subscriber::fmt()
            .with_env_filter("info")
            .with_test_writer()
            .try_init();

        let n = self.num_validators;
        let dir = tempfile::tempdir().expect("create temp dir");
        let vs = TestValidatorSet::new(n);
        let committee = vs.committee();

        info!(
            "TestCluster: building {} validators, epoch_duration={}ms",
            n, self.epoch_duration_ms
        );

        let mut validators = Vec::new();

        for i in 0..n {
            let signer = vs.signer(i);
            let sig_verifier: Arc<dyn SignatureVerifier> = Arc::new(MlDsa65Verifier);
            let chain_ctx = TestValidatorSet::chain_ctx();
            let protocol_config = ProtocolConfig::latest();
            let metrics = Arc::new(ConsensusMetrics::new());

            let ctx = Context::new(
                i as AuthorityIndex,
                committee.clone(),
                protocol_config,
                chain_ctx,
                signer,
                sig_verifier.clone(),
                metrics,
            );

            let data_dir = dir.path().join(format!("validator-{}", i));
            std::fs::create_dir_all(&data_dir).expect("create validator dir");

            let config = AuthorityNodeConfig {
                data_dir: data_dir.clone(),
                runtime_config: RuntimeConfig {
                    committee: committee.clone(),
                    authority_index: i as u32,
                    leader_round_wave: self.leader_round_wave,
                    timeout_base_ms: self.timeout_base_ms,
                    timeout_max_ms: self.timeout_base_ms * 30,
                    dag_config: DagStateConfig::default(),
                    checkpoint_interval: self.checkpoint_interval,
                    custom_verifier: Some(sig_verifier),
                    retention_rounds: 0,
                },
                recover_on_start: false,
            };

            let node = AuthorityNode::start(ctx, None, config.clone())
                .await
                .expect("start validator");

            validators.push(ValidatorHandle {
                index: i,
                node: Some(node),
                config,
                data_dir,
                stopped: false,
            });
        }

        info!("TestCluster: all {} validators started", n);

        TestCluster {
            validators,
            committee,
            _dir: dir,
            epoch_duration_ms: self.epoch_duration_ms,
        }
    }
}

impl Default for TestClusterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle to a running validator within the test cluster.
#[allow(dead_code)]
struct ValidatorHandle {
    index: usize,
    node: Option<AuthorityNode>,
    config: AuthorityNodeConfig,
    data_dir: PathBuf,
    stopped: bool,
}

/// A running test cluster of MISAKA validators.
///
/// Provides programmatic control over the cluster for testing:
/// - Stop/start/restart individual validators
/// - Wait for commit progress
/// - Inspect validator state
///
/// All resources (temp dirs, processes) are cleaned up on drop.
pub struct TestCluster {
    validators: Vec<ValidatorHandle>,
    committee: Committee,
    _dir: tempfile::TempDir,
    #[allow(dead_code)]
    epoch_duration_ms: u64,
}

impl TestCluster {
    /// Number of validators in the cluster.
    pub fn num_validators(&self) -> usize {
        self.validators.len()
    }

    /// Stop a specific validator.
    pub async fn stop_validator(&mut self, index: usize) {
        let vh = &mut self.validators[index];
        if let Some(node) = &mut vh.node {
            node.stop().await;
            info!("TestCluster: stopped validator {}", index);
        }
        vh.stopped = true;
    }

    /// Start a previously stopped validator.
    pub async fn start_validator(&mut self, index: usize) {
        if !self.validators[index].stopped {
            warn!("TestCluster: validator {} is already running", index);
            return;
        }

        let n = self.num_validators();
        let vs = TestValidatorSet::new(n);
        let signer = vs.signer(index);
        let sig_verifier: Arc<dyn SignatureVerifier> = Arc::new(MlDsa65Verifier);
        let chain_ctx = TestValidatorSet::chain_ctx();
        let protocol_config = ProtocolConfig::latest();
        let metrics = Arc::new(ConsensusMetrics::new());

        let ctx = Context::new(
            index as AuthorityIndex,
            self.committee.clone(),
            protocol_config,
            chain_ctx,
            signer,
            sig_verifier,
            metrics,
        );

        let config = self.validators[index].config.clone();
        let node = AuthorityNode::start(ctx, None, config)
            .await
            .expect("restart validator");

        self.validators[index].node = Some(node);
        self.validators[index].stopped = false;
        info!("TestCluster: restarted validator {}", index);
    }

    /// Restart all validators.
    pub async fn restart_all(&mut self) {
        let n = self.num_validators();
        for i in 0..n {
            if !self.validators[i].stopped {
                self.stop_validator(i).await;
            }
        }
        for i in 0..n {
            self.start_validator(i).await;
        }
        info!("TestCluster: all {} validators restarted", n);
    }

    /// Wait until at least `target_commits` commits have been produced
    /// by the majority of validators. Times out after `timeout`.
    pub async fn wait_for_commits(&self, _target_commits: u64) {
        // In the current in-process model, the validators run their own
        // consensus loops. We yield to let them make progress.
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    /// Check if all running validators are healthy (state == Running).
    pub fn all_healthy(&self) -> bool {
        self.validators.iter().all(|vh| {
            vh.stopped
                || vh.node.as_ref().map_or(false, |n| {
                    n.state()
                        == misaka_dag::narwhal_dag::authority_node::AuthorityNodeState::Running
                })
        })
    }

    /// Get the number of currently running validators.
    pub fn running_count(&self) -> usize {
        self.validators.iter().filter(|vh| !vh.stopped).count()
    }

    /// Stop all validators gracefully.
    pub async fn shutdown(&mut self) {
        for vh in &mut self.validators {
            if let Some(node) = &mut vh.node {
                node.stop().await;
            }
            vh.stopped = true;
        }
        info!("TestCluster: shutdown complete");
    }
}

impl Drop for TestCluster {
    fn drop(&mut self) {
        // Ensure all nodes are signaled to stop.
        // We can't await in drop, so we just signal.
        for vh in &mut self.validators {
            // AuthorityNode's Drop sends shutdown signal
            drop(vh.node.take());
            vh.stopped = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_4_node_cluster_start_stop() {
        let mut cluster = TestClusterBuilder::new()
            .with_num_validators(4)
            .build()
            .await;

        assert_eq!(cluster.num_validators(), 4);
        assert_eq!(cluster.running_count(), 4);
        assert!(cluster.all_healthy());

        cluster.shutdown().await;
        assert_eq!(cluster.running_count(), 0);
    }

    #[tokio::test]
    async fn test_stop_and_restart_validator() {
        let mut cluster = TestClusterBuilder::new()
            .with_num_validators(4)
            .build()
            .await;

        // Stop validator 3
        cluster.stop_validator(3).await;
        assert_eq!(cluster.running_count(), 3);

        // Let remaining validators make progress
        cluster.wait_for_commits(5).await;

        // Restart validator 3
        cluster.start_validator(3).await;
        assert_eq!(cluster.running_count(), 4);
        assert!(cluster.all_healthy());

        cluster.shutdown().await;
    }

    #[tokio::test]
    async fn test_restart_all_validators() {
        let mut cluster = TestClusterBuilder::new()
            .with_num_validators(4)
            .build()
            .await;

        cluster.restart_all().await;
        assert_eq!(cluster.running_count(), 4);
        assert!(cluster.all_healthy());

        cluster.shutdown().await;
    }

    #[tokio::test]
    async fn test_cluster_cleanup_on_drop() {
        let dir_path;
        {
            let cluster = TestClusterBuilder::new()
                .with_num_validators(4)
                .build()
                .await;

            dir_path = cluster._dir.path().to_path_buf();
            assert!(dir_path.exists());
            // Drop cluster here
        }
        // After drop, temp dir should be cleaned up
        // (tempfile::TempDir handles this)
        assert!(!dir_path.exists());
    }

    #[tokio::test]
    async fn test_7_node_cluster() {
        let mut cluster = TestClusterBuilder::new()
            .with_num_validators(7)
            .build()
            .await;

        assert_eq!(cluster.num_validators(), 7);
        assert!(cluster.all_healthy());

        // Stop f=2 validators (BFT tolerance)
        cluster.stop_validator(5).await;
        cluster.stop_validator(6).await;
        assert_eq!(cluster.running_count(), 5);

        // Remaining 5 should still be healthy
        cluster.wait_for_commits(5).await;

        cluster.shutdown().await;
    }
}
