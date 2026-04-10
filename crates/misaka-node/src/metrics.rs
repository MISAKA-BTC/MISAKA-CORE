//! Lightweight Prometheus-compatible metrics (no external dependencies).
//!
//! Exposes an `/metrics` HTTP endpoint in Prometheus exposition format.
//! All counters/gauges use `AtomicU64` for lock-free concurrent access.
//!
//! # Usage
//!
//! ```ignore
//! // At startup:
//! let metrics = NodeMetrics::new();
//!
//! // In block producer:
//! metrics.blocks_produced.inc();
//! metrics.block_height.set(new_height);
//! metrics.tx_count.add(result.tx_count as u64);
//!
//! // Expose via axum:
//! app = app.route("/metrics", get(metrics_handler));
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// ═══════════════════════════════════════════════════════════════
//  Atomic Metric Primitives
// ═══════════════════════════════════════════════════════════════

/// Monotonically increasing counter.
pub struct Counter(AtomicU64);

impl Counter {
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Point-in-time gauge (can go up and down).
pub struct Gauge(AtomicU64);

impl Gauge {
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }
    pub fn set(&self, v: u64) {
        self.0.store(v, Ordering::Relaxed);
    }
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    pub fn dec(&self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

// ═══════════════════════════════════════════════════════════════
//  Node Metrics
// ═══════════════════════════════════════════════════════════════

/// All node metrics — shared via `Arc<NodeMetrics>`.
pub struct NodeMetrics {
    // ── Chain ──
    pub block_height: Gauge,
    pub blocks_produced: Counter,
    pub blocks_received: Counter,
    pub block_production_errors: Counter,

    // ── Transactions ──
    pub tx_total: Counter,
    pub tx_submitted_rpc: Counter,
    pub tx_rejected: Counter,
    pub tx_fees_total: Counter,

    // ── Mempool ──
    pub mempool_size: Gauge,
    pub mempool_evictions: Counter,

    // ── UTXO Set ──
    pub utxo_count: Gauge,
    pub spent_count: Gauge,

    // ── P2P ──
    pub p2p_peers_connected: Gauge,
    pub p2p_peers_inbound: Gauge,
    pub p2p_peers_outbound: Gauge,
    pub p2p_messages_sent: Counter,
    pub p2p_messages_received: Counter,
    pub p2p_bytes_sent: Counter,
    pub p2p_bytes_received: Counter,

    // ── Consensus ──
    pub finalized_epoch: Gauge,
    pub checkpoint_votes_received: Counter,
    pub reorgs: Counter,
    pub reorg_max_depth: Gauge,

    // ── ZKP ──
    pub zkp_verifications: Counter,
    pub zkp_verification_failures: Counter,

    // ── Staking ──
    pub active_validators: Gauge,
    pub total_bonded_stake: Gauge,
    pub slashing_events: Counter,

    // ── System ──
    pub uptime_seconds: Gauge,
    pub snapshot_saves: Counter,
    pub snapshot_save_errors: Counter,
}

impl NodeMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            block_height: Gauge::new(),
            blocks_produced: Counter::new(),
            blocks_received: Counter::new(),
            block_production_errors: Counter::new(),

            tx_total: Counter::new(),
            tx_submitted_rpc: Counter::new(),
            tx_rejected: Counter::new(),
            tx_fees_total: Counter::new(),

            mempool_size: Gauge::new(),
            mempool_evictions: Counter::new(),

            utxo_count: Gauge::new(),
            spent_count: Gauge::new(),

            p2p_peers_connected: Gauge::new(),
            p2p_peers_inbound: Gauge::new(),
            p2p_peers_outbound: Gauge::new(),
            p2p_messages_sent: Counter::new(),
            p2p_messages_received: Counter::new(),
            p2p_bytes_sent: Counter::new(),
            p2p_bytes_received: Counter::new(),

            finalized_epoch: Gauge::new(),
            checkpoint_votes_received: Counter::new(),
            reorgs: Counter::new(),
            reorg_max_depth: Gauge::new(),

            zkp_verifications: Counter::new(),
            zkp_verification_failures: Counter::new(),

            active_validators: Gauge::new(),
            total_bonded_stake: Gauge::new(),
            slashing_events: Counter::new(),

            uptime_seconds: Gauge::new(),
            snapshot_saves: Counter::new(),
            snapshot_save_errors: Counter::new(),
        })
    }

    /// Render all metrics in Prometheus exposition format.
    ///
    /// Example output:
    /// ```text
    /// # HELP misaka_block_height Current block height
    /// # TYPE misaka_block_height gauge
    /// misaka_block_height 12345
    /// ```
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(4096);

        // Helper macros
        macro_rules! gauge {
            ($name:expr, $help:expr, $val:expr) => {
                out.push_str(&format!(
                    "# HELP {} {}\n# TYPE {} gauge\n{} {}\n",
                    $name, $help, $name, $name, $val
                ));
            };
        }
        macro_rules! counter {
            ($name:expr, $help:expr, $val:expr) => {
                out.push_str(&format!(
                    "# HELP {} {}\n# TYPE {} counter\n{} {}\n",
                    $name, $help, $name, $name, $val
                ));
            };
        }

        // Chain
        gauge!(
            "misaka_block_height",
            "Current block height",
            self.block_height.get()
        );
        counter!(
            "misaka_blocks_produced_total",
            "Total blocks produced by this node",
            self.blocks_produced.get()
        );
        counter!(
            "misaka_blocks_received_total",
            "Total blocks received from peers",
            self.blocks_received.get()
        );
        counter!(
            "misaka_block_production_errors_total",
            "Block production failures",
            self.block_production_errors.get()
        );

        // Transactions
        counter!(
            "misaka_tx_total",
            "Total transactions processed",
            self.tx_total.get()
        );
        counter!(
            "misaka_tx_submitted_rpc_total",
            "Transactions submitted via RPC",
            self.tx_submitted_rpc.get()
        );
        counter!(
            "misaka_tx_rejected_total",
            "Transactions rejected",
            self.tx_rejected.get()
        );
        counter!(
            "misaka_tx_fees_total",
            "Total transaction fees collected (base units)",
            self.tx_fees_total.get()
        );

        // Mempool
        gauge!(
            "misaka_mempool_size",
            "Current mempool transaction count",
            self.mempool_size.get()
        );
        counter!(
            "misaka_mempool_evictions_total",
            "Mempool eviction events",
            self.mempool_evictions.get()
        );

        // UTXO
        gauge!(
            "misaka_utxo_count",
            "Current unspent output count",
            self.utxo_count.get()
        );
        gauge!(
            "misaka_spent_count",
            "Current spent spent count",
            self.spent_count.get()
        );

        // P2P
        gauge!(
            "misaka_p2p_peers_connected",
            "Total connected peers",
            self.p2p_peers_connected.get()
        );
        gauge!(
            "misaka_p2p_peers_inbound",
            "Inbound peer connections",
            self.p2p_peers_inbound.get()
        );
        gauge!(
            "misaka_p2p_peers_outbound",
            "Outbound peer connections",
            self.p2p_peers_outbound.get()
        );
        counter!(
            "misaka_p2p_messages_sent_total",
            "P2P messages sent",
            self.p2p_messages_sent.get()
        );
        counter!(
            "misaka_p2p_messages_received_total",
            "P2P messages received",
            self.p2p_messages_received.get()
        );
        counter!(
            "misaka_p2p_bytes_sent_total",
            "P2P bytes sent",
            self.p2p_bytes_sent.get()
        );
        counter!(
            "misaka_p2p_bytes_received_total",
            "P2P bytes received",
            self.p2p_bytes_received.get()
        );

        // Consensus
        gauge!(
            "misaka_finalized_epoch",
            "Latest finalized epoch number",
            self.finalized_epoch.get()
        );
        counter!(
            "misaka_checkpoint_votes_received_total",
            "Checkpoint votes received",
            self.checkpoint_votes_received.get()
        );
        counter!(
            "misaka_reorgs_total",
            "Chain reorganization events",
            self.reorgs.get()
        );
        gauge!(
            "misaka_reorg_max_depth",
            "Deepest reorg observed",
            self.reorg_max_depth.get()
        );

        // ZKP
        counter!(
            "misaka_zkp_verifications_total",
            "ZK proof verifications performed",
            self.zkp_verifications.get()
        );
        counter!(
            "misaka_zkp_verification_failures_total",
            "ZK proof verification failures",
            self.zkp_verification_failures.get()
        );

        // Staking
        gauge!(
            "misaka_active_validators",
            "Number of active validators",
            self.active_validators.get()
        );
        gauge!(
            "misaka_total_bonded_stake",
            "Total bonded stake (base units)",
            self.total_bonded_stake.get()
        );
        counter!(
            "misaka_slashing_events_total",
            "Validator slashing events",
            self.slashing_events.get()
        );

        // System
        gauge!(
            "misaka_uptime_seconds",
            "Node uptime in seconds",
            self.uptime_seconds.get()
        );
        counter!(
            "misaka_snapshot_saves_total",
            "UTXO snapshot save operations",
            self.snapshot_saves.get()
        );
        counter!(
            "misaka_snapshot_save_errors_total",
            "Failed snapshot save operations",
            self.snapshot_save_errors.get()
        );

        out
    }
}

impl Default for NodeMetrics {
    fn default() -> Self {
        // Can't use Arc here; use new() for shared access
        Self {
            block_height: Gauge::new(),
            blocks_produced: Counter::new(),
            blocks_received: Counter::new(),
            block_production_errors: Counter::new(),
            tx_total: Counter::new(),
            tx_submitted_rpc: Counter::new(),
            tx_rejected: Counter::new(),
            tx_fees_total: Counter::new(),
            mempool_size: Gauge::new(),
            mempool_evictions: Counter::new(),
            utxo_count: Gauge::new(),
            spent_count: Gauge::new(),
            p2p_peers_connected: Gauge::new(),
            p2p_peers_inbound: Gauge::new(),
            p2p_peers_outbound: Gauge::new(),
            p2p_messages_sent: Counter::new(),
            p2p_messages_received: Counter::new(),
            p2p_bytes_sent: Counter::new(),
            p2p_bytes_received: Counter::new(),
            finalized_epoch: Gauge::new(),
            checkpoint_votes_received: Counter::new(),
            reorgs: Counter::new(),
            reorg_max_depth: Gauge::new(),
            zkp_verifications: Counter::new(),
            zkp_verification_failures: Counter::new(),
            active_validators: Gauge::new(),
            total_bonded_stake: Gauge::new(),
            slashing_events: Counter::new(),
            uptime_seconds: Gauge::new(),
            snapshot_saves: Counter::new(),
            snapshot_save_errors: Counter::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter() {
        let c = Counter::new();
        assert_eq!(c.get(), 0);
        c.inc();
        assert_eq!(c.get(), 1);
        c.add(10);
        assert_eq!(c.get(), 11);
    }

    #[test]
    fn test_gauge() {
        let g = Gauge::new();
        assert_eq!(g.get(), 0);
        g.set(42);
        assert_eq!(g.get(), 42);
        g.inc();
        assert_eq!(g.get(), 43);
        g.dec();
        assert_eq!(g.get(), 42);
    }

    #[test]
    fn test_render_prometheus() {
        let m = NodeMetrics::new();
        m.block_height.set(100);
        m.blocks_produced.add(50);
        m.p2p_peers_connected.set(8);

        let output = m.render_prometheus();
        assert!(output.contains("misaka_block_height 100"));
        assert!(output.contains("misaka_blocks_produced_total 50"));
        assert!(output.contains("misaka_p2p_peers_connected 8"));
        assert!(output.contains("# TYPE misaka_block_height gauge"));
        assert!(output.contains("# TYPE misaka_blocks_produced_total counter"));
    }
}
