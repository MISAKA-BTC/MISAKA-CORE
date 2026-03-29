//! Wallet performance and usage metrics.

use serde::{Serialize, Deserialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// Wallet operation metrics.
#[derive(Debug, Default)]
pub struct WalletMetrics {
    pub txs_sent: AtomicU64,
    pub txs_received: AtomicU64,
    pub total_sent_amount: AtomicU64,
    pub total_received_amount: AtomicU64,
    pub failed_txs: AtomicU64,
    pub rpc_calls: AtomicU64,
    pub rpc_errors: AtomicU64,
    pub sync_rounds: AtomicU64,
    pub addresses_generated: AtomicU64,
    pub utxos_discovered: AtomicU64,
}

impl WalletMetrics {
    pub fn snapshot(&self) -> WalletMetricsSnapshot {
        WalletMetricsSnapshot {
            txs_sent: self.txs_sent.load(Ordering::Relaxed),
            txs_received: self.txs_received.load(Ordering::Relaxed),
            total_sent_amount: self.total_sent_amount.load(Ordering::Relaxed),
            total_received_amount: self.total_received_amount.load(Ordering::Relaxed),
            failed_txs: self.failed_txs.load(Ordering::Relaxed),
            rpc_calls: self.rpc_calls.load(Ordering::Relaxed),
            rpc_errors: self.rpc_errors.load(Ordering::Relaxed),
            sync_rounds: self.sync_rounds.load(Ordering::Relaxed),
            addresses_generated: self.addresses_generated.load(Ordering::Relaxed),
            utxos_discovered: self.utxos_discovered.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletMetricsSnapshot {
    pub txs_sent: u64,
    pub txs_received: u64,
    pub total_sent_amount: u64,
    pub total_received_amount: u64,
    pub failed_txs: u64,
    pub rpc_calls: u64,
    pub rpc_errors: u64,
    pub sync_rounds: u64,
    pub addresses_generated: u64,
    pub utxos_discovered: u64,
}

/// Transaction history entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionHistoryEntry {
    pub tx_id: String,
    pub direction: TxDirection,
    pub amount: u64,
    pub fee: u64,
    pub counterparty: Option<String>,
    pub timestamp: u64,
    pub block_hash: Option<String>,
    pub confirmations: u64,
    pub status: TxStatus,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxDirection { Sent, Received, Self_ }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxStatus { Pending, Confirmed, Failed, Replaced }
