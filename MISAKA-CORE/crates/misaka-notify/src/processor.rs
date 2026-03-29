//! Notification processor — routes notifications through the pipeline.
//!
//! Processing pipeline:
//! 1. Collector receives raw event from consensus/mining
//! 2. Converter transforms to notification format
//! 3. Processor filters by scope and address
//! 4. Broadcaster delivers to subscribed listeners
//! 5. Connection delivers over wRPC/gRPC

use crate::events::EventType;
use crate::notification::*;
use crate::scope::Scope;
use crate::broadcaster::Broadcaster;
use crate::address::tracker::AddressTracker;
use std::sync::Arc;
use std::collections::HashMap;

/// Notification processing pipeline.
pub struct NotificationProcessor {
    broadcaster: Arc<Broadcaster>,
    address_tracker: Arc<parking_lot::RwLock<AddressTracker>>,
    filters: Vec<Box<dyn NotificationFilter + Send + Sync>>,
    stats: ProcessorStats,
}

/// Notification filter trait.
pub trait NotificationFilter: Send + Sync {
    fn should_deliver(&self, notification: &Notification, listener_id: u64) -> bool;
    fn name(&self) -> &str;
}

/// Address-based filter.
pub struct AddressFilter {
    tracker: Arc<parking_lot::RwLock<AddressTracker>>,
}

impl NotificationFilter for AddressFilter {
    fn should_deliver(&self, notification: &Notification, listener_id: u64) -> bool {
        match &notification.payload {
            NotificationPayload::UtxosChanged(utxo_notif) => {
                let tracker = self.tracker.read();
                // Check if any of the addresses in the notification are tracked by this listener
                utxo_notif.added.iter().chain(utxo_notif.removed.iter())
                    .any(|entry| {
                        tracker.listeners_for_address(&entry.address)
                            .contains(&listener_id)
                    })
            }
            _ => true, // Non-address events pass through
        }
    }

    fn name(&self) -> &str { "address_filter" }
}

/// Rate-limiting filter.
pub struct RateLimitFilter {
    limits: HashMap<EventType, (usize, std::time::Duration)>,
    counters: parking_lot::Mutex<HashMap<(u64, EventType), Vec<std::time::Instant>>>,
}

impl RateLimitFilter {
    pub fn new() -> Self {
        let mut limits = HashMap::new();
        limits.insert(EventType::BlockAdded, (60, std::time::Duration::from_secs(60)));
        limits.insert(EventType::UtxosChanged, (100, std::time::Duration::from_secs(60)));
        limits.insert(EventType::MempoolChanged, (30, std::time::Duration::from_secs(60)));
        Self { limits, counters: parking_lot::Mutex::new(HashMap::new()) }
    }
}

impl NotificationFilter for RateLimitFilter {
    fn should_deliver(&self, notification: &Notification, listener_id: u64) -> bool {
        let (max, window) = match self.limits.get(&notification.event_type) {
            Some(l) => *l,
            None => return true,
        };

        let key = (listener_id, notification.event_type);
        let now = std::time::Instant::now();
        let cutoff = now - window;

        let mut counters = self.counters.lock();
        let timestamps = counters.entry(key).or_default();
        timestamps.retain(|t| *t > cutoff);

        if timestamps.len() >= max {
            false
        } else {
            timestamps.push(now);
            true
        }
    }

    fn name(&self) -> &str { "rate_limit_filter" }
}

/// Processing statistics.
#[derive(Debug, Default)]
pub struct ProcessorStats {
    pub received: std::sync::atomic::AtomicU64,
    pub delivered: std::sync::atomic::AtomicU64,
    pub filtered: std::sync::atomic::AtomicU64,
    pub errors: std::sync::atomic::AtomicU64,
}

impl NotificationProcessor {
    pub fn new(
        broadcaster: Arc<Broadcaster>,
        address_tracker: Arc<parking_lot::RwLock<AddressTracker>>,
    ) -> Self {
        let tracker_clone = address_tracker.clone();
        Self {
            broadcaster,
            address_tracker,
            filters: vec![
                Box::new(AddressFilter { tracker: tracker_clone }),
                Box::new(RateLimitFilter::new()),
            ],
            stats: ProcessorStats::default(),
        }
    }

    /// Process a notification through the pipeline.
    pub fn process(&self, notification: Notification) -> usize {
        self.stats.received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Broadcast to all matching subscribers
        let delivered = self.broadcaster.broadcast(&notification);
        self.stats.delivered.fetch_add(delivered as u64, std::sync::atomic::Ordering::Relaxed);

        delivered
    }

    /// Get processing stats.
    pub fn stats_snapshot(&self) -> (u64, u64, u64, u64) {
        (
            self.stats.received.load(std::sync::atomic::Ordering::Relaxed),
            self.stats.delivered.load(std::sync::atomic::Ordering::Relaxed),
            self.stats.filtered.load(std::sync::atomic::Ordering::Relaxed),
            self.stats.errors.load(std::sync::atomic::Ordering::Relaxed),
        )
    }
}

/// Virtual chain changed notification builder.
pub fn build_virtual_chain_notification(
    added_blocks: Vec<String>,
    removed_blocks: Vec<String>,
    accepted_txs: Vec<String>,
) -> Notification {
    Notification {
        event_type: EventType::VirtualChainChanged,
        payload: NotificationPayload::VirtualChainChanged(VirtualChainChangedNotification {
            added_chain_block_hashes: added_blocks,
            removed_chain_block_hashes: removed_blocks,
            accepted_transaction_ids: accepted_txs,
        }),
    }
}

/// UTXO changed notification builder.
pub fn build_utxos_changed_notification(
    added: Vec<UtxoEntry>,
    removed: Vec<UtxoEntry>,
) -> Notification {
    Notification {
        event_type: EventType::UtxosChanged,
        payload: NotificationPayload::UtxosChanged(UtxosChangedNotification {
            added,
            removed,
        }),
    }
}

/// Mempool changed notification builder.
pub fn build_mempool_changed_notification(
    added_tx_ids: Vec<String>,
    removed_tx_ids: Vec<String>,
) -> Notification {
    Notification {
        event_type: EventType::MempoolChanged,
        payload: NotificationPayload::MempoolChanged(MempoolChangedNotification {
            added_tx_ids,
            removed_tx_ids,
        }),
    }
}
