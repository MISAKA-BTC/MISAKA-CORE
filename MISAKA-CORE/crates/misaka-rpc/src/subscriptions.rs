//! RPC subscription management.

use std::collections::{HashMap, HashSet};
use parking_lot::RwLock;

/// Subscription scope types.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SubscriptionScope {
    BlockAdded,
    VirtualChainChanged,
    FinalityConflict,
    UtxosChanged { addresses: Vec<String> },
    SinkBlueScoreChanged,
    VirtualDaaScoreChanged,
    PruningPointUtxoSetOverride,
    NewBlockTemplate,
    MempoolChanged,
}

impl SubscriptionScope {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "blockAdded" => Some(Self::BlockAdded),
            "virtualChainChanged" => Some(Self::VirtualChainChanged),
            "finalityConflict" => Some(Self::FinalityConflict),
            "sinkBlueScoreChanged" => Some(Self::SinkBlueScoreChanged),
            "virtualDaaScoreChanged" => Some(Self::VirtualDaaScoreChanged),
            "newBlockTemplate" => Some(Self::NewBlockTemplate),
            "mempoolChanged" => Some(Self::MempoolChanged),
            _ => None,
        }
    }
}

/// Manages active RPC subscriptions.
pub struct SubscriptionManager {
    next_id: std::sync::atomic::AtomicU64,
    subscriptions: RwLock<HashMap<u64, ActiveSubscription>>,
    by_scope: RwLock<HashMap<String, HashSet<u64>>>,
}

struct ActiveSubscription {
    id: u64,
    client_id: u64,
    scope: SubscriptionScope,
}

impl SubscriptionManager {
    pub fn new() -> Self {
        Self {
            next_id: std::sync::atomic::AtomicU64::new(1),
            subscriptions: RwLock::new(HashMap::new()),
            by_scope: RwLock::new(HashMap::new()),
        }
    }

    pub fn subscribe(&self, client_id: u64, scope: SubscriptionScope) -> u64 {
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let scope_key = format!("{:?}", scope);

        self.subscriptions.write().insert(id, ActiveSubscription {
            id,
            client_id,
            scope,
        });
        self.by_scope.write().entry(scope_key).or_default().insert(id);

        id
    }

    pub fn unsubscribe(&self, id: u64) -> bool {
        if let Some(sub) = self.subscriptions.write().remove(&id) {
            let scope_key = format!("{:?}", sub.scope);
            if let Some(set) = self.by_scope.write().get_mut(&scope_key) {
                set.remove(&id);
            }
            true
        } else {
            false
        }
    }

    pub fn unsubscribe_all(&self, client_id: u64) -> usize {
        let ids: Vec<u64> = self.subscriptions.read().values()
            .filter(|s| s.client_id == client_id)
            .map(|s| s.id)
            .collect();
        let count = ids.len();
        for id in ids {
            self.unsubscribe(id);
        }
        count
    }

    pub fn subscription_count(&self) -> usize { self.subscriptions.read().len() }
}

impl Default for SubscriptionManager {
    fn default() -> Self { Self::new() }
}
