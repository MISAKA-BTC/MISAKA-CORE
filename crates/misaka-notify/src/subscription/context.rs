//! Subscription context: per-listener state.

use crate::listener::ListenerId;
use std::collections::HashMap;

/// Context tracking for active subscriptions.
pub struct SubscriptionContext {
    contexts: HashMap<ListenerId, ListenerContext>,
}

#[derive(Debug, Clone)]
pub struct ListenerContext {
    pub listener_id: ListenerId,
    pub notification_count: u64,
    pub last_notification_time: u64,
    pub dropped_count: u64,
}

impl SubscriptionContext {
    pub fn new() -> Self {
        Self {
            contexts: HashMap::new(),
        }
    }

    pub fn register(&mut self, id: ListenerId) {
        self.contexts.insert(
            id,
            ListenerContext {
                listener_id: id,
                notification_count: 0,
                last_notification_time: 0,
                dropped_count: 0,
            },
        );
    }

    pub fn unregister(&mut self, id: &ListenerId) {
        self.contexts.remove(id);
    }

    pub fn record_notification(&mut self, id: &ListenerId) {
        if let Some(ctx) = self.contexts.get_mut(id) {
            ctx.notification_count += 1;
        }
    }

    pub fn record_drop(&mut self, id: &ListenerId) {
        if let Some(ctx) = self.contexts.get_mut(id) {
            ctx.dropped_count += 1;
        }
    }
}

impl Default for SubscriptionContext {
    fn default() -> Self {
        Self::new()
    }
}
