//! Broadcaster: distributes notifications to all matching subscribers.

use crate::error::{NotifyError, NotifyResult};
use crate::listener::ListenerId;
use crate::notification::Notification;
use crate::subscriber::Subscriber;
use parking_lot::RwLock;
use std::collections::HashMap;

/// Broadcasts notifications to registered subscribers.
pub struct Broadcaster {
    subscribers: RwLock<HashMap<ListenerId, Subscriber>>,
}

impl Broadcaster {
    pub fn new() -> Self {
        Self {
            subscribers: RwLock::new(HashMap::new()),
        }
    }

    pub fn register(&self, subscriber: Subscriber) {
        let id = subscriber.listener_id;
        self.subscribers.write().insert(id, subscriber);
    }

    pub fn unregister(&self, listener_id: ListenerId) -> NotifyResult<()> {
        self.subscribers
            .write()
            .remove(&listener_id)
            .map(|_| ())
            .ok_or(NotifyError::ListenerNotFound(listener_id))
    }

    /// Broadcast a notification to all matching subscribers.
    pub fn broadcast(&self, notification: &Notification) -> usize {
        let subscribers = self.subscribers.read();
        let mut delivered = 0;
        for subscriber in subscribers.values() {
            if subscriber.matches(notification) {
                if subscriber.try_send(notification).is_ok() {
                    delivered += 1;
                }
            }
        }
        delivered
    }

    pub fn subscriber_count(&self) -> usize {
        self.subscribers.read().len()
    }
}

impl Default for Broadcaster {
    fn default() -> Self {
        Self::new()
    }
}
