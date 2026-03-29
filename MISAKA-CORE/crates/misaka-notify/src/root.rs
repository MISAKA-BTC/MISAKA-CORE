//! Root notifier: top-level notification hub.

use crate::broadcaster::Broadcaster;
use crate::collector::Collector;
use crate::error::NotifyResult;
use crate::listener::{ListenerId, new_listener_id};
use crate::notification::Notification;
use crate::scope::Scope;
use crate::subscriber::Subscriber;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Root notification hub that connects collectors to broadcasters.
pub struct RootNotifier {
    broadcaster: Arc<Broadcaster>,
    collector: Collector,
}

impl RootNotifier {
    pub fn new(collector_capacity: usize) -> Self {
        Self {
            broadcaster: Arc::new(Broadcaster::new()),
            collector: Collector::new(collector_capacity),
        }
    }

    /// Register a new subscriber and return its notification receiver.
    pub fn subscribe(&self, scopes: Vec<Scope>) -> (ListenerId, mpsc::Receiver<Notification>) {
        let id = new_listener_id();
        let (mut subscriber, receiver) = Subscriber::new(id, 256);
        for scope in scopes {
            subscriber.add_scope(scope);
        }
        self.broadcaster.register(subscriber);
        (id, receiver)
    }

    /// Unsubscribe a listener.
    pub fn unsubscribe(&self, id: ListenerId) -> NotifyResult<()> {
        self.broadcaster.unregister(id)
    }

    /// Get a sender for feeding notifications into the system.
    pub fn notification_sender(&self) -> mpsc::Sender<Notification> {
        self.collector.sender()
    }

    /// Run the notification processing loop.
    pub async fn run(&mut self) {
        while let Some(notification) = self.collector.collect().await {
            self.broadcaster.broadcast(&notification);
        }
    }

    pub fn broadcaster(&self) -> &Arc<Broadcaster> { &self.broadcaster }
}
