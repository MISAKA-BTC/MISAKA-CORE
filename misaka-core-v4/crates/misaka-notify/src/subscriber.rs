//! Subscriber: wraps a listener with its channel for receiving notifications.

use crate::listener::ListenerId;
use crate::notification::Notification;
use crate::scope::Scope;
use tokio::sync::mpsc;

/// A subscriber that receives notifications on a channel.
pub struct Subscriber {
    pub listener_id: ListenerId,
    pub scopes: Vec<Scope>,
    sender: mpsc::Sender<Notification>,
}

impl Subscriber {
    pub fn new(listener_id: ListenerId, capacity: usize) -> (Self, mpsc::Receiver<Notification>) {
        let (sender, receiver) = mpsc::channel(capacity);
        (
            Self {
                listener_id,
                scopes: Vec::new(),
                sender,
            },
            receiver,
        )
    }

    pub fn add_scope(&mut self, scope: Scope) {
        self.scopes.push(scope);
    }

    pub fn matches(&self, notification: &Notification) -> bool {
        self.scopes
            .iter()
            .any(|s| s.matches(&notification.event_type))
    }

    pub async fn send(&self, notification: Notification) -> Result<(), ()> {
        self.sender.send(notification).await.map_err(|_| ())
    }

    pub fn try_send(&self, notification: &Notification) -> Result<(), ()> {
        self.sender.try_send(notification.clone()).map_err(|_| ())
    }
}
