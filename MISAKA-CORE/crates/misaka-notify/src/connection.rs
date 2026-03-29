//! Connection-aware notification delivery.

use crate::listener::ListenerId;
use crate::notification::Notification;
use tokio::sync::mpsc;

/// A connection that receives notifications.
pub struct NotifyConnection {
    pub listener_id: ListenerId,
    sender: mpsc::Sender<Notification>,
}

impl NotifyConnection {
    pub fn new(listener_id: ListenerId, capacity: usize) -> (Self, mpsc::Receiver<Notification>) {
        let (sender, receiver) = mpsc::channel(capacity);
        (Self { listener_id, sender }, receiver)
    }

    pub async fn send(&self, notification: Notification) -> Result<(), ()> {
        self.sender.send(notification).await.map_err(|_| ())
    }

    pub fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }
}

/// Channel-based connection for RPC notification delivery.
pub struct ChannelConnection {
    sender: mpsc::Sender<Notification>,
    receiver: Option<mpsc::Receiver<Notification>>,
}

impl ChannelConnection {
    pub fn new(capacity: usize) -> Self {
        let (sender, receiver) = mpsc::channel(capacity);
        Self { sender, receiver: Some(receiver) }
    }

    pub fn sender(&self) -> mpsc::Sender<Notification> { self.sender.clone() }
    pub fn take_receiver(&mut self) -> Option<mpsc::Receiver<Notification>> { self.receiver.take() }
}
