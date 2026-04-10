//! Collector: aggregates notifications from multiple sources.

use crate::notification::Notification;
use tokio::sync::mpsc;

/// Collects notifications from multiple producers.
pub struct Collector {
    receiver: mpsc::Receiver<Notification>,
    sender: mpsc::Sender<Notification>,
}

impl Collector {
    pub fn new(capacity: usize) -> Self {
        let (sender, receiver) = mpsc::channel(capacity);
        Self { receiver, sender }
    }

    pub fn sender(&self) -> mpsc::Sender<Notification> {
        self.sender.clone()
    }

    pub async fn collect(&mut self) -> Option<Notification> {
        self.receiver.recv().await
    }

    pub fn try_collect(&mut self) -> Option<Notification> {
        self.receiver.try_recv().ok()
    }
}
