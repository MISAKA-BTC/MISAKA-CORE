//! Multi-producer multi-consumer channel utilities.

use tokio::sync::{broadcast, mpsc};

/// Bounded channel with backpressure metrics.
pub struct MeteredChannel<T> {
    sender: mpsc::Sender<T>,
    receiver: Option<mpsc::Receiver<T>>,
    capacity: usize,
    name: String,
}

impl<T: Send + 'static> MeteredChannel<T> {
    pub fn new(name: impl Into<String>, capacity: usize) -> Self {
        let (sender, receiver) = mpsc::channel(capacity);
        Self {
            sender,
            receiver: Some(receiver),
            capacity,
            name: name.into(),
        }
    }

    pub fn sender(&self) -> mpsc::Sender<T> {
        self.sender.clone()
    }

    pub fn take_receiver(&mut self) -> Option<mpsc::Receiver<T>> {
        self.receiver.take()
    }

    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

/// Broadcast channel with subscriber tracking.
pub struct TrackedBroadcast<T: Clone> {
    sender: broadcast::Sender<T>,
    subscriber_count: std::sync::atomic::AtomicUsize,
}

impl<T: Clone + Send + 'static> TrackedBroadcast<T> {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender,
            subscriber_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn send(&self, value: T) -> Result<usize, broadcast::error::SendError<T>> {
        self.sender.send(value)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<T> {
        self.subscriber_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.sender.subscribe()
    }

    pub fn subscriber_count(&self) -> usize {
        self.subscriber_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Draining iterator that collects all pending messages from a channel.
pub async fn drain_channel<T>(receiver: &mut mpsc::Receiver<T>, max: usize) -> Vec<T> {
    let mut items = Vec::new();
    while items.len() < max {
        match receiver.try_recv() {
            Ok(item) => items.push(item),
            Err(_) => break,
        }
    }
    items
}
