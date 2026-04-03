//! Single-event subscription tracking.

use crate::events::EventType;
use crate::listener::ListenerId;
use std::collections::HashSet;

/// Tracks which listeners are subscribed to a single event type.
pub struct SingleSubscription {
    _event_type: EventType,
    listeners: HashSet<ListenerId>,
}

impl SingleSubscription {
    pub fn new(event_type: EventType) -> Self {
        Self {
            _event_type: event_type,
            listeners: HashSet::new(),
        }
    }

    pub fn add(&mut self, id: ListenerId) -> bool {
        self.listeners.insert(id)
    }
    pub fn remove(&mut self, id: &ListenerId) -> bool {
        self.listeners.remove(id)
    }
    pub fn contains(&self, id: &ListenerId) -> bool {
        self.listeners.contains(id)
    }
    pub fn count(&self) -> usize {
        self.listeners.len()
    }
    pub fn listeners(&self) -> &HashSet<ListenerId> {
        &self.listeners
    }
}
