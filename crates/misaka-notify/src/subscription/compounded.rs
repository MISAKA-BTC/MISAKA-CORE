//! Compounded subscription: merges multiple subscriptions per listener.

use crate::events::EventType;
use crate::listener::ListenerId;
use std::collections::{HashMap, HashSet};

/// Compounded subscriptions across all event types.
pub struct CompoundedSubscription {
    by_event: HashMap<EventType, HashSet<ListenerId>>,
    by_listener: HashMap<ListenerId, HashSet<EventType>>,
}

impl CompoundedSubscription {
    pub fn new() -> Self {
        Self {
            by_event: HashMap::new(),
            by_listener: HashMap::new(),
        }
    }

    pub fn subscribe(&mut self, listener: ListenerId, event: EventType) {
        self.by_event.entry(event).or_default().insert(listener);
        self.by_listener.entry(listener).or_default().insert(event);
    }

    pub fn unsubscribe(&mut self, listener: ListenerId, event: &EventType) {
        if let Some(listeners) = self.by_event.get_mut(event) {
            listeners.remove(&listener);
        }
        if let Some(events) = self.by_listener.get_mut(&listener) {
            events.remove(event);
        }
    }

    pub fn unsubscribe_all(&mut self, listener: &ListenerId) {
        if let Some(events) = self.by_listener.remove(listener) {
            for event in events {
                if let Some(listeners) = self.by_event.get_mut(&event) {
                    listeners.remove(listener);
                }
            }
        }
    }

    pub fn listeners_for(&self, event: &EventType) -> impl Iterator<Item = &ListenerId> {
        self.by_event.get(event).into_iter().flat_map(|s| s.iter())
    }

    pub fn events_for(&self, listener: &ListenerId) -> impl Iterator<Item = &EventType> {
        self.by_listener
            .get(listener)
            .into_iter()
            .flat_map(|s| s.iter())
    }
}

impl Default for CompoundedSubscription {
    fn default() -> Self {
        Self::new()
    }
}
