//! Subscription scopes: which notifications to receive.

use crate::events::EventType;

/// Scope of a notification subscription.
#[derive(Debug, Clone)]
pub enum Scope {
    /// Subscribe to a single event type.
    Single(EventType),
    /// Subscribe to specific address changes.
    UtxosChanged(UtxosChangedScope),
    /// Subscribe to all events.
    All,
}

#[derive(Debug, Clone)]
pub struct UtxosChangedScope {
    pub addresses: Vec<String>,
}

impl Scope {
    pub fn matches(&self, event: &EventType) -> bool {
        match self {
            Scope::Single(et) => et == event,
            Scope::All => true,
            Scope::UtxosChanged(_) => *event == EventType::UtxosChanged,
        }
    }
}
