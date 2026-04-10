//! Subscription management: tracking what each listener is subscribed to.

pub mod compounded;
pub mod context;
pub mod single;

use crate::listener::ListenerId;
use crate::scope::Scope;

/// Command for modifying subscriptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Start,
    Stop,
}

/// Subscription state for a listener.
#[derive(Debug, Clone)]
pub struct SubscriptionState {
    pub listener_id: ListenerId,
    pub scopes: Vec<Scope>,
    pub active: bool,
}

impl SubscriptionState {
    pub fn new(listener_id: ListenerId) -> Self {
        Self {
            listener_id,
            scopes: Vec::new(),
            active: true,
        }
    }
}
