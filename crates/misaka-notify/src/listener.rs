//! Listener management: track subscribed clients.

use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_LISTENER_ID: AtomicU64 = AtomicU64::new(1);

/// Unique listener identifier.
pub type ListenerId = u64;

/// Allocate a new unique listener ID.
pub fn new_listener_id() -> ListenerId {
    NEXT_LISTENER_ID.fetch_add(1, Ordering::Relaxed)
}

/// Listener registration info.
#[derive(Debug, Clone)]
pub struct ListenerInfo {
    pub id: ListenerId,
    pub name: String,
    pub created_at: u64,
}
