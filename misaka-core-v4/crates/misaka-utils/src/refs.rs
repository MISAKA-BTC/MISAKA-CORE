//! Reference counting and Arc utilities.

use std::sync::Arc;

/// Try to unwrap an Arc, returning the inner value if this is the sole reference.
pub fn try_unwrap_arc<T>(arc: Arc<T>) -> Result<T, Arc<T>> {
    Arc::try_unwrap(arc)
}

/// Clone an Arc only if needed (when there's no exclusive access).
pub fn arc_clone_if_shared<T: Clone>(arc: &Arc<T>) -> Arc<T> {
    if Arc::strong_count(arc) == 1 {
        arc.clone()
    } else {
        Arc::new(T::clone(arc))
    }
}
