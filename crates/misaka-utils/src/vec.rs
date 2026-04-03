//! Vector utilities: sorted insertion, dedup, etc.

/// Insert into a sorted vec, maintaining order.
pub fn sorted_insert<T: Ord>(vec: &mut Vec<T>, item: T) {
    let pos = vec.binary_search(&item).unwrap_or_else(|e| e);
    vec.insert(pos, item);
}

/// Remove from a sorted vec by value.
pub fn sorted_remove<T: Ord>(vec: &mut Vec<T>, item: &T) -> bool {
    if let Ok(pos) = vec.binary_search(item) {
        vec.remove(pos);
        true
    } else {
        false
    }
}

/// Check if a sorted vec contains a value.
pub fn sorted_contains<T: Ord>(vec: &[T], item: &T) -> bool {
    vec.binary_search(item).is_ok()
}
