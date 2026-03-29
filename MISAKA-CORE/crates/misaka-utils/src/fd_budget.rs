//! File descriptor budget management.

use std::sync::atomic::{AtomicUsize, Ordering};

static FD_LIMIT: AtomicUsize = AtomicUsize::new(1024);
static FD_USED: AtomicUsize = AtomicUsize::new(0);

/// Set the file descriptor budget.
pub fn set_fd_limit(limit: usize) {
    FD_LIMIT.store(limit, Ordering::Release);
}

/// Try to acquire a file descriptor slot.
pub fn try_acquire_fd() -> bool {
    let limit = FD_LIMIT.load(Ordering::Acquire);
    loop {
        let current = FD_USED.load(Ordering::Acquire);
        if current >= limit { return false; }
        if FD_USED.compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            return true;
        }
    }
}

/// Release a file descriptor slot.
pub fn release_fd() {
    FD_USED.fetch_sub(1, Ordering::Release);
}

/// Get current FD usage.
pub fn fd_usage() -> (usize, usize) {
    (FD_USED.load(Ordering::Acquire), FD_LIMIT.load(Ordering::Acquire))
}

/// RAII FD guard.
pub struct FdGuard(());

impl FdGuard {
    pub fn try_new() -> Option<Self> {
        if try_acquire_fd() { Some(Self(())) } else { None }
    }
}

impl Drop for FdGuard {
    fn drop(&mut self) { release_fd(); }
}
