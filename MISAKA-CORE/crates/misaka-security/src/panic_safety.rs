//! Panic safety — prevent panics from crashing the node.
//!
//! Consensus-critical code MUST NOT panic. This module provides:
//! - Panic hooks for graceful degradation
//! - Catch-unwind wrappers for P2P message handlers
//! - Panic statistics for monitoring

use std::sync::atomic::{AtomicU64, Ordering};

static PANIC_COUNT: AtomicU64 = AtomicU64::new(0);
static CAUGHT_PANICS: AtomicU64 = AtomicU64::new(0);

/// Install the global panic hook for MISAKA.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        PANIC_COUNT.fetch_add(1, Ordering::Relaxed);
        let location = info.location().map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());
        let message = info.payload().downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown panic".to_string());

        tracing::error!("PANIC at {}: {}", location, message);
        eprintln!("MISAKA NODE PANIC at {}: {}", location, message);
    }));
}

/// Catch panics from untrusted code (P2P handlers, script execution).
pub fn catch_panic<F, T>(f: F) -> Result<T, PanicError>
where
    F: FnOnce() -> T + std::panic::UnwindSafe,
{
    match std::panic::catch_unwind(f) {
        Ok(result) => Ok(result),
        Err(payload) => {
            CAUGHT_PANICS.fetch_add(1, Ordering::Relaxed);
            let message = payload.downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".to_string());
            Err(PanicError { message })
        }
    }
}

/// Get panic statistics.
pub fn panic_stats() -> PanicStats {
    PanicStats {
        total_panics: PANIC_COUNT.load(Ordering::Relaxed),
        caught_panics: CAUGHT_PANICS.load(Ordering::Relaxed),
    }
}

pub struct PanicStats {
    pub total_panics: u64,
    pub caught_panics: u64,
}

#[derive(Debug)]
pub struct PanicError {
    pub message: String,
}

impl std::fmt::Display for PanicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "panic: {}", self.message)
    }
}

impl std::error::Error for PanicError {}
