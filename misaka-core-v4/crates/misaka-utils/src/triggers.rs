//! Cooperative triggers for cross-task coordination.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::Notify;

/// Duplex trigger: signal + wait from either side.
pub struct DuplexTrigger {
    state: Arc<TriggerState>,
}

struct TriggerState {
    triggered: AtomicBool,
    notify: Notify,
}

impl DuplexTrigger {
    pub fn new() -> Self {
        Self {
            state: Arc::new(TriggerState {
                triggered: AtomicBool::new(false),
                notify: Notify::new(),
            }),
        }
    }

    pub fn trigger(&self) {
        self.state.triggered.store(true, Ordering::Release);
        self.state.notify.notify_waiters();
    }

    pub fn is_triggered(&self) -> bool {
        self.state.triggered.load(Ordering::Acquire)
    }

    pub async fn wait(&self) {
        loop {
            if self.state.triggered.load(Ordering::Acquire) {
                return;
            }
            self.state.notify.notified().await;
        }
    }

    pub fn reset(&self) {
        self.state.triggered.store(false, Ordering::Release);
    }
}

impl Default for DuplexTrigger {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for DuplexTrigger {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

/// One-shot trigger that fires exactly once.
pub struct OnceTrigger {
    inner: DuplexTrigger,
}

impl OnceTrigger {
    pub fn new() -> Self {
        Self {
            inner: DuplexTrigger::new(),
        }
    }
    pub fn trigger(&self) {
        self.inner.trigger();
    }
    pub fn is_triggered(&self) -> bool {
        self.inner.is_triggered()
    }
    pub async fn wait(&self) {
        self.inner.wait().await;
    }
}

impl Default for OnceTrigger {
    fn default() -> Self {
        Self::new()
    }
}

/// Interval trigger for periodic tasks.
pub struct IntervalTrigger {
    interval_ms: u64,
    last_trigger: std::sync::Mutex<std::time::Instant>,
}

impl IntervalTrigger {
    pub fn new(interval_ms: u64) -> Self {
        Self {
            interval_ms,
            last_trigger: std::sync::Mutex::new(std::time::Instant::now()),
        }
    }

    pub fn should_trigger(&self) -> bool {
        let mut last = self.last_trigger.lock().unwrap_or_else(|e| e.into_inner());
        if last.elapsed().as_millis() as u64 >= self.interval_ms {
            *last = std::time::Instant::now();
            true
        } else {
            false
        }
    }
}
