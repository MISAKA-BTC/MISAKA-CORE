//! Lifecycle management: services, async runtimes, graceful shutdown.

use parking_lot::RwLock;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::watch;
use tracing::{error, info};

// ─── Service trait ────────────────────────────────────────────

/// Marker trait for synchronous service lifecycle.
pub trait Service: Send + Sync + 'static {
    fn name(&self) -> &str;
    fn start(&self) -> Result<(), LifecycleError>;
    fn stop(&self) -> Result<(), LifecycleError>;
    fn is_running(&self) -> bool;
}

/// Trait for async services managed by the runtime.
#[async_trait::async_trait]
pub trait AsyncService: Send + Sync + 'static {
    fn name(&self) -> &str;
    async fn start(&self) -> Result<(), LifecycleError>;
    async fn stop(&self) -> Result<(), LifecycleError>;
    fn is_running(&self) -> bool;
}

// ─── Lifecycle errors ─────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    #[error("Service '{0}' failed to start: {1}")]
    StartFailed(String, String),
    #[error("Service '{0}' failed to stop: {1}")]
    StopFailed(String, String),
    #[error("Service '{0}' already running")]
    AlreadyRunning(String),
    #[error("Service '{0}' not running")]
    NotRunning(String),
    #[error("Shutdown timeout after {0}ms")]
    ShutdownTimeout(u64),
    #[error("Runtime error: {0}")]
    Runtime(String),
}

// ─── Shutdown signal ──────────────────────────────────────────

/// Cooperative shutdown signal using tokio watch channel.
#[derive(Clone)]
pub struct ShutdownSignal {
    sender: Arc<watch::Sender<bool>>,
    receiver: watch::Receiver<bool>,
}

impl ShutdownSignal {
    pub fn new() -> Self {
        let (sender, receiver) = watch::channel(false);
        Self {
            sender: Arc::new(sender),
            receiver,
        }
    }

    /// Trigger shutdown for all listeners.
    pub fn trigger(&self) {
        let _ = self.sender.send(true);
    }

    /// Returns true if shutdown has been triggered.
    pub fn is_triggered(&self) -> bool {
        *self.receiver.borrow()
    }

    /// Wait until shutdown is triggered.
    pub async fn wait(&mut self) {
        while !*self.receiver.borrow_and_update() {
            if self.receiver.changed().await.is_err() {
                return;
            }
        }
    }

    /// Create a new receiver for this signal.
    pub fn subscribe(&self) -> ShutdownSignal {
        Self {
            sender: self.sender.clone(),
            receiver: self.receiver.clone(),
        }
    }
}

impl Default for ShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Async Runtime ────────────────────────────────────────────

/// Managed async runtime for service orchestration.
pub struct AsyncRuntime {
    name: String,
    running: AtomicBool,
    services: RwLock<Vec<Arc<dyn AsyncService>>>,
    shutdown: ShutdownSignal,
}

impl AsyncRuntime {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            running: AtomicBool::new(false),
            services: RwLock::new(Vec::new()),
            shutdown: ShutdownSignal::new(),
        }
    }

    pub fn register(&self, service: Arc<dyn AsyncService>) {
        self.services.write().push(service);
    }

    pub fn shutdown_signal(&self) -> ShutdownSignal {
        self.shutdown.subscribe()
    }

    pub async fn start(&self) -> Result<(), LifecycleError> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Err(LifecycleError::AlreadyRunning(self.name.clone()));
        }
        info!("Starting runtime '{}'", self.name);
        let services = self.services.read().clone();
        for svc in &services {
            info!("  Starting service: {}", svc.name());
            svc.start().await?;
        }
        info!(
            "Runtime '{}' started with {} services",
            self.name,
            services.len()
        );
        Ok(())
    }

    pub async fn stop(&self) -> Result<(), LifecycleError> {
        if !self.running.swap(false, Ordering::SeqCst) {
            return Err(LifecycleError::NotRunning(self.name.clone()));
        }
        info!("Stopping runtime '{}'", self.name);
        self.shutdown.trigger();
        let services = self.services.read().clone();
        for svc in services.iter().rev() {
            info!("  Stopping service: {}", svc.name());
            if let Err(e) = svc.stop().await {
                error!("Failed to stop service '{}': {}", svc.name(), e);
            }
        }
        info!("Runtime '{}' stopped", self.name);
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

// ─── Task spawner ─────────────────────────────────────────────

/// Spawn a named async task with panic logging.
pub fn spawn_task<F>(name: &str, future: F) -> tokio::task::JoinHandle<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let name = name.to_string();
    tokio::spawn(async move {
        future.await;
        tracing::trace!("Task '{}' completed", name);
    })
}

/// Spawn a blocking task on the blocking threadpool.
pub fn spawn_blocking<F, R>(name: &str, func: F) -> tokio::task::JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let _name = name.to_string();
    tokio::task::spawn_blocking(func)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use std::sync::Arc;
    use tokio::task::JoinHandle;
    use tokio::sync::Notify;
    use tokio::time::{timeout, Duration};

    struct TestAsyncService {
        name: &'static str,
        shutdown: ShutdownSignal,
        running: Arc<AtomicBool>,
        shutdown_observed: Arc<AtomicBool>,
        task: Mutex<Option<JoinHandle<()>>>,
    }

    impl TestAsyncService {
        fn new(name: &'static str, shutdown: ShutdownSignal) -> Self {
            Self {
                name,
                shutdown,
                running: Arc::new(AtomicBool::new(false)),
                shutdown_observed: Arc::new(AtomicBool::new(false)),
                task: Mutex::new(None),
            }
        }

        fn shutdown_observed(&self) -> bool {
            self.shutdown_observed.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl AsyncService for TestAsyncService {
        fn name(&self) -> &str {
            self.name
        }

        async fn start(&self) -> Result<(), LifecycleError> {
            if self.running.swap(true, Ordering::SeqCst) {
                return Err(LifecycleError::AlreadyRunning(self.name.to_string()));
            }

            let mut shutdown = self.shutdown.subscribe();
            let running = Arc::clone(&self.running);
            let shutdown_observed = Arc::clone(&self.shutdown_observed);
            let handle = tokio::spawn(async move {
                shutdown.wait().await;
                shutdown_observed.store(true, Ordering::SeqCst);
                running.store(false, Ordering::SeqCst);
            });
            *self.task.lock() = Some(handle);

            Ok(())
        }

        async fn stop(&self) -> Result<(), LifecycleError> {
            let handle = { self.task.lock().take() };
            if let Some(handle) = handle {
                handle.await.map_err(|err| {
                    LifecycleError::StopFailed(self.name.to_string(), err.to_string())
                })?;
            }
            self.running.store(false, Ordering::SeqCst);
            Ok(())
        }

        fn is_running(&self) -> bool {
            self.running.load(Ordering::SeqCst)
        }
    }

    struct NotifiedAsyncService {
        name: &'static str,
        running: Arc<AtomicBool>,
        stop_observed: Arc<AtomicBool>,
        started: Arc<Notify>,
        stop_requested: Arc<Notify>,
        task: Mutex<Option<JoinHandle<()>>>,
    }

    impl NotifiedAsyncService {
        fn new(name: &'static str) -> Self {
            Self {
                name,
                running: Arc::new(AtomicBool::new(false)),
                stop_observed: Arc::new(AtomicBool::new(false)),
                started: Arc::new(Notify::new()),
                stop_requested: Arc::new(Notify::new()),
                task: Mutex::new(None),
            }
        }

        fn started_signal(&self) -> Arc<Notify> {
            Arc::clone(&self.started)
        }

        fn stop_observed(&self) -> bool {
            self.stop_observed.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl AsyncService for NotifiedAsyncService {
        fn name(&self) -> &str {
            self.name
        }

        async fn start(&self) -> Result<(), LifecycleError> {
            if self.running.swap(true, Ordering::SeqCst) {
                return Err(LifecycleError::AlreadyRunning(self.name.to_string()));
            }

            let running = Arc::clone(&self.running);
            let stop_observed = Arc::clone(&self.stop_observed);
            let started = Arc::clone(&self.started);
            let stop_requested = Arc::clone(&self.stop_requested);
            let handle = tokio::spawn(async move {
                started.notify_one();
                stop_requested.notified().await;
                stop_observed.store(true, Ordering::SeqCst);
                running.store(false, Ordering::SeqCst);
            });
            *self.task.lock() = Some(handle);

            Ok(())
        }

        async fn stop(&self) -> Result<(), LifecycleError> {
            self.stop_requested.notify_one();
            let handle = { self.task.lock().take() };
            if let Some(handle) = handle {
                handle.await.map_err(|err| {
                    LifecycleError::StopFailed(self.name.to_string(), err.to_string())
                })?;
            }
            self.running.store(false, Ordering::SeqCst);
            Ok(())
        }

        fn is_running(&self) -> bool {
            self.running.load(Ordering::SeqCst)
        }
    }

    #[tokio::test]
    async fn async_runtime_start_stop_smoke_triggers_shutdown_signal() {
        let runtime = AsyncRuntime::new("smoke-runtime");
        let shutdown = runtime.shutdown_signal();
        let service = Arc::new(TestAsyncService::new(
            "smoke-service",
            shutdown.clone(),
        ));

        assert!(!runtime.is_running());
        assert!(!shutdown.is_triggered());
        assert!(!service.is_running());
        assert!(!service.shutdown_observed());

        runtime.register(service.clone());
        runtime.start().await.expect("runtime should start");

        assert!(runtime.is_running());
        assert!(service.is_running());
        assert!(!shutdown.is_triggered());
        assert!(!service.shutdown_observed());

        runtime.stop().await.expect("runtime should stop");

        assert!(!runtime.is_running());
        assert!(shutdown.is_triggered());
        assert!(!service.is_running());
        assert!(service.shutdown_observed());
    }

    #[tokio::test]
    async fn async_runtime_stops_waiting_service_cleanly() {
        let runtime = AsyncRuntime::new("notify-runtime");
        let service = Arc::new(NotifiedAsyncService::new("notify-service"));
        let started = service.started_signal();

        runtime.register(service.clone());
        runtime.start().await.expect("runtime should start");
        timeout(Duration::from_secs(1), started.notified())
            .await
            .expect("service should enter running state");

        assert!(runtime.is_running());
        assert!(service.is_running());
        assert!(!service.stop_observed());

        runtime.stop().await.expect("runtime should stop");

        assert!(!runtime.is_running());
        assert!(!service.is_running());
        assert!(service.stop_observed());
    }
}
