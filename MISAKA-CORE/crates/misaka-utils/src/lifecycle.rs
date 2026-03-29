//! Lifecycle management: services, async runtimes, graceful shutdown.

use parking_lot::RwLock;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::watch;
use tracing::{info, warn, error};

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
        info!("Runtime '{}' started with {} services", self.name, services.len());
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
