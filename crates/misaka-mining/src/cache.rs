//! Block template cache for rapid template delivery.

use crate::block_template::BlockTemplate;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Cached block template with validity tracking.
struct CachedTemplate {
    template: Arc<BlockTemplate>,
    created_at: Instant,
    virtual_state_id: u64,
}

/// Thread-safe block template cache.
pub struct BlockTemplateCache {
    inner: Mutex<Option<CachedTemplate>>,
    lifetime: Duration,
}

impl BlockTemplateCache {
    pub fn new(lifetime_ms: Option<u64>) -> Self {
        Self {
            inner: Mutex::new(None),
            lifetime: Duration::from_millis(lifetime_ms.unwrap_or(2000)),
        }
    }

    /// Lock the cache and check validity against the current virtual state.
    pub fn lock(&self, virtual_state_id: u64) -> CacheLock<'_> {
        CacheLock {
            guard: self.inner.lock(),
            virtual_state_id,
            lifetime: self.lifetime,
        }
    }
}

pub struct CacheLock<'a> {
    guard: parking_lot::MutexGuard<'a, Option<CachedTemplate>>,
    virtual_state_id: u64,
    lifetime: Duration,
}

impl<'a> CacheLock<'a> {
    /// Get an immutable reference to the cached template if still valid.
    pub fn get_immutable_cached_template(&self) -> Option<Arc<BlockTemplate>> {
        self.guard.as_ref().and_then(|cached| {
            if cached.virtual_state_id == self.virtual_state_id
                && cached.created_at.elapsed() < self.lifetime
            {
                Some(cached.template.clone())
            } else {
                None
            }
        })
    }

    /// Store a new template in the cache.
    pub fn set_template(&mut self, template: BlockTemplate) {
        *self.guard = Some(CachedTemplate {
            template: Arc::new(template),
            created_at: Instant::now(),
            virtual_state_id: self.virtual_state_id,
        });
    }
}
