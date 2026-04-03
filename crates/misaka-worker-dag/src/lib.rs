//! MISAKA Worker — transaction accumulation for block inclusion.
pub mod batch_maker;

pub struct WorkerConfig {
    pub batch_size: usize,       // default 500KB
    pub batch_timeout_ms: u64,   // default 200ms
    pub worker_id: u16,
}
