//! System information collection for metrics reporting.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub version: String,
    pub git_hash: Option<String>,
    pub cpu_count: usize,
    pub total_memory_bytes: u64,
    pub os: String,
    pub arch: String,
    pub uptime_seconds: u64,
}

impl SystemInfo {
    pub fn collect(version: &str) -> Self {
        Self {
            version: version.to_string(),
            git_hash: option_env!("GIT_HASH").map(String::from),
            cpu_count: num_cpus(),
            total_memory_bytes: 0, // Platform-specific
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            uptime_seconds: 0,
        }
    }
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcessMetrics {
    pub resident_set_bytes: u64,
    pub virtual_memory_bytes: u64,
    pub cpu_usage_percent: f64,
    pub fd_count: u64,
    pub thread_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConnectionMetrics {
    pub active_peers: u32,
    pub inbound_connections: u32,
    pub outbound_connections: u32,
    pub banned_peers: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BandwidthMetrics {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConsensusMetrics {
    pub header_count: u64,
    pub block_count: u64,
    pub tip_hashes_count: u32,
    pub difficulty: f64,
    pub past_median_time: u64,
    pub virtual_parent_hashes_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StorageMetrics {
    pub database_size_bytes: u64,
    pub utxo_set_size: u64,
    pub headers_store_size: u64,
}

/// Disk space information for a given path.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiskSpaceInfo {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_percent: f64,
}

const LOW_DISK_THRESHOLD_BYTES: u64 = 1024 * 1024 * 1024; // 1 GiB

impl DiskSpaceInfo {
    /// Check the disk space for the given path. Returns None on unsupported platforms.
    #[cfg(unix)]
    pub fn check(path: &std::path::Path) -> Option<Self> {
        use std::ffi::CString;
        let c_path = CString::new(path.to_str()?).ok()?;
        unsafe {
            let mut stat = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
            if libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) != 0 {
                return None;
            }
            let stat = stat.assume_init();
            let total = stat.f_blocks as u64 * stat.f_frsize as u64;
            let available = stat.f_bavail as u64 * stat.f_frsize as u64;
            let used = total.saturating_sub(available);
            let used_percent = if total > 0 {
                (used as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            Some(Self {
                total_bytes: total,
                available_bytes: available,
                used_percent,
            })
        }
    }

    #[cfg(not(unix))]
    pub fn check(_path: &std::path::Path) -> Option<Self> {
        None
    }

    /// Returns true if available disk space is below the warning threshold (1 GiB).
    pub fn is_low(&self) -> bool {
        self.available_bytes < LOW_DISK_THRESHOLD_BYTES
    }
}
