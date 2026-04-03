//! Admin listener — strictly separated from public RPC.
//!
//! # Security Model
//! - Admin endpoints bind to localhost ONLY on mainnet
//! - mTLS enforced when configured
//! - All admin operations produce audit log entries
//! - Fail-closed: if config is invalid, startup is refused

use std::net::SocketAddr;
use tracing::{info, warn, error};

/// Admin operation audit entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AdminAuditEntry {
    pub timestamp: u64,
    pub operation: String,
    pub operator_id: String,
    pub result: AdminOpResult,
    pub details: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub enum AdminOpResult {
    Success,
    Denied(String),
    Failed(String),
}

/// Admin audit log.
pub struct AdminAuditLog {
    entries: Vec<AdminAuditEntry>,
    persist_path: Option<String>,
    max_entries: usize,
}

impl AdminAuditLog {
    pub fn new(persist_path: Option<String>, max_entries: usize) -> Self {
        Self { entries: Vec::new(), persist_path, max_entries }
    }

    pub fn log(&mut self, operation: &str, operator_id: &str, result: AdminOpResult, details: &str) {
        let entry = AdminAuditEntry {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default().as_secs(),
            operation: operation.to_string(),
            operator_id: operator_id.to_string(),
            result: result.clone(),
            details: details.to_string(),
        };

        match &result {
            AdminOpResult::Success => info!("ADMIN_AUDIT: {} by {} - SUCCESS: {}", operation, operator_id, details),
            AdminOpResult::Denied(r) => warn!("ADMIN_AUDIT: {} by {} - DENIED: {}", operation, operator_id, r),
            AdminOpResult::Failed(r) => error!("ADMIN_AUDIT: {} by {} - FAILED: {}", operation, operator_id, r),
        }

        self.entries.push(entry);

        // Persist
        if let Some(ref path) = self.persist_path {
            let _ = self.persist_to_file(path);
        }

        // Prune old entries
        if self.entries.len() > self.max_entries {
            self.entries.drain(0..self.entries.len() - self.max_entries);
        }
    }

    fn persist_to_file(&self, path: &str) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(&self.entries).unwrap_or_default();
        std::fs::write(path, json)
    }

    pub fn entries(&self) -> &[AdminAuditEntry] { &self.entries }
    pub fn count(&self) -> usize { self.entries.len() }
}

/// Validate admin listener config at startup. FAIL-CLOSED.
pub fn enforce_admin_config(
    admin_bind: &SocketAddr,
    is_mainnet: bool,
    require_mtls: bool,
    tls_cert: &Option<String>,
    tls_key: &Option<String>,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    // Mainnet: MUST be localhost
    if is_mainnet && !admin_bind.ip().is_loopback() {
        errors.push(format!(
            "FATAL: Admin listener on mainnet MUST bind to localhost. Got: {}. \
             Use SSH tunnel for remote admin.", admin_bind.ip()
        ));
    }

    // mTLS: cert and key must exist
    if require_mtls {
        match tls_cert {
            None => errors.push("mTLS enabled but tls_cert_path not configured".into()),
            Some(p) if !std::path::Path::new(p).exists() => errors.push(format!("TLS cert not found: {}", p)),
            _ => {}
        }
        match tls_key {
            None => errors.push("mTLS enabled but tls_key_path not configured".into()),
            Some(p) if !std::path::Path::new(p).exists() => errors.push(format!("TLS key not found: {}", p)),
            _ => {}
        }
    }

    if errors.is_empty() { Ok(()) } else { Err(errors) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_log() {
        let mut log = AdminAuditLog::new(None, 100);
        log.log("shutdown", "operator1", AdminOpResult::Success, "normal shutdown");
        assert_eq!(log.count(), 1);
        assert_eq!(log.entries()[0].operation, "shutdown");
    }

    #[test]
    fn test_mainnet_rejects_public_bind() {
        let public: SocketAddr = "0.0.0.0:3002".parse().expect("valid addr");
        assert!(enforce_admin_config(&public, true, false, &None, &None).is_err());
    }

    #[test]
    fn test_mainnet_allows_localhost() {
        let local: SocketAddr = "127.0.0.1:3002".parse().expect("valid addr");
        assert!(enforce_admin_config(&local, true, false, &None, &None).is_ok());
    }

    #[test]
    fn test_mtls_requires_cert() {
        let local: SocketAddr = "127.0.0.1:3002".parse().expect("valid addr");
        assert!(enforce_admin_config(&local, false, true, &None, &None).is_err());
    }
}
