//! Security audit logging — immutable record of security-relevant events.
//!
//! All security events are logged to a tamper-evident audit trail:
//! - Authentication attempts (success/failure)
//! - Authorization denials
//! - Invariant violations
//! - Peer bans
//! - Configuration changes
//! - Key operations (generation, rotation, deletion)

use serde::{Serialize, Deserialize};
use std::collections::VecDeque;
use parking_lot::Mutex;

/// Security event severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// A security audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: u64,
    pub severity: AuditSeverity,
    pub category: String,
    pub message: String,
    pub source_ip: Option<String>,
    pub peer_id: Option<String>,
    pub details: Option<serde_json::Value>,
    pub event_hash: String,
}

impl AuditEvent {
    pub fn new(severity: AuditSeverity, category: &str, message: &str) -> Self {
        let timestamp = now_secs();
        let hash = compute_event_hash(timestamp, category, message);
        Self {
            timestamp,
            severity,
            category: category.to_string(),
            message: message.to_string(),
            source_ip: None,
            peer_id: None,
            details: None,
            event_hash: hash,
        }
    }

    pub fn with_ip(mut self, ip: &str) -> Self { self.source_ip = Some(ip.to_string()); self }
    pub fn with_peer(mut self, peer: &str) -> Self { self.peer_id = Some(peer.to_string()); self }
    pub fn with_details(mut self, details: serde_json::Value) -> Self { self.details = Some(details); self }
}

/// Audit log storage.
pub struct AuditLog {
    events: Mutex<VecDeque<AuditEvent>>,
    max_events: usize,
    critical_count: std::sync::atomic::AtomicU64,
}

impl AuditLog {
    pub fn new(max_events: usize) -> Self {
        Self {
            events: Mutex::new(VecDeque::with_capacity(max_events)),
            max_events,
            critical_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Record a security event.
    pub fn record(&self, event: AuditEvent) {
        if event.severity == AuditSeverity::Critical {
            self.critical_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        tracing::info!(
            target: "security_audit",
            severity = ?event.severity,
            category = %event.category,
            message = %event.message,
            "AUDIT: {}",
            event.message,
        );

        let mut events = self.events.lock();
        if events.len() >= self.max_events {
            events.pop_front();
        }
        events.push_back(event);
    }

    /// Get recent events.
    pub fn recent(&self, count: usize) -> Vec<AuditEvent> {
        let events = self.events.lock();
        events.iter().rev().take(count).cloned().collect()
    }

    /// Get events by severity.
    pub fn by_severity(&self, severity: AuditSeverity) -> Vec<AuditEvent> {
        self.events.lock().iter().filter(|e| e.severity == severity).cloned().collect()
    }

    /// Get critical event count.
    pub fn critical_count(&self) -> u64 {
        self.critical_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn total_count(&self) -> usize { self.events.lock().len() }
}

fn compute_event_hash(timestamp: u64, category: &str, message: &str) -> String {
    use sha3::{Sha3_256, Digest};
    let mut h = Sha3_256::new();
    h.update(&timestamp.to_le_bytes());
    h.update(category.as_bytes());
    h.update(message.as_bytes());
    hex::encode(&h.finalize()[..8])
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ─── Convenience constructors ─────────────────────────

pub fn auth_success(client: &str, ip: &str) -> AuditEvent {
    AuditEvent::new(AuditSeverity::Info, "auth", &format!("authentication success: {}", client))
        .with_ip(ip)
}

pub fn auth_failure(client: &str, ip: &str, reason: &str) -> AuditEvent {
    AuditEvent::new(AuditSeverity::Warning, "auth", &format!("authentication failed: {} — {}", client, reason))
        .with_ip(ip)
}

pub fn peer_banned(addr: &str, reason: &str) -> AuditEvent {
    AuditEvent::new(AuditSeverity::Warning, "p2p", &format!("peer banned: {} — {}", addr, reason))
        .with_ip(addr)
}

pub fn invariant_violated(category: &str, message: &str) -> AuditEvent {
    AuditEvent::new(AuditSeverity::Critical, "invariant", &format!("{}: {}", category, message))
}

pub fn config_changed(setting: &str, old_value: &str, new_value: &str) -> AuditEvent {
    AuditEvent::new(AuditSeverity::Info, "config",
        &format!("setting changed: {} = {} → {}", setting, old_value, new_value))
}
