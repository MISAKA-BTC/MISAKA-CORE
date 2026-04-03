use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::path::Path;
use std::sync::Mutex;
use tracing::info;

pub struct SqliteProcessedStore {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimResult {
    Claimed,
    AlreadyCompleted,
    InProgress,
}

impl SqliteProcessedStore {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| {
            format!(
                "FATAL: Cannot open processed store '{}'. Do not delete it.",
                path.display()
            )
        })?;

        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS processed_messages (
                request_id      TEXT PRIMARY KEY NOT NULL,
                direction       TEXT NOT NULL,
                status          TEXT NOT NULL,
                amount          TEXT NOT NULL,
                attempt_count   INTEGER NOT NULL DEFAULT 1,
                external_tx_id  TEXT,
                last_error      TEXT,
                claimed_at      TEXT NOT NULL DEFAULT (datetime('now')),
                created_at      TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
             );
             CREATE INDEX IF NOT EXISTS idx_processed_status
               ON processed_messages(status);
             CREATE INDEX IF NOT EXISTS idx_processed_created
               ON processed_messages(created_at);
             CREATE TABLE IF NOT EXISTS cursors (
                key   TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
             );",
        )?;

        let integrity: String = conn.query_row("PRAGMA quick_check;", [], |row| row.get(0))?;
        if integrity != "ok" {
            anyhow::bail!(
                "FATAL: Database integrity check failed for '{}': {}",
                path.display(),
                integrity
            );
        }

        let count: i64 = conn.query_row("SELECT COUNT(*) FROM processed_messages;", [], |row| {
            row.get(0)
        })?;
        info!(
            "SQLite processed store opened: {} ({} rows)",
            path.display(),
            count
        );

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn try_claim(&self, request_id: &str, direction: &str, amount: u64) -> Result<ClaimResult> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("sqlite mutex poisoned: {}", e))?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Exclusive)?;

        let existing: Option<String> = tx
            .query_row(
                "SELECT status FROM processed_messages WHERE request_id = ?1;",
                params![request_id],
                |row| row.get(0),
            )
            .optional()?;

        let result = match existing.as_deref() {
            Some("completed") => ClaimResult::AlreadyCompleted,
            Some("pending") => ClaimResult::InProgress,
            Some("failed") => {
                tx.execute(
                    "UPDATE processed_messages
                        SET status = 'pending',
                            attempt_count = attempt_count + 1,
                            last_error = NULL,
                            updated_at = datetime('now'),
                            claimed_at = datetime('now')
                      WHERE request_id = ?1;",
                    params![request_id],
                )?;
                ClaimResult::Claimed
            }
            Some(_) => ClaimResult::InProgress,
            None => {
                tx.execute(
                    "INSERT INTO processed_messages
                        (request_id, direction, status, amount, claimed_at, created_at, updated_at)
                     VALUES (?1, ?2, 'pending', ?3, datetime('now'), datetime('now'), datetime('now'));",
                    params![request_id, direction, amount.to_string()],
                )?;
                ClaimResult::Claimed
            }
        };

        tx.commit()?;
        Ok(result)
    }

    pub fn mark_completed(&self, request_id: &str, external_tx_id: &str) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("sqlite mutex poisoned: {}", e))?;
        let updated = conn.execute(
            "UPDATE processed_messages
                SET status = 'completed',
                    external_tx_id = ?2,
                    last_error = NULL,
                    updated_at = datetime('now')
              WHERE request_id = ?1
                AND status = 'pending';",
            params![request_id, external_tx_id],
        )?;

        if updated != 1 {
            anyhow::bail!(
                "mark_completed failed: request_id={} was not pending",
                request_id
            );
        }
        Ok(())
    }

    pub fn mark_failed(&self, request_id: &str, last_error: &str) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("sqlite mutex poisoned: {}", e))?;
        conn.execute(
            "UPDATE processed_messages
                SET status = 'failed',
                    last_error = ?2,
                    updated_at = datetime('now')
              WHERE request_id = ?1;",
            params![request_id, last_error],
        )?;
        Ok(())
    }

    /// SEC-BRIDGE: Get a persisted cursor value.
    ///
    /// Used for pagination state (e.g., last processed Solana signature).
    /// Returns `Ok(None)` if the cursor doesn't exist yet.
    pub fn get_cursor(&self, key: &str) -> Result<Option<String>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("sqlite mutex poisoned: {}", e))?;
        let value: Option<String> = conn
            .query_row(
                "SELECT value FROM cursors WHERE key = ?1;",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value)
    }

    /// SEC-BRIDGE: Persist a cursor value (upsert).
    ///
    /// Atomic write — if the process crashes after this call,
    /// the cursor is guaranteed to be persisted.
    pub fn set_cursor(&self, key: &str, value: &str) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("sqlite mutex poisoned: {}", e))?;
        conn.execute(
            "INSERT INTO cursors (key, value, updated_at)
             VALUES (?1, ?2, datetime('now'))
             ON CONFLICT(key) DO UPDATE
                SET value = excluded.value,
                    updated_at = excluded.updated_at;",
            params![key, value],
        )?;
        Ok(())
    }
}
