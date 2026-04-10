//! SQLite store for the Burn & Mint bridge relayer.
//!
//! Tables:
//! - `burn_requests`: tracks Solana burn events through the mint pipeline
//! - `address_registrations`: maps Solana wallets to MISAKA receive addresses
//! - `audit_log`: immutable log of all relayer actions
//! - `cursors`: pagination state for polling

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::path::Path;
use std::sync::Mutex;
use tracing::info;

/// Maximum retry attempts before a burn request is marked permanently failed.
const MAX_ATTEMPTS: i64 = 10;

pub struct BurnRequestStore {
    conn: Mutex<Connection>,
}

/// Result of attempting to claim a burn request for processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimResult {
    /// Successfully claimed for processing.
    Claimed,
    /// Already completed — skip.
    AlreadyCompleted,
    /// Currently being processed by another iteration.
    InProgress,
    /// Permanently failed after MAX_ATTEMPTS — skip.
    PermanentlyFailed,
}

/// A burn request row from the database.
#[derive(Debug, Clone)]
pub struct BurnRequestRow {
    pub id: String,
    pub wallet_address: String,
    pub misaka_receive_address: String,
    pub mint_address: String,
    pub burn_amount_raw: u64,
    pub solana_tx_signature: String,
    pub slot: u64,
    pub block_time: i64,
    pub status: String,
    pub error_message: Option<String>,
    pub attempt_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl BurnRequestStore {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| {
            format!(
                "FATAL: Cannot open burn request store '{}'. Do not delete it.",
                path.display()
            )
        })?;

        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;",
        )?;

        // Run migrations
        Self::migrate(&conn)?;

        let integrity: String = conn.query_row("PRAGMA quick_check;", [], |row| row.get(0))?;
        if integrity != "ok" {
            anyhow::bail!(
                "FATAL: Database integrity check failed for '{}': {}",
                path.display(),
                integrity
            );
        }

        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM burn_requests;", [], |row| row.get(0))?;
        info!(
            "SQLite burn request store opened: {} ({} burn requests)",
            path.display(),
            count
        );

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Create tables if they don't exist, migrate from old schema if needed.
    fn migrate(conn: &Connection) -> Result<()> {
        // Check if old schema exists (processed_messages table)
        let has_old_table: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='processed_messages';",
                [],
                |row| row.get::<_, i64>(0),
            )?
            > 0;

        if has_old_table {
            info!("Detected old lock/mint schema — migrating to burn & mint schema");
            // Keep the old table as a backup, create new tables
            conn.execute_batch(
                "ALTER TABLE processed_messages RENAME TO _old_processed_messages;",
            )?;
        }

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS burn_requests (
                id                      TEXT PRIMARY KEY NOT NULL,
                wallet_address          TEXT NOT NULL,
                misaka_receive_address  TEXT NOT NULL,
                mint_address            TEXT NOT NULL,
                burn_amount_raw         TEXT NOT NULL,
                solana_tx_signature     TEXT NOT NULL UNIQUE,
                slot                    INTEGER NOT NULL,
                block_time              INTEGER NOT NULL,
                status                  TEXT NOT NULL DEFAULT 'detected',
                error_message           TEXT,
                attempt_count           INTEGER NOT NULL DEFAULT 0,
                created_at              TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at              TEXT NOT NULL DEFAULT (datetime('now'))
             );
             CREATE INDEX IF NOT EXISTS idx_burn_status
               ON burn_requests(status);
             CREATE INDEX IF NOT EXISTS idx_burn_wallet
               ON burn_requests(wallet_address);
             CREATE INDEX IF NOT EXISTS idx_burn_created
               ON burn_requests(created_at);
             CREATE INDEX IF NOT EXISTS idx_burn_tx_sig
               ON burn_requests(solana_tx_signature);

             CREATE TABLE IF NOT EXISTS address_registrations (
                wallet_address          TEXT PRIMARY KEY NOT NULL,
                misaka_receive_address  TEXT NOT NULL,
                created_at              TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at              TEXT NOT NULL DEFAULT (datetime('now'))
             );

             CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                action      TEXT NOT NULL,
                request_id  TEXT,
                details     TEXT,
                created_at  TEXT NOT NULL DEFAULT (datetime('now'))
             );
             CREATE INDEX IF NOT EXISTS idx_audit_request
               ON audit_log(request_id);
             CREATE INDEX IF NOT EXISTS idx_audit_created
               ON audit_log(created_at);

             CREATE TABLE IF NOT EXISTS cursors (
                key        TEXT PRIMARY KEY NOT NULL,
                value      TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
             );",
        )?;

        Ok(())
    }

    // ═══════════════════════════════════════════════════════════
    //  Address Registration
    // ═══════════════════════════════════════════════════════════

    /// Register or update a MISAKA receive address for a Solana wallet.
    pub fn register_address(
        &self,
        wallet_address: &str,
        misaka_receive_address: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("mutex: {}", e))?;
        conn.execute(
            "INSERT INTO address_registrations (wallet_address, misaka_receive_address, created_at, updated_at)
             VALUES (?1, ?2, datetime('now'), datetime('now'))
             ON CONFLICT(wallet_address) DO UPDATE
                SET misaka_receive_address = excluded.misaka_receive_address,
                    updated_at = datetime('now');",
            params![wallet_address, misaka_receive_address],
        )?;
        Ok(())
    }

    /// Look up the registered MISAKA receive address for a Solana wallet.
    pub fn get_registered_address(&self, wallet_address: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("mutex: {}", e))?;
        let addr: Option<String> = conn
            .query_row(
                "SELECT misaka_receive_address FROM address_registrations WHERE wallet_address = ?1;",
                params![wallet_address],
                |row| row.get(0),
            )
            .optional()?;
        Ok(addr)
    }

    // ═══════════════════════════════════════════════════════════
    //  Burn Requests
    // ═══════════════════════════════════════════════════════════

    /// Insert a new burn request. Returns false if the tx signature already exists.
    pub fn insert_burn_request(
        &self,
        id: &str,
        wallet_address: &str,
        misaka_receive_address: &str,
        mint_address: &str,
        burn_amount_raw: u64,
        solana_tx_signature: &str,
        slot: u64,
        block_time: i64,
        status: &str,
    ) -> Result<bool> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("mutex: {}", e))?;
        let result = conn.execute(
            "INSERT OR IGNORE INTO burn_requests
                (id, wallet_address, misaka_receive_address, mint_address, burn_amount_raw,
                 solana_tx_signature, slot, block_time, status, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, datetime('now'), datetime('now'));",
            params![
                id,
                wallet_address,
                misaka_receive_address,
                mint_address,
                burn_amount_raw.to_string(),
                solana_tx_signature,
                slot as i64,
                block_time,
                status,
            ],
        )?;
        Ok(result > 0)
    }

    /// Try to claim a burn request for mint processing.
    /// Uses exclusive transaction to prevent double-processing.
    pub fn try_claim_burn(&self, id: &str) -> Result<ClaimResult> {
        let mut conn = self.conn.lock().map_err(|e| anyhow::anyhow!("mutex: {}", e))?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Exclusive)?;

        let row: Option<(String, i64)> = tx
            .query_row(
                "SELECT status, attempt_count FROM burn_requests WHERE id = ?1;",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        let result = match row {
            None => {
                // Not found — caller should insert first
                return Ok(ClaimResult::AlreadyCompleted);
            }
            Some((status, attempts)) => match status.as_str() {
                "mint_completed" => ClaimResult::AlreadyCompleted,
                "failed_permanent" => ClaimResult::PermanentlyFailed,
                "mint_requested" => ClaimResult::InProgress,
                "mint_failed" | "verified" => {
                    if attempts >= MAX_ATTEMPTS {
                        tracing::error!(
                            "burn_request id={} exhausted {} attempts — marking permanently failed",
                            id,
                            MAX_ATTEMPTS
                        );
                        tx.execute(
                            "UPDATE burn_requests
                                SET status = 'failed_permanent',
                                    updated_at = datetime('now')
                              WHERE id = ?1;",
                            params![id],
                        )?;
                        ClaimResult::PermanentlyFailed
                    } else {
                        tx.execute(
                            "UPDATE burn_requests
                                SET status = 'mint_requested',
                                    attempt_count = attempt_count + 1,
                                    error_message = NULL,
                                    updated_at = datetime('now')
                              WHERE id = ?1;",
                            params![id],
                        )?;
                        ClaimResult::Claimed
                    }
                }
                _ => ClaimResult::InProgress,
            },
        };

        tx.commit()?;
        Ok(result)
    }

    /// Mark a burn request as mint completed.
    pub fn mark_mint_completed(&self, id: &str, details: &str) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("mutex: {}", e))?;
        conn.execute(
            "UPDATE burn_requests
                SET status = 'mint_completed',
                    error_message = NULL,
                    updated_at = datetime('now')
              WHERE id = ?1;",
            params![id],
        )?;
        conn.execute(
            "INSERT INTO audit_log (action, request_id, details, created_at)
             VALUES ('mint_completed', ?1, ?2, datetime('now'));",
            params![id, details],
        )?;
        Ok(())
    }

    /// Mark a burn request as mint failed.
    pub fn mark_mint_failed(&self, id: &str, error: &str) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("mutex: {}", e))?;
        conn.execute(
            "UPDATE burn_requests
                SET status = 'mint_failed',
                    error_message = ?2,
                    updated_at = datetime('now')
              WHERE id = ?1;",
            params![id, error],
        )?;
        conn.execute(
            "INSERT INTO audit_log (action, request_id, details, created_at)
             VALUES ('mint_failed', ?1, ?2, datetime('now'));",
            params![id, error],
        )?;
        Ok(())
    }

    /// Get all burn requests with a given status.
    pub fn get_burn_requests_by_status(&self, status: &str) -> Result<Vec<BurnRequestRow>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("mutex: {}", e))?;
        let mut stmt = conn.prepare(
            "SELECT id, wallet_address, misaka_receive_address, mint_address,
                    burn_amount_raw, solana_tx_signature, slot, block_time,
                    status, error_message, attempt_count, created_at, updated_at
             FROM burn_requests WHERE status = ?1 ORDER BY created_at ASC;",
        )?;
        let rows = stmt
            .query_map(params![status], |row| {
                let amount_str: String = row.get(4)?;
                Ok(BurnRequestRow {
                    id: row.get(0)?,
                    wallet_address: row.get(1)?,
                    misaka_receive_address: row.get(2)?,
                    mint_address: row.get(3)?,
                    burn_amount_raw: amount_str.parse().map_err(|e: std::num::ParseIntError| {
                        tracing::error!("corrupt burn_amount_raw in DB: {}", e);
                        rusqlite::Error::FromSqlConversionFailure(
                            4,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?,
                    solana_tx_signature: row.get(5)?,
                    slot: row.get::<_, i64>(6)? as u64,
                    block_time: row.get(7)?,
                    status: row.get(8)?,
                    error_message: row.get(9)?,
                    attempt_count: row.get(10)?,
                    created_at: row.get(11)?,
                    updated_at: row.get(12)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Get a burn request by its Solana tx signature.
    pub fn get_burn_by_signature(&self, signature: &str) -> Result<Option<BurnRequestRow>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("mutex: {}", e))?;
        let row = conn
            .query_row(
                "SELECT id, wallet_address, misaka_receive_address, mint_address,
                        burn_amount_raw, solana_tx_signature, slot, block_time,
                        status, error_message, attempt_count, created_at, updated_at
                 FROM burn_requests WHERE solana_tx_signature = ?1;",
                params![signature],
                |row| {
                    let amount_str: String = row.get(4)?;
                    Ok(BurnRequestRow {
                        id: row.get(0)?,
                        wallet_address: row.get(1)?,
                        misaka_receive_address: row.get(2)?,
                        mint_address: row.get(3)?,
                        burn_amount_raw: amount_str.parse().map_err(|e: std::num::ParseIntError| {
                        tracing::error!("corrupt burn_amount_raw in DB: {}", e);
                        rusqlite::Error::FromSqlConversionFailure(
                            4,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?,
                        solana_tx_signature: row.get(5)?,
                        slot: row.get::<_, i64>(6)? as u64,
                        block_time: row.get(7)?,
                        status: row.get(8)?,
                        error_message: row.get(9)?,
                        attempt_count: row.get(10)?,
                        created_at: row.get(11)?,
                        updated_at: row.get(12)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// Get all burn requests (for admin view).
    pub fn get_all_burn_requests(&self) -> Result<Vec<BurnRequestRow>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("mutex: {}", e))?;
        let mut stmt = conn.prepare(
            "SELECT id, wallet_address, misaka_receive_address, mint_address,
                    burn_amount_raw, solana_tx_signature, slot, block_time,
                    status, error_message, attempt_count, created_at, updated_at
             FROM burn_requests ORDER BY created_at DESC LIMIT 1000;",
        )?;
        let rows = stmt
            .query_map([], |row| {
                let amount_str: String = row.get(4)?;
                Ok(BurnRequestRow {
                    id: row.get(0)?,
                    wallet_address: row.get(1)?,
                    misaka_receive_address: row.get(2)?,
                    mint_address: row.get(3)?,
                    burn_amount_raw: amount_str.parse().map_err(|e: std::num::ParseIntError| {
                        tracing::error!("corrupt burn_amount_raw in DB: {}", e);
                        rusqlite::Error::FromSqlConversionFailure(
                            4,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?,
                    solana_tx_signature: row.get(5)?,
                    slot: row.get::<_, i64>(6)? as u64,
                    block_time: row.get(7)?,
                    status: row.get(8)?,
                    error_message: row.get(9)?,
                    attempt_count: row.get(10)?,
                    created_at: row.get(11)?,
                    updated_at: row.get(12)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    // ═══════════════════════════════════════════════════════════
    //  Audit Log
    // ═══════════════════════════════════════════════════════════

    /// Write an entry to the audit log.
    pub fn audit_log(&self, action: &str, request_id: Option<&str>, details: &str) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("mutex: {}", e))?;
        conn.execute(
            "INSERT INTO audit_log (action, request_id, details, created_at)
             VALUES (?1, ?2, ?3, datetime('now'));",
            params![action, request_id, details],
        )?;
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════
    //  Cursors (pagination state)
    // ═══════════════════════════════════════════════════════════

    /// Get a persisted cursor value.
    pub fn get_cursor(&self, key: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("mutex: {}", e))?;
        let value: Option<String> = conn
            .query_row(
                "SELECT value FROM cursors WHERE key = ?1;",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value)
    }

    /// Persist a cursor value (upsert).
    pub fn set_cursor(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("mutex: {}", e))?;
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
