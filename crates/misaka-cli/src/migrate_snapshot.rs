//! Option C: migrate a v0.8.8 `narwhal_utxo_snapshot.json` into a
//! v0.9.0-dev `initial_utxos.json` that `GenesisCommitteeManifest` can
//! consume at fresh-start bootstrap.
//!
//! # Input format (v0.8.8 snapshot)
//!
//! The file is written by `UtxoSet::save_to_file`. It has a 32-byte
//! binary prefix (a MuHash or state-root digest) followed immediately
//! by the serde_json body:
//!
//! ```text
//! [32 bytes binary prefix] { "height": N, "unspent": [ ... ], ... }
//! ```
//!
//! Each entry in `unspent` is:
//!
//! ```json
//! {
//!   "outref": { "tx_hash": [32 bytes], "output_index": u32 },
//!   "output": {
//!     "amount": u64,
//!     "address": [32 bytes],
//!     "spending_pubkey": [1952 bytes]  // ML-DSA-65
//!   },
//!   "created_at": u64,
//!   "spending_pubkey": [1952 bytes],
//!   "is_emission": bool
//! }
//! ```
//!
//! # Output format (v0.9.0-dev initial_utxos.json)
//!
//! Flat list of the minimum fields needed to re-seed the UTXO set:
//!
//! ```json
//! {
//!   "schema_version": 1,
//!   "source_height": 1003,
//!   "source_snapshot": "narwhal_utxo_snapshot.json",
//!   "total_amount": 150150000000000,
//!   "utxos": [
//!     {
//!       "address": "hex64",
//!       "amount": 50000000000,
//!       "spending_pubkey": "hex3904",
//!       "label": "migrated_0"
//!     },
//!     ...
//!   ]
//! }
//! ```
//!
//! Note: we DROP the original `tx_hash` / `output_index` / `created_at`
//! / `is_emission`. On the new chain, every seeded UTXO gets a fresh
//! synthetic `OutputRef` derived from `SHA3(domain || address || index)`,
//! keeping the new chain's tx-history invariant clean (no fabricated
//! parent transactions).

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Current output file schema. Bumped when the wire shape below changes.
pub const OUTPUT_SCHEMA_VERSION: u32 = 1;

/// One UTXO entry as written to `initial_utxos.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitialUtxoEntry {
    /// 32-byte address (hex, 64 chars, no 0x prefix).
    pub address: String,
    /// Amount in base units.
    pub amount: u64,
    /// ML-DSA-65 public key (hex, 3904 chars = 1952 bytes).
    /// Set to `None` to produce an unspendable allocation (discouraged
    /// for migrations — v0.8.8 snapshot always includes the pk).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spending_pubkey: Option<String>,
    /// Free-form label for audit / debugging.
    #[serde(default)]
    pub label: String,
}

/// Top-level wrapper for `initial_utxos.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitialUtxoFile {
    pub schema_version: u32,
    /// Block height of the source snapshot. Informational only.
    #[serde(default)]
    pub source_height: u64,
    /// Original filename the data came from. Informational only.
    #[serde(default)]
    pub source_snapshot: String,
    /// Sum of all `utxos[i].amount`. Checked by the node on load to
    /// catch TOML/JSON truncation.
    #[serde(default)]
    pub total_amount: u64,
    pub utxos: Vec<InitialUtxoEntry>,
}

/// Intermediate struct matching the v0.8.8 body shape.
#[derive(Debug, Deserialize)]
struct V088Snapshot {
    #[serde(default)]
    height: u64,
    unspent: Vec<V088Entry>,
}

#[derive(Debug, Deserialize)]
struct V088Entry {
    output: V088Output,
}

#[derive(Debug, Deserialize)]
struct V088Output {
    amount: u64,
    address: Vec<u8>,
    #[serde(default)]
    spending_pubkey: Option<Vec<u8>>,
}

/// Strip the 32-byte binary prefix and parse the body.
///
/// v0.8.8 `UtxoSet::save_to_file` prepends a MuHash digest (or similar)
/// before the JSON. We locate the first `{` and decode from there. On
/// a well-formed file the prefix is exactly 32 bytes, but we tolerate
/// any length to stay forward-compatible.
pub fn parse_v088_snapshot(raw: &[u8]) -> Result<(u64, Vec<InitialUtxoEntry>)> {
    let brace_idx = raw
        .iter()
        .position(|&b| b == b'{')
        .context("snapshot contains no '{' — unrecognized format")?;
    let body = &raw[brace_idx..];
    let parsed: V088Snapshot = serde_json::from_slice(body).with_context(|| {
        format!(
            "failed to parse snapshot body (prefix was {} bytes)",
            brace_idx
        )
    })?;

    let mut out = Vec::with_capacity(parsed.unspent.len());
    for (i, e) in parsed.unspent.into_iter().enumerate() {
        if e.output.address.len() != 32 {
            bail!(
                "entry #{} has invalid address length {} (expected 32)",
                i,
                e.output.address.len()
            );
        }
        let spk_hex = match &e.output.spending_pubkey {
            Some(pk) if pk.len() == 1952 => Some(hex::encode(pk)),
            Some(pk) => bail!(
                "entry #{} has invalid spending_pubkey length {} (expected 1952 for ML-DSA-65)",
                i,
                pk.len()
            ),
            None => None,
        };
        out.push(InitialUtxoEntry {
            address: hex::encode(&e.output.address),
            amount: e.output.amount,
            spending_pubkey: spk_hex,
            label: format!("migrated_{}", i),
        });
    }
    Ok((parsed.height, out))
}

/// `misaka-cli migrate-utxo-snapshot --input ... --output ...` entry
/// point.
pub fn run(input: &str, output: &str) -> Result<()> {
    println!("📥 Reading v0.8.8 snapshot: {}", input);
    let raw = fs::read(input)
        .with_context(|| format!("failed to read input {}", input))?;
    println!("   File size: {} bytes", raw.len());

    let (height, utxos) = parse_v088_snapshot(&raw)?;
    let total_amount: u64 = utxos.iter().map(|u| u.amount).sum();
    let with_spk = utxos.iter().filter(|u| u.spending_pubkey.is_some()).count();

    let unique_addrs: std::collections::HashSet<&str> =
        utxos.iter().map(|u| u.address.as_str()).collect();

    println!();
    println!("📊 Summary");
    println!("   Source height:         {}", height);
    println!("   UTXOs:                 {}", utxos.len());
    println!("   Unique addresses:      {}", unique_addrs.len());
    println!("   With spending_pubkey:  {}/{}", with_spk, utxos.len());
    println!("   Total amount:          {} base units", total_amount);
    println!("   Total amount:          {:.6} MISAKA", total_amount as f64 / 1e9);

    let source_name = Path::new(input)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| input.to_string());

    let out_file = InitialUtxoFile {
        schema_version: OUTPUT_SCHEMA_VERSION,
        source_height: height,
        source_snapshot: source_name,
        total_amount,
        utxos,
    };
    let json = serde_json::to_string_pretty(&out_file)
        .context("failed to serialize output JSON")?;
    fs::write(output, &json)
        .with_context(|| format!("failed to write output {}", output))?;

    println!();
    println!("✅ Wrote {} ({} bytes)", output, json.len());
    println!();
    println!("Next steps:");
    println!(
        "  1. Copy `{}` next to your genesis_committee.toml on the v0.9.0-dev node.",
        output
    );
    println!("  2. Add to genesis_committee.toml:");
    println!();
    println!("       [initial_utxos]");
    println!("       source = \"{}\"", output);
    println!();
    println!("  3. Start the v0.9.0-dev node with a fresh data_dir. The seed");
    println!("     runs once at boot when `chain.db` does not yet exist.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: synthesize a minimal v0.8.8-shaped snapshot, migrate,
    /// and verify the output preserves addresses + amounts + pubkeys.
    #[test]
    fn parses_v088_snapshot_with_binary_prefix() {
        let pk = vec![0xAAu8; 1952];
        let addr = vec![0x11u8; 32];
        let body = serde_json::json!({
            "height": 42,
            "unspent": [
                {
                    "outref": { "tx_hash": vec![0u8; 32], "output_index": 0 },
                    "output": {
                        "amount": 123_456_000u64,
                        "address": addr.clone(),
                        "spending_pubkey": pk.clone(),
                    },
                    "created_at": 0,
                    "spending_pubkey": pk.clone(),
                    "is_emission": false
                }
            ],
            "processed_burns": [],
            "total_emitted": 0u64
        });
        let body_json = serde_json::to_vec(&body).unwrap();
        // Prepend a 32-byte binary prefix like the real snapshot has.
        let mut raw = vec![0xDEu8; 32];
        raw.extend_from_slice(&body_json);

        let (height, utxos) = parse_v088_snapshot(&raw).expect("parse");
        assert_eq!(height, 42);
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].address, hex::encode(&addr));
        assert_eq!(utxos[0].amount, 123_456_000);
        assert_eq!(utxos[0].spending_pubkey.as_deref(), Some(hex::encode(&pk).as_str()));
        assert_eq!(utxos[0].label, "migrated_0");
    }

    #[test]
    fn rejects_malformed_address_length() {
        let pk = vec![0xAAu8; 1952];
        let body = serde_json::json!({
            "height": 1,
            "unspent": [{
                "outref": { "tx_hash": vec![0u8; 32], "output_index": 0 },
                "output": {
                    "amount": 1u64,
                    "address": vec![0x11u8; 20], // wrong length
                    "spending_pubkey": pk,
                },
                "created_at": 0,
                "spending_pubkey": vec![0u8; 1952],
                "is_emission": false
            }]
        });
        let body_json = serde_json::to_vec(&body).unwrap();
        let mut raw = vec![0u8; 32];
        raw.extend_from_slice(&body_json);
        assert!(parse_v088_snapshot(&raw).is_err());
    }

    #[test]
    fn rejects_malformed_spending_pubkey_length() {
        let body = serde_json::json!({
            "height": 1,
            "unspent": [{
                "outref": { "tx_hash": vec![0u8; 32], "output_index": 0 },
                "output": {
                    "amount": 1u64,
                    "address": vec![0x11u8; 32],
                    "spending_pubkey": vec![0u8; 100], // wrong length
                },
                "created_at": 0,
                "spending_pubkey": vec![0u8; 100],
                "is_emission": false
            }]
        });
        let body_json = serde_json::to_vec(&body).unwrap();
        let mut raw = vec![0u8; 32];
        raw.extend_from_slice(&body_json);
        assert!(parse_v088_snapshot(&raw).is_err());
    }

    #[test]
    fn missing_spending_pubkey_yields_none() {
        let body = serde_json::json!({
            "height": 0,
            "unspent": [{
                "outref": { "tx_hash": vec![0u8; 32], "output_index": 0 },
                "output": {
                    "amount": 999u64,
                    "address": vec![0x22u8; 32],
                },
                "created_at": 0,
                "is_emission": false
            }]
        });
        let body_json = serde_json::to_vec(&body).unwrap();
        let mut raw = vec![0u8; 32];
        raw.extend_from_slice(&body_json);
        let (_, utxos) = parse_v088_snapshot(&raw).expect("parse");
        assert_eq!(utxos.len(), 1);
        assert!(utxos[0].spending_pubkey.is_none());
    }
}
