//! Burn transaction verifier.
//!
//! Fetches a Solana transaction by signature and verifies that it contains
//! a real SPL Token Burn instruction for the expected MISAKA mint.
//!
//! Uses raw JSON-RPC (no solana-sdk dependency) -- matches existing pattern.
//!
//! Phase 3 C4: Multi-RPC verification. Queries ALL configured RPCs concurrently
//! and compares results (amount, burner, mint, slot). Rejects if ANY mismatch.
//! In non-dev builds, requires solana_rpc_urls.len() >= 2.

use crate::config::RelayerConfig;
use crate::message::VerifiedBurn;
use anyhow::{Context, Result, bail};
use tracing::{debug, info, warn};

/// SPL Token Program ID (full base58).
const SPL_TOKEN_PROGRAM_ID: &str = "TokenkegQEqKKXjqoMNiCeLi7q1HhiTtiMkDehESVQe";

/// SPL Token Burn instruction discriminator byte.
const BURN_INSTRUCTION_DISCRIMINATOR: u8 = 8;

pub struct BurnVerifier {
    config: RelayerConfig,
}

impl BurnVerifier {
    pub fn new(config: RelayerConfig) -> Self {
        Self { config }
    }

    /// Verify a burn transaction on Solana using multi-RPC consensus.
    ///
    /// Phase 3 C4: Queries ALL configured RPCs concurrently, compares results.
    /// Rejects if any mismatch between RPC responses.
    ///
    /// Returns `VerifiedBurn` on success or an error explaining why verification failed.
    /// Verify a burn transaction on Solana.
    ///
    /// SEC-FIX: `expected_wallet` is now mandatory. Previously it was
    /// `Option<&str>`, and when `None` any wallet could claim a burn.
    pub async fn verify_burn_tx(
        &self,
        tx_sig: &str,
        expected_wallet: &str,
    ) -> Result<VerifiedBurn> {
        let rpc_urls = &self.config.solana_rpc_urls;
        let expected_mint = &self.config.solana_misaka_mint;

        // Phase 3 C4: In non-dev builds, require at least 2 RPC URLs.
        #[cfg(not(debug_assertions))]
        if rpc_urls.len() < 2 {
            bail!(
                "Multi-RPC verification requires at least 2 RPC URLs (have {}). \
                 Set SOLANA_RPC_URLS to a comma-separated list of at least 2 RPC endpoints.",
                rpc_urls.len()
            );
        }

        // Query all RPCs concurrently
        let mut handles = Vec::with_capacity(rpc_urls.len());
        for rpc_url in rpc_urls {
            let url = rpc_url.clone();
            let sig = tx_sig.to_string();
            handles.push(tokio::spawn(async move {
                solana_rpc(
                    &url,
                    "getTransaction",
                    serde_json::json!([
                        sig,
                        {
                            "encoding": "jsonParsed",
                            "commitment": "finalized",
                            "maxSupportedTransactionVersion": 0
                        }
                    ]),
                )
                .await
            }));
        }

        // Collect all results
        let mut rpc_results: Vec<(String, serde_json::Value)> = Vec::new();
        for (i, handle) in handles.into_iter().enumerate() {
            let result = handle
                .await
                .map_err(|e| anyhow::anyhow!("RPC task {} panicked: {}", i, e))?
                .with_context(|| format!("RPC {} ({}) failed", i, rpc_urls[i]))?;
            rpc_results.push((rpc_urls[i].clone(), result));
        }

        // Parse burns from each RPC result and verify consistency
        let mut parsed_burns: Vec<(String, VerifiedBurn)> = Vec::new();

        for (rpc_url, tx) in &rpc_results {
            if tx.is_null() {
                bail!(
                    "Transaction {} not found or not finalized on RPC {}",
                    tx_sig, rpc_url
                );
            }

            // Check transaction succeeded (meta.err must be null)
            let meta = tx
                .get("meta")
                .ok_or_else(|| anyhow::anyhow!("Transaction missing meta field from RPC {}", rpc_url))?;

            if meta.get("err") != Some(&serde_json::Value::Null) {
                bail!(
                    "Transaction {} failed on RPC {}: {:?}",
                    tx_sig, rpc_url, meta.get("err")
                );
            }

            // Extract slot and block_time
            let slot = tx.get("slot").and_then(|s| s.as_u64()).unwrap_or(0);
            let block_time = tx.get("blockTime").and_then(|t| t.as_i64()).unwrap_or(0);

            // Search for SPL Token Burn instructions
            let mut burn_results = Vec::new();

            // Check top-level instructions
            if let Some(instructions) = tx
                .get("transaction")
                .and_then(|t| t.get("message"))
                .and_then(|m| m.get("instructions"))
                .and_then(|i| i.as_array())
            {
                for (idx, ix) in instructions.iter().enumerate() {
                    if let Some(burn) = self.parse_burn_from_parsed_instruction(
                        ix, expected_mint, expected_wallet, idx,
                    ) {
                        burn_results.push(burn);
                    }
                }
            }

            // Check inner instructions (from CPI calls)
            if let Some(inner_instructions) = meta
                .get("innerInstructions")
                .and_then(|i| i.as_array())
            {
                for inner_group in inner_instructions {
                    if let Some(ixs) = inner_group.get("instructions").and_then(|i| i.as_array()) {
                        for (idx, ix) in ixs.iter().enumerate() {
                            if let Some(burn) = self.parse_burn_from_parsed_instruction(
                                ix, expected_mint, expected_wallet, idx,
                            ) {
                                burn_results.push(burn);
                            }
                        }
                    }
                }
            }

            if burn_results.is_empty() {
                bail!(
                    "No valid SPL Token Burn instruction found for mint {} in tx {} (RPC {})",
                    expected_mint, tx_sig, rpc_url
                );
            }

            // SEC-FIX: Reject transactions with multiple burn instructions.
            // Previously only burn_results[0] was used, silently ignoring additional
            // burns. An attacker could craft a TX with a small burn first and a large
            // burn second, causing under-minting. Or place a large burn first for over-minting.
            if burn_results.len() > 1 {
                bail!(
                    "Ambiguous: tx {} contains {} burn instructions (expected exactly 1). \
                     Multi-burn transactions are not supported.",
                    tx_sig,
                    burn_results.len()
                );
            }

            let mut burn = burn_results.remove(0);
            burn.slot = slot;
            burn.block_time = block_time;

            if burn.amount == 0 {
                bail!("Burn amount is zero in tx {} (RPC {})", tx_sig, rpc_url);
            }

            parsed_burns.push((rpc_url.clone(), burn));
        }

        // Phase 3 C4: Cross-RPC consistency check
        if parsed_burns.len() >= 2 {
            let (ref_url, ref_burn) = &parsed_burns[0];
            for (rpc_url, burn) in &parsed_burns[1..] {
                if burn.amount != ref_burn.amount {
                    bail!(
                        "Multi-RPC MISMATCH: amount differs between {} ({}) and {} ({})",
                        ref_url, ref_burn.amount, rpc_url, burn.amount
                    );
                }
                if burn.wallet != ref_burn.wallet {
                    bail!(
                        "Multi-RPC MISMATCH: burner differs between {} ({}) and {} ({})",
                        ref_url, ref_burn.wallet, rpc_url, burn.wallet
                    );
                }
                if burn.mint != ref_burn.mint {
                    bail!(
                        "Multi-RPC MISMATCH: mint differs between {} ({}) and {} ({})",
                        ref_url, ref_burn.mint, rpc_url, burn.mint
                    );
                }
                if burn.slot != ref_burn.slot {
                    bail!(
                        "Multi-RPC MISMATCH: slot differs between {} ({}) and {} ({})",
                        ref_url, ref_burn.slot, rpc_url, burn.slot
                    );
                }
            }
            info!(
                "Multi-RPC verification passed: {} RPCs agree on tx {} (amount={}, slot={})",
                parsed_burns.len(),
                &tx_sig[..16.min(tx_sig.len())],
                ref_burn.amount,
                ref_burn.slot
            );
        }

        let (_url, verified_burn) = parsed_burns.remove(0);

        debug!(
            "Verified burn: tx={} amount={} wallet={} mint={} slot={}",
            &tx_sig[..16.min(tx_sig.len())],
            verified_burn.amount,
            verified_burn.wallet,
            verified_burn.mint,
            verified_burn.slot
        );

        Ok(verified_burn)
    }

    /// Parse a burn instruction from a jsonParsed instruction object.
    ///
    /// The SPL Token Program's Burn instruction in jsonParsed format looks like:
    /// ```json
    /// {
    ///   "program": "spl-token",
    ///   "programId": "TokenkegQEqKKXjqoMNiCeLi7q1HhiTtiMkDehESVQe",
    ///   "parsed": {
    ///     "type": "burn",
    ///     "info": {
    ///       "account": "<token_account>",
    ///       "mint": "<mint_address>",
    ///       "authority": "<owner>",
    ///       "amount": "<amount_string>"
    ///     }
    ///   }
    /// }
    /// ```
    fn parse_burn_from_parsed_instruction(
        &self,
        ix: &serde_json::Value,
        expected_mint: &str,
        expected_wallet: &str,
        idx: usize,
    ) -> Option<VerifiedBurn> {
        // Check it's the SPL Token Program
        let program_id = ix.get("programId").and_then(|p| p.as_str())?;
        if program_id != SPL_TOKEN_PROGRAM_ID {
            return None;
        }

        // Check it's a parsed burn instruction
        let parsed = ix.get("parsed")?;
        let ix_type = parsed.get("type").and_then(|t| t.as_str())?;
        if ix_type != "burn" {
            return None;
        }

        let info = parsed.get("info")?;

        // Extract mint
        let mint = info.get("mint").and_then(|m| m.as_str())?;
        if mint != expected_mint {
            debug!(
                "Burn instruction mint {} does not match expected {}",
                mint, expected_mint
            );
            return None;
        }

        // Extract amount (string in parsed format)
        let amount_str = info.get("amount").and_then(|a| a.as_str())?;
        let amount: u64 = amount_str.parse().ok()?;

        // Extract authority (wallet owner)
        let authority = info.get("authority").and_then(|a| a.as_str())?;

        // SEC-FIX: Wallet verification is now mandatory (was previously optional).
        if authority != expected_wallet {
            warn!(
                "Burn authority {} does not match expected wallet {}",
                authority, expected_wallet
            );
            return None;
        }

        Some(VerifiedBurn {
            amount,
            wallet: authority.to_string(),
            mint: mint.to_string(),
            slot: 0,       // filled in by caller
            block_time: 0, // filled in by caller
            burn_index: idx,
        })
    }
}

/// Solana JSON-RPC request helper.
async fn solana_rpc(
    rpc_url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("failed to build HTTP client")?;

    let resp = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .context(format!("Solana RPC '{}' failed", method))?;

    let status = resp.status();
    if !status.is_success() {
        let err_body = resp.text().await.unwrap_or_default();
        bail!(
            "Solana RPC HTTP {}: {}",
            status,
            &err_body[..200.min(err_body.len())]
        );
    }

    let result: serde_json::Value = resp
        .json()
        .await
        .context("failed to parse Solana RPC JSON response")?;

    if let Some(err) = result.get("error") {
        bail!("Solana RPC error: {}", err);
    }

    Ok(result
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null))
}
