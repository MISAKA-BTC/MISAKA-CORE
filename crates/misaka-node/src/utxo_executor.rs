//! Phase 2b: new UTXO execution layer.
//!
//! This module replaces `narwhal_tx_executor.rs`. It uses:
//! - borsh decode (not serde_json) for wire deserialization
//! - IntentMessage-based signature verification (not signing_digest*)
//! - Explicit AppId binding for cross-chain replay protection
//! - Fail-closed semantics (panic on any committed tx failure)
//!
//! Phase 2b M1: Added as dead code. No callers yet.
//! Phase 2b M6: Wired into narwhal runtime (cutover).
//! Phase 2c: narwhal_tx_executor.rs deleted, this becomes sole gateway.

// Phase 2b M6: wired into narwhal runtime (live code)

use borsh::BorshDeserialize;
use misaka_pqc::pq_sign::ml_dsa_verify_raw;
use misaka_types::intent::{AppId, IntentMessage, IntentScope};
use misaka_types::utxo::{OutputRef, TxOutput, TxType, UtxoTransaction};
use misaka_storage::utxo_set::{BlockDelta, UtxoSet};
use std::collections::HashSet;
use tracing::{error, info, warn};

/// Phase 2b hard cap on coinbase output sum (50 MISAKA).
/// Phase 3 replaces with epoch-based SystemEmission.
const PHASE2_MAX_COINBASE_PER_BLOCK: u64 = 50_000_000_000;

/// Maximum transactions per committed batch.
const MAX_TXS_PER_COMMIT: usize = 10_000;

/// §4.4: Emission outputs require 300-block maturity before spending.
const EMISSION_MATURITY: u64 = 300;

/// SEC-FIX: Maximum total supply (21 billion MISAKA in base units).
/// This is the hard cap enforced at the consensus execution layer.
/// Previously only per-block emission cap existed (PHASE2_MAX_COINBASE_PER_BLOCK)
/// but total supply was uncapped — SupplyTracker existed but was not connected.
/// Hard cap: 21 billion MISAKA with 8 decimal places = 21 × 10^8 × 10^8.
/// 2_100_000_000_000_000_000 < u64::MAX (18.4 × 10^18), so this fits in u64.
const MAX_TOTAL_SUPPLY: u64 = 2_100_000_000_000_000_000; // 21B × 10^8 base units

/// §5.5 Fee distribution — proposer receives 50%.
pub const PROPOSER_FEE_SHARE_BPS: u64 = 5000;
/// §5.5 Fee distribution — treasury receives 10%.
pub const TREASURY_FEE_SHARE_BPS: u64 = 1000;
/// §5.5 Fee distribution — 40% burned.
pub const BURN_FEE_SHARE_BPS: u64 = 4000;

// Phase 2b': TX_SIGN_DOMAIN removed — IntentMessage provides domain separation.

/// Errors during TX execution.
#[derive(Debug, thiserror::Error)]
pub enum TxExecutionError {
    #[error("borsh decode failed: {0}")]
    BorshDecodeFailed(String),
    #[error("structural validation failed: {0}")]
    StructuralInvalid(String),
    #[error("UTXO not found: {0}")]
    UtxoNotFound(String),
    #[error("key image already spent: {0}")]
    KeyImageSpent(String),
    #[error("signature verification failed for input {input_index}: {reason}")]
    SignatureInvalid { input_index: usize, reason: String },
    #[error("insufficient funds: inputs={inputs}, outputs_plus_fee={outputs_plus_fee}")]
    InsufficientFunds { inputs: u64, outputs_plus_fee: u64 },
    #[error("amount overflow")]
    AmountOverflow,
    #[error("coinbase/emission exceeds phase2 cap")]
    CoinbaseExceedsCap,
    #[error("transaction expired: expiry={expiry}, current_height={current}")]
    Expired { expiry: u64, current: u64 },
    #[error("emission output not mature: created_at={created_at}, current={current}, required_maturity={required}")]
    EmissionNotMature { created_at: u64, current: u64, required: u64 },
    #[error("P2PKH pubkey mismatch at input {input_index}")]
    PubkeyMismatch { input_index: usize },
    #[error("output {output_index} address/spending_pubkey binding failed: address != SHA3-256(spending_pubkey)")]
    OutputPubkeyBindingFailed { output_index: usize },
    #[error("unsupported tx kind")]
    UnsupportedTxKind,
    #[error("burn already processed: {0}")]
    BurnAlreadyProcessed(String),
}

/// Result of executing a committed batch.
#[derive(Debug)]
pub struct CommitExecutionResult {
    pub commit_index: u64,
    pub txs_accepted: usize,
    pub txs_rejected: usize,
    pub total_fees: u64,
    pub utxos_created: usize,
}

/// New UTXO execution layer (Phase 2b).
///
/// Uses IntentMessage-based signing for cross-chain replay protection.
pub struct UtxoExecutor {
    /// Network identity — embedded in every IntentMessage.
    app_id: AppId,
    utxo_set: UtxoSet,
    height: u64,
    /// Phase 3 C5: Set of burn IDs already processed (replay protection).
    processed_burns: HashSet<[u8; 32]>,
    /// SEC-FIX: Cumulative total emission (sum of all SystemEmission outputs).
    /// Enforces MAX_TOTAL_SUPPLY at the consensus execution layer.
    total_emitted: u64,
}

impl UtxoExecutor {
    /// Create with explicit AppId for cross-chain replay protection.
    pub fn new(app_id: AppId) -> Self {
        Self {
            app_id,
            utxo_set: UtxoSet::new(36),
            height: 0,
            processed_burns: HashSet::new(),
            total_emitted: 0,
        }
    }

    /// Create from an existing UTXO set (crash recovery).
    pub fn with_utxo_set(utxo_set: UtxoSet, app_id: AppId) -> Self {
        let height = utxo_set.height;
        Self { app_id, utxo_set, height, processed_burns: HashSet::new(), total_emitted: 0 }
    }

    /// Execute a committed batch from Narwhal.
    ///
    /// # Failure Semantics (architecture.md §4.6)
    ///
    /// If any committed tx fails validation, the executor **panics**.
    /// Execute a committed batch from Narwhal.
    ///
    /// SECURITY: Invalid transactions are SKIPPED, not panicked on.
    /// Deserialization/structural failures indicate garbage input (e.g. from
    /// a Byzantine proposer or a bypass route), NOT state divergence.
    /// Only true invariant violations (negative balance, hash mismatch)
    /// should ever cause a panic.
    /// Execute a committed batch from Narwhal.
    ///
    /// `leader_address`: SHA3-256 hash of the commit leader's ML-DSA-65 public key.
    /// Used to verify that SystemEmission outputs are directed to the block proposer.
    /// Pass `None` only during initial development; mainnet MUST always provide this.
    pub fn execute_committed(
        &mut self,
        commit_index: u64,
        raw_transactions: &[Vec<u8>],
        leader_address: Option<[u8; 32]>,
    ) -> CommitExecutionResult {
        // Audit R7: Reject commits with too many transactions instead of silent drop
        if raw_transactions.len() > MAX_TXS_PER_COMMIT {
            warn!(
                "commit {} has {} txs, exceeding MAX_TXS_PER_COMMIT={} — rejecting excess",
                commit_index,
                raw_transactions.len(),
                MAX_TXS_PER_COMMIT
            );
        }

        self.height += 1;
        let mut delta = BlockDelta::new(self.height);
        let mut accepted = 0usize;
        let mut rejected = 0usize;
        let mut total_fees = 0u64;
        // Audit #16: Track SystemEmission count per commit (at most 1 allowed)
        let mut emission_count = 0usize;

        for (tx_idx, raw) in raw_transactions.iter().take(MAX_TXS_PER_COMMIT).enumerate() {
            match self.validate_and_apply_tx(raw, &mut delta, &mut emission_count, leader_address.as_ref()) {
                Ok(fee) => {
                    accepted += 1;
                    total_fees = total_fees.saturating_add(fee);
                }
                Err(e) => {
                    rejected += 1;
                    warn!(
                        "commit {} tx {} rejected: {}",
                        commit_index, tx_idx, e
                    );
                }
            }
        }

        CommitExecutionResult {
            commit_index,
            txs_accepted: accepted,
            txs_rejected: rejected,
            total_fees,
            utxos_created: delta.created.len(),
        }
    }

    fn validate_and_apply_tx(
        &mut self,
        raw: &[u8],
        delta: &mut BlockDelta,
        emission_count: &mut usize,
        leader_address: Option<&[u8; 32]>,
    ) -> Result<u64, TxExecutionError> {
        // 1. Phase 2c-A: borsh decode (consensus wire format).
        let tx: UtxoTransaction = borsh::from_slice(raw)
            .map_err(|e| TxExecutionError::BorshDecodeFailed(e.to_string()))?;

        // 2. Structural validation
        tx.validate_structure()
            .map_err(|e| TxExecutionError::StructuralInvalid(e.to_string()))?;

        // 3. Kind dispatch — only TransparentTransfer and SystemEmission allowed
        match tx.tx_type {
            TxType::TransparentTransfer => self.validate_transparent_transfer(&tx, delta),
            TxType::SystemEmission => {
                // Audit #16: At most 1 SystemEmission per commit
                if *emission_count >= 1 {
                    return Err(TxExecutionError::StructuralInvalid(
                        "at most 1 SystemEmission tx per commit".into(),
                    ));
                }
                let result = self.validate_system_emission(&tx, delta, leader_address)?;
                *emission_count += 1;
                Ok(result)
            }
            _ => Err(TxExecutionError::UnsupportedTxKind),
        }
    }

    fn validate_transparent_transfer(
        &mut self,
        tx: &UtxoTransaction,
        delta: &mut BlockDelta,
    ) -> Result<u64, TxExecutionError> {
        // §4.2 step 4: expiry check
        if tx.expiry > 0 && tx.expiry < self.height {
            return Err(TxExecutionError::Expired { expiry: tx.expiry, current: self.height });
        }

        // D4b: spend-tag uniqueness check removed (field deleted from TxInput).
        // Double-spend prevention is now handled by UTXO consumption tracking.

        // §4.2 step 5a: P2PKH output binding — every output with a spending_pubkey
        // must have address == SHA3-256(spending_pubkey). Prevents an attacker from
        // creating outputs that claim someone else's address.
        Self::validate_output_pubkey_binding(&tx.outputs)?;

        // 5. ML-DSA-65 signature verification via IntentMessage.
        //
        // Phase 2c-A: TxSignablePayload contains all signable fields of
        // the transaction (excluding proofs/signatures). It is borsh-encoded
        // and wrapped in IntentMessage for domain separation + replay protection.
        use misaka_types::tx_signable::TxSignablePayload;

        // SECURITY: Reject duplicate input outrefs (prevents free mint via
        // counting the same UTXO amount multiple times)
        {
            let mut seen_outrefs = std::collections::HashSet::new();
            for input in &tx.inputs {
                for outref in &input.utxo_refs {
                    if !seen_outrefs.insert(outref.clone()) {
                        return Err(TxExecutionError::StructuralInvalid(format!(
                            "duplicate input outref {}:{}",
                            hex::encode(&outref.tx_hash[..8]),
                            outref.output_index,
                        )));
                    }
                }
            }
        }

        let payload = TxSignablePayload::from(tx);
        let intent = IntentMessage::wrap(
            IntentScope::TransparentTransfer,
            self.app_id.clone(),
            &payload,
        );
        let signing_digest = intent.signing_digest();

        for (i, input) in tx.inputs.iter().enumerate() {
            // Get spending pubkey from UTXO set
            if input.utxo_refs.is_empty() {
                return Err(TxExecutionError::SignatureInvalid {
                    input_index: i,
                    reason: "no UTXO refs for transparent transfer".into(),
                });
            }

            // SEC-FIX CRITICAL: Enforce single UTXO ref per input.
            // Previously only utxo_refs[0] was signature-verified, but ALL refs
            // were consumed and their amounts summed. An attacker could place their
            // own UTXO at [0] and a victim's UTXO at [1], sign with their own key,
            // and steal the victim's funds.
            //
            // Transparent mode requires exactly 1 UTXO ref per input.
            // This matches the check in tx_resolve.rs (FIX 12/51).
            if input.utxo_refs.len() != 1 {
                return Err(TxExecutionError::SignatureInvalid {
                    input_index: i,
                    reason: format!(
                        "transparent transfer requires exactly 1 utxo_ref per input, got {}. \
                         Multi-ref inputs allow signature bypass (UTXO theft).",
                        input.utxo_refs.len()
                    ),
                });
            }

            let outref = &input.utxo_refs[0];
            let pk_bytes = self.utxo_set.get_spending_key(outref)
                .ok_or_else(|| TxExecutionError::UtxoNotFound(
                    format!("{}:{}", hex::encode(&outref.tx_hash[..8]), outref.output_index),
                ))?;

            // §4.2 step 5b: P2PKH pubkey match
            use sha3::{Digest, Sha3_256};
            if let Some(utxo_entry) = self.utxo_set.get(outref) {
                let pk_hash: [u8; 32] = {
                    let mut h = Sha3_256::new();
                    h.update(&pk_bytes);
                    h.finalize().into()
                };
                if pk_hash != utxo_entry.output.address {
                    return Err(TxExecutionError::PubkeyMismatch { input_index: i });
                }

                // §4.4: 300-block maturity for emission outputs
                if utxo_entry.is_emission && self.height < utxo_entry.created_at + EMISSION_MATURITY {
                    return Err(TxExecutionError::EmissionNotMature {
                        created_at: utxo_entry.created_at,
                        current: self.height,
                        required: EMISSION_MATURITY,
                    });
                }
            }

            // Parse and verify ML-DSA-65 signature over IntentMessage digest
            let pk = misaka_pqc::pq_sign::MlDsaPublicKey::from_bytes(&pk_bytes)
                .map_err(|e| TxExecutionError::SignatureInvalid {
                    input_index: i,
                    reason: format!("invalid public key: {e}"),
                })?;
            let sig = misaka_pqc::pq_sign::MlDsaSignature::from_bytes(&input.proof)
                .map_err(|e| TxExecutionError::SignatureInvalid {
                    input_index: i,
                    reason: format!("invalid signature: {e}"),
                })?;
            // Verify with empty domain prefix — IntentMessage digest already
            // provides full domain separation.
            ml_dsa_verify_raw(&pk, &signing_digest, &sig)
                .map_err(|e| TxExecutionError::SignatureInvalid {
                    input_index: i,
                    reason: format!("ML-DSA-65 verify failed: {e}"),
                })?;
        }

        // 6. Amount balance check
        let mut input_sum: u64 = 0;
        for input in &tx.inputs {
            for outref in &input.utxo_refs {
                if let Some(output) = self.utxo_set.get_output(outref) {
                    input_sum = input_sum.checked_add(output.amount)
                        .ok_or(TxExecutionError::AmountOverflow)?;
                }
            }
        }
        let mut output_sum: u64 = 0;
        for output in &tx.outputs {
            output_sum = output_sum.checked_add(output.amount)
                .ok_or(TxExecutionError::AmountOverflow)?;
        }
        let outputs_plus_fee = output_sum.checked_add(tx.fee)
            .ok_or(TxExecutionError::AmountOverflow)?;
        if input_sum < outputs_plus_fee {
            return Err(TxExecutionError::InsufficientFunds {
                inputs: input_sum,
                outputs_plus_fee,
            });
        }

        // 7. Apply state changes — consume input UTXOs (double-spend prevention)
        let tx_delta = self.utxo_set.apply_transaction(&tx)
            .map_err(|e| TxExecutionError::UtxoNotFound(e.to_string()))?;
        delta.merge(tx_delta);

        Ok(tx.fee)
    }

    /// §4.3: Validate a SystemEmission transaction (formerly Coinbase).
    ///
    /// Constraints:
    /// - inputs MUST be empty
    /// - total output amount must not exceed per-block cap
    /// - outputs are marked as emission (is_emission=true) for maturity tracking
    ///
    /// # SEC-AUDIT: Output address NOT verified against block proposer
    ///
    /// Currently this function does NOT verify that emission outputs go to the
    /// block proposer's address. A Byzantine proposer can redirect block rewards
    /// to any address. This requires passing proposer pubkey context through the
    /// commit pipeline (architectural change).
    ///
    fn validate_system_emission(
        &mut self,
        tx: &UtxoTransaction,
        delta: &mut BlockDelta,
        leader_address: Option<&[u8; 32]>,
    ) -> Result<u64, TxExecutionError> {
        // §4.3: inputs MUST be empty
        if !tx.inputs.is_empty() {
            return Err(TxExecutionError::StructuralInvalid(
                "SystemEmission must have no inputs".into(),
            ));
        }

        // §4.2 step 5a: P2PKH output binding (same rule applies to emission outputs)
        Self::validate_output_pubkey_binding(&tx.outputs)?;

        // SEC-FIX: Verify emission outputs go to the block proposer's address.
        // Without this check, a Byzantine proposer can redirect block rewards
        // to an arbitrary address. The leader_address is derived from the commit
        // leader's ML-DSA-65 pubkey (SHA3-256 hash) in the commit processing loop.
        if let Some(expected_addr) = leader_address {
            for (idx, output) in tx.outputs.iter().enumerate() {
                if output.address != *expected_addr {
                    return Err(TxExecutionError::StructuralInvalid(
                        format!(
                            "SystemEmission output[{}]: address {} does not match \
                             commit leader address {}",
                            idx,
                            hex::encode(&output.address[..8]),
                            hex::encode(&expected_addr[..8]),
                        ),
                    ));
                }
            }
        } else if self.app_id.chain_id == 1 {
            // SEC-FIX: On mainnet, leader_address MUST be provided.
            // Without it, a Byzantine leader can redirect block rewards to any address.
            return Err(TxExecutionError::StructuralInvalid(
                "SystemEmission on mainnet requires leader_address for output verification".into(),
            ));
        } else {
            // Testnet/devnet: log warning but allow (leader_address resolution not yet wired)
            tracing::warn!(
                "SystemEmission processed without leader_address verification \
                 (acceptable for testnet, BLOCKED on mainnet chain_id=1)"
            );
        }

        // Amount cap (reuse PHASE2_MAX_COINBASE_PER_BLOCK for now)
        let mut total: u64 = 0;
        for output in &tx.outputs {
            total = total.checked_add(output.amount)
                .ok_or(TxExecutionError::AmountOverflow)?;
        }
        if total > PHASE2_MAX_COINBASE_PER_BLOCK {
            return Err(TxExecutionError::CoinbaseExceedsCap);
        }

        // SEC-FIX: Enforce total supply cap (MAX_TOTAL_SUPPLY).
        // Previously only per-block cap existed; SupplyTracker had max_supply
        // but was not connected to the execution layer.
        let new_total = self.total_emitted.checked_add(total)
            .ok_or(TxExecutionError::AmountOverflow)?;
        if new_total > MAX_TOTAL_SUPPLY {
            return Err(TxExecutionError::StructuralInvalid(
                format!(
                    "SystemEmission would exceed MAX_TOTAL_SUPPLY: emitted {} + new {} > cap {}",
                    self.total_emitted, total, MAX_TOTAL_SUPPLY
                ),
            ));
        }
        self.total_emitted = new_total;

        // Apply outputs with is_emission=true (§4.4 maturity tracking)
        let tx_hash = tx.tx_hash();
        for (idx, output) in tx.outputs.iter().enumerate() {
            let outref = OutputRef {
                tx_hash,
                output_index: idx as u32,
            };
            self.utxo_set
                .add_output(outref.clone(), output.clone(), self.height, true)
                .map_err(|e| TxExecutionError::StructuralInvalid(
                    format!("SystemEmission output add failed: {}", e),
                ))?;
            delta.created.push(outref);
        }
        Ok(0)
    }

    /// Audit #10: Validate P2PKH output binding.
    /// For each output with spending_pubkey, enforce: address == SHA3-256(spending_pubkey).
    /// This prevents an attacker from creating outputs that claim someone else's address.
    fn validate_output_pubkey_binding(outputs: &[TxOutput]) -> Result<(), TxExecutionError> {
        use sha3::{Digest, Sha3_256};
        for (idx, output) in outputs.iter().enumerate() {
            if let Some(ref spk) = output.spending_pubkey {
                let expected_addr: [u8; 32] = {
                    let mut h = Sha3_256::new();
                    h.update(spk);
                    h.finalize().into()
                };
                if output.address != expected_addr {
                    return Err(TxExecutionError::OutputPubkeyBindingFailed {
                        output_index: idx,
                    });
                }
            }
        }
        Ok(())
    }

    pub fn height(&self) -> u64 { self.height }
    pub fn utxo_count(&self) -> usize { self.utxo_set.len() }
    pub fn utxo_set(&self) -> &UtxoSet { &self.utxo_set }
    pub fn app_id(&self) -> &AppId { &self.app_id }

    /// Phase 3 C7: Return the current state root (MuHash of UTXO set).
    pub fn state_root(&self) -> [u8; 32] {
        self.utxo_set.compute_state_root()
    }

    /// SEC-FIX C-12: Generate block reward (SystemEmission) for the commit leader.
    ///
    /// Narwhal's propose loop only includes user transactions from the mempool.
    /// Block rewards must be generated separately at commit time.
    /// Returns the reward amount (0 if already at max supply).
    pub fn generate_block_reward(
        &mut self,
        leader_address: [u8; 32],
        leader_pubkey: Option<Vec<u8>>,
    ) -> u64 {
        // Check supply cap
        let reward = PHASE2_MAX_COINBASE_PER_BLOCK;
        let new_total = match self.total_emitted.checked_add(reward) {
            Some(t) if t <= MAX_TOTAL_SUPPLY => t,
            _ => {
                tracing::info!("Block reward skipped: total_emitted at or near MAX_TOTAL_SUPPLY");
                return 0;
            }
        };

        // Create the reward UTXO
        let tx_hash = {
            use sha3::{Digest, Sha3_256};
            let mut h = Sha3_256::new();
            h.update(b"MISAKA:block_reward:");
            h.update(&self.height.to_le_bytes());
            h.update(&leader_address);
            let hash: [u8; 32] = h.finalize().into();
            hash
        };
        let outref = misaka_types::utxo::OutputRef {
            tx_hash,
            output_index: 0,
        };
        let output = misaka_types::utxo::TxOutput {
            amount: reward,
            address: leader_address,
            spending_pubkey: leader_pubkey,
        };
        if let Err(e) = self.utxo_set.add_output(outref.clone(), output, self.height, true) {
            tracing::error!("Failed to create block reward UTXO: {}", e);
            return 0;
        }
        // Register spending key if provided
        if let Some(spk) = self.utxo_set.get(&outref).and_then(|e| e.output.spending_pubkey.clone()) {
            let _ = self.utxo_set.register_spending_key(outref, spk);
        }
        self.total_emitted = new_total;
        tracing::debug!(
            "Block reward: {} base units to {} (total_emitted={})",
            reward, hex::encode(&leader_address[..8]), new_total
        );
        reward
    }

    /// Phase 3 C5: Check burn replay protection.
    ///
    /// Returns Ok(()) if the burn_id has not been processed before,
    /// inserting it into the processed set.
    /// Returns Err(BurnAlreadyProcessed) if the burn_id was already seen.
    pub fn check_burn_replay(&mut self, burn_id: [u8; 32]) -> Result<(), TxExecutionError> {
        if !self.processed_burns.insert(burn_id) {
            return Err(TxExecutionError::BurnAlreadyProcessed(
                hex::encode(&burn_id[..8]),
            ));
        }
        Ok(())
    }

    /// Phase 3 C5: Get the set of processed burn IDs.
    pub fn processed_burns(&self) -> &HashSet<[u8; 32]> {
        &self.processed_burns
    }

    /// SEC-FIX: Load previously processed burn IDs from persistent storage.
    ///
    /// MUST be called at startup before processing any new commits.
    /// Without this, burn replay protection is lost on node restart,
    /// allowing double-minting of bridge transactions.
    pub fn load_processed_burns(&mut self, burn_ids: impl IntoIterator<Item = [u8; 32]>) {
        for id in burn_ids {
            self.processed_burns.insert(id);
        }
        tracing::info!(
            "Loaded {} processed burn IDs from persistent storage",
            self.processed_burns.len()
        );
    }

    /// SEC-FIX CRITICAL: Restore total_emitted from persistent storage.
    pub fn set_total_emitted(&mut self, total: u64) {
        self.total_emitted = total;
    }

    /// Get current total_emitted for snapshot persistence.
    pub fn total_emitted(&self) -> u64 {
        self.total_emitted
    }

    /// SEC-FIX: Export processed burn IDs for persistence.
    ///
    /// Callers MUST persist the returned set to durable storage
    /// (RocksDB/SQLite) after each commit that processes burn transactions.
    pub fn processed_burns_snapshot(&self) -> Vec<[u8; 32]> {
        self.processed_burns.iter().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_app_id() -> AppId {
        AppId::new(2, [0u8; 32])
    }

    #[test]
    fn empty_commit_succeeds() {
        let mut executor = UtxoExecutor::new(test_app_id());
        let result = executor.execute_committed(1, &[], None);
        assert_eq!(result.txs_accepted, 0);
        assert_eq!(result.txs_rejected, 0);
    }

    #[test]
    fn malformed_borsh_gracefully_rejected() {
        let mut executor = UtxoExecutor::new(test_app_id());
        let result = executor.execute_committed(1, &[b"not valid borsh".to_vec()], None);
        // Must NOT panic — graceful rejection
        assert_eq!(result.txs_accepted, 0);
        assert_eq!(result.txs_rejected, 1);
    }
}
