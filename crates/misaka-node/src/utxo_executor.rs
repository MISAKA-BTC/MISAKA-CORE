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
use misaka_consensus::protocol_upgrade::is_feature_active;
use misaka_consensus::stake_tx_verify::verify_stake_tx_signature;
use misaka_consensus::staking::StakingRegistry;
use misaka_pqc::pq_sign::ml_dsa_verify_raw;
use misaka_storage::utxo_set::{BlockDelta, UtxoSet};
use misaka_types::intent::{AppId, IntentMessage, IntentScope};
use misaka_types::utxo::{OutputRef, TxOutput, TxType, UtxoTransaction};
use misaka_types::validator_stake_tx::{StakeTxParams, ValidatorStakeTx};
use std::collections::{HashMap, HashSet};
use tracing::{error, info, warn};

/// Phase 2b hard cap on coinbase output sum (50 MISAKA).
/// Phase 3 replaces with epoch-based SystemEmission.
const PHASE2_MAX_COINBASE_PER_BLOCK: u64 = 50_000_000_000;

/// Faucet per-drip cap (100,000 MISAKA). Separate from block reward cap.
const MAX_FAUCET_DRIP_AMOUNT: u64 = 100_000_000_000_000;

/// Maximum transactions per committed batch.
const MAX_TXS_PER_COMMIT: usize = 10_000;

/// §4.4: Emission outputs require 300-block maturity before spending.
const EMISSION_MATURITY: u64 = 300;

/// SEC-FIX: Maximum total supply (10 billion MISAKA in base units).
/// This is the hard cap enforced at the consensus execution layer.
/// Previously only per-block emission cap existed (PHASE2_MAX_COINBASE_PER_BLOCK)
/// but total supply was uncapped — SupplyTracker existed but was not connected.
/// Hard cap: 10 billion MISAKA with 9 decimal places (base units).
/// 10B MSK × 10^9 = 10_000_000_000_000_000_000 base units.
/// Fits within u64::MAX (≈18.4 × 10^18).
const MAX_TOTAL_SUPPLY: u64 = 10_000_000_000_000_000_000; // 10B × 10^9 base units

/// §5.5 Fee distribution — proposer receives 50%.
/// NOTE: Not yet enforced in execution; fees are summed in CommitExecutionResult
/// and distribution is deferred to the staking/treasury module (Phase 3+).
pub const PROPOSER_FEE_SHARE_BPS: u64 = 5000;
/// §5.5 Fee distribution — treasury receives 10%.
pub const TREASURY_FEE_SHARE_BPS: u64 = 1000;
/// §5.5 Fee distribution — 40% burned.
pub const BURN_FEE_SHARE_BPS: u64 = 4000;

// Phase 2b': TX_SIGN_DOMAIN removed — IntentMessage provides domain separation.

/// γ-4: Per-tx savepoint into a `BlockDelta`. Captures the lengths of
/// `delta.spent` and `delta.created` immediately before a stake tx
/// begins its UTXO mutations. `rollback_stake_tx_utxo_side` uses this
/// to identify and reverse exactly this tx's additions when the
/// registry step that follows fails.
#[derive(Debug, Clone, Copy)]
struct StakeTxDeltaSavepoint {
    spent_len: usize,
    created_len: usize,
}

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
    EmissionNotMature {
        created_at: u64,
        current: u64,
        required: u64,
    },
    #[error("P2PKH pubkey mismatch at input {input_index}")]
    PubkeyMismatch { input_index: usize },
    #[error("output {output_index} address/spending_pubkey binding failed: address != SHA3-256(spending_pubkey)")]
    OutputPubkeyBindingFailed { output_index: usize },
    #[error("unsupported tx kind")]
    UnsupportedTxKind,
    #[error("burn already processed: {0}")]
    BurnAlreadyProcessed(String),
    // ── γ-3: stake tx dispatch errors ──────────────────────────────────
    #[error("stake tx requires StakingRegistry but none was provided")]
    StakeRegistryMissing,
    #[error("stake envelope decode failed: {0}")]
    StakeEnvelopeDecode(String),
    #[error("stake tx signature / state verify failed: {0}")]
    StakeVerifyFailed(String),
    #[error("stake registry op failed: {0}")]
    StakeRegistryOp(String),
    #[error("StakeDeposit envelope kind {kind} not allowed for tx_type")]
    StakeDepositWrongKind { kind: String },
    #[error("StakeWithdraw envelope kind {kind} not allowed for tx_type")]
    StakeWithdrawWrongKind { kind: String },
    /// Group 1: feature-gate rejection. Emitted by `apply_stake_deposit` /
    /// `apply_stake_withdraw` when the `on-chain-staking` feature has not yet
    /// reached its scheduled activation height.
    #[error("feature {feature} not active at height {height}")]
    FeatureNotActive { feature: String, height: u64 },
}

/// Result of executing a committed batch.
#[derive(Debug)]
pub struct CommitExecutionResult {
    pub commit_index: u64,
    pub txs_accepted: usize,
    pub txs_rejected: usize,
    pub total_fees: u64,
    pub utxos_created: usize,
    /// R7 C-4: true when this batch already contained a SystemEmission tx.
    /// The caller MUST skip `generate_block_reward` when this is set to
    /// prevent double emission.
    pub had_system_emission: bool,
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
    /// γ-3: Staked receipt marker table.
    ///
    /// For every finalized `TxType::StakeDeposit` Register tx, `outputs[0]` is
    /// a zero-value "locked receipt" tagged with `validator_id`. It is NOT
    /// written to the regular `UtxoSet` (otherwise it could be spent as a
    /// normal UTXO). Instead it is recorded here keyed by its `OutputRef`,
    /// so γ-5's `settle_unlocks` can retire the marker when the unbonding
    /// period completes.
    ///
    /// γ-3 writes entries (on Register). γ-5 reads + removes them (after
    /// `registry.unlock()` succeeds).
    staked_receipt_table: HashMap<OutputRef, [u8; 32]>,
    /// Group 1: test-only override for the `on-chain-staking` feature gate.
    ///
    /// `None` → production path; the gate defers to
    /// `misaka_consensus::protocol_upgrade::is_feature_active("on-chain-staking", height)`
    /// which returns `false` until the feature is scheduled.
    ///
    /// `Some(h)` → treat the feature as active at heights `>= h`. Set only by
    /// `enable_on_chain_staking_for_tests`. Production must leave as `None`.
    staking_activation_override: Option<u64>,
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
            staked_receipt_table: HashMap::new(),
            staking_activation_override: None,
        }
    }

    /// Create from an existing UTXO set (crash recovery).
    pub fn with_utxo_set(utxo_set: UtxoSet, app_id: AppId) -> Self {
        let height = utxo_set.height;
        Self {
            app_id,
            utxo_set,
            height,
            processed_burns: HashSet::new(),
            total_emitted: 0,
            staked_receipt_table: HashMap::new(),
            staking_activation_override: None,
        }
    }

    /// γ-3: inspect the staked-receipt table (γ-5 will consume entries).
    pub fn staked_receipt_table(&self) -> &HashMap<OutputRef, [u8; 32]> {
        &self.staked_receipt_table
    }

    /// Group 1: test-only helper — pretend the `on-chain-staking` feature
    /// activates at `activation_height`, bypassing the global
    /// `FEATURE_ACTIVATIONS` table (which currently has the feature at
    /// `u64::MAX` and therefore rejects every StakeDeposit / StakeWithdraw in
    /// production paths).
    ///
    /// Production must NOT call this. Remove call sites in mempool/executor
    /// tests once the feature reaches a real activation height.
    #[doc(hidden)]
    pub fn enable_on_chain_staking_for_tests(&mut self, activation_height: u64) {
        self.staking_activation_override = Some(activation_height);
    }

    /// Group 1: evaluate the `on-chain-staking` feature gate at the executor's
    /// current block height. Honors the test-only override if set.
    fn on_chain_staking_active(&self) -> bool {
        match self.staking_activation_override {
            Some(h) => self.height >= h,
            None => is_feature_active("on-chain-staking", self.height),
        }
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
        // γ-3: stake tx dispatch plumbing.
        //
        // When `staking` is `None`, any `StakeDeposit` / `StakeWithdraw` tx in
        // the batch is rejected with `TxExecutionError::StakeRegistryMissing`
        // (preserving the pre-γ-3 "unsupported tx kind" rejection semantics
        // while making the reason explicit). Production callers pass
        // `Some(&mut registry)` holding the `Arc<RwLock<_>>::write()` guard.
        staking: Option<&mut StakingRegistry>,
        current_epoch: u64,
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
        // R7 C-3: Keep UtxoSet.height in sync so that add_output stamps
        // outputs with the correct created_at and MuHash elements match.
        self.utxo_set.height = self.height;
        let mut delta = BlockDelta::new(self.height);
        let mut accepted = 0usize;
        let mut rejected = 0usize;
        let mut total_fees = 0u64;
        // Audit #16: Track SystemEmission count per commit (at most 1 allowed)
        let mut emission_count = 0usize;

        // γ-3: hold the mut borrow of the registry across the tx loop; each
        // tx's dispatch re-borrows via `staking.as_deref_mut()`.
        let mut staking = staking;

        for (tx_idx, raw) in raw_transactions.iter().take(MAX_TXS_PER_COMMIT).enumerate() {
            match self.validate_and_apply_tx(
                raw,
                &mut delta,
                &mut emission_count,
                leader_address.as_ref(),
                staking.as_deref_mut(),
                current_epoch,
            ) {
                Ok(fee) => {
                    accepted += 1;
                    total_fees = total_fees.saturating_add(fee);
                }
                Err(e) => {
                    rejected += 1;
                    warn!("commit {} tx {} rejected: {}", commit_index, tx_idx, e);
                }
            }
        }

        CommitExecutionResult {
            commit_index,
            txs_accepted: accepted,
            txs_rejected: rejected,
            total_fees,
            utxos_created: delta.created.len(),
            had_system_emission: emission_count > 0,
        }
    }

    fn validate_and_apply_tx(
        &mut self,
        raw: &[u8],
        delta: &mut BlockDelta,
        emission_count: &mut usize,
        leader_address: Option<&[u8; 32]>,
        staking: Option<&mut StakingRegistry>,
        current_epoch: u64,
    ) -> Result<u64, TxExecutionError> {
        // 1. Phase 2c-A: borsh decode (consensus wire format).
        let tx: UtxoTransaction = borsh::from_slice(raw)
            .map_err(|e| TxExecutionError::BorshDecodeFailed(e.to_string()))?;

        // 2. Structural validation
        tx.validate_structure()
            .map_err(|e| TxExecutionError::StructuralInvalid(e.to_string()))?;

        // 3. Kind dispatch
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
            TxType::Faucet => self.validate_faucet_tx(&tx, delta),
            // γ-3: L1 native validator staking
            TxType::StakeDeposit => {
                let registry = staking.ok_or(TxExecutionError::StakeRegistryMissing)?;
                self.apply_stake_deposit(&tx, registry, current_epoch, delta)
            }
            TxType::StakeWithdraw => {
                let registry = staking.ok_or(TxExecutionError::StakeRegistryMissing)?;
                self.apply_stake_withdraw(&tx, registry, current_epoch, delta)
            }
            // Group 1: explicit SlashEvidence rejection replaces the prior
            // `_ =>` wildcard. Keeping the arm explicit makes the match
            // exhaustive so future `TxType` variants surface as a compile
            // error here instead of silently falling through. SlashEvidence
            // handling itself is deferred to γ-6.
            TxType::SlashEvidence => Err(TxExecutionError::UnsupportedTxKind),
        }
    }

    // ─── γ-3: StakeDeposit / StakeWithdraw dispatch ───────────────────────

    fn decode_and_verify_stake_tx(
        tx: &UtxoTransaction,
        registry: &StakingRegistry,
    ) -> Result<ValidatorStakeTx, TxExecutionError> {
        let stake_tx = ValidatorStakeTx::decode_from_extra(&tx.extra)
            .map_err(|e| TxExecutionError::StakeEnvelopeDecode(e.to_string()))?;
        verify_stake_tx_signature(&stake_tx, registry)
            .map_err(|e| TxExecutionError::StakeVerifyFailed(e.to_string()))?;
        Ok(stake_tx)
    }

    /// Apply a `TxType::StakeDeposit` — envelope kind must be `Register` or
    /// `StakeMore`. Mutates the registry; on Register, writes a marker into
    /// `staked_receipt_table` (keyed by `tx_hash | output_index=0`).
    ///
    /// γ-3.2: `tx.inputs` are now consumed from the UTXO set (double-spend
    /// prevention, matching transparent transfer semantics). `outputs[0]`
    /// is routed to `staked_receipt_table` only; `outputs[1..]` (change)
    /// go into the regular UTXO set normally.
    ///
    /// γ-6 note: registry errors on Register (`AlreadyRegistered` etc.) bubble
    /// up here as `StakeRegistryOp`. γ-6 is slated to introduce a
    /// `mergeable: bool` variant so merge logic can be pushed up without
    /// breaking this arm.
    fn apply_stake_deposit(
        &mut self,
        tx: &UtxoTransaction,
        registry: &mut StakingRegistry,
        current_epoch: u64,
        delta: &mut BlockDelta,
    ) -> Result<u64, TxExecutionError> {
        // Group 1: feature gate — reject before any other work. Runs before
        // envelope decode / signature verify so a pre-activation StakeDeposit
        // is rejected cheaply and without touching the registry.
        if !self.on_chain_staking_active() {
            return Err(TxExecutionError::FeatureNotActive {
                feature: "on-chain-staking".into(),
                height: self.height,
            });
        }

        let stake_tx = Self::decode_and_verify_stake_tx(tx, registry)?;
        let stake_tx_hash = tx.tx_hash();

        // Early kind-check before any mutation — BeginExit cannot appear in
        // a StakeDeposit envelope.
        if matches!(stake_tx.params, StakeTxParams::BeginExit) {
            return Err(TxExecutionError::StakeDepositWrongKind {
                kind: "BeginExit".into(),
            });
        }

        // γ-4 pre-flight: dry-run the registry mutation BEFORE touching the
        // UTXO set. If the registry would reject (already registered, replay,
        // below min, etc.), we fail fast without consuming any inputs. The
        // mutating call downstream re-validates everything, so concurrent
        // registry races still produce a correct result (the rollback path
        // below catches them).
        match &stake_tx.params {
            StakeTxParams::Register(params) => {
                let net_stake = stake_tx.net_stake_amount();
                registry
                    .can_register_l1_native(
                        &stake_tx.validator_id,
                        net_stake,
                        params.commission_bps,
                        &stake_tx_hash,
                    )
                    .map_err(|e| TxExecutionError::StakeRegistryOp(format!("{e:?}")))?;
            }
            StakeTxParams::StakeMore(p) => {
                registry
                    .can_stake_more(&stake_tx.validator_id, p.additional_amount, &stake_tx_hash)
                    .map_err(|e| TxExecutionError::StakeRegistryOp(format!("{e:?}")))?;
            }
            StakeTxParams::BeginExit => unreachable!("guarded above"),
        }

        // γ-3.2: consume tx.inputs + add change outputs.
        //
        // γ-3.3: BlockDelta is threaded through so `undo_last_delta`
        // (SPC switch / shallow rollback) can reverse the UTXO-side
        // effects of a stake tx at the block level. The
        // `staked_receipt_table` entry is NOT captured in `delta` — it
        // lives outside UtxoSet and its rollback is tracked separately
        // (γ-6 scope).
        //
        // γ-4: tx-local rollback. We take a `StakeTxDeltaSavepoint` BEFORE
        // the UTXO consume so that if the registry mutation below fails
        // we can reverse precisely this tx's UTXO-side effects via
        // `rollback_stake_tx_utxo_side`. The pre-flight above makes the
        // rollback path a true safety net (common failure modes no longer
        // reach UTXO consume), but we keep it for concurrent registry
        // races and defense in depth.
        let savepoint = Self::delta_savepoint(delta);
        Self::consume_stake_tx_inputs_and_change(
            &mut self.utxo_set,
            tx,
            stake_tx_hash,
            /* skip_output_index = */ Some(0),
            delta,
        )?;

        let registry_result: Result<(), TxExecutionError> = match &stake_tx.params {
            StakeTxParams::Register(params) => {
                let net_stake = stake_tx.net_stake_amount();
                match registry.register_l1_native(
                    stake_tx.validator_id,
                    params.consensus_pubkey.clone(),
                    net_stake,
                    params.commission_bps,
                    params.reward_address,
                    current_epoch,
                    stake_tx_hash,
                    0, // stake_output_index: 0 is the receipt marker
                ) {
                    Ok(()) => {
                        if let Some(endpoint) = params.p2p_endpoint.clone() {
                            let _ = registry
                                .set_network_address(&stake_tx.validator_id, Some(endpoint));
                        }
                        // Record the locked receipt marker (outputs[0]).
                        let outref = OutputRef {
                            tx_hash: stake_tx_hash,
                            output_index: 0,
                        };
                        self.staked_receipt_table
                            .insert(outref, stake_tx.validator_id);
                        info!(
                            "γ-3 Register: validator={} stake={} epoch={}",
                            hex::encode(stake_tx.validator_id),
                            net_stake,
                            current_epoch,
                        );
                        Ok(())
                    }
                    Err(e) => Err(TxExecutionError::StakeRegistryOp(format!("{e:?}"))),
                }
            }
            StakeTxParams::StakeMore(p) => {
                match registry.stake_more(
                    &stake_tx.validator_id,
                    p.additional_amount,
                    stake_tx_hash,
                ) {
                    Ok(_) => {
                        info!(
                            "γ-3 StakeMore: validator={} additional={} epoch={}",
                            hex::encode(stake_tx.validator_id),
                            p.additional_amount,
                            current_epoch,
                        );
                        Ok(())
                    }
                    Err(e) => Err(TxExecutionError::StakeRegistryOp(format!("{e:?}"))),
                }
            }
            StakeTxParams::BeginExit => unreachable!("guarded above"),
        };

        if let Err(e) = registry_result {
            // γ-4: registry rejected after UTXO consume (pre-flight passed
            // but a concurrent mutation invalidated our assumption, or
            // defense-in-depth check inside the mutating call found
            // something dry-run missed). Reverse exactly this tx's UTXO
            // effects. Rollback failure panics (storage invariant).
            tracing::warn!(
                "γ-4: registry mutation failed after UTXO consume — rolling back: {:?}",
                e
            );
            Self::rollback_stake_tx_utxo_side(&mut self.utxo_set, delta, savepoint);
            return Err(e);
        }

        Ok(tx.fee)
    }

    /// Apply a `TxType::StakeWithdraw` — envelope kind MUST be `BeginExit`.
    /// Drives the validator into `EXITING` state via `registry.exit`.
    ///
    /// γ-3.2: `tx.inputs` are consumed as usual (fee-paying UTXOs).
    /// BeginExit has no receipt marker to skip, so *all* `tx.outputs` (which
    /// in practice is just fee change) go into the regular UTXO set.
    fn apply_stake_withdraw(
        &mut self,
        tx: &UtxoTransaction,
        registry: &mut StakingRegistry,
        current_epoch: u64,
        delta: &mut BlockDelta,
    ) -> Result<u64, TxExecutionError> {
        // Group 1: feature gate — same contract as apply_stake_deposit.
        if !self.on_chain_staking_active() {
            return Err(TxExecutionError::FeatureNotActive {
                feature: "on-chain-staking".into(),
                height: self.height,
            });
        }

        let stake_tx = Self::decode_and_verify_stake_tx(tx, registry)?;
        let stake_tx_hash = tx.tx_hash();

        // Early kind-check before any mutation — see apply_stake_deposit above.
        match &stake_tx.params {
            StakeTxParams::Register(_) | StakeTxParams::StakeMore(_) => {
                return Err(TxExecutionError::StakeWithdrawWrongKind {
                    kind: match &stake_tx.params {
                        StakeTxParams::Register(_) => "Register".into(),
                        StakeTxParams::StakeMore(_) => "StakeMore".into(),
                        _ => unreachable!(),
                    },
                });
            }
            StakeTxParams::BeginExit => {}
        }

        // γ-4 pre-flight: dry-run `exit` before touching the UTXO set.
        // Catches `InvalidTransition` (non-Active state) and
        // `ValidatorNotFound` without consuming fee inputs.
        registry
            .can_exit(&stake_tx.validator_id)
            .map_err(|e| TxExecutionError::StakeRegistryOp(format!("{e:?}")))?;

        // γ-3.2 / γ-3.3: consume inputs + add change outputs (with delta
        // bookkeeping).
        // γ-4: savepoint + rollback on registry failure.
        let savepoint = Self::delta_savepoint(delta);
        Self::consume_stake_tx_inputs_and_change(
            &mut self.utxo_set,
            tx,
            stake_tx_hash,
            /* skip_output_index = */ None,
            delta,
        )?;

        if let Err(e) = registry.exit(&stake_tx.validator_id, current_epoch) {
            let err = TxExecutionError::StakeRegistryOp(format!("{e:?}"));
            tracing::warn!(
                "γ-4: registry exit failed after UTXO consume — rolling back: {:?}",
                err
            );
            Self::rollback_stake_tx_utxo_side(&mut self.utxo_set, delta, savepoint);
            return Err(err);
        }

        info!(
            "γ-3 BeginExit: validator={} epoch={}",
            hex::encode(stake_tx.validator_id),
            current_epoch,
        );
        Ok(tx.fee)
    }

    /// γ-3.2: stake-tx-specific variant of `UtxoSet::apply_transaction`.
    ///
    /// Mirrors the transparent transfer's input consumption + output insertion
    /// semantics, with one extension: the caller may nominate a single
    /// `skip_output_index` (typically `0` for `StakeDeposit`) whose output
    /// is NOT written to the UTXO set — those entries are tracked
    /// elsewhere (`staked_receipt_table`). All other outputs (typically
    /// `outputs[1..]` change) are added normally.
    ///
    /// γ-3.3: captures consumed inputs in `delta.spent` and newly created
    /// outputs in `delta.created`. This matches `UtxoSet::apply_transaction`
    /// semantics and keeps `undo_last_delta` (SPC switch / shallow rollback)
    /// working correctly for stake txs. The `skip_output_index` entry is
    /// intentionally NOT recorded in `delta.created` — it was never added
    /// to the UtxoSet, so there is nothing for `undo_last_delta` to remove.
    fn consume_stake_tx_inputs_and_change(
        utxo_set: &mut UtxoSet,
        tx: &UtxoTransaction,
        tx_hash: [u8; 32],
        skip_output_index: Option<u32>,
        delta: &mut BlockDelta,
    ) -> Result<(), TxExecutionError> {
        // Consume inputs (double-spend prevention). Errors if any referenced
        // UTXO is missing — this is what prevents a TransparentTransfer from
        // spending an already-staked UTXO (and vice versa).
        for input in &tx.inputs {
            for outref in &input.utxo_refs {
                // Snapshot the entry for delta bookkeeping BEFORE removal
                // (matches `UtxoSet::apply_transaction`'s delta.spent shape).
                let spent_entry = utxo_set.get(outref).map(|e| e.output.clone());
                let Some(output) = spent_entry else {
                    return Err(TxExecutionError::UtxoNotFound(format!(
                        "stake tx input UTXO {}:{} not found",
                        hex::encode(&outref.tx_hash[..8]),
                        outref.output_index,
                    )));
                };
                utxo_set.remove_output(outref);
                delta.spent.push((outref.tx_hash, outref.clone(), output));
            }
        }

        // Create outputs, skipping the receipt-marker index (if any).
        for (idx, output) in tx.outputs.iter().enumerate() {
            let idx_u32 = idx as u32;
            if skip_output_index == Some(idx_u32) {
                continue;
            }
            let outref = OutputRef {
                tx_hash,
                output_index: idx_u32,
            };
            utxo_set
                .add_output(outref.clone(), output.clone(), utxo_set.height, false)
                .map_err(|e| TxExecutionError::UtxoNotFound(e.to_string()))?;
            if let Some(ref spk) = output.spending_pubkey {
                let _ = utxo_set.register_spending_key(outref.clone(), spk.clone());
            }
            delta.created.push(outref);
        }
        Ok(())
    }

    /// γ-4: Take a savepoint of the current delta lengths.
    fn delta_savepoint(delta: &BlockDelta) -> StakeTxDeltaSavepoint {
        StakeTxDeltaSavepoint {
            spent_len: delta.spent.len(),
            created_len: delta.created.len(),
        }
    }

    /// γ-4: Reverse the UTXO-side effects produced by a single stake tx
    /// between `savepoint` and now. Called after the registry step fails
    /// so the sender's inputs are not silently donated.
    ///
    /// Strategy:
    /// 1. For every entry appended to `delta.created` since the savepoint,
    ///    remove the OutputRef from the UTXO set. These were change outputs
    ///    added by `consume_stake_tx_inputs_and_change`.
    /// 2. For every entry appended to `delta.spent` since the savepoint,
    ///    re-insert the captured `TxOutput` at its original `OutputRef`.
    ///    These are the inputs the stake tx consumed.
    /// 3. Truncate both delta vecs back to the savepoint lengths so the
    ///    wrapping block-level delta reflects only transactions that
    ///    actually committed.
    ///
    /// Rollback failure is a storage-invariant violation: the UTXO set
    /// diverges from its pre-tx state and state_root will mismatch across
    /// nodes. We `panic!` to trip the process-level fail-closed path
    /// rather than quietly return — continuing would risk silent
    /// consensus divergence. This matches the "fail closed" semantic
    /// used elsewhere (state_root mismatch trips safe-mode).
    fn rollback_stake_tx_utxo_side(
        utxo_set: &mut UtxoSet,
        delta: &mut BlockDelta,
        savepoint: StakeTxDeltaSavepoint,
    ) {
        // 1. Remove change outputs added by this tx.
        let created_to_undo: Vec<OutputRef> = delta.created[savepoint.created_len..].to_vec();
        for outref in &created_to_undo {
            utxo_set.remove_output(outref);
        }

        // 2. Restore consumed inputs. Iterate oldest-first so if any
        //    entry panics the log reflects insertion order.
        let spent_to_restore: Vec<([u8; 32], OutputRef, TxOutput)> =
            delta.spent[savepoint.spent_len..].to_vec();
        for (_tx_hash, outref, output) in &spent_to_restore {
            // Re-insert at the original OutputRef so downstream state is
            // bit-equivalent to the pre-tx state. The height stamp is
            // re-applied from utxo_set.height (caller hasn't bumped it,
            // so this matches the original created_at).
            match utxo_set.add_output(
                outref.clone(),
                output.clone(),
                utxo_set.height,
                /* is_emission = */ false,
            ) {
                Ok(()) => {
                    // Re-register the spending_pubkey if the original had one.
                    if let Some(ref spk) = output.spending_pubkey {
                        let _ = utxo_set.register_spending_key(outref.clone(), spk.clone());
                    }
                }
                Err(e) => {
                    // Storage invariant violation — cannot continue.
                    panic!(
                        "γ-4: UTXO rollback failed — storage invariant violated: \
                         re-inserting OutputRef {:?}: {}",
                        outref, e
                    );
                }
            }
        }

        // 3. Shrink delta back to pre-tx lengths.
        delta.spent.truncate(savepoint.spent_len);
        delta.created.truncate(savepoint.created_len);
    }

    fn validate_transparent_transfer(
        &mut self,
        tx: &UtxoTransaction,
        delta: &mut BlockDelta,
    ) -> Result<u64, TxExecutionError> {
        // §4.2 step 4: expiry check
        if tx.expiry > 0 && tx.expiry < self.height {
            return Err(TxExecutionError::Expired {
                expiry: tx.expiry,
                current: self.height,
            });
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
            // fallback_pk is overwritten in the matching arm below (never read in its
            // initial empty state). The initial Vec::new() triggered
            // under strict CI; mark the placeholder so the warning is silenced while
            // keeping the mut borrow semantics the borrow-checker needs to hand out
            //  from inside the match arm.
            #[allow(unused_assignments)]
            let mut fallback_pk = Vec::new();
            let pk_bytes = match self.utxo_set.get_spending_key(outref) {
                Some(pk) => pk,
                None if tx.extra.len() == 1952 => {
                    fallback_pk = tx.extra.clone();
                    &fallback_pk[..]
                }
                None => {
                    return Err(TxExecutionError::SignatureInvalid {
                        input_index: i,
                        reason: "spending key not found in UTXO set and not provided in tx.extra"
                            .into(),
                    })
                }
            };

            // §4.2 step 5b: P2PKH pubkey match
            use sha3::{Digest, Sha3_256};
            if let Some(utxo_entry) = self.utxo_set.get(outref) {
                let pk_hash: [u8; 32] = {
                    let mut h = Sha3_256::new();
                    h.update(b"MISAKA:address:v1:");
                    h.update(&pk_bytes);
                    h.finalize().into()
                };
                if pk_hash != utxo_entry.output.address {
                    return Err(TxExecutionError::PubkeyMismatch { input_index: i });
                }

                // §4.4: 300-block maturity for emission outputs
                if utxo_entry.is_emission
                    && self.height < utxo_entry.created_at.saturating_add(EMISSION_MATURITY)
                {
                    return Err(TxExecutionError::EmissionNotMature {
                        created_at: utxo_entry.created_at,
                        current: self.height,
                        required: EMISSION_MATURITY,
                    });
                }
            }

            // Parse and verify ML-DSA-65 signature over IntentMessage digest
            let pk = misaka_pqc::pq_sign::MlDsaPublicKey::from_bytes(&pk_bytes).map_err(|e| {
                TxExecutionError::SignatureInvalid {
                    input_index: i,
                    reason: format!("invalid public key: {e}"),
                }
            })?;
            let sig =
                misaka_pqc::pq_sign::MlDsaSignature::from_bytes(&input.proof).map_err(|e| {
                    TxExecutionError::SignatureInvalid {
                        input_index: i,
                        reason: format!("invalid signature: {e}"),
                    }
                })?;
            // Verify with empty domain prefix — IntentMessage digest already
            // provides full domain separation.
            ml_dsa_verify_raw(&pk, &signing_digest, &sig).map_err(|e| {
                TxExecutionError::SignatureInvalid {
                    input_index: i,
                    reason: format!("ML-DSA-65 verify failed: {e}"),
                }
            })?;
        }

        // 6. Amount balance check
        let mut input_sum: u64 = 0;
        for input in &tx.inputs {
            for outref in &input.utxo_refs {
                if let Some(output) = self.utxo_set.get_output(outref) {
                    input_sum = input_sum
                        .checked_add(output.amount)
                        .ok_or(TxExecutionError::AmountOverflow)?;
                }
            }
        }
        let mut output_sum: u64 = 0;
        for output in &tx.outputs {
            output_sum = output_sum
                .checked_add(output.amount)
                .ok_or(TxExecutionError::AmountOverflow)?;
        }
        let outputs_plus_fee = output_sum
            .checked_add(tx.fee)
            .ok_or(TxExecutionError::AmountOverflow)?;
        if input_sum < outputs_plus_fee {
            return Err(TxExecutionError::InsufficientFunds {
                inputs: input_sum,
                outputs_plus_fee,
            });
        }

        // 7. Apply state changes — consume input UTXOs (double-spend prevention)
        let tx_delta = self
            .utxo_set
            .apply_transaction(&tx)
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
                    return Err(TxExecutionError::StructuralInvalid(format!(
                        "SystemEmission output[{}]: address {} does not match \
                             commit leader address {}",
                        idx,
                        hex::encode(&output.address[..8]),
                        hex::encode(&expected_addr[..8]),
                    )));
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
            total = total
                .checked_add(output.amount)
                .ok_or(TxExecutionError::AmountOverflow)?;
        }
        if total > PHASE2_MAX_COINBASE_PER_BLOCK {
            return Err(TxExecutionError::CoinbaseExceedsCap);
        }

        // SEC-FIX: Enforce total supply cap (MAX_TOTAL_SUPPLY).
        // Previously only per-block cap existed; SupplyTracker had max_supply
        // but was not connected to the execution layer.
        let new_total = self
            .total_emitted
            .checked_add(total)
            .ok_or(TxExecutionError::AmountOverflow)?;
        if new_total > MAX_TOTAL_SUPPLY {
            return Err(TxExecutionError::StructuralInvalid(format!(
                "SystemEmission would exceed MAX_TOTAL_SUPPLY: emitted {} + new {} > cap {}",
                self.total_emitted, total, MAX_TOTAL_SUPPLY
            )));
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
                .map_err(|e| {
                    TxExecutionError::StructuralInvalid(format!(
                        "SystemEmission output add failed: {}",
                        e
                    ))
                })?;
            if let Some(ref spk) = output.spending_pubkey {
                let _ = self
                    .utxo_set
                    .register_spending_key(outref.clone(), spk.clone());
            }
            delta.created.push(outref);
        }
        Ok(0)
    }

    /// Validate a Faucet transaction (testnet coin distribution).
    ///
    /// Similar to SystemEmission but without leader address verification,
    /// since Faucet outputs go to the requesting user, not the block proposer.
    fn validate_faucet_tx(
        &mut self,
        tx: &UtxoTransaction,
        delta: &mut BlockDelta,
    ) -> Result<u64, TxExecutionError> {
        if !tx.inputs.is_empty() {
            return Err(TxExecutionError::StructuralInvalid(
                "Faucet tx must have no inputs".into(),
            ));
        }

        Self::validate_output_pubkey_binding(&tx.outputs)?;

        let mut total: u64 = 0;
        for output in &tx.outputs {
            total = total
                .checked_add(output.amount)
                .ok_or(TxExecutionError::AmountOverflow)?;
        }
        if total > MAX_FAUCET_DRIP_AMOUNT {
            return Err(TxExecutionError::CoinbaseExceedsCap);
        }

        let new_total = self
            .total_emitted
            .checked_add(total)
            .ok_or(TxExecutionError::AmountOverflow)?;
        if new_total > MAX_TOTAL_SUPPLY {
            return Err(TxExecutionError::StructuralInvalid(format!(
                "Faucet would exceed MAX_TOTAL_SUPPLY: emitted {} + new {} > cap {}",
                self.total_emitted, total, MAX_TOTAL_SUPPLY
            )));
        }
        self.total_emitted = new_total;

        let tx_hash = tx.tx_hash();
        for (idx, output) in tx.outputs.iter().enumerate() {
            let outref = OutputRef {
                tx_hash,
                output_index: idx as u32,
            };
            self.utxo_set
                .add_output(outref.clone(), output.clone(), self.height, false)
                .map_err(|e| {
                    TxExecutionError::StructuralInvalid(format!("Faucet output add failed: {}", e))
                })?;
            if let Some(ref spk) = output.spending_pubkey {
                let _ = self
                    .utxo_set
                    .register_spending_key(outref.clone(), spk.clone());
            }
            delta.created.push(outref);
        }
        Ok(0)
    }

    /// Audit #10: Validate P2PKH output binding.
    /// For each output with spending_pubkey, enforce:
    ///   address == SHA3-256("MISAKA:address:v1:" || spending_pubkey)
    /// This is the canonical tagged-hash address derivation used by wallets.
    fn validate_output_pubkey_binding(outputs: &[TxOutput]) -> Result<(), TxExecutionError> {
        use sha3::{Digest, Sha3_256};
        for (idx, output) in outputs.iter().enumerate() {
            if let Some(ref spk) = output.spending_pubkey {
                let expected_addr: [u8; 32] = {
                    let mut h = Sha3_256::new();
                    h.update(b"MISAKA:address:v1:");
                    h.update(spk);
                    h.finalize().into()
                };
                if output.address != expected_addr {
                    return Err(TxExecutionError::OutputPubkeyBindingFailed { output_index: idx });
                }
            }
        }
        Ok(())
    }

    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn utxo_count(&self) -> usize {
        self.utxo_set.len()
    }
    pub fn utxo_set(&self) -> &UtxoSet {
        &self.utxo_set
    }
    /// Mutable accessor into the underlying `UtxoSet`.
    ///
    /// Used in two narrowly-scoped places:
    /// - Phase 10 test modules that seed inputs before
    ///   `execute_committed` is driven.
    /// - Option C (v0.9.0-dev) fresh-start UTXO seeding from the
    ///   genesis manifest's `[initial_utxos] source` file.
    ///
    /// Production code paths other than these MUST NOT call this; they
    /// go through `execute_committed` so the state stays consistent
    /// with the block chain and the deltas are captured for rollback.
    pub fn utxo_set_mut(&mut self) -> &mut UtxoSet {
        &mut self.utxo_set
    }
    pub fn app_id(&self) -> &AppId {
        &self.app_id
    }

    /// Phase 3 C7: Return the current state root (MuHash of UTXO set).
    pub fn state_root(&self) -> [u8; 32] {
        self.utxo_set.compute_state_root()
    }

    /// v1.0 hard-fork parallel SMT: return the v4 state root (SMT
    /// root wrapped under the `"MISAKA:state_root:v4:"` domain tag
    /// + height). Runs alongside [`Self::state_root`] during the
    /// migration window; consensus does not consume this value
    /// pre-activation. At the v1.0 activation epoch (Step 7 of the
    /// migration plan), the canonical comparison on the commit
    /// path shifts from `state_root` to this value.
    ///
    /// Observability: callers that want to log/compare both
    /// commitments today can read both via `state_root()` and
    /// `state_root_v4()` without touching the hot path.
    pub fn state_root_v4(&self) -> [u8; 32] {
        self.utxo_set.compute_state_root_v4()
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
        if let Err(e) = self
            .utxo_set
            .add_output(outref.clone(), output, self.height, true)
        {
            tracing::error!("Failed to create block reward UTXO: {}", e);
            return 0;
        }
        // Register spending key if provided
        if let Some(spk) = self
            .utxo_set
            .get(&outref)
            .and_then(|e| e.output.spending_pubkey.clone())
        {
            let _ = self.utxo_set.register_spending_key(outref, spk);
        }
        self.total_emitted = new_total;
        tracing::debug!(
            "Block reward: {} base units to {} (total_emitted={})",
            reward,
            hex::encode(&leader_address[..8]),
            new_total
        );
        reward
    }

    /// γ-5: Apply the UTXO-side effects of `StakingRegistry::settle_unlocks`.
    ///
    /// For each `(validator_id, amount, reward_address)` tuple produced by
    /// the registry at an epoch boundary:
    /// 1. Remove the corresponding entry from `staked_receipt_table` (the
    ///    locked receipt marker written by `apply_stake_deposit` on Register).
    /// 2. Materialize a new transparent UTXO at `reward_address` carrying the
    ///    full `amount`. This uses the same direct-write pattern as
    ///    `generate_block_reward` (Pattern B): no `UtxoTransaction` is
    ///    constructed, so mempool / admission / tx-type dispatch are
    ///    unaffected. The output's synthetic `tx_hash` is
    ///    `SHA3-256("MISAKA:stake_unlock:" || epoch_le || validator_id)`,
    ///    which is deterministic and collision-resistant across validators.
    ///
    /// `is_emission` on the created output is **false** — unbonding is
    /// stake re-circulation, not new supply. `total_emitted` is NOT bumped.
    ///
    /// `reward_address == [0u8; 32]` is treated as "skip + warn" rather
    /// than an error so a single mis-registered validator cannot freeze the
    /// epoch boundary; the registry-side unlock has already happened, and
    /// funds for that validator are considered lost. `register_l1_native`
    /// is expected to reject zero reward_address at registration time,
    /// making this branch a belt-and-braces check.
    ///
    /// Idempotency: calling this with `settled == &[]` is a no-op. Calling
    /// again with the same list would try to add the same OutputRef a
    /// second time and `UtxoSet::add_output` would return
    /// `OutputAlreadyExists`; we surface that as a `warn!` rather than
    /// bubbling an error, matching `generate_block_reward`'s tolerance.
    pub fn apply_settled_unlocks(&mut self, settled: &[([u8; 32], u64, [u8; 32])], epoch: u64) {
        for (validator_id, amount, reward_address) in settled {
            if *reward_address == [0u8; 32] {
                warn!(
                    "γ-5 apply_settled_unlocks: skip validator {} — zero reward_address",
                    hex::encode(&validator_id[..8])
                );
                continue;
            }

            // 1. Reverse-lookup + remove the staked-receipt entry for this
            //    validator. staked_receipt_table is keyed by OutputRef and
            //    valued by validator_id, so we must scan for the matching
            //    value. In practice there is at most one entry per live
            //    validator (Register writes exactly one, StakeMore does not
            //    touch the table), so the linear scan is trivially cheap.
            let receipt_ref = self
                .staked_receipt_table
                .iter()
                .find(|(_, vid)| *vid == validator_id)
                .map(|(k, _)| k.clone());
            if let Some(oref) = receipt_ref.as_ref() {
                self.staked_receipt_table.remove(oref);
            } else {
                // Not fatal — a validator that registered via the Solana
                // path (β-3) and then exited via BeginExit would have no
                // L1 receipt to remove. Log for traceability.
                tracing::info!(
                    "γ-5 apply_settled_unlocks: no staked receipt for {} (solana-path exit?)",
                    hex::encode(&validator_id[..8])
                );
            }

            // 2. Synthetic tx_hash bound to (epoch, validator_id).
            let tx_hash = {
                use sha3::{Digest, Sha3_256};
                let mut h = Sha3_256::new();
                h.update(b"MISAKA:stake_unlock:");
                h.update(epoch.to_le_bytes());
                h.update(validator_id);
                let r: [u8; 32] = h.finalize().into();
                r
            };
            let outref = OutputRef {
                tx_hash,
                output_index: 0,
            };
            let output = TxOutput {
                amount: *amount,
                address: *reward_address,
                // spending_pubkey is left None; the receiver will supply it
                // in the input of a future TransparentTransfer that spends
                // this UTXO, same as any transparent-model output.
                spending_pubkey: None,
            };

            match self.utxo_set.add_output(
                outref.clone(),
                output,
                self.height,
                /* is_emission = */ false,
            ) {
                Ok(()) => {
                    info!(
                        "γ-5 apply_settled_unlocks: created unlock UTXO tx={} amount={} to={} (validator={})",
                        hex::encode(&tx_hash[..8]),
                        amount,
                        hex::encode(&reward_address[..8]),
                        hex::encode(&validator_id[..8]),
                    );
                }
                Err(e) => {
                    warn!(
                        "γ-5 apply_settled_unlocks: add_output failed for validator {}: {}",
                        hex::encode(&validator_id[..8]),
                        e
                    );
                }
            }
        }
    }

    /// Phase 3 C5: Check burn replay protection.
    ///
    /// Returns Ok(()) if the burn_id has not been processed before,
    /// inserting it into the processed set.
    /// Returns Err(BurnAlreadyProcessed) if the burn_id was already seen.
    pub fn check_burn_replay(&mut self, burn_id: [u8; 32]) -> Result<(), TxExecutionError> {
        if !self.processed_burns.insert(burn_id) {
            return Err(TxExecutionError::BurnAlreadyProcessed(hex::encode(
                &burn_id[..8],
            )));
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
#[allow(clippy::expect_used, clippy::unwrap_used, deprecated)]
mod tests {
    use super::*;
    use misaka_consensus::staking::{StakingConfig, StakingRegistry};
    use misaka_crypto::validator_sig::ValidatorPqPublicKey;
    use misaka_pqc::pq_sign::{ml_dsa_sign_raw, MlDsaKeypair};
    use misaka_types::utxo::{TxInput, UtxoTransaction, UTXO_TX_VERSION};
    use misaka_types::validator_stake_tx::{
        RegisterParams, StakeInput, StakeMoreParams, StakeTxKind, StakeTxParams, ValidatorStakeTx,
    };

    fn test_app_id() -> AppId {
        AppId::new(2, [0u8; 32])
    }

    #[test]
    fn empty_commit_succeeds() {
        let mut executor = UtxoExecutor::new(test_app_id());
        executor.enable_on_chain_staking_for_tests(0);
        let result = executor.execute_committed(1, &[], None, None, 0);
        assert_eq!(result.txs_accepted, 0);
        assert_eq!(result.txs_rejected, 0);
    }

    #[test]
    fn malformed_borsh_gracefully_rejected() {
        let mut executor = UtxoExecutor::new(test_app_id());
        executor.enable_on_chain_staking_for_tests(0);
        let result = executor.execute_committed(1, &[b"not valid borsh".to_vec()], None, None, 0);
        // Must NOT panic — graceful rejection
        assert_eq!(result.txs_accepted, 0);
        assert_eq!(result.txs_rejected, 1);
    }

    // ─── γ-3: stake tx dispatch tests ─────────────────────────────────

    /// Build a tiny StakingConfig with a near-zero min_validator_stake so
    /// the compact fixtures (stake_amount = 10_000) register cleanly.
    fn test_staking_config() -> StakingConfig {
        StakingConfig {
            min_validator_stake: 1_000,
            min_uptime_bps: 0,
            min_score: 0,
            ..StakingConfig::testnet()
        }
    }

    fn sign_stake_tx(mut tx: ValidatorStakeTx, kp: &MlDsaKeypair) -> ValidatorStakeTx {
        tx.signature = vec![];
        let payload = tx.signing_payload();
        let sig = ml_dsa_sign_raw(&kp.secret_key, &payload).expect("sign");
        tx.signature = sig.as_bytes().to_vec();
        tx
    }

    /// γ-3.2: UTXO reference used as `tx.inputs[0]` in the stake-deposit
    /// test fixture. Must be pre-seeded into the executor's UTXO set via
    /// `seed_input_utxo` before running.
    fn stake_deposit_input_ref() -> OutputRef {
        OutputRef {
            tx_hash: [0xFFu8; 32],
            output_index: 0,
        }
    }

    fn stake_withdraw_input_ref() -> OutputRef {
        OutputRef {
            tx_hash: [0xEEu8; 32],
            output_index: 0,
        }
    }

    /// γ-3.2: seed a UTXO at the given OutputRef into the executor's UTXO
    /// set so stake-tx `inputs[*]` resolve. The seeded UTXO is a transparent
    /// output of `amount` to a dummy address; tests that spend it via a
    /// real TransparentTransfer need to also set `spending_pubkey` accordingly.
    fn seed_input_utxo(executor: &mut UtxoExecutor, outref: OutputRef, amount: u64) {
        executor
            .utxo_set
            .add_output(
                outref,
                TxOutput {
                    amount,
                    address: [0x77; 32],
                    spending_pubkey: None,
                },
                0, // created_at
                false,
            )
            .expect("seed input utxo");
    }

    fn build_stake_deposit_tx(stake_tx: ValidatorStakeTx) -> UtxoTransaction {
        let extra = stake_tx.encode_for_extra().expect("encode envelope");
        UtxoTransaction {
            version: UTXO_TX_VERSION,
            tx_type: TxType::StakeDeposit,
            inputs: vec![TxInput {
                utxo_refs: vec![stake_deposit_input_ref()],
                proof: vec![0xAA; 16],
            }],
            outputs: vec![TxOutput {
                amount: 0,
                address: [0x11; 32],
                spending_pubkey: None,
            }],
            fee: 1_000,
            extra,
            expiry: 0,
        }
    }

    /// γ-3.2: StakeDeposit with an extra change output (outputs[1]) so we
    /// can verify change goes into the UTXO set while outputs[0] (receipt
    /// marker) does not.
    fn build_stake_deposit_tx_with_change(
        stake_tx: ValidatorStakeTx,
        change_amount: u64,
    ) -> UtxoTransaction {
        let mut tx = build_stake_deposit_tx(stake_tx);
        tx.outputs.push(TxOutput {
            amount: change_amount,
            address: [0x88; 32],
            spending_pubkey: None,
        });
        tx
    }

    fn build_stake_withdraw_tx(stake_tx: ValidatorStakeTx) -> UtxoTransaction {
        let extra = stake_tx.encode_for_extra().expect("encode envelope");
        UtxoTransaction {
            version: UTXO_TX_VERSION,
            tx_type: TxType::StakeWithdraw,
            inputs: vec![TxInput {
                utxo_refs: vec![stake_withdraw_input_ref()],
                proof: vec![0xBB; 16],
            }],
            outputs: vec![TxOutput {
                amount: 0,
                address: [0x22; 32],
                spending_pubkey: None,
            }],
            fee: 1_000,
            extra,
            expiry: 0,
        }
    }

    fn make_register_envelope(kp: &MlDsaKeypair, validator_id: [u8; 32]) -> ValidatorStakeTx {
        let tx = ValidatorStakeTx {
            kind: StakeTxKind::Register,
            validator_id,
            stake_inputs: vec![StakeInput {
                tx_hash: [0xABu8; 32],
                output_index: 0,
                amount: 11_000,
            }],
            fee: 1_000,
            nonce: 0,
            memo: None,
            params: StakeTxParams::Register(RegisterParams {
                consensus_pubkey: kp.public_key.as_bytes().to_vec(),
                reward_address: [2u8; 32],
                commission_bps: 500,
                p2p_endpoint: Some("1.2.3.4:30333".into()),
                moniker: None,
            }),
            signature: vec![],
        };
        sign_stake_tx(tx, kp)
    }

    fn make_stake_more_envelope(
        kp: &MlDsaKeypair,
        validator_id: [u8; 32],
        additional: u64,
    ) -> ValidatorStakeTx {
        let tx = ValidatorStakeTx {
            kind: StakeTxKind::StakeMore,
            validator_id,
            stake_inputs: vec![StakeInput {
                tx_hash: [0xCDu8; 32],
                output_index: 0,
                amount: additional + 1_000,
            }],
            fee: 1_000,
            nonce: 1,
            memo: None,
            params: StakeTxParams::StakeMore(StakeMoreParams {
                additional_amount: additional,
            }),
            signature: vec![],
        };
        sign_stake_tx(tx, kp)
    }

    fn make_begin_exit_envelope(kp: &MlDsaKeypair, validator_id: [u8; 32]) -> ValidatorStakeTx {
        let tx = ValidatorStakeTx {
            kind: StakeTxKind::BeginExit,
            validator_id,
            stake_inputs: vec![],
            fee: 1_000,
            nonce: 2,
            memo: None,
            params: StakeTxParams::BeginExit,
            signature: vec![],
        };
        sign_stake_tx(tx, kp)
    }

    fn validator_id_from_kp(kp: &MlDsaKeypair) -> [u8; 32] {
        ValidatorPqPublicKey::from_bytes(kp.public_key.as_bytes())
            .unwrap()
            .to_canonical_id()
    }

    #[test]
    fn test_apply_stake_deposit_register_ok() {
        let kp = MlDsaKeypair::generate();
        let vid = validator_id_from_kp(&kp);
        let envelope = make_register_envelope(&kp, vid);
        let tx = build_stake_deposit_tx(envelope);
        let raw = borsh::to_vec(&tx).expect("borsh encode tx");

        let mut executor = UtxoExecutor::new(test_app_id());
        executor.enable_on_chain_staking_for_tests(0);
        seed_input_utxo(&mut executor, stake_deposit_input_ref(), 11_000);
        let mut registry = StakingRegistry::new(test_staking_config());
        let result = executor.execute_committed(1, &[raw], None, Some(&mut registry), 0);
        assert_eq!(result.txs_accepted, 1, "register must be accepted");
        assert_eq!(result.txs_rejected, 0);

        // Registry: validator now LOCKED with l1_stake_verified=true
        let account = registry.get(&vid).expect("registered");
        assert_eq!(account.stake_amount, 10_000); // 11_000 input - 1_000 fee
        assert!(account.l1_stake_verified);
        assert!(!account.solana_stake_verified);

        // activate() must succeed (γ-3 OR gate)
        registry
            .activate(&vid, 1)
            .expect("activate with only l1_stake_verified");

        // Staked receipt inserted (outputs[0] of this tx)
        let expected_ref = OutputRef {
            tx_hash: tx.tx_hash(),
            output_index: 0,
        };
        assert_eq!(
            executor.staked_receipt_table().get(&expected_ref),
            Some(&vid),
        );
    }

    #[test]
    fn test_apply_stake_deposit_stake_more_ok() {
        let kp = MlDsaKeypair::generate();
        let vid = validator_id_from_kp(&kp);
        // Step 1: Register
        let reg_tx = build_stake_deposit_tx(make_register_envelope(&kp, vid));
        let reg_raw = borsh::to_vec(&reg_tx).unwrap();
        // Step 2: StakeMore (reuses the same `[0xFF]` input ref — we reseed
        // after the first commit consumes it.
        let sm_tx = build_stake_deposit_tx(make_stake_more_envelope(&kp, vid, 5_000));
        let sm_raw = borsh::to_vec(&sm_tx).unwrap();

        let mut executor = UtxoExecutor::new(test_app_id());
        executor.enable_on_chain_staking_for_tests(0);
        let mut registry = StakingRegistry::new(test_staking_config());
        seed_input_utxo(&mut executor, stake_deposit_input_ref(), 11_000);
        let r1 = executor.execute_committed(1, &[reg_raw], None, Some(&mut registry), 0);
        assert_eq!(r1.txs_accepted, 1);
        // Re-seed the input UTXO (previous commit consumed it) for the
        // StakeMore tx.
        seed_input_utxo(&mut executor, stake_deposit_input_ref(), 6_000);
        let r2 = executor.execute_committed(2, &[sm_raw], None, Some(&mut registry), 0);
        assert_eq!(r2.txs_accepted, 1, "stake_more must be accepted");
        let account = registry.get(&vid).expect("present");
        assert_eq!(account.stake_amount, 15_000, "10_000 + 5_000");
    }

    #[test]
    fn test_apply_stake_withdraw_begin_exit_ok() {
        let kp = MlDsaKeypair::generate();
        let vid = validator_id_from_kp(&kp);
        // Register + activate first
        let reg_tx = build_stake_deposit_tx(make_register_envelope(&kp, vid));
        let reg_raw = borsh::to_vec(&reg_tx).unwrap();
        let exit_tx = build_stake_withdraw_tx(make_begin_exit_envelope(&kp, vid));
        let exit_raw = borsh::to_vec(&exit_tx).unwrap();

        let mut executor = UtxoExecutor::new(test_app_id());
        executor.enable_on_chain_staking_for_tests(0);
        let mut registry = StakingRegistry::new(test_staking_config());
        seed_input_utxo(&mut executor, stake_deposit_input_ref(), 11_000);
        seed_input_utxo(&mut executor, stake_withdraw_input_ref(), 2_000);
        executor.execute_committed(1, &[reg_raw], None, Some(&mut registry), 0);
        registry.activate(&vid, 1).expect("activate");
        let r = executor.execute_committed(2, &[exit_raw], None, Some(&mut registry), 2);
        assert_eq!(r.txs_accepted, 1, "begin_exit must be accepted");
        let account = registry.get(&vid).expect("present");
        assert!(
            matches!(
                account.state,
                misaka_consensus::staking::ValidatorState::Exiting { .. }
            ),
            "state must be Exiting after begin_exit, got {:?}",
            account.state,
        );
    }

    #[test]
    fn test_apply_stake_deposit_replay_rejected() {
        let kp = MlDsaKeypair::generate();
        let vid = validator_id_from_kp(&kp);
        let envelope = make_register_envelope(&kp, vid);
        let tx = build_stake_deposit_tx(envelope);
        let raw = borsh::to_vec(&tx).unwrap();

        let mut executor = UtxoExecutor::new(test_app_id());
        executor.enable_on_chain_staking_for_tests(0);
        let mut registry = StakingRegistry::new(test_staking_config());
        seed_input_utxo(&mut executor, stake_deposit_input_ref(), 11_000);
        let r1 = executor.execute_committed(1, &[raw.clone()], None, Some(&mut registry), 0);
        assert_eq!(r1.txs_accepted, 1);
        // Re-seed input for the replay attempt. The registry should still
        // reject the tx on `StakeSignatureAlreadyUsed` even though the UTXO
        // path would succeed — i.e. replay protection kicks in BEFORE we
        // touch the UTXO set.
        seed_input_utxo(&mut executor, stake_deposit_input_ref(), 11_000);
        let r2 = executor.execute_committed(2, &[raw], None, Some(&mut registry), 0);
        assert_eq!(r2.txs_accepted, 0);
        assert_eq!(r2.txs_rejected, 1, "replay must be rejected");
    }

    #[test]
    fn test_stake_tx_without_registry_rejected() {
        // γ-3 design: when the caller hasn't wired a StakingRegistry, the
        // executor must gracefully reject stake txs (not panic, not leak).
        let kp = MlDsaKeypair::generate();
        let vid = validator_id_from_kp(&kp);
        let tx = build_stake_deposit_tx(make_register_envelope(&kp, vid));
        let raw = borsh::to_vec(&tx).unwrap();

        let mut executor = UtxoExecutor::new(test_app_id());
        executor.enable_on_chain_staking_for_tests(0);
        let result = executor.execute_committed(1, &[raw], None, None, 0);
        assert_eq!(result.txs_accepted, 0);
        assert_eq!(result.txs_rejected, 1);
    }

    // ─── γ-3.2: UTXO consumption tests ────────────────────────────────

    #[test]
    fn test_apply_stake_deposit_consumes_inputs() {
        let kp = MlDsaKeypair::generate();
        let vid = validator_id_from_kp(&kp);
        let tx = build_stake_deposit_tx(make_register_envelope(&kp, vid));
        let raw = borsh::to_vec(&tx).unwrap();
        let mut executor = UtxoExecutor::new(test_app_id());
        executor.enable_on_chain_staking_for_tests(0);
        let mut registry = StakingRegistry::new(test_staking_config());
        let input_ref = stake_deposit_input_ref();
        seed_input_utxo(&mut executor, input_ref.clone(), 11_000);
        // Pre-condition: input is present.
        assert!(executor.utxo_set.get(&input_ref).is_some());
        let r = executor.execute_committed(1, &[raw], None, Some(&mut registry), 0);
        assert_eq!(r.txs_accepted, 1);
        // Post-condition: input removed from the UTXO set.
        assert!(
            executor.utxo_set.get(&input_ref).is_none(),
            "stake_deposit must consume its inputs (γ-3.2)",
        );
    }

    #[test]
    fn test_apply_stake_deposit_change_outputs_in_utxo_set() {
        let kp = MlDsaKeypair::generate();
        let vid = validator_id_from_kp(&kp);
        let tx = build_stake_deposit_tx_with_change(
            make_register_envelope(&kp, vid),
            3_000, // change amount
        );
        let raw = borsh::to_vec(&tx).unwrap();
        let tx_hash = tx.tx_hash();
        let mut executor = UtxoExecutor::new(test_app_id());
        executor.enable_on_chain_staking_for_tests(0);
        let mut registry = StakingRegistry::new(test_staking_config());
        seed_input_utxo(&mut executor, stake_deposit_input_ref(), 14_000);
        let r = executor.execute_committed(1, &[raw], None, Some(&mut registry), 0);
        assert_eq!(r.txs_accepted, 1);
        // outputs[1] (change) must be in the UTXO set
        let change_ref = OutputRef {
            tx_hash,
            output_index: 1,
        };
        assert!(
            executor.utxo_set.get(&change_ref).is_some(),
            "outputs[1] change must be added to UTXO set",
        );
        // outputs[0] (receipt marker) must NOT be in the UTXO set
        let receipt_ref = OutputRef {
            tx_hash,
            output_index: 0,
        };
        assert!(
            executor.utxo_set.get(&receipt_ref).is_none(),
            "outputs[0] receipt marker must NOT leak into UTXO set",
        );
        // receipt marker is in staked_receipt_table instead
        assert_eq!(
            executor.staked_receipt_table().get(&receipt_ref),
            Some(&vid),
        );
    }

    #[test]
    fn test_stake_input_double_spend_rejected() {
        // Scenario: a stake tx references an input UTXO that is NOT in the
        // UTXO set (already spent by an earlier, unrelated tx in the same
        // batch / history). The executor must reject with UtxoNotFound
        // rather than silently proceeding.
        let kp = MlDsaKeypair::generate();
        let vid = validator_id_from_kp(&kp);
        let tx = build_stake_deposit_tx(make_register_envelope(&kp, vid));
        let raw = borsh::to_vec(&tx).unwrap();
        let mut executor = UtxoExecutor::new(test_app_id());
        executor.enable_on_chain_staking_for_tests(0);
        let mut registry = StakingRegistry::new(test_staking_config());
        // Do NOT seed the input; simulates the UTXO having been spent earlier.
        let r = executor.execute_committed(1, &[raw], None, Some(&mut registry), 0);
        assert_eq!(r.txs_accepted, 0);
        assert_eq!(
            r.txs_rejected, 1,
            "stake tx with unknown input must be rejected"
        );
        // Registry must NOT have been mutated
        assert!(
            registry.get(&vid).is_none(),
            "failed stake tx must not leave a partial registry entry",
        );
    }

    #[test]
    fn test_transparent_transfer_cannot_spend_staked_input() {
        // Inverse of the above: once a stake tx consumes an input, the same
        // input cannot be respent by a later TransparentTransfer (or any
        // other tx type). We exercise the property by applying the stake tx
        // first, then observing that the UTXO set no longer contains the
        // input and a second apply with the same input ref fails.
        let kp = MlDsaKeypair::generate();
        let vid = validator_id_from_kp(&kp);
        let tx = build_stake_deposit_tx(make_register_envelope(&kp, vid));
        let raw = borsh::to_vec(&tx).unwrap();
        let input_ref = stake_deposit_input_ref();
        let mut executor = UtxoExecutor::new(test_app_id());
        executor.enable_on_chain_staking_for_tests(0);
        let mut registry = StakingRegistry::new(test_staking_config());
        seed_input_utxo(&mut executor, input_ref.clone(), 11_000);
        let r1 = executor.execute_committed(1, &[raw], None, Some(&mut registry), 0);
        assert_eq!(r1.txs_accepted, 1);
        // UTXO is gone.
        assert!(executor.utxo_set.get(&input_ref).is_none());
        // A second attempt to apply a stake tx against the same (now-missing)
        // input MUST fail with UtxoNotFound — this is the exact path a
        // transparent transfer would take since both flows enforce input
        // presence in the UTXO set.
        let kp2 = MlDsaKeypair::generate();
        let vid2 = validator_id_from_kp(&kp2);
        let tx2 = build_stake_deposit_tx(make_register_envelope(&kp2, vid2));
        let raw2 = borsh::to_vec(&tx2).unwrap();
        // Input was consumed by the first tx — deliberately DO NOT re-seed.
        let r2 = executor.execute_committed(2, &[raw2], None, Some(&mut registry), 0);
        assert_eq!(
            r2.txs_rejected, 1,
            "tx spending an already-staked input must be rejected",
        );
    }

    // ─── γ-3.3: BlockDelta bookkeeping tests ──────────────────────────
    //
    // These tests call `validate_and_apply_tx` directly (private, accessible
    // from within the same module) so they can inspect the `BlockDelta`
    // produced by a single tx in isolation. `execute_committed` wraps
    // `validate_and_apply_tx` and does NOT expose the resulting delta
    // directly, so direct-dispatch is the cleanest test seam.

    fn run_single_tx_for_delta(
        executor: &mut UtxoExecutor,
        registry: &mut StakingRegistry,
        raw: &[u8],
    ) -> (Result<u64, TxExecutionError>, BlockDelta) {
        // Mirror the bookkeeping execute_committed does around
        // validate_and_apply_tx — bump height + delta.height so add_output's
        // created_at stamp matches production semantics.
        executor.height += 1;
        executor.utxo_set.height = executor.height;
        let mut delta = BlockDelta::new(executor.height);
        let mut emission_count = 0usize;
        let result = executor.validate_and_apply_tx(
            raw,
            &mut delta,
            &mut emission_count,
            None,
            Some(registry),
            /* current_epoch = */ 0,
        );
        (result, delta)
    }

    #[test]
    fn test_stake_deposit_delta_spent_populated() {
        let kp = MlDsaKeypair::generate();
        let vid = validator_id_from_kp(&kp);
        let tx = build_stake_deposit_tx(make_register_envelope(&kp, vid));
        let raw = borsh::to_vec(&tx).unwrap();
        let mut executor = UtxoExecutor::new(test_app_id());
        executor.enable_on_chain_staking_for_tests(0);
        let mut registry = StakingRegistry::new(test_staking_config());
        let input_ref = stake_deposit_input_ref();
        seed_input_utxo(&mut executor, input_ref.clone(), 11_000);

        let (result, delta) = run_single_tx_for_delta(&mut executor, &mut registry, &raw);
        result.expect("apply ok");
        // delta.spent[0] shape: (tx_hash, OutputRef, TxOutput) — matches
        // the `UtxoSet::apply_transaction` convention used by TransparentTransfer.
        assert_eq!(delta.spent.len(), 1, "exactly one input should be spent",);
        assert_eq!(delta.spent[0].0, input_ref.tx_hash);
        assert_eq!(delta.spent[0].1, input_ref);
    }

    #[test]
    fn test_stake_deposit_delta_created_skips_receipt_marker() {
        let kp = MlDsaKeypair::generate();
        let vid = validator_id_from_kp(&kp);
        let tx = build_stake_deposit_tx_with_change(make_register_envelope(&kp, vid), 3_000);
        let raw = borsh::to_vec(&tx).unwrap();
        let tx_hash = tx.tx_hash();
        let mut executor = UtxoExecutor::new(test_app_id());
        executor.enable_on_chain_staking_for_tests(0);
        let mut registry = StakingRegistry::new(test_staking_config());
        seed_input_utxo(&mut executor, stake_deposit_input_ref(), 14_000);

        let (result, delta) = run_single_tx_for_delta(&mut executor, &mut registry, &raw);
        result.expect("apply ok");
        // outputs[0] is the receipt marker — must NOT appear in delta.created.
        // outputs[1] is the change — must appear exactly once.
        assert_eq!(
            delta.created.len(),
            1,
            "change output recorded, receipt marker skipped",
        );
        assert_eq!(
            delta.created[0],
            OutputRef {
                tx_hash,
                output_index: 1,
            },
            "delta.created[0] must reference outputs[1] (change), not outputs[0] (receipt)",
        );
        let receipt_ref = OutputRef {
            tx_hash,
            output_index: 0,
        };
        assert!(
            !delta.created.contains(&receipt_ref),
            "receipt marker (outputs[0]) must not leak into delta.created",
        );
    }

    #[test]
    fn test_stake_withdraw_delta_populated() {
        // Register + activate first so BeginExit verifies cleanly.
        let kp = MlDsaKeypair::generate();
        let vid = validator_id_from_kp(&kp);
        let reg_tx = build_stake_deposit_tx(make_register_envelope(&kp, vid));
        let reg_raw = borsh::to_vec(&reg_tx).unwrap();
        let exit_tx = build_stake_withdraw_tx(make_begin_exit_envelope(&kp, vid));
        let exit_raw = borsh::to_vec(&exit_tx).unwrap();
        let exit_tx_hash = exit_tx.tx_hash();

        let mut executor = UtxoExecutor::new(test_app_id());
        executor.enable_on_chain_staking_for_tests(0);
        let mut registry = StakingRegistry::new(test_staking_config());
        seed_input_utxo(&mut executor, stake_deposit_input_ref(), 11_000);
        seed_input_utxo(&mut executor, stake_withdraw_input_ref(), 2_000);
        executor.execute_committed(1, &[reg_raw], None, Some(&mut registry), 0);
        registry.activate(&vid, 1).expect("activate");

        let (result, delta) = run_single_tx_for_delta(&mut executor, &mut registry, &exit_raw);
        result.expect("begin_exit ok");
        assert_eq!(
            delta.spent.len(),
            1,
            "BeginExit fee input recorded in delta.spent",
        );
        assert_eq!(delta.spent[0].1, stake_withdraw_input_ref());
        // BeginExit has no receipt marker to skip → every output goes into
        // delta.created. The fixture has 1 output (change).
        assert_eq!(
            delta.created.len(),
            1,
            "BeginExit single output recorded in delta.created",
        );
        assert_eq!(
            delta.created[0],
            OutputRef {
                tx_hash: exit_tx_hash,
                output_index: 0,
            },
        );
    }

    #[test]
    fn test_stake_tx_delta_shape_matches_transparent_transfer() {
        // Invariant proof: delta.spent for stake tx uses the same
        // (tx_hash, OutputRef, TxOutput) tuple shape as
        // `UtxoSet::apply_transaction` does for TransparentTransfer. This
        // keeps `undo_last_delta` (SPC switch / shallow rollback) working
        // consistently for every tx type.
        let kp = MlDsaKeypair::generate();
        let vid = validator_id_from_kp(&kp);
        let tx = build_stake_deposit_tx(make_register_envelope(&kp, vid));
        let raw = borsh::to_vec(&tx).unwrap();
        let input_ref = stake_deposit_input_ref();
        let mut executor = UtxoExecutor::new(test_app_id());
        executor.enable_on_chain_staking_for_tests(0);
        let mut registry = StakingRegistry::new(test_staking_config());
        seed_input_utxo(&mut executor, input_ref.clone(), 11_000);

        let (_result, delta) = run_single_tx_for_delta(&mut executor, &mut registry, &raw);
        // spent[0] is (tx_hash, OutputRef, TxOutput). Verify each position.
        let spent = delta.spent.first().expect("one spent entry");
        assert_eq!(spent.0, input_ref.tx_hash, "spent.0 == input_ref.tx_hash");
        assert_eq!(spent.1, input_ref, "spent.1 == full OutputRef");
        // spent.2 is TxOutput — we seeded amount=11_000 above.
        assert_eq!(
            spent.2.amount, 11_000,
            "spent.2 carries the original TxOutput"
        );
    }

    // ─── Group 1: feature-gate tests ──────────────────────────────────
    //
    // These tests deliberately do NOT call
    // `enable_on_chain_staking_for_tests`, so they exercise the production
    // code path where `FEATURE_ACTIVATIONS` still has `on-chain-staking` at
    // `u64::MAX`.

    #[test]
    fn test_stake_deposit_rejected_when_feature_inactive() {
        let kp = MlDsaKeypair::generate();
        let vid = validator_id_from_kp(&kp);
        let envelope = make_register_envelope(&kp, vid);
        let tx = build_stake_deposit_tx(envelope);
        let raw = borsh::to_vec(&tx).expect("borsh encode tx");

        let mut executor = UtxoExecutor::new(test_app_id());
        // No enable_on_chain_staking_for_tests call — production default.
        seed_input_utxo(&mut executor, stake_deposit_input_ref(), 11_000);
        let mut registry = StakingRegistry::new(test_staking_config());

        let (result, _delta) = run_single_tx_for_delta(&mut executor, &mut registry, &raw);
        match result {
            Err(TxExecutionError::FeatureNotActive { feature, height }) => {
                assert_eq!(feature, "on-chain-staking");
                assert_eq!(height, executor.height);
            }
            other => panic!("expected FeatureNotActive, got {:?}", other),
        }
        // Registry must be left untouched when the gate rejects.
        assert!(
            registry.get(&vid).is_none(),
            "gate must reject before registry mutation"
        );
    }

    #[test]
    fn test_stake_withdraw_rejected_when_feature_inactive() {
        let kp = MlDsaKeypair::generate();
        let vid = validator_id_from_kp(&kp);
        let envelope = make_begin_exit_envelope(&kp, vid);
        // Reuse the withdraw tx builder. `stake_withdraw_input_ref` is the
        // canonical fee-paying UTXO for BeginExit txs in these tests.
        let withdraw_input_ref = stake_withdraw_input_ref();
        let extra = envelope.encode_for_extra().expect("encode envelope");
        let tx = UtxoTransaction {
            version: UTXO_TX_VERSION,
            tx_type: TxType::StakeWithdraw,
            inputs: vec![TxInput {
                utxo_refs: vec![withdraw_input_ref.clone()],
                proof: vec![0xAA; 16],
            }],
            outputs: vec![TxOutput {
                amount: 1_000,
                address: [0x22; 32],
                spending_pubkey: None,
            }],
            fee: 1_000,
            extra,
            expiry: 0,
        };
        let raw = borsh::to_vec(&tx).expect("borsh encode tx");

        let mut executor = UtxoExecutor::new(test_app_id());
        // No enable call — feature stays inactive.
        seed_input_utxo(&mut executor, withdraw_input_ref, 2_000);
        let mut registry = StakingRegistry::new(test_staking_config());

        let (result, _delta) = run_single_tx_for_delta(&mut executor, &mut registry, &raw);
        match result {
            Err(TxExecutionError::FeatureNotActive { feature, .. }) => {
                assert_eq!(feature, "on-chain-staking");
            }
            other => panic!("expected FeatureNotActive, got {:?}", other),
        }
    }

    #[test]
    fn test_stake_deposit_rejected_below_override_activation_height() {
        // Override activation to height=5. Executor starts at height=0 and
        // run_single_tx_for_delta bumps to height=1 — still below threshold.
        let kp = MlDsaKeypair::generate();
        let vid = validator_id_from_kp(&kp);
        let envelope = make_register_envelope(&kp, vid);
        let tx = build_stake_deposit_tx(envelope);
        let raw = borsh::to_vec(&tx).expect("borsh encode tx");

        let mut executor = UtxoExecutor::new(test_app_id());
        executor.enable_on_chain_staking_for_tests(5);
        seed_input_utxo(&mut executor, stake_deposit_input_ref(), 11_000);
        let mut registry = StakingRegistry::new(test_staking_config());

        let (result, _delta) = run_single_tx_for_delta(&mut executor, &mut registry, &raw);
        assert!(
            matches!(
                result,
                Err(TxExecutionError::FeatureNotActive { height: 1, .. })
            ),
            "expected FeatureNotActive at height=1, got {:?}",
            result
        );
    }

    #[test]
    fn test_stake_deposit_accepted_at_override_activation_height() {
        // Override activation to height=1 (the first bump). Must be accepted.
        let kp = MlDsaKeypair::generate();
        let vid = validator_id_from_kp(&kp);
        let envelope = make_register_envelope(&kp, vid);
        let tx = build_stake_deposit_tx(envelope);
        let raw = borsh::to_vec(&tx).expect("borsh encode tx");

        let mut executor = UtxoExecutor::new(test_app_id());
        executor.enable_on_chain_staking_for_tests(1);
        seed_input_utxo(&mut executor, stake_deposit_input_ref(), 11_000);
        let mut registry = StakingRegistry::new(test_staking_config());

        let (result, _delta) = run_single_tx_for_delta(&mut executor, &mut registry, &raw);
        assert!(
            result.is_ok(),
            "expected StakeDeposit accepted at h=1, got {:?}",
            result
        );
        assert!(
            registry.get(&vid).is_some(),
            "registry must have the registered validator"
        );
    }

    // ─── γ-5: apply_settled_unlocks tests ─────────────────────────────

    #[test]
    fn apply_settled_unlocks_creates_reward_utxo_and_drops_receipt() {
        let mut executor = UtxoExecutor::new(test_app_id());
        executor.enable_on_chain_staking_for_tests(0);

        // Pre-populate the staked receipt table as Register would have done
        // — keyed by an arbitrary OutputRef, valued by validator_id.
        let validator_id = [0x42u8; 32];
        let reward_address = [0x77u8; 32];
        let receipt_ref = OutputRef {
            tx_hash: [0x01u8; 32],
            output_index: 0,
        };
        executor
            .staked_receipt_table
            .insert(receipt_ref.clone(), validator_id);
        assert_eq!(
            executor.staked_receipt_table().get(&receipt_ref),
            Some(&validator_id),
            "preconditions: receipt seeded"
        );

        // Call settle. amount is whatever the registry would have returned.
        let epoch = 42u64;
        let amount = 7_654_321u64;
        executor.apply_settled_unlocks(&[(validator_id, amount, reward_address)], epoch);

        // 1. receipt entry is gone.
        assert!(
            !executor.staked_receipt_table().contains_key(&receipt_ref),
            "receipt must be dropped"
        );
        assert!(
            executor.staked_receipt_table().is_empty(),
            "no stray entries",
        );

        // 2. synthetic tx_hash = SHA3("MISAKA:stake_unlock:" || epoch_le || validator_id)
        let expected_tx_hash: [u8; 32] = {
            use sha3::{Digest, Sha3_256};
            let mut h = Sha3_256::new();
            h.update(b"MISAKA:stake_unlock:");
            h.update(epoch.to_le_bytes());
            h.update(validator_id);
            h.finalize().into()
        };
        let expected_outref = OutputRef {
            tx_hash: expected_tx_hash,
            output_index: 0,
        };
        let entry = executor
            .utxo_set
            .get(&expected_outref)
            .expect("unlock UTXO must exist at synthetic OutputRef");
        assert_eq!(entry.output.amount, amount);
        assert_eq!(entry.output.address, reward_address);
        assert!(
            entry.output.spending_pubkey.is_none(),
            "spending_pubkey is None — receiver supplies it on spend",
        );
        assert!(
            !entry.is_emission,
            "settlement is stake re-circulation, not emission",
        );
    }

    #[test]
    fn apply_settled_unlocks_empty_is_noop() {
        let mut executor = UtxoExecutor::new(test_app_id());
        executor.enable_on_chain_staking_for_tests(0);

        // Seed a receipt that MUST survive (no settlement touches it).
        let survivor_vid = [0xABu8; 32];
        let survivor_ref = OutputRef {
            tx_hash: [0xCDu8; 32],
            output_index: 0,
        };
        executor
            .staked_receipt_table
            .insert(survivor_ref.clone(), survivor_vid);

        let utxo_count_before = executor.utxo_set.len();
        let receipt_count_before = executor.staked_receipt_table().len();

        executor.apply_settled_unlocks(&[], 99);

        assert_eq!(
            executor.utxo_set.len(),
            utxo_count_before,
            "empty settlement must not touch the UTXO set"
        );
        assert_eq!(
            executor.staked_receipt_table().len(),
            receipt_count_before,
            "empty settlement must not touch the receipt table"
        );
        assert_eq!(
            executor.staked_receipt_table().get(&survivor_ref),
            Some(&survivor_vid),
            "survivor entry intact"
        );
    }

    // ─── γ-4: transactional rollback tests ────────────────────────

    /// Preflight catches an obviously-invalid stake deposit (commission
    /// above max_commission_bps) BEFORE consume_stake_tx_inputs_and_change
    /// touches the UTXO set. Seed a fee input; after the rejected tx, that
    /// input must still exist and the registry must be empty.
    #[test]
    fn gamma4_preflight_rejects_high_commission_without_utxo_consume() {
        let kp = MlDsaKeypair::generate();
        let vid = validator_id_from_kp(&kp);

        // Build a Register envelope with commission_bps way above the cap
        // (testnet default max_commission_bps = 5000).
        let mut stake_tx = ValidatorStakeTx {
            kind: StakeTxKind::Register,
            validator_id: vid,
            stake_inputs: vec![StakeInput {
                tx_hash: [0xABu8; 32],
                output_index: 0,
                amount: 11_000,
            }],
            fee: 1_000,
            nonce: 0,
            memo: None,
            params: StakeTxParams::Register(RegisterParams {
                consensus_pubkey: kp.public_key.as_bytes().to_vec(),
                reward_address: [2u8; 32],
                commission_bps: 9999, // above the 5000 cap
                p2p_endpoint: None,
                moniker: None,
            }),
            signature: vec![],
        };
        stake_tx = sign_stake_tx(stake_tx, &kp);
        let tx = build_stake_deposit_tx(stake_tx);
        let raw = borsh::to_vec(&tx).unwrap();

        let mut executor = UtxoExecutor::new(test_app_id());
        executor.enable_on_chain_staking_for_tests(0);
        let mut registry = StakingRegistry::new(test_staking_config());
        seed_input_utxo(&mut executor, stake_deposit_input_ref(), 11_000);

        // Confirm the input is present before the tx.
        assert!(
            executor.utxo_set.get(&stake_deposit_input_ref()).is_some(),
            "precondition: input seeded"
        );

        let result = executor.execute_committed(1, &[raw], None, Some(&mut registry), 0);
        assert_eq!(result.txs_accepted, 0);
        assert_eq!(result.txs_rejected, 1);

        // γ-4 preflight: input must still be present because consume was
        // never called.
        assert!(
            executor.utxo_set.get(&stake_deposit_input_ref()).is_some(),
            "γ-4: preflight rejection must not consume the input UTXO"
        );
        // Registry remains empty.
        assert!(
            registry.get(&vid).is_none(),
            "no validator should have registered"
        );
    }

    /// Rollback path: use StakeMore whose validator is in EXITING state so
    /// `can_stake_more` passes the "state == Locked|Active" pre-filter
    /// elsewhere... Actually that *is* caught by pre-flight now. To force
    /// the rollback path we need a failure mode the pre-flight does NOT
    /// detect. The simplest reliable trigger: directly invoke the apply
    /// helper with a registry that will fail on the mutating call.
    ///
    /// Approach: register a validator via apply_stake_deposit, then send
    /// ANOTHER Register tx for the same validator_id but with a DIFFERENT
    /// stake_tx_hash (via different nonce). can_register_l1_native passes
    /// its stake-signature replay check (new hash) but the existing-entry
    /// check also passes (AlreadyRegistered would be caught...).
    ///
    /// Simpler: mutate the registry between the dry-run and the call by
    /// inserting a conflicting entry directly. Since this module has
    /// crate-private access to `validators` via `StakingRegistry`... it
    /// does NOT — `validators` is private outside the consensus crate.
    ///
    /// Simplest test that exercises the rollback: call
    /// `rollback_stake_tx_utxo_side` directly on a crafted delta. This
    /// verifies the helper's behavior deterministically.
    #[test]
    fn gamma4_rollback_helper_restores_utxo_state() {
        let mut executor = UtxoExecutor::new(test_app_id());
        executor.enable_on_chain_staking_for_tests(0);

        // Seed two input UTXOs that we'll "consume" as if by a stake tx.
        let input_a = OutputRef {
            tx_hash: [0xA1; 32],
            output_index: 0,
        };
        let input_b = OutputRef {
            tx_hash: [0xB2; 32],
            output_index: 0,
        };
        seed_input_utxo(&mut executor, input_a.clone(), 5_000);
        seed_input_utxo(&mut executor, input_b.clone(), 7_000);
        let pre_count = executor.utxo_set.len();

        // Build a delta pretending we consumed A+B and added a change
        // output C. Then call the rollback helper with a savepoint
        // captured "before" any of that.
        let savepoint = UtxoExecutor::delta_savepoint(&BlockDelta::new(executor.height));
        let mut delta = BlockDelta::new(executor.height);

        // Simulate consume_stake_tx_inputs_and_change:
        // - remove A, B; push them into delta.spent
        let a_output = executor.utxo_set.get(&input_a).unwrap().output.clone();
        let b_output = executor.utxo_set.get(&input_b).unwrap().output.clone();
        executor.utxo_set.remove_output(&input_a);
        executor.utxo_set.remove_output(&input_b);
        delta
            .spent
            .push((input_a.tx_hash, input_a.clone(), a_output));
        delta
            .spent
            .push((input_b.tx_hash, input_b.clone(), b_output));

        // - add change output C; push to delta.created
        let change_ref = OutputRef {
            tx_hash: [0xCC; 32],
            output_index: 0,
        };
        executor
            .utxo_set
            .add_output(
                change_ref.clone(),
                TxOutput {
                    amount: 1_000,
                    address: [0xDD; 32],
                    spending_pubkey: None,
                },
                executor.height,
                false,
            )
            .unwrap();
        delta.created.push(change_ref.clone());

        assert_eq!(executor.utxo_set.len(), pre_count - 1);
        assert!(executor.utxo_set.get(&input_a).is_none());
        assert!(executor.utxo_set.get(&input_b).is_none());
        assert!(executor.utxo_set.get(&change_ref).is_some());

        // Roll back.
        UtxoExecutor::rollback_stake_tx_utxo_side(&mut executor.utxo_set, &mut delta, savepoint);

        // Post-rollback: UTXO set matches pre state.
        assert_eq!(
            executor.utxo_set.len(),
            pre_count,
            "UTXO count restored after rollback"
        );
        assert!(
            executor.utxo_set.get(&input_a).is_some(),
            "input A restored"
        );
        assert!(
            executor.utxo_set.get(&input_b).is_some(),
            "input B restored"
        );
        assert!(
            executor.utxo_set.get(&change_ref).is_none(),
            "change output removed"
        );
        // Delta vecs truncated.
        assert!(delta.spent.is_empty(), "delta.spent truncated");
        assert!(delta.created.is_empty(), "delta.created truncated");
    }

    /// Preflight catches stake-signature replay on StakeMore BEFORE the
    /// UTXO side runs. The fee-paying input must survive the rejected tx.
    #[test]
    fn gamma4_preflight_rejects_stake_more_replay_without_utxo_consume() {
        let kp = MlDsaKeypair::generate();
        let vid = validator_id_from_kp(&kp);

        // First: register + verify the validator normally so a StakeMore
        // can legally follow.
        let reg_tx = build_stake_deposit_tx(make_register_envelope(&kp, vid));
        let reg_raw = borsh::to_vec(&reg_tx).unwrap();

        let mut executor = UtxoExecutor::new(test_app_id());
        executor.enable_on_chain_staking_for_tests(0);
        let mut registry = StakingRegistry::new(test_staking_config());
        seed_input_utxo(&mut executor, stake_deposit_input_ref(), 11_000);
        let r1 = executor.execute_committed(1, &[reg_raw], None, Some(&mut registry), 0);
        assert_eq!(r1.txs_accepted, 1, "initial register must succeed");

        // Send a StakeMore, then try to replay the SAME StakeMore.
        let sm_tx = build_stake_deposit_tx(make_stake_more_envelope(&kp, vid, 5_000));
        let sm_raw = borsh::to_vec(&sm_tx).unwrap();

        // Re-seed the fixed input between commits (previous consumption).
        seed_input_utxo(&mut executor, stake_deposit_input_ref(), 6_000);
        let r2 = executor.execute_committed(2, &[sm_raw.clone()], None, Some(&mut registry), 0);
        assert_eq!(r2.txs_accepted, 1, "StakeMore must succeed first time");

        // Replay attempt: fresh fee input, same envelope.
        seed_input_utxo(&mut executor, stake_deposit_input_ref(), 6_000);
        let r3 = executor.execute_committed(3, &[sm_raw], None, Some(&mut registry), 0);
        assert_eq!(r3.txs_accepted, 0);
        assert_eq!(r3.txs_rejected, 1, "replay must be rejected");

        // γ-4 preflight: the fee input for the replay attempt must still
        // be present (never consumed).
        assert!(
            executor.utxo_set.get(&stake_deposit_input_ref()).is_some(),
            "γ-4: preflight rejection of replay must not consume the fee input"
        );
    }

    /// Preflight catches `exit` on a non-Active validator (e.g., LOCKED)
    /// BEFORE UTXO consume. The BeginExit tx's fee input must survive.
    #[test]
    fn gamma4_preflight_rejects_exit_from_locked_without_utxo_consume() {
        let kp = MlDsaKeypair::generate();
        let vid = validator_id_from_kp(&kp);

        // Register but do NOT activate — validator stays LOCKED, so
        // exit() would fail with InvalidTransition.
        let reg_tx = build_stake_deposit_tx(make_register_envelope(&kp, vid));
        let reg_raw = borsh::to_vec(&reg_tx).unwrap();

        let mut executor = UtxoExecutor::new(test_app_id());
        executor.enable_on_chain_staking_for_tests(0);
        // Use a staking config where min_validator_stake is high enough
        // that activate() would fail — but we'll skip activate entirely.
        let mut registry = StakingRegistry::new(test_staking_config());
        seed_input_utxo(&mut executor, stake_deposit_input_ref(), 11_000);
        let r1 = executor.execute_committed(1, &[reg_raw], None, Some(&mut registry), 0);
        assert_eq!(r1.txs_accepted, 1);
        // Confirm still LOCKED.
        assert_eq!(
            registry.get(&vid).unwrap().state,
            misaka_consensus::staking::ValidatorState::Locked
        );

        // Build a BeginExit against the still-LOCKED validator.
        let exit_envelope = make_begin_exit_envelope(&kp, vid);
        let exit_tx = build_stake_withdraw_tx(exit_envelope);
        let exit_raw = borsh::to_vec(&exit_tx).unwrap();
        seed_input_utxo(&mut executor, stake_withdraw_input_ref(), 2_000);

        let r2 = executor.execute_committed(2, &[exit_raw], None, Some(&mut registry), 0);
        assert_eq!(r2.txs_accepted, 0);
        assert_eq!(r2.txs_rejected, 1, "exit from LOCKED must be rejected");

        // γ-4 preflight: BeginExit fee input must still be present.
        assert!(
            executor.utxo_set.get(&stake_withdraw_input_ref()).is_some(),
            "γ-4: preflight rejection of exit must not consume the fee input"
        );
        // Validator state unchanged.
        assert_eq!(
            registry.get(&vid).unwrap().state,
            misaka_consensus::staking::ValidatorState::Locked,
            "exit rejection must leave state untouched"
        );
    }
}
