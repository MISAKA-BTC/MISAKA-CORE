//! UTXO Mempool — ZKP-only admission (v4).
//!
//! # Admission Pipeline (Task 4.1)
//!
//! 1. Structural validation
//! 2. **Cheap size gate** — O(1) byte length checks (anti-DoS)
//! 3. **Dedup** — before eviction (SEC-FIX: prevents duplicate-resubmit attack)
//! 4. **Capacity** — fee-rate-priority eviction (SEC-FIX: fee-per-byte, not absolute fee)
//! 5. **O(1) spend-tag conflict** — mempool + chain HashSet lookup (anti-DoS)
//! 6. Insert
//!
//! Lattice ZKP proof paths have been completely removed.

pub mod admission_pipeline;
// P2-7: reorg_handler and reconciliation are legacy linear-chain modules.
// Not used in DAG mode (feature = "dag"). Retained for non-DAG mode compatibility.
pub mod reconciliation;
pub mod reorg_handler;
use admission_pipeline::cheap_size_gate;
pub use admission_pipeline::PeerTxAdmissionGate;
use misaka_storage::utxo_set::UtxoSet;
use misaka_types::utxo::*;
use std::collections::BTreeMap;
#[cfg(feature = "dag")]
use tokio::sync::mpsc;

/// Fee rate: fee per estimated byte of transaction (micro-units).
/// Used for eviction priority instead of absolute fee to prevent
/// large-tx spam from evicting small high-rate transactions.
fn fee_rate(tx: &UtxoTransaction) -> u128 {
    // Estimate serialized size from struct contents.
    // Each input: proof bytes + utxo_refs (40 each)
    // Each output: ~8 (amount) + 32 (address)
    let input_size: usize = tx
        .inputs
        .iter()
        .map(|i| i.proof.len() + i.utxo_refs.len() * 40)
        .sum();
    let output_size: usize = tx.outputs.len() * 40;
    let extra_size = tx.extra.len();
    let total = (input_size + output_size + extra_size + 64).max(1) as u128; // 64 for fixed fields
    (tx.fee as u128 * 1_000_000) / total
}

/// Mempool admission error — every failure path explicit.
#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    #[error("structural: {0}")]
    Structural(String),
    #[error("spend-tag conflict: {0}")]
    SpendTagConflict(String),
    #[error("ring member not found: input[{index}] member {member}")]
    RingMemberNotFound { index: usize, member: String },
    #[error("ring member has no spending pubkey: input[{index}]")]
    RingMemberNoPubkey { index: usize },
    #[error("output malformed: output[{index}]: {reason}")]
    StealthMalformed { index: usize, reason: String },
    #[error("amount mismatch: inputs={inputs}, outputs+fee={required}")]
    AmountMismatch { inputs: u64, required: u64 },
    #[error("ring amounts not uniform: input[{index}]: {reason}")]
    RingAmountNotUniform { index: usize, reason: String },
    #[error("privacy constraints: {0}")]
    PrivacyConstraints(String),
    #[error("privacy statement: {0}")]
    PrivacyStatement(String),
    #[error("zero-knowledge proof: {0}")]
    ZeroKnowledgeProof(String),
    #[error("capacity full")]
    CapacityFull,
    #[error("duplicate transaction")]
    Duplicate([u8; 32]),
    #[error("narwhal/CoreEngine relay failed before propose_block: {0}")]
    DagRelay(String),
    #[error("rejected tx type: SystemEmission/Faucet cannot be user-submitted")]
    RejectedTxType,
    // ── γ-3.1: L1 native stake tx admission errors ────────────────────
    #[error("stake envelope decode failed: {0}")]
    StakeEnvelopeDecode(String),
    #[error("stake structural validation failed: {0}")]
    StakeStructural(String),
    #[error(
        "stake below min validator stake: net_stake={net_stake}, required={required}"
    )]
    StakeBelowMinValidatorStake { net_stake: u64, required: u64 },
    #[error("stake kind mismatch: tx_type={tx_type}, envelope_kind={envelope_kind}")]
    StakeKindMismatch {
        tx_type: String,
        envelope_kind: String,
    },
    #[error("stake admission requires Arc<StakingConfig>: use UtxoMempool::with_staking_config")]
    StakeConfigMissing,
}

pub struct MempoolEntry {
    pub tx: UtxoTransaction,
    pub tx_hash: [u8; 32],
    pub received_at_ms: u64,
}

/// UTXO mempool with spend-tag double-spend prevention.
///
/// SECURITY (C4 fix): All mutation methods (`admit`, `remove`)
/// require exclusive (`&mut self`) access. Callers MUST wrap `UtxoMempool` in
/// `parking_lot::RwLock` or `std::sync::Mutex` to prevent TOCTOU race conditions
/// on spend checks.
///
/// The spent-input check-and-insert in `admit()` is atomic within a single `&mut self`
/// call — no other thread can read `spent_inputs` between the check and the insert
/// because `&mut self` provides exclusive access at the Rust borrow checker level.
pub struct UtxoMempool {
    entries: BTreeMap<[u8; 32], MempoolEntry>,
    max_size: usize,
    /// SECURITY: Track which input outrefs are already claimed by a mempool TX.
    /// Prevents double-spend within the mempool (same UTXO used by two txs).
    spent_inputs: std::collections::HashMap<misaka_types::utxo::OutputRef, [u8; 32]>,
    /// Optional DAG relay for Narwhal/CoreEngine proposal wiring.
    #[cfg(feature = "dag")]
    dag_relay: Option<mpsc::Sender<Vec<u8>>>,
    /// γ-3.1: process-wide `Arc<StakingConfig>` injected at startup.
    ///
    /// When `Some`, the admit pipeline runs L1-native stake tx admission
    /// checks (envelope decode + structural + min_validator_stake). When
    /// `None` (legacy `UtxoMempool::new` callers / tests that don't care
    /// about stake txs), stake txs are rejected with `StakeConfigMissing`
    /// rather than silently bypassing the filter.
    staking_config: Option<std::sync::Arc<misaka_consensus::staking::StakingConfig>>,
}

impl UtxoMempool {
    /// Legacy constructor. Stake txs cannot be admitted through this
    /// instance — prefer [`Self::with_staking_config`] for production use.
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            max_size,
            spent_inputs: std::collections::HashMap::new(),
            #[cfg(feature = "dag")]
            dag_relay: None,
            staking_config: None,
        }
    }

    /// γ-3.1: construct a mempool that accepts L1-native stake txs.
    ///
    /// `staking_config` is the canonical process-wide
    /// `Arc<StakingConfig>` (same instance carried in `StakingRegistry`
    /// via γ-3's `config_arc()` and in `ValidatorLifecycleBootstrap`).
    pub fn with_staking_config(
        max_size: usize,
        staking_config: std::sync::Arc<misaka_consensus::staking::StakingConfig>,
    ) -> Self {
        Self {
            entries: BTreeMap::new(),
            max_size,
            spent_inputs: std::collections::HashMap::new(),
            #[cfg(feature = "dag")]
            dag_relay: None,
            staking_config: Some(staking_config),
        }
    }

    #[cfg(feature = "dag")]
    pub fn set_narwhal_relay(&mut self, sender: mpsc::Sender<Vec<u8>>) {
        self.dag_relay = Some(sender);
    }

    /// Mempool admission with structural + UTXO existence checks.
    ///
    /// # Admission Order (cheap checks first, Phase 34 hardened)
    ///
    /// 1. Structural validation (field sizes, version)
    /// 2. Cheap size gate (tx byte length, proof byte length) — O(1)
    /// 3. Capacity check
    /// 4. Dedup (tx_hash) — returns Err(Duplicate)
    /// 5. Signature structure pre-check
    /// 6. UTXO existence check — all input refs must exist (Phase 34)
    /// 7. Backend selection
    /// 8. SpendTag conflict (mempool + chain) — O(1) HashSet
    /// 9. Stealth sanity
    /// 10. Insert with spend tracking
    ///
    /// NOTE: Full cryptographic verification (ML-DSA-65 sig, ring proofs,
    /// ZKP) is deferred to block validation / NarwhalTxExecutor.
    /// The mempool performs structural + existence checks only.
    pub fn admit(
        &mut self,
        tx: UtxoTransaction,
        utxo_set: &UtxoSet,
        now_ms: u64,
    ) -> Result<[u8; 32], MempoolError> {
        // ── SEC-FIX: Reject system-only tx types (defense-in-depth) ──
        // Even if RPC ingress missed the check, the mempool must not admit
        // SystemEmission or Faucet transactions from external sources.
        if matches!(
            tx.tx_type,
            misaka_types::utxo::TxType::SystemEmission | misaka_types::utxo::TxType::Faucet
        ) {
            return Err(MempoolError::RejectedTxType);
        }

        // ── 1. Structural validation ──
        tx.validate_structure()
            .map_err(|e| MempoolError::Structural(e.to_string()))?;

        // ── γ-3.1: L1 native stake tx admission checks ──
        //
        // For `TxType::StakeDeposit / StakeWithdraw`, `validate_structure`
        // (γ-1) has already decoded the envelope and cross-checked the
        // envelope kind against the tx_type. Here we add the mempool-level
        // filter: min_validator_stake on Register, non-zero additional_amount
        // on StakeMore, empty stake_inputs on BeginExit.
        //
        // This is a *pre-filter* — the final enforcement is in
        // `utxo_executor::apply_stake_*` (γ-3). Having the check here
        // prevents obviously invalid stake txs from propagating through
        // the DAG relay.
        if matches!(
            tx.tx_type,
            misaka_types::utxo::TxType::StakeDeposit
                | misaka_types::utxo::TxType::StakeWithdraw
        ) {
            Self::admit_stake_tx(&tx, self.staking_config.as_deref())?;
        }

        // ── SEC-FIX: Signature format pre-check (anti-spam) ──
        // Full ML-DSA-65 cryptographic verification is deferred to block validation,
        // but we can cheaply reject obviously invalid signatures here to prevent
        // mempool pollution with garbage-signed transactions.
        // ML-DSA-65 signature length = 3309 bytes.
        if tx.tx_type == misaka_types::utxo::TxType::TransparentTransfer {
            for (i, input) in tx.inputs.iter().enumerate() {
                if input.proof.is_empty() {
                    return Err(MempoolError::Structural(format!(
                        "input[{}]: missing signature (empty proof)",
                        i
                    )));
                }
                if input.proof.len() != 3309 {
                    return Err(MempoolError::Structural(format!(
                        "input[{}]: invalid signature length {} (expected 3309)",
                        i,
                        input.proof.len()
                    )));
                }
            }
        }

        // ── 2. Cheap size gate (Task 4.1) ──
        cheap_size_gate(&tx)?;

        // ── 3. Dedup — BEFORE eviction (SEC-FIX: prevents duplicate-resubmit eviction attack)
        //
        // Previously eviction ran before dedup, allowing an attacker to resubmit
        // an existing high-fee TX to trigger eviction of the lowest-fee TX, then
        // fail on dedup — a free mempool manipulation attack.
        let tx_hash = tx.tx_hash();
        if self.entries.contains_key(&tx_hash) {
            return Err(MempoolError::Duplicate(tx_hash));
        }

        // ── 4. Capacity — fee-rate-priority eviction (SEC-FIX: fee-per-byte, not absolute fee)
        //
        // Compare fee_rate (fee / serialized_size) instead of absolute fee.
        // This prevents large-tx spam from evicting small high-rate txs.
        if self.entries.len() >= self.max_size {
            let new_rate = fee_rate(&tx);

            let lowest_entry = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| fee_rate(&entry.tx))
                .map(|(hash, entry)| (*hash, fee_rate(&entry.tx)));

            if let Some((lowest_hash, lowest_rate)) = lowest_entry {
                if new_rate <= lowest_rate {
                    // New TX has lower or equal fee rate — reject it
                    return Err(MempoolError::CapacityFull);
                }

                // Evict lowest-rate TX to make room
                self.remove(&lowest_hash);
                tracing::debug!(
                    "Mempool full: evicted lowest-rate TX {} (rate={}) for new TX (rate={})",
                    hex::encode(&lowest_hash[..8]),
                    lowest_rate,
                    new_rate
                );
            } else {
                return Err(MempoolError::CapacityFull);
            }
        }

        #[cfg(feature = "dag")]
        let relay_bytes = match &self.dag_relay {
            // Phase 2c-A: borsh encoding for consensus wire format
            Some(_) => Some(borsh::to_vec(&tx).map_err(|e| {
                MempoolError::DagRelay(format!("borsh encode admitted tx for Narwhal: {}", e))
            })?),
            None => None,
        };

        // ── 5. UTXO existence check (Phase 34 — anti-spam) ──
        // Verify that all referenced UTXOs actually exist. This prevents
        // attackers from filling the mempool with TX referencing non-existent
        // UTXOs (which would pass all other checks but fail at block validation).
        // Coinbase TX has no inputs, so skip.
        if tx.tx_type != misaka_types::utxo::TxType::SystemEmission {
            for (i, input) in tx.inputs.iter().enumerate() {
                if input.utxo_refs.is_empty() {
                    return Err(MempoolError::Structural(format!(
                        "input {} has no UTXO refs",
                        i
                    )));
                }
                for (j, outref) in input.utxo_refs.iter().enumerate() {
                    if utxo_set.get(outref).is_none() && utxo_set.get_spending_key(outref).is_none()
                    {
                        return Err(MempoolError::Structural(format!(
                            "input {} ring member {} references non-existent UTXO {}:{}",
                            i,
                            j,
                            hex::encode(&outref.tx_hash[..8]),
                            outref.output_index,
                        )));
                    }
                }
            }
        }

        // ── 5b. SECURITY: Double-spend conflict check ──
        // Reject TX if any of its inputs are already claimed by another mempool TX.
        let tx_hash_for_conflict = tx.tx_hash();
        for input in &tx.inputs {
            for outref in &input.utxo_refs {
                if let Some(existing_tx) = self.spent_inputs.get(outref) {
                    return Err(MempoolError::Structural(format!(
                        "input {}:{} already spent by mempool tx {}",
                        hex::encode(&outref.tx_hash[..8]),
                        outref.output_index,
                        hex::encode(&existing_tx[..8]),
                    )));
                }
            }
        }

        // ── 6. Insert ──
        //
        // NOTE: Full verification is performed at block validation time.
        // The mempool performs only cheap structural checks to prevent DoS.
        // Register spent inputs BEFORE insertion (for rollback safety)
        for input in &tx.inputs {
            for outref in &input.utxo_refs {
                self.spent_inputs.insert(outref.clone(), tx_hash);
            }
        }

        self.entries.insert(
            tx_hash,
            MempoolEntry {
                tx,
                tx_hash,
                received_at_ms: now_ms,
            },
        );

        #[cfg(feature = "dag")]
        if let (Some(sender), Some(tx_bytes)) = (&self.dag_relay, relay_bytes) {
            if let Err(e) = sender.try_send(tx_bytes) {
                self.remove(&tx_hash);
                return Err(MempoolError::DagRelay(e.to_string()));
            }
        }

        Ok(tx_hash)
    }

    /// γ-3.1: envelope-level filter for `StakeDeposit` / `StakeWithdraw`.
    ///
    /// Called by `admit` immediately after `tx.validate_structure()`
    /// succeeds. This helper is purely stateless (no registry, no utxo_set),
    /// so it can live on the type itself.
    ///
    /// Defense-in-depth: `validate_structure` already catches bad magic,
    /// kind cross-checks, and core envelope malformation. The mempool adds
    /// the min_validator_stake / additional_amount semantic filters that
    /// depend on `StakingConfig`.
    fn admit_stake_tx(
        tx: &UtxoTransaction,
        config: Option<&misaka_consensus::staking::StakingConfig>,
    ) -> Result<(), MempoolError> {
        use misaka_types::validator_stake_tx::{StakeTxKind, StakeTxParams, ValidatorStakeTx};

        // Need a StakingConfig to evaluate min_validator_stake.
        let Some(config) = config else {
            return Err(MempoolError::StakeConfigMissing);
        };

        let stake_tx = ValidatorStakeTx::decode_from_extra(&tx.extra)
            .map_err(|e| MempoolError::StakeEnvelopeDecode(e.to_string()))?;
        stake_tx
            .validate_structure()
            .map_err(|e| MempoolError::StakeStructural(e.to_string()))?;

        // Double-check kind vs. tx_type. UtxoTransaction::validate_structure
        // already did this (γ-1) but rerun here so the mempool error message
        // is explicit ("stake kind mismatch" rather than the more generic
        // "{:?} tx: envelope kind X not allowed for this tx_type").
        let envelope_kind = stake_tx.kind;
        let kind_allowed = match tx.tx_type {
            misaka_types::utxo::TxType::StakeDeposit => matches!(
                envelope_kind,
                StakeTxKind::Register | StakeTxKind::StakeMore
            ),
            misaka_types::utxo::TxType::StakeWithdraw => {
                matches!(envelope_kind, StakeTxKind::BeginExit)
            }
            _ => true,
        };
        if !kind_allowed {
            return Err(MempoolError::StakeKindMismatch {
                tx_type: format!("{:?}", tx.tx_type),
                envelope_kind: envelope_kind.as_str().into(),
            });
        }

        match &stake_tx.params {
            StakeTxParams::Register(_) => {
                let net_stake = stake_tx.net_stake_amount();
                if net_stake < config.min_validator_stake {
                    return Err(MempoolError::StakeBelowMinValidatorStake {
                        net_stake,
                        required: config.min_validator_stake,
                    });
                }
            }
            StakeTxParams::StakeMore(p) => {
                if p.additional_amount == 0 {
                    return Err(MempoolError::StakeStructural(
                        "stake_more additional_amount must be > 0".into(),
                    ));
                }
            }
            StakeTxParams::BeginExit => {
                if !stake_tx.stake_inputs.is_empty() {
                    return Err(MempoolError::StakeStructural(
                        "begin_exit envelope must have empty stake_inputs".into(),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Admit a system-originated transaction (Faucet, SystemEmission) that
    /// bypasses the tx_type rejection in `admit`. Only the node's own RPC
    /// should call this — never expose to external users directly.
    pub fn admit_system_tx(
        &mut self,
        tx: UtxoTransaction,
        now_ms: u64,
    ) -> Result<[u8; 32], MempoolError> {
        cheap_size_gate(&tx)?;

        let tx_hash = tx.tx_hash();
        if self.entries.contains_key(&tx_hash) {
            return Err(MempoolError::Duplicate(tx_hash));
        }
        if self.entries.len() >= self.max_size {
            return Err(MempoolError::CapacityFull);
        }

        #[cfg(feature = "dag")]
        let relay_bytes = match &self.dag_relay {
            Some(_) => Some(borsh::to_vec(&tx).map_err(|e| {
                MempoolError::DagRelay(format!("borsh encode system tx for Narwhal: {}", e))
            })?),
            None => None,
        };

        self.entries.insert(
            tx_hash,
            MempoolEntry {
                tx,
                tx_hash,
                received_at_ms: now_ms,
            },
        );

        #[cfg(feature = "dag")]
        if let (Some(sender), Some(tx_bytes)) = (&self.dag_relay, relay_bytes) {
            if let Err(e) = sender.try_send(tx_bytes) {
                self.remove(&tx_hash);
                return Err(MempoolError::DagRelay(e.to_string()));
            }
        }

        Ok(tx_hash)
    }

    pub fn remove(&mut self, tx_hash: &[u8; 32]) -> bool {
        if let Some(entry) = self.entries.remove(tx_hash) {
            // Clean up spent_inputs tracking
            for input in &entry.tx.inputs {
                for outref in &input.utxo_refs {
                    self.spent_inputs.remove(outref);
                }
            }
            true
        } else {
            false
        }
    }

    /// R7 M-9: Sort by fee_rate (fee per byte), consistent with eviction policy.
    pub fn top_by_fee(&self, n: usize) -> Vec<&UtxoTransaction> {
        let mut txs: Vec<&MempoolEntry> = self.entries.values().collect();
        txs.sort_by(|a, b| fee_rate(&b.tx).cmp(&fee_rate(&a.tx)));
        txs.truncate(n);
        txs.into_iter().map(|e| &e.tx).collect()
    }

    pub fn contains_tx(&self, tx_hash: &[u8; 32]) -> bool {
        self.entries.contains_key(tx_hash)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn max_size(&self) -> usize {
        self.max_size
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_utxo_set() -> UtxoSet {
        let mut utxo_set = UtxoSet::new(100);
        for i in 0..4u8 {
            let outref = OutputRef {
                tx_hash: [(i + 1) as u8; 32],
                output_index: 0,
            };
            utxo_set
                .add_output(
                    outref.clone(),
                    TxOutput {
                        amount: 10_000,
                        address: [0x11; 32],
                        spending_pubkey: Some(vec![0x22; 1952]),
                    },
                    0,
                    false,
                )
                .unwrap();
            utxo_set
                .register_spending_key(outref, vec![0x22; 1952])
                .expect("test: register_spending_key");
        }
        utxo_set
    }

    fn sample_v4_tx(salt: [u8; 32]) -> UtxoTransaction {
        UtxoTransaction {
            version: UTXO_TX_VERSION,
            tx_type: TxType::TransparentTransfer,
            inputs: vec![TxInput {
                utxo_refs: vec![OutputRef {
                    tx_hash: [1u8; 32], // references UTXO from sample_utxo_set
                    output_index: 0,
                }],
                proof: vec![0u8; 3309],
            }],
            outputs: vec![TxOutput {
                amount: 9_900,
                address: [0xCC; 32],
                spending_pubkey: None,
            }],
            fee: 100,
            extra: salt.to_vec(), // salt differentiates tx hashes
            expiry: 0,
        }
    }

    #[test]
    fn test_admit_v4_tx() {
        let mut pool = UtxoMempool::new(100);
        let utxo_set = sample_utxo_set();
        let tx = sample_v4_tx([0xAA; 32]);
        let hash = pool.admit(tx, &utxo_set, 1000).unwrap();
        assert_eq!(pool.len(), 1);
        assert_ne!(hash, [0; 32]);
    }

    #[test]
    fn test_duplicate_tx_rejected() {
        let mut pool = UtxoMempool::new(100);
        let utxo_set = sample_utxo_set();
        let first = pool
            .admit(sample_v4_tx([0xAA; 32]), &utxo_set, 1000)
            .unwrap();
        let second = pool.admit(sample_v4_tx([0xAA; 32]), &utxo_set, 2000);
        assert!(matches!(second, Err(MempoolError::Duplicate(hash)) if hash == first));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_capacity_full_rejected() {
        let mut pool = UtxoMempool::new(1);
        let utxo_set = sample_utxo_set();
        pool.admit(sample_v4_tx([0x01; 32]), &utxo_set, 1000)
            .unwrap();
        let result = pool.admit(sample_v4_tx([0x02; 32]), &utxo_set, 2000);
        assert!(matches!(result, Err(MempoolError::CapacityFull)));
    }

    #[test]
    fn test_cheap_size_gate_rejects_oversized() {
        let mut pool = UtxoMempool::new(100);
        let utxo_set = sample_utxo_set();
        let mut tx = sample_v4_tx([0xCC; 32]);
        tx.inputs[0].proof = vec![0u8; admission_pipeline::MAX_PROOF_BYTES_PER_INPUT + 1];
        let result = pool.admit(tx, &utxo_set, 1000);
        assert!(result.is_err());
    }

    #[cfg(feature = "dag")]
    #[test]
    fn test_admit_relays_to_narwhal_propose_queue() {
        let mut pool = UtxoMempool::new(100);
        let utxo_set = sample_utxo_set();

        let (relay_tx, mut relay_rx) = tokio::sync::mpsc::channel(4);
        pool.set_narwhal_relay(relay_tx);

        let tx = sample_v4_tx([0xAB; 32]);
        let hash = pool.admit(tx, &utxo_set, 1000).unwrap();
        let relayed_bytes = relay_rx.try_recv().expect("relayed tx bytes");
        let relayed_tx: UtxoTransaction =
            borsh::from_slice(&relayed_bytes).expect("borsh decode relayed tx");

        assert_eq!(relayed_tx.tx_hash(), hash);
    }

    // ─── γ-3.1: stake tx admission tests ──────────────────────────────

    use misaka_consensus::staking::StakingConfig;
    use misaka_types::validator_stake_tx::{
        RegisterParams, StakeInput, StakeMoreParams, StakeTxKind, StakeTxParams, ValidatorStakeTx,
    };
    use std::sync::Arc;

    fn stake_test_config() -> Arc<StakingConfig> {
        // Small min_validator_stake (10_000) so the fixture numbers fit.
        Arc::new(StakingConfig {
            min_validator_stake: 10_000,
            min_uptime_bps: 0,
            min_score: 0,
            ..StakingConfig::testnet()
        })
    }

    fn stake_input_utxo_set() -> UtxoSet {
        let mut utxo_set = UtxoSet::new(100);
        // Pre-seed `tx.inputs[0]` ref used by stake_utxo_tx (tx_hash=[0xAB; 32]).
        let outref = OutputRef {
            tx_hash: [0xABu8; 32],
            output_index: 0,
        };
        utxo_set
            .add_output(
                outref.clone(),
                TxOutput {
                    amount: 20_000,
                    address: [0x11; 32],
                    spending_pubkey: Some(vec![0x22; 1952]),
                },
                0,
                false,
            )
            .unwrap();
        utxo_set
            .register_spending_key(outref, vec![0x22; 1952])
            .unwrap();
        utxo_set
    }

    /// Build a `TxType::StakeDeposit` UtxoTransaction carrying `envelope`
    /// in `extra`. The UTXO input references the pre-seeded tx_hash=0xAB.
    fn stake_utxo_tx(
        tx_type: TxType,
        envelope: &ValidatorStakeTx,
    ) -> UtxoTransaction {
        UtxoTransaction {
            version: UTXO_TX_VERSION,
            tx_type,
            inputs: vec![TxInput {
                utxo_refs: vec![OutputRef {
                    tx_hash: [0xABu8; 32],
                    output_index: 0,
                }],
                proof: vec![0u8; 3309],
            }],
            outputs: vec![TxOutput {
                amount: 0,
                address: [0x11; 32],
                spending_pubkey: None,
            }],
            fee: 100,
            extra: envelope.encode_for_extra().expect("encode envelope"),
            expiry: 0,
        }
    }

    fn make_register_envelope(net_stake: u64) -> ValidatorStakeTx {
        // With fee=1_000 and 1 input of amount=net_stake+1_000 → net_stake.
        ValidatorStakeTx {
            kind: StakeTxKind::Register,
            validator_id: [1u8; 32],
            stake_inputs: vec![StakeInput {
                tx_hash: [0xCDu8; 32],
                output_index: 0,
                amount: net_stake + 1_000,
            }],
            fee: 1_000,
            nonce: 0,
            memo: None,
            params: StakeTxParams::Register(RegisterParams {
                consensus_pubkey: vec![0u8; 1952],
                reward_address: [2u8; 32],
                commission_bps: 500,
                p2p_endpoint: None,
                moniker: None,
            }),
            signature: vec![0u8; 32],
        }
    }

    fn make_begin_exit_envelope() -> ValidatorStakeTx {
        ValidatorStakeTx {
            kind: StakeTxKind::BeginExit,
            validator_id: [1u8; 32],
            stake_inputs: vec![],
            fee: 1_000,
            nonce: 2,
            memo: None,
            params: StakeTxParams::BeginExit,
            signature: vec![0u8; 32],
        }
    }

    #[test]
    fn test_admit_stake_deposit_register_valid() {
        let mut pool = UtxoMempool::with_staking_config(100, stake_test_config());
        let utxo_set = stake_input_utxo_set();
        let envelope = make_register_envelope(/* net_stake = */ 15_000);
        let tx = stake_utxo_tx(TxType::StakeDeposit, &envelope);
        pool.admit(tx, &utxo_set, 1000)
            .expect("valid register admitted");
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_admit_stake_deposit_below_min_rejected() {
        let mut pool = UtxoMempool::with_staking_config(100, stake_test_config());
        let utxo_set = stake_input_utxo_set();
        // net_stake = 5_000 < min_validator_stake = 10_000
        let envelope = make_register_envelope(/* net_stake = */ 5_000);
        let tx = stake_utxo_tx(TxType::StakeDeposit, &envelope);
        match pool.admit(tx, &utxo_set, 1000) {
            Err(MempoolError::StakeBelowMinValidatorStake { net_stake, required }) => {
                assert_eq!(net_stake, 5_000);
                assert_eq!(required, 10_000);
            }
            other => panic!(
                "expected StakeBelowMinValidatorStake, got {:?}",
                other.map(|_| "Ok")
            ),
        }
    }

    #[test]
    fn test_admit_stake_withdraw_begin_exit_valid() {
        let mut pool = UtxoMempool::with_staking_config(100, stake_test_config());
        let utxo_set = stake_input_utxo_set();
        let envelope = make_begin_exit_envelope();
        let tx = stake_utxo_tx(TxType::StakeWithdraw, &envelope);
        pool.admit(tx, &utxo_set, 1000)
            .expect("valid begin_exit admitted");
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_admit_stake_deposit_bad_envelope_rejected() {
        let mut pool = UtxoMempool::with_staking_config(100, stake_test_config());
        let utxo_set = stake_input_utxo_set();
        let envelope = make_register_envelope(/* net_stake = */ 15_000);
        let mut tx = stake_utxo_tx(TxType::StakeDeposit, &envelope);
        // Corrupt the envelope magic so decode fails.
        tx.extra[0] ^= 0xFF;
        // The corrupted envelope is caught by `UtxoTransaction::validate_structure`
        // (γ-1 wiring) rather than our `admit_stake_tx` helper, so the
        // mempool surfaces it as `Structural` rather than `StakeEnvelopeDecode`.
        // Either error is acceptable — the invariant is "bad envelope must
        // be rejected, not silently admitted".
        match pool.admit(tx, &utxo_set, 1000) {
            Err(MempoolError::Structural(s)) => {
                assert!(
                    s.contains("magic") || s.contains("envelope"),
                    "error must reference envelope / magic, got: {s}",
                );
            }
            Err(MempoolError::StakeEnvelopeDecode(_)) => {}
            other => panic!("expected envelope-related error, got {:?}", other.map(|_| "Ok")),
        }
    }

    #[test]
    fn test_admit_stake_deposit_wrong_kind_rejected() {
        // tx_type = StakeDeposit but envelope kind = BeginExit.
        // UtxoTransaction::validate_structure (γ-1) catches this first with
        // a "envelope kind X not allowed for this tx_type" message — we
        // accept Structural here since the mempool layer has the same
        // invariant (defense-in-depth).
        let mut pool = UtxoMempool::with_staking_config(100, stake_test_config());
        let utxo_set = stake_input_utxo_set();
        let envelope = make_begin_exit_envelope();
        let tx = stake_utxo_tx(TxType::StakeDeposit, &envelope);
        match pool.admit(tx, &utxo_set, 1000) {
            Err(MempoolError::Structural(s)) => {
                assert!(
                    s.contains("envelope kind") || s.contains("kind"),
                    "error must reference kind mismatch, got: {s}",
                );
            }
            Err(MempoolError::StakeKindMismatch { .. }) => {}
            other => panic!("expected kind-mismatch error, got {:?}", other.map(|_| "Ok")),
        }
    }

    #[test]
    fn test_admit_stake_tx_without_config_rejected() {
        // Legacy UtxoMempool::new (no StakingConfig) must not silently
        // pass stake txs through. `admit_stake_tx` surfaces
        // `StakeConfigMissing` so an operator sees a clear error.
        let mut pool = UtxoMempool::new(100);
        let utxo_set = stake_input_utxo_set();
        let envelope = make_register_envelope(15_000);
        let tx = stake_utxo_tx(TxType::StakeDeposit, &envelope);
        match pool.admit(tx, &utxo_set, 1000) {
            Err(MempoolError::StakeConfigMissing) => {}
            other => panic!(
                "expected StakeConfigMissing, got {:?}",
                other.map(|_| "Ok")
            ),
        }
    }
}
