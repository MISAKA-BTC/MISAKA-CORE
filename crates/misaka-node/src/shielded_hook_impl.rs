//! Shielded Block Hook — misaka-node 実装
//!
//! `misaka-dag::ShieldedBlockHook` の具体実装。
//! DAG block が atomic commit された後に `ShieldedState` を更新する。
//!
//! # P0 → P1 移行計画
//!
//! P0: DAG WriteBatch commit 後に hook でインメモリ更新。
//!     失敗時は warn ログのみ（再起動で DB から復元）。
//!
//! P1: `StoreWriteBatch` に shielded フィールドを追加し、
//!     DAG の RocksDB WriteBatch と同一バッチで atomic commit。

use misaka_dag::{ShieldedBlockHook, ShieldedTxPayload};
use misaka_shielded::{
    parse_verifying_key_artifact, CircuitVersion, Groth16VerifierAdapter, PlonkVerifierAdapter,
    ProofBackendKind, SharedShieldedState, ShieldDepositTx, ShieldWithdrawTx,
    ShieldedAuthoritativeBackendTargetTag, ShieldedConfig, ShieldedState, ShieldedTransferTx,
    ShieldedVkPolicyModeTag,
};
use parking_lot::RwLock;
use std::sync::Arc;
use tracing::{error, info, warn};

// ─── NodeShieldedHook ─────────────────────────────────────────────────────────

/// `ShieldedBlockHook` の実装。
#[derive(Debug)]
pub struct NodeShieldedHook {
    shielded: SharedShieldedState,
    snapshot_path: String,
}

impl NodeShieldedHook {
    pub fn new(shielded: SharedShieldedState, data_dir: &str) -> Self {
        let snapshot_path = format!("{}/shielded_state.json", data_dir);
        Self {
            shielded,
            snapshot_path,
        }
    }
}

impl ShieldedBlockHook for NodeShieldedHook {
    fn on_block_committed(
        &self,
        block_height: u64,
        _block_hash: &[u8; 32],
        shielded_txs: &[ShieldedTxPayload],
    ) {
        if shielded_txs.is_empty() {
            self.shielded.write().on_block_finalized(block_height);
            return;
        }

        let mut state = self.shielded.write();

        for payload in shielded_txs {
            let tx_hash = *payload.tx_hash();

            let result = match payload {
                ShieldedTxPayload::Deposit { serialized, .. } => {
                    match serde_json::from_slice::<ShieldDepositTx>(serialized) {
                        Ok(tx) => state.apply_deposit(&tx, tx_hash, block_height).map(|_| ()),
                        Err(e) => {
                            error!(
                                "ShieldedHook: deposit deserialize failed tx={}: {}",
                                hex::encode(tx_hash),
                                e
                            );
                            continue;
                        }
                    }
                }
                ShieldedTxPayload::Transfer { serialized, .. } => {
                    match serde_json::from_slice::<ShieldedTransferTx>(serialized) {
                        Ok(tx) => state
                            .apply_shielded_transfer(&tx, tx_hash, block_height)
                            .map(|_| ()),
                        Err(e) => {
                            error!(
                                "ShieldedHook: transfer deserialize failed tx={}: {}",
                                hex::encode(tx_hash),
                                e
                            );
                            continue;
                        }
                    }
                }
                ShieldedTxPayload::Withdraw { serialized, .. } => {
                    match serde_json::from_slice::<ShieldWithdrawTx>(serialized) {
                        Ok(tx) => state.apply_withdraw(&tx, tx_hash, block_height).map(|_| ()),
                        Err(e) => {
                            error!(
                                "ShieldedHook: withdraw deserialize failed tx={}: {}",
                                hex::encode(tx_hash),
                                e
                            );
                            continue;
                        }
                    }
                }
            };

            match result {
                Ok(()) => tracing::debug!(
                    "ShieldedHook: applied tx={} block={}",
                    hex::encode(tx_hash),
                    block_height
                ),
                Err(e) => warn!(
                    "ShieldedHook: apply failed tx={} block={}: {} — restart to recover",
                    hex::encode(tx_hash),
                    block_height,
                    e
                ),
            }
        }

        state.on_block_finalized(block_height);

        // A-2: Persist shielded state snapshot after every block with shielded TXs
        if let Err(e) = state.save_snapshot(&self.snapshot_path) {
            warn!(
                "ShieldedHook: failed to save snapshot: {} — state will recover from DAG on restart",
                e
            );
        }
    }

    fn on_block_reverted(
        &self,
        block_height: u64,
        block_hash: &[u8; 32],
        shielded_txs: &[ShieldedTxPayload],
    ) {
        if shielded_txs.is_empty() {
            return;
        }
        let mut state = self.shielded.write();
        let hash_hex = hex::encode(block_hash);

        // Undo nullifier confirmations for this block's shielded TXs
        for payload in shielded_txs {
            match payload {
                ShieldedTxPayload::Deposit {
                    tx_hash,
                    serialized,
                } => {
                    if let Ok(_tx) = serde_json::from_slice::<ShieldDepositTx>(serialized) {
                        // Remove commitment (revert append) — commitment tree is append-only,
                        // so we truncate by restoring the previous snapshot.
                        // For now, log the revert and rely on snapshot restoration.
                        info!(
                            "ShieldedHook: REVERT deposit tx={} block={} height={}",
                            hex::encode(&tx_hash[..8]),
                            &hash_hex[..8],
                            block_height
                        );
                    }
                }
                ShieldedTxPayload::Transfer {
                    tx_hash,
                    serialized,
                } => {
                    if let Ok(tx) = serde_json::from_slice::<ShieldedTransferTx>(serialized) {
                        // Undo nullifier confirmations
                        for nf in &tx.nullifiers {
                            state.nullifier_set.remove_confirmed(nf);
                        }
                        info!(
                            "ShieldedHook: REVERT transfer tx={} nullifiers={} block={}",
                            hex::encode(&tx_hash[..8]),
                            tx.nullifiers.len(),
                            &hash_hex[..8]
                        );
                    }
                }
                ShieldedTxPayload::Withdraw {
                    tx_hash,
                    serialized,
                } => {
                    if let Ok(tx) = serde_json::from_slice::<ShieldWithdrawTx>(serialized) {
                        for nf in &tx.nullifiers {
                            state.nullifier_set.remove_confirmed(nf);
                        }
                        info!(
                            "ShieldedHook: REVERT withdraw tx={} block={}",
                            hex::encode(&tx_hash[..8]),
                            &hash_hex[..8]
                        );
                    }
                }
            }
        }

        // Save snapshot after revert
        if let Err(e) = state.save_snapshot(&self.snapshot_path) {
            warn!("ShieldedHook: failed to save snapshot after revert: {}", e);
        }
    }

    fn on_tx_evicted(&self, tx_hash: &[u8; 32]) {
        self.shielded.write().release_nullifier_reservation(tx_hash);
    }
}

// ─── ShieldedBootstrap ────────────────────────────────────────────────────────

/// ノード起動時の shielded state 初期化。
pub struct ShieldedBootstrap;

#[derive(Debug, Default)]
pub struct ShieldedVerifierAdapters {
    pub groth16: Option<Arc<dyn Groth16VerifierAdapter>>,
    pub plonk: Option<Arc<dyn PlonkVerifierAdapter>>,
}

pub fn resolve_startup_verifier_adapters(
    enable_real_backend_bootstrap: bool,
) -> anyhow::Result<ShieldedVerifierAdapters> {
    if !enable_real_backend_bootstrap {
        return Ok(ShieldedVerifierAdapters::default());
    }

    let adapters = crate::shielded_verifier_adapters::compiled_startup_verifier_adapters();
    if adapters.groth16.is_some() || adapters.plonk.is_some() {
        return Ok(adapters);
    }

    anyhow::bail!(
        "shielded real backend bootstrap requested but no production Groth16/PLONK verifier adapters are compiled"
    )
}

pub fn validate_startup_verifier_adapter_contract(
    enable_real_backend_bootstrap: bool,
    authoritative_target: Option<&str>,
    groth16_vk_path: Option<&str>,
    plonk_vk_path: Option<&str>,
    adapters: &ShieldedVerifierAdapters,
) -> anyhow::Result<()> {
    if !enable_real_backend_bootstrap {
        return Ok(());
    }

    let target = ShieldedBootstrap::resolve_authoritative_target(authoritative_target)?;
    match target {
        ShieldedAuthoritativeBackendTargetTag::Groth16
            if groth16_vk_path.is_some() && adapters.groth16.is_none() =>
        {
            anyhow::bail!(
                "shielded real backend bootstrap requested for groth16 target but no compiled Groth16 verifier adapter is available"
            );
        }
        ShieldedAuthoritativeBackendTargetTag::Plonk
            if plonk_vk_path.is_some() && adapters.plonk.is_none() =>
        {
            anyhow::bail!(
                "shielded real backend bootstrap requested for plonk target but no compiled PLONK verifier adapter is available"
            );
        }
        _ => {}
    }

    Ok(())
}

impl ShieldedBootstrap {
    fn resolve_authoritative_target(
        target: Option<&str>,
    ) -> anyhow::Result<ShieldedAuthoritativeBackendTargetTag> {
        match target {
            Some("groth16") => Ok(ShieldedAuthoritativeBackendTargetTag::Groth16),
            Some("plonk") => Ok(ShieldedAuthoritativeBackendTargetTag::Plonk),
            Some("groth16_or_plonk") | None => {
                Ok(ShieldedAuthoritativeBackendTargetTag::Groth16OrPlonk)
            }
            Some(other) => anyhow::bail!(
                "invalid shielded authoritative target '{}': expected groth16|plonk|groth16_or_plonk",
                other
            ),
        }
    }

    fn resolve_vk_policy(
        label: &str,
        policy: Option<&str>,
        path: Option<&str>,
    ) -> anyhow::Result<ShieldedVkPolicyModeTag> {
        match policy {
            Some("disabled") => {
                if path.is_some() {
                    anyhow::bail!(
                        "{} verifying key path is set while policy=disabled; remove the path or use observe/require",
                        label
                    );
                }
                Ok(ShieldedVkPolicyModeTag::Disabled)
            }
            Some("observe") => Ok(ShieldedVkPolicyModeTag::Observe),
            Some("require") => Ok(ShieldedVkPolicyModeTag::Require),
            Some(other) => anyhow::bail!(
                "invalid {} verifying key policy '{}': expected disabled|observe|require",
                label,
                other
            ),
            None => {
                if path.is_some() {
                    Ok(ShieldedVkPolicyModeTag::Require)
                } else {
                    Ok(ShieldedVkPolicyModeTag::Disabled)
                }
            }
        }
    }

    fn load_vk_bytes_with_policy(
        label: &str,
        expected_kind: ProofBackendKind,
        expected_version: CircuitVersion,
        policy: ShieldedVkPolicyModeTag,
        path: Option<&str>,
    ) -> anyhow::Result<Option<misaka_shielded::ParsedVerifyingKeyArtifact>> {
        match policy {
            ShieldedVkPolicyModeTag::Disabled => Ok(None),
            ShieldedVkPolicyModeTag::Observe => {
                let Some(path) = path else {
                    return Ok(None);
                };
                match std::fs::read(path) {
                    Ok(bytes) => {
                        match parse_verifying_key_artifact(&bytes, expected_kind, expected_version)
                        {
                            Ok(artifact) => Ok(Some(artifact)),
                            Err(e) => {
                                warn!(
                                    "ShieldedBootstrap: failed to parse {} verifying key artifact in observe mode {}: {}",
                                    label, path, e
                                );
                                Ok(None)
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            "ShieldedBootstrap: failed to read {} verifying key in observe mode {}: {}",
                            label, path, e
                        );
                        Ok(None)
                    }
                }
            }
            ShieldedVkPolicyModeTag::Require => {
                let Some(path) = path else {
                    anyhow::bail!(
                        "{} verifying key is required but no path was provided",
                        label
                    );
                };
                let bytes = std::fs::read(path).map_err(|e| {
                    anyhow::anyhow!("failed to read {} verifying key {}: {}", label, path, e)
                })?;
                let artifact =
                    parse_verifying_key_artifact(&bytes, expected_kind, expected_version).map_err(
                        |e| {
                            anyhow::anyhow!(
                                "failed to parse {} verifying key artifact {}: {}",
                                label,
                                path,
                                e
                            )
                        },
                    )?;
                Ok(Some(artifact))
            }
        }
    }

    /// 設定から shielded state を初期化する。
    /// disabled の場合は None を返す（transparent-only モード）。
    pub fn from_node_config(
        enabled: bool,
        testnet_mode: bool,
        max_anchor_age: u64,
        min_shielded_fee: u64,
        authoritative_target: Option<&str>,
        groth16_vk_policy: Option<&str>,
        groth16_vk_path: Option<&str>,
        plonk_vk_policy: Option<&str>,
        plonk_vk_path: Option<&str>,
    ) -> anyhow::Result<Option<SharedShieldedState>> {
        Self::from_node_config_with_adapters(
            enabled,
            testnet_mode,
            max_anchor_age,
            min_shielded_fee,
            authoritative_target,
            groth16_vk_policy,
            groth16_vk_path,
            plonk_vk_policy,
            plonk_vk_path,
            ShieldedVerifierAdapters::default(),
        )
    }

    pub fn from_node_config_with_adapters(
        enabled: bool,
        testnet_mode: bool,
        max_anchor_age: u64,
        min_shielded_fee: u64,
        authoritative_target: Option<&str>,
        groth16_vk_policy: Option<&str>,
        groth16_vk_path: Option<&str>,
        plonk_vk_policy: Option<&str>,
        plonk_vk_path: Option<&str>,
        adapters: ShieldedVerifierAdapters,
    ) -> anyhow::Result<Option<SharedShieldedState>> {
        if !enabled {
            info!("ShieldedBootstrap: DISABLED (transparent-only mode)");
            return Ok(None);
        }
        let config = ShieldedConfig {
            enabled: true,
            mempool_proof_verify: false,
            max_anchor_age_blocks: max_anchor_age,
            min_shielded_fee,
            testnet_mode,
        };
        let mut state = ShieldedState::new(config);
        if testnet_mode {
            state
                .register_stub_backend_for_testnet()
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            info!("ShieldedBootstrap: testnet stub backend registered (dev/testnet only)");
        } else {
            // C-1: Register SHA3 Merkle proof backend for production
            state.register_sha3_backend();
            info!("ShieldedBootstrap: SHA3 Merkle proof backend registered (production)");
        }
        let authoritative_target = Self::resolve_authoritative_target(authoritative_target)?;
        state.set_authoritative_target(authoritative_target.clone());

        let groth16_policy =
            Self::resolve_vk_policy("Groth16", groth16_vk_policy, groth16_vk_path)?;
        let plonk_policy = Self::resolve_vk_policy("PLONK", plonk_vk_policy, plonk_vk_path)?;
        let groth16_vk_artifact = Self::load_vk_bytes_with_policy(
            "Groth16",
            ProofBackendKind::Groth16,
            CircuitVersion::GROTH16_V1,
            groth16_policy,
            groth16_vk_path,
        )?;
        let plonk_vk_artifact = Self::load_vk_bytes_with_policy(
            "PLONK",
            ProofBackendKind::Plonk,
            CircuitVersion::PLONK_V1,
            plonk_policy,
            plonk_vk_path,
        )?;
        let groth16_vk_for_shell = groth16_vk_artifact.clone();
        let plonk_vk_for_shell = plonk_vk_artifact.clone();
        state.configure_groth16_shell_contract_from_artifact(groth16_policy, groth16_vk_for_shell);
        state.configure_plonk_shell_contract_from_artifact(plonk_policy, plonk_vk_for_shell);

        if let (Some(artifact), Some(adapter)) = (groth16_vk_artifact, adapters.groth16) {
            state.register_groth16_real_backend_from_artifact(artifact, adapter);
            info!("ShieldedBootstrap: Groth16 real-ready backend registered from startup seam");
        }
        if let (Some(artifact), Some(adapter)) = (plonk_vk_artifact, adapters.plonk) {
            state.register_plonk_real_backend_from_artifact(artifact, adapter);
            info!("ShieldedBootstrap: PLONK real-ready backend registered from startup seam");
        }
        info!(
            "ShieldedBootstrap: verifier contract configured (authoritative_target={:?}, groth16_policy={:?}, groth16_vk_loaded={}, plonk_policy={:?}, plonk_vk_loaded={})",
            authoritative_target,
            groth16_policy,
            groth16_vk_path.is_some(),
            plonk_policy,
            plonk_vk_path.is_some()
        );
        info!(
            "ShieldedBootstrap: ENABLED (testnet={}, anchor_age={}, min_fee={})",
            testnet_mode, max_anchor_age, min_shielded_fee
        );
        Ok(Some(Arc::new(RwLock::new(state))))
    }

    /// Load shielded state snapshot from disk if available.
    pub fn load_snapshot(shared: &SharedShieldedState, data_dir: &str) {
        let path = format!("{}/shielded_state.json", data_dir);
        if std::path::Path::new(&path).exists() {
            let mut state = shared.write();
            match state.load_snapshot(&path) {
                Ok(()) => info!("ShieldedBootstrap: restored snapshot from {}", path),
                Err(e) => warn!(
                    "ShieldedBootstrap: failed to load snapshot: {} — starting fresh",
                    e
                ),
            }
        } else {
            info!(
                "ShieldedBootstrap: no snapshot found at {} — starting fresh",
                path
            );
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use misaka_dag::ShieldedTxPayload;
    use misaka_shielded::{
        CircuitVersion, EncryptedNote, NoteCommitment, Nullifier, ProofBackend, ProofBackendKind,
        ProofError, ShieldDepositTx, ShieldedPublicInputs, MIN_SHIELDED_FEE, VK_ARTIFACT_SCHEMA_V1,
        VK_FINGERPRINT_ALGO_BLAKE3_V1,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Debug)]
    struct AcceptingGroth16Adapter;

    impl Groth16VerifierAdapter for AcceptingGroth16Adapter {
        fn verify(
            &self,
            _verifying_key_bytes: &[u8],
            _public_inputs: &ShieldedPublicInputs,
            _canonical_public_inputs: &[u8],
            _canonical_public_input_words: &[[u8; 32]],
            _payload: &misaka_shielded::ParsedGroth16ProofPayload,
        ) -> Result<(), ProofError> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct AcceptingPlonkAdapter;

    impl PlonkVerifierAdapter for AcceptingPlonkAdapter {
        fn verify(
            &self,
            _verifying_key_bytes: &[u8],
            _public_inputs: &ShieldedPublicInputs,
            _canonical_public_inputs: &[u8],
            _canonical_public_input_words: &[[u8; 32]],
            _payload: &misaka_shielded::ParsedPlonkProofPayload,
        ) -> Result<(), ProofError> {
            Ok(())
        }
    }

    fn build_vk_artifact(
        backend_kind: ProofBackendKind,
        circuit_version: CircuitVersion,
        verifying_key_bytes: &[u8],
    ) -> Vec<u8> {
        let tag = match backend_kind {
            ProofBackendKind::Groth16 => 1u8,
            ProofBackendKind::Plonk => 2u8,
            ProofBackendKind::Sha3Merkle => 3u8,
            ProofBackendKind::Sha3Transfer => 4u8,
            ProofBackendKind::Stub => 5u8,
        };
        let mut bytes = Vec::with_capacity(4 + 1 + 1 + 2 + 1 + 4 + verifying_key_bytes.len());
        bytes.extend_from_slice(b"MSVK");
        bytes.push(VK_ARTIFACT_SCHEMA_V1);
        bytes.push(tag);
        bytes.extend_from_slice(&circuit_version.0.to_le_bytes());
        bytes.push(VK_FINGERPRINT_ALGO_BLAKE3_V1);
        bytes.extend_from_slice(&(verifying_key_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(verifying_key_bytes);
        bytes
    }

    fn enabled_state() -> SharedShieldedState {
        ShieldedBootstrap::from_node_config(
            true,
            true,
            100,
            MIN_SHIELDED_FEE,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap()
        .unwrap()
    }

    fn deposit_payload() -> ShieldedTxPayload {
        use misaka_pqc::pq_sign::MlDsaKeypair;
        use sha3::{Digest, Sha3_256};

        // ML-DSA-65 キーペア生成 → 有効な署名付き deposit
        let kp = MlDsaKeypair::generate();
        let pubkey_bytes = kp.public_key.as_bytes().to_vec();
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:address:v1:");
        h.update(&pubkey_bytes);
        let hash = h.finalize();
        let mut from = [0u8; 32];
        from.copy_from_slice(&hash);

        let mut tx = ShieldDepositTx {
            from,
            amount: 1_000_000,
            asset_id: 0,
            fee: MIN_SHIELDED_FEE,
            output_commitment: NoteCommitment([0xAAu8; 32]),
            encrypted_note: EncryptedNote {
                epk: [0u8; 32],
                ciphertext: vec![0u8; 64],
                tag: [0u8; 16],
                view_tag: 0,
            },
            signature_bytes: vec![],
            sender_pubkey: pubkey_bytes,
        };
        let payload = tx.signing_payload();
        let sig = misaka_pqc::ml_dsa_sign(&kp.secret_key, &payload).expect("sign ok");
        tx.signature_bytes = sig.as_bytes().to_vec();

        ShieldedTxPayload::Deposit {
            tx_hash: [0xBBu8; 32],
            serialized: serde_json::to_vec(&tx).unwrap(),
        }
    }

    #[test]
    fn hook_applies_deposit() {
        let shared = enabled_state();
        let hook = NodeShieldedHook::new(shared.clone(), "/tmp");
        assert_eq!(shared.read().commitment_count(), 0);
        hook.on_block_committed(1, &[0u8; 32], &[deposit_payload()]);
        assert_eq!(shared.read().commitment_count(), 1);
    }

    #[test]
    fn hook_records_finalization_on_empty_block() {
        let shared = enabled_state();
        let hook = NodeShieldedHook::new(shared.clone(), "/tmp");
        let root_before = shared.read().current_root();
        hook.on_block_committed(5, &[0u8; 32], &[]);
        assert_eq!(shared.read().current_root(), root_before);
    }

    #[test]
    fn hook_releases_reservation_on_evict() {
        let shared = enabled_state();
        let hook = NodeShieldedHook::new(shared.clone(), "/tmp");
        let nf = Nullifier([0x42u8; 32]);
        let tx = [0x99u8; 32];
        shared.write().reserve_nullifiers(&[nf], tx).unwrap();
        assert!(shared.read().nullifier_set.is_reserved(&nf));
        hook.on_tx_evicted(&tx);
        assert!(!shared.read().nullifier_set.is_reserved(&nf));
    }

    #[test]
    fn bootstrap_disabled_returns_none() {
        assert!(ShieldedBootstrap::from_node_config(
            false, false, 100, 1000, None, None, None, None, None
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn bootstrap_testnet_registers_stub_backend_only_in_testnet_mode() {
        let shared = ShieldedBootstrap::from_node_config(
            true,
            true,
            100,
            MIN_SHIELDED_FEE,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap()
        .expect("enabled");

        let status = shared.read().layer4_status();
        assert_eq!(status.backend_selection_mode, "testnet_stub");
        assert_eq!(
            shared.read().accepted_circuit_versions(),
            vec![CircuitVersion::STUB_V1]
        );
        assert_eq!(status.registered_backends.len(), 1);
        assert_eq!(status.registered_backends[0].backend_id, "stub-v1");
    }

    #[test]
    fn bootstrap_loads_shell_vk_contract_without_expanding_acceptance() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let base = std::env::temp_dir().join(format!("misaka-shielded-vk-{}", unique));
        std::fs::create_dir_all(&base).expect("dir");
        let groth16_path = base.join("groth16.vk");
        std::fs::write(
            &groth16_path,
            build_vk_artifact(
                ProofBackendKind::Groth16,
                CircuitVersion::GROTH16_V1,
                &[1u8, 2, 3, 4],
            ),
        )
        .expect("write vk");

        let shared = ShieldedBootstrap::from_node_config(
            true,
            false,
            100,
            MIN_SHIELDED_FEE,
            Some("groth16"),
            None,
            Some(groth16_path.to_str().expect("path")),
            None,
            None,
        )
        .unwrap()
        .expect("enabled");

        let status = shared.read().layer4_status();
        assert_eq!(
            status.verifier_contract.authoritative_target,
            ShieldedAuthoritativeBackendTargetTag::Groth16
        );
        let groth16 = status
            .catalog_backends
            .iter()
            .find(|b| b.backend_id == "groth16-shell-v1")
            .expect("groth16");
        assert!(groth16.verifying_key_loaded);
        assert_eq!(
            status.verifier_contract.groth16_vk_policy,
            ShieldedVkPolicyModeTag::Require
        );
        assert!(status.verifier_contract.groth16_vk_fingerprint.is_some());
        assert_eq!(status.verifier_contract.groth16_vk_artifact_schema, Some(1));
        assert_eq!(
            status.verifier_contract.groth16_vk_fingerprint_algorithm,
            Some(1)
        );
        assert_eq!(
            status.verifier_contract.groth16_vk_artifact_payload_length,
            Some(4)
        );
        assert_eq!(status.verifier_contract.plonk_vk_artifact_schema, None);
        assert_eq!(
            status.verifier_contract.plonk_vk_fingerprint_algorithm,
            None
        );
        assert_eq!(
            status.verifier_contract.plonk_vk_artifact_payload_length,
            None
        );
        assert!(!status.groth16_plonk_ready);
        let versions = shared.read().accepted_circuit_versions();
        assert!(versions.contains(&misaka_shielded::CircuitVersion::SHA3_MERKLE_V1));
        assert!(versions.contains(&misaka_shielded::CircuitVersion::SHA3_TRANSFER_V2));
        assert!(versions.contains(&misaka_shielded::CircuitVersion::SHA3_TRANSFER_V3));
        assert!(!status
            .registered_backends
            .iter()
            .any(|b| b.backend_id == "stub-v1"));

        let _ = std::fs::remove_file(groth16_path);
        let _ = std::fs::remove_dir(base);
    }

    #[test]
    fn bootstrap_fails_closed_when_vk_path_is_missing() {
        let err = ShieldedBootstrap::from_node_config(
            true,
            false,
            100,
            MIN_SHIELDED_FEE,
            None,
            None,
            Some("/definitely/missing/groth16.vk"),
            None,
            None,
        )
        .expect_err("missing vk path must fail");
        let text = err.to_string();
        assert!(text.contains("Groth16"));
        assert!(text.contains("verifying key"));
    }

    #[test]
    fn bootstrap_fails_closed_when_vk_artifact_kind_mismatches() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let base = std::env::temp_dir().join(format!("misaka-shielded-vk-bad-{}", unique));
        std::fs::create_dir_all(&base).expect("dir");
        let path = base.join("groth16.vk");
        std::fs::write(
            &path,
            build_vk_artifact(
                ProofBackendKind::Plonk,
                CircuitVersion::PLONK_V1,
                &[1u8, 2, 3],
            ),
        )
        .expect("write vk");

        let err = ShieldedBootstrap::from_node_config(
            true,
            false,
            100,
            MIN_SHIELDED_FEE,
            None,
            None,
            Some(path.to_str().expect("path")),
            None,
            None,
        )
        .expect_err("kind mismatch must fail");
        assert!(err.to_string().contains("backend kind mismatch"));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir(base);
    }

    #[test]
    fn bootstrap_observe_mode_keeps_shell_unloaded_when_vk_is_missing() {
        let shared = ShieldedBootstrap::from_node_config(
            true,
            false,
            100,
            MIN_SHIELDED_FEE,
            Some("plonk"),
            Some("observe"),
            Some("/definitely/missing/groth16.vk"),
            None,
            None,
        )
        .expect("observe should not fail")
        .expect("enabled");

        let status = shared.read().layer4_status();
        assert_eq!(
            status.verifier_contract.authoritative_target,
            ShieldedAuthoritativeBackendTargetTag::Plonk
        );
        let groth16 = status
            .catalog_backends
            .iter()
            .find(|b| b.backend_id == "groth16-shell-v1")
            .expect("groth16");
        assert!(!groth16.verifying_key_loaded);
        assert_eq!(
            status.verifier_contract.groth16_vk_policy,
            ShieldedVkPolicyModeTag::Observe
        );
        assert_eq!(status.verifier_contract.groth16_vk_fingerprint, None);
        assert_eq!(status.verifier_contract.groth16_vk_artifact_schema, None);
        assert_eq!(
            status.verifier_contract.groth16_vk_fingerprint_algorithm,
            None
        );
        assert_eq!(
            status.verifier_contract.groth16_vk_artifact_payload_length,
            None
        );
        let versions = shared.read().accepted_circuit_versions();
        assert!(versions.contains(&misaka_shielded::CircuitVersion::SHA3_MERKLE_V1));
        assert!(versions.contains(&misaka_shielded::CircuitVersion::SHA3_TRANSFER_V2));
        assert!(versions.contains(&misaka_shielded::CircuitVersion::SHA3_TRANSFER_V3));
    }

    #[test]
    fn bootstrap_observe_mode_ignores_invalid_vk_artifact() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let base = std::env::temp_dir().join(format!("misaka-shielded-vk-observe-{}", unique));
        std::fs::create_dir_all(&base).expect("dir");
        let path = base.join("groth16-invalid.vk");
        std::fs::write(&path, [1u8, 2, 3]).expect("write invalid");

        let shared = ShieldedBootstrap::from_node_config(
            true,
            false,
            100,
            MIN_SHIELDED_FEE,
            Some("groth16"),
            Some("observe"),
            Some(path.to_str().expect("path")),
            None,
            None,
        )
        .expect("observe should not fail")
        .expect("enabled");

        let status = shared.read().layer4_status();
        let groth16 = status
            .catalog_backends
            .iter()
            .find(|b| b.backend_id == "groth16-shell-v1")
            .expect("groth16");
        assert!(!groth16.verifying_key_loaded);
        assert!(groth16.verifying_key_fingerprint.is_none());

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir(base);
    }

    #[test]
    fn bootstrap_disabled_policy_rejects_conflicting_vk_path() {
        let err = ShieldedBootstrap::from_node_config(
            true,
            false,
            100,
            MIN_SHIELDED_FEE,
            None,
            Some("disabled"),
            Some("/tmp/groth16.vk"),
            None,
            None,
        )
        .expect_err("disabled policy must reject conflicting path");
        assert!(err.to_string().contains("policy=disabled"));
    }

    #[test]
    fn bootstrap_rejects_invalid_authoritative_target() {
        let err = ShieldedBootstrap::from_node_config(
            true,
            false,
            100,
            MIN_SHIELDED_FEE,
            Some("bogus"),
            None,
            None,
            None,
            None,
        )
        .expect_err("invalid target must fail closed");
        assert!(err
            .to_string()
            .contains("invalid shielded authoritative target"));
    }

    #[test]
    fn startup_resolver_returns_empty_adapters_by_default() {
        let adapters = resolve_startup_verifier_adapters(false).expect("default resolver");
        assert!(adapters.groth16.is_none());
        assert!(adapters.plonk.is_none());
    }

    #[test]
    fn startup_verifier_contract_ignores_explicit_target_without_real_bootstrap() {
        validate_startup_verifier_adapter_contract(
            false,
            Some("plonk"),
            None,
            Some("/tmp/plonk.vk"),
            &ShieldedVerifierAdapters::default(),
        )
        .expect("real bootstrap disabled should not hard fail");
    }

    #[test]
    fn startup_verifier_contract_fails_closed_when_explicit_groth16_target_has_no_adapter() {
        let err = validate_startup_verifier_adapter_contract(
            true,
            Some("groth16"),
            Some("/tmp/groth16.vk"),
            None,
            &ShieldedVerifierAdapters::default(),
        )
        .expect_err("must fail closed");
        assert!(err
            .to_string()
            .contains("no compiled Groth16 verifier adapter"));
    }

    #[test]
    fn startup_verifier_contract_fails_closed_when_explicit_plonk_target_has_no_adapter() {
        let err = validate_startup_verifier_adapter_contract(
            true,
            Some("plonk"),
            None,
            Some("/tmp/plonk.vk"),
            &ShieldedVerifierAdapters::default(),
        )
        .expect_err("must fail closed");
        assert!(err
            .to_string()
            .contains("no compiled PLONK verifier adapter"));
    }

    #[test]
    fn startup_verifier_contract_allows_family_target_without_matching_single_adapter() {
        validate_startup_verifier_adapter_contract(
            true,
            Some("groth16_or_plonk"),
            Some("/tmp/groth16.vk"),
            None,
            &ShieldedVerifierAdapters::default(),
        )
        .expect("family target should remain allowed");
    }

    #[cfg(all(
        not(feature = "shielded-groth16-verifier"),
        not(feature = "shielded-plonk-verifier")
    ))]
    #[test]
    fn startup_resolver_fails_closed_when_real_bootstrap_is_requested_without_compiled_adapters() {
        let err = resolve_startup_verifier_adapters(true).expect_err("must fail closed");
        assert!(err
            .to_string()
            .contains("no production Groth16/PLONK verifier adapters are compiled"));
    }

    #[cfg(any(
        feature = "shielded-groth16-verifier",
        feature = "shielded-plonk-verifier"
    ))]
    #[test]
    fn startup_resolver_returns_compiled_adapters_when_feature_enabled() {
        let adapters = resolve_startup_verifier_adapters(true).expect("compiled adapters");
        #[cfg(feature = "shielded-groth16-verifier")]
        assert!(adapters.groth16.is_some());
        #[cfg(not(feature = "shielded-groth16-verifier"))]
        assert!(adapters.groth16.is_none());
        #[cfg(feature = "shielded-plonk-verifier")]
        assert!(adapters.plonk.is_some());
        #[cfg(not(feature = "shielded-plonk-verifier"))]
        assert!(adapters.plonk.is_none());
    }

    #[cfg(feature = "shielded-groth16-verifier")]
    #[test]
    fn bootstrap_with_compiled_groth16_adapter_registers_real_ready_backend_from_startup() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let base =
            std::env::temp_dir().join(format!("misaka-shielded-vk-compiled-groth16-{}", unique));
        std::fs::create_dir_all(&base).expect("dir");
        let groth16_path = base.join("groth16.vk");
        std::fs::write(
            &groth16_path,
            build_vk_artifact(
                ProofBackendKind::Groth16,
                CircuitVersion::GROTH16_V1,
                &crate::shielded_verifier_adapters::tests::sample_groth16_vk_bytes(),
            ),
        )
        .expect("write vk");

        let adapters = resolve_startup_verifier_adapters(true).expect("compiled adapters");
        let shared = ShieldedBootstrap::from_node_config_with_adapters(
            true,
            false,
            100,
            MIN_SHIELDED_FEE,
            Some("groth16"),
            None,
            Some(groth16_path.to_str().expect("path")),
            None,
            None,
            adapters,
        )
        .expect("bootstrap")
        .expect("enabled");

        let status = shared.read().layer4_status();
        assert!(status.groth16_plonk_ready);
        assert!(status.verifier_contract.authoritative_target_ready);
        assert!(shared
            .read()
            .accepted_circuit_versions()
            .contains(&CircuitVersion::GROTH16_V1));
        let groth16 = status
            .registered_backends
            .iter()
            .find(|b| b.backend_id == "groth16-v1")
            .expect("real groth16 backend");
        assert!(groth16.verifier_body_implemented);
        assert!(groth16.verifying_key_loaded);
        assert!(groth16.production_ready);

        let _ = std::fs::remove_file(groth16_path);
        let _ = std::fs::remove_dir(base);
    }

    #[cfg(feature = "shielded-plonk-verifier")]
    #[test]
    fn bootstrap_with_compiled_plonk_adapter_registers_real_ready_backend_from_startup() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let base =
            std::env::temp_dir().join(format!("misaka-shielded-vk-compiled-plonk-{}", unique));
        std::fs::create_dir_all(&base).expect("dir");
        let plonk_path = base.join("plonk.vk");
        std::fs::write(
            &plonk_path,
            build_vk_artifact(
                ProofBackendKind::Plonk,
                CircuitVersion::PLONK_V1,
                &crate::shielded_verifier_adapters::tests::sample_plonk_vk_bytes(),
            ),
        )
        .expect("write vk");

        let adapters = resolve_startup_verifier_adapters(true).expect("compiled adapters");
        let shared = ShieldedBootstrap::from_node_config_with_adapters(
            true,
            false,
            100,
            MIN_SHIELDED_FEE,
            Some("plonk"),
            None,
            None,
            None,
            Some(plonk_path.to_str().expect("path")),
            adapters,
        )
        .expect("bootstrap")
        .expect("enabled");

        let status = shared.read().layer4_status();
        assert!(status.groth16_plonk_ready);
        assert!(status.verifier_contract.authoritative_target_ready);
        assert!(shared
            .read()
            .accepted_circuit_versions()
            .contains(&CircuitVersion::PLONK_V1));
        let plonk = status
            .registered_backends
            .iter()
            .find(|b| b.backend_id == "plonk-v1")
            .expect("real plonk backend");
        assert!(plonk.verifier_body_implemented);
        assert!(plonk.verifying_key_loaded);
        assert!(plonk.production_ready);

        let _ = std::fs::remove_file(plonk_path);
        let _ = std::fs::remove_dir(base);
    }

    #[test]
    fn bootstrap_with_adapters_registers_real_ready_groth16_backend_from_startup() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let base = std::env::temp_dir().join(format!("misaka-shielded-vk-real-{}", unique));
        std::fs::create_dir_all(&base).expect("dir");
        let groth16_path = base.join("groth16.vk");
        std::fs::write(
            &groth16_path,
            build_vk_artifact(
                ProofBackendKind::Groth16,
                CircuitVersion::GROTH16_V1,
                &[9u8, 8, 7, 6],
            ),
        )
        .expect("write vk");

        let shared = ShieldedBootstrap::from_node_config_with_adapters(
            true,
            false,
            100,
            MIN_SHIELDED_FEE,
            Some("groth16"),
            None,
            Some(groth16_path.to_str().expect("path")),
            None,
            None,
            ShieldedVerifierAdapters {
                groth16: Some(Arc::new(AcceptingGroth16Adapter)),
                plonk: None,
            },
        )
        .expect("bootstrap")
        .expect("enabled");

        let status = shared.read().layer4_status();
        assert!(status.groth16_plonk_ready);
        assert!(status.verifier_contract.authoritative_target_ready);
        assert!(shared
            .read()
            .accepted_circuit_versions()
            .contains(&CircuitVersion::GROTH16_V1));
        let groth16 = status
            .registered_backends
            .iter()
            .find(|b| b.backend_id == "groth16-v1")
            .expect("real groth16 backend");
        assert!(groth16.verifier_body_implemented);
        assert!(groth16.verifying_key_loaded);
        assert!(groth16.production_ready);
        assert_eq!(
            groth16.phase,
            misaka_shielded::rpc_types::ShieldedProofBackendPhaseTag::Real
        );

        let _ = std::fs::remove_file(groth16_path);
        let _ = std::fs::remove_dir(base);
    }

    #[test]
    fn bootstrap_with_adapters_registers_real_ready_plonk_backend_from_startup() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let base = std::env::temp_dir().join(format!("misaka-shielded-vk-real-plonk-{}", unique));
        std::fs::create_dir_all(&base).expect("dir");
        let plonk_path = base.join("plonk.vk");
        std::fs::write(
            &plonk_path,
            build_vk_artifact(
                ProofBackendKind::Plonk,
                CircuitVersion::PLONK_V1,
                &[6u8, 7, 8, 9],
            ),
        )
        .expect("write vk");

        let shared = ShieldedBootstrap::from_node_config_with_adapters(
            true,
            false,
            100,
            MIN_SHIELDED_FEE,
            Some("plonk"),
            None,
            None,
            None,
            Some(plonk_path.to_str().expect("path")),
            ShieldedVerifierAdapters {
                groth16: None,
                plonk: Some(Arc::new(AcceptingPlonkAdapter)),
            },
        )
        .expect("bootstrap")
        .expect("enabled");

        let status = shared.read().layer4_status();
        assert!(status.groth16_plonk_ready);
        assert!(status.verifier_contract.authoritative_target_ready);
        assert!(shared
            .read()
            .accepted_circuit_versions()
            .contains(&CircuitVersion::PLONK_V1));
        let plonk = status
            .registered_backends
            .iter()
            .find(|b| b.backend_id == "plonk-v1")
            .expect("real plonk backend");
        assert!(plonk.verifier_body_implemented);
        assert!(plonk.verifying_key_loaded);
        assert!(plonk.production_ready);
        assert_eq!(
            plonk.phase,
            misaka_shielded::rpc_types::ShieldedProofBackendPhaseTag::Real
        );

        let _ = std::fs::remove_file(plonk_path);
        let _ = std::fs::remove_dir(base);
    }
}
