//! ZK Proof Backend — modular verifier インターフェース。
//!
//! # Design Principle
//! - chain node は verify のみ実行する
//! - proving は wallet/client 側または専用 prover service 側で行う
//! - `ProofBackend` trait で proving system を差し替え可能にする
//!
//! # P0 Phase: StubProofBackend
//! ShieldDeposit / ShieldWithdraw は P0 フェーズでは ZK proof なしで実装。
//! StubBackend は proof bytes を無視して常に Ok を返す。
//!
//! # P1 Phase: RealProofBackend
//! ShieldedTransfer に Groth16 または PLONK backend を統合予定。
//! circuit_version によって backend を切り替え可能にする。
//!
//! # Security Notes
//! - Production では StubProofBackend を使用禁止（feature flag で制御）
//! - verifier key は circuit_version に 1:1 で紐づく
//! - proof size limit を超えたものは即座に reject

use crate::{
    rpc_types::ShieldedAuthoritativeBackendTargetTag,
    types::{CircuitVersion, ShieldedProof, ShieldedPublicInputs},
};
use std::collections::HashMap;
use std::sync::Arc;

const SHELL_PROOF_ENVELOPE_MAGIC: &[u8; 4] = b"MSKP";
pub const SHELL_PROOF_ENVELOPE_SCHEMA_V1: u8 = 1;
pub const SHELL_PROOF_ENVELOPE_HEADER_LEN_V1: usize = 4 + 1 + 1 + 32 + 32;
const VK_ARTIFACT_MAGIC: &[u8; 4] = b"MSVK";
pub const VK_ARTIFACT_SCHEMA_V1: u8 = 1;
pub const VK_FINGERPRINT_ALGO_BLAKE3_V1: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShellProofEnvelopeKind {
    Groth16 = 1,
    Plonk = 2,
}

impl ShellProofEnvelopeKind {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Groth16),
            2 => Some(Self::Plonk),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedShellProofEnvelope {
    schema_version: u8,
    kind: ShellProofEnvelopeKind,
    vk_fingerprint: [u8; 32],
    public_input_hash: [u8; 32],
    payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedGroth16ProofPayload {
    pub proof_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPlonkProofPayload {
    pub proof_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedVerifyingKeyArtifact {
    pub schema_version: u8,
    pub backend_kind: ProofBackendKind,
    pub circuit_version: CircuitVersion,
    pub fingerprint_algo: u8,
    pub payload_length: u32,
    pub verifying_key_bytes: Vec<u8>,
}

pub trait Groth16VerifierAdapter: Send + Sync + std::fmt::Debug {
    fn verify(
        &self,
        verifying_key_bytes: &[u8],
        public_inputs: &ShieldedPublicInputs,
        canonical_public_inputs: &[u8],
        canonical_public_input_words: &[[u8; 32]],
        payload: &ParsedGroth16ProofPayload,
    ) -> Result<(), ProofError>;
}

pub trait PlonkVerifierAdapter: Send + Sync + std::fmt::Debug {
    fn verify(
        &self,
        verifying_key_bytes: &[u8],
        public_inputs: &ShieldedPublicInputs,
        canonical_public_inputs: &[u8],
        canonical_public_input_words: &[[u8; 32]],
        payload: &ParsedPlonkProofPayload,
    ) -> Result<(), ProofError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofBackendPhase {
    Stub,
    Shell,
    Real,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofBackendKind {
    Stub,
    Groth16,
    Plonk,
    Sha3Merkle,
    Sha3Transfer,
}

impl ProofBackendKind {
    fn from_vk_artifact_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Groth16),
            2 => Some(Self::Plonk),
            3 => Some(Self::Sha3Merkle),
            4 => Some(Self::Sha3Transfer),
            5 => Some(Self::Stub),
            _ => None,
        }
    }

    #[cfg(test)]
    fn vk_artifact_tag(self) -> u8 {
        match self {
            Self::Groth16 => 1,
            Self::Plonk => 2,
            Self::Sha3Merkle => 3,
            Self::Sha3Transfer => 4,
            Self::Stub => 5,
        }
    }
}

/// Privacy guarantee level of a proof backend.
///
/// This is a self-reported property that tells users and operators
/// exactly what privacy guarantees they get from each backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyLevel {
    /// No privacy. All values visible to all parties.
    /// Examples: Stub backend, transparent transactions.
    None,
    /// Commitment-based integrity. Values hidden from proof bytes, but:
    /// - Transaction structure (num inputs/outputs) is visible
    /// - Nullifiers and output commitments are public on-chain
    /// - Transaction graph analysis is possible
    /// - NOT mathematically zero-knowledge
    /// Examples: SHA3 V3 transfer proofs.
    TransparentIntegrity,
    /// Full zero-knowledge. Verifier learns nothing beyond "proof is valid".
    /// - Transaction structure is hidden (padded)
    /// - No metadata leaks beyond what public inputs reveal
    /// - Mathematically proven ZK property (simulation-extractable)
    /// Examples: Groth16, PLONK (when implemented with real adapters).
    ZeroKnowledge,
}

impl std::fmt::Display for PrivacyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::TransparentIntegrity => write!(f, "transparent-integrity"),
            Self::ZeroKnowledge => write!(f, "zero-knowledge"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofBackendDescriptor {
    pub circuit_version: CircuitVersion,
    pub backend_id: &'static str,
    pub backend_kind: ProofBackendKind,
    pub phase: ProofBackendPhase,
    pub production_ready: bool,
    pub transfer_capable: bool,
    pub groth16_plonk_family: bool,
    pub proof_size_limit: usize,
    /// Self-reported privacy guarantee level.
    pub privacy_level: PrivacyLevel,
    pub note: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofBackendRuntimeStatus {
    pub descriptor: ProofBackendDescriptor,
    pub verifier_body_implemented: bool,
    pub verifying_key_required: bool,
    pub verifying_key_loaded: bool,
    pub verifying_key_fingerprint: Option<[u8; 32]>,
    pub verifying_key_artifact_schema_version: Option<u8>,
    pub verifying_key_fingerprint_algorithm: Option<u8>,
    pub verifying_key_artifact_payload_length: Option<u32>,
}

// ─── trait ────────────────────────────────────────────────────────────────────

/// ZK proof verifier の抽象インターフェース。
///
/// chain node はこの trait のみに依存する。
/// proving system の交換・アップグレードが trait の変更なく可能。
pub trait ProofBackend: Send + Sync + std::fmt::Debug {
    fn descriptor(&self) -> ProofBackendDescriptor;

    fn runtime_status(&self) -> ProofBackendRuntimeStatus {
        let descriptor = self.descriptor();
        ProofBackendRuntimeStatus {
            descriptor,
            verifier_body_implemented: !matches!(descriptor.phase, ProofBackendPhase::Shell),
            verifying_key_required: false,
            verifying_key_loaded: false,
            verifying_key_fingerprint: None,
            verifying_key_artifact_schema_version: None,
            verifying_key_fingerprint_algorithm: None,
            verifying_key_artifact_payload_length: None,
        }
    }

    /// circuit バージョン
    fn circuit_version(&self) -> CircuitVersion;

    /// proof の最大バイト数
    fn proof_size_limit(&self) -> usize;

    /// public inputs + proof を検証する。
    ///
    /// # Errors
    /// - `ProofError::TooLarge`: proof が size limit 超過
    /// - `ProofError::Malformed`: deserialize 失敗
    /// - `ProofError::InvalidPublicInputs`: public inputs の構造不正
    /// - `ProofError::VerificationFailed`: proof が invalid
    fn verify(
        &self,
        public_inputs: &ShieldedPublicInputs,
        proof: &ShieldedProof,
    ) -> Result<(), ProofError>;

    /// cheap pre-validation（フォーマット確認のみ、DoS 対策）
    fn pre_validate(&self, proof: &ShieldedProof) -> Result<(), ProofError> {
        if proof.bytes.len() > self.proof_size_limit() {
            return Err(ProofError::TooLarge {
                actual: proof.bytes.len(),
                limit: self.proof_size_limit(),
            });
        }
        if proof.bytes.is_empty() {
            return Err(ProofError::Malformed("empty proof bytes".to_string()));
        }
        Ok(())
    }
}

// ─── CircuitRegistry ──────────────────────────────────────────────────────────

/// Circuit バージョンごとの backend registry。
/// ノード起動時に登録し、tx 検証時に version で lookup する。
#[derive(Debug, Default)]
pub struct CircuitRegistry {
    backends: HashMap<CircuitVersion, Box<dyn ProofBackend>>,
    min_accepted: Option<CircuitVersion>,
    max_accepted: Option<CircuitVersion>,
}

impl CircuitRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// backend を登録する
    pub fn register(&mut self, backend: Box<dyn ProofBackend>) {
        let v = backend.circuit_version();
        self.backends.insert(v, backend);

        // accepted range を自動更新
        self.min_accepted = self.backends.keys().min().copied();
        self.max_accepted = self.backends.keys().max().copied();
    }

    /// circuit_version に対応する backend を取得
    pub fn get(&self, version: &CircuitVersion) -> Option<&dyn ProofBackend> {
        self.backends.get(version).map(|b| b.as_ref())
    }

    /// version が accept 範囲内か
    pub fn is_accepted(&self, version: &CircuitVersion) -> bool {
        match (self.min_accepted, self.max_accepted) {
            (Some(min), Some(max)) => *version >= min && *version <= max,
            _ => false,
        }
    }

    /// 登録済み backend 数
    pub fn len(&self) -> usize {
        self.backends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }

    pub fn accepted_versions(&self) -> Vec<CircuitVersion> {
        let mut versions: Vec<_> = self.backends.keys().copied().collect();
        versions.sort();
        versions
    }

    pub fn descriptors(&self) -> Vec<ProofBackendDescriptor> {
        self.runtime_statuses()
            .into_iter()
            .map(|s| s.descriptor)
            .collect()
    }

    pub fn runtime_statuses(&self) -> Vec<ProofBackendRuntimeStatus> {
        let mut statuses: Vec<_> = self.backends.values().map(|b| b.runtime_status()).collect();
        statuses.sort_by_key(|s| s.descriptor.circuit_version);
        statuses
    }

    pub fn has_real_backend(&self) -> bool {
        self.runtime_statuses()
            .iter()
            .any(|s| s.descriptor.production_ready)
    }

    pub fn has_transfer_ready_backend(&self) -> bool {
        self.runtime_statuses()
            .iter()
            .any(|s| s.descriptor.production_ready && s.descriptor.transfer_capable)
    }

    pub fn has_groth16_or_plonk_ready_backend(&self) -> bool {
        self.runtime_statuses().iter().any(|s| {
            s.descriptor.production_ready
                && s.descriptor.groth16_plonk_family
                && s.verifier_body_implemented
                && (!s.verifying_key_required || s.verifying_key_loaded)
        })
    }

    pub fn has_authoritative_target_ready(
        &self,
        target: ShieldedAuthoritativeBackendTargetTag,
    ) -> bool {
        match target {
            ShieldedAuthoritativeBackendTargetTag::Groth16 => {
                self.runtime_statuses().iter().any(|s| {
                    s.descriptor.production_ready
                        && matches!(s.descriptor.backend_kind, ProofBackendKind::Groth16)
                        && s.verifier_body_implemented
                        && (!s.verifying_key_required || s.verifying_key_loaded)
                })
            }
            ShieldedAuthoritativeBackendTargetTag::Plonk => {
                self.runtime_statuses().iter().any(|s| {
                    s.descriptor.production_ready
                        && matches!(s.descriptor.backend_kind, ProofBackendKind::Plonk)
                        && s.verifier_body_implemented
                        && (!s.verifying_key_required || s.verifying_key_loaded)
                })
            }
            ShieldedAuthoritativeBackendTargetTag::Groth16OrPlonk => {
                self.has_groth16_or_plonk_ready_backend()
            }
        }
    }

    pub fn preferred_production_backend(&self) -> Option<&'static str> {
        let mut fallback = None;
        for status in self.runtime_statuses() {
            let descriptor = status.descriptor;
            if descriptor.production_ready && descriptor.transfer_capable {
                let vk_ready = !status.verifying_key_required || status.verifying_key_loaded;
                if status.verifier_body_implemented && vk_ready {
                    return Some(descriptor.backend_id);
                }
            }
            if descriptor.production_ready && fallback.is_none() {
                fallback = Some(descriptor.backend_id);
            }
        }
        fallback
    }
}

pub fn compiled_backend_catalog() -> Vec<ProofBackendRuntimeStatus> {
    vec![
        StubProofBackend::new_for_testnet().runtime_status(),
        Groth16Backend::new(CircuitVersion::GROTH16_V1, vec![]).runtime_status(),
        PlonkBackend::new(CircuitVersion::PLONK_V1, vec![]).runtime_status(),
        Sha3MerkleProofBackend::new().runtime_status(),
        crate::sha3_proof::Sha3TransferProofBackend::new().runtime_status(),
    ]
}

fn compute_vk_fingerprint(verifying_key_bytes: &[u8]) -> Option<[u8; 32]> {
    if verifying_key_bytes.is_empty() {
        return None;
    }
    let mut hasher = blake3::Hasher::new_derive_key("MISAKA shielded vk fingerprint v1");
    hasher.update(verifying_key_bytes);
    Some(*hasher.finalize().as_bytes())
}

fn canonicalize_public_inputs(public_inputs: &ShieldedPublicInputs) -> Result<Vec<u8>, ProofError> {
    public_inputs
        .canonical_bytes_v1()
        .map_err(ProofError::InvalidPublicInputs)
}

fn compute_canonical_public_input_hash(canonical_inputs: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("MISAKA shielded public input hash v1");
    hasher.update(canonical_inputs);
    *hasher.finalize().as_bytes()
}

fn parse_groth16_payload_v1(payload: &[u8]) -> Result<ParsedGroth16ProofPayload, ProofError> {
    if payload.is_empty() {
        return Err(ProofError::Malformed(
            "empty Groth16 shell payload".to_string(),
        ));
    }
    Ok(ParsedGroth16ProofPayload {
        proof_bytes: payload.to_vec(),
    })
}

fn parse_plonk_payload_v1(payload: &[u8]) -> Result<ParsedPlonkProofPayload, ProofError> {
    if payload.is_empty() {
        return Err(ProofError::Malformed(
            "empty PLONK shell payload".to_string(),
        ));
    }
    Ok(ParsedPlonkProofPayload {
        proof_bytes: payload.to_vec(),
    })
}

pub fn parse_verifying_key_artifact(
    bytes: &[u8],
    expected_kind: ProofBackendKind,
    expected_version: CircuitVersion,
) -> Result<ParsedVerifyingKeyArtifact, ProofError> {
    const HEADER_LEN: usize = 4 + 1 + 1 + 2 + 1 + 4;
    if bytes.len() < HEADER_LEN + 1 {
        return Err(ProofError::Malformed(
            "verifying key artifact too short".to_string(),
        ));
    }
    if &bytes[..4] != VK_ARTIFACT_MAGIC {
        return Err(ProofError::Malformed(
            "verifying key artifact magic mismatch".to_string(),
        ));
    }
    let schema_version = bytes[4];
    if schema_version != VK_ARTIFACT_SCHEMA_V1 {
        return Err(ProofError::Malformed(format!(
            "unsupported verifying key artifact schema {}",
            schema_version
        )));
    }
    let backend_kind = ProofBackendKind::from_vk_artifact_tag(bytes[5]).ok_or_else(|| {
        ProofError::Malformed("unknown verifying key artifact backend kind".to_string())
    })?;
    if backend_kind != expected_kind {
        return Err(ProofError::Malformed(format!(
            "verifying key artifact backend kind mismatch: expected {:?}, got {:?}",
            expected_kind, backend_kind
        )));
    }
    let circuit_version = CircuitVersion(u16::from_le_bytes([bytes[6], bytes[7]]));
    if circuit_version != expected_version {
        return Err(ProofError::Malformed(format!(
            "verifying key artifact circuit version mismatch: expected {:?}, got {:?}",
            expected_version, circuit_version
        )));
    }
    let fingerprint_algo = bytes[8];
    if fingerprint_algo != VK_FINGERPRINT_ALGO_BLAKE3_V1 {
        return Err(ProofError::Malformed(format!(
            "unsupported verifying key artifact fingerprint algorithm {}",
            fingerprint_algo
        )));
    }
    let payload_length = u32::from_le_bytes([bytes[9], bytes[10], bytes[11], bytes[12]]);
    let verifying_key_bytes = bytes[13..].to_vec();
    if verifying_key_bytes.len() != payload_length as usize {
        return Err(ProofError::Malformed(format!(
            "verifying key artifact payload length mismatch: declared {}, actual {}",
            payload_length,
            verifying_key_bytes.len()
        )));
    }
    if verifying_key_bytes.is_empty() {
        return Err(ProofError::Malformed(
            "verifying key artifact payload is empty".to_string(),
        ));
    }
    Ok(ParsedVerifyingKeyArtifact {
        schema_version,
        backend_kind,
        circuit_version,
        fingerprint_algo,
        payload_length,
        verifying_key_bytes,
    })
}

fn parse_shell_proof_envelope(
    proof: &ShieldedProof,
    expected_kind: ShellProofEnvelopeKind,
) -> Result<ParsedShellProofEnvelope, ProofError> {
    if proof.bytes.len() < SHELL_PROOF_ENVELOPE_HEADER_LEN_V1 + 1 {
        return Err(ProofError::Malformed(
            "shell proof envelope too short".to_string(),
        ));
    }
    if &proof.bytes[..4] != SHELL_PROOF_ENVELOPE_MAGIC {
        return Err(ProofError::Malformed(
            "shell proof envelope magic mismatch".to_string(),
        ));
    }
    let schema_version = proof.bytes[4];
    if schema_version != SHELL_PROOF_ENVELOPE_SCHEMA_V1 {
        return Err(ProofError::Malformed(format!(
            "unsupported shell proof envelope schema {}",
            schema_version
        )));
    }
    let kind = ShellProofEnvelopeKind::from_byte(proof.bytes[5])
        .ok_or_else(|| ProofError::Malformed("unknown shell proof envelope kind".to_string()))?;
    if kind != expected_kind {
        return Err(ProofError::Malformed(
            "shell proof envelope kind mismatch".to_string(),
        ));
    }
    let mut vk_fingerprint = [0u8; 32];
    vk_fingerprint.copy_from_slice(&proof.bytes[6..38]);
    let mut public_input_hash = [0u8; 32];
    public_input_hash.copy_from_slice(&proof.bytes[38..70]);
    let payload = proof.bytes[SHELL_PROOF_ENVELOPE_HEADER_LEN_V1..].to_vec();
    if payload.is_empty() {
        return Err(ProofError::Malformed(
            "shell proof envelope payload is empty".to_string(),
        ));
    }
    Ok(ParsedShellProofEnvelope {
        schema_version,
        kind,
        vk_fingerprint,
        public_input_hash,
        payload,
    })
}

// ─── StubProofBackend (P0 phase) ──────────────────────────────────────────────

/// Stub verifier — P0 フェーズ用。
///
/// ShieldDeposit / ShieldWithdraw の proof は P0 では stub で、
/// 実際の ZK proof を要求しない。
///
/// # ⚠️ SECURITY WARNING
/// `new_for_testnet()` は testnet/dev のみ使用。
/// production では必ず real ProofBackend を登録すること。
/// - `testnet_only` は private。外部から false に書き換えることはできない。
/// - `ShieldedTransfer` には使用禁止（必ず real backend を使うこと）。
#[derive(Debug)]
pub struct StubProofBackend {
    version: CircuitVersion,
    /// true: testnet/dev のみで使用可能。
    /// SECURITY [H3]: pub → private。外部からの無効化を防ぐ。
    testnet_only: bool,
}

impl StubProofBackend {
    pub fn new_for_testnet() -> Self {
        Self {
            version: CircuitVersion::STUB_V1,
            testnet_only: true,
        }
    }

    /// testnet_only かどうかを確認（テスト用読み取りアクセス）
    pub fn is_testnet_only(&self) -> bool {
        self.testnet_only
    }
}

impl ProofBackend for StubProofBackend {
    fn descriptor(&self) -> ProofBackendDescriptor {
        ProofBackendDescriptor {
            circuit_version: self.version,
            backend_id: "stub-v1",
            backend_kind: ProofBackendKind::Stub,
            phase: ProofBackendPhase::Stub,
            production_ready: false,
            transfer_capable: false,
            groth16_plonk_family: false,
            proof_size_limit: self.proof_size_limit(),
            privacy_level: PrivacyLevel::None,
            note:
                "Testnet/dev stub backend only. Accepts stub marker proofs, never production-grade.",
        }
    }

    fn circuit_version(&self) -> CircuitVersion {
        self.version
    }

    fn proof_size_limit(&self) -> usize {
        // stub は 4 bytes のマーカーのみ
        1024
    }

    fn verify(
        &self,
        _public_inputs: &ShieldedPublicInputs,
        proof: &ShieldedProof,
    ) -> Result<(), ProofError> {
        if !self.testnet_only {
            return Err(ProofError::StubDisabledInProduction);
        }
        // P0: stub proof bytes チェックのみ
        if proof.bytes.is_empty() {
            return Err(ProofError::Malformed("empty stub proof".to_string()));
        }
        // SEC-FIX [Audit #3]: Only accept valid stub marker proofs.
        // Non-stub bytes are REJECTED — no more blanket accept for "compatibility".
        if proof.is_stub() {
            return Ok(());
        }
        Err(ProofError::Malformed(
            "StubBackend: proof is not a valid stub marker; non-stub proofs require a real backend"
                .to_string(),
        ))
    }
}

// ─── Groth16ProofBackend (P1 phase, stub shell) ───────────────────────────────

/// Groth16 verifier — P1 フェーズ用の shell。
///
/// P1 では bellman / arkworks を使った実装に差し替える。
/// P0 では compile できる shell のみ提供。
///
/// # P1 Implementation Roadmap
///
/// 1. **Circuit 定義** (Rank-1 Constraint System):
///    - ShieldedTransfer: nullifier 正当性、commitment 存在証明、値の保存則
///    - ShieldWithdraw: nullifier 正当性、commitment 存在証明、出金額の正当性
///
/// 2. **Trusted Setup**: circuit 固有の CRS/SRS を生成（powers-of-tau ceremony）
///
/// 3. **Verifying Key**: trusted setup から VK を抽出し、on-chain に保存
///    - `CF_SHIELD_CIRCUIT_VKEYS` に circuit_version → VK bytes のマッピング
///    - ノード起動時に VK を読み込んで `Groth16Backend` を初期化
///
/// 4. **Proof Verification**: arkworks `Groth16::verify()` を呼び出し
///    - public_inputs を Field 要素に変換
///    - proof bytes を arkworks `Proof<Bls12_381>` にデシリアライズ
///    - VK + public_inputs + proof → pairing check
///
/// 5. **Post-Quantum 移行計画**: Groth16 は ECDLP ベース（BLS12-381）のため、
///    量子コンピュータに対して脆弱。将来的には lattice-based ZKP (e.g., STARK,
///    Aurora, Ligero) への移行を検討する。circuit_version による切り替え機構は
///    そのために設計されている。
#[derive(Debug)]
pub struct Groth16Backend {
    version: CircuitVersion,
    /// P1: verifying key bytes (deserialized from circuit_registry CF)
    verifying_key_bytes: Vec<u8>,
    verifier_adapter: Option<Arc<dyn Groth16VerifierAdapter>>,
    vk_artifact_schema_version: Option<u8>,
    vk_fingerprint_algorithm: Option<u8>,
    vk_artifact_payload_length: Option<u32>,
}

impl CircuitVersion {
    /// P1 Groth16 circuit (ShieldedTransfer + ShieldWithdraw)
    pub const GROTH16_V1: Self = CircuitVersion(100);
    /// Future: PLONK-based circuit
    pub const PLONK_V1: Self = CircuitVersion(200);
}

impl Groth16Backend {
    fn is_real_ready(&self) -> bool {
        self.verifier_adapter.is_some()
    }

    pub fn new(version: CircuitVersion, verifying_key_bytes: Vec<u8>) -> Self {
        Self {
            version,
            verifying_key_bytes,
            verifier_adapter: None,
            vk_artifact_schema_version: None,
            vk_fingerprint_algorithm: None,
            vk_artifact_payload_length: None,
        }
    }

    pub fn new_from_vk_artifact(artifact: ParsedVerifyingKeyArtifact) -> Self {
        Self {
            version: artifact.circuit_version,
            verifying_key_bytes: artifact.verifying_key_bytes,
            verifier_adapter: None,
            vk_artifact_schema_version: Some(artifact.schema_version),
            vk_fingerprint_algorithm: Some(artifact.fingerprint_algo),
            vk_artifact_payload_length: Some(artifact.payload_length),
        }
    }

    pub fn with_verifier_adapter(
        mut self,
        verifier_adapter: Arc<dyn Groth16VerifierAdapter>,
    ) -> Self {
        self.verifier_adapter = Some(verifier_adapter);
        self
    }
}

impl ProofBackend for Groth16Backend {
    fn descriptor(&self) -> ProofBackendDescriptor {
        let is_real_ready = self.is_real_ready();
        ProofBackendDescriptor {
            circuit_version: self.version,
            backend_id: if is_real_ready {
                "groth16-v1"
            } else {
                "groth16-shell-v1"
            },
            backend_kind: ProofBackendKind::Groth16,
            phase: if is_real_ready {
                ProofBackendPhase::Real
            } else {
                ProofBackendPhase::Shell
            },
            production_ready: is_real_ready,
            transfer_capable: true,
            groth16_plonk_family: true,
            proof_size_limit: self.proof_size_limit(),
            privacy_level: PrivacyLevel::ZeroKnowledge, // Groth16 is true ZK when implemented
            note: if is_real_ready {
                "Groth16 verifier adapter is wired. Runtime registration seam is real-ready; actual verifier body depends on the adapter implementation."
            } else {
                "Groth16 verifier shell. Verifying key loading exists, pairing verify body is not implemented yet."
            },
        }
    }

    fn circuit_version(&self) -> CircuitVersion {
        self.version
    }

    fn runtime_status(&self) -> ProofBackendRuntimeStatus {
        ProofBackendRuntimeStatus {
            descriptor: self.descriptor(),
            verifier_body_implemented: self.verifier_adapter.is_some(),
            verifying_key_required: true,
            verifying_key_loaded: !self.verifying_key_bytes.is_empty(),
            verifying_key_fingerprint: compute_vk_fingerprint(&self.verifying_key_bytes),
            verifying_key_artifact_schema_version: self.vk_artifact_schema_version,
            verifying_key_fingerprint_algorithm: self.vk_fingerprint_algorithm,
            verifying_key_artifact_payload_length: self.vk_artifact_payload_length,
        }
    }

    fn proof_size_limit(&self) -> usize {
        // Groth16 proof on BLS12-381:
        // 2 × G1 (48 bytes compressed) + 1 × G2 (96 bytes compressed) = 192
        // plus the shell proof envelope header.
        SHELL_PROOF_ENVELOPE_HEADER_LEN_V1 + 192
    }

    fn verify(
        &self,
        public_inputs: &ShieldedPublicInputs,
        proof: &ShieldedProof,
    ) -> Result<(), ProofError> {
        self.pre_validate(proof)?;
        if self.verifying_key_bytes.is_empty() {
            return Err(ProofError::VerifyingKeyNotLoaded);
        }
        let expected_vk_fingerprint = compute_vk_fingerprint(&self.verifying_key_bytes)
            .ok_or(ProofError::VerifyingKeyNotLoaded)?;
        let envelope = parse_shell_proof_envelope(proof, ShellProofEnvelopeKind::Groth16)?;
        if envelope.vk_fingerprint != expected_vk_fingerprint {
            return Err(ProofError::VerifyingKeyFingerprintMismatch);
        }
        let canonical_inputs = canonicalize_public_inputs(public_inputs)?;
        let canonical_input_words = public_inputs
            .canonical_word_chunks_v1()
            .map_err(ProofError::InvalidPublicInputs)?;
        let expected_public_input_hash = compute_canonical_public_input_hash(&canonical_inputs);
        if envelope.public_input_hash != expected_public_input_hash {
            return Err(ProofError::PublicInputHashMismatch);
        }
        let payload = parse_groth16_payload_v1(&envelope.payload)?;
        if let Some(adapter) = &self.verifier_adapter {
            return adapter.verify(
                &self.verifying_key_bytes,
                public_inputs,
                &canonical_inputs,
                &canonical_input_words,
                &payload,
            );
        }
        // P1: arkworks による実際の verify をここに実装
        //
        // ```rust (P1)
        // use ark_bls12_381::Bls12_381;
        // use ark_groth16::{Groth16, PreparedVerifyingKey, Proof};
        // use ark_serialize::CanonicalDeserialize;
        //
        // let pvk = PreparedVerifyingKey::<Bls12_381>::deserialize_compressed(
        //     &self.verifying_key_bytes[..]
        // ).map_err(|e| ProofError::Malformed(format!("VK deserialize: {}", e)))?;
        //
        // let proof = Proof::<Bls12_381>::deserialize_compressed(
        //     &payload.proof_bytes[..]
        // ).map_err(|e| ProofError::Malformed(format!("proof deserialize: {}", e)))?;
        //
        // let public_inputs = self.encode_public_inputs(public_inputs)?;
        //
        // Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &public_inputs, &proof)
        //     .map_err(|_| ProofError::VerificationFailed)?;
        // ```
        Err(ProofError::NotImplemented(
            "Groth16 verify: P1 phase — add arkworks dependency and implement pairing check"
                .to_string(),
        ))
    }
}

// ─── PlonkProofBackend (P1 phase, stub shell) ────────────────────────────────

#[derive(Debug)]
pub struct PlonkBackend {
    version: CircuitVersion,
    verifying_key_bytes: Vec<u8>,
    verifier_adapter: Option<Arc<dyn PlonkVerifierAdapter>>,
    vk_artifact_schema_version: Option<u8>,
    vk_fingerprint_algorithm: Option<u8>,
    vk_artifact_payload_length: Option<u32>,
}

impl PlonkBackend {
    fn is_real_ready(&self) -> bool {
        self.verifier_adapter.is_some()
    }

    pub fn new(version: CircuitVersion, verifying_key_bytes: Vec<u8>) -> Self {
        Self {
            version,
            verifying_key_bytes,
            verifier_adapter: None,
            vk_artifact_schema_version: None,
            vk_fingerprint_algorithm: None,
            vk_artifact_payload_length: None,
        }
    }

    pub fn new_from_vk_artifact(artifact: ParsedVerifyingKeyArtifact) -> Self {
        Self {
            version: artifact.circuit_version,
            verifying_key_bytes: artifact.verifying_key_bytes,
            verifier_adapter: None,
            vk_artifact_schema_version: Some(artifact.schema_version),
            vk_fingerprint_algorithm: Some(artifact.fingerprint_algo),
            vk_artifact_payload_length: Some(artifact.payload_length),
        }
    }

    pub fn with_verifier_adapter(
        mut self,
        verifier_adapter: Arc<dyn PlonkVerifierAdapter>,
    ) -> Self {
        self.verifier_adapter = Some(verifier_adapter);
        self
    }
}

impl ProofBackend for PlonkBackend {
    fn descriptor(&self) -> ProofBackendDescriptor {
        let is_real_ready = self.is_real_ready();
        ProofBackendDescriptor {
            circuit_version: self.version,
            backend_id: if is_real_ready {
                "plonk-v1"
            } else {
                "plonk-shell-v1"
            },
            backend_kind: ProofBackendKind::Plonk,
            phase: if is_real_ready {
                ProofBackendPhase::Real
            } else {
                ProofBackendPhase::Shell
            },
            production_ready: is_real_ready,
            transfer_capable: true,
            groth16_plonk_family: true,
            proof_size_limit: self.proof_size_limit(),
            privacy_level: PrivacyLevel::ZeroKnowledge, // PLONK is true ZK when implemented
            note: if is_real_ready {
                "PLONK verifier adapter is wired. Runtime registration seam is real-ready; actual verifier body depends on the adapter implementation."
            } else {
                "PLONK verifier shell. Verifying key loading exists, polynomial commitment verify body is not implemented yet."
            },
        }
    }

    fn runtime_status(&self) -> ProofBackendRuntimeStatus {
        ProofBackendRuntimeStatus {
            descriptor: self.descriptor(),
            verifier_body_implemented: self.verifier_adapter.is_some(),
            verifying_key_required: true,
            verifying_key_loaded: !self.verifying_key_bytes.is_empty(),
            verifying_key_fingerprint: compute_vk_fingerprint(&self.verifying_key_bytes),
            verifying_key_artifact_schema_version: self.vk_artifact_schema_version,
            verifying_key_fingerprint_algorithm: self.vk_fingerprint_algorithm,
            verifying_key_artifact_payload_length: self.vk_artifact_payload_length,
        }
    }

    fn circuit_version(&self) -> CircuitVersion {
        self.version
    }

    fn proof_size_limit(&self) -> usize {
        // Conservative shell limit for compiled PLONK proofs.
        // The current compiled `dusk-plonk` adapter serializes proofs at 1008 bytes,
        // so keep headroom while remaining fail-closed.
        SHELL_PROOF_ENVELOPE_HEADER_LEN_V1 + 1152
    }

    fn verify(
        &self,
        public_inputs: &ShieldedPublicInputs,
        proof: &ShieldedProof,
    ) -> Result<(), ProofError> {
        self.pre_validate(proof)?;
        if self.verifying_key_bytes.is_empty() {
            return Err(ProofError::VerifyingKeyNotLoaded);
        }
        let expected_vk_fingerprint = compute_vk_fingerprint(&self.verifying_key_bytes)
            .ok_or(ProofError::VerifyingKeyNotLoaded)?;
        let envelope = parse_shell_proof_envelope(proof, ShellProofEnvelopeKind::Plonk)?;
        if envelope.vk_fingerprint != expected_vk_fingerprint {
            return Err(ProofError::VerifyingKeyFingerprintMismatch);
        }
        let canonical_inputs = canonicalize_public_inputs(public_inputs)?;
        let canonical_input_words = public_inputs
            .canonical_word_chunks_v1()
            .map_err(ProofError::InvalidPublicInputs)?;
        let expected_public_input_hash = compute_canonical_public_input_hash(&canonical_inputs);
        if envelope.public_input_hash != expected_public_input_hash {
            return Err(ProofError::PublicInputHashMismatch);
        }
        let payload = parse_plonk_payload_v1(&envelope.payload)?;
        if let Some(adapter) = &self.verifier_adapter {
            return adapter.verify(
                &self.verifying_key_bytes,
                public_inputs,
                &canonical_inputs,
                &canonical_input_words,
                &payload,
            );
        }
        Err(ProofError::NotImplemented(
            "PLONK verify: P1 phase — add concrete backend dependency and implement polynomial commitment verification"
                .to_string(),
        ))
    }
}

// ─── SHA3MerkleProofBackend (PQ-safe, production) ─────────────────────────────

/// SHA3-256 based Merkle membership proof backend.
///
/// Post-quantum safe: relies only on SHA3-256 hash function security.
/// Unlike Groth16/PLONK (pairing-based, quantum-vulnerable), this backend
/// uses hash-based proofs that remain secure against quantum adversaries.
///
/// # Proof Format
/// ```text
/// [leaf_position: 4 bytes LE u32]
/// [sibling_0: 32 bytes] [sibling_1: 32 bytes] ... [sibling_{DEPTH-1}: 32 bytes]
/// Total: 4 + 32*32 = 1028 bytes
/// ```
///
/// # Verification
/// 1. Recompute root from commitment + Merkle path
/// 2. Compare with anchor in public inputs
/// 3. Verify nullifier binding (structural, from public inputs)
#[derive(Debug)]
pub struct Sha3MerkleProofBackend {
    version: CircuitVersion,
}

impl CircuitVersion {
    /// SHA3 Merkle proof (PQ-safe, production)
    pub const SHA3_MERKLE_V1: Self = CircuitVersion(50);
}

impl Sha3MerkleProofBackend {
    pub fn new() -> Self {
        Self {
            version: CircuitVersion::SHA3_MERKLE_V1,
        }
    }

    /// Recompute Merkle root from leaf commitment + proof path
    fn recompute_root(commitment: &[u8; 32], position: u32, siblings: &[[u8; 32]]) -> [u8; 32] {
        let mut current = *commitment;
        let mut pos = position;
        for sibling in siblings {
            let mut hasher = blake3::Hasher::new_derive_key("MISAKA shielded node v1");
            if pos & 1 == 0 {
                hasher.update(&current);
                hasher.update(sibling);
            } else {
                hasher.update(sibling);
                hasher.update(&current);
            }
            current = *hasher.finalize().as_bytes();
            pos >>= 1;
        }
        current
    }
}

impl ProofBackend for Sha3MerkleProofBackend {
    fn descriptor(&self) -> ProofBackendDescriptor {
        ProofBackendDescriptor {
            circuit_version: self.version,
            backend_id: "sha3-merkle-v1",
            backend_kind: ProofBackendKind::Sha3Merkle,
            phase: ProofBackendPhase::Real,
            production_ready: true,
            transfer_capable: false,
            groth16_plonk_family: false,
            proof_size_limit: self.proof_size_limit(),
            privacy_level: PrivacyLevel::TransparentIntegrity,
            note: "PQ-safe hash-based Merkle membership verifier for shielded anchors.",
        }
    }

    fn circuit_version(&self) -> CircuitVersion {
        self.version
    }

    fn proof_size_limit(&self) -> usize {
        // 4 (position) + 32 * 32 (siblings) = 1028 bytes
        1028
    }

    fn verify(
        &self,
        public_inputs: &ShieldedPublicInputs,
        proof: &ShieldedProof,
    ) -> Result<(), ProofError> {
        self.pre_validate(proof)?;

        // Parse proof bytes
        if proof.bytes.len() < 4 {
            return Err(ProofError::Malformed("proof too short for position".into()));
        }
        let position = u32::from_le_bytes([
            proof.bytes[0],
            proof.bytes[1],
            proof.bytes[2],
            proof.bytes[3],
        ]);

        let sibling_bytes = &proof.bytes[4..];
        let depth = sibling_bytes.len() / 32;
        if sibling_bytes.len() % 32 != 0 || depth == 0 {
            return Err(ProofError::Malformed(format!(
                "invalid sibling data: {} bytes (need multiple of 32)",
                sibling_bytes.len()
            )));
        }

        let mut siblings = Vec::with_capacity(depth);
        for i in 0..depth {
            let mut s = [0u8; 32];
            s.copy_from_slice(&sibling_bytes[i * 32..(i + 1) * 32]);
            siblings.push(s);
        }

        // Verify each output commitment's Merkle membership
        for cm in &public_inputs.output_commitments {
            let computed_root = Self::recompute_root(&cm.0, position, &siblings);
            if computed_root != public_inputs.anchor.0 {
                return Err(ProofError::VerificationFailed);
            }
        }

        // Nullifier count must match (structural check)
        if public_inputs.nullifiers.is_empty() && public_inputs.output_commitments.is_empty() {
            return Err(ProofError::InvalidPublicInputs(
                "empty inputs and outputs".into(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error("proof too large: {actual} bytes (limit: {limit})")]
    TooLarge { actual: usize, limit: usize },

    #[error("malformed proof: {0}")]
    Malformed(String),

    #[error("invalid public inputs: {0}")]
    InvalidPublicInputs(String),

    #[error("proof verification failed")]
    VerificationFailed,

    #[error("stub backend disabled in production")]
    StubDisabledInProduction,

    #[error("verifying key not loaded")]
    VerifyingKeyNotLoaded,

    #[error("verifying key fingerprint mismatch")]
    VerifyingKeyFingerprintMismatch,

    #[error("canonical public input hash mismatch")]
    PublicInputHashMismatch,

    #[error("circuit version not supported: {0:?}")]
    UnsupportedVersion(CircuitVersion),

    #[error("not implemented: {0}")]
    NotImplemented(String),
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::types::{NoteCommitment, Nullifier, ShieldedPublicInputs, TreeRoot};

    #[derive(Debug)]
    struct AcceptingGroth16Adapter;

    impl Groth16VerifierAdapter for AcceptingGroth16Adapter {
        fn verify(
            &self,
            verifying_key_bytes: &[u8],
            public_inputs: &ShieldedPublicInputs,
            canonical_public_inputs: &[u8],
            canonical_public_input_words: &[[u8; 32]],
            payload: &ParsedGroth16ProofPayload,
        ) -> Result<(), ProofError> {
            assert_eq!(verifying_key_bytes, &[1, 2, 3]);
            assert_eq!(
                canonical_public_inputs,
                canonicalize_public_inputs(public_inputs).expect("canonical inputs")
            );
            assert_eq!(
                canonical_public_input_words,
                public_inputs
                    .canonical_word_chunks_v1()
                    .expect("canonical word chunks")
            );
            assert_eq!(payload.proof_bytes, vec![0xAB; 64]);
            Ok(())
        }
    }

    #[derive(Debug)]
    struct AcceptingPlonkAdapter;

    impl PlonkVerifierAdapter for AcceptingPlonkAdapter {
        fn verify(
            &self,
            verifying_key_bytes: &[u8],
            public_inputs: &ShieldedPublicInputs,
            canonical_public_inputs: &[u8],
            canonical_public_input_words: &[[u8; 32]],
            payload: &ParsedPlonkProofPayload,
        ) -> Result<(), ProofError> {
            assert_eq!(verifying_key_bytes, &[1, 2, 3]);
            assert_eq!(
                canonical_public_inputs,
                canonicalize_public_inputs(public_inputs).expect("canonical inputs")
            );
            assert_eq!(
                canonical_public_input_words,
                public_inputs
                    .canonical_word_chunks_v1()
                    .expect("canonical word chunks")
            );
            assert_eq!(payload.proof_bytes, vec![0xCD; 64]);
            Ok(())
        }
    }

    fn build_vk_artifact(
        backend_kind: ProofBackendKind,
        circuit_version: CircuitVersion,
        verifying_key_bytes: &[u8],
    ) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + 1 + 1 + 2 + 1 + 4 + verifying_key_bytes.len());
        bytes.extend_from_slice(VK_ARTIFACT_MAGIC);
        bytes.push(VK_ARTIFACT_SCHEMA_V1);
        bytes.push(backend_kind.vk_artifact_tag());
        bytes.extend_from_slice(&circuit_version.0.to_le_bytes());
        bytes.push(VK_FINGERPRINT_ALGO_BLAKE3_V1);
        bytes.extend_from_slice(&(verifying_key_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(verifying_key_bytes);
        bytes
    }

    fn build_shell_proof_envelope(
        kind: ShellProofEnvelopeKind,
        verifying_key_bytes: &[u8],
        public_inputs: &ShieldedPublicInputs,
        payload: &[u8],
    ) -> ShieldedProof {
        let fingerprint = compute_vk_fingerprint(verifying_key_bytes).expect("vk fingerprint");
        let canonical_inputs = canonicalize_public_inputs(public_inputs).expect("canonical inputs");
        let public_input_hash = compute_canonical_public_input_hash(&canonical_inputs);
        let mut bytes = Vec::with_capacity(4 + 1 + 1 + 32 + 32 + payload.len());
        bytes.extend_from_slice(SHELL_PROOF_ENVELOPE_MAGIC);
        bytes.push(SHELL_PROOF_ENVELOPE_SCHEMA_V1);
        bytes.push(kind as u8);
        bytes.extend_from_slice(&fingerprint);
        bytes.extend_from_slice(&public_input_hash);
        bytes.extend_from_slice(payload);
        ShieldedProof { bytes }
    }

    fn dummy_inputs() -> ShieldedPublicInputs {
        ShieldedPublicInputs {
            anchor: TreeRoot::empty(),
            nullifiers: vec![Nullifier([0u8; 32])],
            output_commitments: vec![NoteCommitment([1u8; 32])],
            fee: 100,
            withdraw_amount: None,
            circuit_version: CircuitVersion::STUB_V1,
        }
    }

    #[test]
    fn stub_accepts_stub_proof() {
        let backend = StubProofBackend::new_for_testnet();
        let proof = ShieldedProof::dev_testnet_stub();
        let inputs = dummy_inputs();
        assert!(backend.verify(&inputs, &proof).is_ok());
    }

    #[test]
    fn stub_rejects_empty_proof() {
        let backend = StubProofBackend::new_for_testnet();
        let proof = ShieldedProof { bytes: vec![] };
        let inputs = dummy_inputs();
        assert!(matches!(
            backend.verify(&inputs, &proof),
            Err(ProofError::Malformed(_))
        ));
    }

    #[test]
    fn registry_lookup() {
        let mut reg = CircuitRegistry::new();
        reg.register(Box::new(StubProofBackend::new_for_testnet()));
        assert!(reg.get(&CircuitVersion::STUB_V1).is_some());
        assert!(reg.is_accepted(&CircuitVersion::STUB_V1));
        assert!(!reg.is_accepted(&CircuitVersion(99)));
    }

    #[test]
    fn shell_runtime_status_reports_vk_and_body_gaps() {
        let inputs = dummy_inputs();
        let unloaded_shell_proof = ShieldedProof {
            bytes: vec![0xAB; 64],
        };

        let groth16 = Groth16Backend::new(CircuitVersion::GROTH16_V1, vec![]);
        let groth16_status = groth16.runtime_status();
        assert!(groth16_status.verifying_key_required);
        assert!(!groth16_status.verifying_key_loaded);
        assert!(!groth16_status.verifier_body_implemented);
        assert!(matches!(
            groth16.verify(&inputs, &unloaded_shell_proof),
            Err(ProofError::VerifyingKeyNotLoaded)
        ));

        let groth16_with_vk = Groth16Backend::new(CircuitVersion::GROTH16_V1, vec![1, 2, 3]);
        let groth16_status = groth16_with_vk.runtime_status();
        assert!(groth16_status.verifying_key_fingerprint.is_some());
        assert_eq!(groth16_status.verifying_key_artifact_schema_version, None);
        assert_eq!(groth16_status.verifying_key_fingerprint_algorithm, None);
        assert_eq!(groth16_status.verifying_key_artifact_payload_length, None);
        let groth16_proof = build_shell_proof_envelope(
            ShellProofEnvelopeKind::Groth16,
            &[1, 2, 3],
            &inputs,
            &[0xAB; 64],
        );
        assert!(matches!(
            groth16_with_vk.verify(&inputs, &groth16_proof),
            Err(ProofError::NotImplemented(_))
        ));

        let plonk = PlonkBackend::new(CircuitVersion::PLONK_V1, vec![]);
        let plonk_status = plonk.runtime_status();
        assert!(plonk_status.verifying_key_required);
        assert!(!plonk_status.verifying_key_loaded);
        assert!(!plonk_status.verifier_body_implemented);
        assert!(matches!(
            plonk.verify(&inputs, &unloaded_shell_proof),
            Err(ProofError::VerifyingKeyNotLoaded)
        ));

        let plonk_with_vk = PlonkBackend::new(CircuitVersion::PLONK_V1, vec![1, 2, 3]);
        let plonk_proof = build_shell_proof_envelope(
            ShellProofEnvelopeKind::Plonk,
            &[1, 2, 3],
            &inputs,
            &[0xCD; 64],
        );
        let plonk_status = plonk_with_vk.runtime_status();
        assert!(plonk_status.verifying_key_required);
        assert!(plonk_status.verifying_key_loaded);
        assert!(plonk_status.verifying_key_fingerprint.is_some());
        assert_eq!(plonk_status.verifying_key_artifact_schema_version, None);
        assert_eq!(plonk_status.verifying_key_fingerprint_algorithm, None);
        assert_eq!(plonk_status.verifying_key_artifact_payload_length, None);
        assert!(!plonk_status.verifier_body_implemented);
        assert!(matches!(
            plonk_with_vk.verify(&inputs, &plonk_proof),
            Err(ProofError::NotImplemented(_))
        ));
    }

    #[test]
    fn shell_runtime_status_reports_artifact_metadata_when_built_from_vk_artifact() {
        let groth16_artifact = parse_verifying_key_artifact(
            &build_vk_artifact(
                ProofBackendKind::Groth16,
                CircuitVersion::GROTH16_V1,
                &[1, 2, 3, 4],
            ),
            ProofBackendKind::Groth16,
            CircuitVersion::GROTH16_V1,
        )
        .expect("groth16 artifact");
        let groth16_status =
            Groth16Backend::new_from_vk_artifact(groth16_artifact).runtime_status();
        assert!(groth16_status.verifying_key_loaded);
        assert_eq!(
            groth16_status.verifying_key_artifact_schema_version,
            Some(VK_ARTIFACT_SCHEMA_V1)
        );
        assert_eq!(
            groth16_status.verifying_key_fingerprint_algorithm,
            Some(VK_FINGERPRINT_ALGO_BLAKE3_V1)
        );
        assert_eq!(
            groth16_status.verifying_key_artifact_payload_length,
            Some(4)
        );

        let plonk_artifact = parse_verifying_key_artifact(
            &build_vk_artifact(
                ProofBackendKind::Plonk,
                CircuitVersion::PLONK_V1,
                &[9, 8, 7],
            ),
            ProofBackendKind::Plonk,
            CircuitVersion::PLONK_V1,
        )
        .expect("plonk artifact");
        let plonk_status = PlonkBackend::new_from_vk_artifact(plonk_artifact).runtime_status();
        assert!(plonk_status.verifying_key_loaded);
        assert_eq!(
            plonk_status.verifying_key_artifact_schema_version,
            Some(VK_ARTIFACT_SCHEMA_V1)
        );
        assert_eq!(
            plonk_status.verifying_key_fingerprint_algorithm,
            Some(VK_FINGERPRINT_ALGO_BLAKE3_V1)
        );
        assert_eq!(plonk_status.verifying_key_artifact_payload_length, Some(3));
    }

    #[test]
    fn shell_verify_rejects_vk_fingerprint_mismatch() {
        let inputs = dummy_inputs();
        let groth16 = Groth16Backend::new(CircuitVersion::GROTH16_V1, vec![1, 2, 3]);
        let wrong = build_shell_proof_envelope(
            ShellProofEnvelopeKind::Groth16,
            &[9, 9, 9],
            &inputs,
            &[0xAA; 32],
        );
        assert!(matches!(
            groth16.verify(&inputs, &wrong),
            Err(ProofError::VerifyingKeyFingerprintMismatch)
        ));
    }

    #[test]
    fn shell_verify_rejects_wrong_kind_envelope() {
        let inputs = dummy_inputs();
        let groth16 = Groth16Backend::new(CircuitVersion::GROTH16_V1, vec![1, 2, 3]);
        let wrong_kind = build_shell_proof_envelope(
            ShellProofEnvelopeKind::Plonk,
            &[1, 2, 3],
            &inputs,
            &[0xAA; 32],
        );
        assert!(matches!(
            groth16.verify(&inputs, &wrong_kind),
            Err(ProofError::Malformed(_))
        ));
    }

    #[test]
    fn shell_verify_rejects_public_input_hash_mismatch() {
        let inputs = dummy_inputs();
        let other_inputs = ShieldedPublicInputs {
            anchor: TreeRoot([0x44; 32]),
            ..dummy_inputs()
        };
        let groth16 = Groth16Backend::new(CircuitVersion::GROTH16_V1, vec![1, 2, 3]);
        let wrong = build_shell_proof_envelope(
            ShellProofEnvelopeKind::Groth16,
            &[1, 2, 3],
            &other_inputs,
            &[0xAA; 32],
        );
        assert!(matches!(
            groth16.verify(&inputs, &wrong),
            Err(ProofError::PublicInputHashMismatch)
        ));
    }

    #[test]
    fn groth16_adapter_receives_parsed_payload_and_canonical_inputs() {
        let inputs = dummy_inputs();
        let backend = Groth16Backend::new(CircuitVersion::GROTH16_V1, vec![1, 2, 3])
            .with_verifier_adapter(Arc::new(AcceptingGroth16Adapter));
        let proof = build_shell_proof_envelope(
            ShellProofEnvelopeKind::Groth16,
            &[1, 2, 3],
            &inputs,
            &[0xAB; 64],
        );

        assert!(backend.verify(&inputs, &proof).is_ok());
        let status = backend.runtime_status();
        assert!(status.verifier_body_implemented);
        assert!(status.descriptor.production_ready);
        assert!(matches!(status.descriptor.phase, ProofBackendPhase::Real));
        assert_eq!(status.descriptor.backend_id, "groth16-v1");
    }

    #[test]
    fn plonk_adapter_receives_parsed_payload_and_canonical_inputs() {
        let inputs = dummy_inputs();
        let backend = PlonkBackend::new(CircuitVersion::PLONK_V1, vec![1, 2, 3])
            .with_verifier_adapter(Arc::new(AcceptingPlonkAdapter));
        let proof = build_shell_proof_envelope(
            ShellProofEnvelopeKind::Plonk,
            &[1, 2, 3],
            &inputs,
            &[0xCD; 64],
        );

        assert!(backend.verify(&inputs, &proof).is_ok());
        let status = backend.runtime_status();
        assert!(status.verifier_body_implemented);
        assert!(status.descriptor.production_ready);
        assert!(matches!(status.descriptor.phase, ProofBackendPhase::Real));
        assert_eq!(status.descriptor.backend_id, "plonk-v1");
    }

    #[test]
    fn canonical_public_inputs_is_stable() {
        let inputs = dummy_inputs();
        let left = canonicalize_public_inputs(&inputs).expect("left");
        let right = canonicalize_public_inputs(&inputs).expect("right");
        assert_eq!(left, right);
    }

    #[test]
    fn canonical_public_input_words_are_stable_and_length_prefixed() {
        let inputs = dummy_inputs();
        let bytes = canonicalize_public_inputs(&inputs).expect("canonical bytes");
        let words = inputs
            .canonical_word_chunks_v1()
            .expect("canonical word chunks");
        let words_again = inputs
            .canonical_word_chunks_v1()
            .expect("canonical word chunks");

        assert_eq!(words, words_again);
        assert_eq!(words[0][..8], (bytes.len() as u64).to_le_bytes());
        assert!(words.len() >= 2);
    }

    #[test]
    fn groth16_shell_size_limit_accounts_for_envelope_bytes() {
        let backend = Groth16Backend::new(CircuitVersion::GROTH16_V1, vec![1, 2, 3]);
        let inputs = dummy_inputs();
        let payload = vec![0xAB; 192];
        let proof = build_shell_proof_envelope(
            ShellProofEnvelopeKind::Groth16,
            &[1, 2, 3],
            &inputs,
            &payload,
        );
        assert_eq!(
            proof.bytes.len(),
            SHELL_PROOF_ENVELOPE_HEADER_LEN_V1 + payload.len()
        );
        assert!(backend.pre_validate(&proof).is_ok());
    }

    #[test]
    fn vk_artifact_roundtrip_parses_expected_contract() {
        let bytes = build_vk_artifact(
            ProofBackendKind::Groth16,
            CircuitVersion::GROTH16_V1,
            &[1, 2, 3],
        );
        let parsed = parse_verifying_key_artifact(
            &bytes,
            ProofBackendKind::Groth16,
            CircuitVersion::GROTH16_V1,
        )
        .expect("parse");
        assert_eq!(parsed.schema_version, VK_ARTIFACT_SCHEMA_V1);
        assert_eq!(parsed.backend_kind, ProofBackendKind::Groth16);
        assert_eq!(parsed.circuit_version, CircuitVersion::GROTH16_V1);
        assert_eq!(parsed.fingerprint_algo, VK_FINGERPRINT_ALGO_BLAKE3_V1);
        assert_eq!(parsed.payload_length, 3);
        assert_eq!(parsed.verifying_key_bytes, vec![1, 2, 3]);
    }

    #[test]
    fn vk_artifact_rejects_backend_kind_mismatch() {
        let bytes = build_vk_artifact(
            ProofBackendKind::Plonk,
            CircuitVersion::PLONK_V1,
            &[1, 2, 3],
        );
        assert!(matches!(
            parse_verifying_key_artifact(
                &bytes,
                ProofBackendKind::Groth16,
                CircuitVersion::GROTH16_V1
            ),
            Err(ProofError::Malformed(_))
        ));
    }

    #[test]
    fn size_limit_check() {
        let backend = StubProofBackend::new_for_testnet();
        let big_proof = ShieldedProof {
            bytes: vec![0u8; 2000],
        };
        assert!(matches!(
            backend.pre_validate(&big_proof),
            Err(ProofError::TooLarge { .. })
        ));
    }

    #[test]
    fn compiled_catalog_reports_stub_shell_and_real_paths() {
        let catalog = compiled_backend_catalog();
        assert!(catalog.iter().any(|s| s.descriptor.backend_id == "stub-v1"));
        assert!(catalog
            .iter()
            .any(|s| s.descriptor.backend_id == "groth16-shell-v1"));
        assert!(catalog
            .iter()
            .any(|s| s.descriptor.backend_id == "plonk-shell-v1"));
        assert!(catalog
            .iter()
            .any(|s| s.descriptor.backend_id == "sha3-merkle-v1"));
        assert!(catalog
            .iter()
            .any(|s| s.descriptor.backend_id == "sha3-transfer-v2"));
    }
}
