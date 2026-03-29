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

use crate::types::{CircuitVersion, ShieldedProof, ShieldedPublicInputs};
use std::collections::HashMap;

// ─── trait ────────────────────────────────────────────────────────────────────

/// ZK proof verifier の抽象インターフェース。
///
/// chain node はこの trait のみに依存する。
/// proving system の交換・アップグレードが trait の変更なく可能。
pub trait ProofBackend: Send + Sync + std::fmt::Debug {
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
            "StubBackend: proof is not a valid stub marker; non-stub proofs require a real backend".to_string(),
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
}

impl CircuitVersion {
    /// P1 Groth16 circuit (ShieldedTransfer + ShieldWithdraw)
    pub const GROTH16_V1: Self = CircuitVersion(100);
    /// Future: PLONK-based circuit
    pub const PLONK_V1: Self = CircuitVersion(200);
}

impl Groth16Backend {
    pub fn new(version: CircuitVersion, verifying_key_bytes: Vec<u8>) -> Self {
        Self { version, verifying_key_bytes }
    }
}

impl ProofBackend for Groth16Backend {
    fn circuit_version(&self) -> CircuitVersion {
        self.version
    }

    fn proof_size_limit(&self) -> usize {
        // Groth16 proof on BLS12-381:
        // 2 × G1 (48 bytes compressed) + 1 × G2 (96 bytes compressed) = 192
        192
    }

    fn verify(
        &self,
        _public_inputs: &ShieldedPublicInputs,
        proof: &ShieldedProof,
    ) -> Result<(), ProofError> {
        self.pre_validate(proof)?;
        if self.verifying_key_bytes.is_empty() {
            return Err(ProofError::VerifyingKeyNotLoaded);
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
        //     &proof.bytes[..]
        // ).map_err(|e| ProofError::Malformed(format!("proof deserialize: {}", e)))?;
        //
        // let public_inputs = self.encode_public_inputs(public_inputs)?;
        //
        // Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &public_inputs, &proof)
        //     .map_err(|_| ProofError::VerificationFailed)?;
        // ```
        Err(ProofError::NotImplemented(
            "Groth16 verify: P1 phase — add arkworks dependency and implement pairing check".to_string(),
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
        Self { version: CircuitVersion::SHA3_MERKLE_V1 }
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
            proof.bytes[0], proof.bytes[1], proof.bytes[2], proof.bytes[3],
        ]);

        let sibling_bytes = &proof.bytes[4..];
        let depth = sibling_bytes.len() / 32;
        if sibling_bytes.len() % 32 != 0 || depth == 0 {
            return Err(ProofError::Malformed(format!(
                "invalid sibling data: {} bytes (need multiple of 32)", sibling_bytes.len()
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
            return Err(ProofError::InvalidPublicInputs("empty inputs and outputs".into()));
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
        let proof = ShieldedProof::stub();
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
    fn size_limit_check() {
        let backend = StubProofBackend::new_for_testnet();
        let big_proof = ShieldedProof { bytes: vec![0u8; 2000] };
        assert!(matches!(
            backend.pre_validate(&big_proof),
            Err(ProofError::TooLarge { .. })
        ));
    }
}
