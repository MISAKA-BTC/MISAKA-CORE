//! Core shielded types.
//!
//! Note: このファイルは on-chain に保存「される」型（commitment, nullifier,
//! encrypted note）と wallet 側でのみ扱う型（Note のプレーンテキスト）を
//! 明確に分離している。
//!
//! # Privacy Model
//! - `Note` は wallet 内のみ。チェーンには保存しない。
//! - `NoteCommitment` と `EncryptedNote` だけが on-chain に存在する。
//! - `Nullifier` は note 消費時に公開される。

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ─── 基本識別子 ────────────────────────────────────────────────────────────────

/// 32-byte note commitment (Blake3 ベース Pedersen-style commitment)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NoteCommitment(pub [u8; 32]);

impl NoteCommitment {
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for NoteCommitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// 32-byte nullifier = PRF_nf(nk, rho)
/// note が消費されたことを示す。チェーン上に公開される。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Nullifier(pub [u8; 32]);

impl Nullifier {
    /// PRF_nf(nk, rho) — domain separated Blake3
    /// nk: nullifier deriving key (32 bytes)
    /// rho: note unique value = commitment bytes xor position encoding
    pub fn derive(nk: &[u8; 32], rho: &[u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key("MISAKA shielded nullifier v1");
        hasher.update(nk);
        hasher.update(rho);
        Nullifier(*hasher.finalize().as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for Nullifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Merkle tree root (commitment tree の現在 root)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TreeRoot(pub [u8; 32]);

impl TreeRoot {
    pub fn empty() -> Self {
        // 空の木の root = Blake3("MISAKA empty tree root v1")
        let h = blake3::derive_key("MISAKA shielded empty root v1", &[]);
        TreeRoot(h)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for TreeRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Circuit バージョン識別子
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CircuitVersion(pub u16);

impl CircuitVersion {
    /// 初期 circuit バージョン（stub verifier に対応）
    pub const STUB_V1: Self = CircuitVersion(1);
}

// ─── Note (wallet-only) ──────────────────────────────────────────────────────

/// Note: shielded pool 内の残高単位。
/// **wallet 内のみで保持。チェーンには平文では保存しない。**
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct Note {
    /// 残高 (base units)
    pub value: u64,
    /// 資産 ID (将来の multi-asset 対応)
    pub asset_id: u64,
    /// 受取人の diversified public key (32 bytes)
    pub recipient_pk: [u8; 32],
    /// note 固有の blinding randomness
    pub rcm: [u8; 32],
    /// plaintext memo (暗号化前)
    #[zeroize(skip)]
    pub memo: Option<Vec<u8>>,
}

impl Note {
    /// Commitment cm = Blake3_domain("MISAKA note commit v1", value || asset_id || pk || rcm)
    pub fn commitment(&self) -> NoteCommitment {
        let mut hasher = blake3::Hasher::new_derive_key("MISAKA shielded note commit v1");
        hasher.update(&self.value.to_le_bytes());
        hasher.update(&self.asset_id.to_le_bytes());
        hasher.update(&self.recipient_pk);
        hasher.update(&self.rcm);
        NoteCommitment(*hasher.finalize().as_bytes())
    }

    /// rho = Blake3("MISAKA note rho v1", cm || position_le)
    /// position: commitment tree 内の leaf index
    pub fn rho(&self, position: u64) -> [u8; 32] {
        let cm = self.commitment();
        let mut hasher = blake3::Hasher::new_derive_key("MISAKA shielded note rho v1");
        hasher.update(cm.as_bytes());
        hasher.update(&position.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// nullifier = PRF_nf(nk, rho(position))
    pub fn nullifier(&self, nk: &[u8; 32], position: u64) -> Nullifier {
        let rho = self.rho(position);
        Nullifier::derive(nk, &rho)
    }
}

// ─── On-chain 暗号化 note ─────────────────────────────────────────────────────

/// On-chain に保存される暗号化 note。
/// recipient が自分宛かどうかを判定するために使用。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedNote {
    /// Ephemeral public key (key agreement: recipient_ivk * epk → shared secret)
    pub epk: [u8; 32],
    /// ChaCha20-Poly1305 暗号化本体
    pub ciphertext: Vec<u8>,
    /// AEAD tag (16 bytes)
    pub tag: [u8; 16],
    /// view tag: shared secret の最初の 1 byte (wallet の高速スキャン用)
    pub view_tag: u8,
}

impl EncryptedNote {
    /// Note を recipient の ivk（incoming view key）で暗号化する。
    ///
    /// ivk: 32-byte incoming view key
    /// epk_secret: ephemeral scalar (wallet が毎回乱数生成)
    ///
    /// # Security
    /// - epk_secret は毎 note で独立した乱数を使うこと（key reuse 禁止）
    /// - SECURITY FIX [H1]: key と nonce は同じ shared_bytes から slice せず、
    ///   ドメイン分離した Blake3 derive_key で独立して導出する。
    ///   旧実装は key[0..32] と nonce[16..28] が 12 bytes 重複していた。
    /// - SECURITY FIX [H2]: 暗号化失敗を Result で伝播。
    ///   旧実装の unwrap_or_default() は空 ciphertext を on-chain に書いていた。
    pub fn encrypt(
        note: &Note,
        ivk: &[u8; 32],
        epk_secret: &[u8; 32],
    ) -> Result<Self, EncryptError> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305, Nonce,
        };

        // ─── 1. epk = Blake3("…epk derive v1", epk_secret) ───────────────────
        //
        // SECURITY FIX [v9.1]: epk_hash を seed 計算の **前に** 導出し、
        // seed_material に epk_hash を使用する。
        //
        // 旧実装のバグ: encrypt 側は seed = KDF(ivk || epk_secret) を使い、
        // decrypt 側は seed = KDF(ivk || self.epk) を使っていた。
        // self.epk = blake3(epk_secret) ≠ epk_secret のため、
        // seed が異なり AEAD 復号が常に認証エラーで失敗していた。
        //
        // 修正: encrypt/decrypt 両方で seed = KDF(ivk || epk_hash) を使う。
        // decrypt 側は self.epk (= epk_hash) を使うため、自動的に一致する。
        let epk_hash = blake3::derive_key("MISAKA shielded epk derive v1", epk_secret);

        // ─── 2. shared seed (ivk + epk_hash を KDF に通す) ───────────────────
        let mut seed_material = [0u8; 64];
        seed_material[..32].copy_from_slice(ivk);
        seed_material[32..].copy_from_slice(&epk_hash);
        let seed = blake3::derive_key("MISAKA shielded note enc seed v1", &seed_material);

        // ─── 3. key / nonce / view_tag を独立したドメインで導出 ───────────────
        // H1 fix: 旧実装は shared_bytes[0..32] を key、[16..28] を nonce に使い
        //         bytes 16-27 が重複していた。
        let key_bytes = blake3::derive_key("MISAKA shielded note enc key v1", &seed);
        let nonce_seed = blake3::derive_key("MISAKA shielded note enc nonce v1", &seed);
        let vtag_seed = blake3::derive_key("MISAKA shielded note view tag v1", &seed);

        // ─── 4. plaintext = value || asset_id || recipient_pk || rcm || memo ─
        let mut plaintext = Vec::with_capacity(128);
        plaintext.extend_from_slice(&note.value.to_le_bytes());
        plaintext.extend_from_slice(&note.asset_id.to_le_bytes());
        plaintext.extend_from_slice(&note.recipient_pk);
        plaintext.extend_from_slice(&note.rcm);
        match &note.memo {
            Some(m) => {
                plaintext.extend_from_slice(&(m.len() as u32).to_le_bytes());
                plaintext.extend_from_slice(m);
            }
            None => plaintext.extend_from_slice(&0u32.to_le_bytes()),
        }

        // ─── 5. ChaCha20-Poly1305 暗号化 ─────────────────────────────────────
        let key = ChaCha20Poly1305::new(&key_bytes.into());
        let nonce = Nonce::from_slice(&nonce_seed[..12]); // nonce は 12 bytes

        // H2 fix: encrypt 失敗は Err として上位に伝播する。
        let encrypted = key
            .encrypt(nonce, plaintext.as_slice())
            .map_err(|e| EncryptError::AeadFailure(e.to_string()))?;

        if encrypted.len() < 16 {
            return Err(EncryptError::OutputTooShort);
        }
        let (ciphertext, tag_bytes) = encrypted.split_at(encrypted.len() - 16);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(tag_bytes);

        Ok(EncryptedNote {
            epk: epk_hash,
            ciphertext: ciphertext.to_vec(),
            tag,
            view_tag: vtag_seed[0],
        })
    }

    /// ivk で試し解読。自分宛でなければ Err。
    ///
    /// # Security
    /// encrypt() と対称な KDF を使って key/nonce/view_tag を独立導出する。
    pub fn try_decrypt(&self, ivk: &[u8; 32]) -> Result<Note, DecryptError> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305, Nonce,
        };

        // ─── 1. seed = KDF(ivk || epk) ────────────────────────────────────────
        // epk は on-chain の EncryptedNote.epk フィールドに格納されている
        let mut seed_material = [0u8; 64];
        seed_material[..32].copy_from_slice(ivk);
        seed_material[32..].copy_from_slice(&self.epk);
        let seed = blake3::derive_key("MISAKA shielded note enc seed v1", &seed_material);

        // ─── 2. view tag 高速スキャン ─────────────────────────────────────────
        let vtag_seed = blake3::derive_key("MISAKA shielded note view tag v1", &seed);
        if vtag_seed[0] != self.view_tag {
            return Err(DecryptError::ViewTagMismatch);
        }

        // ─── 3. key / nonce を独立導出（encrypt と対称） ──────────────────────
        let key_bytes = blake3::derive_key("MISAKA shielded note enc key v1", &seed);
        let nonce_seed = blake3::derive_key("MISAKA shielded note enc nonce v1", &seed);
        let key = ChaCha20Poly1305::new(&key_bytes.into());
        let nonce = Nonce::from_slice(&nonce_seed[..12]);

        // ciphertext + tag を再結合
        let mut full = self.ciphertext.clone();
        full.extend_from_slice(&self.tag);

        let plaintext = key
            .decrypt(nonce, full.as_slice())
            .map_err(|_| DecryptError::AeadFailure)?;

        // parse
        if plaintext.len() < 8 + 8 + 32 + 32 + 4 {
            return Err(DecryptError::Truncated);
        }
        let mut off = 0;
        let value = u64::from_le_bytes(
            plaintext[off..off + 8]
                .try_into()
                .map_err(|_| DecryptError::Truncated)?,
        );
        off += 8;
        let asset_id = u64::from_le_bytes(
            plaintext[off..off + 8]
                .try_into()
                .map_err(|_| DecryptError::Truncated)?,
        );
        off += 8;
        let mut recipient_pk = [0u8; 32];
        recipient_pk.copy_from_slice(&plaintext[off..off + 32]);
        off += 32;
        let mut rcm = [0u8; 32];
        rcm.copy_from_slice(&plaintext[off..off + 32]);
        off += 32;
        let memo_len = u32::from_le_bytes(
            plaintext[off..off + 4]
                .try_into()
                .map_err(|_| DecryptError::Truncated)?,
        ) as usize;
        off += 4;
        let memo = if memo_len > 0 {
            if off + memo_len > plaintext.len() {
                return Err(DecryptError::Truncated);
            }
            Some(plaintext[off..off + memo_len].to_vec())
        } else {
            None
        };

        Ok(Note {
            value,
            asset_id,
            recipient_pk,
            rcm,
            memo,
        })
    }
}

/// 暗号化エラー（wallet 側のみ。on-chain には伝播しない）
#[derive(Debug, thiserror::Error)]
pub enum EncryptError {
    #[error("AEAD encryption failed: {0}")]
    AeadFailure(String),
    #[error("encrypted output too short")]
    OutputTooShort,
}

#[derive(Debug, thiserror::Error)]
pub enum DecryptError {
    #[error("view tag mismatch (not our note)")]
    ViewTagMismatch,
    #[error("key derivation error")]
    KeyDerivation,
    #[error("AEAD decryption failed")]
    AeadFailure,
    #[error("plaintext truncated")]
    Truncated,
}

// ─── ViewKey / AuditKey ───────────────────────────────────────────────────────

/// Incoming View Key: 受信 note のみ解読可能。
/// 税務申告・CEX 照会・監査への選択的開示に使用。
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct IncomingViewKey(pub [u8; 32]);

impl IncomingViewKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Nullifier Deriving Key: note の nullifier を導出するための鍵。
/// Full View Key の一部。
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct NullifierKey(pub [u8; 32]);

impl NullifierKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Full View Key: 送受信両方の note を開示可能。法人・取引所向け。
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct FullViewKey {
    pub ivk: IncomingViewKey,
    pub nk: NullifierKey,
}

// ─── ShieldedProof ────────────────────────────────────────────────────────────

/// On-chain に保存される ZK proof bytes。
/// circuit_version によって解釈が変わる。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldedProof {
    pub bytes: Vec<u8>,
}

impl ShieldedProof {
    /// Low-level stub proof constructor.
    ///
    /// Retained for tests and legacy dev/testnet seams. Runtime-adjacent code
    /// should prefer `dev_testnet_stub()` so intent is explicit.
    pub fn stub() -> Self {
        // P0 フェーズ: ShieldDeposit / ShieldWithdraw は proof なしで実装
        // P1 フェーズ: ShieldedTransfer の実際の proof に差し替える
        Self {
            bytes: vec![0xAA; 4],
        } // stub marker
    }

    /// Explicit dev/testnet stub proof constructor.
    ///
    /// This does not make the proof production-valid. It exists so CLI or
    /// harness code can declare that it intentionally uses the legacy
    /// testnet-only stub seam.
    pub fn dev_testnet_stub() -> Self {
        Self::stub()
    }

    pub fn is_stub(&self) -> bool {
        self.bytes == vec![0xAA; 4]
    }
}

/// Proof 検証に渡す public inputs
#[derive(Debug, Clone)]
pub struct ShieldedPublicInputs {
    pub anchor: TreeRoot,
    pub nullifiers: Vec<Nullifier>,
    pub output_commitments: Vec<NoteCommitment>,
    pub fee: u64,
    /// ShieldWithdraw 時のみ Some
    pub withdraw_amount: Option<u64>,
    pub circuit_version: CircuitVersion,
}

impl ShieldedPublicInputs {
    pub const CANONICAL_SCHEMA_V1: u8 = 1;

    pub fn canonical_bytes_v1(&self) -> Result<Vec<u8>, String> {
        if self.nullifiers.is_empty() && self.output_commitments.is_empty() {
            return Err("empty inputs and outputs".into());
        }

        let nullifier_count =
            u32::try_from(self.nullifiers.len()).map_err(|_| "too many nullifiers".to_string())?;
        let output_count = u32::try_from(self.output_commitments.len())
            .map_err(|_| "too many output commitments".to_string())?;

        let mut out = Vec::with_capacity(
            2 + 8
                + 1
                + 8
                + 32
                + 4
                + self.nullifiers.len() * 32
                + 4
                + self.output_commitments.len() * 32,
        );
        out.extend_from_slice(&self.circuit_version.0.to_le_bytes());
        out.extend_from_slice(&self.fee.to_le_bytes());
        match self.withdraw_amount {
            Some(amount) => {
                out.push(1);
                out.extend_from_slice(&amount.to_le_bytes());
            }
            None => {
                out.push(0);
                out.extend_from_slice(&0u64.to_le_bytes());
            }
        }
        out.extend_from_slice(self.anchor.as_bytes());
        out.extend_from_slice(&nullifier_count.to_le_bytes());
        for nf in &self.nullifiers {
            out.extend_from_slice(nf.as_bytes());
        }
        out.extend_from_slice(&output_count.to_le_bytes());
        for cm in &self.output_commitments {
            out.extend_from_slice(cm.as_bytes());
        }
        Ok(out)
    }

    /// Pairing 系 verifier 実装へ渡す前段の deterministic word encoding。
    ///
    /// - word[0]: canonical byte length (u64 LE) を先頭 8 bytes に格納
    /// - word[1..]: canonical bytes を 32-byte chunk に zero-pad して格納
    ///
    /// これにより、後段 backend は元 byte 長を失わずに field encoding へ進める。
    pub fn canonical_word_chunks_v1(&self) -> Result<Vec<[u8; 32]>, String> {
        let canonical_bytes = self.canonical_bytes_v1()?;
        let mut words = Vec::with_capacity(1 + canonical_bytes.len().div_ceil(32));

        let mut len_word = [0u8; 32];
        len_word[..8].copy_from_slice(
            &(u64::try_from(canonical_bytes.len()).map_err(|_| "canonical bytes too long")?)
                .to_le_bytes(),
        );
        words.push(len_word);

        for chunk in canonical_bytes.chunks(32) {
            let mut word = [0u8; 32];
            word[..chunk.len()].copy_from_slice(chunk);
            words.push(word);
        }

        Ok(words)
    }
}

// ─── SpentRecord (nullifier set 用メタデータ) ─────────────────────────────────

/// NullifierSet に nullifier と一緒に保存するメタデータ
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpentRecord {
    /// どの tx で消費されたか
    pub tx_hash: [u8; 32],
    /// 何ブロック目で確定したか
    pub block_height: u64,
}

// ─── MerkleWitness (wallet の proof 生成用) ───────────────────────────────────

/// Merkle authentication path。wallet が ZK proof を生成する際に使用。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleWitness {
    pub position: u64,
    /// depth 順の auth path (32-byte hashes, leaf → root 方向)
    pub auth_path: Vec<[u8; 32]>,
}
