//! Wallet Note Scanner
//!
//! Monero スタイルの incoming view key によるスキャンモデル。
//! chain から受け取った EncryptedNote を ivk で試し解読し、
//! 自分宛の note を検出する。
//!
//! # Scanning Model
//!
//! 1. ノードから `EncryptedNote` のストリームを受け取る
//! 2. view_tag (1 byte) で高速フィルタリング (O(1) per note, 1/256 false positive)
//! 3. view_tag が一致した note だけ AEAD フル復号を試みる
//! 4. 成功した note を `ScannedNote` として保存
//! 5. NullifierSet との照合で消費済みかどうかを判定
//!
//! # Threat Model
//! - wallet は ivk を外部に出さない
//! - scanner は node に ivk を送らない（node-side scanning は禁止）
//! - view tag は scanner 効率化のみ。privacy への影響は最小限
//!
//! # Note Selection
//! spend 時は randomized order で note を選択し timing correlation を防ぐ。

use crate::types::{
    DecryptError, EncryptedNote, FullViewKey, IncomingViewKey, Note, NoteCommitment, Nullifier,
    NullifierKey,
};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};

// ─── ScannedNote ──────────────────────────────────────────────────────────────

/// scanner が検出した自分宛の note
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedNote {
    /// 解読済み note (平文)
    #[serde(skip)] // wallet ストレージには暗号化して保存すること
    pub note: Option<Note>,
    /// commitment tree 内の leaf position
    pub position: u64,
    /// note commitment
    pub commitment: NoteCommitment,
    /// どの tx で生成されたか
    pub tx_hash: [u8; 32],
    /// 確定したブロック高
    pub block_height: u64,
    /// 消費済みかどうか (nullifier_set 照合済み)
    pub spent: bool,
}

impl ScannedNote {
    /// note が available (unspent and confirmed) かどうか
    pub fn is_available(&self) -> bool {
        !self.spent && self.note.is_some()
    }

    pub fn value(&self) -> u64 {
        self.note.as_ref().map(|n| n.value).unwrap_or(0)
    }
}

// ─── ScannedBlock ─────────────────────────────────────────────────────────────

/// wallet scanner がノードから受け取るブロックデータ
#[derive(Debug, Clone)]
pub struct ScannedBlock {
    pub height: u64,
    /// (position, encrypted_note, tx_hash)
    pub encrypted_notes: Vec<(u64, EncryptedNote, [u8; 32])>,
    /// このブロックで消費された nullifiers（spent 判定に使用）
    pub spent_nullifiers: Vec<Nullifier>,
}

// ─── NullifierChecker ─────────────────────────────────────────────────────────

/// nullifier の spent 状態を確認するトレイト。
/// ノードへの RPC 照会または local cache で実装する。
pub trait NullifierChecker {
    fn is_spent(&self, nf: &Nullifier) -> bool;
}

/// インメモリ版 (wallet local cache)
pub struct LocalNullifierCache {
    spent: std::collections::HashSet<Nullifier>,
}

impl LocalNullifierCache {
    pub fn new() -> Self {
        Self {
            spent: std::collections::HashSet::new(),
        }
    }

    pub fn mark_spent(&mut self, nf: Nullifier) {
        self.spent.insert(nf);
    }

    pub fn load_from_block(&mut self, block: &ScannedBlock) {
        for nf in &block.spent_nullifiers {
            self.spent.insert(*nf);
        }
    }
}

impl NullifierChecker for LocalNullifierCache {
    fn is_spent(&self, nf: &Nullifier) -> bool {
        self.spent.contains(nf)
    }
}

// ─── NoteScanner ──────────────────────────────────────────────────────────────

/// Wallet の note scanner。
///
/// ivk を保持し、チェーンの EncryptedNote を試し解読する。
/// note の zeroize は `Note` 型が `ZeroizeOnDrop` を実装しているため自動。
#[derive(Debug)]
pub struct NoteScanner {
    ivk: IncomingViewKey,
    nk: NullifierKey,
    /// 検出済み note の一覧（position → note）
    notes: Vec<ScannedNote>,
    /// 最後にスキャンしたブロック高
    pub last_scanned_block: u64,
    /// スキャン統計
    pub stats: ScanStats,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ScanStats {
    pub blocks_scanned: u64,
    pub notes_found: u64,
    pub view_tag_hits: u64,
    pub view_tag_misses: u64,
    pub decrypt_failures: u64,
}

impl NoteScanner {
    pub fn new(ivk: IncomingViewKey, nk: NullifierKey) -> Self {
        Self {
            ivk,
            nk,
            notes: Vec::new(),
            last_scanned_block: 0,
            stats: ScanStats::default(),
        }
    }

    /// Full View Key から scanner を生成
    pub fn from_full_view_key(fvk: FullViewKey) -> Self {
        // FullViewKey derives ZeroizeOnDrop (impl Drop), so we cannot
        // destructure it directly. Clone the fields instead; fvk is
        // zeroized when it drops at the end of this scope.
        Self::new(fvk.ivk.clone(), fvk.nk.clone())
    }

    // ─── Block Scanning ───────────────────────────────────────────────────

    /// ブロックをスキャンし、自分宛の note を検出する。
    /// 検出された note の一覧を返す。
    pub fn scan_block(&mut self, block: &ScannedBlock) -> Vec<usize> {
        let mut found_indices = Vec::new();

        for (position, enc_note, tx_hash) in &block.encrypted_notes {
            match self.try_decrypt_note(enc_note, *position, *tx_hash, block.height) {
                Ok(idx) => found_indices.push(idx),
                Err(_) => {}
            }
        }

        // spent nullifier を反映
        for nf in &block.spent_nullifiers {
            self.mark_spent_by_nullifier(nf);
        }

        self.last_scanned_block = block.height;
        self.stats.blocks_scanned += 1;

        found_indices
    }

    /// 単一の EncryptedNote を試し解読する。
    fn try_decrypt_note(
        &mut self,
        enc: &EncryptedNote,
        position: u64,
        tx_hash: [u8; 32],
        block_height: u64,
    ) -> Result<usize, DecryptError> {
        // view tag 高速スキャン
        let expected_view_tag = self.compute_view_tag(&enc.epk);
        if expected_view_tag != enc.view_tag {
            self.stats.view_tag_misses += 1;
            return Err(DecryptError::ViewTagMismatch);
        }
        self.stats.view_tag_hits += 1;

        // フル復号
        let note = enc.try_decrypt(self.ivk.as_bytes()).map_err(|e| {
            self.stats.decrypt_failures += 1;
            e
        })?;

        let commitment = note.commitment();
        let scanned = ScannedNote {
            note: Some(note),
            position,
            commitment,
            tx_hash,
            block_height,
            spent: false,
        };

        let idx = self.notes.len();
        self.notes.push(scanned);
        self.stats.notes_found += 1;

        tracing::debug!(
            "NoteScanner: found note at position={} block={} tx={}",
            position,
            block_height,
            hex::encode(tx_hash)
        );

        Ok(idx)
    }

    /// view tag を計算する（AEAD 前の高速スキャン用）
    fn compute_view_tag(&self, epk: &[u8; 32]) -> u8 {
        let mut seed_material = [0u8; 64];
        seed_material[..32].copy_from_slice(self.ivk.as_bytes());
        seed_material[32..].copy_from_slice(epk);
        let seed = blake3::derive_key("MISAKA shielded note enc seed v1", &seed_material);
        let vtag_seed = blake3::derive_key("MISAKA shielded note view tag v1", &seed);
        vtag_seed[0]
    }

    // ─── Spent Tracking ───────────────────────────────────────────────────

    /// nullifier に対応する note を spent に更新する
    fn mark_spent_by_nullifier(&mut self, spent_nf: &Nullifier) {
        for note in self.notes.iter_mut() {
            if note.spent {
                continue;
            }
            if let Some(n) = &note.note {
                let nf = n.nullifier(self.nk.as_bytes(), note.position);
                if &nf == spent_nf {
                    note.spent = true;
                    tracing::debug!(
                        "NoteScanner: note at position={} marked spent",
                        note.position
                    );
                }
            }
        }
    }

    // ─── Balance & Note Selection ─────────────────────────────────────────

    /// 未消費 note の総残高
    pub fn shielded_balance(&self) -> u64 {
        self.notes
            .iter()
            .filter(|n| n.is_available())
            .map(|n| n.value())
            .sum()
    }

    /// 未消費 note の一覧（参照）
    pub fn unspent_notes(&self) -> Vec<&ScannedNote> {
        self.notes.iter().filter(|n| n.is_available()).collect()
    }

    /// 指定 amount に必要な note を選択する。
    ///
    /// timing correlation を防ぐため randomized order でシャッフルしてから選択する。
    /// 選択された note の index（`self.notes` 内）を返す。
    pub fn select_notes_for_spend(
        &self,
        amount: u64,
        rng: &mut impl rand::Rng,
    ) -> Result<Vec<usize>, WalletScanError> {
        let mut available: Vec<usize> = self
            .notes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.is_available())
            .map(|(i, _)| i)
            .collect();

        // シャッフルで timing correlation を防ぐ
        available.shuffle(rng);

        let mut selected = Vec::new();
        let mut total = 0u64;

        for idx in available {
            selected.push(idx);
            total += self.notes[idx].value();
            if total >= amount {
                break;
            }
        }

        if total < amount {
            return Err(WalletScanError::InsufficientBalance {
                available: total,
                required: amount,
            });
        }

        Ok(selected)
    }

    /// nullifier を計算する（spend 時に必要）
    pub fn compute_nullifier(&self, note_idx: usize) -> Option<Nullifier> {
        let sn = self.notes.get(note_idx)?;
        let note = sn.note.as_ref()?;
        Some(note.nullifier(self.nk.as_bytes(), sn.position))
    }

    /// 全 note の数（spent 含む）
    pub fn total_note_count(&self) -> usize {
        self.notes.len()
    }

    /// scanner をリセット（フルリスキャン用）
    pub fn reset(&mut self) {
        self.notes.clear();
        self.last_scanned_block = 0;
        self.stats = ScanStats::default();
    }
}

// ─── PaymentProof ─────────────────────────────────────────────────────────────

/// 特定の支払いが行われたことを第三者に証明するための構造体。
/// CEX 照会・税務・法人会計に使用する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentProof {
    /// 対象の tx hash
    pub tx_hash: [u8; 32],
    /// 支払われた金額（公開）
    pub amount: u64,
    /// 資産 ID
    pub asset_id: u64,
    /// 受取人が自分宛と確認できる証拠（note commitment + ivk のコミット）
    pub recipient_commitment: [u8; 32],
    /// ブロック高（タイムスタンプ代替）
    pub block_height: u64,
    /// オプション memo
    pub memo: Option<Vec<u8>>,
    /// 作成タイムスタンプ (Unix ms)
    pub created_at_ms: u64,
}

impl PaymentProof {
    /// ScannedNote から PaymentProof を生成する
    pub fn from_scanned_note(
        sn: &ScannedNote,
        ivk: &IncomingViewKey,
        created_at_ms: u64,
    ) -> Option<Self> {
        let note = sn.note.as_ref()?;

        // recipient_commitment = Blake3("MISAKA payment proof v1", ivk || cm)
        let mut hasher = blake3::Hasher::new_derive_key("MISAKA shielded payment proof v1");
        hasher.update(ivk.as_bytes());
        hasher.update(sn.commitment.as_bytes());
        let rc = *hasher.finalize().as_bytes();

        Some(PaymentProof {
            tx_hash: sn.tx_hash,
            amount: note.value,
            asset_id: note.asset_id,
            recipient_commitment: rc,
            block_height: sn.block_height,
            memo: note.memo.clone(),
            created_at_ms,
        })
    }

    /// 第三者が ivk を使って payment proof を検証する
    pub fn verify(&self, ivk: &IncomingViewKey, claimed_cm: &NoteCommitment) -> bool {
        let mut hasher = blake3::Hasher::new_derive_key("MISAKA shielded payment proof v1");
        hasher.update(ivk.as_bytes());
        hasher.update(claimed_cm.as_bytes());
        let expected = *hasher.finalize().as_bytes();
        self.recipient_commitment == expected
    }
}

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum WalletScanError {
    #[error("insufficient shielded balance: available={available}, required={required}")]
    InsufficientBalance { available: u64, required: u64 },

    #[error("note at index {0} not found")]
    NoteNotFound(usize),
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::types::{IncomingViewKey, Note, NullifierKey};
    use rand::SeedableRng;

    fn make_scanner() -> NoteScanner {
        NoteScanner::new(IncomingViewKey([0u8; 32]), NullifierKey([1u8; 32]))
    }

    #[test]
    fn empty_scanner_zero_balance() {
        let s = make_scanner();
        assert_eq!(s.shielded_balance(), 0);
        assert_eq!(s.total_note_count(), 0);
    }

    #[test]
    fn select_notes_insufficient() {
        let s = make_scanner();
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let result = s.select_notes_for_spend(1000, &mut rng);
        assert!(matches!(
            result,
            Err(WalletScanError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn payment_proof_verify() {
        let ivk = IncomingViewKey([0u8; 32]);
        let cm = NoteCommitment([1u8; 32]);
        let note = Note {
            value: 100,
            asset_id: 0,
            recipient_pk: [0u8; 32],
            rcm: [0u8; 32],
            memo: None,
        };
        let sn = ScannedNote {
            note: Some(note),
            position: 0,
            commitment: cm,
            tx_hash: [0u8; 32],
            block_height: 1,
            spent: false,
        };
        let proof = PaymentProof::from_scanned_note(&sn, &ivk, 0).expect("proof created");
        assert!(proof.verify(&ivk, &cm));

        // wrong ivk should fail
        let wrong_ivk = IncomingViewKey([99u8; 32]);
        assert!(!proof.verify(&wrong_ivk, &cm));
    }
}
