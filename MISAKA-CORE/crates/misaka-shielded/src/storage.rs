//! Shielded State — Storage Layer
//!
//! RocksDB Column Family の定義と、ShieldedWriteSet を WriteBatch に変換する
//! ヘルパーを提供する。
//!
//! # Column Families
//!
//! | CF 名                    | key                      | value                  |
//! |--------------------------|--------------------------|------------------------|
//! | `shield_commitments`     | position: u64 LE (8B)    | NoteCommitment (32B)   |
//! | `shield_nullifiers`      | Nullifier (32B)           | SpentRecord (JSON)     |
//! | `shield_notes_enc`       | position: u64 LE (8B)    | EncryptedNote (JSON)   |
//! | `shield_roots`           | block_height: u64 LE (8B)| TreeRoot (32B)         |
//! | `shield_frontier`        | b"frontier" (literal)    | MerkleFrontier (JSON)  |
//! | `shield_circuit_vkeys`   | CircuitVersion: u16 LE   | verifying key bytes    |
//!
//! # Atomic Commit Rule
//! transparent state と shielded state の変更は **同一 WriteBatch** に詰めて
//! 単一の `db.write(batch)` で commit する。このファイルはその WriteBatch に
//! shielded 部分を書き込むヘルパーを提供する。

use crate::commitment_tree::MerkleFrontier;
use crate::nullifier_set::NullifierSet;
use crate::types::{CircuitVersion, Nullifier, SpentRecord, TreeRoot};
use crate::shielded_state::ShieldedWriteSet;

// ─── CF 名定数 ────────────────────────────────────────────────────────────────

pub const CF_SHIELD_COMMITMENTS: &str = "shield_commitments";
pub const CF_SHIELD_NULLIFIERS: &str = "shield_nullifiers";
pub const CF_SHIELD_NOTES_ENC: &str = "shield_notes_enc";
pub const CF_SHIELD_ROOTS: &str = "shield_roots";
pub const CF_SHIELD_FRONTIER: &str = "shield_frontier";
pub const CF_SHIELD_CIRCUIT_VKEYS: &str = "shield_circuit_vkeys";

/// 全 shielded CF 名のリスト（RocksDB 初期化時に一括作成するために使用）
pub const ALL_SHIELDED_CFS: &[&str] = &[
    CF_SHIELD_COMMITMENTS,
    CF_SHIELD_NULLIFIERS,
    CF_SHIELD_NOTES_ENC,
    CF_SHIELD_ROOTS,
    CF_SHIELD_FRONTIER,
    CF_SHIELD_CIRCUIT_VKEYS,
];

// ─── キーエンコード ────────────────────────────────────────────────────────────

/// position (u64) → DB key: LE 8 bytes
/// LE を使う理由: RocksDB のデフォルトコンパレータで数値順にスキャンできる
pub fn position_key(position: u64) -> [u8; 8] {
    position.to_le_bytes()
}

/// block_height (u64) → DB key: LE 8 bytes
pub fn block_height_key(height: u64) -> [u8; 8] {
    height.to_le_bytes()
}

/// CircuitVersion → DB key: LE 2 bytes
pub fn circuit_version_key(version: CircuitVersion) -> [u8; 2] {
    version.0.to_le_bytes()
}

pub const FRONTIER_KEY: &[u8] = b"frontier";

// ─── WriteBatch ヘルパー (trait-based, RocksDB 非依存) ─────────────────────────

/// RocksDB の WriteBatch を抽象化するトレイト。
/// テスト時はモック実装を使える。
/// 本番では `RocksWriteBatch` を使う。
pub trait ShieldedBatch {
    fn put_cf(&mut self, cf: &str, key: &[u8], value: &[u8]);
}

/// `ShieldedWriteSet` の内容を `ShieldedBatch` に書き込む。
/// 呼び出し側がこの後に transparent state の変更も同じ batch に追加し、
/// 最終的に単一の `db.write(batch)` で commit する。
#[allow(clippy::unwrap_or_default)]
pub fn write_shield_set_to_batch(
    ws: &ShieldedWriteSet,
    block_height: u64,
    batch: &mut dyn ShieldedBatch,
) {
    // commitments
    for (pos, cm) in &ws.commitments {
        batch.put_cf(CF_SHIELD_COMMITMENTS, &position_key(*pos), cm.as_bytes());
    }

    // nullifiers
    for (nf, record) in &ws.nullifiers {
        let value = serde_json::to_vec(record).unwrap_or_default();
        batch.put_cf(CF_SHIELD_NULLIFIERS, nf.as_bytes(), &value);
    }

    // encrypted notes
    for (pos, enc) in &ws.encrypted_notes {
        let value = serde_json::to_vec(enc).unwrap_or_default();
        batch.put_cf(CF_SHIELD_NOTES_ENC, &position_key(*pos), &value);
    }

    // frontier
    batch.put_cf(CF_SHIELD_FRONTIER, FRONTIER_KEY, &ws.new_frontier);

    // root (keyed by block_height)
    batch.put_cf(CF_SHIELD_ROOTS, &block_height_key(block_height), ws.new_root.as_bytes());
}

// ─── ロード用ヘルパー (起動時の DB → メモリ復元) ─────────────────────────────

/// DB から frontier をロードする。
/// 存在しなければ新規（空の木）を返す。
pub fn load_frontier_from_bytes(bytes: Option<&[u8]>) -> MerkleFrontier {
    match bytes {
        Some(b) if !b.is_empty() => {
            MerkleFrontier::deserialize(b).unwrap_or_default()
        }
        _ => MerkleFrontier::new(),
    }
}

/// DB から nullifier セットをバルクロードする。
/// イテレータ形式でエントリを受け取る。
pub fn load_nullifiers(
    set: &mut NullifierSet,
    entries: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
) -> usize {
    let mut count = 0;
    for (k, v) in entries {
        if k.len() != 32 {
            continue;
        }
        let mut nf_bytes = [0u8; 32];
        nf_bytes.copy_from_slice(&k);
        let nf = Nullifier(nf_bytes);
        if let Ok(record) = serde_json::from_slice::<SpentRecord>(&v) {
            set.bulk_load(std::iter::once((nf, record)));
            count += 1;
        }
    }
    count
}

/// root 履歴をバルクロードする（起動時の anchor 有効性復元用）
pub fn load_root_history(
    entries: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
) -> Vec<(u64, TreeRoot)> {
    let mut history = Vec::new();
    for (k, v) in entries {
        if k.len() != 8 || v.len() != 32 {
            continue;
        }
        let height = u64::from_le_bytes(k[..8].try_into().unwrap_or([0u8; 8]));
        let mut root_bytes = [0u8; 32];
        root_bytes.copy_from_slice(&v);
        history.push((height, TreeRoot(root_bytes)));
    }
    history.sort_by_key(|(h, _)| *h);
    history
}

// ─── StorageStats ─────────────────────────────────────────────────────────────

/// shielded storage の統計（explorer / monitoring 用）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShieldedStorageStats {
    pub commitment_count: u64,
    pub nullifier_count: usize,
    pub current_root: String,
    pub enabled: bool,
}

// ─── テスト用モック WriteBatch ────────────────────────────────────────────────

#[cfg(test)]
pub mod test_helpers {
    use super::*;
    use std::collections::HashMap;

    /// テスト用インメモリ batch
    #[derive(Default, Debug)]
    pub struct MockBatch {
        pub entries: HashMap<String, Vec<(Vec<u8>, Vec<u8>)>>,
    }

    impl ShieldedBatch for MockBatch {
        fn put_cf(&mut self, cf: &str, key: &[u8], value: &[u8]) {
            self.entries
                .entry(cf.to_string())
                .or_default()
                .push((key.to_vec(), value.to_vec()));
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::types::{EncryptedNote, NoteCommitment, Nullifier, SpentRecord, TreeRoot};
    use test_helpers::MockBatch;

    fn dummy_enc_note() -> EncryptedNote {
        EncryptedNote {
            epk: [1u8; 32],
            ciphertext: vec![2u8; 32],
            tag: [3u8; 16],
            view_tag: 4,
        }
    }

    fn dummy_write_set() -> ShieldedWriteSet {
        ShieldedWriteSet {
            nullifiers: vec![(
                Nullifier([0u8; 32]),
                SpentRecord { tx_hash: [1u8; 32], block_height: 5 },
            )],
            commitments: vec![(0, NoteCommitment([2u8; 32]))],
            encrypted_notes: vec![(0, dummy_enc_note())],
            new_frontier: vec![0u8; 8],
            new_root: TreeRoot([3u8; 32]),
            transparent_credit: None,
            transparent_debit: None,
        }
    }

    #[test]
    fn write_set_fills_batch() {
        let ws = dummy_write_set();
        let mut batch = MockBatch::default();
        write_shield_set_to_batch(&ws, 5, &mut batch);

        assert!(batch.entries.contains_key(CF_SHIELD_COMMITMENTS));
        assert!(batch.entries.contains_key(CF_SHIELD_NULLIFIERS));
        assert!(batch.entries.contains_key(CF_SHIELD_NOTES_ENC));
        assert!(batch.entries.contains_key(CF_SHIELD_FRONTIER));
        assert!(batch.entries.contains_key(CF_SHIELD_ROOTS));
    }

    #[test]
    fn position_key_encoding() {
        let k = position_key(256);
        assert_eq!(k, [0, 1, 0, 0, 0, 0, 0, 0]); // LE
    }

    #[test]
    fn frontier_load_empty() {
        let f = load_frontier_from_bytes(None);
        assert_eq!(f.size(), 0);
    }

    #[test]
    fn frontier_roundtrip() {
        use crate::types::NoteCommitment;
        let mut f = MerkleFrontier::new();
        f.append(NoteCommitment([42u8; 32]));
        let bytes = f.serialize();
        let f2 = load_frontier_from_bytes(Some(&bytes));
        assert_eq!(f2.size(), 1);
    }
}
