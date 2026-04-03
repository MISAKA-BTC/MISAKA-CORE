//! Nullifier Set — double-spend 防止の核心。
//!
//! # Two-layer design
//!
//! 1. **Confirmed set**: ブロックに取り込まれた nullifier（永続化必須）
//! 2. **Reserved set**: mempool 内の tx が持つ nullifier（一時的）
//!
//! mempool admission 時に reserved を確認し、block apply 時に confirmed に移動。
//! tx が evict された場合は reserved から解放する。
//!
//! # Persistence
//! Confirmed set は呼び出し側 (ShieldedState) が WriteBatch 経由で DB に書く。
//! このオブジェクトはインメモリのミラー + reservation 管理を担う。

use crate::types::{Nullifier, SpentRecord};
use std::collections::HashMap;

/// Nullifier Set のインメモリ表現。
///
/// DB への書き込みは呼び出し側が WriteBatch で行う。
/// このオブジェクトは DB の confirmed state をミラーし、
/// mempool reservation も管理する。
#[derive(Debug, Default)]
pub struct NullifierSet {
    /// confirmed: ブロックに確定した nullifier → SpentRecord
    confirmed: HashMap<Nullifier, SpentRecord>,
    /// reserved: mempool 内の tx が予約中の nullifier → tx_hash
    reserved: HashMap<Nullifier, [u8; 32]>,
}

impl NullifierSet {
    pub fn new() -> Self {
        Self::default()
    }

    // ─── Confirmed operations ─────────────────────────────────────────────

    /// confirmed セットに nullifier を追加（block apply 時に呼ぶ）
    pub fn insert_confirmed(&mut self, nf: Nullifier, record: SpentRecord) {
        self.confirmed.insert(nf, record);
        // confirm されたので reservation も解放
        self.reserved.remove(&nf);
    }

    /// confirmed セットに nullifier が存在するか
    pub fn is_confirmed_spent(&self, nf: &Nullifier) -> bool {
        self.confirmed.contains_key(nf)
    }

    /// SpentRecord の取得
    pub fn get_record(&self, nf: &Nullifier) -> Option<&SpentRecord> {
        self.confirmed.get(nf)
    }

    /// confirmed セットから tx_hash に対応する最初の nullifier/record を取得する。
    pub fn find_record_by_tx_hash(&self, tx_hash: &[u8; 32]) -> Option<(Nullifier, &SpentRecord)> {
        self.confirmed
            .iter()
            .find_map(|(nf, record)| (record.tx_hash == *tx_hash).then_some((*nf, record)))
    }

    /// confirmed セット内で tx_hash に対応する nullifier 数を返す。
    pub fn confirmed_count_by_tx_hash(&self, tx_hash: &[u8; 32]) -> usize {
        self.confirmed
            .values()
            .filter(|record| record.tx_hash == *tx_hash)
            .count()
    }

    /// DB からロードした nullifier 群をバルク挿入（起動時の復元用）
    pub fn bulk_load(&mut self, entries: impl IntoIterator<Item = (Nullifier, SpentRecord)>) {
        for (nf, record) in entries {
            self.confirmed.insert(nf, record);
        }
    }

    // ─── Reservation operations (mempool) ─────────────────────────────────

    /// mempool が tx を admit する際に nullifier を予約する。
    ///
    /// # Returns
    /// - `Ok(())`: 予約成功
    /// - `Err(NullifierConflict)`: confirmed または既に別 tx が予約中
    pub fn reserve(&mut self, nf: Nullifier, tx_hash: [u8; 32]) -> Result<(), NullifierError> {
        if self.is_confirmed_spent(&nf) {
            return Err(NullifierError::AlreadySpent(nf));
        }
        if let Some(existing_tx) = self.reserved.get(&nf) {
            if *existing_tx != tx_hash {
                return Err(NullifierError::AlreadyReserved {
                    nullifier: nf,
                    reserved_by: *existing_tx,
                });
            }
        }
        self.reserved.insert(nf, tx_hash);
        Ok(())
    }

    /// tx の全 nullifier を一括予約。失敗したら何も予約しない（原子的）。
    pub fn reserve_batch(
        &mut self,
        nullifiers: &[Nullifier],
        tx_hash: [u8; 32],
    ) -> Result<(), NullifierError> {
        // 先に全部チェック
        for nf in nullifiers {
            if self.is_confirmed_spent(nf) {
                return Err(NullifierError::AlreadySpent(*nf));
            }
            if let Some(existing) = self.reserved.get(nf) {
                if *existing != tx_hash {
                    return Err(NullifierError::AlreadyReserved {
                        nullifier: *nf,
                        reserved_by: *existing,
                    });
                }
            }
        }
        // 全部 OK なら挿入
        for nf in nullifiers {
            self.reserved.insert(*nf, tx_hash);
        }
        Ok(())
    }

    /// tx が evict・失敗した際に reservation を解放する
    pub fn release_reservation(&mut self, tx_hash: &[u8; 32]) {
        self.reserved.retain(|_, v| v != tx_hash);
    }

    /// nullifier が reserved かどうか
    pub fn is_reserved(&self, nf: &Nullifier) -> bool {
        self.reserved.contains_key(nf)
    }

    /// confirmed or reserved のいずれかに存在するか（二重使用チェック）
    pub fn is_spent_or_reserved(&self, nf: &Nullifier) -> bool {
        self.is_confirmed_spent(nf) || self.is_reserved(nf)
    }

    // ─── Stats ────────────────────────────────────────────────────────────

    pub fn confirmed_count(&self) -> usize {
        self.confirmed.len()
    }

    pub fn reserved_count(&self) -> usize {
        self.reserved.len()
    }

    /// snapshot: DB 保存のために confirmed entries を返す
    pub fn confirmed_entries(&self) -> Vec<(Nullifier, SpentRecord)> {
        self.confirmed
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }

    /// Remove a confirmed nullifier (for reorg/revert).
    pub fn remove_confirmed(&mut self, nf: &Nullifier) -> bool {
        self.confirmed.remove(nf).is_some()
    }
}

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum NullifierError {
    #[error("nullifier already spent on-chain: {0}")]
    AlreadySpent(Nullifier),
    #[error(
        "nullifier {nullifier} already reserved by tx {}",
        hex::encode(reserved_by)
    )]
    AlreadyReserved {
        nullifier: Nullifier,
        reserved_by: [u8; 32],
    },
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::types::SpentRecord;

    fn nf(i: u8) -> Nullifier {
        Nullifier([i; 32])
    }

    fn record(h: u8) -> SpentRecord {
        SpentRecord {
            tx_hash: [h; 32],
            block_height: 1,
        }
    }

    #[test]
    fn fresh_nullifier_not_spent() {
        let set = NullifierSet::new();
        assert!(!set.is_confirmed_spent(&nf(1)));
    }

    #[test]
    fn insert_and_check() {
        let mut set = NullifierSet::new();
        set.insert_confirmed(nf(1), record(1));
        assert!(set.is_confirmed_spent(&nf(1)));
        assert!(!set.is_confirmed_spent(&nf(2)));
    }

    #[test]
    fn reserve_and_release() {
        let mut set = NullifierSet::new();
        let tx = [0u8; 32];
        set.reserve(nf(1), tx).expect("should reserve");
        assert!(set.is_reserved(&nf(1)));
        set.release_reservation(&tx);
        assert!(!set.is_reserved(&nf(1)));
    }

    #[test]
    fn double_reserve_same_tx_ok() {
        let mut set = NullifierSet::new();
        let tx = [0u8; 32];
        set.reserve(nf(1), tx).expect("first reserve ok");
        set.reserve(nf(1), tx).expect("same tx re-reserve ok");
    }

    #[test]
    fn double_reserve_different_tx_fails() {
        let mut set = NullifierSet::new();
        set.reserve(nf(1), [0u8; 32]).expect("first reserve ok");
        let result = set.reserve(nf(1), [1u8; 32]);
        assert!(matches!(
            result,
            Err(NullifierError::AlreadyReserved { .. })
        ));
    }

    #[test]
    fn reserve_already_spent_fails() {
        let mut set = NullifierSet::new();
        set.insert_confirmed(nf(1), record(1));
        let result = set.reserve(nf(1), [0u8; 32]);
        assert!(matches!(result, Err(NullifierError::AlreadySpent(_))));
    }

    #[test]
    fn batch_reserve_atomic() {
        let mut set = NullifierSet::new();
        set.insert_confirmed(nf(3), record(3)); // nf(3) は消費済み

        // nf(1), nf(2), nf(3) を一括予約 → nf(3) で失敗
        let result = set.reserve_batch(&[nf(1), nf(2), nf(3)], [0u8; 32]);
        assert!(result.is_err());
        // 原子的: nf(1), nf(2) も予約されていない
        assert!(!set.is_reserved(&nf(1)));
        assert!(!set.is_reserved(&nf(2)));
    }

    #[test]
    fn find_record_by_tx_hash_returns_matching_record() {
        let mut set = NullifierSet::new();
        set.insert_confirmed(nf(1), record(0xAA));
        set.insert_confirmed(nf(2), record(0xBB));

        let (found_nf, found_record) = set
            .find_record_by_tx_hash(&[0xBB; 32])
            .expect("record by tx hash");
        assert_eq!(found_nf, nf(2));
        assert_eq!(found_record.tx_hash, [0xBB; 32]);
    }

    #[test]
    fn confirmed_count_by_tx_hash_counts_multiple_nullifiers() {
        let mut set = NullifierSet::new();
        set.insert_confirmed(nf(1), record(0xCC));
        set.insert_confirmed(nf(2), record(0xCC));
        set.insert_confirmed(nf(3), record(0xDD));

        assert_eq!(set.confirmed_count_by_tx_hash(&[0xCC; 32]), 2);
        assert_eq!(set.confirmed_count_by_tx_hash(&[0xDD; 32]), 1);
        assert_eq!(set.confirmed_count_by_tx_hash(&[0xEE; 32]), 0);
    }
}
