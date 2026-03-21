# MISAKA Network — 統合セキュリティ監査 最終修正レポート

**Date:** 2026-03-19  
**Patch:** MISAKA-ALL-FIXES-FINAL.patch (3,161 lines, 38 files)  
**対象コードベース:** misaka-CONSENSUS-SAFE v1.0 (19,000+ LoC)

---

## 修正サマリ

| カテゴリ | CRITICAL | HIGH | MEDIUM | LOW | 合計 |
|---------|----------|------|--------|-----|------|
| 暗号・PQC | 2 | 1 | - | - | 3 |
| コンセンサス迂回 | 1 | - | - | - | 1 |
| UTXO ライフサイクル | 1 | - | 1 | - | 2 |
| P2P / ネットワーク | - | 1 | - | - | 1 |
| ブリッジ / Relayer | - | 1 | - | - | 1 |
| ストレージ耐障害性 | - | 1 | 3 | - | 4 |
| 設定検証 | - | 1 | - | - | 1 |
| 型安全性 | - | - | 1 | - | 1 |
| **合計** | **4** | **5** | **5** | **0** | **14** |

---

## CRITICAL 修正 (4件)

### SEC-001: LogRing signer_pk 露出によるアノニミティ破壊
**File:** `crates/misaka-pqc/src/logring.rs`

`LogRingSignature` から `signer_pk` フィールドを除去。検証時は Merkle path の
directions ビットから leaf index を復元し `ring_pubkeys[index]` を使用。
署名のワイヤサイズが 512 バイト削減。

### SEC-002: LogRing Fiat-Shamir transcript 不整合
**File:** `crates/misaka-pqc/src/logring.rs`

`logring_challenge()` から `signer_pk` パラメータを除去。
Sign / Verify 両方で同一の transcript を使用:
`H(DST_CHALLENGE || merkle_root || message || h(w) || link_tag)`

### ARCH-001: Block Producer コンセンサス検証迂回
**File:** `crates/misaka-node/src/block_producer.rs` (全面書き換え)

`apply_block_atomic()` の直接呼び出しを除去。新フロー:
Mempool → `resolve_tx()` → `BlockCandidate` → `execute_block()` → `validate_and_apply_block()`

新規 `crates/misaka-consensus/src/tx_resolve.rs` (130行) を追加。

### ARCH-002: 新規 UTXO の Spending Pubkey 未永続化
**Files:** `crates/misaka-types/src/utxo.rs`, `crates/misaka-consensus/src/block_validation.rs`

`TxOutput` に `spending_pubkey: Option<Vec<u8>>` を追加。
`validate_and_apply_block()` 内で output 作成時に `register_spending_key()` を自動呼出。
38 ファイルの全 `TxOutput` コンストラクタを更新。

---

## HIGH 修正 (5件)

### SEC-003: LRS KI Proof 省略可能
**Files:** `block_validation.rs`, `mempool/lib.rs`

LRS スキームで KI proof を必須化。None / empty は即座にリジェクト。

### SEC-004: P2P Handshake MITM 保護
**File:** `crates/misaka-p2p/src/handshake.rs`

`complete()` に `expected_responder_pk` パラメータ追加。
なりすまし Responder を decapsulate 前に検出。

### SEC-005: Bridge Relayer 二重処理防止 (レビュー反映済み)
**Files:** `relayer/src/store.rs` (全面書き換え), `relayer/src/main.rs` (全面書き換え)

**レビュー Critical #1〜#3 を反映:**
- `is_processed → send → mark` の危険なフロー → `try_claim(pending) → send → mark_completed/failed` に変更
- `Mutex<Connection>` で排他制御
- `transaction_with_behavior(TransactionBehavior::Exclusive)` で正しい排他TX
- `ClaimResult` enum (`Claimed` / `AlreadyCompleted` / `InProgress`)
- `pending → completed / failed` の3段階状態遷移
- `attempt_count`, `external_tx_id`, `last_error`, `claimed_at` カラム追加
- `amount` を `TEXT` で保存 (`u64 → i64` cast 問題の回避)
- `solana_errors` / `misaka_errors` の分離

### SEC-006: derive_secret_poly ゼロ多項式フォールバック
**File:** `crates/misaka-pqc/src/pq_ring.rs`

戻り値を `Result<Poly, CryptoError>` に変更。20 ファイルの呼び出し箇所を更新。

### CONF-001: CLI Config Validation のランタイム実体化
**Files:** `crates/misaka-node/src/main.rs`, `config_validation.rs`

CLI 引数全体から `TestnetConfig` を構築。`WrongTestnetChainId` を有効化。

---

## MEDIUM 修正 (5件)

### STORE-001: block_store.rs コメント/実装不整合
コメントの「bincode」を実装通りの「JSON」に修正。

### STORE-002: `created_at` が height であることが不明瞭
`StoredUtxo.created_at` → `created_in_height` にリネーム。

### STORE-003: single-writer 前提が未文書化
`RocksBlockStore` の doc comment に single-writer invariant を明記。

### STORE-004: 未使用 import
`block_store.rs` から `IteratorMode`, `Direction`, `Sha3_256`, `Sha3Digest`, `error` を除去。

### TYPE-001: TxType 明示化
`TxType` enum (`Transfer` / `Coinbase` / `Faucet`) を追加。
`UtxoTransaction` に `tx_type` フィールド追加。全コンストラクタ更新。

---

## Phase 2.4: 空ブロック時 State Height 同期
全ブロック（空含む）が `execute_block()` を通過するため height が常に同期。
`chain_store.rs` の `state_root` をプレースホルダとして明記。

---

## Relayer 安全フロー（レビュー反映後）

```
poll event
  → deterministic event_id (SHA3-256)
  → try_claim(event_id)
      → INSERT 'pending' (新規) → Claimed
      → 既存 'completed' → AlreadyCompleted (skip)
      → 既存 'pending' → InProgress (skip — 他workerが処理中)
      → 既存 'failed' → UPDATE to 'pending', attempt_count++ → Claimed (retry)
  → 外部送信 (mint / unlock)
  → 成功: mark_completed(event_id, external_tx_id)
  → 失敗: mark_failed(event_id, error_message)
```

**保証:**
- Multi-instance safe: EXCLUSIVE transaction で物理的に排他
- Crash recovery: pending のまま残ったメッセージは再起動後にfailed扱い→retry可能
- Replay safe: completed は二度と処理されない

---

## 変更ファイル一覧 (38 files)

| # | ファイル | 変更種別 | 修正ID |
|---|---------|---------|--------|
| 1 | `crates/misaka-pqc/src/logring.rs` | 大規模変更 | SEC-001, SEC-002 |
| 2 | `crates/misaka-pqc/src/pq_ring.rs` | 変更 | SEC-006 |
| 3 | `crates/misaka-node/src/block_producer.rs` | **全面書き換え** | ARCH-001 |
| 4 | `crates/misaka-consensus/src/tx_resolve.rs` | **新規** | ARCH-001 |
| 5 | `crates/misaka-consensus/src/block_validation.rs` | 変更 | SEC-003, ARCH-002 |
| 6 | `crates/misaka-consensus/src/lib.rs` | 変更 | ARCH-001 |
| 7 | `crates/misaka-types/src/utxo.rs` | 変更 | ARCH-002, TYPE-001 |
| 8 | `crates/misaka-p2p/src/handshake.rs` | 変更 | SEC-004 |
| 9 | `relayer/src/store.rs` | **全面書き換え** | SEC-005 (v2) |
| 10 | `relayer/src/main.rs` | **全面書き換え** | SEC-005 (v2) |
| 11 | `relayer/Cargo.toml` | 変更 | SEC-005 |
| 12 | `crates/misaka-storage/src/block_store.rs` | **新規** | STORE-001〜004 |
| 13 | `crates/misaka-storage/src/recovery.rs` | **新規** | 起動時整合性チェック |
| 14 | `crates/misaka-storage/src/lib.rs` | 変更 | モジュール追加 |
| 15 | `crates/misaka-storage/Cargo.toml` | 変更 | rocksdb 追加 |
| 16 | `crates/misaka-node/src/main.rs` | 変更 | CONF-001, 起動チェック |
| 17 | `crates/misaka-node/src/config_validation.rs` | 変更 | CONF-001 |
| 18 | `crates/misaka-node/src/chain_store.rs` | 変更 | state_root doc |
| 19 | `crates/misaka-node/src/rpc_server.rs` | 変更 | TxType, spending_pubkey |
| 20 | `crates/misaka-node/src/sync.rs` | 変更 | TxType, spending_pubkey |
| 21-38 | その他 18 ファイル | 変更 | SEC-006 unwrap, TxOutput field |
