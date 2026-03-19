# MISAKA Network — Pre-Mainnet アーキテクチャ再構築レポート

**Date:** 2026-03-18
**Scope:** RPC暗号検証バイパス遮断、ブロック生成堅牢化、Relayer本実装化

---

## Executive Summary

10項目の修正を完了。最も深刻な問題は**RPC `submit_tx` が暗号検証を完全にバイパス**し、
任意のJSONがそのままブロック化されていたこと。`UtxoMempool::admit()` という
完全な検証実装が既に存在していたにも関わらず、一切呼ばれていなかった。

---

## フェーズ1: CRITICAL（暗号検証バイパスの遮断）

### 1. submit_tx の検証統合 ✅

**問題:** `submit_tx` が `serde_json::Value` として任意のJSONを受け取り、
`pending_txs: VecDeque<PendingTx>` に `raw_json: String` として突っ込んでいた。
リング署名、KI証明、UTXO存在確認、金額整合性チェックが**一切なし**。
攻撃者は `{"fee":0,"outputs":[{"amount":999999999}]}` を送るだけで無限通貨生成可能。

**修正:**
- `Json<serde_json::Value>` → `axum::body::Bytes` + `serde_json::from_slice::<UtxoTransaction>()`
- `UtxoMempool::admit(tx, &utxo_set, now_ms)` を**必ず通過**
- `admit()` がリング署名検証、KI証明検証、UTXO存在確認、二重支払い検出を実行
- `Err` → 即座にJSON `{"accepted":false}` で拒否（Fail-closed）

### 2. 決定的TXハッシュ ✅

**問題:** `tx_hash = SHA3(body_json || now_ms)` — タイムスタンプ依存で非決定的。
同一TXを再送すると異なるハッシュが生成される。

**修正:** `UtxoTransaction::tx_hash()` による canonical encoding ハッシュに統一。
TX内容（inputs, outputs, fee, ring signatures）のみからの決定的計算。

### 3. Block Producer の生JSON再パース廃止 ✅

**問題:** `parse_outputs_from_raw(raw_json)` / `parse_inputs_from_raw(raw_json)` が
ブロック生成時に生JSONを再解釈。Mempoolでの検証結果とブロック内実体が乖離する危険。

**修正:**
- `PendingTx { raw_json: String }` 構造体を完全に廃止
- `NodeState` から `pending_txs: VecDeque<PendingTx>` を削除
- `NodeState.mempool: UtxoMempool` に置換
- Block Producer は `mempool.top_by_fee(n)` で検証済み `UtxoTransaction` を取得
- `verified_tx_to_stored()` で型安全にStoredTxへ変換（JSON再パースなし）

---

## フェーズ2: HIGH（インフラ安全確保）

### 4. Faucet フィーチャーゲート化 ✅

**修正:**
- `#[cfg(feature = "faucet")]` でエンドポイント全体をゲート
- ハードコード `1_000_000` → `NodeState.faucet_amount` (config読み込み)
- ハードコード `300_000ms` → `NodeState.faucet_cooldown_ms` (config読み込み)

### 5. CORS 厳格化 ✅

**修正:**
- `CorsLayer::permissive()` 廃止
- 環境変数 `MISAKA_CORS_ORIGINS` からカンマ区切りで許可オリジン読み込み
- 未設定時は `localhost:3000`, `localhost:3001`, `127.0.0.1:3000` のみ許可

### 6. Relayer Solana Event 本実装 ✅

**問題:** `parse_lock_event_from_log()` がプレースホルダ。`amount: 0` を返すだけ。

**修正:**
- Anchor `"Program data: "` プレフィックス後のbase64データをデコード
- 8バイトdiscriminator → SHA256("event:TokensLocked")[..8] と照合
- Borshレイアウト: user(32) + mint(32) + amount(8) + recipient(4+N) + nonce(8)
- mint/user → base58エンコード、amount/nonce → LE u64デコード
- misaka_recipient → UTF-8文字列 + `msk1` プレフィックス検証
- amount == 0 → 拒否

### 7. Relayer HTTP クライアント ✅

**問題:** 生TcpStream + 手書きHTTP/1.1リクエスト。TLS非対応、タイムアウトなし。

**修正:**
- `misaka_watcher.rs`: `http_post()` → `reqwest::Client` (30秒タイムアウト、ステータスコード検証)
- `solana_watcher.rs`: `http_post_json()` → `reqwest::Client` (同上)

### 8. Bridge 構文エラー ✅

**修正:** `require!(... BridgeError::InsufficientCommitteeSignatures` → 末尾 `);` 追加。

---

## フェーズ3: MEDIUM（状態管理と検証強化）

### 9. ProcessedStore Fail-closed ✅

**問題:** `load().unwrap_or(Self::new())` — ファイル破損時に履歴がリセット、二重処理。

**修正:**
- ファイル存在 + パース失敗 → `anyhow::bail!` (FATALエラーでプロセス停止)
- ファイル不在 (初回起動) → `Self::new()` (正当な初期化)
- `save()` → atomic write (tmp → rename) でクラッシュ時の部分書き込み防止

### 10. Ed25519 全署名走査 ✅

**問題:** Ed25519 instruction内の最初の署名エントリーのみ検査。

**修正:**
- `num_sigs` 全エントリーをループ走査
- 各エントリーの `sig_ix_index`, `pk_ix_index`, `msg_ix_index` が
  `0xFFFF` (同一instruction内データ参照) であることを検証
- offset/sizeの厳密なbounds check

---

## 変更ファイル一覧

| ファイル | 変更概要 |
|---------|---------|
| `crates/misaka-node/src/rpc_server.rs` | submit_tx → mempool.admit() 統合、CORS厳格化、Faucetゲート |
| `crates/misaka-node/src/block_producer.rs` | 全面書き換え: PendingTx廃止、UtxoMempool統合 |
| `relayer/src/solana_watcher.rs` | Anchor event parser本実装、reqwest化 |
| `relayer/src/misaka_watcher.rs` | reqwest化 |
| `relayer/src/main.rs` | ProcessedStore fail-closed + atomic write |
| `relayer/src/config.rs` | misaka_chain_id追加 |
| `relayer/src/message.rs` | BurnReceipt/LockEvent フィールド修正 |
| `solana-bridge/.../lib.rs` | Ed25519全署名走査、構文エラー修正 |

---

## データフロー（修正後）

```
Wallet/CLI
    │
    ▼
submit_tx (RPC)
    │  Bytes → serde_json::from_slice::<UtxoTransaction>()
    │  厳密な型デシリアライズ（任意JSON拒否）
    ▼
UtxoMempool::admit(tx, utxo_set)
    │  ✓ validate_structure()
    │  ✓ UTXO存在確認 (ring members)
    │  ✓ リング署名検証 (LRS/LogRing/Chipmunk)
    │  ✓ KI/Link-tag 証明検証
    │  ✓ 二重支払い検出 (chain + mempool)
    │  ✓ Stealth extension sanity
    │  × いずれか失敗 → {"accepted": false, "error": "..."}
    ▼
Mempool (verified entries only)
    │
    ▼
Block Producer
    │  mempool.top_by_fee(256)
    │  → Vec<&UtxoTransaction>  (検証済みオブジェクト)
    │  → verified_tx_to_stored()  (JSON再パースなし)
    ▼
Block (chain_store)
```
