# MISAKA Core — セキュリティ監査修正サマリー

**日付**: 2026-03-25
**対象**: MISAKA-CORE v0.5.1
**指摘件数**: 9件（Critical 3 / High 2 / Medium 4）
**修正件数**: 9/9 完了

---

## Critical

### SEC-FIX-1: API per-IP rate limit が全体 bucket 化していた

| 項目 | 内容 |
|------|------|
| ファイル | `misaka-api/src/main.rs`, `misaka-api/src/middleware.rs` |
| 原因 | `axum::serve(listener, app)` で起動していたため `ConnectInfo<SocketAddr>` が注入されず、`extract_ip()` が常に `127.0.0.1` を返していた |
| 修正 | `into_make_service_with_connect_info::<SocketAddr>()` を有効化。`extract_ip()` で `req.extensions().get::<ConnectInfo<SocketAddr>>()` からソケットIPを読むように変更。fallback 時は `warn!` ログ出力 |

### SEC-FIX-2: Faucet IP 制限が全ユーザー共用ロックになっていた

| 項目 | 内容 |
|------|------|
| ファイル | `misaka-api/src/routes/faucet.rs` |
| 原因 | `ConnectInfo` が取得できない場合に `"unknown"` 文字列にフォールバックし、全リクエストが同一IP扱いになっていた |
| 修正 | `ConnectInfo` が `None` の場合は `500 Internal Server Error` でリジェクト。サーバー設定不備として明示的に拒否する |

### SEC-FIX-6: Block reward 送付先がハードコード仮値 `[0x01; 32]` / `[0x02; 32]`

| 項目 | 内容 |
|------|------|
| ファイル | `misaka-node/src/block_producer.rs`, `misaka-node/src/main.rs` |
| 原因 | proposer/treasury アドレスが placeholder のまま。報酬が誰にも属さないアドレスへ流出 |
| 修正 | `NodeState` に `proposer_payout_address` / `treasury_address` (両方 `Option<[u8; 32]>`) を追加。CLI/env (`--proposer-payout-address`, `MISAKA_PROPOSER_ADDRESS`) で設定。未設定時は coinbase 生成をスキップし `warn!` 出力。起動時にもバリデータへ警告表示 |

---

## High

### SEC-FIX-3: Peer discovery が未認証アドレスを受理 → eclipse / SSRF 足がかり

| 項目 | 内容 |
|------|------|
| ファイル | `misaka-node/src/dag_p2p_network.rs`, `misaka-node/src/dag_p2p_transport.rs` |
| 原因 | gossip 経由の peer アドレスを無検証で `discovered_peers` に追加。private IP も受理していた |
| 修正 | (1) `is_discovery_addr_rejected()` で loopback / private / link-local / CGN / documentation / ULA アドレスを拒否。(2) transport 側で `transport_pubkey: None` の peer を dial 対象から除外（TOFU 防止） |

### SEC-FIX-5: Keystore が HKDF ベースでオフライン総当たりに脆弱

| 項目 | 内容 |
|------|------|
| ファイル | `misaka-crypto/src/keystore.rs`, `misaka-crypto/Cargo.toml` |
| 原因 | HKDF-SHA3-256 は password-hard ではなく、弱パスフレーズだと高速に総当たり可能 |
| 修正 | v2 形式で **argon2id** (m=256MiB, t=4, p=2) を導入。新規暗号化は常に v2。v1 (HKDF) は復号のみ対応（migration パス）。`migrate_keystore_v1_to_v2()` と `needs_migration()` ヘルパー追加。テスト6件（v2 roundtrip, v1 legacy decrypt, v1→v2 migration 等） |

---

## Medium

### SEC-FIX-4: DAG block serve/ingest の body 完全性検証が弱い

| 項目 | 内容 |
|------|------|
| ファイル | `misaka-node/src/dag_p2p_network.rs` |
| 原因 | `GetDagBlocks` 応答が `txs_json: vec![]` 固定。受信側も atomic pipeline をバイパス |
| 修正 | (1) serve 側: `dag_store.get_block_txs()` で実際の TX body を返す。body 欠如時は `warn!` 出力。(2) receive 側: `txs_json` を `serde_json::from_slice` でデシリアライズし、失敗時は quarantine。`insert_block()` に `received_txs` を渡す |

### SEC-FIX-7: Discovery 情報の量・質の制御が甘い

| 項目 | 内容 |
|------|------|
| ファイル | `misaka-node/src/dag_p2p_network.rs` |
| 原因 | 100件 cap はあるが品質制御なし。1 peer から100件の偽アドレスで埋められる |
| 修正 | (1) per-source limit: 同一送信元から最大5件。(2) deduplication: 既存アドレスをスキップ。(3) subnet diversity: 同一 /24 (IPv4) or /48 (IPv6) に最大3件。`extract_subnet_prefix()` ヘルパー追加 |

### SEC-FIX-8: API rate limiter が in-memory のみ

| 項目 | 内容 |
|------|------|
| ファイル | `misaka-api/src/middleware.rs` |
| 対応 | doc コメントに multi-instance 制限事項を明記: restart リセット、instance 跨ぎバイパス、tarpit 未実装。mainnet 向けに Redis ベースの推奨設計（key schema, 2段階 burst/sustained）を記載 |

### SEC-FIX-9: Faucet queue depth カウンタのドリフト

| 項目 | 内容 |
|------|------|
| ファイル | `misaka-api/src/routes/faucet.rs` |
| 原因 | `queue_tx.send()` 失敗時・タイムアウト時・oneshot ドロップ時に depth カウンタがデクリメントされず、永続的にインクリメントされ続ける |
| 修正 | 3箇所に `saturating_sub(1)` デクリメントを追加: (1) send 失敗時、(2) oneshot channel ドロップ時、(3) 30s タイムアウト時 |

---

## 変更ファイル一覧

| ファイル | Fix # |
|----------|-------|
| `crates/misaka-api/src/main.rs` | #1 |
| `crates/misaka-api/src/middleware.rs` | #1, #8 |
| `crates/misaka-api/src/routes/faucet.rs` | #2, #9 |
| `crates/misaka-node/src/dag_p2p_network.rs` | #3, #4, #7 |
| `crates/misaka-node/src/dag_p2p_transport.rs` | #3 |
| `crates/misaka-node/src/block_producer.rs` | #6 |
| `crates/misaka-node/src/main.rs` | #6 |
| `crates/misaka-crypto/src/keystore.rs` | #5 |
| `crates/misaka-crypto/Cargo.toml` | #5 |
