# MISAKA-CORE v7 — Security Hardening Report

**Date:** 2026-03-25
**Scope:** Mainnet 攻撃耐性強化 — RPC DoS, API hardening, P2P Eclipse, Relayer, WAL, Reorg
**Status:** 7 fixes implemented, 18 tests added

---

## 1. 今回見つけた高優先度の攻撃面

### CRITICAL (P0)

| # | File | Issue | Impact |
|---|------|-------|--------|
| **C-1** | `rpc_rate_limit.rs:109` | `extract_ip()` が **常に `127.0.0.1` を返す** — per-IP rate limit が実質グローバル1バケット | 単一IPからの全RPC DoS可能。ConcurrencyLimitLayer(64) を1クライアントが独占可能 |
| **C-2** | `dag_rpc.rs:782` | `axum::serve(listener, app)` — `into_make_service_with_connect_info` 未使用 | ConnectInfo が extensions に注入されないため、C-1修正だけでは不十分 |
| **C-3** | `rpc_server.rs:149` | v1 RPC server も同上 + per-IP rate limit middleware 自体が未接続 | v1 RPC は ConcurrencyLimit(64) のみ。IP単位の制限なし |

### HIGH (P1)

| # | File | Issue | Impact |
|---|------|-------|--------|
| **H-1** | `main.rs:211-224` | Swagger UI が `unpkg.com` CDN から JS/CSS ロード | CDN 侵害で operator ブラウザに任意 JS 実行。XSS → API key 窃取 |
| **H-2** | `relayer/config.rs` | 全バリデーション失敗が `panic!()` | systemd restart loop で operator は原因不明。構造化ログ不可 |

### MEDIUM (P2)

| # | File | Issue | Impact |
|---|------|-------|--------|
| **M-1** | `middleware.rs` | Rate limiter が in-memory 固定。trait 抽象化なし | マルチインスタンス環境で rate limit bypass。Redis 移行不可 |
| **M-2** | `reorg_handler.rs` | reorg depth/TX数 に CPU budget なし | 深い reorg 攻撃で validator CPU 枯渇（O(n) 再検証） |
| **M-3** | `discovery.rs` | dial candidate 選択に subnet diversity 制御なし | Eclipse attack: 全 outbound 接続を攻撃者 subnet に誘導 |
| **M-4** | `wal.rs` | `compact()` の rename 後に directory fsync なし | ext4 default mount でクラッシュ時に journal 消失の可能性 |

---

## 2. 実装した修正

### FIX-1: Node RPC per-IP Rate Limit の完全修正 [CRITICAL]

**攻撃シナリオ:** 攻撃者が1 IPから大量リクエストを送信。rate limit は全リクエストを同一バケット（localhost）にカウントするため、正規ユーザーもブロックされる。

**根本原因:** `extract_ip()` が `ConnectInfo<SocketAddr>` を読まず localhost 固定リテラルを返す。`axum::serve()` が `into_make_service_with_connect_info` を使わないため extensions に SocketAddr が注入されない。

**修正内容:**
1. `rpc_rate_limit.rs`: `extract_ip()` を ConnectInfo ベースに書き換え。X-Forwarded-For は明示的に信用しない（Node RPC は direct TCP）
2. `dag_rpc.rs`: `axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())`
3. `rpc_server.rs`: 同上 + per-IP rate limit middleware (`node_rate_limit`) を接続

**互換性影響:** なし。API レスポンスは変わらない。

**追加テスト:**
- `test_per_ip_isolation_different_ips_get_separate_buckets` — 異なるIPが独立バケットを持つことを保証
- `test_write_and_read_tiers_are_separate` — write/read 制限が独立
- `test_extract_ip_with_connect_info` — ConnectInfo からIP抽出できること
- `test_extract_ip_without_connect_info_falls_back_to_localhost` — fallback は localhost（fail-closed）
- `test_is_write_path_classification` — パス分類の正確性
- `test_gc_runs_and_does_not_lose_active_entries` — GC が active entries を消さない

---

### FIX-2: Swagger UI 外部 CDN 依存の除去 [HIGH]

**攻撃シナリオ:** unpkg.com CDN が侵害され、swagger-ui-bundle.js に悪意のある JS が注入される。/docs を開いた operator のブラウザで任意コード実行。API key やセッション情報の窃取が可能。

**根本原因:** swagger-ui の JS/CSS を外部 CDN (`https://unpkg.com/swagger-ui-dist@5/`) からロード。

**修正内容:** feature gate `swagger-cdn` を導入。デフォルト（production）では CDN ロードなしの通知ページを表示。OpenAPI spec は `/api/openapi.yaml` で引き続き提供。`--features swagger-cdn` で dev 環境のみ CDN 版を有効化。

**互換性影響:** `/docs` の表示が変わる（production ではインタラクティブ UI → 通知ページ）。API spec 自体は変わらない。

---

### FIX-3: Rate Limiter Backend Trait 抽象化 [MEDIUM]

**攻撃シナリオ:** API をマルチインスタンスで LB 配下に置くと、各インスタンスが独立した in-memory カウンタを持つ。攻撃者はリクエストを分散させて per-instance limit × N の実効レートを得る。

**根本原因:** `RateLimiter` が `HashMap` を直接保持。backend を差し替える抽象化レイヤーがない。

**修正内容:** `RateLimiterBackend` trait（`async fn check_and_increment`）を定義。現行の `InMemoryBackend` がデフォルト実装。`RateLimiter::with_backend()` で Redis 等の外部 backend に差し替え可能。

**互換性影響:** `RateLimiter::new()` / `with_limits()` のシグネチャ変更なし。内部フィールドが `state: Arc<Mutex<...>>` → `backend: Arc<dyn RateLimiterBackend>` に変更。

---

### FIX-4: Relayer Config panic→typed error 整理 [HIGH]

**攻撃シナリオ:** 直接的な攻撃ではないが、設定ミスで relayer が `panic!()` → systemd restart loop に入り、operator が原因を特定できない。mainnet でのダウンタイム長期化。

**根本原因:** `from_env()` 内の全バリデーションが `panic!()` で即死。エラーの型区分なし。

**修正内容:**
1. `ConfigError` enum（`MissingEnv`, `InvalidNetwork`, `KeypairNotFound`, `NetworkMismatch`, `InvalidField`）を定義
2. `from_env()` → `Result<Self, ConfigError>` に変更
3. URL, program ID, network consistency の validation を関数分離
4. `main.rs` で `error!()` → `process::exit(1)` に変更（clean exit）

**互換性影響:** `from_env()` の戻り値が `Self` → `Result<Self, ConfigError>` に変更。呼び出し側の修正が必要（main.rs は修正済み）。

**追加テスト:**
- `test_validate_url_rejects_empty` / `_non_http` / `_accepts_valid`
- `test_validate_program_id_rejects_short`
- `test_network_consistency_mainnet_rejects_devnet_url` / `_wrong_chain_id` / `_placeholder`
- `test_from_env_missing_network_returns_error`
- `test_from_env_invalid_network_returns_error`
- `test_expand_tilde_with_home`
- `test_config_error_display_messages`

---

### FIX-5: WAL Directory Fsync [MEDIUM-LOW]

**攻撃シナリオ:** compact() が `tmp → rename` した直後にクラッシュ。ext4 default mount (data=ordered) では rename は directory entry 更新だが、journal commit は次の periodic writeback (~30s) まで遅延。この窓でクラッシュすると journal ファイルが消失し、ノードが inconsistent state で起動する。

**根本原因:** `fs::rename()` 後に親ディレクトリの `fsync()` を呼んでいない。

**修正内容:** `compact()` と `clear()` の後に `fsync_directory()` を追加。SQLite/RocksDB と同等の crash safety。

**互換性影響:** なし。パフォーマンスへの影響は compact/clear 時のみ（infrequent）。

**追加テスト:**
- `test_wal_truncated_mid_write_detected` — partial write からの回復
- `test_wal_compact_preserves_incomplete_blocks` — compact が in-progress TX を保持
- `test_wal_multiple_phases_tracked_correctly` — 最後の phase を正確に追跡
- `test_wal_empty_file_handled_gracefully`
- `test_wal_all_blank_lines_ignored`

---

### FIX-6: Reorg Handler CPU Budget [MEDIUM]

**攻撃シナリオ:** 攻撃者が意図的に深い reorg（100+ blocks × 1000 TXs/block）をトリガー。orphaned TX の再評価がO(n)で行われ、validator CPU が数十秒間専有される。その間の block production が停止。

**根本原因:** `evaluate_orphans()` に depth limit も TX budget もない。

**修正内容:**
1. `MAX_REORG_EVALUATION_DEPTH = 128` — 超過時は全 orphan を即 drop
2. `MAX_REORG_EVALUATION_TX_BUDGET = 5_000` — depth 以内でも TX 数で cap
3. `evaluate_orphans()` に `reorg_depth: usize` パラメータ追加
4. Budget 超過時は `tracing::warn!` で operator 通知 + 残り TX を drop

**互換性影響:** `evaluate_orphans()` のシグネチャ変更（`reorg_depth` パラメータ追加）。呼び出し側の修正が必要。

**追加テスト:**
- `test_deep_reorg_drops_all_orphans` — 深い reorg で全 drop
- `test_reorg_at_exact_depth_limit_still_evaluates` — 境界値
- `test_tx_budget_caps_evaluation` — TX budget 超過で drop

---

### FIX-7: P2P Discovery Subnet Diversity + Record Freshness [MEDIUM]

**攻撃シナリオ:** 攻撃者が同一 /24 (IPv4) or /48 (IPv6) から大量の peer record を advertise。dial candidate 選択が subnet を考慮しないため、全 outbound 接続が攻撃者ノードに行く（Eclipse attack）。

**根本原因:** `select_dial_candidates()` が failure count と freshness でソートするのみ。subnet diversity 制約なし。

**修正内容:**
1. `MAX_DIAL_CANDIDATES_PER_SUBNET = 2` — 同一 SubnetId からの candidate を制限
2. `MAX_RECORD_AGE_SECS = 6h` — stale record を dial candidate から除外
3. `select_dial_candidates()` で SubnetId ベースの diversity 選択を実装

**互換性影響:** outbound 接続先の分布が変わる（より diverse に）。機能的な互換性問題なし。

**追加テスト:**
- `test_dial_candidates_subnet_diversity` — 同一 subnet cap の検証
- `test_stale_records_not_selected_for_dial` — stale record 除外

---

## 3. 追加したテスト一覧

| Crate | Test | Category |
|-------|------|----------|
| misaka-node | `test_per_ip_isolation_different_ips_get_separate_buckets` | Unit |
| misaka-node | `test_write_and_read_tiers_are_separate` | Unit |
| misaka-node | `test_extract_ip_with_connect_info` | Unit |
| misaka-node | `test_extract_ip_without_connect_info_falls_back_to_localhost` | Unit |
| misaka-node | `test_is_write_path_classification` | Unit |
| misaka-node | `test_gc_runs_and_does_not_lose_active_entries` | Unit |
| misaka-storage | `test_wal_truncated_mid_write_detected` | Regression |
| misaka-storage | `test_wal_compact_preserves_incomplete_blocks` | Regression |
| misaka-storage | `test_wal_multiple_phases_tracked_correctly` | Regression |
| misaka-storage | `test_wal_empty_file_handled_gracefully` | Regression |
| misaka-storage | `test_wal_all_blank_lines_ignored` | Regression |
| misaka-mempool | `test_deep_reorg_drops_all_orphans` | Unit |
| misaka-mempool | `test_reorg_at_exact_depth_limit_still_evaluates` | Unit |
| misaka-mempool | `test_tx_budget_caps_evaluation` | Unit |
| misaka-p2p | `test_dial_candidates_subnet_diversity` | Integration |
| misaka-p2p | `test_stale_records_not_selected_for_dial` | Unit |
| misaka-relayer | `test_from_env_missing_network_returns_error` + 9 others | Unit |

---

## 4. まだ残る Mainnet 前の課題 (Backlog)

### P0 — Mainnet Blocker

1. **Redis-backed rate limiter 実装** — trait は導入済み。実装 + integration test が必要
2. **P2P message size pre-validation** — decode 前に length/count/depth の cheap check を入れる。現状は巨大メッセージが decode まで到達する
3. **`dev-rpc` feature の production build 排除確認** — `get_address_outputs` がアドレス→UTXO マッピングをリークする。CI で `--no-default-features` ビルドテスト追加
4. **Snapshot 読み込み時の integrity check** — silent fallback がないか確認。破損時に fail-closed + operator 通知が必要

### P1 — High Priority

5. **Per-AS diversity** — 現状 SubnetId は /24 (IPv4) / /48 (IPv6) のみ。AS-level diversity（GeoIP or BGP origin AS）は未実装
6. **Inbound connection per-subnet cap in discovery layer** — `connection_guard.rs` は既に実装済みだが、discovery ingress 側でも subnet count を追跡すべき
7. **Faucet queue depth atomic counter** — 現状は `Mutex<usize>`。`AtomicUsize` に置き換えでロック競合を削減
8. **WAL versioning header** — journal format が変わった時に backward compat を保証するためのバージョンバイトを先頭に追加
9. **Relayer poll loop back-off** — 連続エラー時の exponential back-off + circuit breaker パターン
10. **Logging audit** — 秘密鍵の hex dump、過剰な内部状態、PII がログに出ないか全 `tracing::*` 呼び出しを監査

### P2 — Nice to Have

11. **Tarpit for rate-limited clients** — 即 429 ではなく人工遅延でbot の retry 効率を下げる
12. **CORS origin の runtime reload** — 現状はプロセス再起動が必要
13. **Idempotency cache の shared backend 対応** — rate limiter 同様に Redis 移行可能にする
14. **P2P handshake timeout enforcement** — 現状 handshake 中の resource 使用量に段階制御なし
15. **Mempool eviction policy formalization** — fee, size, age, conflict history に基づく明示的な eviction 優先度

---

## 変更ファイル一覧

```
crates/misaka-node/src/rpc_rate_limit.rs    — FIX-1: extract_ip + ConnectInfo + tests
crates/misaka-node/src/dag_rpc.rs           — FIX-1: into_make_service_with_connect_info
crates/misaka-node/src/rpc_server.rs        — FIX-1: ConnectInfo + per-IP rate limit middleware
crates/misaka-api/src/main.rs               — FIX-2: Swagger UI feature gate
crates/misaka-api/src/middleware.rs          — FIX-3: RateLimiterBackend trait
crates/misaka-api/Cargo.toml                — FIX-2/3: swagger-cdn feature, async-trait dep
crates/misaka-storage/src/wal.rs            — FIX-5: directory fsync + tests
crates/misaka-mempool/src/reorg_handler.rs  — FIX-6: CPU budget + depth limit + tests
crates/misaka-p2p/src/discovery.rs          — FIX-7: subnet diversity + freshness + tests
relayer/src/config.rs                       — FIX-4: typed errors + tests
relayer/src/main.rs                         — FIX-4: from_env() Result handling
relayer/Cargo.toml                          — FIX-4: thiserror dep
```
