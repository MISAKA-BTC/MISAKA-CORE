> **⚠ HISTORICAL DOCUMENT — v0.4.x era**
>
> This document was written for a previous codebase version that included
> PoW/mining, dev features, and faucet functionality. As of v0.5.0,
> MISAKA Network is **Pure PoS** with no PoW, no faucet, and no dev features.
> References to `pq_hash`, `mining`, `RandomX`, `Argon2id PoW`, `faucet`,
> `dev-rpc`, `dev-bridge-mock`, and `MockVerifier` are no longer applicable.

---

# MISAKA Core v2 — Mainnet Hardening Changelog

**Date**: 2026-03-19
**Scope**: CLI wallet anonymity, DAG isolation, config hardcoding, bridge safety

---

## Phase 1: CRITICAL — 匿名性の崩壊防止と未完成機能の隔離

### 1. CLI ダミーデコイの完全廃止 [CRITICAL]

**Files**: `crates/misaka-cli/src/transfer.rs` (full rewrite)

**Before**: リング署名のデコイが人工生成の `Poly` で構築され、`ringMembers` が `"00".repeat(32)` 等の固定値。実際のチェーン上の UTXO ではないため、検証者が即座に「位置0が真の署名者」と判別可能 → **匿名性ゼロ**。

**After**:
- RPC `/api/get_decoy_utxos` 経由で same-amount の実 UTXO を取得
- `spending_pubkey` を持つ UTXO のみ使用（ring signature 構築に必要）
- signer 位置をリング内でランダム化（`rand::gen_range`）
- decoy 不足時は明確なエラー（暗黙のフォールバックなし）

### 2. 手書き HTTP クライアントの全廃 [CRITICAL]

**Files**: `crates/misaka-cli/src/rpc_client.rs` (full rewrite), `Cargo.toml`

**Before**: 生 TCP ソケット + 手書き URL パーサ。TLS 非対応、chunked encoding の不完全な処理、タイムアウトなし。

**After**:
- `reqwest` クレートに完全移行
- 30秒タイムアウト + 10秒 connect timeout
- transient error に対する最大2回リトライ（500ms 間隔）
- non-2xx ステータスの拒否（fail-closed）
- `RpcClient` struct でコネクションプール再利用

### 3. DAG 機能の厳格隔離 [CRITICAL]

**Files**: `crates/misaka-node/Cargo.toml`, `crates/misaka-node/src/main.rs`

**Before**: `dag_consensus` feature が release build でもコンパイル可能。チェックポイントに `genesis_hash` と `[0u8; 32]` がハードコード。

**After**:
- Feature flag を `experimental_dag` にリネーム
- `#[cfg(all(not(debug_assertions), feature = "experimental_dag"))] compile_error!(...)` 追加 → release build で DAG モードは物理的にコンパイル不可
- チェックポイントのプレースホルダを `panic!()` ガードに置換（未実装の `selected_parent_chain_tip()` / `compute_utxo_root()` を呼ぶ形に）
- 全 `dag_consensus` 参照を `experimental_dag` に統一

---

## Phase 2: HIGH — 設定の一元化と脆弱なインターフェースの修正

### 4. chain_id ハードコード廃止 [HIGH]

**Files**: `crates/misaka-rpc/src/lib.rs`

**Before**: `NodeStatus { chain_id: 1, ... }` — テストネット（chain_id=2）で不正な値を返却。

**After**: `handle_request()` に `chain_id: u32` パラメータを追加。呼び出し側からランタイム設定値を注入。

### 5. faucet_amount / faucet_cooldown CLI引数化 [HIGH]

**Files**: `crates/misaka-node/src/main.rs`

**Before**: `faucet_amount: 1_000_000` / `faucet_cooldown_ms: 300_000` がハードコード。

**After**: `--faucet-amount` / `--faucet-cooldown-ms` CLI 引数で設定可能。デフォルト値は既存と同じ。

### 6. Bridge ReplayProtection の volatile デフォルト排除 [HIGH]

**Files**: `crates/misaka-bridge/src/replay.rs`, `crates/misaka-bridge/src/lib.rs`

**Before**: `ReplayProtection::new()` が pub で volatile バックエンドを返す。prod コードで呼ぶとリスタート時に全 nullifier 喪失 → リプレイ攻撃可能。

**After**:
- `new()` → `#[cfg(test)] new_volatile_for_test()` にリネーム
- `BridgeModule::new()` が `replay_data_path: &Path` を必須引数として受取
- テストコードは `BridgeModule::new_for_test()` を使用
- `BridgeError::Internal` variant 追加

### 7. DAG CORS の unwrap() 修正 [HIGH]

**Files**: `crates/misaka-node/src/dag_rpc.rs`

**Before**: `"http://localhost:3000".parse::<HeaderValue>().unwrap()` — 単一オリジンかつ unwrap。

**After**: v1 `rpc_server.rs` と同じパターン（`expect("static origin")` + localhost 4オリジン）に統一。

---

## Phase 2 Addendum: 型安全性とAPI hardening

### 9. VerifiedRingProof enum 導入 — ダミー署名オブジェクトの排除 [HIGH]

**Files**: `crates/misaka-consensus/src/block_validation.rs`, `crates/misaka-consensus/src/tx_resolve.rs`

**Before**: `VerifiedTx` が全スキームで `Vec<RingSig>` と `Vec<Option<KiProof>>` を持ち、LogRing/Chipmunk では `Poly::zero()` のダミー `RingSig` が入っていた。型がスキームの意味論を反映していない。

**After**:
- `VerifiedRingProof` enum: `Lrs { sig, ki_proof }` / `LogRing { raw_sig }` / `Chipmunk { raw_sig, raw_ki_proof }`
- `VerifiedTx.ring_proofs: Vec<VerifiedRingProof>` — ダミー値が型レベルで不可能
- block_validation の `match tx.ring_scheme` → `match &vtx.ring_proofs[i]` に変更（コンパイル時網羅性保証）
- tx_resolve.rs からダミー `RingSig { c0: Poly::zero(), ... }` 構築を完全除去

### 10. P2P handshake API — Option<PK> 排除 [HIGH]

**Files**: `crates/misaka-p2p/src/handshake.rs`

**Before**: `complete(reply, sk, expected_pk: Option<&PK>)` — `None` を渡すとMITM保護がスキップされる。

**After**:
- `complete_verified(reply, sk, expected_pk: &PK)` — 本番用、PK必須
- `complete_unverified_for_dev(reply, sk)` — `#[cfg(feature = "dev")]` ガード
- `Option` による安全性バイパスが型レベルで不可能

### 11. P2pMessage::encode() → Result [MEDIUM]

**Files**: `crates/misaka-node/src/p2p_network.rs`

**Before**: `encode() -> Vec<u8>` — シリアライズ失敗時に空の `Vec` を返し、相手に壊れたフレームを送信しうる。

**After**: `encode() -> Result<Vec<u8>, serde_json::Error>` — 全呼び出し箇所で `match` / `unwrap_or_default()` で適切にハンドリング。

### 12. Workspace clippy lints 全crate有効化 [LOW]

**Files**: 全17 crate の `Cargo.toml`

`[lints] workspace = true` を追加し、workspace の `unwrap_used = "deny"` / `expect_used = "deny"` / `panic = "deny"` が全crateに適用される。

---

## Phase 3: MEDIUM — ウォレット状態の改善

### 8. Wallet State: チェーンスキャン統合 [MEDIUM]

**Files**: `crates/misaka-cli/src/transfer.rs`, `crates/misaka-cli/src/wallet_state.rs`

**Before**: ローカル JSON ファイルが UTXO の唯一の情報源。ファイルが古い/破損した場合に残高不整合。

**After**:
- `sync_wallet_from_chain()` がトランザクション前にチェーンから最新 UTXO を取得
- ローカルファイルは「キャッシュ」として扱い、チェーンが source of truth
- RPC 失敗時はローカルキャッシュにフォールバック（警告付き）
- `recalculate_balance()` を pub 化してチェーン同期後に呼び出し可能に
