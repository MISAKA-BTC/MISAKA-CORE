> **⚠ HISTORICAL DOCUMENT — v0.4.x era**
>
> This document was written for a previous codebase version that included
> PoW/mining, dev features, and faucet functionality. As of v0.5.0,
> MISAKA Network is **Pure PoS** with no PoW, no faucet, and no dev features.
> References to `pq_hash`, `mining`, `RandomX`, `Argon2id PoW`, `faucet`,
> `dev-rpc`, `dev-bridge-mock`, and `MockVerifier` are no longer applicable.

---

# MISAKA Network — 最終ハードニングレポート

**Date:** 2026-03-18
**Scope:** Feature管理、CORS Fail-closed、Zero-Panic、P2P相互認証、PoW刷新

---

## 修正サマリー

| # | 重大度 | 項目 | 状態 |
|---|--------|------|------|
| 1 | **CRITICAL** | Feature定義欠落 + CORS Fail-open | ✅ Fixed |
| 2 | **CRITICAL** | Relayer `.expect()` 残存 (Zero-Panic違反) | ✅ Fixed |
| 3 | **HIGH** | P2P Handshake 片側認証 | ✅ Fixed |
| 4 | **HIGH** | PoW自前hash → Argon2id | ✅ Fixed |

---

## 1. Feature管理の厳格化 + CORS Fail-closed (Critical)

### 1a. Feature 定義

**問題:** `rpc_server.rs` で `#[cfg(feature = "faucet")]` と `#[cfg(feature = "dev-rpc")]`
を使用しているが、`Cargo.toml` に `[features]` セクションが存在しなかった。
Cargoは未定義featureに対して警告は出すがエラーにはしないため、
`cargo build --features faucet` が**暗黙に無視**される場合がある。

**修正:**
```toml
[features]
default = []
dev-rpc = []
faucet = []
dev-bridge-mock = []
dev = ["dev-rpc", "faucet", "dev-bridge-mock"]
```

`main.rs` の既存 `compile_error!` ガードと組み合わせ:
- `cargo build --release` → dev featureはoff（安全）
- `cargo build --release --features dev` → コンパイルエラー（安全）
- `cargo build --features faucet` → faucetのみon（テストネット用）

### 1b. CORS Fail-closed

**問題:** `MISAKA_CORS_ORIGINS` が設定されているがパースに失敗した場合、
`CorsLayer::permissive()` にフォールバック。これは**任意のオリジンからの
クロスサイトリクエストを許可**してしまう。

**修正:**
- `MISAKA_CORS_ORIGINS` 設定あり + 有効なオリジン0件 → `anyhow::bail!` (起動拒否)
- `MISAKA_CORS_ORIGINS` 未設定 → `127.0.0.1` / `localhost` のみ許可
- `CorsLayer::permissive()` の呼び出しは**コードベース全体からゼロ**

---

## 2. Zero-Panic ポリシーの徹底 (Critical)

**問題:** ワークスペース `Cargo.toml` で `unwrap_used = "deny"` を設定しているが、
`relayer/src/main.rs` に `.expect("FATAL: ...")` が残存。Relayerはブリッジ資金を
扱うプロセスであり、パニックによるクラッシュループは資金の二重処理リスクに直結。

**修正:**
```rust
// Before (panic on corrupt store)
let mut store = ProcessedStore::load(&store_path)
    .expect("FATAL: Cannot load processed store");

// After (graceful error + exit)
let mut store = match ProcessedStore::load(&store_path) {
    Ok(s) => s,
    Err(e) => {
        error!("{}", e);
        error!("Relayer cannot start safely. Exiting.");
        std::process::exit(1);
    }
};
```

**検証結果:** Relayer全ソース（4ファイル）で `unwrap()`/`expect()` がゼロであることを確認。

---

## 3. P2P Handshake 相互認証の完了 (High)

**問題:** Initiator → Responder の認証は完了していたが、Responder → Initiator の
検証ステップが実装されていなかった。Responder は Initiator の署名を受け取るが、
**検証せずに接続を確立**していた。

攻撃者は任意のイニシエーターになりすましてP2Pネットワークに参加可能だった。

**修正:**
```
Before:
  Initiator → Responder: ephemeral KEM PK
  Responder → Initiator: ciphertext + PK + sig  ← Initiator verifies ✅
  Initiator → Responder: sig                    ← Responder IGNORES ❌

After:
  Initiator → Responder: ephemeral KEM PK
  Responder → Initiator: ciphertext + PK + sig  ← Initiator verifies ✅
  Initiator → Responder: sig + PK               ← Responder verifies ✅
```

実装:
- `ResponderReply` に `transcript` フィールド追加（検証に必要なデータ保持）
- `ResponderReply::verify_initiator(sig, pk)` メソッド追加
  - Initiator の ML-DSA-65 署名を transcript に対して検証
  - 失敗 → `Err(CryptoError)` → 呼び出し側で接続DROP
- テスト3件追加:
  - `test_mutual_auth_handshake` — 正常な相互認証フロー
  - `test_mutual_auth_wrong_initiator_rejected` — 偽イニシエーター拒否
  - `test_mutual_auth_wrong_responder_rejected` — 偽レスポンダー検出

---

## 4. PoW アルゴリズム → Argon2id (High)

**問題:** `pq_hash` が自前の `randomx_mix()` を使用。256KiB scratchpad + SHA3 XOR folding
という簡易実装で、**実際のメモリハードネスが不十分**。専用ASICは256KiBを内部SRAMに
収容でき、数百倍の高速化が可能。

**修正:** `argon2` crate (RFC 9106) の Argon2id に完全置換:

| パラメータ | 値 | 根拠 |
|-----------|-----|------|
| `m_cost` | 65536 KiB (64 MiB) | ASIC内部SRAMに収まらない |
| `t_cost` | 3 | OWASP推奨最小値 |
| `p_cost` | 1 | ブロックレベルで並列化 |
| `output` | 64 bytes | Digest512と互換 |
| salt | `SHA3-256("MISAKA_POW_SALT_V2:" \|\| data)[..16]` | 決定論的 |

最終出力: `SHA3-512(Argon2id_output)` — Grover耐性を維持。

**セキュリティ特性:**
- **メモリハード:** 64MiB必須 → ASIC/FPGAで経済的な攻撃不可能
- **サイドチャネル耐性:** Argon2**id** は data-independent + data-dependent の
  ハイブリッドモードでタイミング攻撃に耐性
- **決定論的:** 同一入力 → 同一出力（PoW検証可能）
- **標準化:** RFC 9106 / Password Hashing Competition 優勝者

---

## 変更ファイル一覧

| ファイル | 変更内容 |
|---------|---------|
| `crates/misaka-node/Cargo.toml` | `[features]` セクション追加 |
| `crates/misaka-node/src/rpc_server.rs` | CORS fail-closed化 |
| `relayer/src/main.rs` | `.expect()` 排除 |
| `crates/misaka-p2p/src/handshake.rs` | Responder側 `verify_initiator()` + テスト3件 |
| `crates/misaka-crypto/Cargo.toml` | `argon2 = "0.5"` 依存追加 |
| `crates/misaka-crypto/src/hash.rs` | Argon2id PoW実装 |

---

## 全セッション累計修正サマリー

前回までのセキュリティ監査 + アーキテクチャ再構築と合わせた全修正:

| カテゴリ | 件数 | 代表的な修正 |
|---------|------|------------|
| **CRITICAL (暗号バイパス)** | 5件 | submit_tx検証統合、Bridge Ed25519偽検証、panic!排除 |
| **CRITICAL (インフラ)** | 3件 | CORS fail-closed、Feature定義、Zero-Panic |
| **HIGH (暗号/検証)** | 10件 | 相互認証完了、expect排除、volatile zeroize、overflow |
| **MEDIUM (堅牢化)** | 8件 | Merkle DST、Argon2id PoW、block validation強化 |
| **合計** | **26件** | 20ファイル変更 |
