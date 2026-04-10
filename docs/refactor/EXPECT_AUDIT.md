# .expect() 監査報告 v2

## 概要

| カテゴリ | 件数 |
|---------|------|
| 全 `.expect()` | 2,272 |
| テスト/integration tests 内 | 2,213 (97.4%) |
| **Production src** | **59** (2.6%) |

## Production 59 件の A/B/C 分類

### A. Invariant 系 — 残す (25 件)

リテラル値パース (到達不可能) またはデータ構造の不変条件。

| # | ファイル:行 | message | 改善後 message |
|---|-----------|---------|---------------|
| A1-A6 | `api/main.rs:99-104` | `"static origin"` | `"INVARIANT: literal HTTP origin must parse"` |
| A7 | `api/proxy.rs:158` | `"validated host"` | `"INVARIANT: URL host validated before this point"` |
| A8-A12 | `dag_rpc.rs:102-106` | `"static origin"` | `"INVARIANT: literal HTTP origin must parse"` |
| A13-A16 | `rpc_server.rs:68-71` | `"static origin"` | `"INVARIANT: literal HTTP origin must parse"` |
| A17 | `rpc/server.rs:22` | (already improved) | OK |
| A18 | `rpc/wrpc/server.rs:24` | (already improved) | OK |
| A19 | `crypto/keystore.rs:124` | `"HKDF expand..."` | `"INVARIANT: HKDF-SHA3 with 32-byte output is infallible"` |
| A20 | `storage/encryption.rs:135` | `"valid length"` | `"INVARIANT: fixed-length array conversion"` |
| A21 | `dag_p2p_network.rs:1272` | `"just inserted"` | `"INVARIANT: HashMap key inserted on previous line"` |
| A22-A23 | `ibd/negotiate.rs:69,205` | `"checked non-empty"` | `"INVARIANT: locator.is_empty() checked above"` |
| A24 | `txscript/script_engine.rs:224` | `"checked"` | `"INVARIANT: cond_stack.is_empty() checked above"` |
| A25 | `txscript/data_stack.rs:254` | `"non-empty"` | `"INVARIANT: result guaranteed non-empty by construction"` |

### B. Setup 系 — 残す (5 件)

起動時 1 回。失敗 = 環境異常。

| # | ファイル:行 | message |
|---|-----------|---------|
| B1 | `metrics/registry.rs:22` | `"SETUP: prometheus registry creation"` |
| B2-B5 | `metrics/registry.rs:49,58,67,79` | `"SETUP: metric registration"` |

### B2. Setup/test helper — shielded adapters (26 件)

`shielded_verifier_adapters.rs` の `sample_*` / `dummy_*` 関数群。
Feature-gated (`shielded-groth16-verifier` / `shielded-plonk-verifier`)。
テストヘルパーだが `#[cfg(test)]` 外に存在。

| 件数 | 種類 | 対応 |
|------|------|------|
| 26 | Groth16/PLONK proof sample 生成 | B に分類 (test helper、production で feature 未有効) |

### C. Runtime 系 — Result 化対象 (3 件)

| # | ファイル:行 | message | 失敗原因 |
|---|-----------|---------|---------|
| C1 | `rpc/auth.rs:532` | `"system clock must be after UNIX epoch"` | 時刻異常 |
| C2 | `utils/tower.rs:36` | `"semaphore closed"` | shutdown race |
| C3 | `pqc/privacy_backend.rs:101` | (コメントのみ、expect なし) | N/A — 除外 |

**実質 C は 2 件のみ。** (rocksdb の 3 件は Phase 2 で修正済み)

## 目標再評価

Production `.expect()` は **59 件** (2,272 の 2.6%)。
テスト 2,213 件を含めた「2,272 → ≤ 1,200」は**テストの expect を 1,072 件以上削減する**ことを意味する。

テスト expect の分布:

| ファイル | テスト expect 件数 |
|---------|-----------------|
| `dag_rpc.rs` (テスト部分) | ~1,405 |
| `shielded_verifier_adapters.rs` | ~26 (B2 に分類) |
| 他テスト | ~782 |

`dag_rpc.rs` のテスト 1,405 件がテスト expect の 63% を占める。
Phase 7 の dag_rpc.rs 分割で `tests/` ディレクトリに移動すると
grep のカウントは変わるが、実質的な削減ではない。

**現実的な目標**:
- Production C 種 2 件を Result 化 → production 57 件に
- テスト expect はテストの正当な用法として残す
- clippy lint で**新規流入を防止**
- A/B の message を統一フォーマットに改善

## 最終目標数値

| Before | After | 方法 |
|--------|-------|------|
| Production: 59 | **57** | C2 件 Result 化 |
| A/B message 改善: 0 | **30** 件改善 | "INVARIANT:" / "SETUP:" format |
| clippy lint: 未設定 | **有効** | 新規 expect に CI 警告 |
