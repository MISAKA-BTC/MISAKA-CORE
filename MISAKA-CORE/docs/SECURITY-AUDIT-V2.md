> **⚠ HISTORICAL DOCUMENT — v0.4.x era**
>
> This document was written for a previous codebase version that included
> PoW/mining, dev features, and faucet functionality. As of v0.5.0,
> MISAKA Network is **Pure PoS** with no PoW, no faucet, and no dev features.
> References to `pq_hash`, `mining`, `RandomX`, `Argon2id PoW`, `faucet`,
> `dev-rpc`, `dev-bridge-mock`, and `MockVerifier` are no longer applicable.

---

# MISAKA Network — セキュリティ監査 V2（Mainnet Hardening）

**Date:** 2026-03-18
**Auditor:** Claude (Anthropic)
**Scope:** misaka-net-core-audit-final.zip — 全crate + Solana Bridge + Relayer
**Branch:** mainnet-final → mainnet-hardened

---

## Executive Summary

コードベース全体（194ファイル、~810KB）をセキュリティ・量子耐性暗号・mainnet品質の観点から監査し、
**17件の改善**を実施。内訳: CRITICAL 3件、HIGH 8件、MEDIUM 6件。

既存のP0 fixは概ね良好だが、**Solana Bridge の Ed25519 検証が偽装**（ハッシュ比較のみ）、
**プロダクションコード内の `panic!`/`unwrap()`/`expect()` 残存**、
**秘密鍵のzeroizeがコンパイラ最適化で除去される可能性**など、mainnet前に修正必須の問題を発見。

---

## 発見事項一覧

| # | 重大度 | ファイル | 問題 | 状態 |
|---|--------|---------|------|------|
| 1 | **CRITICAL** | `solana-bridge/lib.rs` | `verify_ed25519_sig` がハッシュ比較のみ（偽造可能） | ✅ Fixed |
| 2 | **CRITICAL** | `pq_ring.rs:181` | `challenge_to_bytes()` 内の `panic!` | ✅ Fixed |
| 3 | **CRITICAL** | `pq_ring.rs:618-625` | `derive_child()` 内の `assert!` + `panic!` | ✅ Fixed |
| 4 | **HIGH** | `solana-bridge/lib.rs` | `update_committee` にメンバー重複チェック欠落 | ✅ Fixed |
| 5 | **HIGH** | `solana-bridge/lib.rs` | `lock_tokens` / `unlock_tokens` の整数オーバーフロー | ✅ Fixed |
| 6 | **HIGH** | `pq_sign.rs` | `to_pqcrypto()` 3箇所で `.expect()` 使用 | ✅ Fixed |
| 7 | **HIGH** | `pq_kem.rs` | `to_pqcrypto()` 3箇所で `.expect()` 使用 | ✅ Fixed |
| 8 | **HIGH** | `handshake.rs:99` | `responder_handle` 内の `.unwrap()` | ✅ Fixed |
| 9 | **HIGH** | `handshake.rs` | 片方向認証のみ（initiator sigが返されない） | ✅ Fixed |
| 10 | **HIGH** | `validator_sig.rs` | 秘密鍵zeroizeがコンパイラ最適化で無効化される可能性 | ✅ Fixed |
| 11 | **HIGH** | `block_validation.rs` | 金額保存チェックで `saturating_add`（無音の上限クリップ） | ✅ Fixed |
| 12 | **MEDIUM** | `rpc/lib.rs:84` | `serde_json::to_value().unwrap()` | ✅ Fixed |
| 13 | **MEDIUM** | `hash.rs` | Merkle tree に second preimage 防御なし | ✅ Fixed |
| 14 | **MEDIUM** | `hash.rs` | `pq_hash` scratchpad が 4KiB（ASIC耐性不足） | ✅ Fixed |
| 15 | **MEDIUM** | `block_validation.rs` | ブロック高さ単調性チェックなし | ✅ Fixed |
| 16 | **MEDIUM** | `block_validation.rs` | ブロックあたり最大TX数制限なし | ✅ Fixed |
| 17 | **MEDIUM** | `pq_sign.rs`, `pq_kem.rs` | 秘密鍵zeroizeが `volatile_write` 不使用 | ✅ Fixed |

---

## 詳細解説

### #1: CRITICAL — Bridge Ed25519 偽検証

**問題:** `verify_ed25519_sig()` は実際のEd25519署名検証を行わず、
`SHA3(DST || pubkey || message)` のハッシュ前半と署名前半を比較するだけ。

攻撃者は `hashv(["MISAKA_ED25519_SIG_V1:", pk, msg])` を自分で計算し、
その先頭32バイトを署名に埋め込むだけで委員会メンバーを偽装できる。
**これによりブリッジの全資金が窃取可能。**

**修正:** Solana Ed25519 precompile のinstruction introspection を使用する
`verify_ed25519_sig_via_ixs()` に置換。SolanaランタイムがEd25519検証を
実行し、このコードはその結果をsysvarから確認する正規の方式。
`UnlockTokens` に `instructions_sysvar` アカウントを追加。

### #2-3: CRITICAL — プロダクションコードの `panic!`

**問題:** `challenge_to_bytes()` が不正な係数で `panic!` し、
`derive_child()` が `assert!(index > 0)` で `panic!` する。
ノードがクラッシュ → DoS攻撃、コンセンサス停止の原因になる。

**修正:** 両方を `Result` 返却に変更。エラーを上位に伝播し、
ノードは安全に処理を拒否する。

### #4: HIGH — `update_committee` 重複チェック欠落

**問題:** `initialize_committee` にはメンバー重複チェックがあるが、
`update_committee` にはない。管理者が同一pubkeyを複数回登録すると、
1署名で複数カウントされ、threshold をバイパスできる。

**修正:** `initialize_committee` と同じソート＋隣接重複チェックを追加。

### #5: HIGH — 整数オーバーフロー

**問題:** `total_locked += amount` と `total_released += amount` が
Rustのデフォルト動作でオーバーフロー（release buildではwrap）。
理論的に会計不整合が発生可能。

**修正:** `checked_add()` + 専用 `ArithmeticOverflow` エラー。

### #6-8: HIGH — `.expect()` / `.unwrap()` 残存

**問題:** `pq_sign.rs`, `pq_kem.rs`, `handshake.rs` に合計7箇所の
`.expect()` / `.unwrap()` が残存。すべてプロダクションコードパスで
到達可能であり、不正入力でノードがクラッシュする。

**修正:** すべて `Result` 返却または `?` 演算子に変更。

### #9: HIGH — P2P Handshake 片方向認証

**問題:** `InitiatorHandshake::complete()` がイニシエーターのML-DSA-65
署名を計算しているが、`_our_sig` として無視。レスポンダーはイニシエーター
のアイデンティティを検証できない。

攻撃者は任意のイニシエーターになりすましてP2Pネットワークに参加可能。

**修正:** `HandshakeResult` に `our_signature` フィールドを追加。
呼び出し側はこれをレスポンダーに送信し、相互認証を完結する。

### #10, #17: HIGH/MEDIUM — 秘密鍵 Zeroize の安全性

**問題:** `for b in iter_mut() { *b = 0; }` はコンパイラが
「値がdrop後に読まれない」と判断して最適化で除去する可能性がある。
秘密鍵がメモリに残留し、メモリダンプ攻撃で漏洩する。

**修正:** `std::ptr::write_volatile` + `atomic::fence(SeqCst)` で
コンパイラの最適化を確実に防止。

### #11: HIGH — Amount Conservation の `saturating_add`

**問題:** `sum_outputs.saturating_add(tx.fee)` は u64::MAX で
クリップされるだけで、実際のオーバーフロー（出力合計+手数料 > u64::MAX）
を静かに無視する。理論的に無からの通貨創造が可能。

**修正:** `checked_add()` + エラー返却。

### #13: MEDIUM — Merkle Tree Second Preimage

**問題:** リーフノードと内部ノードが同じハッシュ構造を使用。
攻撃者が2つのリーフの連結と一致するデータを持つ1つのリーフを
構築し、異なるMerkleツリーで同じルートを得る可能性がある。

**修正:** リーフに `0x00` プレフィックス、内部ノードに `0x01`
プレフィックスのドメイン分離を追加（RFC 6962準拠）。

### #14: MEDIUM — pq_hash Scratchpad 拡大

**問題:** 4KiB scratchpad はASIC/FPGAの内部レジスタに完全に収まり、
メモリハードネスが実質ゼロ。

**修正:** 256KiB + 16ラウンドに拡大。完全なRandomXではないが、
ASIC/FPGAでのキャッシュが大幅に困難になる。

---

## 残存リスク（P1以降）

| 優先度 | リスク | 影響 | 推奨対策 |
|--------|-------|------|---------|
| **P1** | Storage WAL/fsync 未実装 | クラッシュ時データ破損 | WAL + atomic batch write |
| **P1** | Same-amount ring（プライバシー制限） | 匿名セット縮小 | Pedersen commitment + range proof |
| **P1** | Peer scoring/ban 未実装 | DoS攻撃耐性不足 | 行動ベーススコアリング |
| **P1** | pq_hash は依然 RandomX未完全実装 | ASIC耐性不十分 | `randomx-rs` crate 統合 |
| **P1** | Bridge: Ed25519 → ML-DSA-65 移行 | Solana側が量子非耐性 | Solana PQ precompile待ち |
| **P2** | STARK range proof stub | 機密トランザクション未実装 | winterfell / risc0 |
| **P2** | 形式検証なし | 健全性の数学的保証なし | Lean4 / Coq |

---

## 量子耐性暗号の評価

### 完全にPQ化済み ✅
- **コンセンサス署名:** ML-DSA-65 (FIPS 204) — Ed25519完全排除
- **KEM:** ML-KEM-768 (FIPS 203) — stealth address
- **ハッシュ:** SHA3-256/512 — SHA2完全禁止
- **リング署名:** Lattice-based (Z_q[X]/(X^256+1)) — ECC不使用
- **P2P Handshake:** ML-KEM-768 + ML-DSA-65 — Noise XX的相互認証
- **LogRing:** O(log n) Merkle + Lattice Σ-protocol

### PQ移行未完了 ⚠️
- **Solana Bridge:** Ed25519（Solanaプラットフォーム制約、PQ precompile待ち）
- **PoW hash:** SHA3-512ベース（Grover耐性あり、但しASIC耐性不十分）

### パラメータ安全性
- q=12289, n=256: NIST PQ Level 1（128-bit post-quantum security）相当
- ML-DSA-65: NIST PQ Level 3
- ML-KEM-768: NIST PQ Level 3
- SHA3-256: 128-bit PQ security（Grover half）

---

## 変更ファイル一覧

| ファイル | 変更概要 |
|---------|---------|
| `solana-bridge/.../lib.rs` | Ed25519 precompile検証、重複チェック、overflow対策 |
| `crates/misaka-pqc/src/pq_ring.rs` | panic!/assert! 除去、Result返却化 |
| `crates/misaka-pqc/src/pq_sign.rs` | expect() 除去、volatile zeroize |
| `crates/misaka-pqc/src/pq_kem.rs` | expect() 除去、volatile zeroize |
| `crates/misaka-crypto/src/hash.rs` | Merkle domain separation、scratchpad拡大 |
| `crates/misaka-crypto/src/validator_sig.rs` | volatile zeroize、sign API更新 |
| `crates/misaka-p2p/src/handshake.rs` | 相互認証完結、unwrap除去 |
| `crates/misaka-consensus/src/block_validation.rs` | height check、TX上限、checked_add |
| `crates/misaka-rpc/src/lib.rs` | unwrap除去 |
