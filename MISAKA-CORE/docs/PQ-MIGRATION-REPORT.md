> **⚠ HISTORICAL DOCUMENT — v0.4.x era**
>
> This document was written for a previous codebase version that included
> PoW/mining, dev features, and faucet functionality. As of v0.5.0,
> MISAKA Network is **Pure PoS** with no PoW, no faucet, and no dev features.
> References to `pq_hash`, `mining`, `RandomX`, `Argon2id PoW`, `faucet`,
> `dev-rpc`, `dev-bridge-mock`, and `MockVerifier` are no longer applicable.

---

# MISAKA Network — Post-Quantum Migration Report

**Version:** v0.5.0-pq  
**Date:** 2026-03-18  
**Status:** ECC完全排除完了

---

## 概要

MISAKA Networkコードベース全体から**ECC（Ed25519/secp256k1）依存を完全排除**し、
NIST標準ベースのポスト量子暗号（PQC）のみで動作するL1チェーンへ移行した。

---

## 変更サマリー

### 削除された暗号プリミティブ

| プリミティブ | 旧用途 | 状態 |
|---|---|---|
| Ed25519 | バリデータ署名（ハイブリッド） | **完全削除** |
| ed25519-dalek クレート | P2P handshake, consensus | **依存排除** |
| SHA-256 (HKDF) | Stealth KEM鍵導出 | **SHA3-256に置換** |
| sha2 クレート | ワークスペース全体 | **依存排除** |

### 新規導入/強化された暗号プリミティブ

| プリミティブ | NIST標準 | 用途 |
|---|---|---|
| ML-DSA-65 (Dilithium3) | FIPS 204 | 全署名（TX, バリデータ, P2P） |
| ML-KEM-768 (Kyber768) | FIPS 203 | Stealth KEM, P2P鍵交換 |
| 格子リング署名 (LRS/Chipmunk) | — | 送信者匿名性 |
| SHA3-256 / SHA3-512 | FIPS 202 | 全ハッシュ処理 |
| HKDF-SHA3-256 | — | 全鍵導出 |
| STARK証明 (スタブ) | — | ZKトランザクション検証 |

---

## ファイル別変更詳細

### 新規ファイル (3件)

| ファイル | 内容 |
|---|---|
| `crates/misaka-crypto/src/validator_sig.rs` | PQ-onlyバリデータ署名 (ML-DSA-65) |
| `crates/misaka-pqc/src/stark_proof.rs` | STARKベースZK証明（インターフェース+スタブ） |
| `crates/misaka-bridge/src/isolation.rs` | PQ/非PQブリッジトークン分離 |

### 削除ファイル (1件)

| ファイル | 理由 |
|---|---|
| `crates/misaka-crypto/src/hybrid.rs` | Ed25519+ML-DSA-65ハイブリッド → PQ-onlyに置換 |

### 変更ファイル (19件)

| ファイル | 変更内容 |
|---|---|
| `Cargo.toml` (workspace) | `ed25519-dalek`, `sha2` 依存削除 |
| `crates/misaka-crypto/Cargo.toml` | Ed25519依存削除 |
| `crates/misaka-crypto/src/lib.rs` | hybrid → validator_sig re-export |
| `crates/misaka-crypto/src/hash.rs` | SHA3-512 + CPU-bound Grover耐性ハッシュ (`pq_hash`) 追加 |
| `crates/misaka-types/src/validator.rs` | ハイブリッドPK/Sig → ML-DSA-65 only |
| `crates/misaka-consensus/src/validator_set.rs` | hybrid_verify → validator_verify |
| `crates/misaka-consensus/src/committee.rs` | テストをPQ-onlyに移行 |
| `crates/misaka-consensus/src/finality.rs` | テストをPQ-onlyに移行 |
| `crates/misaka-consensus/src/proposer.rs` | テストをPQ-onlyに移行 |
| `crates/misaka-p2p/src/handshake.rs` | ハイブリッド → ML-DSA-65 mutual auth |
| `crates/misaka-pqc/Cargo.toml` | sha2依存削除 |
| `crates/misaka-pqc/src/lib.rs` | stark_proof モジュール追加 |
| `crates/misaka-pqc/src/pq_stealth.rs` | HKDF\<SHA-256\> → HKDF\<SHA3-256\> |
| `crates/misaka-pqc/src/stealth_v2.rs` | HKDF\<SHA-256\> → HKDF\<SHA3-256\> |
| `crates/misaka-pqc/src/pq_ring.rs` | HKDF\<SHA-256\> → HKDF\<SHA3-256\>, child key導出 |
| `crates/misaka-bridge/src/lib.rs` | isolation モジュール追加, テスト修正 |
| `crates/misaka-bridge/src/verifier.rs` | Ed25519委員会署名 → ML-DSA-65 |
| `crates/misaka-rpc/src/lib.rs` | スキーム説明文修正 |
| `crates/misaka-consensus/Cargo.toml` | description修正 |

---

## アーキテクチャ: PQ暗号スタック

```
┌─────────────────────────────────────────────────────┐
│                   MISAKA L1 Chain                    │
├─────────────────────────────────────────────────────┤
│  Transaction Auth    │  ML-DSA-65 (FIPS 204)        │
│  Ring Signature      │  格子ベース Σ-protocol        │
│  Key Image           │  SHA3-256(SHA3-512(s))        │
│  Stealth Address     │  ML-KEM-768 + HKDF-SHA3-256  │
│  ZK Proof            │  STARK (hash-only, ECC不使用) │
│  Validator Consensus │  ML-DSA-65 (PQ-only)         │
│  P2P Handshake       │  ML-KEM-768 + ML-DSA-65      │
│  Hash Function       │  SHA3-256 / SHA3-512          │
│  PoW Hash            │  SHA3-512(CPU-bound mix)      │
│  KDF                 │  HKDF-SHA3-256                │
├─────────────────────────────────────────────────────┤
│  Bridge (分離)       │  native=PQ / wrapped=非PQ     │
└─────────────────────────────────────────────────────┘
```

---

## セキュリティ考慮事項

### Grover攻撃耐性
- SHA3-256 (128-bit PQ security) → 標準ハッシュ
- SHA3-512 (256-bit PQ security) → PoWハッシュ
- CPU-bound mixing → ASIC耐性

### Side-channel耐性
- `Poly::norm_inf()` → constant-time実装（secret-dependent分岐なし）
- `constant_time_eq()` → scan_tag比較
- 秘密鍵 → Drop時にゼロ化

### ブリッジ隔離
- `TokenType::Native` → 完全PQセキュリティ
- `TokenType::Wrapped(BridgeOrigin)` → 非PQ外部チェーン由来を明示
- 非PQトークンがnativeトークンとして扱われることを防止

---

## 未実装/今後の課題

1. **STARK証明器**: 現在はハッシュコミットメントスタブ。winterfell/risc0統合が必要
2. **Falcon-512**: オプショナル軽量署名（モジュール化済みで差し替え可能）
3. **SPHINCS+**: ハッシュベース署名のバックアップ（将来的に追加可能）
4. **RandomX完全統合**: 現在は簡易CPU-bound mixing。本番用はrandomx-rs統合
5. **GPU/FPGA最適化**: NTT乗算の並列化

---

## ドメイン分離タグ一覧

| タグ | 用途 | バージョン |
|---|---|---|
| `MISAKA-PQ-SIG:v2:` | バリデータ署名 | v2 (PQ-only) |
| `MISAKA-v1:ml-dsa-65:tx-auth:` | TX署名 | v1 |
| `MISAKA-v2:p2p:session-key:` | P2Pセッション鍵 | v2 |
| `MISAKA-v2:p2p:transcript:` | P2Pハンドシェイク | v2 |
| `MISAKA:proposal:v2:` | ブロック提案 | v2 |
| `MISAKA:vote:v2:` | 委員会投票 | v2 |
| `MISAKA_BRIDGE_AUTH:v2:` | ブリッジ認可 | v2 |
| `MISAKA_BRIDGE_ORIGIN:v1:` | ブリッジ起源ID | v1 |
| `MISAKA_STARK:v1:` | STARK証明 | v1 |
| `MISAKA_KI_V1:` | 正規Key Image | v1 |
| `misaka/pq-stealth/*` | Stealth鍵導出 | v1 |
| `MISAKA_STEALTH_V2:*` | Stealth v2鍵導出 | v2 |
