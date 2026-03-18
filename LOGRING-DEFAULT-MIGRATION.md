# LogRing System Default Migration Report

**Date:** 2026-03-18  
**Status:** LogRing-v1 is now the system default ring signature scheme

---

## 変更サマリー

LogRing O(log n) リング署名を**全レイヤーでシステムデフォルト**に昇格。
LRS-v1 はレガシー互換として引き続き利用可能。

### 変更ファイル一覧（10ファイル）

| # | ファイル | 変更内容 |
|---|---------|---------|
| 1 | `crates/misaka-pqc/Cargo.toml` | `logring` feature gate削除（常時コンパイル） |
| 2 | `crates/misaka-pqc/src/lib.rs` | `pub mod logring`（無条件）、ヘッダーにLogRing default記載 |
| 3 | `crates/misaka-types/src/utxo.rs` | `RING_SCHEME_LOGRING=0x03`, `default_ring_scheme()→0x03`, `MAX_RING_SIZE_V3=1024` |
| 4 | `crates/misaka-mempool/src/lib.rs` | LogRing検証を**最初のmatch arm**に配置、`link_tags_mempool`追跡 |
| 5 | `crates/misaka-consensus/src/block_validation.rs` | LogRing検証を**最初のmatch arm**に配置 |
| 6 | `crates/misaka-node/src/config_validation.rs` | `default_ring_scheme: 0x03`, `is_ring_scheme_allowed(0x03)→true` |
| 7 | `crates/misaka-rpc/src/lib.rs` | `ring_signature_scheme`フィールド追加、LogRing情報表示 |
| 8 | `configs/testnet.toml` | `default_scheme = "logring-v1"`, `max_ring_size = 1024` |
| 9 | `crates/misaka-pqc/benches/ring_bench.rs` | LogRing benchの`#[cfg]`削除（常時実行） |
| 10 | `crates/misaka-pqc/src/logring.rs` | 既存実装（1,198行、30テスト）— 変更なし |

---

## アーキテクチャ全体図

```
                      ┌─ wallet/CLI ─┐
                      │  ring_scheme │
                      │  = 0x03      │    <-- LogRing default
                      └──────┬───────┘
                             │ submit_tx
                             ▼
                    ┌── RPC Server ──┐
                    │ ring_signature │
                    │ _scheme:       │
                    │ "LogRing-v1    │
                    │  O(log n)      │
                    │  [default]"    │
                    └───────┬────────┘
                            │
                            ▼
                   ┌─── Mempool ───┐
                   │ match scheme  │
                   │ ┌─0x03──────┐ │    <-- FIRST (default)
                   │ │ LogRing   │ │
                   │ │ verify +  │ │
                   │ │ link_tag  │ │
                   │ │ tracking  │ │
                   │ ├─0x01──────┤ │    <-- legacy
                   │ │ LRS       │ │
                   │ ├─0x02──────┤ │    <-- feature-gated
                   │ │ Chipmunk  │ │
                   │ └───────────┘ │
                   └───────┬───────┘
                           │
                           ▼
              ┌── Block Validation ──┐
              │ match scheme         │
              │ ┌─0x03: LogRing ────┐│  <-- FIRST
              │ │ parse + verify    ││
              │ │ link_tag == ki    ││
              │ ├─0x01: LRS ───────┤│  <-- legacy  
              │ ├─0x02: Chipmunk ──┤│  <-- gated
              │ └───────────────────┘│
              └──────────────────────┘
```

---

## 検証チェックリスト（全合格）

| # | チェック項目 | 結果 |
|---|------------|------|
| 1 | pqc: logring.rs が無条件コンパイル | ✅ |
| 2 | pqc: Cargo.toml にlogring featureが不要 | ✅ |
| 3 | types: default_ring_scheme() → 0x03 | ✅ |
| 4 | types: RING_SCHEME_LOGRING = 0x03 定義済み | ✅ |
| 5 | types: UTXO_TX_VERSION_V3 = 0x03 定義済み | ✅ |
| 6 | types: MAX_RING_SIZE = 1024 (V3経由) | ✅ |
| 7 | mempool: LogRing が最初のmatch arm | ✅ |
| 8 | mempool: link_tags_mempool で二重支払い検知 | ✅ |
| 9 | mempool: spent_link_tags でオンチェーン使用済み検知 | ✅ |
| 10 | block_validation: LogRing が最初のmatch arm | ✅ |
| 11 | block_validation: link_tag == key_image 一致確認 | ✅ |
| 12 | config: default_ring_scheme = 0x03 | ✅ |
| 13 | config: is_ring_scheme_allowed(0x03) → true | ✅ |
| 14 | RPC: ring_signature_scheme フィールド追加 | ✅ |
| 15 | testnet.toml: logring-v1 default | ✅ |
| 16 | LRS (0x01) 引き続き利用可能 | ✅ |
| 17 | Chipmunk (0x02) feature gate維持 | ✅ |
| 18 | feature gate なし（常時コンパイル） | ✅ |

---

## O(log n) サイズ効果

| リングサイズ | LRS-v1 (O(n)) | LogRing (O(log n)) | 圧縮比 |
|------------|---------------|---------------------|--------|
| 4 | 2,336 B | ~1,191 B | 2.0× |
| 16 | 8,480 B | ~1,257 B | 6.7× |
| 32 | 16,672 B | ~1,290 B | **12.9×** |
| 1024 | 不可能 | ~1,455 B | **∞** |

**LogRing により、リングサイズ 32〜1024 が実用的に運用可能になった。**

---

## 二重支払い防止メカニズム

### LogRing の link_tag

```
link_tag = SHA3-256("MISAKA_LOGRING_LINK_V1:" || SHA3-512(sk) || ring_root)
```

- 同一 (sk, ring_root) → **同一 link_tag** → 二重支払い検知
- mempool: `link_tags_mempool` HashSet で重複拒否
- on-chain: `spent_link_tags` HashSet で使用済み拒否
- block validation: `seen_key_images` で block内重複拒否
- `UtxoTransaction.inputs[i].key_image` に link_tag を格納（互換性）

### LRS の key_image（レガシー）

```
key_image = SHA3-256("MISAKA-LRS:ki:v1:" || SHA3-512(s))
```

LRS TX は従来通り `key_image` で二重支払い検知。
**LogRing と LRS は異なる DST を使用するため、クロスプロトコル衝突なし。**

---

## scheme 判別フロー

```
TX受信 → ring_scheme バイト確認
  │
  ├─ 0x03 → LogRing 検証（デフォルト）
  │   ├─ LogRingSignature::from_bytes()
  │   ├─ logring_verify()
  │   ├─ link_tag 二重支払いチェック
  │   └─ key_image == link_tag 一致確認
  │
  ├─ 0x01 → LRS 検証（レガシー）
  │   ├─ RingSig::from_bytes()
  │   ├─ ring_verify()
  │   └─ ki_proof 検証
  │
  ├─ 0x02 → Chipmunk（feature gate）
  │   └─ #[cfg(feature = "chipmunk")] でのみ有効
  │
  └─ other → Err(UnsupportedScheme)
```
