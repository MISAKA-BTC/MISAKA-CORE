> **⚠ HISTORICAL DOCUMENT — v0.4.x era**
>
> This document was written for a previous codebase version that included
> PoW/mining, dev features, and faucet functionality. As of v0.5.0,
> MISAKA Network is **Pure PoS** with no PoW, no faucet, and no dev features.
> References to `pq_hash`, `mining`, `RandomX`, `Argon2id PoW`, `faucet`,
> `dev-rpc`, `dev-bridge-mock`, and `MockVerifier` are no longer applicable.

---

# MISAKA Network — Testnet Hardening Report

**Version:** v0.5.0-testnet  
**Date:** 2026-03-18  
**Status:** P0 hardening complete, P1/P2 items documented

---

## 全体方針

1. **LRS-v1をtestnetデフォルトのリング署名として固定**
2. **ChipmunkをすべてのCargo.tomlのdefault featuresから排除**
3. **Bridge verifierのfail-open仮実装を実ML-DSA-65検証に置換**
4. **Config validationで起動時に危険設定を拒否**
5. **Faucet/RPC/mempoolのDoS対策基盤を整備**

---

## P0 修正完了項目

### A. Chipmunk排除 (default features)

| Crate | 変更前 | 変更後 |
|---|---|---|
| misaka-pqc | `default = ["chipmunk", "stealth-v2"]` | `default = ["stealth-v2"]` |
| misaka-mempool | `default = ["custom-pq-main", "chipmunk"]` | `default = ["custom-pq-main"]` |
| misaka-consensus | `default = ["strict-ki-proof", "chipmunk"]` | `default = ["strict-ki-proof"]` |

**効果:** `cargo build` でChipmunkコードは一切コンパイルされない。
testnet default profileではChipmunk TX/検証は`#[cfg(feature = "chipmunk")]`で完全に不活性化。

### B. Bridge Verifier (P0最重要)

**旧実装の問題:**
- `CommitteeVerifier`がauthorized memberのpk_hashだけチェックし、署名を実検証していなかった
- `// TODO: Real Ed25519 / hybrid sig verification` コメントのまま放置

**新実装:**
- `CommitteeMember` 構造体にフルML-DSA-65公開鍵(1952バイト)を保持
- `pk_hash`と`public_key`の整合性をconstructor時に検証
- 全署名を`ml_dsa_verify_raw()`で実暗号学的検証
- Domain separationにchain_id, public_input, nonceを含む
- Duplicate signer, unknown signer, corrupted sig, misaligned proof_data → すべてreject
- テスト: 12ケース（real ML-DSA sign/verify, cross-chain-id, corruption等）

### C. Config Validation

**新規ファイル:** `crates/misaka-node/src/config_validation.rs`

起動時チェック項目:
- chain_id > 0
- P2P/RPC port > 0, 重複なし
- block_time >= 5秒
- advertise_addr: public/seedモードで0.0.0.0/loopback禁止
- faucet amount: 0 < amount <= 1,000,000
- chipmunk: feature未有効時にconfig enableは拒否
- ring_scheme: chipmunk無効時に0x02指定は拒否
- bridge: disabled by default

**`TestnetConfig::is_ring_scheme_allowed()`:**
- 0x01 (LRS) → 常に許可
- 0x02 (Chipmunk) → `chipmunk_enabled`時のみ
- その他 → 常に拒否

### D. Testnet Sample Config

**新規ファイル:** `configs/testnet.toml`

全パラメータをTOML形式で文書化。operator向け設定テンプレート。

---

## P1 残課題（次イテレーション）

### P2P Hardening
- [ ] `panic!`を`Result`に統一（p2p_network.rs全域）
- [ ] chain_id不一致peerを即reject
- [ ] oversized message即切断
- [ ] peer score/ban/backoff簡易版
- [ ] rate limiting (block gossip / tx gossip)
- [ ] protocol version + genesis hash をhandshakeに含める
- [ ] hidden nodeをpeer list応答に含めない（既存ロジック確認）

### RPC Hardening
- [ ] `get_address_outputs`をdev-onlyに移動（privacy設計と矛盾）
- [ ] pagination上限の厳密適用（max page_size = 100）
- [ ] submit_tx でring_scheme許可チェック（config連携）
- [ ] faucet rate limit（IP/address基盤）
- [ ] health endpointにsync状態を含める

### Mempool/Block Validation
- [ ] expired tx reject
- [ ] underpriced tx reject (min_fee check)
- [ ] cross-tx key image conflict detection（block内）
- [ ] LRS ring size上限のconfig連携
- [ ] block validation時のring_scheme許可チェック

### Storage/Durability
- [ ] write batch / atomic commit
- [ ] crash後の整合性チェック
- [ ] genesis hash固定化
- [ ] state snapshot / replay from block log

### Consensus
- [ ] validator signature verify必須化
- [ ] timestamp skew check
- [ ] empty block policy
- [ ] slot drift許容値

---

## P2 残課題（将来）

- [ ] Peer scoring
- [ ] Fuzz / property tests
- [ ] STARK proof本格統合（winterfell/risc0）
- [ ] Bridge testnet opt-in mode
- [ ] Chipmunk bench/research path分離
- [ ] GPU/FPGA NTT最適化
- [ ] RandomX完全統合

---

## セキュリティ上まだ残るリスク

1. **P2P panic**: `p2p_network.rs`に`unwrap()`が残存。malformed packetでnode crashの可能性
2. **RPC pagination**: 上限未設定のendpointあり。大量リクエストでメモリ圧迫の可能性
3. **Faucet**: rate limitが完全ではない。IP基盤の制限は未実装
4. **Storage atomicity**: write batch未導入。crash時に部分更新の可能性
5. **Validator signature**: testnet初期はvalidator署名検証がOptional
6. **Bridge**: disabled by defaultだが、config変更で有効化した場合の運用手順が未整備

---

## Feature Gate一覧

| Feature | Crate | 状態 | 説明 |
|---|---|---|---|
| `chipmunk` | misaka-pqc | opt-in | ChipmunkRing署名 |
| `chipmunk` | misaka-mempool | opt-in | Chipmunk TX受入 |
| `chipmunk` | misaka-consensus | opt-in | Chipmunk block検証 |
| `stealth-v2` | misaka-pqc | default | Stealth v2プロトコル |
| `dev-bridge-mock` | misaka-bridge | dev-only | MockVerifier (本番禁止) |
| `strict-ki-proof` | misaka-consensus | default | KI proof必須化 |
| `legacy-block-fallback` | misaka-consensus | opt-in | 旧ブロック互換 |

---

## Testnet起動手順

```bash
# 1. ビルド（Chipmunk無効、LRS-v1のみ）
cargo build --release -p misaka-node

# 2. Genesis生成
cargo run --release -p misaka-cli -- genesis --chain-id 2

# 3. Node起動（public mode）
cargo run --release -p misaka-node -- \
  --chain-id 2 \
  --mode public \
  --rpc-port 3001 \
  --p2p-port 6690 \
  --advertise-addr YOUR_PUBLIC_IP:6690 \
  --block-time 60 \
  --validator

# 4. Faucet から受取
cargo run --release -p misaka-cli -- faucet --address msk1YOUR_ADDRESS

# 5. Transfer
cargo run --release -p misaka-cli -- transfer \
  --to msk1RECIPIENT_ADDRESS \
  --amount 1000 \
  --fee 10

# Chipmunkを有効化する場合（研究用）:
cargo build --release -p misaka-node --features chipmunk
cargo run --release -p misaka-node -- --enable-chipmunk ...
```

---

## Domain Separation Tag棚卸し

| Tag | 用途 | 衝突リスク |
|---|---|---|
| `MISAKA-PQ-SIG:v2:` | validator署名 | なし |
| `MISAKA-v1:ml-dsa-65:tx-auth:` | TX署名 | なし |
| `MISAKA-v2:p2p:session-key:` | P2Pセッション | なし |
| `MISAKA-v2:p2p:transcript:` | P2Pハンドシェイク | なし |
| `MISAKA:proposal:v2:` | ブロック提案 | なし |
| `MISAKA:vote:v2:` | 委員会投票 | なし |
| `MISAKA_BRIDGE_AUTH:v2:` | ブリッジ認可 | なし |
| `MISAKA_KI_V1:` | 正規Key Image | なし |
| `MISAKA-LRS:ki:v1:` | LRS Key Image (legacy) | **→canonical_kiに統一推奨** |
| `MISAKA-LRS:challenge:v1:` | LRS challenge hash | なし |
| `MISAKA-LRS:a-param:v1` | LRS公開パラメータ | なし |
| `misaka/pq-stealth/*` | Stealth v1 | なし |
| `MISAKA_STEALTH_V2:*` | Stealth v2 | なし |
| `MISAKA_STARK:v1:` | STARK証明 | なし |
