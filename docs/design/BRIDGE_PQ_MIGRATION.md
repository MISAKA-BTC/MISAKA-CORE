# Bridge PQ Migration Design

## Current State

MISAKA 側の bridge authorization は ML-DSA-65 committee verification (PQ native)。
Solana 側は Ed25519 (非 PQ) に依存。

## Solana 側の Ed25519 依存

- Solana のプログラム署名検証は Ed25519 precompile
- Bridge relayer が Solana TX に Ed25519 署名を付与
- MISAKA → Solana のアンロック TX には Ed25519 が必要

### リスク

Solana が PQ 移行を行うまで、bridge relayer の Ed25519 秘密鍵が漏洩すると
Solana 側で不正アンロックが可能。MISAKA 側は ML-DSA-65 で保護されているが、
Solana 側のガードは Ed25519 のみ。

## 移行パス

### Phase 1 (現在): Hybrid

```
MISAKA → Bridge committee (ML-DSA-65) → Relayer → Solana (Ed25519)
```

- MISAKA 側: PQ safe
- Solana 側: 非 PQ (Ed25519 precompile)
- リスク: relayer Ed25519 鍵の漏洩

### Phase 2 (Solana PQ 対応後): Full PQ

```
MISAKA → Bridge committee (ML-DSA-65) → Relayer → Solana (PQ program)
```

- Solana が PQ 署名検証をプログラムレベルでサポートした時点で移行
- Relayer は ML-DSA-65 で Solana TX に署名

### Phase 3 (将来): Trustless bridge

- ZK bridge proof (MISAKA の STARK/SNARK 証明を Solana で検証)
- Relayer が不要になる

## 現時点の緩和策

1. **Relayer 鍵ローテーション**: Ed25519 鍵を定期的に更新
2. **Multisig**: Solana 側のアンロックに M-of-N multisig を要求
3. **Rate limiting**: Solana プログラムに per-epoch アンロック上限を設定
4. **MISAKA 側 ML-DSA-65 検証**: bridge_in TX は domain-separated 署名で検証
   (`MISAKA-v1:bridge-auth:` prefix)
