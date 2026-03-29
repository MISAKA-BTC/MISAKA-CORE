# MISAKA Network — Kaspa構造パリティ + 格子暗号設計書

## 1. 設計方針

**「Kaspaの構造をそのまま、暗号方式だけ格子暗号に差し替え、PoSでTPSを最大化」**

| レイヤー | Kaspa | MISAKA | 変更理由 |
|---|---|---|---|
| 署名 | secp256k1 Schnorr (64B sig, 32B pk) | **ML-DSA-65** (3,293B sig, 1,952B pk) | 耐量子 |
| ハッシュ | Blake2b-256 | **Blake3-256** | 高速、同等安全性 |
| KEM | なし | **ML-KEM-768** (シールドプール用) | 耐量子鍵交換 |
| コンセンサス | PoW (kHeavyHash) | **PoS (BFT + GhostDAG)** | エネルギー効率 |
| DAG構造 | GhostDAG (PHANTOM) | **GhostDAG (PHANTOM)** 同一 | 構造パリティ |
| トランザクション | UTXO | **UTXO** 同一 | 構造パリティ |
| スクリプトエンジン | Stack-based | **Stack-based** 同一 + PQ opcodes | 構造パリティ |
| アドレス形式 | kaspa:prefix | **misaka1** prefix | ネットワーク分離 |
| RPC | JSON-RPC + wRPC(Borsh) | **JSON-RPC + wRPC(Borsh)** 同一 | 互換性 |

---

## 2. 暗号方式マッピング (secp256k1 → ML-DSA-65)

### 2.1 サイズ比較

| | Kaspa (secp256k1) | MISAKA (ML-DSA-65) | 倍率 |
|---|---|---|---|
| 公開鍵 | 32 bytes | 1,952 bytes | ×61 |
| 署名 | 64 bytes | 3,293 bytes | ×51 |
| 秘密鍵 | 32 bytes | 4,032 bytes | ×126 |
| P2PKH script | 35 bytes | 35 bytes | ×1 (ハッシュのみ格納) |
| P2PK script | 34 bytes | 1,954 bytes | ×57 |
| 標準TX入力 | ~150 bytes | ~5,300 bytes | ×35 |
| 標準TX出力 | ~35 bytes | ~35 bytes | ×1 |

### 2.2 透明送金のフロー (Kaspa完全互換)

```
送信者                                    受信者
  │                                        │
  │ 1. UTXO選択 (coin selection)          │
  │ 2. TX構築 (inputs + outputs)           │
  │ 3. SigHash計算 (Blake3 domain-sep)     │
  │ 4. ML-DSA-65署名 (各inputに対して)     │
  │ 5. 署名スクリプト組立                   │
  │ 6. TX送信 → mempool                    │
  │                            ┌───────────│
  │                            │ 7. ブロック│
  │                            │    に含まれ│
  │                            │ 8. UTXO追加│
  │                            └───────────│
```

### 2.3 スクリプトテンプレート

```
P2PKH-PQ (推奨、Kaspa P2PKHと同構造):
  ScriptPubKey: OP_DUP OP_BLAKE3 <32-byte-hash> OP_EQUALVERIFY OP_CHECKSIG_PQ
  ScriptSig:    <3293-byte-mldsa65-sig> <1952-byte-mldsa65-pubkey>
  
  → 公開鍵はハッシュでスクリプトに埋め込む (Kaspaと同じ32バイト)
  → 署名時にフルPKを提示 → Blake3ハッシュで照合

P2PK-PQ (Kaspa P2PKと同構造):
  ScriptPubKey: <1952-byte-pubkey> OP_CHECKSIG_PQ
  ScriptSig:    <3293-byte-sig>
  
  → 大きいが、マイナーやバリデーターのcoinbase用

P2SH-PQ (Kaspa P2SHと同構造):
  ScriptPubKey: OP_BLAKE3 <32-byte-script-hash> OP_EQUAL
  ScriptSig:    <serialized-redeem-script>
```

### 2.4 SigHash計算 (Kaspa sighash_type と完全互換)

```rust
sig_hash = Blake3(
    domain: "TransactionSigningHash"  // Kaspa互換ドメイン
    || sighash_type (1 byte)
    || hash_prevouts (32 bytes)       // Blake3(all input outpoints)
    || hash_sequence (32 bytes)       // Blake3(all sequences)  
    || outpoint (36 bytes)            // current input's outpoint
    || script_public_key (var)        // UTXO's locking script
    || value (8 bytes)                // UTXO amount
    || hash_outputs (32 bytes)        // Blake3(all outputs)
    || lock_time (8 bytes)
    || subnetwork_id (20 bytes)
    || gas (8 bytes)
    || payload_hash (32 bytes)
)
```

---

## 3. TPS最適化 (PoS → Kaspaより高速)

### 3.1 Kaspaの制約 (PoW)

| パラメータ | Kaspa Mainnet | Kaspa Testnet-11 |
|---|---|---|
| BPS (blocks/sec) | 1 | 10 |
| GhostDAG K | 18 | 18 |
| Max parents | 10 | 10 |
| Max block mass | 500,000 | 500,000 |
| 標準TX mass | ~2,500 | ~2,500 |
| TXs/block | ~200 | ~200 |
| **理論TPS** | **~200** | **~2,000** |

### 3.2 MISAKA PoS パラメータ

PoSではマイニング遅延がないため、BPSを大幅に引き上げ可能。
ただしネットワーク伝搬遅延とDAG幅の制約がある。

**保守的設計**: まず10 BPS (Kaspa testnet-11相当) で安全性を確認してから段階的引き上げ。

| パラメータ | MISAKA Phase 1 | MISAKA Phase 2 | MISAKA Phase 3 |
|---|---|---|---|
| BPS | **10** | **20** | **32** |
| GhostDAG K | 18 | 36 | 58 |
| Max parents | 10 | 16 | 24 |
| Block interval | 100ms | 50ms | 31.25ms |
| Max block mass | 500,000 | 500,000 | 500,000 |
| Max block mass (PQ調整) | **2,000,000** | **2,000,000** | **2,000,000** |
| PQ TX mass | ~8,000 | ~8,000 | ~8,000 |
| TXs/block | ~250 | ~250 | ~250 |
| **理論TPS** | **~2,500** | **~5,000** | **~8,000** |

### 3.3 GhostDAG K の計算根拠

Kaspaの論文(PHANTOM)により:
- K ≥ 2λD (λ=BPS, D=network_delay)
- D ≈ 500ms (グローバルP2P遅延)

| BPS | K計算 (D=500ms) | K (安全マージン×1.5) |
|---|---|---|
| 1 (Kaspa) | 2×1×0.5 = 1 | 18 (大幅余裕) |
| 10 | 2×10×0.5 = 10 | 18 |
| 20 | 2×20×0.5 = 20 | 36 |
| 32 | 2×32×0.5 = 32 | 58 |

### 3.4 Mass計算の調整

ML-DSA-65署名は51倍大きいが、P2PKH-PQではPKハッシュ(32バイト)をスクリプトに格納するため、
出力サイズはKaspaと同一。入力サイズのみ増大。

```
Kaspa標準TX (1 input, 2 outputs):
  Input:  32(txid) + 4(index) + 8(seq) + 64(sig) + 33(pk) = ~141 bytes
  Output: 8(value) + 2(ver) + 25(script) = ~35 bytes × 2 = ~70 bytes
  Total:  ~221 bytes → mass ≈ 2,500

MISAKA PQ TX (1 input, 2 outputs):
  Input:  32(txid) + 4(index) + 8(seq) + 3293(sig) + 1952(pk) = ~5,289 bytes
  Output: 8(value) + 2(ver) + 35(script) = ~45 bytes × 2 = ~90 bytes
  Total:  ~5,469 bytes → mass ≈ 8,000 (調整後)
```

**解決策**: `MAX_BLOCK_MASS` を Kaspaの 500K から **2,000K** に引き上げ。
これにより、PQ TXでも1ブロックに ~250 TX格納可能 (Kaspaと同等のTXs/block)。

---

## 4. コンセンサスパラメータ統一表

```rust
// ═══ MISAKA Network Parameters (Phase 1) ═══
pub const NETWORK_ID: &str = "misaka-mainnet";
pub const PROTOCOL_VERSION: u32 = 1;

// ── GhostDAG ──
pub const GHOSTDAG_K: u64 = 18;           // Same as Kaspa
pub const MAX_BLOCK_PARENTS: usize = 10;   // Same as Kaspa
pub const MAX_MERGESET_SIZE: usize = 512;  // 2× Kaspa (PQ larger blocks)
pub const BPS: u64 = 10;                   // 10× Kaspa mainnet
pub const TARGET_TIME_PER_BLOCK_MS: u64 = 100; // 100ms = 10 BPS

// ── Block Limits ──
pub const MAX_BLOCK_MASS: u64 = 2_000_000;      // 4× Kaspa (PQ TX larger)
pub const MAX_TX_MASS: u64 = 200_000;            // 2× Kaspa
pub const MAX_BLOCK_TRANSACTIONS: usize = 50_000; // Same as Kaspa
pub const MAX_BLOCK_SIG_OPS: u64 = 80_000;       // Same as Kaspa

// ── Mass Calculation ──  
pub const MASS_PER_TX_BYTE: u64 = 1;              // Same as Kaspa
pub const MASS_PER_SCRIPT_PUB_KEY_BYTE: u64 = 10; // Same as Kaspa
pub const MASS_PER_SIG_OP: u64 = 1000;            // Same as Kaspa
pub const MASS_PER_PQ_SIG_OP: u64 = 1000;         // Same weight (normalzied by block mass increase)
pub const MASS_PER_INPUT: u64 = 100;               // Same as Kaspa
pub const MASS_PER_OUTPUT: u64 = 50;               // Same as Kaspa
pub const BASE_MASS: u64 = 100;                    // Same as Kaspa

// ── Cryptography ──
pub const SIG_ALGORITHM: &str = "ML-DSA-65";
pub const HASH_ALGORITHM: &str = "Blake3-256";
pub const KEM_ALGORITHM: &str = "ML-KEM-768";      // For shielded pool
pub const PK_SIZE: usize = 1_952;                   // ML-DSA-65 public key
pub const SIG_SIZE: usize = 3_293;                   // ML-DSA-65 signature
pub const SK_SIZE: usize = 4_032;                    // ML-DSA-65 secret key
pub const HASH_SIZE: usize = 32;                     // Blake3 output

// ── Finality & Pruning (blue_score based) ──
pub const FINALITY_DEPTH: u64 = 200;                // Same as Kaspa
pub const PRUNING_DEPTH: u64 = 100_000;             // Same as Kaspa
pub const COINBASE_MATURITY: u64 = 100;              // Same as Kaspa

// ── Address ──
pub const ADDRESS_PREFIX: &str = "misaka1";
pub const TESTNET_PREFIX: &str = "misakatest1";

// ── Tokenomics ──  
pub const TOTAL_SUPPLY: u64 = 21_000_000_000;       // 21 billion MISAKA
pub const DECIMALS: u32 = 9;                          // 1 MISAKA = 10^9 base units
pub const INITIAL_BLOCK_REWARD: u64 = 500_000_000_000; // 500 MISAKA/block
```

---

## 5. セキュリティ等価性の証明

### 5.1 暗号安全性

| 安全性指標 | Kaspa (secp256k1) | MISAKA (ML-DSA-65) |
|---|---|---|
| 古典的安全性 | 128-bit | **192-bit** (上位) |
| 量子安全性 | 0-bit (脆弱) | **128-bit** (NIST Level 3) |
| EUF-CMA安全性 | ✓ | ✓ |
| SUF-CMA安全性 | ✓ (Schnorr) | ✓ (ML-DSA) |
| NIST標準 | ✗ | **✓ (FIPS 204)** |

### 5.2 コンセンサス安全性 (GhostDAG保証同一)

- **Liveness**: K≥2λDの条件でBPSに関わらず保証 → MISAKAでも同一
- **Safety**: FINALITY_DEPTH=200でreorg確率 < 2^(-64) → Kaspaと同一
- **51%攻撃**: PoSではstake量で決定 → PoWの51%攻撃と同等の耐性

### 5.3 DoS耐性 (同一設計)

| 防御 | Kaspa | MISAKA |
|---|---|---|
| Max block mass | 500K | 2M (PQ調整) |
| Max sig ops/block | 80K | 80K |
| Mass-based fee | ✓ | ✓ |
| Script size limit | 10KB | 10KB |
| Mempool eviction | Fee-rate | Fee-rate |
| P2P rate limit | Per-type | Per-type |
| Bogon filtering | ✓ | ✓ |

---

## 6. 実装の差分まとめ

### 変更するファイル:
1. `misaka-dag/src/constants.rs` — BPS, block mass, K parameter
2. `misaka-consensus/src/mass.rs` — PQ mass normalization
3. `misaka-crypto/src/signature.rs` — ML-DSA-65 verification pipeline
4. `misaka-txscript/src/script_engine.rs` — OP_CHECKSIG_PQ dispatch
5. `misaka-txscript/src/script_builder.rs` — P2PKH-PQ template
6. `misaka-types/src/constants.rs` — network-wide constants
7. `misaka-node/src/config.rs` — default BPS, block time

### 変更しないファイル (Kaspa同一構造):
- GhostDAG実装 (`ghostdag_v2.rs`)
- Reachability (`reachability.rs`)
- UTXO処理 (`utxo_set.rs`)
- DAGストア (`dag_store.rs`)
- RPCプロトコル (JSON-RPC, wRPC)
- ウォレットRPC API
- Pruning/Finality logic
