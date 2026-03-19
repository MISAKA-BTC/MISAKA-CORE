# MISAKA Validator Tools

misakastake.com バリデータ登録・運用ツール。

## 前提条件

- Node.js 18+
- VPS (Ubuntu 22.04+ 推奨)

## セットアップ

```bash
cd validator-tools
npm install
```

## フロー

```
┌─────────────────────────────────────────────────────────────┐
│                        VPS 上で実行                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. node generate-l1-key.js                                 │
│     → l1-secret-key.json (VPSに保管)                       │
│     → l1-public-key.json (共有可)                          │
│     → L1 Public Key (hex 64文字) を表示                    │
│                                                             │
│  2. misakastake.com で登録                                  │
│     → L1 Public Key を貼り付け                             │
│     → Node Name を入力                                     │
│     → Register Validator を押す                            │
│                                                             │
│  3. node start-validator.js --key ./l1-secret-key.json      │
│     → ML-DSA-65 鍵の整合性検証                             │
│     → misaka-node をバリデータモードで起動                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘

⚠ Solanaの秘密鍵はVPSに不要
```

## コマンド

### 鍵生成

```bash
# デフォルト (カレントディレクトリに出力)
node generate-l1-key.js

# 名前とディレクトリを指定
node generate-l1-key.js --name my-validator --output ./keys
```

**出力ファイル:**

| ファイル | 内容 | 共有 |
|---------|------|------|
| `l1-secret-key.json` | 秘密鍵 (ML-DSA-65, 4032 bytes) | ❌ 絶対禁止 |
| `l1-public-key.json` | 公開鍵 + Proof-of-Possession | ✅ misakastake.com に提出 |

### バリデータ起動

```bash
# 基本
node start-validator.js --key ./l1-secret-key.json

# ポート指定
node start-validator.js --key ./l1-secret-key.json --rpc-port 3001 --p2p-port 6690

# ピア接続
node start-validator.js --key ./l1-secret-key.json --peers 1.2.3.4:6690,5.6.7.8:6690

# ドライラン (起動コマンド表示のみ)
node start-validator.js --key ./l1-secret-key.json --dry-run
```

**オプション:**

| フラグ | デフォルト | 説明 |
|--------|-----------|------|
| `--key` | `./l1-secret-key.json` | 秘密鍵ファイルパス |
| `--rpc-port` | `3001` | RPC ポート |
| `--p2p-port` | `6690` | P2P ポート |
| `--chain-id` | `2` | Chain ID (1=mainnet, 2=testnet) |
| `--block-time` | `60` | ブロック生成間隔 (秒) |
| `--peers` | (なし) | 静的ピア (カンマ区切り) |
| `--seeds` | (なし) | シードノード (カンマ区切り) |
| `--advertise-addr` | (なし) | 外部アドバタイズアドレス |
| `--log-level` | `info` | ログレベル |
| `--dry-run` | false | 起動コマンドの表示のみ |

## 暗号アルゴリズム

| 項目 | アルゴリズム | サイズ |
|------|------------|--------|
| 署名 | ML-DSA-65 (FIPS 204 / Dilithium3) | pk=1952B, sk=4032B, sig=3309B |
| ハッシュ | SHA3-256 | 32 bytes |
| L1 Public Key | SHA3-256(ML-DSA-65 public key) | 32 bytes (64 hex) |
| Validator ID | SHA3-256(ML-DSA-65 public key)[0..20] | 20 bytes (40 hex) |

## セキュリティ

- **秘密鍵は VPS 外に出さない** — `l1-secret-key.json` は生成したVPS上のみで使用
- **Solana秘密鍵は不要** — L1バリデータ運用にSolana鍵は一切不要
- **鍵生成時に自動検証** — sign/verify テストが内蔵
- **起動時に再検証** — `start-validator.js` が鍵の整合性を毎回チェック
- **Proof-of-Possession** — 登録時にML-DSA-65署名で鍵所有を証明
- **ECC (Ed25519) 不使用** — 全て耐量子暗号 (Post-Quantum)
