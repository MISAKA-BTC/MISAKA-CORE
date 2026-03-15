
⸻

MISAKA Network — チェーン仕様書 v0.4.2

耐量子暗号ネイティブ・プライバシーブロックチェーン  ￼

1. 概要

MISAKA Network は、次の 2 つを中核設計原則とする Layer 1 ブロックチェーンです。 ￼
	•	耐量子安全性 — すべての暗号プリミティブは格子ベース（NIST PQC 標準）です。プロトコル内に ECC は一切使用しません。 ￼
	•	デフォルトでのプライバシー — 送信者匿名性のためのリング署名、受信者匿名性のためのステルスアドレスを採用します。 ￼

主要プロパティ

項目	値
ブロック時間	60 秒
コンセンサス	Ed25519 + ML-DSA-65 のハイブリッド署名を用いた BFT
トランザクションモデル	UTXO
送信者プライバシー	リング署名（LRS-v1 または ChipmunkRing-v1）
受信者プライバシー	ML-KEM-768 ステルスアドレス（v1 または v2）
金額	公開
リングサイズ	4–16（LRS-v1）/ 4–32（ChipmunkRing-v1）
キーイメージ	正準・方式非依存
ハッシュ関数	SHA3-256 / SHA3-512
1 ブロックあたり最大 TX 数	1,000
チェーン ID（Mainnet）	1
チェーン ID（Testnet）	2


⸻

2. 暗号プリミティブ

2.1 ML-DSA-65（FIPS 204）

用途: バリデータ署名、ブロック提案、委員会投票。 ￼

パラメータ	サイズ
公開鍵	1,952 バイト
秘密鍵	4,032 バイト
署名	3,309 バイト
安全性	NIST Level 3

2.2 ML-KEM-768（FIPS 203）

用途: ステルスアドレス鍵交換（受信者プライバシー）。 ￼

パラメータ	サイズ
公開鍵	1,184 バイト
秘密鍵	2,400 バイト
暗号文	1,088 バイト
共有秘密	32 バイト
安全性	NIST Level 3

2.3 ハイブリッド・バリデータ署名

Ed25519 と ML-DSA-65 の 両方が検証に成功する必要 があります。
ドメインタグ: MISAKA-HYBRID-SIG:v1:  ￼

構成要素	サイズ
ハイブリッド公開鍵	1,984 バイト（32 + 1,952）
ハイブリッド署名	3,373 バイト（64 + 3,309）

2.4 リング署名

ring_scheme フィールドにより、トランザクションごとに 2 つの方式から選択できます。 ￼

LRS-v1（Lyubashevsky 格子 Σ-プロトコル）

パラメータ	値
q	12,289
n	256
η	1
τ	46
γ	6,000
β	5,954
リングサイズ	4–16
TX バージョン	0x01
スキームタグ	0x01

ChipmunkRing-v1（拡張格子リング署名）

パラメータ	値
q	12,289
n	256
η	2
τ	46
γ	8,192
β	8,100
リングサイズ	4–32
TX バージョン	0x02
スキームタグ	0x02
状態	⚠ 監査前

両方式は同じ RingScheme トレイト・インターフェースを共有し、同じ支出秘密鍵から 同一の正準キーイメージ を生成します。 ￼

2.5 正準キーイメージ

方式非依存かつ決定的です。これにより、方式をまたいだ二重支払い を防止します。 ￼

KI = SHA3-256("MISAKA_KI_V1:" || SHA3-512(s.to_bytes()))  ￼

正準 DST MISAKA_KI_V1: は旧来の方式別 DST を置き換えます。LRS と ChipmunkRing の両アダプタは、この正準導出を使用します。 ￼

2.6 キーイメージ正当性証明（Σ-プロトコル）

各方式はそれぞれ独自の KI 証明フォーマットを持ちますが、どちらも 同じ正準キーイメージ導出を知っていること を証明します。 ￼
	•	LRS KI proof: 576 バイト（32 challenge + 512 response + 32 commitment）
	•	ChipmunkRing KI proof: 576 バイト（同じ構造だがパラメータが異なる）  ￼

⸻

3. トランザクションモデル

3.1 UTXO トランザクション

UtxoTransaction {
  version: u8,          // 0x01 (LRS) or 0x02 (ChipmunkRing)
  ring_scheme: u8,      // 0x01 (LRS) or 0x02 (ChipmunkRing)
  inputs: Vec<RingInput>,
  outputs: Vec<TxOutput>,
  fee: u64,
  extra: Vec<u8>,       // up to 1,024 bytes
}
```  [oai_citation:21‡MISAKA-CHAIN-SPEC.pdf](sediment://file_0000000089747206aabfdf827930dec4)

### 3.2 リング入力

```text
RingInput {
  ring_members: Vec<OutputRef>, // 4–32 UTXO references
  ring_signature: Vec<u8>,      // scheme-dependent
  key_image: [u8; 32],          // canonical, deterministic
  ki_proof: Vec<u8>,            // scheme-dependent, REQUIRED
}
```  [oai_citation:22‡MISAKA-CHAIN-SPEC.pdf](sediment://file_0000000089747206aabfdf827930dec4)

### 3.3 トランザクション出力

```text
TxOutput {
  amount: u64,
  one_time_address: [u8; 20],
  pq_stealth: Option<PqStealthData>, // v1 (0x01) or v2 (0x02)
}
```  [oai_citation:23‡MISAKA-CHAIN-SPEC.pdf](sediment://file_0000000089747206aabfdf827930dec4)

### 3.4 プライバシー特性

| 項目 | メカニズム | 状態 |
|---|---|---|
| 送信者匿名性 | リング署名（4–32 デコイ） | 有効 |
| 受信者匿名性 | ML-KEM-768 ステルスアドレス | 有効 |
| 金額秘匿 | なし | 設計上公開 |
| 二重支払い防止 | 正準キーイメージ | 有効 |
| 方式横断の二重支払い防止 | 正準 KI DST | 有効 |  [oai_citation:24‡MISAKA-CHAIN-SPEC.pdf](sediment://file_0000000089747206aabfdf827930dec4)

### 3.5 ステルスアドレス・プロトコル

- **v1** — 元の ML-KEM + HKDF + XChaCha20-Poly1305
- **v2** — バージョン付きドメイン分離、最適化 scan_tag、アドレスコミットメント、任意の暗号化メモを追加した強化版  [oai_citation:25‡MISAKA-CHAIN-SPEC.pdf](sediment://file_0000000089747206aabfdf827930dec4)

Stealth v2 のオンチェーンデータ:  [oai_citation:26‡MISAKA-CHAIN-SPEC.pdf](sediment://file_0000000089747206aabfdf827930dec4)

```text
StealthPayloadV2 {
  version: 0x02,
  kem_ct: [u8; 1088],        // ML-KEM-768 ciphertext
  scan_tag: [u8; 16],        // fast-rejection (constant-time)
  addr_commit: [u8; 20],     // one-time address commitment
  amount_ct: Vec<u8>,        // AEAD encrypted amount (24 bytes)
  memo_ct: Option<Vec<u8>>,  // AEAD encrypted memo
}

ドメインラベル（すべて v2 プレフィックス付き）:  ￼
	•	MISAKA_STEALTH_V2:root
	•	MISAKA_STEALTH_V2:address
	•	MISAKA_STEALTH_V2:scan
	•	MISAKA_STEALTH_V2:amount
	•	MISAKA_STEALTH_V2:memo
	•	MISAKA_STEALTH_V2:nonce
	•	MISAKA_STEALTH_V2:addr_commit

スキャンフロー: quick_scan（scan_tag のみ）→ full recover（AEAD 復号）。 ￼

⸻

4. コンセンサス

パラメータ	値
ブロック時間	60 秒
クォーラム閾値	2/3 + 1（6,667 bps）
最小バリデータ数	4
エポック長	720 checkpoints（約 12 時間）
プロポーザー選出	スロットごとのラウンドロビン

ブロック検証では、tx.ring_scheme に従ってリング署名検証を分岐します。 ￼
	•	0x01 → LRS verify + LRS KI proof
	•	0x02 → ChipmunkRing verify + ChipmunkRing KI proof

両方とも、同じ spent-set に対して 正準キーイメージの一意性 を確認します。 ￼

⸻

5. トークノミクス

パラメータ	値
ジェネシス供給量	10,000,000,000 MISAKA
初期インフレ率	年率 5%
逓減	毎年 -0.5%
下限	年率 1%
手数料: Validator	1.5%
手数料: Admin	1.0%
手数料: Archive	0.5%


⸻

6. ネットワークアーキテクチャ

6.1 ノードモード

項目	Public	Hidden	Seed
受信接続	有効	無効	有効
IP 広告	有効	無効	有効
ブロック生成	有効	有効	無効
ピア探索	有効	無効	有効
最大 inbound	48	0	128
最大 outbound	16	16	32

用途:  ￼
	•	Seed Node → --mode seed（ブートストラップ）
	•	Explorer / Relay → --mode public
	•	Validator / Miner / Wallet → --mode hidden

Hidden ノードでは、TCP リスナーは無効化され、Hello 内の listen_addr は None、GetPeers にも出現しません。 ￼

6.2 P2P メッセージ

Hello, NewBlock, NewTx, GetPeers, Peers, RequestBlock, Ping/Pong。
TCP 上の長さプレフィックス付き JSON で、最大 1 MB。 ￼

⸻

7. クロスチェーンブリッジ（Solana）

7.1 アーキテクチャ

Solana（lock/unlock）←→ Relayer ←→ Misaka（mint/burn + ZK-ACE authorization）  ￼

7.2 Misaka 側
	•	BridgeVerifier トレイト: 差し替え可能な認可機構
（MockVerifier は開発専用、CommitteeVerifier は本番用）
	•	BridgeRequest / BridgeReceipt はドメイン分離された authorization_hash を使用
	•	ブリッジ対象トークンを登録する AssetRegistry
	•	ReplayProtection（nullifier set）  ￼

ドメインタグ:  ￼
	•	MISAKA_BRIDGE_MINT:v1:
	•	MISAKA_BRIDGE_BURN:v1:
	•	MISAKA_BRIDGE_RELEASE:v1:

MockVerifier は #[cfg(feature = "dev-bridge-mock")] の背後に限定されます。
デフォルトビルドでは CommitteeVerifier のみ使用されます。 ￼

7.3 Solana Anchor Program

PDA seed は misaka-bridge- プレフィックスで集中管理されています。 ￼

アカウント	Seeds
Config	["misaka-bridge-config"]
Vault Authority	["misaka-bridge-vault-auth"]
Vault	["misaka-bridge-vault", mint]
Asset Mapping	["misaka-bridge-asset", asset_id]
Lock Receipt	["misaka-bridge-receipt", nonce]
Nonce State	["misaka-bridge-nonce", request_id]

命令群: initialize_bridge, register_asset, lock_tokens, unlock_tokens, pause_bridge, unpause_bridge, rotate_relayer。 ￼

7.4 Relayer
	•	双方向ポーリング
（Solana lock → Misaka mint、Misaka burn → Solana unlock）
	•	永続的な処理済みメッセージ保存領域（JSON ファイル）
	•	決定的な冪等性キー
SHA3-256(domain || tx_hash || amount || recipient)
	•	共有ボリュームによりマルチインスタンス安全
	•	Docker Compose + systemd 配備対応  ￼

⸻

8. RPC インターフェース

14 個のエンドポイントを提供します。 ￼
	•	get_chain_info
	•	get_latest_blocks
	•	get_block_by_height
	•	get_block_by_hash
	•	get_latest_txs
	•	get_tx_by_hash
	•	get_validator_set
	•	get_validator_by_id
	•	get_block_production
	•	get_address_outputs
	•	search
	•	submit_tx
	•	faucet
	•	health

⸻

9. クレート構成

合計: 約 13,600 行の Rust、170 以上のテスト、17 クレート。 ￼

主な構成:  ￼
	•	misaka-types/
TX モデル、ステルス、バリデータ型、genesis
	•	misaka-crypto/
ハイブリッド署名（Ed25519 + ML-DSA-65）
	•	misaka-pqc/
PQ 暗号: LRS、ChipmunkRing、KI proof、stealth v1/v2、RingScheme trait、canonical KI、NTT、wire codec
	•	misaka-storage/
ロールバック対応 UTXO Set
	•	misaka-mempool/
方式認識型 PQ 検証付き TX pool
	•	misaka-consensus/
BFT、ブロック検証（方式分岐）、proposer
	•	misaka-execution/
ブロック実行エンジン
	•	misaka-tokenomics/
供給量、インフレ、手数料分配
	•	misaka-bridge/
クロスチェーンブリッジ（ZK-ACE verifier trait）
	•	misaka-node/
バリデータノード（P2P、RPC、block producer）
	•	misaka-cli/
CLI ツール（keygen、genesis、transfer、faucet）
	•	misaka-test-vectors/
プロトコル test vectors
	•	solana-bridge/
Anchor program（lock/unlock/vault）
	•	relayer/
ブリッジリレイヤー（双方向、冪等性）
	•	docs/
CHIPMUNK-AUDIT.md、chain spec

⸻

10. セキュリティモデル

耐量子安全性

すべての公開鍵暗号は NIST PQC 標準を使用します。
ハイブリッド・バリデータ署名には性能目的で Ed25519 も含まれますが、安全性の依拠先は ML-DSA-65 です。 ￼

プライバシー保証
	•	送信者に対する強い計算量的プライバシー
（リング匿名集合 4–32）
	•	受信者に対するステルスアドレスの unlinkability
	•	正準キーイメージの決定性により、署名方式をまたぐ二重支払いを防止
	•	金額は監査性のため 公開（設計上の選択）  ￼

ブリッジセキュリティ
	•	MockVerifier は開発用 feature flag の背後に完全隔離
	•	CommitteeVerifier は M-of-N 閾値、重複排除、ドメイン分離を備える
	•	リプレイ保護は Misaka 側の nullifier set と Solana 側の PDA nonce state により実現
	•	PDA seed に prefix を付け、プログラム間衝突を防止  ￼

監査状況

コンポーネント	状態
LRS-v1 ring signature	実装済み、本番利用中
ChipmunkRing-v1	⚠ 監査前（docs/CHIPMUNK-AUDIT.md 参照）
Canonical Key Image	実装済み、方式横断テスト済み
Stealth v2	実装済み、16 テスト
Bridge MockVerifier	開発専用で隔離
Bridge CommitteeVerifier	⚠ Ed25519 署名検証が未完
Solana PDA seeds	Prefix 化・集中管理済み
Relayer idempotency	永続ストア対応


⸻

