## MISAKA Network — P2P Security Hardening Report

**Date:** 2026-03-25
**Scope:** `misaka-p2p` crate + `dag_p2p_transport.rs` wire protocol
**Protocol Version:** v2 → v3 (breaking change)

---

### Executive Summary

MISAKA P2P レイヤーの包括的セキュリティ監査を実施し、6つの脆弱性クラスを特定・修正しました。修正は3つのカテゴリに分類されます: ハンドシェイクプロトコルの強化（3件）、トランスポートセッション保護（2件）、ネットワーク層の防御（1件 + 新モジュール）。

全修正はワイヤプロトコルのメジャーバージョンアップ（v2→v3）として統合されており、DST（Domain Separation Tag）の一括更新により旧バージョンとの互換性はありません。テストネットノードの同時アップグレードが必要です。

---

### Vulnerability Matrix

| ID | Severity | Category | Attack Vector | Fix |
|----|----------|----------|---------------|-----|
| SEC-HS-FRESH | **High** | Handshake | リプレイ攻撃 — 録画したハンドシェイクフローの再生 | 双方向32Bフレッシュネスnonce |
| SEC-HS-VER | **Medium** | Handshake | ダウングレード攻撃 — 旧プロトコルへの誘導 | バージョンネゴ + transcript binding |
| SEC-HS-BIND | **Medium** | Handshake | Identity misbinding — ハンドシェイクの横取り | 双方PK hashのtranscript含有 |
| SEC-ST-LIFE | **Medium** | Transport | ステイルセッション — 鍵侵害の影響範囲拡大 | 24hセッション寿命制限 |
| SEC-ST-SEQ | **High** | Transport | フレームリプレイ — 重複メッセージ注入 | スライディングウィンドウnonce tracker |
| SEC-DISC-BOGON | **Medium** | Discovery | ストア汚染 — Bogon IP宣伝によるSSRF/接続浪費 | アドレス検証 + Bogonフィルタ |
| SEC-P2P-GUARD | **High** | Network | Eclipse / DoS — ハンドシェイクフラッド、サブネット独占 | 多層接続ガード（新モジュール） |

---

### Detailed Changes

#### 1. `connection_guard.rs` — 新規モジュール (SEC-P2P-GUARD)

**問題:** ハンドシェイクフラッド、Eclipse攻撃、メモリ枯渇に対する防御が存在しなかった。

**解決:** 5層の防御メカニズムを持つ `ConnectionGuard` を実装。

```
TCP accept → guard.check_inbound(ip) → Allow / Reject
         → guard.register_half_open(ip) → slot_id
         → [handshake completes] → guard.promote_to_established(slot_id)
         → [connection closes] → guard.on_disconnect(ip)
```

| レイヤー | パラメータ | デフォルト |
|---------|-----------|-----------|
| Per-IP スロットリング | `MAX_HANDSHAKE_ATTEMPTS_PER_IP` | 5回/60秒 |
| Half-open 上限 | `MAX_HALF_OPEN` | 64接続 |
| Half-open タイムアウト | `HALF_OPEN_TIMEOUT_SECS` | 15秒 |
| /24 サブネット制限 | `MAX_INBOUND_PER_SUBNET` | 4本 |
| Per-IP 制限 | `MAX_INBOUND_PER_IP` | 2本 |

追加: `is_bogon_ip()` — RFC 1918, RFC 6598 (CGNAT), リンクローカル, ループバック, 予約済みアドレスの検出。`validate_advertised_address()` — PeerRecord内のアドレス検証。

**テスト:** 14件追加。

---

#### 2. `handshake.rs` — v2→v3 全書換

##### SEC-HS-FRESH: フレッシュネスnonce

**問題:** ハンドシェイクtranscriptにランダム要素が無く、弱いRNGでエフェメラルKEM鍵ペアが再利用された場合、録画したハンドシェイクの完全リプレイが可能だった。

**修正:** Initiator/Responder双方が32バイトのCSPRNG nonceを生成し、transcriptに注入。

```
transcript = DST || version || nonce_i(32) || nonce_r(32) || kem_pk || ct || ipk_hash || rpk_hash
```

##### SEC-HS-VER: プロトコルバージョン

**問題:** バージョンネゴシエーション機構が無く、将来のプロトコル変更時にダウングレード攻撃のリスクがあった。

**修正:** Initiatorがバージョンバイトを送信、Responderが `MIN_PROTOCOL_VERSION` との比較をKEM実行前（CPU節約）に実施。バージョンはtranscriptに binding。

##### SEC-HS-BIND: Identity Binding

**問題:** Transcriptが双方の公開鍵を含まず、identity misbinding攻撃（ハンドシェイクを意図しない相手にリダイレクト）が理論上可能だった。

**修正:** 双方のML-DSA-65公開鍵をドメイン分離SHA3-256でハッシュし、transcriptに含有。Responderはstep 2時点でInitiatorのPKを知らないため、ゼロプレースホルダを使用（双方で同一のtranscript計算を保証）。InitiatorのIDはstep 7のML-DSA-65署名検証で証明。

**テスト:** 5件追加。

---

#### 3. `secure_transport.rs` — セッション保護

##### SEC-ST-LIFE: セッション寿命制限

**問題:** セッションに最大存続時間が無く、一度確立されたセッションが無期限に存続。鍵侵害時の影響範囲が無制限、ステイルセッションのリソースリークも懸念。

**修正:** `MAX_SESSION_LIFETIME_SECS = 86400`（24h）。`SessionGuard` 型が送受信の両方でライフタイムチェックを実施。期限切れ時は `AeadError::SessionExpired` を返却。

##### SEC-ST-SEQ: Nonce Replay Protection

**問題:** 受信側のnonce追跡が無く、攻撃者が暗号化フレームをキャプチャ・リプレイした場合、AEADは正常に復号（nonce/keyペアが有効なため）し、アプリケーション層が重複メッセージを処理してしまう。

**修正:** `RecvNonceTracker` — 64ビットスライディングウィンドウ方式。

- 既出nonce → `AeadError::NonceReplay` で即座拒否
- `MAX_NONCE_GAP`（32）を超えるジャンプ → `AeadError::NonceGapTooLarge` で拒否
- 窓内の軽微なreorder（TCP由来）は許容

##### SessionGuard 統合型

`SessionGuard` は `DirectionalKeys` + `NonceCounter`（送信）+ `RecvNonceTracker`（受信）+ ライフタイム管理 + メトリクスを統合した型安全なセッション管理オブジェクト。

```rust
let mut session = SessionGuard::new(keys);
let wire = session.encrypt_and_frame(plaintext)?;   // lifetime + nonce check
let plain = session.verify_and_decrypt(frame)?;      // replay + gap + lifetime check
if session.needs_action() { /* rekey or disconnect */ }
```

**テスト:** 7件追加。

---

#### 4. `discovery.rs` — SEC-DISC-BOGON

**問題:** `PeerStore::ingest_peer_record()` がアドレスの妥当性を検証せず、プライベートIPやループバックアドレスを含むPeerRecordが保存されていた。

**修正:** `connection_guard::validate_advertised_address()` で全アドレスを検証。1つでもBogonアドレスを含むレコードは拒否（fail-closed）。

**テスト:** 2件追加（10.x拒否、127.0.0.1拒否）。

---

#### 5. `dag_p2p_transport.rs` — v3ワイヤプロトコル

Responder/Initiator双方のTCPハンドシェイク関数を更新:

- **Initiator送信:** `kem_pk || identity_pk || nonce_i(32) || version(1)`
- **Responder送信:** `ct || identity_pk || sig || nonce_r(32) || version(1)`
- Transcript構築をv3形式に統一
- 全DST `MISAKA-v2:` → `MISAKA-v3:` 更新（session key, directional key, rekey, transcript）

---

#### 6. `misaka-crypto/validator_sig.rs`

`ValidatorPqPublicKey::zero()` コンストラクタを追加。ハンドシェイクtranscriptでInitiator PKプレースホルダとして使用。

---

### Breaking Changes

| 変更 | 影響 | 移行方法 |
|------|------|---------|
| DST `v2` → `v3` | 全ノード間で互換性なし | テストネット全ノード同時アップグレード |
| ハンドシェイクワイヤ形式変更 | 旧ノードとの接続不可 | 同上 |
| `DirectionalKeys` DST変更 | セッション鍵が異なる | 同上 |
| `responder_handle()` 引数追加 | API破壊的変更 | `nonce_i`, `initiator_version` パラメータ追加 |
| `HandshakeResult` フィールド追加 | 構造体変更 | `protocol_version` フィールド追加 |

### Test Coverage

| ファイル | 新規テスト | カバー領域 |
|---------|-----------|-----------|
| `handshake.rs` | 5 | v3フロー、バージョン拒否、nonce一意性 |
| `secure_transport.rs` | 7 | リプレイ検出、reorder許容、gap拒否、SessionGuard統合 |
| `connection_guard.rs` | 14 | IPスロットリング、half-open制限、サブネット飽和、bogon検出 |
| `discovery.rs` | 2 | プライベートIP拒否、ループバック拒否 |
| **合計** | **28** | |

### Recommendations

1. ~~**テストネット同時デプロイ**~~ ✅ `scripts/testnet_v3_upgrade.sh` で実装済み。
2. ~~**Validator向けセッション寿命短縮**~~ ✅ `configs/testnet.toml` + `mainnet.toml` に `max_session_lifetime_secs` パラメータ追加済み。
3. ~~**CSPRNG直接利用**~~ ✅ `generate_freshness_nonce()` を `rand::rngs::OsRng` に置換済み（~100x高速化）。
4. ~~**ConnectionGuard統合**~~ ✅ `dag_p2p_transport.rs` の accept ループに完全統合済み（`ConnSlotGuard` RAIIパターン）。
5. **IPv6サブネット改善**: 現在の `/24` 相当の抽出は IPv6 では不十分。`/48` プレフィックスベースの実装を検討。
6. **ConnectionGuard設定の動的読み込み**: 現在は定数値。`testnet.toml` / `mainnet.toml` の設定値をランタイムに読み込む機構の実装を推奨。

---

### Deployment

テストネットデプロイスクリプト `scripts/testnet_v3_upgrade.sh` が用意されています。

```bash
# 1. ビルド
cargo build --release --features dag

# 2. プリフライト（SSH接続確認 + バイナリ検証）
./scripts/testnet_v3_upgrade.sh preflight

# 3. 全フェーズ実行（stop → deploy → start → verify）
./scripts/testnet_v3_upgrade.sh all

# 緊急ロールバック（v2に戻す）
./scripts/testnet_v3_upgrade.sh rollback
```

| フェーズ | 説明 |
|---------|------|
| `preflight` | SSH接続、バイナリ存在、設定バージョン検証 |
| `stop` | 全ノード同時停止（並列SSH） |
| `deploy` | v2バックアップ → v3バイナリ + 設定アップロード |
| `start` | 全ノード同時起動 |
| `verify` | v3ハンドシェイク成功確認 + ピア接続数チェック |
| `rollback` | v2バイナリ + 設定を復元して再起動 |
