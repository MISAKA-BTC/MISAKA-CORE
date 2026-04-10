# Stub/Placeholder インベントリ

grep 結果 148 件を分類。

## 分類サマリー

| 分類 | 件数 | 対応 |
|------|------|------|
| **A: 既に feature-gated (stark-stub)** | 42 | release ビルドで存在しない。OK |
| **B: テストヘルパー (dummy_*)** | 52 | テスト内のダミーデータ生成。正当。OK |
| **C: コメント/ドキュメント内の言及** | 28 | "Stub" という単語がコメントに出現するだけ。OK |
| **D: TODO/FIXME (要対応)** | 8 | GitHub issue を振る or 修正 |
| **E: Production 残存 (要修正)** | 18 | 本修正対象 |

## A: feature-gated (42 件) — 対応不要

全て `#[cfg(feature = "stark-stub")]` でゲート済み。
release ビルドで `compile_error!` が発火するため production に漏洩不可能。
- `pqc/lib.rs`: 6 件
- `pqc/privacy_dispatch.rs`: 10 件
- `pqc/stark_proof.rs`: 3 件
- `pqc/privacy_constraints.rs`: 2 件
- `pqc/privacy_backend.rs`: 1 件
- `consensus/block_validation.rs`: 2 件
- `node/dag_rpc.rs`: 4 件
- `pqc/composite_proof.rs`: 1 件 (コメントのみ)
- その他: 13 件

## B: テストヘルパー (52 件) — 対応不要

`dummy_utxo()`, `dummy_inputs()`, `dummy_fee()`, `dummy_enc_note()` 等。
全て `#[cfg(test)]` 内またはテスト専用ヘルパー関数。正当な用途。

## C: コメント/ドキュメント (28 件) — 対応不要

"StubProofBackend" "placeholder" 等がコメントやドキュメントに出現するのみ。
コード実行パスには影響なし。

## D: TODO/FIXME (8 件) — issue 振り

| # | ファイル | 行 | 内容 | 対応 |
|---|---------|---|------|------|
| D1 | `main.rs:991` | `TODO: integrate with UTXO set` | balance API が 0 固定 | issue #TBD |
| D2 | `dag_p2p_network.rs:695` | `TODO: PeerRecord gossip` | peer discovery 未実装 | issue #TBD |
| D3 | `mining/monitor.rs:29` | `TODO: collect expired tx IDs` | mempool GC | issue #TBD |
| D4 | `dag/qdag_verify.rs:168` | `TODO(P1): epoch-proof` | Q-DAG-CT 拡張 | issue #TBD |
| D5 | `main.rs:2960` | `stake_tx_hash placeholder` | staking TX hash | **修正** |
| D6 | `main.rs:3736` | `Stub P2P for RPC server` | legacy P2P | **修正** |
| D7 | `rpc/handler.rs:143` | `placeholder — actual execution` | RPC dispatch | **修正** |
| D8 | `vm/runtime.rs:110` | `placeholder return` | VM runtime | **修正** |

## E: Production 残存 (18 件) — 修正対象

### E1: StubProofBackend struct (proof_backend.rs)
Phase 5.1 で `#[cfg(any(test, feature = "dev-stub-proof"))]` に隔離済み。
ただし `shielded_state.rs:198` で testnet 登録コードが残存。
→ **登録パス自体を cfg gate する。**

### E2: ProofBackendKind::Stub / ProofBackendPhase::Stub (proof_backend.rs:104,111)
enum variant として残存。production binary で match arm が必要。
→ **variant を cfg gate するか、`#[non_exhaustive]` にして production では unreachable!()。**

### E3: ShieldedProofBackendKindTag::Stub (rpc_types.rs:283,291)
RPC レスポンス型に Stub variant。
→ **cfg gate。production RPC では Stub backend は登録不可能なので返らない。**

### E4: shielded_hook_impl.rs:566 / shielded_rpc.rs:653
`ProofBackendKind::Stub => 5u8` のマッピング。
→ **E2 と同時に cfg gate。**

### E5: validator_sig.rs:33 `ValidatorPqPublicKey::zero()` "sentinel / placeholder"
ゼロ公開鍵をセンチネルとして使用。
→ **コメント改善のみ** (セマンティクスとして正当: "null public key")。

### E6: handshake.rs:208,220,277 `ValidatorPqPublicKey::zero()` placeholder
P2P handshake でゼロ PK をプレースホルダーとして使用。
→ **設計上残す** (initiator 側で responder PK が未知の段階で使用。プロトコル仕様)。

### E7: dag_p2p_transport.rs:569 `ValidatorPqPublicKey::zero()` placeholder
→ **E6 と同じ理由で設計上残す。**

### E8: block_producer.rs:67,389,391 "placeholder" addresses
→ **SEC-FIX-6 で修正済み** (config から読み込み)。コメント更新のみ。

### E9: selected_chain.rs:22 `&[]` placeholder
→ **コード確認**: 実際のキー計算は U64KeyBytes で行われており、&[] は never-called path。削除可。

### E10: tx_resolve.rs:116 "placeholder Poly"
→ **設計上残す** (ML-DSA verify path では Poly は使われない。型整合のためのゼロ値)。

### E11: vm/runtime.rs:110 `Ok(vec![])` placeholder
→ **VM 未実装** (Phase 0 で Executor trait 境界のみ凍結。VM 本体は将来)。コメント更新。

### E12: shielded_state.rs:1278 `signature_bytes: vec![]` placeholder
→ **修正**: 空署名は deposit TX 構築時の仮値。実署名で埋めるべき。

## 対応計画

### 即修正 (この PR)

1. `ProofBackendKind::Stub` / `ProofBackendPhase::Stub` → cfg gate
2. `rpc_types.rs` の Stub variant → cfg gate
3. `shielded_hook_impl.rs` / `shielded_rpc.rs` の Stub マッピング → cfg gate
4. D5-D8 の placeholder 値を修正 or コメント更新
5. `block_producer.rs` のコメント更新 (SEC-FIX-6 済み)

### コメント改善のみ

6. E5, E6, E7: "placeholder" → "protocol-required zero sentinel" に更新
7. E10, E11: "placeholder" → "not used in current path; reserved for VM" に更新

### 削除

8. E9 `selected_chain.rs:22` の dead placeholder
