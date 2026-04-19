# MISAKA-CORE

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Consensus](https://img.shields.io/badge/consensus-Narwhal%2FBullshark-green.svg)](docs/architecture.md)
[![Signature](https://img.shields.io/badge/signature-ML--DSA--65%20(FIPS%20204)-purple.svg)](docs/architecture.md)

**MISAKA-CORE** は MISAKA Network の Rust 実装 monorepo です。
Narwhal/Bullshark DAG 合意、ML-DSA-65 ポスト量子署名、SMT 状態コミットメントで
構成される post-quantum native L1 blockchain の正本ソースです。

> **現在のバージョン: v0.9.0**（workspace `Cargo.toml`）
>
> v0.9.0 で landed：
> - **Phase 2 storage foundation**（PR #11/#12/#13）— `StorageCf` / `NarwhalCf` enum、
>   CF split + pruning、BlobDB + ZSTD、10s block time、WAL 512MB cap
> - **SMT state commitment**（PR #12 PR E）— MuHash3072 → Sparse Merkle Tree
>   （`MISAKA:state_root:v5:`）、O(log N) inclusion/exclusion proof 対応
> - **Phase 3a + 3a.5**（PR #14）— Cert V2 store-layer、adaptive round scheduler、
>   epoch boundary handler、EpochStatsCollector
> - v0.8.9 hotfix（PR #10）の cold-reset + peer-churn liveness 修正

---

## 📖 Documentation

| 目的 | 参照先 |
|---|---|
| **Testnet に validator として参加** | [`docs/JOIN_TESTNET.md`](docs/JOIN_TESTNET.md) |
| **Testnet join の troubleshooting** | [`docs/JOIN_TESTNET_TROUBLESHOOTING.md`](docs/JOIN_TESTNET_TROUBLESHOOTING.md) |
| **Observer mode（同期のみ）** | [`distribution/public-node/README.md`](distribution/public-node/README.md) |
| **Seed node 設定（multi-seed + PK pinning）** | [`docs/ops/seed-configuration.md`](docs/ops/seed-configuration.md) |
| **Operator runbook** | [`docs/ops/VALIDATOR_RUNBOOK.md`](docs/ops/VALIDATOR_RUNBOOK.md) |
| **Upgrade 手順** | [`docs/ops/UPGRADE_PROCEDURE.md`](docs/ops/UPGRADE_PROCEDURE.md) |
| **Architecture overview** | [`docs/architecture.md`](docs/architecture.md) |
| **Consensus 設計** | [`docs/consensus/`](docs/consensus/) |
| **Design docs（機能別）** | [`docs/design/`](docs/design/) |
| **SLO / metrics** | [`docs/ops/SLO.md`](docs/ops/SLO.md) |
| **Release manifest** | [`docs/TESTNET_MANIFEST.json`](docs/TESTNET_MANIFEST.json) |

---

## 🏗️ Repository Layout

```
MISAKA-CORE/
├── crates/
│   ├── misaka-types/         # 共通型 (Transaction, Block, ChainContext, ...)
│   ├── misaka-crypto/        # SHA3 / Blake3 / keccak domain-separated helpers
│   ├── misaka-pqc/           # ML-DSA-65 + ML-KEM-768 wrappers
│   ├── misaka-muhash/        # MuHash3072 multiset accumulator (v5 以降 legacy)
│   ├── misaka-smt/           # Sparse Merkle Tree (v1.0 state commitment)
│   ├── misaka-storage/       # UtxoSet + RocksDB + WAL + snapshot
│   ├── misaka-mempool/       # 2-tier mempool (Narwhal cert lane + legacy)
│   ├── misaka-consensus/     # Staking / slashing / uptime / pipeline processors
│   ├── misaka-dag/           # Narwhal/Bullshark DAG 本体 (core_engine, leader,
│   │                         #   commit_finalizer, linearizer, ...)
│   ├── misaka-p2p/           # Narwhal block relay + anemo transport
│   ├── misaka-rpc/           # HTTP API (health, chain_info, submit_tx, ...)
│   ├── misaka-node/          # binary entrypoint + runtime glue
│   ├── misaka-cli/           # keygen, migrate, snapshot 等の CLI サブコマンド
│   ├── misaka-config/        # NodeConfig + TOML / JSON loader
│   └── ...（その他 misaka-mev, misaka-indexes, misaka-genesis-builder 等）
├── distribution/
│   ├── public-node/          # Observer-mode end-user package
│   └── testnet-validator/    # Validator config + systemd + logrotate テンプレート
├── docs/
│   ├── JOIN_TESTNET.md                    # 参加者向け primary guide (v0.9.0)
│   ├── JOIN_TESTNET_TROUBLESHOOTING.md    # エラー対処集
│   ├── TESTNET_MANIFEST.json              # 現在の testnet 諸元
│   ├── architecture.md / consensus/ / design/
│   ├── ops/ (VALIDATOR_RUNBOOK, UPGRADE_PROCEDURE, SLO, ...)
│   └── issues/ (既知問題のトラッキング)
├── scripts/
│   ├── start-node.sh / start-testnet.sh           # Dev smoke launcher
│   ├── testnet-join.sh                             # Self-host validator join helper
│   ├── test_cold_reset.sh                          # 4-node cold-reset harness
│   └── dag_*.sh / recovery_*.sh                    # 多数の rehearsal / soak harness
├── Cargo.toml                # Workspace manifest (version 0.9.0)
├── LICENSE                   # Apache-2.0
├── NOTICE                    # 第三者コンポーネント帰属
└── README.md                 # (this file)
```

---

## 🚀 Quick Start

### 1. 依存パッケージ (Ubuntu 22.04+)

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev clang libclang-dev cmake curl git

# Rust toolchain (1.75+)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

### 2. Clone + build

```bash
git clone https://github.com/MISAKA-BTC/MISAKA-CORE.git
cd MISAKA-CORE
cargo build --release -p misaka-node --features "dag,testnet"
```

成果物: `target/release/misaka-node`（約 16 MiB）

### 3. Single-node local smoke

```bash
bash scripts/start-node.sh
```

`misaka-data/validator.key` と local single-node genesis が自動生成され、
`http://127.0.0.1:3000` で RPC が立ち上がります。

```bash
curl -s http://127.0.0.1:3000/api/health | jq .
curl -s http://127.0.0.1:3000/api/get_chain_info | jq .
```

### 4. Local validator cluster rehearsal

```bash
MISAKA_TESTNET_VALIDATORS=3 bash scripts/start-testnet.sh
```

3 validator keys + shared genesis が作られ、`127.0.0.1:3000-3002` / `16110-16112` で 3 node 起動。

### 5. Public testnet に validator として参加

[`docs/JOIN_TESTNET.md`](docs/JOIN_TESTNET.md) に従ってください（12 節の完全ガイド）。

---

## 🧪 Development

### Test

```bash
# Workspace 全体
cargo test --workspace --features "testnet,dag,json-store-dev"

# 個別 crate
cargo test -p misaka-dag --lib
cargo test -p misaka-storage --lib
cargo test -p misaka-node --bin misaka-node
```

既知の flaky test は [`docs/issues/`](docs/issues/) に記録しています。

### Clippy + fmt

```bash
cargo clippy --workspace --all-targets --features "testnet,dag,json-store-dev"
cargo fmt --all -- --check
```

CI でも同じコマンドが走ります（`.github/workflows/ci.yml`）。

### Strict RUSTFLAGS（CI と同じ）

```bash
RUSTFLAGS="-D warnings -A unused_imports -A unused_variables -A dead_code -A unused_must_use -A unused_mut" \
  cargo check --all-targets --features "testnet,dag,json-store-dev"
```

---

## 🔐 Security Properties

### Cryptographic primitives

| 層 | 方式 | 備考 |
|---|---|---|
| Signature (consensus + tx) | **ML-DSA-65** (FIPS 204 / Dilithium3) | Post-quantum、1952B pk / 3309B sig |
| P2P key exchange | **ML-KEM-768** (FIPS 203) | Hybrid ChaCha20-Poly1305 AEAD |
| Keystore KDF | **Argon2id** | Default 64 MiB / 3 iter / 4 thread |
| Keystore AEAD | **ChaCha20-Poly1305** | File-level encryption |
| State commitment | **Sparse Merkle Tree** (`MISAKA:state_root:v5:`) | O(log N) proof、v0.9.0 で MuHash3072 から置換 |
| Block / commit digest | **Blake3** (domain-separated) | `MISAKA:narwhal:block:v2:` 等 |
| Hash domains | SHA3-256 / Blake3 with explicit prefix | `sha3_domain(domain, data)` / `blake3_domain(domain, data)` |

### Chain-level safeguards

- **Safe-mode halt** — `state_root` mismatch 検知時に process 全体を halt。
  `/api/health.safeMode` に surface。手動 restart 必須
- **Self-equivocation slashing** — 同じ round で複数 block に署名 → 5-10% slashing 自動適用
- **Downtime slashing** — epoch 中 0 proposal → 1% Minor slash
- **Peer quarantine** — invalid sig / equivocation 検知で peer を round window 内で隔離
- **Max suspended per author** = 256（replay DoS 耐性）
- **Peer replay window** = 100 round（cache replay bound、v0.8.8.1 hotfix）

### Production deployment notes

- RPC (3001) は **loopback (127.0.0.1) のみ**。reverse proxy + Bearer auth + IP allowlist なしの外部公開は禁止
- 秘密鍵は Argon2id + ChaCha20-Poly1305 で暗号化 keystore 必須 (`require_encrypted_keystore = true`)
- 1 validator key = 1 node を厳守。同じ key で複数 node 起動 → self-equivocation → 即 slash

---

## 📦 Versioning & Releases

- **Semantic versioning**（`MAJOR.MINOR.PATCH`）
- **Consensus-breaking** = MINOR bump（v0.8.x → v0.9.0）
- **Wire-format-breaking** = MAJOR bump（v0.9.x → v1.0）予定の activation hard fork
- Workspace level のバージョンは `Cargo.toml` の `[workspace.package].version`

### Release artifacts

- **Source** — this repo（tag: `v0.9.0`、`v0.9.1`、…）
- **Pre-built binaries** — GitHub Releases の `v*` tag（Linux x86_64 / macOS arm64 / Windows x86_64）
  - SHA-256 + Sigstore cosign keyless 署名付き（検証手順は
    [`distribution/public-node/README.md`](distribution/public-node/README.md)）

---

## 🤝 Contributing

1. Issue を先に開いて scope を合意
2. Fork → feature branch
3. `cargo fmt --all` + `cargo clippy --workspace --all-targets` が clean
4. Tests 追加（regression は必ず）
5. PR template に従う
6. Contribution は自動的に **Apache-2.0** ライセンスで submit されます（LICENSE §5）

### Commit message

Conventional Commits style 準拠：

- `feat(<scope>): ...`
- `fix(<scope>): ...`
- `chore(<scope>): ...`
- `docs(<scope>): ...`
- `refactor(<scope>): ...`
- `test(<scope>): ...`

`<scope>` は crate 名、phase 名、または `ci` / `build` 等。

---

## 📜 License

- **Code**: [Apache License 2.0](LICENSE)
- **Documentation**: Apache License 2.0（同じく）
- **Third-party**: 個別ライセンス（[NOTICE](NOTICE) 参照）

`Copyright 2026 MISAKA Foundation`

---

## 🔗 Links

- **GitHub**: https://github.com/MISAKA-BTC/MISAKA-CORE
- **Releases**: https://github.com/MISAKA-BTC/MISAKA-CORE/releases
- **Issues**: https://github.com/MISAKA-BTC/MISAKA-CORE/issues
- **Observer launcher**（別 repo）: https://github.com/sasakiyuuu/misaka-test-net

---

_最終更新：2026-04-19（v0.9.0 base）_
