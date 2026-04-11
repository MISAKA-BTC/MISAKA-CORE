# MISAKA Network — Public Testnet Quickstart

> この文書は **source checkout 上の local smoke / local rehearsal** を素早く回すための quickstart です。
> `v0.5.13` の current public start line の正本ではありません。
> public observer package は `distribution/public-node/README.md`、
> operator の current truth は `local-start-docs-v0513/07_operator_startup_runbook_v0513.ja.md` を参照してください。
> まず testnet を開始する line は public observer package、次に source checkout smoke、最後に local rehearsal の順で分けて読んでください。

## Requirements

- Ubuntu 22.04+ / macOS 13+
- 2 GB RAM, 20 GB disk
- Rust 1.75+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- OpenSSL / native build deps: `sudo apt install build-essential pkg-config libssl-dev clang libclang-dev cmake`

## 1. Choose the Right Entrypoint

| Intent | Current entrypoint | Default RPC | Default relay |
|------|-------|------|------|
| Public observer on the official/public testnet | `distribution/public-node/README.md` and `start-public-node.*` | `3001` | `16110` |
| Source checkout single node / local smoke | `bash scripts/start-node.sh` | `3000` | `16110` |
| Local validator cluster / rehearsal | `bash scripts/start-testnet.sh` | `3000+` | `16110+` |
| Isolated Phase C committee rehearsal | `bash scripts/start-phase-c-committee-rehearsal.sh` | `3000+` | `16110+` |
| Self-host validator join | `bash scripts/testnet-join.sh --genesis-path ... --index ...` | `3001` | `16110` |

`bash scripts/start-node.sh` は generic source-build launcher です。official/public observer の front door にはしません。

## 2. Public Observer Package

public observer の current baseline は [distribution/public-node/README.md](/misaka-test-net-v0513/misaka-core-v4/distribution/public-node/README.md) です。
ここでは stock release asset を展開して `start-public-node.*` を起動し、`role:"observer"` と `topology:"joined"` を確認します。

確認の入口は次の 2 つだけです。

```bash
curl -s http://127.0.0.1:3001/api/health | jq .
curl -s http://127.0.0.1:3001/api/get_chain_info | jq .
```

`/api/health` が `ok`、`peerCount` が `1`、`commitsTotal` が増加していれば public observer baseline は成立しています。

## 3. Source Checkout Quick Start (Single Node)

```bash
cd MISAKA-CORE
bash scripts/start-node.sh
```

初回実行時に `misaka-data/validator.key` と local single-node genesis が自動生成されます。
source checkout 上の smoke 用なので、public observer package の current start line とは別物です。
ノードは `http://127.0.0.1:3000` で起動します。

## 4. Local Validator Cluster / Rehearsal

```bash
MISAKA_TESTNET_VALIDATORS=3 bash scripts/start-testnet.sh
```

`MISAKA_TESTNET_VALIDATORS` を省略すると current default は `15` です。
`3` は explicit smoke 例です。`15` は local rehearsal の current baseline です。
上の例では 3 validator keys と shared genesis が作られ、localhost 上で 3 ノードが起動します
(`RPC: 3000-3002`, `P2P: 16110-16112`)。

重要:

- `bash scripts/start-testnet.sh` は current stock runtime (`validatorBreadth / stock Narwhal`) の local rehearsal です
- Phase C の committee runtime はこれと別線で、`bash scripts/start-phase-c-committee-rehearsal.sh` を使います
- `ghostdag-compat` build を `start-testnet.sh` / `start-node.sh` に直接混ぜる場合も、`MISAKA_PHASE_C_REHEARSAL=1` の explicit opt-in が必要です

## 5. Verify the Node Surface

```bash
curl -s http://127.0.0.1:3000/api/health | jq .
# -> {"status":"ok","consensus":"mysticeti-equivalent","blocks":N,"round":N,"safeMode":{"halted":false}}

curl -s http://127.0.0.1:3000/api/get_chain_info | jq .
# -> {"chainId":2,"consensus":"Mysticeti-equivalent","nodeMode":"public","role":"validator",...}

curl -s http://127.0.0.1:3000/api/get_peers | jq .
```

`/api/health` と `/api/get_chain_info` が current truth です。
old docs の `:16112/health` ではなく、RPC 側の `/api/health` を見てください。

## 6. Role Separation

- **Public observer**: official/public testnet への入口は `distribution/public-node/start-public-node.*` です。runtime 上は `role:"observer"` を返し、ブロック受信と検証のみを行います。
- **Operator / genesis validator**: `scripts/testnet-deploy.sh --ip <public-ip>` を使います。公開 relay port は `16110/tcp`、RPC は原則 `127.0.0.1:3001` のまま扱います。
- **Self-host validator**: `scripts/testnet-join.sh --genesis-path ... --index ...` を使います。operator から共有された `genesis_committee.toml` が必要です。
- `mode` は露出面 (`public` / `hidden` / `seed`) を表し、`role` は validator か observer かを表します。`public` mode でも、手元の鍵が genesis committee に入っていなければ `role:"observer"` です。

## 7. Current Notes

- 新しいアドレス例は `misaka1...` を使ってください。`/api/testnet_info` に残る `misakatest1` は legacy surface です。
- `/api/submit_tx` は current runtime では完全な `UtxoTransaction` JSON を期待します。old docs にある最小 JSON の例は stale です。
- `scripts/start-node.sh` は local dev 用に `MISAKA_RPC_AUTH_MODE=open` を使います。loopback のまま使うか、外へ出すなら reverse proxy + auth を前段で付けてください。
- public observer/operator の relay は `16110` が current convention です。`6690` は一部の legacy/bootstrap config にだけ残ります。

## 8. Configuration

Environment variables:
```
MISAKA_RPC_PORT=3000
MISAKA_P2P_PORT=16110
MISAKA_DATA_DIR=./misaka-data
MISAKA_VALIDATORS=1
MISAKA_VALIDATOR_INDEX=0
MISAKA_CHAIN_ID=2
MISAKA_GENESIS_PATH=./misaka-data/genesis_committee.toml
```

## 9. Troubleshooting

- **Port already in use**: `sudo lsof -i :3000` then `kill -9 <PID>`
- **Public observer cannot join**: Check `16110/tcp` reachability and verify seed / seed-pubkeys are from the same package
- **Build fails**: `sudo apt install pkg-config libssl-dev build-essential clang cmake`
- **Build fails with `stdbool.h`**: `export BINDGEN_EXTRA_CLANG_ARGS="-isystem $(gcc -print-file-name=include)"`
- **Node stops on SSH disconnect**: Use `nohup` or `tmux`
- **Genesis error**: Delete `misaka-data/` and re-run — the script regenerates keys and genesis
