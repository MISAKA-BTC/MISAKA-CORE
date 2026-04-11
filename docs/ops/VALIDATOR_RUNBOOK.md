# バリデータ運用マニュアル

> この文書は validator 運用の長期 runbook で、`v0.5.13` の public testnet 開始ラインの正本ではありません。
> current の入口と運用真値は `distribution/public-node/README.md` と
> `local-start-docs-v0513/07_operator_startup_runbook_v0513.ja.md` を優先してください。
> public observer package の運用はこの runbook の対象外です。observer baseline は package の README を見てください。

## 前提

- OS: Ubuntu 22.04+ / macOS 14+
- Rust: 1.78+
- ディスク: SSD 100GB+
- メモリ: 8GB+
- ネットワーク: 公開IP (Active バリデータ)、NAT/outbound-only (Backup)

## 役割と入口

| 役割 | Current entrypoint | Relay / RPC |
|------|--------------------|-------------|
| Public observer | `distribution/public-node/start-public-node.*` | `16110` / `3001` |
| 公式 operator / genesis validator | `scripts/testnet-deploy.sh --ip <public-ip>` | `16110` / `3001` |
| 既存 operator へ self-host validator join | `scripts/testnet-join.sh --genesis-path ... --index ...` | `16110` / `3001` |
| private / custom topology / source-build local rehearsal | `scripts/start-node.sh` | `16110` / `3000` |

この runbook は validator/operator 側を対象にします。public observer の入口は `distribution/public-node` です。

## Genesis Operator Quick Start

```bash
export MISAKA_VALIDATOR_PASSPHRASE='change-me'
bash scripts/testnet-deploy.sh --ip YOUR_PUBLIC_IP --name misaka-testnet-sr0
```

この経路では次が current default です。

- service manager: `systemd` (`misaka-node.service`)
- relay port: `16110/tcp`
- RPC: `127.0.0.1:3001`
- observers: `MISAKA_ACCEPT_OBSERVERS=1`

確認:

```bash
sudo systemctl status misaka-node --no-pager
curl -s http://127.0.0.1:3001/api/health | jq .
curl -s http://127.0.0.1:3001/api/get_chain_info | jq '{role, topology, peerCount, metrics, status}'
sudo journalctl -u misaka-node -f
```

## Self-host Validator Join

```bash
export MISAKA_VALIDATOR_PASSPHRASE='change-me'
bash scripts/testnet-join.sh \
  --genesis-path /path/to/genesis_committee.toml \
  --index 1 \
  --advertise-addr YOUR_PUBLIC_IP:16110
```

前提:

- operator から共有された `genesis_committee.toml`
- seed address と seed pubkeys
- `16110/tcp` の到達性
- 長期運用するなら foreground ではなく `systemd` で包む

## Current Role Separation

- `--mode public|hidden|seed` は公開面を決めます。
- `--validator` は提案・投票側として起動するかを決めます。
- local の transport identity が genesis committee に入っていない場合、runtime は `role:"observer"` で動きます。public mode でも validator にはなりません。
- public seed / operator が observer を受け入れる場合は `MISAKA_ACCEPT_OBSERVERS=1` を付けます。
- `scripts/start-node.sh` は generic source-build launcher であり、public observer package の置き換えではありません。

## Config and Key Notes

- current CLI では `validator.key` は data dir 配下に置かれ、`--emit-validator-pubkey` や初回起動時に自動生成されます。
- old docs にあった `misaka-node keygen --output ...` や `--key-dir` は current public testnet runbook の surface ではありません。
- `--config` による file load 自体は残っており、TOML と legacy JSON の両方を読めます。ただし public testnet の current truth は `testnet-deploy.sh` / `testnet-join.sh` です。
- validator passphrase は `MISAKA_VALIDATOR_PASSPHRASE` か `MISAKA_VALIDATOR_PASSPHRASE_FILE` を使います。
- RPC は原則 `127.0.0.1:3001` に閉じたまま扱い、公開が必要なら reverse proxy + auth を前段で付けます。

## 監視

```bash
curl -s http://127.0.0.1:3001/api/health | jq .
curl -s http://127.0.0.1:3001/api/get_chain_info | jq '{role, topology, peerCount, metrics, status}'
curl -s http://127.0.0.1:3001/api/metrics | egrep 'misaka_consensus_(current_round|commits_total|leaders_skipped_total|sync_failed_total|wal_errors_total)'
sudo journalctl -u misaka-node -f
```

## トラブルシューティング

| 症状 | 原因 | 対処 |
|------|------|------|
| `topology:"solo"` のまま | seed 到達不能、`16110/tcp` 不達、seed pubkeys mismatch | firewall、`--advertise-addr`、seed / seed-pubkeys、`MISAKA_ACCEPT_OBSERVERS` を確認 |
| `round not advancing` | ネットワーク分断 or leader timeout 連鎖 | `/api/health` と `/api/metrics` で round / commits / sync failures を確認 |
| `equivocation detected` | Byzantine ノード | `EquivocationProof` と `misaka_consensus_equivocations_total` の増加を保全し escalation |
| `wal_errors_total` 増加 | disk / fs / permission 問題 | journal、空き容量、所有権、再起動可否を確認 |
| `StubDisabledInProduction` | StubProofBackend が起動 | release build で `dev-stub-proof` feature を外す |
