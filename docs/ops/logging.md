# MISAKA logging — ops notes

## Baseline (v0.8.8)

- `~91 MB/day/node` raw `node.log` output
- Dominated by `peer_sig_verify_failed` + `block_received` at WARN level
- No rotation, no compression → files grew without bound and had to be
  force-truncated to reclaim disk

## v0.8.9 / BLOCKER M / Phase 1

Two independent fixes, both optional, both low risk:

### 1. Tighten `RUST_LOG`

New default in `deploy/systemd/misaka-node.service.example`:

```
RUST_LOG=misaka=info,narwhal=warn,mysticeti=info,tower=warn,h2=warn,hyper=warn,rocksdb=warn
```

- `misaka=info` keeps validator-lifecycle, staking, execution logs
- `narwhal=warn` drops the repetitive verify-fail / block-received noise
- `mysticeti=info` keeps commit-cycle + propose_block visibility
- `tower,h2,hyper=warn` silences the chatty HTTP/2 middleware
- `rocksdb=warn` keeps BlobDB GC + compaction errors but not info spam

Target: **<10 MB/day raw, <1 MB/day compressed**.

### 2. logrotate

`deploy/logrotate/misaka-node`:

- daily rotate, 7 days retention
- `maxsize 500M` — emergency rotate if something spams to catastrophe
- `zstd -19 -T0` compression of rotated segments
  (final compressed size ~1–2% of raw; zstd is worth the CPU)
- `copytruncate` so the running `misaka-node` process keeps its fd open

## Install

```bash
sudo cp deploy/logrotate/misaka-node /etc/logrotate.d/misaka
sudo chmod 644 /etc/logrotate.d/misaka
sudo logrotate -d /etc/logrotate.d/misaka        # dry-run
sudo logrotate -f /etc/logrotate.d/misaka        # force initial rotation
```

Apply `RUST_LOG` tuning by editing the systemd unit:

```bash
# Drop the example into place (edit paths first!)
sudo cp deploy/systemd/misaka-node.service.example /etc/systemd/system/misaka-node.service
sudo systemctl daemon-reload
sudo systemctl restart misaka-node
```

For nodes not managed by systemd (e.g. the testnet cluster that runs
from a plain `nohup bash /tmp/startNN.sh` script), edit the start
script to `export RUST_LOG=misaka=info,narwhal=warn,...` before the
`exec misaka-node …` line.

## Verifying

```bash
# 1 hour after the change, check the growth rate:
du -h /home/ubuntu/node.log
du -h /tmp/cluster-4/node27.log

# Target: < 1 MB per hour.
```

If the raw log is still > 1 MB/hour after the change, identify the
noisy module with:

```bash
awk '/^[0-9]{4}-[0-9]{2}-[0-9]{2}/ { if (match($0, /\[([a-z_]+)\]/, m)) print m[1] }' \
    /home/ubuntu/node.log \
    | sort | uniq -c | sort -rn | head -20
```

Add the top offender at `warn` level to `RUST_LOG` and restart.

## Future work

- **v0.9.x (Phase 2)**: structured JSON logging hook, metrics extraction
  from logs deprecated in favour of Prometheus
- **v0.10.x (Phase 3)**: per-epoch log-retention policy tied to
  archival/pruned mode (pruned nodes retain 7 days, archival nodes
  retain indefinitely under operator control)
