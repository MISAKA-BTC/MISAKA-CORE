# MISAKA Docker

Node と Explorer を Docker Compose で独立管理。

## 構成

```
docker/
├── node/                    # MISAKA Node (Rust)
│   ├── Dockerfile           # Multi-stage Rust build
│   ├── docker-compose.yml   # seed / public / validator profiles
│   ├── .env.example
│   └── .env
└── explorer/                # MISAKA Explorer (Next.js)
    ├── Dockerfile           # Multi-stage Node.js build
    ├── docker-compose.yml   # explorer + optional nginx
    ├── nginx.conf           # HTTPS termination example
    ├── .env.example
    └── .env
```

## セットアップ

```bash
tar xzf misaka-docker.tar.gz
bash setup_docker.sh
```

## Node

### Seed ノード

```bash
cd docker/node
# .env を編集
echo "ADVERTISE_ADDR=49.212.136.189:6690" > .env
docker compose up seed -d
docker compose logs -f seed
```

### Public ノード

```bash
cd docker/node
cat >> .env << EOF
PUBLIC_ADVERTISE_ADDR=133.167.126.51:6691
SEED_ADDR=49.212.136.189:6690
EOF
docker compose up public -d
```

### Validator ノード

```bash
cd docker/node
cat >> .env << EOF
VALIDATOR_ADVERTISE_ADDR=133.167.126.51:6692
VALIDATOR_INDEX=0
VALIDATOR_COUNT=1
BLOCK_TIME=60
EOF
docker compose up validator -d
```

### CLI (コンテナ内)

```bash
docker exec -it misaka-seed misaka-cli status
docker exec -it misaka-seed misaka-cli keygen --name alice
docker exec -it misaka-seed misaka-cli faucet msk1... --wallet alice.key.json
docker exec -it misaka-seed misaka-cli transfer --from alice.key.json --to msk1... --amount 1000
```

### ポートマッピング

| サービス | P2P | RPC |
|---------|-----|-----|
| seed | 6690 | 3001 |
| public | 6691 | 3002 |
| validator | 6692 | 3003 |

## Explorer

```bash
cd docker/explorer
echo "MISAKA_RPC_URL=http://host.docker.internal:3001" > .env
docker compose up -d --build
```

ブラウザで `http://localhost:3000` → Explorer 表示。

### 既存 nginx と連携

host の nginx がポート 3000 にプロキシ済みなら、docker compose で explorer だけ起動すれば OK。
`nginx.conf` は参考用。

## データ永続化

```bash
# Node データ確認
docker volume ls | grep misaka

# バックアップ
docker run --rm -v misaka-seed-data:/data -v $(pwd):/backup alpine tar czf /backup/seed-data.tar.gz -C /data .

# リストア
docker run --rm -v misaka-seed-data:/data -v $(pwd):/backup alpine sh -c "cd /data && tar xzf /backup/seed-data.tar.gz"
```

## 停止 / 削除

```bash
# 停止
cd docker/node && docker compose down
cd docker/explorer && docker compose down

# データも削除
cd docker/node && docker compose down -v
```
