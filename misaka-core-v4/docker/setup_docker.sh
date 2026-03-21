#!/bin/bash
# setup_docker.sh — Set up Docker environment for MISAKA
# Run from the project root (where misaka-net-core and misaka-explorer live)

set -e

echo "=== MISAKA Docker Setup ==="
echo ""

# 1. Create docker/ directory structure
mkdir -p docker/node docker/explorer

# 2. Copy Docker files
cp docker-dist/node/Dockerfile docker/node/
cp docker-dist/node/docker-compose.yml docker/node/
cp docker-dist/node/.env.example docker/node/.env.example
cp docker-dist/explorer/Dockerfile docker/explorer/
cp docker-dist/explorer/docker-compose.yml docker/explorer/
cp docker-dist/explorer/.env.example docker/explorer/.env.example
cp docker-dist/explorer/nginx.conf docker/explorer/

# 3. Create .dockerignore at project root (for node build context)
cat > .dockerignore << 'DIEOF'
target/
.git/
*.tar.gz
*.zip
node_modules/
misaka-explorer/
docker/
docs/
*.log
*.pid
*.session
data/
DIEOF

# 4. Create explorer .dockerignore
cat > misaka-explorer/.dockerignore << 'DIEOF'
node_modules/
.next/
*.tar.gz
*.zip
*.log
DIEOF

# 5. Patch explorer next.config.js for standalone output
NEXT_CONFIG="misaka-explorer/next.config.js"
if ! grep -q "standalone" "$NEXT_CONFIG" 2>/dev/null; then
    cat > "$NEXT_CONFIG" << 'NCEOF'
/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  output: 'standalone',
};
module.exports = nextConfig;
NCEOF
    echo "  next.config.js: patched with output: 'standalone'"
fi

# 6. Create .env files from examples if they don't exist
if [ ! -f docker/node/.env ]; then
    cp docker/node/.env.example docker/node/.env
    echo "  Created docker/node/.env (edit with your IPs)"
fi
if [ ! -f docker/explorer/.env ]; then
    cp docker/explorer/.env.example docker/explorer/.env
    echo "  Created docker/explorer/.env (edit with your RPC URL)"
fi

echo ""
echo "=== Setup complete ==="
echo ""
echo "Directory structure:"
echo "  docker/"
echo "  ├── node/"
echo "  │   ├── Dockerfile"
echo "  │   ├── docker-compose.yml"
echo "  │   ├── .env.example"
echo "  │   └── .env"
echo "  └── explorer/"
echo "      ├── Dockerfile"
echo "      ├── docker-compose.yml"
echo "      ├── nginx.conf"
echo "      ├── .env.example"
echo "      └── .env"
echo ""
echo "Usage:"
echo ""
echo "  # ─── Node ──────────────────────────────────"
echo "  cd docker/node"
echo "  # Edit .env with your public IP"
echo "  docker compose up seed -d              # Seed node"
echo "  docker compose up public -d            # Public node"
echo "  docker compose up validator -d         # Validator"
echo "  docker compose logs -f seed            # Watch logs"
echo ""
echo "  # ─── Explorer ──────────────────────────────"
echo "  cd docker/explorer"
echo "  # Edit .env with RPC URL"
echo "  docker compose up -d --build           # Build & start"
echo "  docker compose logs -f explorer        # Watch logs"
echo ""
echo "  # ─── CLI (from node container) ─────────────"
echo "  docker exec -it misaka-seed misaka-cli status"
echo "  docker exec -it misaka-seed misaka-cli keygen --name alice"
echo ""
