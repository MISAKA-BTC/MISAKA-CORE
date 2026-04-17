#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────
#  register_validator_example.sh
#
#  Observer ノードをバリデータとして登録するサンプルスクリプト。
#  使い方:
#    bash scripts/register_validator_example.sh <PUBLIC_KEY_HEX> <IP:PORT>
#
#  例:
#    bash scripts/register_validator_example.sh \
#      0xabcdef0123456789...  \
#      203.0.113.10:16110
# ─────────────────────────────────────────────────────────
set -euo pipefail

SEED_URL="${MISAKA_SEED_URL:-https://misakascan.com}"

if [ $# -lt 2 ]; then
  echo "Usage: $0 <PUBLIC_KEY_HEX> <NETWORK_ADDRESS>"
  echo ""
  echo "  PUBLIC_KEY_HEX   0x-prefixed hex of the node's public key (2592 bytes = 5184 hex chars + 0x)"
  echo "  NETWORK_ADDRESS  IP:PORT that other validators can reach (e.g. 203.0.113.10:16110)"
  echo ""
  echo "Environment:"
  echo "  MISAKA_SEED_URL  Seed node base URL (default: $SEED_URL)"
  exit 1
fi

PUBLIC_KEY="$1"
NETWORK_ADDRESS="$2"

echo "=== Registering validator ==="
echo "  Seed:    $SEED_URL"
echo "  PK:      ${PUBLIC_KEY:0:20}...${PUBLIC_KEY: -8}"
echo "  Addr:    $NETWORK_ADDRESS"
echo ""

RESPONSE=$(curl -sf -X POST "${SEED_URL}/api/register_validator" \
  -H "Content-Type: application/json" \
  -d "{\"public_key\":\"${PUBLIC_KEY}\",\"network_address\":\"${NETWORK_ADDRESS}\"}")

echo "Response: $RESPONSE"
echo ""

STATUS=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || true)

if [ "$STATUS" = "ok" ]; then
  echo "Registration successful."
  echo ""
  echo "=== Current committee ==="
  curl -sf "${SEED_URL}/api/get_committee" | python3 -m json.tool 2>/dev/null || \
    curl -sf "${SEED_URL}/api/get_committee"
else
  echo "Registration may have failed. Check the response above."
  exit 1
fi
