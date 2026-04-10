#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
#  MISAKA — ネットワーク診断 & ポート開放ガイド
# ═══════════════════════════════════════════════════════════
set -euo pipefail

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  MISAKA Network — ネットワーク診断                       ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

echo "── LAN 情報 ─────────────────────────────────────────────"
if command -v ip &>/dev/null; then
    LOCAL_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || echo "unknown")
elif command -v ifconfig &>/dev/null; then
    LOCAL_IP=$(ifconfig 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | head -1 | awk '{print $2}' | sed 's/addr://')
else
    LOCAL_IP="unknown"
fi
echo "  LAN IP         : $LOCAL_IP"

EXTERNAL_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "取得失敗")
echo "  External IP    : $EXTERNAL_IP"
echo ""

echo "── 必要なポート ──────────────────────────────────────────"
echo ""
echo "  ┌─────────────────────────────────────────────────────┐"
echo "  │ ロール       │ ポート   │ プロトコル │ 必須?       │"
echo "  ├─────────────────────────────────────────────────────┤"
echo "  │ Public Node  │ TCP 6691 │ P2P        │ 推奨        │"
echo "  │ Seed Node    │ TCP 6690 │ P2P        │ 必須        │"
echo "  │ Validator    │ TCP 6690 │ P2P        │ 必須        │"
echo "  │ RPC API      │ TCP 3001 │ HTTP       │ 任意        │"
echo "  └─────────────────────────────────────────────────────┘"
echo ""
echo "  * 参加するだけならポート開放は不要です (outbound のみ)"
echo "  * 他ノードから見える public node にしたい場合は TCP 6691"
echo "  * seed を配る場合は TCP 6690"
echo ""

echo "── ポートチェック ────────────────────────────────────────"
for port in 6690 6691 3001; do
    if command -v nc &>/dev/null; then
        if nc -z 127.0.0.1 $port 2>/dev/null; then
            echo "  Port $port: OPEN (ローカルでリッスン中)"
        else
            echo "  Port $port: CLOSED"
        fi
    elif command -v ss &>/dev/null; then
        if ss -tln | grep -q ":$port "; then
            echo "  Port $port: OPEN (ローカルでリッスン中)"
        else
            echo "  Port $port: CLOSED"
        fi
    else
        echo "  Port $port: (チェックツールなし)"
    fi
done
echo ""

echo "── Router 設定について ──────────────────────────────────"
echo ""
echo "  ポートフォワーディングの設定方法はルーターの機種により異なります。"
echo "  一般的な手順:"
echo "    1. ブラウザで http://192.168.1.1 or http://192.168.0.1 を開く"
echo "    2. 「ポートフォワーディング」「仮想サーバー」を探す"
echo "    3. 外部ポート 6690 → LAN IP $LOCAL_IP : 6690 (TCP) を追加"
echo ""
