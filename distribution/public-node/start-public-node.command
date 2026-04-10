#!/usr/bin/env bash
# macOS: ダブルクリックで起動
# Finder から .command を開くと新しい Terminal ウインドウで実行されます
cd "$(dirname "$0")"
exec bash ./start-public-node.sh
