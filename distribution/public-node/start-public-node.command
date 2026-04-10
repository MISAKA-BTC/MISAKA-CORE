#!/usr/bin/env bash
# macOS: Finder でダブルクリックすると新しい Terminal で実行されます。
# 内部では start-public-node.sh を呼び出しているだけです。
cd "$(dirname "$0")"
exec bash ./start-public-node.sh
