#!/usr/bin/env bash
# ============================================================
# make-release-zip.sh — MISAKA-CORE リリース ZIP 作成スクリプト
#
# 【使い方】
#   cd /path/to/misaka-core
#   bash scripts/make-release-zip.sh [output_name]
#
# 例:
#   bash scripts/make-release-zip.sh MISAKA-CORE-v9-hardened
#
# 【安全設計】
#   - git ls-files を使い .gitignore で追跡されている
#     ファイルだけを対象にする
#   - *.env / *.key / *.pem 等は .gitignore で除外済みなので
#     絶対に zip に入らない
#   - 手動 --exclude に頼らないため消しミスゼロ
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_NAME="${1:-MISAKA-CORE-release}"
OUTPUT_ZIP="${OUTPUT_NAME}.zip"

echo "[make-release-zip] repo: $REPO_ROOT"
echo "[make-release-zip] output: $OUTPUT_ZIP"

# git が使えるか確認
if ! command -v git &>/dev/null; then
  echo "ERROR: git not found. git ls-files が必要です。" >&2
  exit 1
fi

cd "$REPO_ROOT"

# git 管理下にあるか確認
if ! git rev-parse --git-dir &>/dev/null; then
  echo "ERROR: git リポジトリではありません: $REPO_ROOT" >&2
  echo "       git init 後に実行してください。" >&2
  exit 1
fi

# ── ZIP 作成 ────────────────────────────────────────────────
# git ls-files: .gitignore を完全に尊重して追跡ファイルのみ列挙
# --others --exclude-standard: untracked だが .gitignore で
#   明示的に許可されているファイルも含めたい場合は追加する
# 今回は tracked files のみで十分（secrets は never tracked）

echo "[make-release-zip] collecting tracked files..."
FILE_LIST=$(git ls-files)
FILE_COUNT=$(echo "$FILE_LIST" | wc -l)
echo "[make-release-zip] $FILE_COUNT files found"

# 万が一の安全チェック：危険なパターンが含まれていないか
DANGEROUS=$(echo "$FILE_LIST" | grep -iE "\.(env|key|pem|p12|pfx|secret|seed|mnemonic|priv)$" | grep -v "\.example$" || true)
if [[ -n "$DANGEROUS" ]]; then
  echo "" >&2
  echo "⚠️  WARNING: 以下の危険ファイルが git tracking されています！" >&2
  echo "$DANGEROUS" >&2
  echo "" >&2
  echo "   git rm --cached <file> で untrack してから再実行してください。" >&2
  exit 1
fi

# zip 作成（git archive を使う方法が最も確実）
echo "[make-release-zip] creating zip via git archive..."
git archive --format=zip --prefix="misaka-core/" HEAD -o "$OUTPUT_ZIP"

echo ""
echo "✅  Done: $OUTPUT_ZIP"
echo "   Size: $(du -h "$OUTPUT_ZIP" | cut -f1)"
echo "   Files: $(unzip -l "$OUTPUT_ZIP" | tail -1)"
echo ""
echo "⚠️  含まれていないファイル（正常）:"
echo "   - target/ (ビルド成果物)"
echo "   - *.env, *.key, *.pem (secrets)"
echo "   - .gitignore に記載された全パターン"
