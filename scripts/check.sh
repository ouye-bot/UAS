#!/usr/bin/env bash
# 飞证聚合门禁（本地权威 CI）。exit 0=绿。
# 分层：backend（ruff+pytest）/ zksvc（cargo test）/ gcs-web（tsc+vitest）/ 文档一致性/链烟测/浏览器级 UI 回归。
set -euo pipefail
UAS="$(cd "$(dirname "$0")/.." && pwd)"
cd "$UAS"

echo "== [1/6] backend：ruff + pytest =="
cd backend
./.venv/Scripts/python.exe -m ruff check app tests
./.venv/Scripts/python.exe -m ruff format --check app tests
./.venv/Scripts/python.exe -m pytest -q -m "not slow"
# bridge 产品面单测（阶段二：纳入门禁——此前游离在外）
./.venv/Scripts/python.exe -m pytest -q ../gcs/bridge/test_bridge_core.py
cd "$UAS"

echo "== [2/6] zksvc：cargo test =="
cd zksvc
cargo test --quiet 2>&1 | grep -E "^test result" 
cd "$UAS"

echo "== [3/6] gcs/web：vue-tsc + vitest + vite build =="
cd gcs/web
npm run typecheck --silent
npm test --silent
npm run build --silent
cd "$UAS"

echo "== [4/6] 文档一致性 =="
python scripts/doc_consistency_check.py

echo "== [5/6] 链烟测（FISCO BCOS 国密四节点） =="
cd backend
./.venv/Scripts/python.exe scripts/chain_smoke.py
cd "$UAS"

echo "== [6/6] 浏览器级 UI 回归（Playwright——终结「API 绿但 UI 坏」事故族） =="
cd backend
./.venv/Scripts/python.exe scripts/e2e_browser_ui.py
cd "$UAS"
echo "== check.sh 全绿 exit 0 =="
