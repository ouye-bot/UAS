#!/usr/bin/env bash
# 并发 2 档自动扫描（主会话重启窗口执行——先读 perf-concurrency2-manual.md）
set -euo pipefail
UAS="$(cd "$(dirname "$0")/../../.." && pwd)"
PY="$UAS/backend/.venv/Scripts/python.exe"
export FZ_PROVE_MAX_CONCURRENT=2
echo "[1/3] 注入 FZ_PROVE_MAX_CONCURRENT=2 重启三服务……"
python "$UAS/backend/scripts/sitl_e2e_services.py" down
python "$UAS/backend/scripts/sitl_e2e_services.py" up
echo "[2/3] 并发 2 档扫描（预热 1 + 实测 5 张）……"
cd "$UAS/backend" && "$PY" scripts/perf_suite.py --concurrency 1 --runs 5
echo "[3/3] 恢复缺省串行闸=1（无 env 重启）……"
unset FZ_PROVE_MAX_CONCURRENT
python "$UAS/backend/scripts/sitl_e2e_services.py" down
python "$UAS/backend/scripts/sitl_e2e_services.py" up
echo "== 并发 2 档扫描完成（报告见 backend/scripts/reports/）=="
