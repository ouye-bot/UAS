#!/usr/bin/env bash
# 飞证环境拉起（链探活/venv 就绪/WSL 互操作自愈三段）。
# 幂等：重复执行无副作用。判决行：每段 OK/FAIL 打印；任一 FAIL=exit 1。
set -uo pipefail
UAS="$(cd "$(dirname "$0")/.." && pwd)"

echo "== [1/3] FISCO BCOS 国密链（WSL 四节点） =="
wsl -u root bash -c "cd /home/ouye/fisco-bcos-node/nodes_sm/127.0.0.1 && bash start_all.sh" || echo "  （start_all 非零返回：可能已在跑，以探活为准）"
sleep 2
BLOCK=$(wsl -u root bash -c "curl -s -X POST http://127.0.0.1:8545 -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"method\":\"getBlockNumber\",\"params\":[1],\"id\":1}'" | grep -o '"result":"0x[0-9a-f]*"' || true)
if [ -n "$BLOCK" ]; then
  echo "  OK 链探活：$BLOCK"
else
  echo "  FAIL 链不可达（检查 WSL start_all）"
  exit 1
fi

echo "== [2/3] backend venv 依赖就绪 =="
if "$UAS/backend/.venv/Scripts/python.exe" -c "import gmssl, fastapi" 2>/dev/null; then
  echo "  OK venv 依赖在位"
else
  echo "  FAIL venv 缺依赖（重装：backend/.venv/Scripts/python.exe -m pip install -e 'backend[dev]'）"
  exit 1
fi

echo "== [3/3] WSL 互操作自愈（桥接 interop 调 Windows zkc.exe 依赖） =="
if wsl -u root bash -c "test -e /proc/sys/fs/binfmt_misc/WSLInterop"; then
  echo "  OK WSLInterop 在位"
else
  wsl -u root bash -c "echo ':WSLInterop:M::MZ::/init:PF' > /proc/sys/fs/binfmt_misc/register"
  if wsl bash -c "/mnt/c/Windows/System32/cmd.exe /c 'echo ok' 2>/dev/null" | grep -q ok; then
    echo "  OK WSLInterop 已重注册（binfmt 曾丢失——Exec format error 免疫）"
  else
    echo "  FAIL 互操作仍不可用（wsl --shutdown 后重走 up.sh）"
    exit 1
  fi
fi
echo "== up.sh 三段全绿 =="
