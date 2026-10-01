# 本机部署路径（.local_env 不入库——模板见 .local_env.example）
_l="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.local_env"
[ -f "$_l" ] && . "$_l"
UAS_WSL="${FZ_UAS_WSL:-/mnt/c/uas}"
#!/usr/bin/env bash
# FISCO 链节点拉起（幂等）：清硬关机残留的 RocksDB LOCK → 四节点启动 → 健康核验。
# 背景（2026-09-30）：宿主重启后 WSL 硬杀，block RocksDB 残留 LOCK 文件使四节点
# 全部 init 即 terminate（terminate handler called）——拔 LOCK 即愈。
# 在 WSL 内执行：bash ${UAS_WSL}/scripts/chain_nodes_up.sh
set -x
d0=/home/ouye/fisco-bcos-node/nodes_sm/127.0.0.1
systemctl stop fz-sitl fz-relay 2>/dev/null
for n in 0 1 2 3; do
  find "$d0/node$n/data" -name LOCK -delete 2>/dev/null
done
pkill -x fisco-bcos 2>/dev/null
sleep 2
for n in 0 1 2 3; do
  (cd "$d0/node$n" && nohup bash start.sh > /dev/null 2>&1 &)
done
sleep 10
echo "nodes_running=$(ps aux | grep fisco-bcos | grep -v grep | wc -l)"
for p in 8545 8546 8547 8548; do
  echo -n "$p:"
  curl -s -m 4 -X POST -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","method":"getBlockNumber","params":[1],"id":1}' \
    "http://127.0.0.1:$p" | head -c 60
  echo
done
echo SCRIPT_DONE
