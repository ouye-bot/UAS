# 本机部署路径（.local_env 不入库——模板见 .local_env.example）。
# 双候选：仓内形态（gcs/bridge/ 的上级）与 ASCII 复制形态（同目录——demo_up
# 把本脚本与 .local_env 一并复制到无中文目录执行）。
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_l="$_d/.local_env"
[ -f "$_l" ] || _l="$_d/../.local_env"
[ -f "$_l" ] && . "$_l"
UAS_WSL="${FZ_UAS_WSL:-/mnt/c/uas}"
#!/bin/bash
# 飞证 GCS 桥启动（WSL SITL 档）——demo_up 将本脚本复制到 ASCII 路径执行。
# 背景：wsl.exe 经 Windows subprocess 传中文路径乱码；junction 路径又被
# wslpath -w 的 realpath 双形态破坏（已存在文件解析回 C 盘真身、不存在目录
# 保持 D 盘映射——spec/out 分属两盘被装配器 fail-closed 拦截 [实测]）。
# 故本脚本自持真实 C 盘路径，由「模板入仓+复制到 ASCII 路径执行」绕开传参。
# 尾部必须后台化（nohup ... & + 立即退出）——demo_up 的 subprocess.run 等
# 本脚本返回，前台化会让启动器等满超时崩溃 [实测]。
set -e
UAS=${UAS_WSL}
cd "$UAS/backend"
ENGINE_SK=$(sed 's/SK=//' "${FZ_TMP_WSL:-/mnt/c/Users/Public/AppData/Local/Temp}/fz_engine_sk.txt")
TOKEN=$(sed 's/TOKEN=//' "${FZ_TMP_WSL:-/mnt/c/Users/Public/AppData/Local/Temp}/fz_engine_token.txt")
pkill -f 'uvicorn server:app' 2>/dev/null || true
sleep 1
export PYTHONPATH="$UAS/backend:$UAS/gcs/bridge"
export FZ_API_BASE=http://127.0.0.1:8000 FZ_ENGINE_PUB_PROXY=1
export FZ_ZKSVC_DIR="$UAS/zksvc" FZ_ZK_CASES_DIR="$UAS/backend/fz-zk-cases"
export FZ_ENGINE_SK="$ENGINE_SK" FZ_ENGINE_TOKEN="$TOKEN"
export FZ_GCS_LINK=sitl FZ_SITL_CONN=tcp:127.0.0.1:5760
# systemd 瞬态单元形态：前台执行（exec）——unit 存活期间飞控桥常驻，
# 不受 wsl 会话清理影响（与 fz-sitl 同款守护形态）。
exec python3 -m uvicorn server:app --host 127.0.0.1 --port 8100
