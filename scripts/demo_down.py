"""飞证演示环境停止（配合 demo_up.py）——W-11 新拓扑换代（2026-09-27）。

分层语义（与 demo_up.preclean 同纪律）：
- 演示栈（本脚本停）：backend(8000)/web(5174)/worker（按命令行，Name 过滤
  防普查自我指涉误杀）/WSL 桥单元 fz-bridge（systemctl stop 幂等）。
- 常驻基础设施（不动，仅提示）：WSL 链节点、fz-sitl2 飞控、fz_wsl_keepalive
  ——需要彻底下线时手动 `wsl -u root systemctl stop fz-sitl2`。
"""

from __future__ import annotations

import subprocess
import sys

PORTS = [8000, 5174]


def pids_on(port: int) -> list[str]:
    # 中文 Windows netstat 输出为 GBK——显式编码（UTF-8 严格解码会炸掉读线程）
    out = subprocess.run(["netstat", "-ano"], capture_output=True,
                         text=True, encoding="gbk", errors="replace").stdout or ""
    pids = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[1].endswith(f":{port}") and "LISTENING" in line:
            pids.add(parts[-1])
    return sorted(pids)


def worker_pids() -> list[str]:
    """worker 残留（Name=python.exe 过滤——纯 CommandLine 匹配会把普查命令
    自身进程链当目标，2026-09-27 实锤误杀全量 worker 导致 e2e 假失败）。"""
    out = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "Get-CimInstance Win32_Process -Filter \"name='python.exe' and "
         "commandline like '%app.zk.worker%'\" "
         "| Select-Object -ExpandProperty processid"],
        capture_output=True,
    ).stdout.decode("gbk", errors="replace")
    return [tok for tok in out.split() if tok.isdigit()]


def main() -> int:
    any_hit = False
    for port in PORTS:
        for pid in pids_on(port):
            any_hit = True
            subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True)
            print(f"port {port}: killed pid {pid}")
    for pid in worker_pids():
        any_hit = True
        subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True)
        print(f"worker: killed pid {pid}")
    # WSL 桥（fz-bridge systemd 瞬态单元）——mirrored 下 Windows 侧杀端口
    # 只断 relay 不停真身；stop 幂等（单元不存在也不报错）
    subprocess.run(
        ["wsl", "-u", "root", "bash", "-c",
         "systemctl stop fz-bridge 2>/dev/null; "
         "pkill -f 'uvicorn server:app' 2>/dev/null; true"],
        capture_output=True,
    )
    print("[wsl] fz-bridge 已停（链节点/fz-sitl2/keepalive 为常驻基础设施未动——"
          "彻底下线：wsl -u root systemctl stop fz-sitl2）")
    if not any_hit:
        print("无在跑的演示服务")
    return 0


if __name__ == "__main__":
    sys.exit(main())
