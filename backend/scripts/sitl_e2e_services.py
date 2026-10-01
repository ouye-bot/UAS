# -*- coding: utf-8 -*-
"""e2e 服务编排（AI 受控后台进程版——不开控制台窗，日志落文件，退出码真实回传）。

用法：python scripts/e2e_services.py up|down|status
- up：backend(8000)+bridge(8100)+worker（验证 worker）——fake 锚模式
- down/status：杀三服务/探活（重启前全杀纪律——多实例残留教训）
"""
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

UAS = Path(__file__).resolve().parents[2]
BACKEND = UAS / "backend"
BRIDGE = UAS / "gcs" / "bridge"
PY = BACKEND / ".venv" / "Scripts" / "python.exe"
LOGDIR = UAS / "logs" / "e2e_services"


def _procs():
    out = subprocess.run(
        ["netstat", "-ano", "-p", "TCP"], capture_output=True
    ).stdout.decode("gbk", errors="replace")
    pids = {}
    for line in out.splitlines():
        for port in (":8000", ":8100"):
            if f"127.0.0.1{port}" in line and "LISTENING" in line:
                pids.setdefault(port, set()).add(line.split()[-1])
    return pids


def down() -> int:
    for round_ in range(2):
        pids = _procs()
        for port, ps in pids.items():
            for pid in ps:
                subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True)
                print(f"killed {port} pid={pid}")
        if round_ == 0:
            time.sleep(1.5)
    # worker 无端口——按命令行匹配杀（wmic 已从新 Windows 移除，用 PowerShell CIM）
    out = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "Get-CimInstance Win32_Process -Filter \"commandline like '%app.zk.worker%'\" "
         "| Select-Object -ExpandProperty processid"],
        capture_output=True,
    ).stdout.decode("gbk", errors="replace")
    for tok in out.split():
        if tok.isdigit():
            subprocess.run(["taskkill", "/F", "/PID", tok], capture_output=True)
            print(f"killed worker pid={tok}")
    for pat in ("app.main:create_app", "server:app", "app.zk.worker"):
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_Process -Filter \"commandline like '%" + pat + "%'\" "
             "| Select-Object -ExpandProperty processid"],
            capture_output=True,
        ).stdout.decode("gbk", errors="replace")
        for tok in out.split():
            if tok.isdigit():
                subprocess.run(["taskkill", "/F", "/PID", tok], capture_output=True)
                print(f"killed [{pat}] pid={tok}")
    return 0


def status() -> int:
    pids = _procs()
    for port in (":8000", ":8100"):
        print(f"{port} listeners: {pids.get(port, set()) or '无'}")
    return 0


def wait_http(url: str, timeout_s: float = 30) -> bool:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with opener.open(url, timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.8)
    return False


BRIDGE_URL = "http://127.0.0.1:8100"


def _chain_up() -> bool:
    """WSL FISCO 链探活（8545 getBlockNumber）。"""
    import json as _json

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(
        "http://127.0.0.1:8545",
        data=_json.dumps(
            {"jsonrpc": "2.0", "method": "getBlockNumber", "params": [1], "id": 1}
        ).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with opener.open(req, timeout=3) as r:
            return b"result" in r.read()
    except Exception:
        return False


def _trail_route_ready() -> bool:
    """新代码就绪探针（旧桥残留=404 路由不存在）。空 body 掷 422（alt_max_cm
    必填校验）——422 同样证明路由在（pydantic 层先于业务层）；409=无遥测。"""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(BRIDGE_URL + "/prove/trail/start",
                                 data=b"{}", headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with opener.open(req, timeout=6) as r:
            return r.status in (200, 409, 422)
    except urllib.error.HTTPError as e:
        return e.code in (200, 409, 422)
    except Exception:
        return False


def up(no_bridge: bool = False) -> int:
    assert PY.exists(), f"venv 缺失: {PY}"
    LOGDIR.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    os.environ.setdefault("FZ_ENGINE_TOKEN", __import__("secrets").token_hex(16))  # R3-0.5 同源注入
    # 缺省 fake（CI 形态）；真链验收=FZ_CHAIN_ANCHOR=real 外部注入（阶段一），
    # 注入后先探活链——不可达即失败退出（验收场景不静默降级）。
    if env.get("FZ_CHAIN_ANCHOR", "fake") != "fake":
        if not _chain_up():
            print("[chain] FZ_CHAIN_ANCHOR=real 但链不可达（8545 探活失败）——退出")
            return 1
    env.setdefault("FZ_CHAIN_ANCHOR", "fake")
    env["FZ_ZKSVC_DIR"] = str(UAS / "zksvc")
    env.setdefault("FZ_ZK_CASES_DIR", str(BACKEND / "fz-zk-cases"))
    env.setdefault("FZ_AUDIT_TOKEN", "fake-audit-token")

    logs = {}
    logs["backend"] = open(LOGDIR / "backend.log", "w", encoding="utf-8")
    logs["worker"] = open(LOGDIR / "worker.log", "w", encoding="utf-8")

    subprocess.Popen(
        [str(PY), "-m", "uvicorn", "app.main:create_app", "--factory",
         "--host", "127.0.0.1", "--port", "8000"],
        cwd=str(BACKEND), env=env, stdout=logs["backend"], stderr=subprocess.STDOUT)
    subprocess.Popen(
        [str(PY), "-m", "app.zk.worker"],
        cwd=str(BACKEND), env=env, stdout=logs["worker"], stderr=subprocess.STDOUT)
    if not no_bridge:
        # 阶段二：S1/S2 场景的 bridge 由脚本自管（WSL 内 sitl 形态）——no_bridge
        # 跳过 Windows 桥（8100 端口让给 WSL 桥）
        logs["bridge"] = open(LOGDIR / "bridge.log", "w", encoding="utf-8")
        bridge_env = env.copy()
        bridge_env["PYTHONPATH"] = f"{BACKEND}{os.pathsep}{BRIDGE}"
        # ③GCS 化分档：判决栈桥显式允许合成采样（S4/e2e 的受控测试输入——
        # 产品 demo_up 档不设此 env，合成路径默认物理关闭）。
        bridge_env["FZ_ALLOW_SYNTHETIC_SAMPLE"] = "1"
        subprocess.Popen(
            [str(PY), "-m", "uvicorn", "server:app", "--host", "127.0.0.1", "--port", "8100"],
            cwd=str(BRIDGE), env=bridge_env, stdout=logs["bridge"], stderr=subprocess.STDOUT)

    ok_api = wait_http("http://127.0.0.1:8000/healthz")
    if no_bridge:
        print(f"backend={ok_api}（no_bridge 模式——8100 由场景脚本自管）")
        return 0 if ok_api else 1
    ok_bridge = wait_http("http://127.0.0.1:8100/engine_pub")
    ok_trail = _trail_route_ready()
    # 单实例探针（双进程重绑=请求交替命中教训）
    pids = _procs()
    single = all(len(v) == 1 for v in pids.values()) and len(pids) == 2
    print(f"backend={ok_api} bridge={ok_bridge} trail={ok_trail} 单实例={single} pids={ {k: list(v) for k, v in pids.items()} }")
    if not (ok_api and ok_bridge and ok_trail and single):
        return 1
    return 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    no_bridge = "--no-bridge" in sys.argv
    raise SystemExit(
        down() if cmd == "down" else up(no_bridge=no_bridge) if cmd == "up" else status()
    )
