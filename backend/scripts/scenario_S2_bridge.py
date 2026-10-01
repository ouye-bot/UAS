# -*- coding: utf-8 -*-
"""S2 围栏判决行回归（R1-4：真 SITL 经 bridge API 全流程——web 飞行屏同款接口）。

流程（单会话纪律——一个 wsl.exe 进程全程持有 SITL）：
  ①拉起 WSL SITL（held Popen）→②桥接 FZ_GCS_LINK=sitl 模式重启→③等 GPS 锁
  →④POST /arm（真令牌：围栏参数 PARAM_VALUE 确认写入+ARM ACK）→⑤RC 爬升循环
  （真 MAVLink 遥测）→⑥固件围栏触发（STATUSTEXT "Max Alt fence breached"捕获
  +breach 事件 source=1）→⑦DISARM 收尾→判决行断言。

用法：cd uas/backend && python scripts/scenario_S2_bridge.py
前置：WSL ArduPilot（~/ardupilot/build/sitl/bin/arducopter，B5 编译在位）；
      backend(8000) 在线（令牌面）；本脚本自管 bridge(8100, sitl 模式)。
"""

from __future__ import annotations

import json
import os
UAS_WSL = os.environ.get("FZ_UAS_WSL", "/mnt/c/uas")  # 部署路径（env 可覆盖）
import socket
import subprocess
import threading
import sys
import time
import urllib.request
from pathlib import Path

UAS = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(UAS / "backend"))

BRIDGE = "http://127.0.0.1:8100"
ALT_MAX_M = 30  # 围栏 30m（B5 S2 同口径——实测触发 ~36.8m 过冲）

_checks = 0


def ok(label: str) -> None:
    global _checks
    _checks += 1
    print(f"  [OK] {label}")


def expect(cond: bool, label: str, detail: str = "") -> None:
    if cond:
        ok(label)
    else:
        print(f"  [FAIL] {label} {detail}")
        raise SystemExit(1)


def opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))  # 回环禁代理


def bridge_get(path: str, timeout: float = 30) -> dict:
    with opener().open(BRIDGE + path, timeout=timeout) as r:
        return json.loads(r.read().decode())


def bridge_post(path: str, body: dict, timeout: float = 60) -> dict:
    req = urllib.request.Request(
        BRIDGE + path, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with opener().open(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def port_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) == 0


def wsl_root(cmd: str) -> str:
    r = subprocess.run(["wsl", "-u", "root", "bash", "-c", cmd],
                       capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()


def _unit_watchdog(stop: "threading.Event") -> None:
    """单元看门狗：inactive 即重建瞬态单元（幽灵 stop 对抗——每次拉起留痕）。"""
    while not stop.is_set():
        state = wsl_root("systemctl is-active fz-sitl 2>/dev/null")
        if state.strip() != "active":
            wsl_root(
                "systemctl reset-failed fz-sitl 2>/dev/null; "
                "systemd-run --unit=fz-sitl --property=Restart=on-failure "
                "--working-directory=/root "
                "/home/ouye/ardupilot/build/sitl/bin/arducopter --model + --speedup 1 -I0 "
                "2>/dev/null; true"
            )
            print("  [watchdog] 单元重建（曾有 inactive）", flush=True)
        stop.wait(5)


def wait_units_ready(timeout_s: float = 60) -> bool:
    """等待 SITL SERIAL0 进入监听（journal 判据：bind port 5760）。"""
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        log = wsl_root("journalctl -u fz-sitl --no-pager -n 30 2>/dev/null")
        if "SERIAL0 on TCP port" in log:
            return True
        time.sleep(3)
    return False


def mint_token() -> tuple[bytes, str]:
    """真令牌（backend KMS engine 钥签发——S2 被测面=飞行闸门，令牌本身真签真验）。"""
    import time as _time

    from app.crypto.sm2 import sign_digest
    from app.crypto.sm3 import sm3_bytes
    from app.kms import engine_signing_keypair

    sk, _pk = engine_signing_keypair()
    now = int(_time.time())
    tok = {
        "authId": 2,
        "plan_hash": "cd" * 32,
        "alt_max": ALT_MAX_M,  # 围栏 cm 即令牌 alt_max（cm 口径：30m=30cm? ——见下）
        "t_start": now - 60,
        "t_end": now + 3600,
        "nonce": "ab" * 16,
        "policy_version": "policy-2026-09-v1",
    }
    # 单位契约（复审[中9]统一）：令牌/固件=meters；30m 围栏→alt_max=30
    tok["alt_max"] = ALT_MAX_M
    body = json.dumps(tok, separators=(",", ":"), sort_keys=True)
    sig = sign_digest(sk, sm3_bytes(body.encode()))
    return (body + "|" + sig).encode(), tok["plan_hash"]


def main() -> int:
    print("== S2 围栏判决行回归（真 SITL × bridge API，单会话纪律）==")
    bridge_proc = None
    wsl_proc = None
    relay_proc = None
    keepalive_proc = None
    stop_flag = threading.Event()
    try:
        # ① WSL SITL + MAVLink 中继 = systemd 瞬态单元（进程治理：会话界杀手
        # 免疫——nohup 后台进程不过 wsl.exe 会话界且后台任务超时会清进程树，
        # 实测 2026-09-22；systemd 单元由 PID1 守护，亦是 S5 进程守护的预演）。
        wsl_root("systemctl stop fz-sitl 2>/dev/null; systemctl reset-failed fz-sitl 2>/dev/null; "
                 "pkill -9 -x arducopter 2>/dev/null; pkill -9 -f fz_relay.py 2>/dev/null; true")
        # 无 -S（合成时钟对 VM 时间回跳敏感）；无 -w（参数擦除触发间歇自举循环
        # ——双重实锤 2026-09-22）；Restart=on-failure 兜底自愈。
        # 🔴 中继已移除：桥接（WSL 内）直连 SERIAL0 TCP——中继会与桥接争抢
        # 一次性连接槽（03:54 run 实锤）。
        wsl_root("systemd-run --unit=fz-sitl --property=Restart=on-failure "
                 "--working-directory=/root "
                 "/home/ouye/ardupilot/build/sitl/bin/arducopter --model + --speedup 1 -I0")
        # 🔴 VM keepalive（总根因修复）：WSL2 VM 在最后一个会话断开后 ~60s 自动
        # 关机（journal 的 "Stopping"=VM 关机现场，非幽灵 stop）——systemd 单元
        # 陪葬。本驱动全程持有一个空闲会话保 VM 存活。
        keepalive_proc = subprocess.Popen(
            ["wsl", "bash", "-c", "exec sleep infinity"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        print("  [..] SITL+中继（systemd 单元）拉起中…")
        # 单元看门狗：若存在"幽灵 stop"（02:30:25 事故未定谳）⟹ 5s 内拉起并记录
        watchdog = threading.Thread(target=_unit_watchdog, args=(stop_flag,), daemon=True)
        watchdog.start()
        expect(wait_units_ready(), "① SITL 心跳经中继锁定（journal 判据）")

        # ② 桥接 sitl 模式（杀旧桥——多实例纪律）
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-NetTCPConnection -LocalPort 8100 -State Listen "
             "| Select-Object -ExpandProperty OwningProcess"],
            capture_output=True,
        ).stdout.decode("gbk", errors="replace")
        for pid in {tok for tok in out.split() if tok.isdigit()}:
            subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True)
        env = dict(os.environ)
        # 桥接进程在 WSL 内运行（R1-4/S2 最终拓扑拍板）：SITLLink 走 WSL 内部
        # TCP 5760（B5 已证 24k msg/90s 满速流；Windows→WSL 直连受 mirrored
        # TCP-EOF 限制不可用）；mirrored 网络使 Windows/Web 照常访问 127.0.0.1:8100。
        # 🔴 Windows→WSL 环境变量不透传（WSLENV 门控）——全部烤进 bash 命令行
        bridge_proc = subprocess.Popen(
            ["wsl", "bash", "-c",
             f"cd '{UAS_WSL}/gcs/bridge' && "
             "export FZ_GCS_LINK=sitl "
             "FZ_SITL_CONN=tcp:127.0.0.1:5760 "
             f"PYTHONPATH={UAS_WSL}/backend:"
             f"{UAS_WSL}/gcs/bridge && "
             "exec python3 -m uvicorn server:app --host 127.0.0.1 --port 8100"],
            stdout=open(UAS / "logs" / "s2_bridge.log", "w"), stderr=subprocess.STDOUT,
        )
        t0 = time.time()
        while time.time() - t0 < 30:
            try:
                st = bridge_get("/link_status")
                break
            except Exception:
                time.sleep(1)
        expect(st.get("mode") == "sitl", "② 桥接 SITLLink 模式在线", f"got {st}")

        # ③ GPS 锁
        r = bridge_post("/sitl/wait_gps", {"timeout_s": 120}, timeout=240)
        expect(r.get("ok") is True, "③ GPS 锁（fix_type≥3）")

        # ④ ARM（围栏 30m：PARAM_VALUE 确认写入+COMMAND_ACK）
        token_payload, plan_hash = mint_token()
        r = bridge_post("/arm", {
            "token_payload_hex": token_payload.hex(),
            "plan_hash_hex": plan_hash,
        }, timeout=120)
        expect(r.get("ok") is True, "④ 闸门 ARM（围栏先写后 ARM，参数确认）",
               json.dumps(r, ensure_ascii=False)[:200])
        expect(r.get("alt_max") == ALT_MAX_M, "④' 围栏上限=令牌 alt_max(meters)")

        # ④'' 遥测链起链（authId 贯穿+围栏状态绑定检查点报文）
        r = bridge_post("/telemetry/start", {
            "auth_id": r.get("auth_id"),
            "fence_state_hex": r.get("fence_state_hex"),
        })
        expect(r.get("ok") is True and "genesis_head_hex" in r, "④'' 遥测链 genesis 起链")

        # ⑤ RC 爬升循环（真遥测）——直至固件围栏触发或超时
        print("  [..] RC 油门爬升中（真 MAVLink 遥测 2Hz）…")
        breached = False
        peak_cm = 0
        t0 = time.time()
        while time.time() - t0 < 150:
            r = bridge_post("/sitl/climb", {"pwm": 1750, "hold_s": 2.0}, timeout=30)
            if r.get("alt_cm"):
                peak_cm = max(peak_cm, r["alt_cm"])
            if r.get("fence_breached"):
                breached = True
                print(f"  [..] 围栏触发 @{r.get('alt_cm')}cm（STATUSTEXT: {r.get('last_statustext')}）")
                break
            time.sleep(0.4)
        expect(breached, "⑤ 固件围栏触发（STATUSTEXT 捕获）", f"peak={peak_cm}cm")
        expect(peak_cm >= ALT_MAX_M * 100, "⑤' 触发高度≥围栏值（硬拦截实锤）",
               f"peak={peak_cm}cm fence={ALT_MAX_M}m")

        # ⑥ 真采样消费围栏态（固件事件→链上面 source=1）
        r = bridge_get(f"/telemetry/sitl_sample?t_epoch={int(time.time())}")
        expect(r.get("ok") is True and r.get("fence_breached") is True,
               "⑥ 真采样面围栏态一致+breach 事件生成",
               json.dumps(r, ensure_ascii=False)[:200])
        expect(r.get("event") is not None and r["event"].get("event_type") == 1,
               "⑥' 违规事件 event_type=1（固件围栏为权威源——D16）")

        # ⑦ 审计面（ARM 行在案）
        r = bridge_get("/audit")
        expect(len(r.get("arms", [])) >= 1, "⑦ ARM 审计行在案（A7）")

        print(f"\n== S2 经桥接全流程 {_checks} 项断言 [OK] ==")
        return 0
    finally:
        stop_flag.set()
        # 收尾：DISARM+停 systemd 单元+停桥
        try:
            bridge_post("/sitl/disarm", {}, timeout=10)
        except Exception:
            pass
        for proc in (bridge_proc, relay_proc, wsl_proc, keepalive_proc):
            if proc is not None:
                proc.kill()
        # 杀 wsl.exe 启动器≠杀远端进程（㊿+38 假活教训）——WSL 侧 uvicorn 必须补刀
        wsl_root("systemctl stop fz-sitl 2>/dev/null; "
                 "pkill -f 'uvicorn server:app' 2>/dev/null; true")


if __name__ == "__main__":
    raise SystemExit(main())
