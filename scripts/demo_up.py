"""飞证演示环境一键启动（供队长手动功能测试）。

用法：cd uas && python scripts/demo_up.py [--fake]
  默认 fake 锚模式（无需 WSL 链在线）——前端全部功能可测；
  默认真链模式（需 WSL FISCO 四节点在线——脚本自动探活拉起）；--fake 切无链模式。

拉起三服务（各占独立控制台窗口，Ctrl+C 或关窗即停）+常驻基础设施探活：
  SITL 飞控（fz-sitl 瞬态单元——未在位自动拉起；MAVLink 心跳启动硬门）。
  backend  http://127.0.0.1:8000  （API/分发页 /verify/；治理台走 web 登录）
  bridge   http://127.0.0.1:8100
  web      http://localhost:5174
停止：python scripts/demo_down.py（或直接关三个控制台窗口）。
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

UAS = Path(__file__).resolve().parents[1]
BACKEND = UAS / "backend"
BRIDGE = UAS / "gcs" / "bridge"
WEB = UAS / "gcs" / "web"
PY = BACKEND / ".venv" / "Scripts" / "python.exe"
CREATE_NEW_CONSOLE = 0x10  # Windows：独立控制台窗口

CHECKLIST = """
================ 飞证 · 手动功能测试清单 ================
【模式】真链默认（探活自动判定；链不可达诚实降级 fake 并打印）。
  真链档：受理门控链视图（nonceUsed/pin）+worker recordAuth 真链上链+
  检查点/事件上链（/engine 面）全接线——阶段一二判决行在 docs/性能档案.md。

前端（飞手工作台）  http://localhost:5174
  ①我的记录     注册承诺 → 真实 RA 签发（链上 registerCommitment）
                签发子凭证 → id′/24h 有效期
                负例：坏格式身份证 → 后端 422 原样呈现
  ②起飞申请     桥接本机实时出证（AUTH 约 2 分钟，分段进度可见）→ 回执码
                → ready 领取 → 令牌（worker verify-instances 真验证）
                重放负例：sub_cred_used/nonce_used 真实拒绝
  ③令牌与飞行   领取令牌 → ARM（真令牌验签+围栏参数写入）→「开始记录」
                →「爬升一段」进入合规高度带（自动真采样 2Hz）→ 冲高触发
                固件围栏红条 →「结束飞行并封链」（检查点锚定+DISARM）
  ④留痕与TRAIL  样本 ≥128 →「TRAIL 出证」（本机 ~1 分钟）→ 判决件三件套下载
                → 第三方复验（verify-instances）；链上留痕面板同步
                （回执查询页已删 2026-10-04——回执码消费走③取件）
审计台（治理面）  http://localhost:5174  审计员账户登录 → 审计工作台
  流程          线索聚合（可立案过滤）→ 创建令状（logWarrant 上链）→
                协作队列发起双控解锁（审计签名+管理员签名缺一不可）
                → 追溯时间线（事件→令状→实名，链上单一事实源）
【全真判决行】scenario_S1_fullchain.py 46 断言（登记→出证→ARM 真 SITL→
  合规飞行→TRAIL 证书→围栏触发取证→令状追溯，零替身）。
  面板数据验收：verify_panel_chain.py 17 断言（面板=链上事实）。
【现行全量基线（2026-10-12 修整窗口后）】后端 pytest 571 ｜ 前端 vitest 169 ｜
  浏览器级 UI 回归 41 断言（3 分钟演示动线：docs/演示动线3分钟.md，彩排器
  scripts/demo_rehearse_3min.py）。口径权威=docs/性能档案.md「现行口径总表」（判决行单一事实源，答辩口径卡 A9 同指）。
========================================================
"""


def wait_http(url: str, timeout_s: float = 30) -> bool:
    import urllib.request

    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.8)
    return False


def _wsl_root_out(cmd: str) -> str:
    r = subprocess.run(["wsl", "-u", "root", "bash", "-c", cmd], capture_output=True, text=True)
    return (r.stdout or "") + (r.stderr or "")


def _chain_nodes_up() -> None:
    """拉起 WSL FISCO 四节点——直调 §八复活工序 chain_nodes_up.sh（先拔硬关机
    残留 RocksDB LOCK→pkill 残余→逐节点启动→探活）。此前经 up.sh 直调
    start_all.sh：无拔 LOCK/无 pkill/仅 sleep 2 即探活——硬关机（断电/强重启）
    残留态下四节点 init 即 terminate，探活恒 FAIL 降级 fake 档（2026-10-15
    实弹定谳+本日复现；手动重跑才偶发成功=时序不可靠）。路径直传中文目录：
    Windows subprocess→wsl.exe 三形态（bash -c/裸参/bash -n）当日探针实测
    无损，且不经 MSYS 故无 PATHCONV 参数改写问题（gcs_bridge_start.sh 的
    ASCII 复制另有 .local_env 同目录功能需求——chain_nodes_up.sh 的 source
    是可选短路且 UAS_WSL 未被使用，原位执行反而 source 到真 .local_env）。"""
    _wsl_uas = "/mnt/" + UAS.drive[0].lower() + UAS.as_posix()[2:]
    subprocess.run(
        ["wsl", "-u", "root", "bash", f"{_wsl_uas}/scripts/chain_nodes_up.sh"],
        capture_output=True,
    )


_SITL_READY_MARK = "SERIAL0 on TCP port"  # journal 就绪判据（S1 wait_units_ready 同源）


def _sitl_ready() -> bool:
    """三判据：fz-sitl 单元 active + journal SERIAL0 就绪行 + 5760 监听在位。"""
    if _wsl_root_out("systemctl is-active fz-sitl 2>/dev/null").strip() != "active":
        return False
    out = _wsl_root_out("journalctl -u fz-sitl --no-pager -n 30 2>/dev/null; ss -ltn 2>/dev/null")
    return _SITL_READY_MARK in out and ":5760" in out


def ensure_sitl(timeout_s: float = 90) -> bool:
    """SITL 飞控探活拉起（幂等——活的 SITL 不动，保 GPS 锁与在飞会话）。

    宿主重启后 WSL 进程全灭：链节点有本脚本探活拉起，而 SITL（systemd 瞬态
    单元 fz-sitl——transient 单元不跨重启）此前无人重建=栈残废。2026-10-14
    实弹定谳：ARM Connection refused×30——桥直连 tcp:5760 无人监听（飞控侧
    唯一语义），前端解锁 10s+ 无响应。本函数把 MEMORY §八 复活工序并入启动
    序列（栈单一事实源）：拉起命令与 S1 stage0/sitl_units_up.sh 逐字同源
    （不自创工序）；生产拓扑=无 relay、桥直连（5760 单客户端槽纪律）——本
    函数不拉 relay、不做 5760 TCP 探活（防占烧单槽，判据止于端口 LISTEN）。"""
    if _sitl_ready():
        print("[sitl] 飞控仿真在位（fz-sitl active + SERIAL0/5760 监听）——不动")
        return True
    print("[sitl] 飞控仿真未就绪（宿主重启后瞬态单元消亡？）——拉起中…")
    _wsl_root_out(
        "systemctl stop fz-sitl 2>/dev/null; systemctl reset-failed fz-sitl 2>/dev/null; "
        "pkill -9 -x arducopter 2>/dev/null; true"
    )
    _wsl_root_out(
        "systemd-run --unit=fz-sitl --property=Restart=on-failure --working-directory=/root "
        "/home/ouye/ardupilot/build/sitl/bin/arducopter --model + --speedup 1 -I0"
    )
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        if _sitl_ready():
            print(f"[sitl] 飞控仿真就绪（SERIAL0 on TCP 5760，耗时 {time.time() - t0:.0f}s）")
            return True
        time.sleep(3)
    return False


def preclean() -> None:
    """启动前清场（㊿+26/38 纪律的产品化：残留多实例/假活进程是历史头号事故源
    ——web 活着但 API 死的半残态就是这么来的）。清 8000/8100/5174 端口进程+
    worker（按命令行，Name 过滤防普查命令自我指涉误杀）+WSL 桥单元（fz-bridge
    ——gcs_bridge_start.sh 随后重建）。

    分层纪律（W-11，2026-09-27）：演示栈（backend/web/worker/fz-bridge）清场
    重建；常驻基础设施（WSL 链节点、fz-sitl2 飞控、keepalive schtasks）**不动**
    ——fz-sitl2 被 pkill arducopter 误杀后无人重建=栈残废（旧 preclean 的
    `pkill -9 -x arducopter`+`systemctl stop fz-sitl` 为裸跑时代遗产，新拓扑
    下必删）。"""
    import subprocess as _sp

    out = (
        _sp.run(
            ["netstat", "-ano"], capture_output=True, text=True, encoding="gbk", errors="replace"
        ).stdout
        or ""
    )
    pids: dict[str, set] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and "LISTENING" in line:
            for port in (":8000", ":8100", ":5174"):
                if parts[1].endswith(port):
                    pids.setdefault(port, set()).add(parts[-1])
    for port, ps in pids.items():
        for pid in ps:
            _sp.run(["taskkill", "/F", "/PID", pid], capture_output=True)
            print(f"[clean] {port} 残留进程 pid={pid} 已结束")
    # worker 按「进程名=python.exe ∧ 命令行含 app.zk.worker」清（Name 过滤——
    # 纯 CommandLine 匹配会把普查命令自身的进程链当目标，2026-09-27 实锤误杀）
    out = _sp.run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_Process -Filter \"name='python.exe' and "
            "commandline like '%app.zk.worker%'\" "
            "| Select-Object -ExpandProperty processid",
        ],
        capture_output=True,
    ).stdout.decode("gbk", errors="replace")
    for tok in out.split():
        if tok.isdigit():
            _sp.run(["taskkill", "/F", "/PID", tok], capture_output=True)
            print(f"[clean] worker 残留 pid={tok} 已结束")
    # WSL 侧：只清桥（gcs_bridge_start.sh 重建）——fz-sitl2/链/裸 arducopter
    # 均为常驻基础设施不动（W-11 分层）
    _sp.run(
        [
            "wsl",
            "-u",
            "root",
            "bash",
            "-c",
            "systemctl stop fz-bridge 2>/dev/null; pkill -f 'uvicorn server:app' 2>/dev/null; true",
        ],
        capture_output=True,
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fake", action="store_true", help="无链模式（CI/离线演示——真链为 R1-3 默认）")
    ap.add_argument(
        "--no-clean", action="store_true", help="跳过启动前清场（默认清——残留防治纪律）"
    )
    args = ap.parse_args()

    if not args.no_clean:
        preclean()

    assert PY.exists(), f"backend venv 缺失: {PY}"
    # venv 依赖探针（原 up.sh [2/3] 段内联随迁——demo_up 拉链不再经 up.sh 后，
    # 依赖缺失若不在此报错，只会在启动末尾呈现为 backend=False 而无从定位）。
    _dep = subprocess.run([str(PY), "-c", "import gmssl, fastapi"], capture_output=True)
    assert _dep.returncode == 0, (
        "backend venv 缺依赖（重装：backend/.venv/Scripts/python.exe "
        "-m pip install -e 'backend[dev]'）"
    )
    # WSLInterop 自愈段（原 up.sh [3/3]）不随迁：wsl.conf [boot] command 已加
    # binfmt 幂等自愈（MEMORY §八 保活条），启动器无需重复。
    env = os.environ.copy()
    if not args.fake:
        # 真链默认（R1-3）：自动探活/拉起 WSL FISCO 四节点
        import urllib.request as _u

        def _chain_up() -> bool:
            try:
                req = _u.Request(
                    "http://127.0.0.1:8545",
                    data=json.dumps(
                        {"jsonrpc": "2.0", "method": "getBlockNumber", "params": [1], "id": 1}
                    ).encode(),
                    headers={"Content-Type": "application/json"},
                )
                with _u.urlopen(req, timeout=3) as r:
                    return b"result" in r.read()
            except Exception:
                return False

        if not _chain_up():
            print("[chain] WSL 链未起——拉起中…（chain_nodes_up.sh：先拔硬关机残留 LOCK 再启动）")
            _chain_nodes_up()
        print(f"[chain] 探活: {'OK' if _chain_up() else 'FAIL（将降级无链模式——明确打印）'}")
        if _chain_up():
            # 显式真链档（阶段一：全服务链写面统一真链——authz 门控/worker
            # recordAuth/锚定/事件；缺省 fake 只属 CI，不设 env 不得静默真链）
            env["FZ_CHAIN_ANCHOR"] = "real"
        else:
            env["FZ_CHAIN_ANCHOR"] = "fake"
            print("[chain] ⚠ 链不可达——本次以无链模式启动（fail-closed 诚实降级）")
    # SITL 飞控探活拉起（桥恒 sitl 模式——gcs_bridge_start.sh 硬编码
    # FZ_GCS_LINK=sitl，故 --fake 链档同样需要飞控在线；失败硬门=栈启动
    # 永不遗留 SITL 未启动——2026-10-14 宿主重启事故的结构性封堵）。
    if not ensure_sitl():
        print("[sitl] ⚠ 飞控仿真拉起失败（90s 无 SERIAL0 就绪行）——ARM 必拒。"
              "人工排查：wsl -u root journalctl -u fz-sitl -n 50")
        return 1
    env["FZ_ZKSVC_DIR"] = str(UAS / "zksvc")
    # .local_env 注入（2026-10-04 批3.2 根修）：链上交易钥已换 CSPRNG 随机
    # （部署合约的角色=这四把钥）——backend/worker 不加载它们就退回派生
    # 演示钥，链写全部被合约 revert（roles_live G.1 实弹 0x16 抓出）。解析
    # export KEY=VALUE 行注入子进程 env；.local_env 为部署事实源，同键覆盖
    # 外部值（与桥脚本 source 同语义）。真链档缺此文件=起服后在对账/写面
    # 处人话报错，不静默。
    _env_file = UAS / ".local_env"
    if _env_file.exists():
        import re as _re

        for _line in _env_file.read_text(encoding="utf-8").splitlines():
            _m = _re.match(r"^\s*(?:export\s+)?([A-Z0-9_]+)=(.*)\s*$", _line)
            if _m and not _line.lstrip().startswith("#"):
                env[_m.group(1)] = _m.group(2).strip().strip('"').strip("'")
    # 出证产物目录三服务同源（backend 受理对账 / worker 判决件 / bridge 写面
    # 共用同一 _cases_dir——缺省 /tmp 会让受理 400 case_incomplete 假败，
    # R2 收口实测踩雷：对账面读 backend/fz-zk-cases 而写面落 /tmp）。
    env["FZ_ZK_CASES_DIR"] = str(BACKEND / "fz-zk-cases")
    # 审计令牌分档（2026-09-28 安全深检 B-P2 根修：真链档此前仍是 repo 公开
    # 常量——随机化批次漏网最后一钥）。fake 档保留公开演示值（/audit/demo-token
    # 披露判定 demo:true）；真链档每场随机+%TEMP% 持久（与六钥同纪律——
    # 读过 repo 的评委不再能进治理面）
    env.setdefault("FZ_AUDIT_TOKEN", "fake-audit-token")
    # R3-0.5：engine 转发面令牌三服务同源（backend 校验 ⟂ bridge 携带——
    # 缺注入=检查点/事件上链全 401，教训㊿+44 的「一处定义、同源注入」）
    import secrets as _secrets

    if env.get("FZ_CHAIN_ANCHOR") == "real" and env["FZ_AUDIT_TOKEN"] == "fake-audit-token":
        env["FZ_AUDIT_TOKEN"] = _secrets.token_hex(16)
    env.setdefault("FZ_ENGINE_TOKEN", _secrets.token_hex(16))
    # 演示启动注入随机引擎钥（S5[低]：缺省确定性派生可被读过 repo 的评委
    # 自推私钥铸合法令牌——每场演示一次性随机，进程组共享同一钥）
    env.setdefault("FZ_ENGINE_SK", _secrets.token_hex(32))
    # A-P1-1（R4 第一批声称未落地项补课）：RA 签名钥同纪律随机化——缺省确定性
    # 派生下评委可自推 RA 钥伪造子凭证直通全链（与 ENGINE 随机化的缓解不对称）
    env.setdefault("FZ_RA_SK", _secrets.token_hex(32))
    # 2026-09-28 密码评审 P1-4：剩余三面一并随机化（此前半吊子态——ENGINE/
    # RA_SK 已随机而这三面仍公开派生：RA 运维令牌/实名映射 wrap 钥/绑定 HMAC
    # 钥均可被读过代码者自推，"RA 库可见方=仅登记机构"在缺省档不成立）
    env.setdefault("FZ_RA_OPS_TOKEN", _secrets.token_hex(32))
    env.setdefault("FZ_WRAP_KEY", _secrets.token_bytes(16).hex())
    env.setdefault("FZ_AUTHZ_BINDING_KEY", _secrets.token_hex(32))
    # 每场随机密钥持久 %TEMP%（重启栈时外部显式 export 同值——连续性纪律：
    # 服务重启间换钥会让在途回执/已发令牌/已签子凭证全部失效）
    import tempfile as _tf

    _persist = {
        "FZ_ENGINE_SK": "fz_engine_sk.txt",
        "FZ_ENGINE_TOKEN": "fz_engine_token.txt",
        "FZ_RA_SK": "fz_ra_sk.txt",
        "FZ_RA_OPS_TOKEN": "fz_ra_ops_token.txt",
        "FZ_WRAP_KEY": "fz_wrap_key.txt",
        "FZ_AUTHZ_BINDING_KEY": "fz_authz_binding_key.txt",
        "FZ_AUDIT_TOKEN": "fz_audit_token.txt",
    }
    for _k, _f in _persist.items():
        (Path(_tf.gettempdir()) / _f).write_text(env[_k])

    flags = subprocess.CREATE_NEW_CONSOLE if os.name == "nt" else 0
    procs = []
    # backend 日志落盘（2026-10-02 乙5 可观测性：JSON 日志/异常堆栈可回读——
    # 控制台窗口缓冲不可编程回读的教训）。FZ_DEMO_LOGS=0 恢复控制台形态。
    _logd = UAS / "logs" / "demo"
    _logd.mkdir(parents=True, exist_ok=True)
    if os.environ.get("FZ_DEMO_LOGS", "1") != "0":
        _blog = open(_logd / "backend.log", "ab")
        procs.append(
            subprocess.Popen(
                [
                    str(PY),
                    "-m",
                    "uvicorn",
                    "app.main:create_app",
                    "--factory",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "8000",
                ],
                cwd=str(BACKEND),
                env=env,
                stdout=_blog,
                stderr=subprocess.STDOUT,
            )
        )
    else:
        procs.append(
            subprocess.Popen(
                [
                    str(PY),
                    "-m",
                    "uvicorn",
                    "app.main:create_app",
                    "--factory",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "8000",
                ],
                cwd=str(BACKEND),
                env=env,
                creationflags=flags,
            )
        )
    # ③GCS 化拓扑统一（2026-09-27）：桥=SITL 同侧（WSL）——Windows 桥
    # （FakeLink）退役（真实测试策略：产品路径零合成遥测）。启动=模板脚本
    # （gcs_bridge_start.sh，自持真实 C 盘路径与密钥读文件）复制到 ASCII
    # 路径后由 systemd-run 瞬态单元执行（批⑩守护形态：脚本 exec 前台=
    # unit 主进程，PID1 管理存活——wsl 会话清理零清杀；W-11 批实测修复：
    # 旧「wsl -e bash 直调」在脚本 exec 前台化后必 60s 超时）。
    _sh_src = UAS / "gcs" / "bridge" / "gcs_bridge_start.sh"
    # 桥启动脚本复制到 ASCII 无中文路径执行（wsl.exe 传中文路径乱码——见
    # gcs_bridge_start.sh 头注）。目标目录默认=系统临时目录（FZ_ASCII_DIR 可覆盖），
    # WSL 侧路径由 wslpath 现场换算（不硬编码盘符）。
    import os as _os

    # 🔴 缺省必须 ASCII 无中文（wsl.exe 传中文路径乱码——本注释存在的原因）；
    # 系统临时目录含中文用户名，不可用。
    _ascii_dir = _os.environ.get("FZ_ASCII_DIR", "D:/fz_bridge_tmp")  # noqa: 正斜杠——反斜杠会被 shell 层吃掉
    _sh_dst = Path(_ascii_dir) / "_fz_bridge_start.sh"
    _sh_dst.parent.mkdir(parents=True, exist_ok=True)
    _sh_dst.write_text(_sh_src.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
    # .local_env 随脚本同目录复制——桥脚本按 BASH_SOURCE 相对推导 source
    _env_src = UAS / ".local_env"
    if _env_src.exists():
        (Path(_ascii_dir) / ".local_env").write_text(
            _env_src.read_text(encoding="utf-8"), encoding="utf-8", newline="\n"
        )
    # WSL 侧路径纯字符串换算（D:/x/y → /mnt/d/x/y）——wslpath 子进程在部分
    # 调用环境返回空（2026-10-02 终验实弹），字符串换算零依赖且确定。
    _wsl_sh = "/mnt/" + _sh_dst.drive[0].lower() + _sh_dst.as_posix()[2:]
    # 前清 failed 态（transient 单元失败后驻留——不 reset 则 systemd-run 静默拒，
    # capture_output 吞掉报错=桥"无原因"起不来；2026-10-02 终验实弹）
    subprocess.run(
        ["wsl", "-u", "root", "systemctl", "reset-failed", "fz-bridge"],
        capture_output=True,
        timeout=30,
    )
    subprocess.run(
        ["wsl", "-u", "root", "systemd-run", "--unit=fz-bridge", "--uid=ouye", "bash", _wsl_sh],
        capture_output=True,
        timeout=30,
    )
    # 验证 worker（R1：产品面全链——申请→真实验证→取件不再是诚实拒绝而是真通）
    procs.append(
        subprocess.Popen(
            [str(PY), "-m", "app.zk.worker"], cwd=str(BACKEND), env=env, creationflags=flags
        )
    )
    procs.append(
        subprocess.Popen(
            ["npm", "run", "dev", "--", "--port", "5174", "--strictPort"],
            cwd=str(WEB),
            env=env,
            creationflags=flags,
            shell=(os.name == "nt"),
        )
    )

    import time as _t

    _t.sleep(5)  # WSL 桥 nohup 启动缓冲（③GCS 化：桥走 WSL 侧）
    ok_api = wait_http("http://127.0.0.1:8000/healthz")
    ok_bridge = wait_http("http://127.0.0.1:8100/engine_pub")
    ok_web = wait_http("http://localhost:5174/")
    # 钥域同源门（2026-10-14 分脑第二形态的结构性封堵）：桥/后端引擎令牌各源
    # 一处（桥=%TEMP% 档、后端=启动器 env）——混场栈（S1/e2e 遗留 backend+演示
    # 桥）健康检查全绿而 TRAIL 绑定 401（binding_unavailable）。判别器=拿
    # %TEMP% 档值打 backend 引擎面：401=分脑（硬门红，启动期即定性）；404/
    # 400=令牌对（auth_id=0 无记录，业务层拒绝——钥域一致）。硬门失败提示
    # 指向 demo_down+demo_up 全栈重拉（不做令牌外科手术——SK 场次混用不可回）。
    ok_keydomain = False
    try:
        import urllib.request as _ur2

        _tok = (Path(_tf.gettempdir()) / "fz_engine_token.txt").read_text().strip()
        _req = _ur2.Request(
            "http://127.0.0.1:8000/engine/trail/binding?auth_id=0&chain_head_hex="
            + "0" * 64,
            headers={"X-Engine-Token": _tok},
        )
        opener2 = _ur2.build_opener(_ur2.ProxyHandler({}))  # 回环禁系统代理
        try:
            with opener2.open(_req, timeout=10) as _r:
                ok_keydomain = _r.status == 200  # 理论不可达（auth_id=0 无记录）
        except _ur2.HTTPError as _he:
            # 401=钥域分脑；其余（404/400/422…）=令牌被接受、业务层拒绝=同源
            ok_keydomain = _he.code != 401
            if _he.code == 401:
                print("[keydomain] ⚠ 桥/后端引擎令牌分脑（401）——混场栈。"
                      "修复：python scripts/demo_down.py 后重跑本脚本（全栈同源重拉）")
    except Exception as _e:  # noqa: BLE001 —— 档缺失/网络面故障=按不一致处理（fail-closed）
        print(f"[keydomain] 探测失败（按分脑处理）: {_e}")
    if not ok_keydomain:
        print("[keydomain] ⚠ 钥域同源未确认——TRAIL 出证将 401。建议全栈重拉。")
    # MAVLink 健康门（启动验收=HTTP 三服务活 **且** 飞控心跳真通——8100 活而
    # 5760 死的半残态 2026-10-14 实弹：界面可用、解锁即 Connection refused×30）。
    # 判据=桥 /link_status.link_ok（SITLLink.last_hb_ts 心跳新鲜度）；未就绪重试
    # （桥首连+GPS/心跳建立需数秒；桥侧 connect 重试环最长 ~65s 才定性——
    # 单次探活容忍 90s）。硬门失败=退出码 1+指向性排查话术（不静默半残）。
    ok_mavlink = False
    _t0 = _t.time()
    while _t.time() - _t0 < 180:
        try:
            import urllib.request as _ur

            with _ur.urlopen("http://127.0.0.1:8100/link_status", timeout=90) as _r:
                _st = json.loads(_r.read().decode())
            if _st.get("link_ok"):
                ok_mavlink = True
                print(f"[mavlink] 飞控链路活体确认（心跳 { _st.get('hb_age_s') }s 前）")
                break
        except Exception:
            pass
        _t.sleep(3)
    if not ok_mavlink:
        print("[mavlink] ⚠ 飞控心跳未通——桥 8100 活但 MAVLink 链路未建立。"
              "排查：wsl -u root systemctl is-active fz-sitl；"
              "curl http://127.0.0.1:8100/link_status")
    print(f"backend={ok_api} bridge={ok_bridge} web={ok_web} mavlink={ok_mavlink} "
          f"keydomain={ok_keydomain}")
    if not (ok_api and ok_bridge and ok_web and ok_mavlink and ok_keydomain):
        print("有服务未就绪——查看各控制台窗口报错；端口被占则先 python scripts/demo_down.py")
        return 1
    print(CHECKLIST)
    return 0


if __name__ == "__main__":
    sys.exit(main())
