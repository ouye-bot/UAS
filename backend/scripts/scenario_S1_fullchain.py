# -*- coding: utf-8 -*-
"""S1 全真串联判决行（阶段二）：一个脚本贯穿全生命周期，中途任何一段用替身=失败。

七阶段（同一飞手同一令牌同一 authId 贯穿）：
  [0] 编排：清场→backend+worker（真链）→SITL（WSL systemd 单元+keepalive+看门狗）
      →桥接（WSL 内 sitl 模式——真链环境+interop zkc 出证）
  [1] AUTH 全链（真链）：登记→子凭证→绑定→桥接本机出证（真 zkc）→受理→worker
      verify-instances→取件 ECIES→令牌+链上 recordAuth 11 元组对账
  [2] 合规飞行（真 SITL）：ARM（围栏=令牌 alt_max 政策值）→温和爬升 15-19m 带
      →2Hz 真遥测采样 ≥128（TRAIL 合规窗口=前 128 样本）
  [3] TRAIL 合规证书（真出证）：检查点（设备签+围栏态）真链锚定→本机出证
      （interop zkc）→判决件三件套下载→第三方独立复验+篡改链头负例
  [4] 超限取证（真固件）：继续爬升→固件围栏触发（STATUSTEXT）→超限样本入链
      →breach 事件 recordEvent 真链上链→DISARM
  [5] 审计令状→追溯：围栏事件→令状创建（logWarrant 上链）→无令状解锁负例→
      RA 协作解锁（unwrap 实名+logWarrantUnlock）→追溯视图链上回读
      （getAuth/检查点→个人闭环）

用法：cd uas/backend && ./.venv/Scripts/python.exe scripts/scenario_S1_fullchain.py
前置：WSL FISCO 四节点在线+ArduPilot SITL 编译在位+链 pin 已发布（publish_pin）+
      rev_root 已对齐（align_rev_root）。
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

UAS = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(UAS / "backend"))

API = "http://127.0.0.1:8000"
BRIDGE = "http://127.0.0.1:8100"
ZKC = UAS / "zksvc" / "target" / "release" / "zkc.exe"
CASES = UAS / "backend" / "fz-zk-cases"

CLASS_ID = 0  # 微型（真政策：alt_max=50m required=1——令牌 alt_max 来自政策引擎）
N_WINDOW = 128  # TRAIL 定档（B6-d1）
ALT_BAND = (1500, 1900)  # 合规带 cm（bang-bang 控制目标——距 50m 围栏 ≥31m 余量）

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
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))



# ---- 账户会话（2026-09-29 账户批：X-Audit/X-RA-Token 退役）----
def _account_sessions():
    """按需登录审计员/管理员（env 初始口令；未激活态激活、已注册则跳过）。"""
    import os as _os
    from scripts.script_auth import script_login

    aud_pw = _os.environ.get("FZ_SEED_AUDITOR_PASSWORD")
    adm_pw = _os.environ.get("FZ_SEED_ADMIN_PASSWORD")
    if not aud_pw or not adm_pw:
        raise SystemExit(
            "需要 FZ_SEED_AUDITOR_PASSWORD / FZ_SEED_ADMIN_PASSWORD（部署方交付的"
            "预置账户初始口令——未激活态）。请先运行 scripts/seed_accounts.py 并以"
            "env 注入口令。"
        )
    return script_login(API, "auditor", aud_pw), script_login(API, "admin", adm_pw)


_AUD_SESS = None
_ADM_SESS = None


def _sess_cookie(path: str) -> str:
    """按路径分发会话 Cookie：/audit→审计员；/ra/revoke|/ra/collab|/admin→管理员。"""
    global _AUD_SESS, _ADM_SESS
    if _AUD_SESS is None:
        _AUD_SESS, _ADM_SESS = _account_sessions()
    if path.startswith("/ra/revoke") or path.startswith("/ra/collab") or path.startswith("/admin"):
        s = _ADM_SESS
    elif path.startswith("/audit"):
        s = _AUD_SESS
    else:
        return ""
    return "; ".join(f"{k}={v}" for k, v in s.cookies.get_dict().items())


def api_get(path: str, timeout: float = 30, headers: dict | None = None) -> dict:
    ck = _sess_cookie(path)
    hdrs = dict(headers or {})
    if ck:
        hdrs["Cookie"] = ck
    req = urllib.request.Request(API + path, headers=hdrs)
    with opener().open(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def api_post(path: str, body: dict, timeout: float = 90, headers: dict | None = None) -> tuple[int, dict]:
    # 会话 Cookie 必须并入 headers dict——曾以 **({"Cookie": …}) kwargs 形态传
    # 给 Request 构造器（b73771a 引入，TypeError 当场崩）：账户批后 /audit 面
    # 走登录会话，S1 §5 首次在登录态执行即触发（2026-09-30 预飞抓到）。
    hdrs = {"Content-Type": "application/json", **(headers or {})}
    ck = _sess_cookie(path)
    if ck:
        hdrs["Cookie"] = ck
    req = urllib.request.Request(
        API + path,
        data=json.dumps(body).encode(),
        headers=hdrs,
        method="POST",
    )
    try:
        with opener().open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


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


def sm3_hex(b: bytes) -> str:
    from app.crypto.sm3 import sm3_bytes

    return sm3_bytes(b).hex()


def wsl_root(cmd: str) -> str:
    r = subprocess.run(["wsl", "-u", "root", "bash", "-c", cmd], capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()


# ───────────────────────── 编排段 ─────────────────────────


def _commit_free_gb() -> float:
    """commit 余量（GB）——ctypes 直读 GlobalMemoryStatusEx（R3-3.1 换代：
    旧实现经 powershell 子进程，在后台托管环境下进程树被外部硬杀=门函数
    即死点；ullAvailPageFile 即「commit 限额−已用」，与旧口径同义）。"""
    import ctypes

    class _MemStat(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    stat = _MemStat()
    stat.dwLength = ctypes.sizeof(_MemStat)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
        return -1.0
    return stat.ullAvailPageFile / 2**30


def _unit_watchdog(stop: threading.Event) -> None:
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
            print("  [watchdog] 单元重建", flush=True)
        stop.wait(5)


def wait_units_ready(timeout_s: float = 90) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        log = wsl_root("journalctl -u fz-sitl --no-pager -n 30 2>/dev/null")
        if "SERIAL0 on TCP port" in log:
            return True
        time.sleep(3)
    return False


def stage0() -> tuple[list, threading.Event, subprocess.Popen | None, subprocess.Popen | None]:
    """编排：backend+worker（真链）→SITL→WSL 桥。返回需收尾的资源柄。"""
    print("== [0] 编排（清场→backend/worker 真链→SITL systemd→WSL 桥）==")
    # R3-3.1（2026-09-24 实测）：新电路 AUTH 出证 commit 峰值加成 ≈12GB
    # （RAYON=12 全开，系统级曲线 31→42.8GB 平台）；RAYON=6 峰值约减半
    # （R1 扫参曲线），出证时延 +30~40%（S1 断言全为功能面，不受影响）。
    # 桌面长会话基线 ~31GB/47.8GB 极限时，封顶是稳定运行点。
    env_rayon = os.environ.setdefault("RAYON_NUM_THREADS", "6")
    free = _commit_free_gb()
    print(f"  [..] commit 余量 ≈{free:.1f}GB（RAYON=6 封顶后 AUTH 峰值加成 ~6GB）")
    expect(free > 10.0, "内存窗口充足（commit 余量>10GB，RAYON=6 口径）", f"当前 {free:.1f}GB")

    subprocess.run(
        [str(UAS / "backend" / ".venv" / "Scripts" / "python.exe"),
         "scripts/sitl_e2e_services.py", "down"],
        cwd=str(UAS / "backend"), capture_output=True,
    )
    env = dict(os.environ)
    # R3-0.5：engine 转发面令牌同源注入——🔴必须落 os.environ（WSL 桥 spawn
    # 的 f-string 从 os.environ 内插；只进 env 字典 ⟹ 桥无令牌 401，
    # 第四~六轮 S1 三连 3.1 失败的本因）
    os.environ.setdefault("FZ_ENGINE_TOKEN", __import__("secrets").token_hex(16))
    env.setdefault("FZ_ENGINE_TOKEN", os.environ["FZ_ENGINE_TOKEN"])
    env["FZ_CHAIN_ANCHOR"] = "real"
    env["FZ_ZKSVC_DIR"] = str(UAS / "zksvc")
    env["FZ_ZK_CASES_DIR"] = str(CASES)
    up = subprocess.run(
        [str(UAS / "backend" / ".venv" / "Scripts" / "python.exe"),
         "scripts/sitl_e2e_services.py", "up", "--no-bridge"],
        cwd=str(UAS / "backend"), env=env, capture_output=True, text=True,
    )
    expect(up.returncode == 0, "backend+worker 起链模式在线", up.stdout[-200:])
    r = api_get("/chain/panel")
    expect(r["data"]["mode"] == "real", "链面=真链模式（panel 回读）")

    # 撤销根幂等对齐前置（阶段二：烟测/吊销历史可能留下链根漂移——每次 S1
    # 运行前对账本地镜像与链公示，不一致即推链对齐；一致时零交易）
    al = subprocess.run(
        [str(UAS / "backend" / ".venv" / "Scripts" / "python.exe"),
         "scripts/align_rev_root.py"],
        cwd=str(UAS / "backend"), env=env, capture_output=True, text=True,
    )
    expect(al.returncode == 0, "撤销根对齐前置（幂等）", al.stdout[-200:])

    # SITL（systemd 瞬态单元+keepalive——S2 三件套）
    wsl_root(
        "systemctl stop fz-sitl 2>/dev/null; systemctl reset-failed fz-sitl 2>/dev/null; "
        "pkill -9 -x arducopter 2>/dev/null; true"
    )
    wsl_root(
        "systemd-run --unit=fz-sitl --property=Restart=on-failure "
        "--working-directory=/root "
        "/home/ouye/ardupilot/build/sitl/bin/arducopter --model + --speedup 1 -I0"
    )
    keepalive = subprocess.Popen(
        ["wsl", "bash", "-c", "exec sleep infinity"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    stop_flag = threading.Event()
    threading.Thread(target=_unit_watchdog, args=(stop_flag,), daemon=True).start()
    expect(wait_units_ready(), "SITL systemd 单元就绪（journal 判据）")

    # 杀 8100 旧桥（多实例纪律）后起 WSL 桥（真链+interop 出证）。
    # 🔴 2026-10-01 预飞根修：旧形态=Windows 侧 Get-NetTCPConnection 找 PID
    # +taskkill——mirrored 网络下 Windows 网栈**看不到 WSL 内监听**（实测
    # netstat/Get-NetTCPConnection 对 8100 零输出）⟹ 扑空 ⟹ 旧桥（可能持
    # demo_up 的 temp 随机钥）存活占 8100，S1 新桥 bind 失败退出（Errno 98
    # ——logs/s1_bridge.log 铁证），而健康检查只看 mode=sitl（旧桥也应答
    # sitl）=假阳性 ⟹ ARM 打到旧桥，temp 钥验 S1 backend（确定性派生钥）
    # 签发的令牌 ⟹ bad_signature。根修两刀：
    # ① 杀桥改 WSL 侧（systemctl stop+pkill——systemd/非 systemd 形态通吃），
    #    并确认 8100 不可达（杀干净硬判据）；
    # ② 拉起后 /engine_pub 与 backend /authz/engine/pub 逐字节一致（钥域
    #    同源断言——不依赖间接推断，新桥没起来直接红）。
    wsl_root("systemctl stop fz-bridge 2>/dev/null; systemctl reset-failed fz-bridge 2>/dev/null; "
             "pkill -f 'uvicorn server:app' 2>/dev/null; true")
    _t_kill = time.time()
    while time.time() - _t_kill < 10:
        try:
            bridge_get("/link_status")
            time.sleep(0.5)  # 旧桥仍可达——继续等
        except Exception:
            break
    else:
        raise SystemExit("[编排] 8100 旧桥 10s 未清干净——pkill 落空，人工排查")
    import os as _os
    m = _os.environ.get("FZ_UAS_WSL", "/mnt/c/uas")
    bridge = subprocess.Popen(
        ["wsl", "bash", "-c",
         f"cd '{m}/gcs/bridge' && "
         "export FZ_GCS_LINK=sitl "
         # R3-0.5：WSLENV 不透传（S1 拓扑既有教训）⟹ 值必须 Python 侧内插
         f"FZ_ENGINE_TOKEN={os.environ.get('FZ_ENGINE_TOKEN', '')} "
         # 2026-09-26：桥无私钥（R3-B2 裁钥）⟹ 验签钥源必须与 backend/worker
         # 同源——外部注入 FZ_ENGINE_SK 的场景下确定性派生会验错人（钥域一致
         # 性家族缺陷，demo_up 同批根修），显式代理旗标恒开（两态均安全）
         "FZ_ENGINE_PUB_PROXY=1 "
         # R3-3.1：出证进程 RAYON 封顶随桥透传（zkc 继承——桌面 commit 有限）
         f"RAYON_NUM_THREADS={os.environ.get('RAYON_NUM_THREADS', '6')} "
         "FZ_SITL_CONN=tcp:127.0.0.1:5760 "
         f"FZ_DEVICE_SERIAL={SN} "
         f"PYTHONPATH={m}/backend:{m}/gcs/bridge "
         "FZ_API_BASE=http://127.0.0.1:8000 "
         f"FZ_ZKSVC_DIR={m}/zksvc "
         f"FZ_ZK_CASES_DIR={m}/backend/fz-zk-cases "
         "&& exec python3 -m uvicorn server:app --host 127.0.0.1 --port 8100"],
        stdout=open(UAS / "logs" / "s1_bridge.log", "w"), stderr=subprocess.STDOUT,
    )
    t0 = time.time()
    st: dict = {}
    while time.time() - t0 < 40:
        try:
            st = bridge_get("/link_status")
            break
        except Exception:
            time.sleep(1)
    expect(st.get("mode") == "sitl", "WSL 桥 sitl 模式在线", str(st))
    # 🔴 钥域同源断言（2026-10-01 根修②）：桥的验签公钥必须与 backend 逐字节
    # 一致——bind 失败的旧桥假阳性在 mode=sitl 检查下不可见，钥域不一致在
    # ARM 才爆（bad_signature）。这里把同源性前移成编排期硬断言。
    bp = bridge_get("/engine_pub").get("engine_pub_hex", "")
    kp = api_get("/authz/engine/pub")
    kp = (kp.get("data") or kp).get("engine_pub_hex", "")
    expect(bp and bp == kp, "桥验签公钥与 backend 逐字节一致（钥域同源）",
           f"bridge={bp[:16]}… backend={kp[:16]}…")
    return [keepalive, bridge], stop_flag, keepalive, bridge


# ───────────────────────── [1] AUTH 全链 ─────────────────────────


ID_NUMBER = "11010119900101" + secrets.token_hex(2)  # 逐轮随机（B7 黑名单纪律）
SN = "FZ-SN-S1-" + secrets.token_hex(2)  # ⑥代 SN 绑定：桥 FZ_DEVICE_SERIAL 与登记同源（一证一机闭环）


def stage1_auth() -> tuple[dict, dict]:
    """登记→…→令牌+链上对账。返回 (tok, 材料)。"""
    from app.crypto.sm2 import decrypt as ecies_decrypt
    from app.crypto.sm2 import generate_keypair

    print("== [1] AUTH 全链（真链：登记→出证→受理→worker→取件→recordAuth 对账）==")
    holder_sk, holder_pk = generate_keypair()
    sn = SN
    rc, reg = api_post("/ra/register", {
        "username": "s1-" + secrets.token_hex(3),
        "id_number": ID_NUMBER,
        "cert_level": 3, "sn": sn, "user_pub_hex": holder_pk, "class_id": CLASS_ID,
    })
    expect(rc == 200 and reg["code"] == "ok", "1.1 登记承诺（RA 真实签发+链上）")
    cred = reg["data"]
    rc2, sub = api_post("/ra/sub-credentials", {
        "master_cred_hash_hex": cred["master_cred_hash_hex"],
        "salt_hex": cred["salt_hex"],
        "id_number": ID_NUMBER,
        "cert_level": 3, "sn": sn, "holder_pub_hex": holder_pk,
    })
    expect(rc2 == 200 and sub["code"] == "ok", "1.2 子凭证签发（一次性）")
    sub = sub["data"]

    plan_hash_hex = secrets.token_bytes(32).hex()
    nonce_hex = secrets.token_bytes(16).hex()
    binding = api_get(
        f"/authz/binding?class_id={CLASS_ID}&plan_hash_hex={plan_hash_hex}&nonce_hex={nonce_hex}"
    )["data"]
    expect("challenge_hex" in binding, "1.3 绑定面（HMAC 挑战+政策值）")

    start = bridge_post("/prove/start", {
        "plan_hash_hex": plan_hash_hex, "nonce_hex": nonce_hex, "class_id": CLASS_ID,
        "id_number": ID_NUMBER, "cert_level": 3, "sn": sn,
        "salt_hex": cred["salt_hex"], "id_prime_hex": sub["id_prime_hex"],
        "sig_hex": sub["sig_hex"], "expires_at": sub["expires_at"],
        "holder_sk_hex": holder_sk, "holder_pk_hex": holder_pk,
    }, timeout=30)
    task_id, case_id = start["task_id"], start["case_id"]
    prove_t_epoch = start["binding"]["t_epoch"]
    print(f"  [..] 1.4 桥接本机出证（task={task_id[:12]}…，interop zkc，~3 分钟）")
    t0 = time.time()
    status = "assembling"
    while status in ("assembling", "proving"):
        time.sleep(5)
        t = bridge_get(f"/prove/task/{task_id}")
        s = t.get("status") or t.get("data", {}).get("status")
        if s != status:
            status = s
            print(f"  [..] 状态：{status}（{time.time() - t0:.0f}s）")
        if status == "failed":
            print("  [FAIL] 出证失败：", str(t)[:300])
            raise SystemExit(1)
        if time.time() - t0 > 1500:
            raise SystemExit(1)
    expect(status == "done", f"1.4 桥接本机出证完成（{time.time() - t0:.0f}s，WSL interop zkc）")

    rc5, ap = api_post("/authz/apply", {
        "session_pk_hex": holder_pk,
        "sub_cred_message_hex": sub["message_hex"],
        "sub_sig_hex": sub["sig_hex"],
        "sub_cred_hash_hex": sub["sub_cred_hash_hex"],
        "nonce_hex": nonce_hex, "plan_hash_hex": plan_hash_hex,
        "class_id": CLASS_ID, "case_id": case_id,
        "rev_root_hex": api_get("/ra/revocation/snapshot")["data"]["root_hex"],
        "t_start": prove_t_epoch, "t_end": prove_t_epoch + 7200,
    })
    expect(rc5 == 200 and ap.get("ok") is True, "1.5 受理通过（实例核对+入队）",
           f"rc={rc5} {json.dumps(ap, ensure_ascii=False)[:200]}")
    receipt_code = ap["data"]["receipt_code"]

    t1 = time.time()
    rr = {"status": "waiting"}
    while time.time() - t1 < 120:
        rr = api_get(f"/authz/receipt/{receipt_code}")["data"]
        if rr["status"] != "waiting":
            break
        time.sleep(2)
    expect(rr["status"] == "ready", f"1.6 worker 真实验证→ready（{time.time() - t1:.0f}s）")

    payload = ecies_decrypt(holder_sk, bytes.fromhex(rr["token_cipher_hex"]))
    body, sig_hex = payload.rsplit(b"|", 1)
    tok = json.loads(body)
    ok("1.7 取件 ECIES 解密（会话私钥本地）")
    expect(tok["plan_hash"] == plan_hash_hex and tok["authId"] > 0, "1.8 令牌绑定+authId 贯穿")

    # 链上 recordAuth 对账（阶段一 ⑨⑪ 同构）
    from app.chain.client import ChainClient
    from app.chain.contracts import load_binding
    from app.chain.signer import TxSigner
    from app.kms import chain_ra_tx_key

    addr = json.loads((UAS / "contracts" / ".chain_addresses.json").read_text())
    client = ChainClient(rpc_url=os.environ.get("FZ_CHAIN_RPC", "http://127.0.0.1:8545"),
                         from_addr=TxSigner(chain_ra_tx_key()).address)
    fa = load_binding("FlightAuthRegistry", client, addr["FlightAuthRegistry"]["address"])
    rec = fa.call_fn("getAuth", [tok["authId"]])
    expect(rec[0].hex() == sm3_hex(body) and rec[6].hex() == sub["sub_cred_hash_hex"]
           and rec[7].hex() == sm3_hex((CASES / case_id / "proof.bin").read_bytes()),
           "1.9 链上 recordAuth 对账（tokenHash/subCredHash/proofDigest 三源一致）")
    expect(fa.call_fn("nonceUsed", [bytes.fromhex(nonce_hex)])[0] is True,
           "1.10 nonce 链上烧毁（recordAuth 内含）")
    expect(int(fa.call_fn("tokenAuthIds", [bytes.fromhex(sm3_hex(body))])[0]) == tok["authId"],
           "1.11 闸门键 tokenAuthIds 回读=authId")
    return tok, {"plan_hash_hex": plan_hash_hex, "case_id": case_id,
                 "master_cred_hash_hex": cred["master_cred_hash_hex"],
                 "token_payload_hex": payload.hex()}


# ───────────────────── [2]+[4] 真飞行（合规窗→超限取证，一飞到底） ─────────────────────


def stage_flight(tok: dict, mats: dict) -> dict:
    """合规采样 128（TRAIL 窗口）→继续爬升→固件围栏触发→事件。返回现场。"""
    print("== [2] 合规飞行（真 SITL：ARM→15-19m 带→2Hz 真采样 128）==")
    req = urllib.request.Request(
        f"{BRIDGE}/sitl/wait_gps?timeout_s=180",
        data=b"{}", headers={"Content-Type": "application/json"}, method="POST",
    )
    with opener().open(req, timeout=300) as r:
        wg = json.loads(r.read().decode())
    expect(wg.get("ok") is True, "2.1 GPS 锁（fix_type≥3）")

    r = bridge_post("/arm", {"token_payload_hex": mats["token_payload_hex"],
                             "plan_hash_hex": mats["plan_hash_hex"]}, timeout=120)
    expect(r.get("ok") is True, "2.2 闸门 ARM（真令牌：围栏参数确认+ACK）",
           json.dumps(r, ensure_ascii=False)[:200])
    alt_max_m = r.get("alt_max")
    expect(alt_max_m == tok["alt_max"], "2.3 围栏上限=令牌 alt_max（政策值 meters）")

    r = bridge_post("/telemetry/start", {"auth_id": r.get("auth_id"),
                                         "fence_state_hex": r.get("fence_state_hex")})
    expect(r.get("ok") is True, "2.4 遥测链 genesis 起链（authId+围栏态绑定）")

    state = {"n": 0, "breached": False, "window_clean": True, "stop": False,
             "peak_window_cm": 0, "peak_cm": 0}

    def sampler() -> None:
        while not state["stop"]:
            try:
                s = bridge_get(f"/telemetry/sitl_sample?t_epoch={int(time.time())}")
                if s.get("ok"):
                    state["n"] = s.get("n", state["n"])
                    alt = s.get("alt_cm", 0) or 0
                    state["peak_cm"] = max(state["peak_cm"], alt)
                    if state["n"] <= N_WINDOW:
                        state["peak_window_cm"] = max(state["peak_window_cm"], alt)
                        if alt > alt_max_m * 100:
                            state["window_clean"] = False
                    if s.get("fence_breached"):
                        state["breached"] = True
            except Exception:
                pass
            time.sleep(0.5)

    th = threading.Thread(target=sampler, daemon=True)
    th.start()
    print("  [..] 温和爬升至合规带（bang-bang 15-19m）…")

    def climb(pwm: int, hold_s: float = 0.9) -> dict:
        # /sitl/climb 的 pwm/hold_s 是 query 参数（POST body 不进 FastAPI 简单形参）
        req = urllib.request.Request(
            f"{BRIDGE}/sitl/climb?pwm={pwm}&hold_s={hold_s}",
            data=b"{}", headers={"Content-Type": "application/json"}, method="POST",
        )
        with opener().open(req, timeout=30) as r:
            return json.loads(r.read().decode())

    t0 = time.time()
    # ① 合规带控制直至窗口满
    while state["n"] < N_WINDOW and time.time() - t0 < 240:
        r = climb(1500, 0.5)
        alt = r.get("alt_cm")
        if alt is not None:
            pwm = 1620 if alt < ALT_BAND[0] else (1380 if alt > ALT_BAND[1] else 1480)
        else:
            pwm = 1620
        climb(pwm, 0.9)
    expect(state["n"] >= N_WINDOW, f"2.5 采样满 {N_WINDOW}（当前 {state['n']}）")
    expect(state["window_clean"], "2.6 合规窗全样本 <围栏（TRAIL 窗口可证明）",
           f"窗口峰 {state['peak_window_cm']}cm vs 围栏 {alt_max_m * 100}cm")
    ok(f"2.7 窗口峰高 {state['peak_window_cm']}cm（带内）")

    print("== [4] 超限取证（继续爬升→固件围栏触发→breach 事件）==")
    t1 = time.time()
    while not state["breached"] and time.time() - t1 < 360:
        climb(1750, 1.4)
    expect(state["breached"], "4.1 固件围栏触发（STATUSTEXT 捕获）",
           f"peak={state['peak_cm']}cm")
    ok(f"4.2 触发后峰高 {state['peak_cm']}cm（硬拦截实锤，围栏 {alt_max_m}m）")
    # 触发后采样一轮（超限样本入链+breach 事件生成——sitl_sample 内建）
    ev = None
    for _ in range(6):
        s = bridge_get(f"/telemetry/sitl_sample?t_epoch={int(time.time())}")
        if s.get("ok") and s.get("event"):
            ev = s["event"]
            break
        time.sleep(0.5)
    expect(ev is not None and ev.get("event_type") == 1, "4.3 breach 事件（固件权威源）")
    state["stop"] = True
    try:
        bridge_post("/sitl/disarm", {}, timeout=15)
        ok("4.4 DISARM 收尾")
    except Exception:
        pass
    state["event"] = ev
    state["alt_max_m"] = alt_max_m
    return state


# ───────────────────────── [3] TRAIL 合规证书 ─────────────────────────


def stage3_trail(state: dict, tok: dict) -> None:
    print("== [3] TRAIL 合规证书（锚定→出证→下载→第三方复验）==")
    r = bridge_post("/telemetry/anchor", {}, timeout=120)
    expect(r.get("ok") is True and r.get("anchored", 0) >= 1,
           "3.1 检查点真链锚定（设备签+围栏态）", str(r)[:200])

    alt_max_cm = tok["alt_max"] * 100  # TRAIL 电路口径=cm（×100 在出证装配面）
    r = bridge_post("/prove/trail/start", {"alt_max_cm": alt_max_cm}, timeout=30)
    expect(r.get("task_id") and r.get("case_id") and r.get("chain_head_hex"),
           "3.2 TRAIL 出证任务受理", str(r)[:200])
    task = r["task_id"]
    anchor_head_hex = r["chain_head_hex"]
    print("  [..] 3.3 TRAIL 本机出证中（interop zkc ~45s）…")
    t0 = time.time()
    status = "assembling"
    while status in ("assembling", "proving"):
        time.sleep(4)
        t = bridge_get(f"/prove/task/{task}")
        s = t.get("status") or t.get("data", {}).get("status")
        if s != status:
            status = s
            print(f"  [..] 状态：{status}（{time.time() - t0:.0f}s）")
        if status == "failed":
            print("  [FAIL] TRAIL 出证失败：", str(t)[:300])
            raise SystemExit(1)
        if time.time() - t0 > 600:
            raise SystemExit(1)
    case_id = t.get("case_id") or t.get("data", {}).get("case_id")
    expect(case_id is not None, "3.3' 出证任务 case_id 在案", str(t)[:200])
    expect(status == "done", f"3.3 TRAIL 出证完成（{time.time() - t0:.0f}s）")

    out_dir = UAS / "zksvc" / "target" / "probe" / f"s1_case_{case_id[:8]}"
    out_dir.mkdir(parents=True, exist_ok=True)
    verdict = None
    for name in ("proof.bin", "verifier_param.bin", "verdict.json", "instances.json",
                 "expected.json", "binding.json"):
        with opener().open(f"{BRIDGE}/prove/case/{case_id}/{name}", timeout=60) as resp:
            data = resp.read()
        (out_dir / name).write_bytes(data)
        if name == "verdict.json":
            verdict = json.loads(data)
    expect(verdict.get("verdict") == "OK", "3.4 判决件三件套下载（verdict=OK）",
           json.dumps(verdict)[:150])
    print(f"  [..] proof={verdict['bytes']:,}B prove={verdict['prove_s']:.1f}s")

    env = {**os.environ, "FZ_ZK_ALLOW_TRAIL": "1",
           "FZ_TRAIL_CANONICAL_SPEC": str(UAS / "zksvc" / "tests" / "trail_canonical_spec.json")}
    # 2026-10 电路换代：期望绑定必携三字段（chain_head‖alt_max_cm‖t_start）
    # ——第三方复验用案卷随卷 expected.json（不自建旧形态单链头期望）。
    exp = out_dir / "expected.json"
    exp_full = json.loads(exp.read_text(encoding="utf-8"))
    assert "alt_max_cm" in exp_full and "t_start" in exp_full, f"案卷期望缺换代字段: {sorted(exp_full)}"
    proc = subprocess.run(
        [str(ZKC), "verify-instances",
         "--instances", str(out_dir / "instances.json"),
         "--proof", str(out_dir / "proof.bin"),
         "--vp", str(out_dir / "verifier_param.bin"),
         "--expected", str(exp)],
        capture_output=True, text=True, env=env,
    )
    expect(proc.returncode == 0 and "OK" in (proc.stdout + proc.stderr),
           "3.5 第三方独立复验（verify-instances：轨迹样本零披露）",
           (proc.stdout + proc.stderr)[-200:])
    exp.write_text(json.dumps({**exp_full, "chain_head_hex": "ab" * 32}), encoding="utf-8")
    proc = subprocess.run(
        [str(ZKC), "verify-instances",
         "--instances", str(out_dir / "instances.json"),
         "--proof", str(out_dir / "proof.bin"),
         "--vp", str(out_dir / "verifier_param.bin"),
         "--expected", str(exp)],
        capture_output=True, text=True, env=env,
    )
    expect(proc.returncode == 2, "3.6 篡改链头复验拒绝（exit 2）")


# ───────────────────────── [5] 令状→追溯 ─────────────────────────


def stage5_warrant(state: dict, tok: dict, mats: dict) -> None:
    print("== [5] 审计令状→解锁→追溯（事件→个人闭环）==")
    # 账户批：/audit 面走会话 Cookie（_sess_cookie 按路径分发）；引擎面令牌仍同源随行
    hdr = {"X-Engine-Token": os.environ.get("FZ_ENGINE_TOKEN", "")}
    ev = state["event"]
    # 事件上链（recordEvent——围栏触发 eventType=1）
    rc, r = api_post("/engine/event", {
        "auth_id": tok["authId"],
        "event_type": ev["event_type"],
        "event_hash_hex": ev["event_hash_hex"],
    }, headers=hdr)  # R3-0.5：引擎令牌必须随调用（hdr 里躺着不传=401，第 6~7 轮实测）
    expect(rc == 200 and r.get("ok") is True, "5.1 违规事件真链上链（recordEvent）",
           str(r)[:160])

    rc, w = api_post("/audit/warrants", {
        "case_no": f"S1-{secrets.token_hex(4)}",
        "legal_basis_hash_hex": sm3_hex(b"S1-warrant-legal-basis"),
        "target_auth_id": tok["authId"],
        "note": "S1 全真串联：固件围栏触发事件追溯",
    }, headers=hdr)
    expect(rc == 200 and w.get("code") == "ok", "5.2 令状创建（logWarrant 上链）", str(w)[:200])
    wh = w["data"]["warrant_hash_hex"]

    # 无令状解锁负例
    ghost = sm3_hex(b"s1-ghost" + secrets.token_bytes(8))
    rc2, bad = api_post(f"/audit/warrants/{ghost}/unlock",
                        {"master_cred_hash_hex": mats["master_cred_hash_hex"]}, headers=hdr)
    expect(rc2 in (400, 403, 404) and (bad.get("code") in ("warrant_not_found", "warrant_not_on_chain", "missing_collab_code")),
           "5.3 无令状解锁拒绝（流程双控第一关）", f"rc={rc2} {str(bad)[:120]}")

    # 机构管理员出具随案协作函（账户批：/ra 协作面=管理员会话门禁；
    # FZC2：出具只带令状哈希——凭证由服务端从授权链解析，函-令状-凭证三方绑定）
    rc4, cc = api_post("/ra/collab-code",
                       {"warrant_hash_hex": wh})
    expect(rc4 == 200 and cc.get("code") == "ok" and cc.get("data", {}).get("code"),
           "5.4 RA 协作函出具（FZC2 函-令状绑定）", str(cc)[:160])

    rc3, unl = api_post(f"/audit/warrants/{wh}/unlock",
                        {"collab_code": cc["data"]["code"]}, headers=hdr)
    expect(rc3 == 200 and unl.get("code") == "ok", "5.4' RA 协作解锁（unwrap 实名）", str(unl)[:200])
    expect(unl["data"]["unlocked"]["username"].startswith("s1-"),
           "5.5 解锁面=注册实名（通道②密文）")

    tr = api_get(f"/audit/warrants/{wh}/trace", headers=hdr)
    expect(tr.get("code") == "ok", "5.6 追溯视图（链上单一事实源）", str(tr)[:120])
    trace = tr["data"]
    rec = trace["chain_trace"]["auth_record"]
    expect(rec is not None and int(rec["status"]) == 0 and rec["proof_digest"],
           "5.7 授权记录链上回读（authId 贯穿）")
    cps = trace["chain_trace"]["checkpoints"]
    expect(bool(cps) and cps[0]["seq"] >= 1, "5.8 检查点留痕链上回读")
    expect(trace["warrant"]["unlocked"]["username"].startswith("s1-"),
           "5.9 追溯闭环：围栏事件→令状→实名（全链留痕）")


# ───────────────────────── 主流程 ─────────────────────────


def main() -> int:
    t_all = time.time()
    resources: list = []
    stop_flag = None
    try:
        resources, stop_flag, _ka, _br = stage0()
        tok, mats = stage1_auth()
        state = stage_flight(tok, mats)
        stage3_trail(state, tok)
        stage5_warrant(state, tok, mats)
        mins = (time.time() - t_all) / 60
        print(f"\n== S1 全真串联全绿：{_checks} 项断言 [OK] ==")
        print(f"== 单一判决行：authId={tok['authId']} 贯穿 | 真链+真证明+真 SITL+真围栏 | "
              f"全程 {mins:.1f} 分钟 | 中途零替身 ==")
        return 0
    finally:
        if stop_flag is not None:
            stop_flag.set()
        try:
            bridge_post("/sitl/disarm", {}, timeout=8)
        except Exception:
            pass
        for p in resources:
            try:
                p.kill()
            except Exception:
                pass
        # 杀 wsl.exe 启动器≠杀远端进程（㊿+38 假活教训）——WSL 侧 uvicorn 必须补刀
        wsl_root("systemctl stop fz-sitl 2>/dev/null; "
                 "pkill -f 'uvicorn server:app' 2>/dev/null; true")


if __name__ == "__main__":
    raise SystemExit(main())
