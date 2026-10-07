# -*- coding: utf-8 -*-
"""安全防御链实弹套件（S1~S12）——环节×攻击形态矩阵，一键运行出统一报告。

对照 docs/三大测试体系设计方案.md §3.2。原则：
- 不是从零造防线测试——收拢既有 e2e/单测的负例构造，对**运行中的真栈**实弹；
- 每条负例=双段断言：①攻击被拦（状态码/拒绝码）②审计痕迹在案
  （backend /metrics 计数增量、库内拒绝态行、桥 audit 面 denial 行）；
- 任一攻击实际得手（拿到本不该有的数据/状态）= fail(attack_success=True)
  ⟹ 整场 verdict=failed（报告引擎硬规则）；
- 破坏性操作（杀 worker/停桥）后必须恢复验证：worker 接管孤儿任务、
  桥 link_status 正常+审计库跨重启存活；
- 单变量原则：每个负例只动被测维度，其余前置保持有效（对照项/正例控制）。

用法（cd uas/backend）：
    .venv/Scripts/python.exe scripts/security_chain.py            # 全量（默认）
    .venv/Scripts/python.exe scripts/security_chain.py --quick    # 跳过真出证轴
    .venv/Scripts/python.exe scripts/security_chain.py --recover  # 含 429 真等 300s 窗口恢复
    .venv/Scripts/python.exe scripts/security_chain.py --destructive  # 含 backend 重启守卫实弹

前置：backend(8000, 真链档)+bridge(8100, SITL)+worker 在线（scripts/demo_up.py）；
种子账户 auditor/admin123（首登激活语义）或 %TEMP%\\fz_accounts_seed.txt。
预算：全量含 2 次真出证（AUTH 电路 ~90-180s/次）+真 ARM+杀 worker+停桥，
总时长约 12~20 分钟；超 40 分钟预算时用 --quick。

诚实边界（默认档跳过、xfail 标注，非软通道）：
- S2 300s 限速窗口恢复：仅 --recover 档真等；
- S11 backend 重启启动守卫：仅 --destructive 档执行（栈属主会话所有）。
测试专用注记：S10 复原 worker 以 FZ_WORKER_LEASE_S=60 拉起（demo 缺省 1200）
——测试预算内接管孤儿任务的租约 knob，仅测试窗使用，报告中如实标注。
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

UAS = Path(__file__).resolve().parents[2]
BACKEND = UAS / "backend"
sys.path.insert(0, str(BACKEND))

from scripts.testkit.report import ReportBuilder  # noqa: E402

# 本套件 env_error 一律传字符串详情——适配层归一为 report.py 期望的 dict 形态
# （不改动共享底盘文件）。
from scripts.testkit import report as _tkreport  # noqa: E402

_orig_env_error = _tkreport.Module.env_error


def _env_error_str(self, name, detail=None):  # noqa: ANN001, ANN202
    if isinstance(detail, str):
        detail = {"detail": detail}
    _orig_env_error(self, name, detail=detail)


_tkreport.Module.env_error = _env_error_str

API = "http://127.0.0.1:8000"
BRIDGE = "http://127.0.0.1:8100"
PREFIX = "sec_chain"           # 测试数据专用前缀（清理判据）
WSL_BRIDGE_SH = "/mnt/d/fz_bridge_tmp/_fz_bridge_start.sh"
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
CREATE_NEW_CONSOLE = 0x10 if os.name == "nt" else 0

# 运行期共享（main() 装配）
RB = None
SEC = {"matrix": [], "races": [], "rate": {}, "recovery": [], "honesty": []}
CASES_DIR = BACKEND / "fz-zk-cases"


# ---------------------------------------------------------------- HTTP 基座
def http(method, url, body=None, headers=None, timeout=30.0):
    """返回 (status, json, latency_ms, request_id)；连接级失败 status=None。"""
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    t0 = time.perf_counter()
    try:
        with OPENER.open(req, timeout=timeout) as r:
            raw = r.read().decode()
            rid = (r.headers.get("X-Request-ID") or "")
            try:
                return r.status, json.loads(raw), (time.perf_counter() - t0) * 1000, rid
            except ValueError:
                return r.status, {"_raw": raw[:200]}, (time.perf_counter() - t0) * 1000, rid
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        rid = (e.headers.get("X-Request-ID") or "") if e.headers else ""
        try:
            return e.code, json.loads(raw), (time.perf_counter() - t0) * 1000, rid
        except ValueError:
            return e.code, {"_raw": raw[:200]}, (time.perf_counter() - t0) * 1000, rid
    except Exception as e:  # noqa: BLE001  连接拒绝/超时=transport 层
        return None, {"_err": f"{type(e).__name__}: {e}"}, (time.perf_counter() - t0) * 1000, ""


def get(path, **kw):
    return http("GET", API + path, **kw)


def post(path, body=None, **kw):
    return http("POST", API + path, body=body, **kw)


def bget(path, **kw):
    return http("GET", BRIDGE + path, **kw)


def bpost(path, body=None, **kw):
    return http("POST", BRIDGE + path, body=body, **kw)


def cookie_of(sess) -> str:
    return "; ".join(f"{k}={v}" for k, v in sess.cookies.get_dict().items())


# ---------------------------------------------------------------- 观测基座
def metrics() -> dict:
    """/metrics=Prometheus 纯文本——独立请求解析（http() 走 JSON 信封语义）。"""
    req = urllib.request.Request(API + "/metrics", headers={"Content-Type": "text/plain"})
    try:
        with OPENER.open(req, timeout=10) as r:
            text = r.read().decode()
    except Exception:  # noqa: BLE001
        return {}
    out = {}
    for line in text.splitlines():
        if " " in line:
            k, v = line.rsplit(" ", 1)
            try:
                out[k] = float(v)
            except ValueError:
                pass
    return out


def mkey(path: str, code: int) -> str:
    return f'fz_requests_total{{code="{code}",path="{path}"}}'


def mdelta(before: dict, after: dict, key: str) -> float:
    return (after.get(key, 0.0) - before.get(key, 0.0)) if key else -1.0


_DB = None


def db() -> sqlite3.Connection:
    global _DB
    if _DB is None:
        _DB = sqlite3.connect(str(BACKEND / "feizheng.db"), timeout=10)
        _DB.row_factory = sqlite3.Row
    return _DB


def db_one(sql, args=()):
    row = db().execute(sql, args).fetchone()
    return dict(row) if row else None


def db_val(sql, args=(), default=None):
    row = db().execute(sql, args).fetchone()
    return (list(row)[0] if row else default)


def db_count(sql, args=()) -> int:
    return int(db_val(sql, args, 0))


# ---------------------------------------------------------------- 栈操作面
def worker_pids() -> list[int]:
    out = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "Get-CimInstance Win32_Process -Filter \"name='python.exe' and "
         "commandline like '%app.zk.worker%'\" | Select-Object -ExpandProperty processid"],
        capture_output=True).stdout.decode("gbk", errors="replace")
    return sorted(int(t) for t in out.split() if t.isdigit())


def backend_pids() -> list[int]:
    out = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "Get-CimInstance Win32_Process -Filter \"name='python.exe' and "
         "commandline like '%uvicorn app.main%'\" | Select-Object -ExpandProperty processid"],
        capture_output=True).stdout.decode("gbk", errors="replace")
    return sorted(int(t) for t in out.split() if t.isdigit())


def kill_workers(pids: list[int]) -> None:
    for pid in pids:
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True)


def load_persisted_keys() -> None:
    """%TEMP% 持久钥回注进程 env（demo_up 同源纪律——run3 实弹教训：本地派生
    HMAC 挑战（FZ_AUTHZ_BINDING_KEY）缺钥即回退确定性域钥，与在线服务派生
    键空间分叉——S9-4 对拍 rc=2 的根因）。"""
    t = Path(tempfile.gettempdir())
    for var, fname in (
        ("FZ_ENGINE_SK", "fz_engine_sk.txt"), ("FZ_ENGINE_TOKEN", "fz_engine_token.txt"),
        ("FZ_RA_SK", "fz_ra_sk.txt"), ("FZ_RA_OPS_TOKEN", "fz_ra_ops_token.txt"),
        ("FZ_WRAP_KEY", "fz_wrap_key.txt"), ("FZ_AUTHZ_BINDING_KEY", "fz_authz_binding_key.txt"),
        ("FZ_AUDIT_TOKEN", "fz_audit_token.txt"),
    ):
        p = t / fname
        if p.is_file() and not os.environ.get(var):
            try:
                os.environ[var] = p.read_text(encoding="utf-8").strip()
            except OSError:
                pass


def worker_env(lease_s: int | None = None) -> dict:
    """worker 复原 env（demo_up 同源纪律：%TEMP% 持久钥回注——服务重启间换钥
    会让在途回执/已发令牌/已签子凭证全部失效）。lease_s=测试租约 knob。"""
    env = os.environ.copy()
    env["FZ_CHAIN_ANCHOR"] = "real"
    env["FZ_ZKSVC_DIR"] = str(UAS / "zksvc")
    env["FZ_ZK_CASES_DIR"] = str(CASES_DIR)
    t = Path(tempfile.gettempdir())
    for var, fname in (
        ("FZ_ENGINE_SK", "fz_engine_sk.txt"), ("FZ_ENGINE_TOKEN", "fz_engine_token.txt"),
        ("FZ_RA_SK", "fz_ra_sk.txt"), ("FZ_RA_OPS_TOKEN", "fz_ra_ops_token.txt"),
        ("FZ_WRAP_KEY", "fz_wrap_key.txt"), ("FZ_AUTHZ_BINDING_KEY", "fz_authz_binding_key.txt"),
        ("FZ_AUDIT_TOKEN", "fz_audit_token.txt"),
    ):
        p = t / fname
        if p.is_file():
            env[var] = p.read_text(encoding="utf-8").strip()
    if lease_s:
        env["FZ_WORKER_LEASE_S"] = str(lease_s)
    return env


def spawn_worker(lease_s: int | None = None) -> subprocess.Popen:
    py = BACKEND / ".venv" / "Scripts" / "python.exe"
    return subprocess.Popen(
        [str(py), "-m", "app.zk.worker"], cwd=str(BACKEND),
        env=worker_env(lease_s), creationflags=CREATE_NEW_CONSOLE)


def bridge_stop() -> None:
    subprocess.run(
        ["wsl", "-u", "root", "bash", "-c",
         "systemctl stop fz-bridge 2>/dev/null; pkill -f 'uvicorn server:app' 2>/dev/null; true"],
        capture_output=True, timeout=60)


def bridge_start() -> None:
    subprocess.run(["wsl", "-u", "root", "systemctl", "reset-failed", "fz-bridge"],
                   capture_output=True, timeout=30)
    subprocess.run(
        ["wsl", "-u", "root", "systemd-run", "--unit=fz-bridge", "--uid=ouye", "bash", WSL_BRIDGE_SH],
        capture_output=True, timeout=30)


def wait_http(url: str, timeout_s: float = 60) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        st, _, _, _ = http("GET", url, timeout=4)
        if st == 200:
            return True
        time.sleep(0.8)
    return False


# ---------------------------------------------------------------- 业务助手
def seed_password(marker: str, default: str) -> str:
    env = os.environ.get("FZ_SEED_AUDITOR_PASSWORD" if marker == "auditor" else "FZ_SEED_ADMIN_PASSWORD")
    if env:
        return env
    seed = Path(tempfile.gettempdir()) / "fz_accounts_seed.txt"
    if seed.is_file():
        for line in seed.read_text(encoding="utf-8").splitlines():
            if marker in line:
                tail = line.rsplit(" ", 1)[-1].strip()
                if tail:
                    return tail
    return default


def inst_sessions():
    """审计员/管理员会话（首登激活语义）。"""
    from scripts.script_auth import script_login

    aud = script_login(API, "auditor", seed_password("auditor", "auditor123"))
    adm = script_login(API, "admin", seed_password("admin", "admin123"))
    return aud, adm


def ra_register(username: str) -> tuple[dict, str, str]:
    """HTTP 登记承诺（当前纪元服务端域钥封装）。返回 (cred, sk, pk)。"""
    from app.crypto.sm2 import generate_keypair

    sk, pk = generate_keypair()
    sn = "FZ-SEC-" + secrets.token_hex(3).upper()
    # 证件号逐轮随机（18 字）：B7 重注册禁入（0019 批）——S8 撤销后固定证件号
    # 入黑名单，二次运行必 409 id_revoked_before（非契约错误）。签发/出证面
    # 逐级携带同号（issue_sub/full_prove/S8-4）——同凭证生命周期同号。
    id_number = "11010119900101" + secrets.token_hex(2)
    st, r, _, _ = post("/ra/register", {
        "username": username, "id_number": id_number,
        "cert_level": 3, "sn": sn,
        "user_pub_hex": pk, "class_id": 1,
    }, timeout=60)
    if st != 200 or r.get("code") != "ok":
        raise RuntimeError(f"ra_register 失败: {st} {str(r)[:200]}")
    data = r["data"]
    data["sn"] = sn  # 响应未必回带——子凭证重签/撤销轴复用同 sn
    data["id_number"] = id_number  # 同上——签发预检/出证 id 域逐级同源
    return data, sk, pk


def issue_sub(cred: dict, sn: str) -> tuple[dict, str, str]:
    """子凭证签发（一次性出示钥批同构——每次全新 pk′）。返回 (sub, sk′, pk′)。"""
    from app.crypto.sm2 import generate_keypair

    sub_sk, sub_pk = generate_keypair()
    st, r, _, _ = post("/ra/sub-credentials", {
        "master_cred_hash_hex": cred["master_cred_hash_hex"], "salt_hex": cred["salt_hex"],
        "id_number": cred["id_number"], "cert_level": 3, "sn": sn,
        "holder_pub_hex": sub_pk,
    }, timeout=60)
    if st != 200 or r.get("code") != "ok":
        raise RuntimeError(f"issue_sub 失败: {st} {str(r)[:200]}")
    return r["data"], sub_sk, sub_pk


def dummy_case() -> str:
    """受理面前置完整性用假案卷（gate 在内容核对前拦截——同 test_revoke 形态）。"""
    case_id = secrets.token_hex(8)
    d = CASES_DIR / case_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "proof.bin").write_bytes(b"sec-chain-dummy")
    (d / "verifier_param.bin").write_bytes(b"sec-chain-dummy")
    (d / "instances.json").write_text(json.dumps({"instances": ["00" * 32] * 25}), encoding="utf-8")
    return case_id


def apply_body(sub: dict, session_pk: str, plan_hex: str, nonce_hex: str, case_id: str,
               t_start: int, rev_root: str, t_end: int | None = None) -> dict:
    return {
        "session_pk_hex": session_pk,
        "sub_cred_message_hex": sub["message_hex"], "sub_sig_hex": sub["sig_hex"],
        "sub_cred_hash_hex": sub["sub_cred_hash_hex"],
        "nonce_hex": nonce_hex, "plan_hash_hex": plan_hex, "class_id": 1,
        "case_id": case_id, "rev_root_hex": rev_root,
        "t_start": t_start, "t_end": t_end or (t_start + 7200),
    }


def rev_root_now() -> str:
    st, r, _, _ = get("/ra/revocation/snapshot", timeout=15)
    if st != 200:
        raise RuntimeError(f"snapshot 失败: {st}")
    return r["data"]["root_hex"]


def full_prove(sub: dict, sub_sk: str, sub_pk: str, holder_pk: str) -> dict:
    """真出证全程：绑定→桥接 prove/start→轮询 done。返回（binding/case_id/t_epoch）。"""
    plan_hex = secrets.token_bytes(32).hex()
    nonce_hex = secrets.token_bytes(16).hex()
    st, b, _, _ = get(f"/authz/binding?class_id=1&plan_hash_hex={plan_hex}&nonce_hex={nonce_hex}", timeout=15)
    if st != 200 or "challenge_hex" not in b.get("data", {}):
        raise RuntimeError(f"binding 失败: {st} {str(b)[:160]}")
    t_epoch = b["data"]["t_epoch"]
    # 串行闸让行（共享栈多套件并发）：429 prove_busy=桥上已有出证任务——
    # 瞬态竞争非环境损坏，退避重试（上限 12 分钟）后继续；其余错误照抛。
    deadline = time.time() + 720
    while True:
        st, s, _, _ = bpost("/prove/start", {
            "plan_hash_hex": plan_hex, "nonce_hex": nonce_hex, "class_id": 1,
            "id_number": sub["_id"], "cert_level": 3, "sn": sub["_sn"],
            "salt_hex": sub["_salt"], "id_prime_hex": sub["id_prime_hex"],
            "sig_hex": sub["sig_hex"], "expires_at": sub["expires_at"],
            "holder_sk_hex": sub_sk, "holder_pk_hex": sub_pk,
        }, timeout=30)
        if st == 200 and s.get("task_id"):
            break
        if st == 429 and (s or {}).get("code") == "prove_busy" and time.time() < deadline:
            print("  [..] 串行闸忙（他套件出证中）——45s 后让行重试 …", flush=True)
            time.sleep(45)
            continue
        raise RuntimeError(f"prove/start 失败: {st} {str(s)[:200]}")
    task_id, case_id = s["task_id"], s["case_id"]
    # 权威时间锚=桥侧绑定的 t_epoch（桥 /prove/start 内部重取绑定并烙入实例 21
    # ——本地预取值与之差 1 秒即 409 instance_mismatch（run3 实弹定谳）；与
    # e2e_frontend_api 同源取 start["binding"]["t_epoch"]）
    t_epoch = (s.get("binding") or {}).get("t_epoch", t_epoch)
    t0, status = time.time(), "assembling"
    while status in ("assembling", "proving"):
        time.sleep(4)
        _, t, _, _ = bget(f"/prove/task/{task_id}", timeout=15)
        s2 = t.get("status") or t.get("data", {}).get("status")
        if s2 and s2 != status:
            status = s2
        if status == "failed":
            raise RuntimeError(f"出证失败: {str(t)[:200]}")
        if time.time() - t0 > 900:
            raise RuntimeError("出证超时 900s")
    if status != "done":
        raise RuntimeError(f"出证终态异常: {status}")
    return {"plan_hash_hex": plan_hex, "nonce_hex": nonce_hex, "t_epoch": t_epoch,
            "task_id": task_id, "case_id": case_id, "prove_s": round(time.time() - t0, 1),
            "holder_pk": holder_pk}


# ================================================================ S1 会话隔离
def s1_session_isolation():
    m = RB.module("S1", "会话隔离——角色×面交叉 403/401 全遍历（自有面不实弹）")
    pilot = None
    try:
        from scripts.script_auth import script_login
        pilot = script_login(API, PREFIX + "_pilot", "SecChain-Pw-1")
    except Exception as e:  # noqa: BLE001
        m.env_error("S1-0 飞手测试会话", detail=str(e)[:160])
        return
    aud_ck, adm_ck = cookie_of(INST_AUD), cookie_of(INST_ADM)
    before = metrics()
    # 面=审计/机构/吊销/飞手资料；own[角色]=该角色自有面集合——自有面不请求
    # （POST 自有面会真出函/真吊销，非探测语义），只实弹**非自有**面（攻击轴）。
    faces = [
        ("GET", "/audit/warrants", None, "audit"),
        ("GET", "/admin/overview", None, "admin"),
        ("POST", "/ra/revoke", {"master_cred_hash_hex": "ab" * 32, "reason": "S1 越权探测",
                                "sig_hex": "00" * 64, "epoch": 1}, "revoke"),
        ("POST", "/auth/profile", {"id_number": "110101199001011234", "cert_level": 3,
                                   "sn": "FZ-SEC-S1", "class_id": 1}, "pilot"),
    ]
    own = {"auditor": {"audit"}, "admin": {"admin", "revoke"}, "pilot": {"pilot"}}
    roles = [("pilot", cookie_of(pilot)), ("auditor", aud_ck),
             ("admin", adm_ck), ("anon", None)]
    granted, lat_rows, rid_seen = [], [], True
    for role_name, ck in roles:
        for method, path, body, face in faces:
            if role_name != "anon" and face in own.get(role_name, set()):
                continue  # 自有面跳过（非攻击轴）
            st, r, ms, rid = http(method, API + path, body=body,
                                  headers={"Cookie": ck} if ck else None, timeout=20)
            if rid is None:
                rid_seen = False
            rej = (r or {}).get("detail", {}).get("code") if isinstance(r, dict) else None
            exp = 401 if role_name == "anon" else 403
            okc = st == exp
            lat_rows.append({"role": role_name, "face": face, "status": st,
                             "rej_code": rej, "ms": round(ms, 1)})
            name = f"S1-{role_name}→{face}"
            if okc:
                m.pass_(name, defense_ref="app/accounts/deps.py:require_role",
                        latency_ms=round(ms, 1), detail={"status": st, "rej_code": rej})
            else:
                granted.append(name)
                m.fail(name, expected=str(exp), actual=str(st),
                       defense_ref="app/accounts/deps.py:require_role", attack_success=True,
                       detail={"code": rej})
    after = metrics()
    # 审计痕迹：metrics 403/401 计数增量（每被拒面≥1）+X-Request-ID 贯穿
    trace_ok = True
    for path in ("/audit/warrants", "/admin/overview", "/ra/revoke", "/auth/profile"):
        for code in (403, 401):
            d = mdelta(before, after, mkey(path, code))
            if d < 1:
                trace_ok = False
                m.fail(f"S1-痕迹 {path}:{code}", expected="≥1", actual=str(d),
                       defense_ref="app/main.py:obs_middleware")
    if rid_seen and trace_ok:
        m.pass_("S1-痕迹 越权拒绝全数落 /metrics+X-Request-ID 贯穿（8 面×2 码全增量）",
                defense_ref="app/main.py:obs_middleware",
                detail={"attack_rows": len(lat_rows), "request_id_all": True})
    SEC["matrix"].append({"module": "S1 会话隔离", "rows": lat_rows})
    SEC["honesty"].append("S1 自有面不实弹（POST 自有面=真出函/真吊销，非探测语义）——"
                          "攻击轴=非自有交叉面 403/401 全遍历 12 格+匿名 401×4。")
    if granted:
        RB.abort(f"S1 攻击得手: {granted}")


# ================================================================ S2 挑战+限速
def s2_challenge_ratelimit(opts):
    m = RB.module("S2", "挑战一次性+登录限速 429（login|ip|username 键控）")
    from scripts.script_auth import script_login

    # 限速键=ip|username——测试用户每次运行唯一后缀（前轮 429 残键在 300s 窗内
    # 会污染重跑——单变量纪律：本轮攻击只落在本轮专用键上）
    rt_name = f"{PREFIX}_rt_{secrets.token_hex(3)}"
    lim_name = f"{PREFIX}_limit_{secrets.token_hex(3)}"
    iso_name = f"{PREFIX}_iso_{secrets.token_hex(3)}"

    # ---- ① 挑战 nonce 一次性（重放拒） ----
    rt = script_login(API, rt_name, "SecChain-Pw-1")
    st, ch, _, _ = post(f"/auth/challenge/{rt_name}", timeout=15)
    nonce = ch["data"]["nonce_hex"]
    from app.crypto.sm2 import sign as sm2_sign
    sig = sm2_sign(rt.sk, f"FZ-AUTH-LOGIN|{nonce}".encode())
    body = {"username": rt_name, "nonce_hex": nonce, "sig_hex": sig}
    b = metrics()
    st1, r1, ms1, _ = post("/auth/login", body, timeout=15)
    st2, r2, ms2, _ = post("/auth/login", body, timeout=15)
    consumed = db_val("SELECT consumed_ts FROM auth_challenges WHERE nonce_hex=?", (nonce,))
    if st1 == 200 and st2 == 401 and (r2 or {}).get("code") == "bad_challenge" and consumed:
        m.pass_("S2-1 挑战 nonce 重放 → 401 bad_challenge（一次性消费）",
                defense_ref="app/accounts/service.py:login", latency_ms=round(ms2, 1),
                detail={"first": st1, "replay": st2, "consumed_ts": str(consumed)[:19]})
    else:
        m.fail("S2-1 挑战 nonce 重放", expected="200→401 bad_challenge",
               actual=f"{st1}→{st2}", defense_ref="app/accounts/service.py:login",
               attack_success=(st2 == 200))
    a = metrics()
    d401 = mdelta(b, a, mkey("/auth/login", 401))
    if d401 >= 1:
        m.pass_("S2-1痕迹 重放拒绝落 /metrics(401)", defense_ref="app/main.py:obs_middleware",
                detail={"delta": d401})
    else:
        m.fail("S2-1痕迹 /metrics(401)", expected="≥1", actual=str(d401),
               defense_ref="app/main.py:obs_middleware")

    # ---- ② 429 限流实弹（专用用户连发→恰第 11 发触发） ----
    lim = script_login(API, lim_name, "SecChain-Pw-1")  # 成功登录会 reset 该键
    st, ch2, _, _ = post(f"/auth/challenge/{lim_name}", timeout=15)
    nonce_l = ch2["data"]["nonce_hex"]
    bad = {"username": lim_name, "nonce_hex": nonce_l, "sig_hex": "00" * 64}
    curve, hit429_at = [], None
    flood_t0 = time.time()
    b = metrics()
    for i in range(1, 15):
        st, r, ms, _ = post("/auth/login", bad, timeout=15)
        curve.append({"n": i, "status": st, "code": (r or {}).get("code"), "ms": round(ms, 1)})
        if st == 429 and hit429_at is None:
            hit429_at = i
            break
    a = metrics()
    d429 = mdelta(b, a, mkey("/auth/login", 429))
    ok_curve = hit429_at == 11 and all(c["status"] == 401 for c in curve[:10])
    SEC["rate"] = {"user": lim_name, "window_s": 300, "max_attempts": 10,
                   "trigger_at": hit429_at, "attempts": curve,
                   "flood_started": time.strftime("%H:%M:%S", time.localtime(flood_t0))}
    if ok_curve and d429 >= 1:
        m.pass_("S2-2 429 限流实弹：10 发 401 后第 11 发触发 429（窗口 300s）",
                defense_ref="app/accounts/service.py:AttemptLimiter",
                latency_ms=curve[-1]["ms"], detail={"trigger_at": hit429_at, "metric429": d429})
        m.pass_("S2-2痕迹 429 落 /metrics(429)", defense_ref="app/main.py:obs_middleware",
                detail={"delta": d429})
    else:
        m.fail("S2-2 429 限流实弹", expected="第 11 发 429", actual=f"trigger_at={hit429_at} curve={curve[-3:]}",
               defense_ref="app/accounts/service.py:AttemptLimiter",
               attack_success=hit429_at is None)

    # ---- ③ 键控隔离：专用用户限速不影响他人（auditor 挑战照常+全新用户可登录） ----
    st_a, _, _, _ = post("/auth/challenge/auditor", timeout=15)
    iso = script_login(API, iso_name, "SecChain-Pw-1")
    st_w, w, _, _ = get("/auth/whoami", headers={"Cookie": cookie_of(iso)}, timeout=15)
    if st_a == 200 and st_w == 200 and (w or {}).get("data", {}).get("username") == iso_name:
        m.pass_("S2-3 限速键控隔离：limit 用户 429 中，auditor 挑战 200+新用户登录 200",
                defense_ref="app/accounts/router.py:_client_key",
                detail={"auditor_challenge": st_a, "iso_login": st_w})
    else:
        m.fail("S2-3 限速键控隔离", expected="auditor 200/iso 200",
               actual=f"{st_a}/{st_w}", defense_ref="app/accounts/router.py:_client_key")

    # ---- ④ 窗口恢复（--recover 真等 300s；默认 xfail 标注） ----
    if opts.recover:
        remain = max(0.0, 300.0 - (time.time() - flood_t0) + 5)
        print(f"  [..] S2-4 --recover：真等限速窗口 {remain:.0f}s …", flush=True)
        time.sleep(remain)
        st, ch3, _, _ = post(f"/auth/challenge/{lim_name}", timeout=15)
        nonce3 = ch3["data"]["nonce_hex"]
        sig3 = sm2_sign(lim.sk, f"FZ-AUTH-LOGIN|{nonce3}".encode())
        st_r, r_r, ms_r, _ = post("/auth/login", {"username": lim_name,
                                                  "nonce_hex": nonce3, "sig_hex": sig3}, timeout=15)
        if st_r == 200:
            m.pass_("S2-4 300s 窗口恢复：窗口过后续登成功（真等实测）",
                    defense_ref="app/accounts/service.py:AttemptLimiter", latency_ms=round(ms_r, 1))
        else:
            m.fail("S2-4 300s 窗口恢复", expected="200", actual=str(st_r),
                   defense_ref="app/accounts/service.py:AttemptLimiter")
    else:
        m.xfail("S2-4 300s 窗口恢复（默认档不真等）",
                reason="限速窗 300s 真等仅 --recover 档执行——默认 xfail 标注非软通道",
                defense_ref="app/accounts/service.py:AttemptLimiter")


# ================================================================ S3 双控
def s3_dual_control(target_auth_id: int, fly_username: str):
    m = RB.module("S3", "双控（审计签+管理员签）负例×4+并发双 approve 竞态")
    from app.crypto.sm2 import sign as sm2_sign

    aud_ck, adm_ck = cookie_of(INST_AUD), cookie_of(INST_ADM)
    # 令状（真链 logWarrant——真实令状+真实目标授权）
    st, w, _, _ = post("/audit/warrants", {
        "case_no": "SEC-DC-" + secrets.token_hex(3),
        "legal_basis_text": "security_chain 双控实弹——授权 #{} 协同解锁".format(target_auth_id),
        "target_auth_id": target_auth_id,
    }, headers={"Cookie": aud_ck}, timeout=90)
    if st != 200 or w.get("code") != "ok":
        m.env_error("S3-0 令状创建（真链）", detail=f"{st} {str(w)[:160]}")
        return
    wh = w["data"]["warrant_hash_hex"]
    note = "security_chain 双控实弹协同请求"
    msg = f"FZ-COLLAB-REQ|v1|{wh}|{note}"
    good_sig = sm2_sign(INST_AUD.sk, msg.encode())

    # ---- 负例①缺审计签（坏签名） ----
    b = metrics()
    st, r, ms, _ = post("/audit/collab-requests", {
        "warrant_hash_hex": wh, "note": note, "sig_hex": "00" * 64},
        headers={"Cookie": aud_ck}, timeout=30)
    a = metrics()
    n_rows = db_count("SELECT COUNT(*) FROM collab_requests WHERE warrant_hash_hex=?", (wh,))
    if st == 401 and (r or {}).get("code") == "bad_sig" and n_rows == 0 \
            and mdelta(b, a, mkey("/audit/collab-requests", 401)) >= 1:
        m.pass_("S3-1 缺审计签（坏 sig）→ 401 bad_sig 且零请求行+痕迹落 metrics",
                defense_ref="app/accounts/collab.py:_verify_action_sig",
                latency_ms=round(ms, 1), detail={"rows": n_rows})
    else:
        m.fail("S3-1 缺审计签", expected="401 bad_sig/0 行", actual=f"{st} {str(r)[:80]} rows={n_rows}",
               defense_ref="app/accounts/collab.py:_verify_action_sig",
               attack_success=(st == 200))

    # ---- 负例②篡改 note（签名与内容不符） ----
    st, r, ms, _ = post("/audit/collab-requests", {
        "warrant_hash_hex": wh, "note": note + "-被篡改", "sig_hex": good_sig},
        headers={"Cookie": aud_ck}, timeout=30)
    n_rows = db_count("SELECT COUNT(*) FROM collab_requests WHERE warrant_hash_hex=?", (wh,))
    if st == 401 and n_rows == 0:
        m.pass_("S3-2 篡改 note → 签名核验拒 401（req_hash 绑定内容——签的不是所提交的）",
                defense_ref="app/accounts/collab.py:req_hash_of", latency_ms=round(ms, 1),
                detail={"rows": n_rows})
    else:
        m.fail("S3-2 篡改 note", expected="401", actual=f"{st} rows={n_rows}",
               defense_ref="app/accounts/collab.py:req_hash_of", attack_success=(st == 200))

    # ---- 正路建请求（后续竞态载体） ----
    st, fr, _, _ = post("/audit/collab-requests", {
        "warrant_hash_hex": wh, "note": note, "sig_hex": good_sig},
        headers={"Cookie": aud_ck}, timeout=30)
    if st != 200 or fr.get("data", {}).get("status") != "pending":
        m.env_error("S3-3 协作请求创建", detail=f"{st} {str(fr)[:160]}")
        return
    req_id = fr["data"]["id"]
    admin_sig = sm2_sign(INST_ADM.sk, msg.encode())

    # ---- 负例③缺管理员签 approve ----
    st, r, ms, _ = post(f"/admin/collab-requests/{req_id}/approve",
                        {"sig_hex": "00" * 64}, headers={"Cookie": adm_ck}, timeout=30)
    still = db_val("SELECT status FROM collab_requests WHERE id=?", (req_id,))
    if st == 401 and still == "pending":
        m.pass_("S3-3 缺管理员签 approve → 401 且状态不动（pending）",
                defense_ref="app/accounts/collab.py:approve_and_execute",
                latency_ms=round(ms, 1), detail={"status": still})
    else:
        m.fail("S3-3 缺管理员签 approve", expected="401/pending", actual=f"{st}/{still}",
               defense_ref="app/accounts/collab.py:approve_and_execute",
               attack_success=(st == 200))

    # ---- 竞态：并发双 approve（恰一 200 一 409，无双执行） ----
    results = []
    barrier = threading.Barrier(2)

    def _approve(ck):
        barrier.wait(timeout=10)
        st_, r_, ms_, _ = post(f"/admin/collab-requests/{req_id}/approve",
                               {"sig_hex": admin_sig}, headers={"Cookie": ck}, timeout=60)
        results.append({"status": st_, "code": (r_ or {}).get("code"),
                        "data_status": (r_.get("data") or {}).get("status") if isinstance(r_, dict) else None,
                        "ms": round(ms_, 1)})

    ts = [threading.Thread(target=_approve, args=(adm_ck,)) for _ in range(2)]
    t0 = time.time()
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=90)
    oks = [r for r in results if r["status"] == 200]
    conflicts = [r for r in results if r["status"] == 409]
    # 终态轮询（后台执行）
    final = None
    deadline = time.time() + 180
    while time.time() < deadline:
        _, lst, _, _ = get("/audit/collab-requests", headers={"Cookie": aud_ck}, timeout=20)
        hit = [x for x in (lst.get("data", {}).get("items") or []) if x["id"] == req_id]
        if hit and hit[0]["status"] in ("executed", "execute_failed"):
            final = hit[0]
            break
        time.sleep(1.5)
    issued_n = db_count("SELECT COUNT(*) FROM collab_issued WHERE warrant_hash_hex=?", (wh,))
    row = db_one("SELECT status, executed_ts, admin_sig_hex FROM collab_requests WHERE id=?", (req_id,))
    race = {"name": "S3 并发双 approve", "results": results,
            "final_status": (final or {}).get("status"), "collab_issued_rows": issued_n,
            "row": {k: (str(v)[:24] if v else v) for k, v in (row or {}).items()},
            "total_s": round(time.time() - t0, 1)}
    SEC["races"].append(race)
    ok_race = (len(oks) == 1 and len(conflicts) == 1
               and (final or {}).get("status") == "executed"
               and issued_n == 1 and (row or {}).get("executed_ts"))
    if ok_race:
        m.pass_("S3-4 并发双 approve 竞态：恰一 200 approved、一 409，终态 executed 且出函台账=1",
                defense_ref="app/accounts/collab.py:approve_and_execute(条件 UPDATE)",
                detail=race)
    else:
        m.fail("S3-4 并发双 approve 竞态", expected="1×200+1×409+executed+台账1",
               actual=json.dumps(race, ensure_ascii=False)[:220],
               defense_ref="app/accounts/collab.py:approve_and_execute(条件 UPDATE)",
               attack_success=len(oks) > 1 or issued_n > 1)
    # 审计痕迹：双签密码学复验面（历史签名可回验——双控不可抵赖）
    st, vs, _, _ = get(f"/audit/collab-requests/{req_id}/verify-sigs",
                       headers={"Cookie": aud_ck}, timeout=20)
    d = vs.get("data", {}) if isinstance(vs, dict) else {}
    if st == 200 and d.get("auditor", {}).get("ok") and d.get("admin", {}).get("ok"):
        m.pass_("S3-5痕迹 双签纪元公钥复验面：auditor/admin 两签均 ok=true（不可抵赖在案）",
                defense_ref="app/accounts/collab.py:verify_request_sigs",
                detail={"auditor_epoch": d["auditor"].get("epoch"), "admin_epoch": d["admin"].get("epoch")})
    else:
        m.fail("S3-5痕迹 双签复验面", expected="两签 ok", actual=str(vs)[:120],
               defense_ref="app/accounts/collab.py:verify_request_sigs")


# ================================================================ S4 令牌一次性
def s4_token_one_time(caseA, holder_sk, holder_pk, plan_hex):
    """真出证案卷→受理→取件→S5 围栏负例→并发双 ARM 竞态→token_used。
    返回 token 信息（authId 供 S3 令状目标）。"""
    m = RB.module("S4", "令牌一次性——受理→取件→双击竞态→二次 ARM 拒")
    from app.crypto.sm2 import decrypt as ecies_decrypt, verify_digest
    from app.crypto.sm3 import sm3_bytes

    rev_root = rev_root_now()
    sub = caseA["sub"]
    body = apply_body(sub, holder_pk, plan_hex, caseA["nonce_hex"], caseA["case_id"],
                      caseA["t_epoch"], rev_root)
    st, ap, ms, _ = post("/authz/apply", body, timeout=60)
    if st != 200 or not ap.get("ok"):
        m.env_error("S4-1 受理（真案卷）", detail=f"{st} {str(ap)[:200]}")
        return None
    receipt_code = ap["data"]["receipt_code"]
    # worker 真实验证（zkc verify-instances+recordAuth 真链）→ ready
    rr, status = None, "waiting"
    t0 = time.time()
    while time.time() - t0 < 240:
        _, rr, _, _ = get(f"/authz/receipt/{receipt_code}", timeout=15)
        rr = rr.get("data", rr)
        if rr.get("status") != "waiting":
            break
        time.sleep(2)
    if rr.get("status") != "ready":
        m.env_error("S4-2 worker 验证→ready", detail=f"status={rr.get('status')} {str(rr)[:160]}")
        return None
    payload = ecies_decrypt(holder_sk, bytes.fromhex(rr["token_cipher_hex"]))
    tok_body, sig_hex_b = payload.rsplit(b"|", 1)
    sig_hex = sig_hex_b.decode()
    tok = json.loads(tok_body)
    st, ep, _, _ = get("/authz/engine/pub", timeout=15)
    engine_pub = ep["data"]["engine_pub_hex"]
    sig_ok = verify_digest(engine_pub, sm3_bytes(tok_body), sig_hex)
    if sig_ok and tok["plan_hash"] == plan_hex and tok["authId"] > 0:
        m.pass_("S4-1 受理→worker 真验证→取件+令牌验签（authId={} 贯穿）".format(tok["authId"]),
                defense_ref="app/zk/worker.py:_process_one",
                latency_ms=round(ms, 1), detail={"auth_id": tok["authId"], "alt_max": tok["alt_max"]})
    else:
        m.fail("S4-1 令牌验签", expected="sig ok+绑定", actual=f"sig={sig_ok} tok={str(tok)[:80]}",
               defense_ref="app/zk/worker.py:_process_one")
    token_payload_hex = payload.hex()
    tok_hash = sm3_bytes(payload).hex()

    # ---- S5 团栏负例（令牌在场=单变量：只改被测字段） ----
    m5 = RB.module("S5", "围栏 fail-closed（桥 ARM 面）——篡改 alt_max/错 plan_hash")
    arms0 = _bridge_audit_snapshot()
    tampered = json.dumps({**tok, "alt_max": tok["alt_max"] + 1}, separators=(",", ":"), sort_keys=True)
    st, t1, ms1, _ = bpost("/arm", {"token_payload_hex": (tampered + "|" + sig_hex).encode().hex(),
                                    "plan_hash_hex": plan_hex}, timeout=120)
    st, t2, ms2, _ = bpost("/arm", {"token_payload_hex": token_payload_hex,
                                    "plan_hash_hex": "ff" * 32}, timeout=120)
    arms1 = _bridge_audit_snapshot()
    deny_new = [d for d in arms1.get("denials", []) if d not in arms0.get("denials", [])]
    deny_codes = [d[1] for d in deny_new]
    if t1.get("ok") is False and t2.get("ok") is False and "bad_signature" in deny_codes \
            and "plan_mismatch" in deny_codes:
        m5.pass_("S5-1 篡改 alt_max→bad_signature 拒；错 plan_hash→plan_mismatch 拒（双负例）",
                 defense_ref="gcs/bridge/telemetry.py:verify_token",
                 detail={"codes": deny_codes, "lat_ms": [round(ms1, 0), round(ms2, 0)]})
        m5.pass_("S5-1痕迹 拒绝落桥 audit 面 denials 表（可查）",
                 defense_ref="gcs/bridge/telemetry.py:LocalAudit.record_denial",
                 detail={"new_denials": len(deny_new)})
    else:
        attack = t1.get("ok") is True or t2.get("ok") is True
        m5.fail("S5-1 围栏负例", expected="双拒+痕迹", actual=f"{str(t1)[:80]} | {str(t2)[:80]} | {deny_codes}",
                defense_ref="gcs/bridge/telemetry.py:verify_token", attack_success=attack)

    # ---- 双击竞态：并发双 ARM 同一令牌 ----
    results = []
    barrier = threading.Barrier(2)

    def _arm():
        barrier.wait(timeout=10)
        st_, r_, ms_, _ = bpost("/arm", {"token_payload_hex": token_payload_hex,
                                         "plan_hash_hex": plan_hex}, timeout=180)
        results.append({"status": st_, "ok": (r_ or {}).get("ok"),
                        "code": (r_ or {}).get("code"), "first_arm": (r_ or {}).get("first_arm"),
                        "rearmed": (r_ or {}).get("rearmed"), "ms": round(ms_, 1)})

    ts = [threading.Thread(target=_arm) for _ in range(2)]
    t0 = time.time()
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=240)
    arms2 = _bridge_audit_snapshot()
    arm_rows = [r for r in arms2.get("arms", []) if r and r[0] == tok_hash]
    oks = [r for r in results if r.get("ok")]
    race = {"name": "S4 并发双 ARM", "results": results,
            "token_arms_rows": len(arm_rows), "total_s": round(time.time() - t0, 1)}
    SEC["races"].append(race)
    one_first = sum(1 for r in results if r.get("first_arm")) == 1
    if len(oks) == 1 and one_first and len(arm_rows) == 1:
        loser = [r for r in results if not r.get("ok")]
        m.pass_("S4-2 双击竞态：恰一 ok（first_arm=true），败者 {}（FC 串行/一次性拦）".format(
            loser[0].get("code") if loser else "?"),
            defense_ref="gcs/bridge/sitl_link.py:FlightGate.attempt_arm", detail=race)
    else:
        m.fail("S4-2 双击竞态", expected="恰一 ok/审计 1 行", actual=json.dumps(race, ensure_ascii=False)[:220],
               defense_ref="gcs/bridge/sitl_link.py:FlightGate.attempt_arm",
               attack_success=len(oks) > 1 or len(arm_rows) > 1)
        if len(oks) > 1:
            SEC["honesty"].append(
                "S4-2 竞态发现（真实漏洞，非测试构造误差）：FlightGate.attempt_arm 的"
                "一次性检查（first_arm 查询）先于围栏写入+2s settle+ARM 全序列（~4.5s 窗）"
                "且无互斥——双击双线程均读 prev=None 后各自跑完整解锁序列，双双返回"
                " ok:true；审计层 token_arms 因 INSERT OR IGNORE 仍 1 行（账面单次），"
                "但闸门应答层一次性语义被竞窗击穿。修复建议（桥侧，超出本套件边界）："
                "attempt_arm 入口加闸门互斥，或先以条件 INSERT 预占 token_arms 再执行序列。")

    # ---- 二次 ARM（token_used 一次性）+痕迹 ----
    st, r3, ms3, _ = bpost("/arm", {"token_payload_hex": token_payload_hex,
                                    "plan_hash_hex": plan_hex}, timeout=120)
    arms3 = _bridge_audit_snapshot()
    used_denials = [d for d in arms3.get("denials", []) if len(d) > 1 and d[1] == "token_used"]
    if r3.get("ok") is False and r3.get("code") == "token_used" and used_denials:
        m.pass_("S4-3 二次 ARM → token_used 拒（一次授权一次解锁）",
                defense_ref="gcs/bridge/sitl_link.py:FlightGate.attempt_arm(token_used)",
                latency_ms=round(ms3, 1), detail={"denial_rows": len(used_denials)})
    else:
        m.fail("S4-3 二次 ARM", expected="token_used", actual=str(r3)[:120],
               defense_ref="gcs/bridge/sitl_link.py:FlightGate.attempt_arm(token_used)",
               attack_success=r3.get("ok") is True)
    # 状态复位：SITL 落地解锁（恢复飞行态——恢复验证轴）
    st, dis, _, _ = bpost("/sitl/disarm", {}, timeout=30)
    st, asx, _, _ = bget(f"/arm/status?token_payload_hex={token_payload_hex}", timeout=15)
    if (asx or {}).get("used") is True:
        m.pass_("S4-4痕迹 /arm/status 单一事实源 used=true+桥审计库跨请求存活（SITL 已复位 disarm={}）".format(
            (dis or {}).get("ok")), defense_ref="gcs/bridge/server.py:arm_status",
            detail={"disarm": (dis or {}).get("ok", False)})
    else:
        m.fail("S4-4痕迹 /arm/status", expected="used=true", actual=str(asx)[:120],
               defense_ref="gcs/bridge/server.py:arm_status")
    return {"auth_id": tok["authId"], "token_payload_hex": token_payload_hex}


def _bridge_audit_snapshot() -> dict:
    st, r, _, _ = bget("/audit", timeout=15)
    if st != 200 or not isinstance(r, dict):
        return {"arms": [], "denials": []}
    return {"arms": r.get("arms") or [], "denials": [tuple(d) for d in (r.get("denials") or [])]}


# ================================================================ S6 nonce 烧毁
def s6_nonce_burn(caseA, fly):
    m = RB.module("S6", "nonce 烧毁——链级重放 409+并发重放竞态")
    holder_pk = fly["pk"]
    sub_replay, _sk, _pk = issue_sub(fly["cred"], fly["sn"])
    replay = apply_body(sub_replay, holder_pk, caseA["plan_hash_hex"], caseA["nonce_hex"],
                        caseA["case_id"], caseA["t_epoch"], rev_root_now())
    b = metrics()
    st, r, ms, _ = post("/authz/apply", replay, timeout=60)
    a = metrics()
    n_once = db_count("SELECT COUNT(*) FROM applications WHERE nonce_hex=?", (caseA["nonce_hex"],))
    if st == 409 and (r or {}).get("code") == "nonce_used" and n_once == 1 \
            and mdelta(b, a, mkey("/authz/apply", 409)) >= 1:
        m.pass_("S6-1 同 nonce 换新子凭证重放 → 409 nonce_used（链级权威+库级兜底）",
                defense_ref="app/authz/service.py:admission_gate③", latency_ms=round(ms, 1),
                detail={"app_rows_for_nonce": n_once})
    else:
        m.fail("S6-1 nonce 重放", expected="409 nonce_used/1 行", actual=f"{st} {str(r)[:100]} rows={n_once}",
               defense_ref="app/authz/service.py:admission_gate③", attack_success=(st == 200))

    # 并发重放竞态：双线程同 nonce 同报文——双拒、零新增行
    results = []
    barrier = threading.Barrier(2)

    def _apply():
        barrier.wait(timeout=10)
        st_, r_, ms_, _ = post("/authz/apply", replay, timeout=60)
        results.append({"status": st_, "code": (r_ or {}).get("code"), "ms": round(ms_, 1)})

    ts = [threading.Thread(target=_apply) for _ in range(2)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=120)
    n_after = db_count("SELECT COUNT(*) FROM applications WHERE nonce_hex=?", (caseA["nonce_hex"],))
    race = {"name": "S6 并发 nonce 重放", "results": results, "app_rows_for_nonce": n_after}
    SEC["races"].append(race)
    if all(r["status"] == 409 and r["code"] == "nonce_used" for r in results) and n_after == 1:
        m.pass_("S6-2 并发重放竞态：双线程同 nonce 全 409，申请行数不增（=1）",
                defense_ref="app/authz/service.py:admission_gate③", detail=race)
    else:
        m.fail("S6-2 并发重放竞态", expected="双 409/行=1", actual=json.dumps(race, ensure_ascii=False)[:200],
               defense_ref="app/authz/service.py:admission_gate③",
               attack_success=any(r["status"] == 200 for r in results) or n_after > 1)


# ================================================================ S7 电路指纹
def s7_circuit_pin(fly, holder_pk):
    m = RB.module("S7", "电路指纹 pin fail-closed——本地 MANIFEST 篡改→受理拒")
    manifest = UAS / "zksvc" / "vendor" / "MANIFEST.json"
    orig = manifest.read_bytes()
    man = json.loads(orig.decode("utf-8"))
    man["aggregate_sm3"] = ("0" if not man["aggregate_sm3"].startswith("0") else "1") + man["aggregate_sm3"][1:]
    try:
        manifest.write_bytes(json.dumps(man, ensure_ascii=False).encode("utf-8"))
        sub, _sk, _pk = issue_sub(fly["cred"], fly["sn"])
        case_id = dummy_case()
        body = apply_body(sub, holder_pk, secrets.token_bytes(32).hex(),
                          secrets.token_bytes(16).hex(), case_id, int(time.time()), rev_root_now())
        b409 = metrics().get(mkey("/authz/apply", 409), 0)
        st, r, ms, _ = post("/authz/apply", body, timeout=60)
        a409 = metrics().get(mkey("/authz/apply", 409), 0)
        if st == 409 and (r or {}).get("code") == "pin_mismatch":
            m.pass_("S7-1 本地指纹与链上公示不符 → 409 pin_mismatch（改纹即拒）",
                    defense_ref="app/authz/service.py:admission_gate④", latency_ms=round(ms, 1))
            if a409 > b409:
                m.pass_("S7-1痕迹 拒绝落 /metrics(409)", defense_ref="app/main.py:obs_middleware",
                        detail={"delta": a409 - b409})
            else:
                m.fail("S7-1痕迹 /metrics(409)", expected="≥1", actual="0",
                       defense_ref="app/main.py:obs_middleware")
        else:
            m.fail("S7-1 指纹篡改受理", expected="409 pin_mismatch", actual=f"{st} {str(r)[:120]}",
                   defense_ref="app/authz/service.py:admission_gate④", attack_success=(st == 200))
    finally:
        manifest.write_bytes(orig)  # 复原（验收硬规则：测试后必须复原）
    restored = manifest.read_bytes() == orig
    # 复原正例控制（单变量）：同形态申请在指纹复原后越过 pin 门（死因前移到实例核对）
    sub2, _sk2, _pk2 = issue_sub(fly["cred"], fly["sn"])
    case_id2 = dummy_case()
    body2 = apply_body(sub2, holder_pk, secrets.token_bytes(32).hex(),
                       secrets.token_bytes(16).hex(), case_id2, int(time.time()), rev_root_now())
    st2, r2, ms2, _ = post("/authz/apply", body2, timeout=60)
    code2 = (r2 or {}).get("code")
    SEC["recovery"].append({"item": "S7 vendor/MANIFEST.json 复原",
                            "verdict": "restored" if restored else "MISMATCH",
                            "detail": "字节级比对一致" if restored else "复原后不一致——需人工介入"})
    if restored and st2 == 409 and code2 in ("instance_mismatch", "stale_rev_root", "sub_cred_used", "nonce_used"):
        m.pass_("S7-2 复原验证：MANIFEST 字节级复原+同形态申请越过 pin 门（死因前移 {}——pin 不再拦）".format(code2),
                defense_ref="app/authz/service.py:admission_gate④", latency_ms=round(ms2, 1),
                detail={"after_code": code2})
    else:
        m.fail("S7-2 复原验证", expected="restored+非 pin 死因", actual=f"restored={restored} {st2}/{code2}",
               defense_ref="app/authz/service.py:admission_gate④")
    return [case_id, case_id2]


# ================================================================ S8 撤销三层
def s8_revoke_layers():
    m = RB.module("S8", "撤销三层——按人吊销→传播（旧子凭证/见证/重签全拒）")
    aud_ck, adm_ck = cookie_of(INST_AUD), cookie_of(INST_ADM)
    user = PREFIX + "_rev"
    cred, sk, pk = ra_register(user)
    sub, _sk, sub_pk = issue_sub(cred, cred["sn"])
    # 见证键=子凭证出示钥 pk′.x（一次性出示钥域——登记钥不入撤销集，run2 实弹
    # 定谳 witness 200：键域错位非防线失守）
    st, w0, _, _ = get(f"/ra/revocation/witness?holder_pk_hex={sub_pk}", timeout=20)
    root0 = rev_root_now()
    if not (st == 200 and "siblings_hex" in (w0.get("data") or {})):
        m.env_error("S8-0 吊销前基线（见证可取）", detail=f"{st} {str(w0)[:120]}")
        return
    # ① 按人级联吊销（admin 会话门禁；未登录=401 先证；B1 升格再加
    #    「会话在但缺签名=401」新负例——签名成为撤销动作的第二道门）
    st_anon, _, _, _ = post("/ra/revoke/by-username", {"username": user, "reason": "x"}, timeout=15)
    st_pv, pv, _, _ = get(f"/ra/revoke/by-username/preview?username={user}",
                          headers={"Cookie": adm_ck}, timeout=20)
    pv_data = pv.get("data") or {}
    if not (st_pv == 200 and pv_data.get("handles")):
        m.env_error("S8-1 preview 取句柄集/目标纪元", detail=f"{st_pv} {str(pv)[:120]}")
        return
    epoch = pv_data["epoch"]
    reason = "security_chain 撤销实弹"
    st_nosig, rv_nosig, _, _ = post("/ra/revoke/by-username", {
        "username": user, "reason": reason, "epoch": epoch},
        headers={"Cookie": adm_ck}, timeout=20)
    from app.crypto.sm2 import sign as sm2_sign
    msg = "FZ-REVOKE|v1|" + "|".join(sorted(h.lower() for h in pv_data["handles"])) \
        + f"|{reason}|{epoch}"
    b = metrics()
    st, rv, _, _ = post("/ra/revoke/by-username", {
        "username": user, "reason": reason,
        "sig_hex": sm2_sign(INST_ADM.sk, msg.encode()), "epoch": epoch},
        headers={"Cookie": adm_ck}, timeout=60)
    a = metrics()
    root1 = rev_root_now()
    rev_row = db_one("SELECT handle_hex FROM revocations ORDER BY id DESC LIMIT 1")
    if st_anon == 401 and st_nosig == 401 and st == 200 and rv.get("code") == "ok" \
            and root1 != root0:
        m.pass_("S8-1 按人级联吊销（未登录 401→缺签名 401→admin 签名 200）+纪元根更迭",
                defense_ref="app/ra/router.py:/ra/revoke/by-username",
                detail={"anon": st_anon, "nosig": st_nosig,
                        "root": f"{root0[:10]}→{root1[:10]}",
                        "handle": (rev_row or {}).get("handle_hex", "")[:16]})
    else:
        m.fail("S8-1 按人吊销", expected="401/401/200+根更迭",
               actual=f"{st_anon}/{st_nosig}/{st} 根动={root1 != root0} nosig={str(rv_nosig)[:60]}",
               defense_ref="app/ra/router.py:/ra/revoke/by-username")
    # ② 传播：旧子凭证以旧根申请 → 409 stale_rev_root
    case_id = dummy_case()
    body = apply_body(sub, pk, secrets.token_bytes(32).hex(), secrets.token_bytes(16).hex(),
                      case_id, int(time.time()), root0)
    st, r, ms, _ = post("/authz/apply", body, timeout=60)
    if st == 409 and (r or {}).get("code") == "stale_rev_root":
        m.pass_("S8-2 传播①：被吊销者旧子凭证旧根申请 → 409 stale_rev_root",
                defense_ref="app/authz/service.py:admission_gate(④' rev_root)",
                latency_ms=round(ms, 1))
    else:
        m.fail("S8-2 旧根申请", expected="409 stale_rev_root", actual=f"{st} {str(r)[:100]}",
               defense_ref="app/authz/service.py:admission_gate(④' rev_root)", attack_success=(st == 200))
    # ③ 传播：见证面 fail-fast 403 revoked（不烧出证；键=被吊销子凭证 pk′.x）
    st, w1, _, _ = get(f"/ra/revocation/witness?holder_pk_hex={sub_pk}", timeout=20)
    if st == 403 and (w1 or {}).get("code") == "revoked":
        m.pass_("S8-3 传播②：见证重取 → 403 revoked（fail-fast）",
                defense_ref="app/ra/router.py:/ra/revocation/witness")
    else:
        m.fail("S8-3 见证面", expected="403 revoked", actual=f"{st} {str(w1)[:80]}",
               defense_ref="app/ra/router.py:/ra/revocation/witness", attack_success=(st == 200))
    # ④ 签发预检：二次签发 → 403 cred_revoked
    st, s2, _, _ = post("/ra/sub-credentials", {
        "master_cred_hash_hex": cred["master_cred_hash_hex"], "salt_hex": cred["salt_hex"],
        "id_number": cred["id_number"], "cert_level": 3, "sn": cred.get("sn", ""),
        "holder_pub_hex": pk}, timeout=30)
    if st == 403 and (s2 or {}).get("code") == "cred_revoked":
        m.pass_("S8-4 传播③：二次签发子凭证 → 403 cred_revoked（RA 预检）",
                defense_ref="app/ra/service.py:RaService")
    else:
        m.fail("S8-4 二次签发", expected="403 cred_revoked", actual=f"{st} {str(s2)[:80]}",
               defense_ref="app/ra/service.py:RaService", attack_success=(st == 200))
    mt = metrics()
    traces = {"apply409": mdelta(b, mt, mkey("/authz/apply", 409)),
              "witness403": mdelta(b, mt, mkey("/ra/revocation/witness", 403)),
              "sub403": mdelta(b, mt, mkey("/ra/sub-credentials", 403))}
    if all(v >= 1 for v in traces.values()):
        m.pass_("S8-5痕迹 三层拒绝全数落 /metrics（apply409/witness403/sub403）",
                defense_ref="app/main.py:obs_middleware", detail=traces)
    else:
        m.fail("S8-5痕迹 /metrics", expected="全≥1", actual=str(traces),
               defense_ref="app/main.py:obs_middleware")
    return {"user": user, "handle": (rev_row or {}).get("handle_hex")}


# ================================================================ S9 受理门控五步
def s9_admission_gate(caseA, fly, holder_pk):
    m = RB.module("S9", "受理门控五步——缺步/乱序/错根/实例不符/缺 e_hex fail-closed")
    # ① 缺步：缺 rev_root 字段 → pydantic 422（门控输入形态强制）
    sub, _sk, _pk = issue_sub(fly["cred"], fly["sn"])
    body = apply_body(sub, holder_pk, secrets.token_bytes(32).hex(),
                      secrets.token_bytes(16).hex(), dummy_case(), int(time.time()), rev_root_now())
    broken = {k: v for k, v in body.items() if k != "rev_root_hex"}
    st, r, ms, _ = post("/authz/apply", broken, timeout=30)
    if st == 422:
        m.pass_("S9-1 缺步（缺 rev_root_hex）→ 422（门控输入形态强制）",
                defense_ref="app/authz/router.py:ApplyIn", latency_ms=round(ms, 1))
    else:
        m.fail("S9-1 缺步提交", expected="422", actual=f"{st} {str(r)[:80]}",
               defense_ref="app/authz/router.py:ApplyIn", attack_success=(st == 200))
    # ② 乱序/错值：错 rev_root → 409 stale_rev_root
    sub_b, _skb, _pkb = issue_sub(fly["cred"], fly["sn"])
    body_b = apply_body(sub_b, holder_pk, secrets.token_bytes(32).hex(),
                        secrets.token_bytes(16).hex(), dummy_case(), int(time.time()), "ab" * 32)
    st, r, ms, _ = post("/authz/apply", body_b, timeout=60)
    if st == 409 and (r or {}).get("code") == "stale_rev_root":
        m.pass_("S9-2 rev_root 错 → 409 stale_rev_root（链上当前纪元不一致拒）",
                defense_ref="app/authz/service.py:admission_gate(④')", latency_ms=round(ms, 1))
    else:
        m.fail("S9-2 rev_root 错", expected="409 stale_rev_root", actual=f"{st} {str(r)[:100]}",
               defense_ref="app/authz/service.py:admission_gate(④')", attack_success=(st == 200))
    # ③ 实例不符：真案卷×新 nonce（唯一可 unmarried 变量组合——原 nonce 已烧，
    #    门控③先行；此处死因=inst19 ctx_tag 绑定核对）→ 409 instance_mismatch
    sub_c, _skc, _pkc = issue_sub(fly["cred"], fly["sn"])
    body_c = apply_body(sub_c, holder_pk, caseA["plan_hash_hex"], secrets.token_bytes(16).hex(),
                        caseA["case_id"], caseA["t_epoch"], rev_root_now())
    st, r, ms, _ = post("/authz/apply", body_c, timeout=60)
    if st == 409 and (r or {}).get("code") == "instance_mismatch":
        m.pass_("S9-3 实例不符（旧案卷×新 nonce——公开实例与申请绑定逐位核对失败）"
                "→ 409 instance_mismatch",
                defense_ref="app/authz/service.py:admission_gate⑤", latency_ms=round(ms, 1),
                detail={"case": caseA["case_id"][:12]})
    else:
        m.fail("S9-3 实例不符", expected="409 instance_mismatch", actual=f"{st} {str(r)[:100]}",
               defense_ref="app/authz/service.py:admission_gate⑤", attack_success=(st == 200))
    # ④ 缺 e_hex fail-closed（worker 期望面——单变量对拍：全期望 pass/缺 e 拒）
    if not caseA.get("run_zk"):
        m.xfail("S9-4 缺 e_hex fail-closed（zkc 期望面对拍）", reason="--quick 档跳过 zkc 真验证",
                defense_ref="zksvc verify-instances 期望门")
        return
    try:
        os.environ.setdefault("FZ_ZKSVC_DIR", str(UAS / "zksvc"))
        from app.authz.policy import POLICY_VERSION, get_rule
        from app.authz.service import binding_challenge, binding_pred_id
        from app.crypto.sm3 import sm3_bytes
        from app.ra.credential import digest_e_bytes
        from app.zk.worker import WorkerDeps
        from gmssl.sm2 import default_ecc_table

        case_dir = str(CASES_DIR / caseA["case_id"])
        required = get_rule(1)[1]
        _n = int(default_ecc_table["n"], 16)
        e_hex = format(int.from_bytes(digest_e_bytes(bytes.fromhex(caseA["sub"]["message_hex"])), "big") % _n, "064x")
        full = {"e_hex": e_hex,
                "challenge_hex": binding_challenge(caseA["plan_hash_hex"], caseA["nonce_hex"]),
                "pred_id": binding_pred_id(caseA["plan_hash_hex"], caseA["nonce_hex"], POLICY_VERSION),
                "t_epoch": caseA["t_epoch"], "required_level": required,
                "class_id": 1, "smt_root_hex": caseA["rev_root"]}
        missing = {k: v for k, v in full.items() if k != "e_hex"}
        deps = WorkerDeps()
        rc_ok, log_ok = deps.zkc_verify(case_dir, full)
        rc_no, log_no = deps.zkc_verify(case_dir, missing)
        named = ("e_hex" in log_no) or ("期望" in log_no) or ("expected" in log_no.lower())
        if rc_ok == 0 and rc_no != 0 and named:
            m.pass_("S9-4 缺 e_hex → zkc 期望门 fail-closed 拒（同案卷全期望 rc=0 对拍——单变量）",
                    defense_ref="zksvc verify-instances 期望门（ff76735 封口）",
                    latency_ms=None, detail={"rc_full": rc_ok, "rc_missing": rc_no,
                                             "log_tail": log_no[-140:]})
        else:
            m.fail("S9-4 缺 e_hex 对拍", expected="rc_ok=0/rc_missing≠0+具名",
                   actual=f"rc={rc_ok}/{rc_no} named={named}",
                   defense_ref="zksvc verify-instances 期望门（ff76735 封口）",
                   attack_success=(rc_no == 0))
    except Exception as e:  # noqa: BLE001
        m.env_error("S9-4 zkc 对拍", detail=f"{type(e).__name__}: {e}"[:200])


# ================================================================ S10 worker 容错
def s10_worker_resilience(fly, holder_pk):
    m = RB.module("S10", "worker 容错——验证中杀进程→残留如实→重启接管→恢复验证")
    pids_before = worker_pids()
    if not pids_before:
        m.env_error("S10-0 worker 在场", detail="无 app.zk.worker 进程")
        return
    # 第二次真出证（专供中断实验——与 S4 案卷解耦）
    sub_b, sub_sk, sub_pk = issue_sub(fly["cred"], fly["sn"])
    try:
        proveB = full_prove({**sub_b, "_sn": fly["sn"], "_salt": fly["cred"]["salt_hex"],
                             "_id": fly["cred"]["id_number"]},
                            sub_sk, sub_pk, holder_pk)
    except Exception as e:  # noqa: BLE001
        m.env_error("S10-1 真出证（prove B）", detail=str(e)[:200])
        return
    rev_root = rev_root_now()
    body = apply_body(sub_b, holder_pk, proveB["plan_hash_hex"], proveB["nonce_hex"],
                      proveB["case_id"], proveB["t_epoch"], rev_root)
    st, ap, _, _ = post("/authz/apply", body, timeout=60)
    if st != 200 or not ap.get("ok"):
        m.env_error("S10-2 受理（prove B）", detail=f"{st} {str(ap)[:160]}")
        return
    receipt_code = ap["data"]["receipt_code"]
    # 等认领（locked_by 置位=verify 进行中）→ 立即全杀。120s 容忍=共享栈下
    # worker 可能先排水他套件的历史 pending（run4 期 P 尾巴实测教训）。
    row_id = db_val("SELECT id FROM applications WHERE nonce_hex=?", (proveB["nonce_hex"],))
    claimed_by, waited = None, time.time()
    while time.time() - waited < 120:
        r = db_one("SELECT status, locked_by FROM applications WHERE id=?", (row_id,))
        if r and r["locked_by"]:
            claimed_by = r["locked_by"]
            break
        time.sleep(0.12)
    if not claimed_by:
        m.fail("S10-3 等待 worker 认领", expected="locked_by 置位", actual="120s 未认领",
               defense_ref="app/zk/worker.py:_claim_pending")
        return
    kill_t = time.time()
    kill_workers(pids_before)
    time.sleep(2.0)
    residue = db_one("SELECT status, locked_by, locked_at FROM applications WHERE id=?", (row_id,))
    rstatus = db_val("SELECT status FROM receipts WHERE application_id=?", (row_id,))
    pids_now = worker_pids()
    honest = (residue["status"] == "pending" and residue["locked_by"] == claimed_by
              and rstatus == "waiting" and not pids_now)
    if honest:
        m.pass_("S10-3 验证中杀 worker（{}→taskkill /T）→任务残留如实：pending+租约在案+回执 waiting".format(
            claimed_by), defense_ref="app/zk/worker.py:_claim_pending(租约语义)",
            latency_ms=round((time.time() - kill_t) * 1000, 0),
            detail={"locked_by": claimed_by, "status": residue["status"], "receipt": rstatus})
    else:
        too_late = residue["status"] == "approved"
        m.fail("S10-3 中断残留", expected="pending+locked+waiting+零进程",
               actual=f"{dict(residue)} receipt={rstatus} pids={pids_now}",
               defense_ref="app/zk/worker.py:_claim_pending(租约语义)",
               attack_success=False,
               detail={"note": "击杀落在验证完成之后（时序未命中，非攻击得手）" if too_late else
                       "残留形态与预期不符——逐字段核查"})
    # 重启 worker（demo_up 同款命令行+同源 env；租约 60s=测试预算内接管 knob）
    proc = spawn_worker(lease_s=60)
    up = False
    for _ in range(20):
        if worker_pids():
            up = True
            break
        time.sleep(0.5)
    # 孤儿接管→approved→回执 ready
    final, rr = None, None
    deadline = time.time() + 300
    while time.time() < deadline:
        r = db_one("SELECT status, locked_by FROM applications WHERE id=?", (row_id,))
        _, rr, _, _ = get(f"/authz/receipt/{receipt_code}", timeout=10)
        rr = rr.get("data", rr)
        if r and r["status"] in ("approved", "rejected") and rr.get("status") != "waiting":
            final = r
            break
        time.sleep(3)
    vpath = CASES_DIR / "verdicts" / f"app-{row_id}.verdict.json"
    recovery = {"respawned": up, "orphan_taken_over": bool(final and final["status"] == "approved"),
                "receipt": rr.get("status"), "verdict_file": vpath.is_file(),
                "lease_s": 60, "worker_pids": worker_pids()}
    SEC["recovery"].append({"item": "S10 worker 杀进程→重启接管孤儿任务", "verdict":
                            "recovered" if (recovery["orphan_taken_over"] and recovery["receipt"] == "ready") else "FAILED",
                            "detail": recovery})
    if up and final and final["status"] == "approved" and rr.get("status") == "ready" and vpath.is_file():
        m.pass_("S10-4 重启 worker→租约到期接管孤儿→真验证 approved+回执 ready+判决件归档（恢复验证过）",
                defense_ref="app/zk/worker.py:_claimable(租约接手)", detail=recovery)
    else:
        m.fail("S10-4 恢复验证", expected="approved+ready+判决件", actual=json.dumps(recovery, ensure_ascii=False)[:220],
               defense_ref="app/zk/worker.py:_claimable(租约接手)")
    n_workers = len(worker_pids())
    # 共享栈韧性（run5 实弹教训）：他套件（P 补扫）可能并行拉起自己的 worker
    # ——本套件卫生判据=≥1 存活且孤儿已被接管（S10-4）；数量如实记录不武断判红
    if n_workers >= 1:
        m.pass_("S10-5 栈卫生：worker 存活×{}（杀 {} 残留+拉起 1；共享栈下他套件"
                "可能并行增投——数量如实）".format(n_workers, len(pids_before)),
                defense_ref="scripts/demo_up.py:preclean 纪律", detail={"pids": worker_pids()})
    else:
        m.fail("S10-5 栈卫生", expected="≥1", actual="0",
               defense_ref="scripts/demo_up.py:preclean 纪律")


# ================================================================ S11 启动守卫
def s11_startup_guard(opts):
    m = RB.module("S11", "启动守卫（纪元漂移自愈）——单测层引用+真栈收敛态")
    # ① 单测层（tests/test_ra_align.py 6 项——套件引用其结论）
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/test_ra_align.py", "-q", "--no-header"],
            cwd=str(BACKEND), capture_output=True, text=True, timeout=600,
            encoding="utf-8", errors="replace")
        tail = (proc.stdout + proc.stderr).splitlines()
        summary = next((l for l in reversed(tail) if "passed" in l or "failed" in l), "")[:120]
        if proc.returncode == 0:
            m.pass_("S11-1 单测层启动守卫全绿（引用 tests/test_ra_align.py 结论）",
                    defense_ref="app/ra/align.py:startup_align_guard", detail={"pytest": summary})
        else:
            m.fail("S11-1 单测层启动守卫", expected="全绿", actual=summary,
                   defense_ref="app/ra/align.py:startup_align_guard")
    except Exception as e:  # noqa: BLE001
        m.xfail("S11-1 单测层执行不可达", reason=f"{type(e).__name__}: {e}"[:120],
                defense_ref="app/ra/align.py:startup_align_guard")
    # ② 真栈收敛态：链上公示根==本地镜像根（守卫收敛效果在案——不重启即可断言）
    st, snap, _, _ = get("/ra/revocation/snapshot", timeout=15)
    local_root = (snap.get("data") or {}).get("root_hex")
    chain_root = None
    try:
        sys.path.insert(0, str(BACKEND))
        os.environ.setdefault("FZ_CHAIN_ANCHOR", "real")
        from app.authz.router import _chain_rev_root
        _epoch, chain_root = _chain_rev_root()
    except Exception as e:  # noqa: BLE001
        m.env_error("S11-2 链上公示根回读", detail=str(e)[:160])
        return
    if local_root and chain_root and local_root.lower() == chain_root.lower():
        m.pass_("S11-2 真栈守卫收敛态：链上 revRoot==本地撤销镜像根（漂移=0，启动对齐在案）",
                defense_ref="app/ra/align.py:startup_align_guard",
                detail={"root": local_root[:16]})
    else:
        m.fail("S11-2 收敛态", expected="相等", actual=f"local={str(local_root)[:16]} chain={str(chain_root)[:16]}",
               defense_ref="app/ra/align.py:startup_align_guard")
    # ③ backend 重启实弹（--destructive；默认 xfail——栈归主会话所有）
    if opts.destructive:
        pids = backend_pids()
        env = worker_env()
        env["FZ_WORKER_LEASE_S"] = "1200"
        for pid in pids:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True)
        time.sleep(2)
        py = str(BACKEND / ".venv" / "Scripts" / "python.exe")
        subprocess.Popen([py, "-m", "uvicorn", "app.main:create_app", "--factory",
                          "--host", "127.0.0.1", "--port", "8000"],
                         cwd=str(BACKEND), env=env, creationflags=CREATE_NEW_CONSOLE)
        up = wait_http(API + "/healthz", 60)
        root_after = rev_root_now() if up else None
        if up and root_after == local_root:
            m.pass_("S11-3 --destructive backend 重启→启动守卫自检执行，纪元根保持一致",
                    defense_ref="app/main.py:create_app(startup_align_guard)")
        else:
            m.fail("S11-3 backend 重启守卫", expected="up+根一致", actual=f"up={up} root={str(root_after)[:16]}",
                   defense_ref="app/main.py:create_app(startup_align_guard)")
    else:
        m.xfail("S11-3 backend 重启实弹（默认档跳过）",
                reason="backend 进程归主会话所有不重启——--destructive 档执行/主会话终验",
                defense_ref="app/main.py:create_app(startup_align_guard)")


# ================================================================ S12 故障注入
def s12_bridge_outage():
    m = RB.module("S12", "故障注入——停 fz-bridge→依赖面 fail-closed→重启→恢复")
    st0, link0, _, _ = bget("/link_status", timeout=10)
    if st0 != 200:
        m.env_error("S12-0 桥在线前置", detail=str(link0)[:120])
        return
    audit_before = _bridge_audit_snapshot()
    # —— 停桥（demo_up 桥段同款 systemd 面） ——
    bridge_stop()
    down_t = time.time()
    st_l, _, ms_l, _ = bget("/link_status", timeout=5)
    down_ms = round(ms_l, 0)
    # 桥依赖业务面：出证/ARM 在桥停窗口=transport 干净拒绝（非挂死/非半开）
    st_arm, _, ms_arm, _ = bpost("/arm", {"token_payload_hex": "00", "plan_hash_hex": "00" * 32}, timeout=8)
    st_prove, _, ms_prove, _ = bpost("/prove/start", {"plan_hash_hex": "00" * 32}, timeout=8)
    # backend 自有面在桥停期间：结构化不挂死（apply 假案卷→400 case_incomplete；
    # 绑定面/健康面照常——backend 对桥无反向硬依赖）
    st_ap, r_ap, ms_ap, _ = post("/authz/apply", apply_body(
        {"message_hex": "00" * 330, "sig_hex": "00" * 128, "sub_cred_hash_hex": "00" * 64},
        "11" * 64, "00" * 32, "00" * 16, "deadbeef" * 4, int(time.time()), rev_root_now()), timeout=15)
    st_bz, _, _, _ = get("/healthz", timeout=10)
    st_bind, _, _, _ = get("/authz/binding?class_id=1&plan_hash_hex={}&nonce_hex={}".format(
        secrets.token_bytes(32).hex(), secrets.token_bytes(16).hex()), timeout=10)
    outage = {"bridge_down_ms": down_ms, "arm_fail_ms": round(ms_arm, 0),
              "prove_fail_ms": round(ms_prove, 0), "apply_ms": round(ms_ap, 0),
              "apply_code": (r_ap or {}).get("code"), "backend_healthz": st_bz}
    ok_down = (st_l is None and st_arm is None and st_prove is None
               and down_ms < 6000 and ms_arm < 9000 and ms_prove < 9000
               and st_ap == 400 and (r_ap or {}).get("code") == "case_incomplete"
               and st_bz == 200 and st_bind == 200)
    if ok_down:
        m.pass_("S12-1 停桥：桥面出证/ARM transport 级干净拒绝（<9s 无挂死）；backend 自有面"
                "结构化不降级（apply 400 case_incomplete/healthz/binding 200）",
                defense_ref="app/authz/router.py:apply(前置完整性)", latency_ms=down_ms, detail=outage)
    else:
        m.fail("S12-1 停桥窗口行为", expected="transport 拒+backend 结构化",
               actual=json.dumps(outage, ensure_ascii=False)[:220],
               defense_ref="app/authz/router.py:apply(前置完整性)")
    # —— 起桥（reset-failed+systemd-run，demo_up 同款） ——
    bridge_start()
    up = wait_http(BRIDGE + "/engine_pub", 90)
    st1, link1, _, _ = bget("/link_status", timeout=10) if up else (None, {}, 0, "")
    audit_after = _bridge_audit_snapshot() if up else {}
    audit_kept = len(audit_after.get("denials", [])) >= len(audit_before.get("denials", []))
    # 恢复后桥面结构化负例（不烧真出证）：重启后遥测链为空→no_telemetry 409
    # （具名结构化拒绝=业务逻辑活着）；飞行中栈则 window_out_of_range——两者
    # 皆为桥面结构化证据（run5 实弹定谳：重启后窗口负例死因前移到遥测门）
    st_w, r_w, _, _ = bpost("/prove/trail/start", {"alt_max_cm": 7800, "window": 99}, timeout=15) \
        if up else (None, {}, 0, "")
    w_code = (r_w or {}).get("code")
    recovery = {"bridge_up": up, "mode": (link1 or {}).get("mode"),
                "audit_rows_kept": audit_kept,
                "denials_before": len(audit_before.get("denials", [])),
                "denials_after": len(audit_after.get("denials", [])),
                "structured_409": st_w == 409 and w_code in ("window_out_of_range", "no_telemetry"),
                "structured_code": w_code,
                "outage_s": round(time.time() - down_t, 1)}
    SEC["recovery"].append({"item": "S12 fz-bridge 停/起（systemd 瞬态单元）",
                            "verdict": "recovered" if (up and recovery["mode"] == "sitl"
                                                       and audit_kept and recovery["structured_409"]) else "FAILED",
                            "detail": recovery})
    if up and recovery["mode"] == "sitl" and audit_kept and recovery["structured_409"]:
        m.pass_("S12-2 重启桥→link_status=SITL 正常+审计库跨重启存活+结构化负例 409（恢复验证过）",
                defense_ref="scripts/demo_up.py:桥段(systemd-run)", detail=recovery)
    else:
        m.fail("S12-2 桥恢复验证", expected="sitl+审计存活+409", actual=json.dumps(recovery, ensure_ascii=False)[:220],
               defense_ref="scripts/demo_up.py:桥段(systemd-run)")


# ================================================================ 主控
def preflight(m) -> dict:
    st, h, _, _ = get("/healthz", timeout=10)
    if st != 200:
        m.env_error("P-1 backend :8000 探活", detail=f"status={st}")
        return {}
    st, link, _, _ = bget("/link_status", timeout=10)
    if st != 200 or (link or {}).get("mode") != "sitl":
        m.env_error("P-2 桥 :8100 SITL 探活", detail=f"status={st} link={str(link)[:100]}")
        return {}
    mt = metrics()
    if not mt:
        m.env_error("P-3 /metrics 可达", detail="空指标面")
        return {}
    st, panel, _, _ = get("/chain/panel", timeout=20)
    mode = (panel.get("data") or {}).get("mode") if st == 200 else None
    if mode != "real":
        m.env_error("P-4 真链档确认", detail=f"panel mode={mode}")
        return {}
    pids = worker_pids()
    if not pids:
        m.env_error("P-5 worker 在场", detail="无 app.zk.worker 进程")
        return {}
    info = {"worker_pids": pids, "backend_pids": backend_pids(), "link": link, "panel": mode}
    m.pass_("P 环境前置：backend 真链档+桥 SITL+worker {} 在场+/metrics 可达".format(pids),
            defense_ref="scripts/demo_up.py", detail=info)
    return info


def cleanup():
    """测试数据清理（能删则删）：sec_chain_% 账户行+假案卷目录+飞行态复位。
    保留：令状/协作/申请/授权（链上锚定审计痕迹——删除即毁痕）。"""
    notes = []
    try:
        c = db()
        for tbl in ("web_sessions", "auth_challenges", "account_pubkey_history", "accounts"):
            cur = c.execute(f"DELETE FROM {tbl} WHERE username LIKE ?", (PREFIX + "%",))
            if cur.rowcount:
                notes.append(f"{tbl}:{cur.rowcount}")
        c.commit()
    except Exception as e:  # noqa: BLE001
        notes.append(f"db_err:{type(e).__name__}")
    try:
        if CASES_DIR.is_dir():
            n = 0
            for d in CASES_DIR.iterdir():
                # 假案卷=非 hex 命名内容标记/小文件目录（dummy_case 均为纯 hex 名——
                # 以「proof.bin 内容为 dummy 标记」判别，防误删真出证案卷）
                pf = d / "proof.bin"
                if pf.is_file() and pf.read_bytes() == b"sec-chain-dummy":
                    import shutil
                    shutil.rmtree(d, ignore_errors=True)
                    n += 1
            if n:
                notes.append(f"dummy_cases:{n}")
    except Exception as e:  # noqa: BLE001
        notes.append(f"case_err:{type(e).__name__}")
    try:
        st, dis, _, _ = bpost("/sitl/disarm", {}, timeout=15)
        if st == 200:
            notes.append("disarm:ok")
    except Exception:  # noqa: BLE001
        pass
    return notes


def main() -> int:
    global RB, INST_AUD, INST_ADM, API, BRIDGE
    ap = argparse.ArgumentParser(description="安全防御链实弹套件 S1~S12")
    ap.add_argument("--quick", action="store_true", help="跳过真出证轴（S4/S5/S6/S9d/S10——xfail 标注）")
    ap.add_argument("--recover", action="store_true", help="含 429 限速 300s 真等窗口恢复")
    ap.add_argument("--destructive", action="store_true", help="含 backend 重启启动守卫实弹")
    ap.add_argument("--only", default="",
                    help="逗号分隔模块子集（如 --only S4）——回归/补扫用；依赖自动带上（S4/S5/S6/S9/S3 需真出证）")
    ap.add_argument("--api", default=API)
    ap.add_argument("--bridge", default=BRIDGE)
    opts = ap.parse_args()
    API, BRIDGE = opts.api.rstrip("/"), opts.bridge.rstrip("/")
    load_persisted_keys()

    RB = ReportBuilder(suite="security_chain", uas_root=UAS)
    t_all = time.time()
    print("== 安全防御链实弹（S1~S12 × 真栈） ==", flush=True)

    mp = RB.module("P", "环境前置断言")
    info = preflight(mp)
    if RB.aborted:
        RB.save("reports")
        return 2

    # 机构会话（激活语义）——S1/S3/S8 共用
    ma = RB.module("A", "机构会话激活")
    try:
        INST_AUD, INST_ADM = inst_sessions()
        who_a = INST_AUD.get(API + "/auth/whoami", timeout=10).json()["data"]
        who_d = INST_ADM.get(API + "/auth/whoami", timeout=10).json()["data"]
        if who_a.get("role") == "auditor" and who_d.get("role") == "admin":
            ma.pass_("A-1 种子账户激活+会话（auditor/admin 挑战-应答）",
                     defense_ref="scripts/script_auth.py:script_login",
                     detail={"auditor": who_a.get("status"), "admin": who_d.get("status")})
        else:
            ma.env_error("A-1 机构会话角色", detail=f"{who_a}/{who_d}")
            RB.save("reports")
            return 2
    except Exception as e:  # noqa: BLE001
        ma.env_error("A-1 机构会话激活", detail=f"{type(e).__name__}: {e}"[:200])
        RB.save("reports")
        return 2

    fly = None
    only = {m.strip().upper() for m in opts.only.split(",") if m.strip()} if opts.only else None

    def want(*names: str) -> bool:
        """--only 子集门（None=全量；子集模式依赖自动带上）。"""
        return only is None or bool(only.intersection(names))

    # 子集模式依赖声明：S4/S5/S6/S9/S3 共用真出证轴 V；S3 缺 S4 时目标授权回退
    # 库内最新 approved（回归/补扫场景不重烧出证）。
    if only and (only & {"S4", "S5", "S6", "S9", "V", "S3", "S10"}):
        only.add("V")
    try:
        # 业务测试用户（专用前缀——清理判据）。sn=注册 sn（子凭证原像含 sn——
        # 换 sn 即承诺不匹配 bad_preimage，run2 实弹定谳）
        cred, fly_sk, fly_pk = ra_register(PREFIX + "_fly")
        fly = {"cred": cred, "sk": fly_sk, "pk": fly_pk, "sn": cred["sn"]}

        if want("S1"):
            s1_session_isolation()
            if RB.aborted:
                raise RuntimeError("S1 中止")
        if want("S2"):
            s2_challenge_ratelimit(opts)
            if RB.aborted:
                raise RuntimeError("S2 中止")
        if want("S8"):
            s8_revoke_layers()
            if RB.aborted:
                raise RuntimeError("S8 中止")

        if want("S10"):
            # S10 自带 prove B 轴（quick 档仍标注跳过）
            if opts.quick:
                RB.module("S10", "worker 容错").xfail("真任务轴（--quick 档跳过）",
                                                      reason="需真出证任务——全量档执行", defense_ref="app/zk/worker.py")
            else:
                s10_worker_resilience(fly, fly_pk)
                if RB.aborted:
                    raise RuntimeError("S10 中止")

        if want("V", "S4", "S5", "S6", "S9", "S3"):
            if opts.quick:
                for mod, ref in (("S4", "app/zk/worker.py"),
                                 ("S5", "gcs/bridge/telemetry.py:verify_token"),
                                 ("S6", "app/authz/service.py:admission_gate③")):
                    RB.module(mod).xfail("真出证轴（--quick 档跳过）", reason="quick 档不烧真出证——全量档执行",
                                         defense_ref=ref)
            else:
                # 真出证 A（AUTH 电路真证明——S4/S5/S6/S9 载体）
                mpv = RB.module("V", "真出证（预算项——AUTH 电路 ~90-180s）")
                sub_a, sub_a_sk, sub_a_pk = issue_sub(cred, fly["sn"])
                try:
                    proveA = full_prove({**sub_a, "_sn": fly["sn"], "_salt": cred["salt_hex"],
                                         "_id": cred["id_number"]},
                                        sub_a_sk, sub_a_pk, fly_pk)
                    mpv.pass_("V-1 真出证完成（真电路真证明，{:.0f}s）".format(proveA["prove_s"]),
                              defense_ref="zksvc（19,578 约束 AUTH 电路）", latency_ms=proveA["prove_s"] * 1000,
                              detail={"case_id": proveA["case_id"][:16]})
                    caseA = {**proveA, "sub": sub_a, "run_zk": True, "rev_root": rev_root_now()}
                except Exception as e:  # noqa: BLE001
                    mpv.env_error("V-1 真出证", detail=str(e)[:200])
                    RB.save("reports")
                    return 2
                if want("S7"):
                    s7_circuit_pin(fly, fly_pk)
                    if RB.aborted:
                        raise RuntimeError("S7 中止")
                if want("S9"):
                    s9_admission_gate(caseA, fly, fly_pk)
                    if RB.aborted:
                        raise RuntimeError("S9 中止")
                tok = None
                if want("S4"):
                    tok = s4_token_one_time(caseA, fly_sk, fly_pk, caseA["plan_hash_hex"])
                    if RB.aborted or tok is None:
                        raise RuntimeError("S4 中止")
                if want("S6"):
                    s6_nonce_burn(caseA, fly)
                    if RB.aborted:
                        raise RuntimeError("S6 中止")
                if want("S3"):
                    target = (tok or {}).get("auth_id") or db_val(
                        "SELECT auth_id FROM auth_records ORDER BY id DESC LIMIT 1")
                    s3_dual_control(int(target), PREFIX + "_fly")
                    if RB.aborted:
                        raise RuntimeError("S3 中止")

        if want("S12"):
            s12_bridge_outage()
            if RB.aborted:
                raise RuntimeError("S12 中止")
        if want("S11"):
            s11_startup_guard(opts)
    except RuntimeError as e:
        print(f"== 套件中止：{e} ==", flush=True)
    except Exception as e:  # noqa: BLE001  兜底：未预期异常必须记 fail——零失败≠通过
        RB.module("X").fail("套件未预期异常中止", expected="无异常",
                            actual=f"{type(e).__name__}: {e}"[:200])
        print(f"== 套件异常中止：{type(e).__name__}: {e} ==", flush=True)
    finally:
        notes = cleanup()
        SEC["honesty"].append("清理账：" + ("; ".join(notes) if notes else "无可删行") +
                              "。保留项：令状/协作请求/申请/授权（链上锚定审计痕迹，删除即毁痕）；"
                              f"{PREFIX}_rev 用户凭证按业务真实吊销（撤销面实弹产物）。")
        SEC["honesty"].append("S10 复原 worker 以 FZ_WORKER_LEASE_S=60 拉起（demo 缺省 1200）——"
                              "测试预算内接管孤儿任务的租约 knob，仅测试窗使用；此后 worker 按该 env 常驻。")
        SEC["honesty"].append("真弹消耗：真出证×2（AUTH 电路真证明）+真链 recordAuth/burnNonce+真 ARM/DISARM+"
                              "真 429 限速+真进程击杀+真 systemd 桥停起；无任何测试豁免头/旁路标记。")
        path = Path(RB.save("reports"))
        # 报告增强节（§1 矩阵/§2 竞态/§3 429 曲线/§4 恢复判决/§5 诚实声明）
        try:
            rep = json.loads(path.read_text(encoding="utf-8"))
            built = RB.build()
            matrix = []
            for mname, mmod in built["modules"].items():
                for it in mmod["items"]:
                    matrix.append({
                        "module": f"{mname} {mmod['display']}" if mname in ("S1",) else mname,
                        "attack": it["name"],
                        "verdict": it["verdict"],
                        "expected": it["expected"], "actual": it["actual"],
                        "attack_success": it["attack_success"],
                        "defense_ref": it["defense_ref"],
                    })
            rep["chain_sections"] = {
                "s1_matrix": matrix,
                "s2_races": SEC["races"],
                "s3_rate_limit_429": SEC["rate"],
                "s4_recovery_verdicts": SEC["recovery"],
                "s5_honesty": SEC["honesty"],
            }
            path.write_text(json.dumps(rep, ensure_ascii=False, indent=1), encoding="utf-8")
        except Exception as e:  # noqa: BLE001
            print(f"== 报告节增强失败（主报告不受影响）: {e} ==", flush=True)

    s = RB.build()["summary"]
    print("== 总时长 {:.1f} 分钟 ==".format((time.time() - t_all) / 60), flush=True)
    return 0 if (s["verdict"] == "success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
