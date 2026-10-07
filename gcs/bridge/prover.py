"""桥接实时出证服务（R1-1c）：见证不出设备的飞手侧证明生产线。

架构事实：AUTH 见证（身份证号/盐/持有者私钥）只在桥接进程内存组装——
透明 SNARK（零可信设置）使飞手本地 prove 成为自身计算；只有证明、
公开实例与验证参数进入服务端验证面（实例驱动，spec/秘密不上路）。

任务状态机：assembling → proving → done / failed（失败含可读原因）。
"""

from __future__ import annotations

import errno
import os
import secrets
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

router = APIRouter(prefix="/prove", tags=["prove"])

import struct as _struct


class TrailStartIn(BaseModel):
    """TRAIL 合规证明出证请求（R1-6）：数据面=本机遥测语句窗口（128 样本），
    alt_max_cm=令牌 meters×100（TRAIL 电路口径=cm；转换在调用面）。
    window=行程证书包窗口号（2026-09-28）：samples[128w:128(w+1)] 切片，
    每窗口自 GENESIS 重放独立成证（窗口头自含语义不变）。"""
    alt_max_cm: int
    window: int = 0


def _trip_index_path() -> Path:
    """行程索引（JSONL 追加——桥重启存活；与案卷同目录持久化）。"""
    return _cases_dir() / "trip_index.jsonl"


def _record_trip(rec: dict) -> None:
    import json as _json

    with _LOCK:
        with _trip_index_path().open("a", encoding="utf-8") as f:
            f.write(_json.dumps(rec, ensure_ascii=False) + "\n")


def _load_trip(auth_id: int) -> list[dict]:
    """按授权号过滤的行程窗口清单（损坏行跳过——索引面不阻断出证）。"""
    import json as _json

    out: list[dict] = []
    p = _trip_index_path()
    if not p.is_file():
        return out
    for line in p.read_text(encoding="utf-8").splitlines():
        try:
            r = _json.loads(line)
        except ValueError:
            continue
        if r.get("auth_id") == auth_id:
            out.append(r)
    out.sort(key=lambda r: r.get("window", 0))
    return out

_TASKS: dict[str, dict] = {}
_LOCK = threading.Lock()

# 出证并发闸+任务表回收（2026-09-28 安全深检 B-P2）：AUTH/TRAIL 单次出证
# ~14GB 内存——并发多任务可自伤（内存竞争史复燃条件）；_TASKS 只进不出=
# 慢性泄漏。FZ_PROVE_MAX_CONCURRENT 缺省 1（桥接=单飞手本机，串行即够）；
# 终态任务超 FZ_TASK_TTL_S（缺省 2h——判决件下载走 case_id 不依赖任务表）
# 在新任务受理时惰性回收。
#
# 内存感知准入（2026-10-04 并发阻塞根修批，43b6b02 定谳闭环；2026-10-06
# 阈值换代）：计数闸之外的第二维度——受理时读宿主**可用**内存，低于单张
# 出证峰值需求即 429 人话拒绝。闸=2 配低可用内存时不再重演「双任务受理后
# 25 分钟零进展」的阻塞现场。阈值沿革：⑤⑥代实测峰值 11.7~14GB⟹缺省 13；
# ⑥代组合 A（bh 死重+掩蔽惰性+mimalloc）+⑦代电路（advice −20%）+验证
# bug 根修后**实测峰值 7.5GB**（2026-10-06 采样器全程记录，栈在线）⟹缺省
# 8.5（峰值+1.0GB 余量）。换代须重测峰值再校准，不许拍脑袋调回。
_PROVE_MAX = int(os.environ.get("FZ_PROVE_MAX_CONCURRENT", "1"))
_TASK_TTL_S = int(os.environ.get("FZ_TASK_TTL_S", "7200"))
_MIN_AVAIL_GIB = float(os.environ.get("FZ_PROVE_MIN_AVAIL_GIB", "8.5"))

# 任务租约/心跳（任务二看门狗语义）：活跃任务每 _HEARTBEAT_S 续一次
# lease_until；看门狗扫 lease_until 超时=出证线程 stalled，强杀+failed 可重试。
_LEASE_S = int(os.environ.get("FZ_PROVE_LEASE_S", "90"))
_HEARTBEAT_S = int(os.environ.get("FZ_PROVE_HEARTBEAT_S", "30"))


def _purge_stale_tasks_locked() -> None:
    """终态任务超 TTL 回收（持锁调用；内存表+SQLite 任务表双面）。"""
    now = time.time()
    stale = [
        tid for tid, t in _TASKS.items()
        if t.get("status") in ("done", "failed")
        and now - t.get("finished_at", 0) > _TASK_TTL_S
    ]
    for tid in stale:
        _TASKS.pop(tid, None)
    _db_purge_terminal_older_than(now - _TASK_TTL_S)


def _active_prove_count_locked() -> int:
    return sum(1 for t in _TASKS.values() if t.get("status") in ("assembling", "proving"))


# ---- 任务二：出证任务状态落盘（prove_tasks 表） ----
# _TASKS（进程内存）仍是活线程的权威快照（快/无 I/O 阻塞热点）；SQLite 表=
# 持久镜像：桥重启任务不蒸发（重启时进行中任务如实标 failed 可重试），
# /prove/task 内存未命中即读库，看门狗扫 lease_until 强杀 stalled 任务。
# 写面全部 best-effort（镜像失败不阻断出证主径——print 留痕可诊断）。
#
# 🔴 库选址（2026-10-04 实弹定谳）：缺省=桥本地盘工作区（WSL=ext4）——曾按
# 任务书初版放 gcs/bridge/gcs_audit.db（/mnt/c 9p）并开 WAL，实弹测得两处
# 硬伤：① WAL 的 -shm 共存于 9p ⟹ 桥进程首开后对**他进程**提交永久失明
# （Windows 侧注入的活跃行 404 看不见——WAL-index 跨 9p 边界不连贯）；
# ② 桥持锁期间新连接 CANTOPEN（unable to open database file）。SQLite WAL
# 在 9p/网络文件系统本就是不支持面——任务表落桥本地盘（WAL 完全可靠），
# 重启存续语义不变（文件同样跨重启存活）；gcs_audit.db 回归 LocalAudit
# 专用（恢复其原生 journal 模式）。FZ_PROVE_TASK_DB 可显式覆盖。

_PROVE_DB_CONN = None
# 🔴 RLock（可重入）：_db_* 写面持锁调用 _prove_db()（内部再次取锁建连）——
# 普通 Lock=自锁死（首跑实测：pytest 全挂起在 _prove_db，栈转储定谳）。
_PROVE_DB_LOCK = threading.RLock()
_WATCHDOG_STARTED = False


def _prove_task_db_path() -> Path:
    """任务表库路径：FZ_PROVE_TASK_DB > 缺省=出证工作区（桥本地盘）。
    pytest 下未显式指定时落临时目录（测试零污染生产库）。"""
    env = os.environ.get("FZ_PROVE_TASK_DB")
    if env:
        return Path(env)
    if os.environ.get("PYTEST_CURRENT_TEST"):
        import tempfile

        return Path(tempfile.mkdtemp(prefix="fz-prove-tasks-")) / "prove_tasks.db"
    return _workspace_dir() / "prove_tasks.db"


def _prove_db():
    """prove_tasks 单例连接（WAL+busy_timeout——与 backend db.py 同纪律）。"""
    global _PROVE_DB_CONN
    import sqlite3

    with _PROVE_DB_LOCK:
        if _PROVE_DB_CONN is None:
            p = _prove_task_db_path()
            p.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(p), check_same_thread=False, timeout=10)
            mode = str(conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]).lower()
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS prove_tasks ("
                "id TEXT PRIMARY KEY, kind TEXT NOT NULL DEFAULT 'auth',"
                "case_id TEXT, status TEXT NOT NULL, stage TEXT, stage_ts TEXT,"
                "error TEXT, t_epoch INTEGER, pid INTEGER,"
                "created_at REAL, updated_at REAL, finished_at REAL,"
                "heartbeat_at REAL, lease_until REAL, error_code TEXT)"
            )
            # B3 换代补列（存量库无 error_code——ALTER 幂等，重复列静默跳过）
            try:
                conn.execute("ALTER TABLE prove_tasks ADD COLUMN error_code TEXT")
            except Exception:  # noqa: BLE001 —— 列已存在
                pass
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_prove_tasks_status"
                " ON prove_tasks(status)"
            )
            conn.commit()
            if mode != "wal":
                print(f"[prover] prove_tasks 库 WAL 未生效（mode={mode}——9p/网络"
                      f"文件系统会回落 delete）；路径={p}", flush=True)
            _PROVE_DB_CONN = conn
        return _PROVE_DB_CONN


def _db_task_insert(task_id: str, *, kind: str, case_id: str, status: str,
                    t_epoch: int | None = None) -> None:
    import json as _json

    now = time.time()
    try:
        with _PROVE_DB_LOCK:
            _prove_db().execute(
                "INSERT OR REPLACE INTO prove_tasks"
                " (id, kind, case_id, status, stage, stage_ts, error, t_epoch,"
                " created_at, updated_at, lease_until) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (task_id, kind, case_id, status, None, _json.dumps({}), None,
                 t_epoch, now, now, now + _LEASE_S),
            )
            _prove_db().commit()
    except Exception as e:  # noqa: BLE001——镜像失败不阻断受理
        print(f"[prover] 任务落盘失败 id={task_id[:8]}…: {e}", flush=True)


def _db_task_update(task_id: str, **fields) -> bool:
    """任务表增量更新（best-effort）。stage_ts dict 自动 JSON 化。返回成败
    （心跳面据此计数连续失败——断供自停防看门狗误判活任务）。"""
    import json as _json

    sets: list[str] = []
    vals: list = []
    for k, v in fields.items():
        if v is None:
            continue
        if k == "stage_ts" and isinstance(v, dict):
            v = _json.dumps(v)
        sets.append(f"{k}=?")
        vals.append(v)
    if not sets:
        return True
    sets.append("updated_at=?")
    vals.append(time.time())
    vals.append(task_id)
    try:
        with _PROVE_DB_LOCK:
            _prove_db().execute(
                f"UPDATE prove_tasks SET {', '.join(sets)} WHERE id=?", vals
            )
            _prove_db().commit()
        return True
    except Exception as e:  # noqa: BLE001
        print(f"[prover] 任务表更新失败 id={task_id[:8]}…: {e}", flush=True)
        return False


def _db_task_finish(task_id: str, status: str, error: str | None = None,
                    error_code: str | None = None) -> None:
    """终态写入（防翻案：仅活跃态可入终态——看门狗与出证线程竞争时先到者赢）。"""
    try:
        with _PROVE_DB_LOCK:
            _prove_db().execute(
                "UPDATE prove_tasks SET status=?, error=?, error_code=?, finished_at=?,"
                " updated_at=? WHERE id=? AND status IN ('assembling','proving')",
                (status, error, error_code, time.time(), time.time(), task_id),
            )
            _prove_db().commit()
    except Exception as e:  # noqa: BLE001
        print(f"[prover] 任务终态落盘失败 id={task_id[:8]}…: {e}", flush=True)


def _db_task_get(task_id: str) -> dict | None:
    import json as _json

    try:
        with _PROVE_DB_LOCK:  # 读面同锁（共享连接跨线程——读写并发即 ProgrammingError）
            row = _prove_db().execute(
                "SELECT id, kind, case_id, status, stage, stage_ts, error, t_epoch,"
                " pid, created_at, finished_at, heartbeat_at, lease_until, error_code"
                " FROM prove_tasks WHERE id=?",
                (task_id,),
            ).fetchone()
    except Exception as e:  # noqa: BLE001——读面失败=按不存在处理（404 诚实）但留痕
        print(f"[prover] 任务表读取失败 id={task_id[:8]}…: {e}", flush=True)
        return None
    if row is None:
        return None
    try:
        stage_ts = _json.loads(row[5]) if row[5] else {}
    except ValueError:
        stage_ts = {}
    return {
        "task_id": row[0], "kind": row[1], "case_id": row[2], "status": row[3],
        "stage": row[4], "stage_ts": stage_ts, "error": row[6], "t_epoch": row[7],
        "pid": row[8], "created_at": row[9], "finished_at": row[10],
        "prove_heartbeat": row[11], "lease_until": row[12], "error_code": row[13],
    }


def _db_active_rows() -> list[dict]:
    try:
        with _PROVE_DB_LOCK:  # 读面同锁（共享连接跨线程）
            rows = _prove_db().execute(
                "SELECT id, pid, lease_until, case_id FROM prove_tasks"
                " WHERE status IN ('assembling','proving')"
            ).fetchall()
    except Exception as e:  # noqa: BLE001——空表语义但留痕（看门狗盲飞必须可见）
        print(f"[prover] 活跃任务查询失败（看门狗本轮盲）: {e}", flush=True)
        return []
    return [
        {"id": r[0], "pid": r[1], "lease_until": r[2], "case_id": r[3]}
        for r in rows
    ]


def _db_purge_terminal_older_than(cutoff: float) -> int:
    try:
        with _PROVE_DB_LOCK:
            cur = _prove_db().execute(
                "DELETE FROM prove_tasks WHERE status IN ('done','failed')"
                " AND finished_at IS NOT NULL AND finished_at < ?",
                (cutoff,),
            )
            _prove_db().commit()
            return cur.rowcount
    except Exception:  # noqa: BLE001
        return 0


def _kill_orphan_pid(pid) -> bool:
    """遗留 zkc 孤儿进程尽力击杀（桥重启恢复面）。仅 Linux 桥（/proc 核对
    cmdline 含 zkc 才杀——防 pid 复用误伤）。"""
    if not pid or not sys.platform.startswith("linux"):
        return False
    try:
        cmdline = Path(f"/proc/{int(pid)}/cmdline").read_bytes()
    except (OSError, ValueError):
        return False
    if b"zkc" not in cmdline:
        return False
    try:
        import signal

        os.kill(int(pid), signal.SIGKILL)
        return True
    except OSError:
        return False


def _recover_tasks_on_startup() -> int:
    """桥重启任务恢复（任务二语义——诚实可重试，不虚报 done）：库里进行中
    任务=上次进程的失联现场，如实标 failed（bridge_restarted 人话）；遗留
    zkc 孤儿进程尽力击杀（防占内存）。返回恢复条数。"""
    n = 0
    for r in _db_active_rows():
        killed = _kill_orphan_pid(r.get("pid"))
        err = (
            "bridge_restarted: 桥接重启时出证仍在进行——出证进程已失联"
            + ("（已强杀遗留进程）" if killed else "")
            + "，材料需重新提交后再次发起（可重试）"
        )
        _db_task_finish(r["id"], "failed", err)
        n += 1
    return n


def _prove_watchdog_sweep() -> int:
    """看门狗一轮：lease_until 超时的活跃任务=出证线程 stalled（心跳断供）——
    强杀遗留出证进程+如实 failed（可重试）。返回本轮处置条数。"""
    now = time.time()
    n = 0
    for r in _db_active_rows():
        if (r.get("lease_until") or 0) >= now:
            continue
        _kill_orphan_pid(r.get("pid"))
        err = ("prove_watchdog: 任务心跳超时（lease_until 已过）——"
               "出证进程已被强杀，任务失败可重试")
        _db_task_finish(r["id"], "failed", err)
        with _LOCK:
            t = _TASKS.get(r["id"])
            if t is not None and t.get("status") not in ("done", "failed"):
                t["status"] = "failed"
                t["error"] = err
                t["finished_at"] = now
        n += 1
    return n


def _start_prove_watchdog(interval_s: float = 15.0) -> None:
    """看门狗守护线程（server startup 挂载——幂等）。"""
    global _WATCHDOG_STARTED
    if _WATCHDOG_STARTED:
        return
    _WATCHDOG_STARTED = True

    def _loop() -> None:
        while True:
            time.sleep(interval_s)
            try:
                n = _prove_watchdog_sweep()
                if n:
                    print(f"[prover] 看门狗处置 {n} 个租约超时任务（强杀+failed 可重试）", flush=True)
            except Exception as e:  # noqa: BLE001——下轮继续
                print(f"[prover] 看门狗轮异常（下轮继续）: {e}", flush=True)

    threading.Thread(target=_loop, daemon=True, name="prove-watchdog").start()


def _spawn_heartbeat(task_id: str) -> None:
    """任务心跳守护（30s）：task["prove_heartbeat"] 推进（/prove/task 可观测）+
    prove_tasks.lease_until 续租（看门狗判据）。终态即退出；DB 写 best-effort
    （镜像失败不阻断出证——租约断供最坏由看门狗误判，故心跳失败容忍两个周期）。"""

    def _loop() -> None:
        misses = 0
        while True:
            time.sleep(_HEARTBEAT_S)
            with _LOCK:
                t = _TASKS.get(task_id)
                if t is None or t.get("status") in ("done", "failed"):
                    return
                t["prove_heartbeat"] = round(time.time(), 3)
                status, stage = t.get("status"), t.get("stage")
            # DB 写成功与否（_db_task_update 自捕获）——连续失败两周期即自我了断
            # （防 DB 面长期故障时看门狗误判活任务）
            if _db_task_update(task_id, status=status, stage=stage,
                               heartbeat_at=time.time(),
                               lease_until=time.time() + _LEASE_S):
                misses = 0
            else:
                misses += 1
                if misses >= 2:
                    return

    threading.Thread(target=_loop, daemon=True, name=f"prove-hb-{task_id[:8]}").start()


# ---- 内存感知准入 + 绑定面限速 ----

_MEM_CACHE = {"ts": 0.0, "gib": -1.0}


def _host_avail_gib() -> float:
    """宿主可用内存（GiB）。桥在 WSL 内时 zkc.exe 跑在 Windows 宿主——判决面
    是宿主内存：经 powershell.exe interop 读（15s 缓存——受理频度低，可接受）。
    读不到=-1 哨兵（判决见 _memory_admission：批 4-5 起不可知=保守拒绝，
    不再 fail-open 放行）。pytest 下 +inf（测试确定性——生产语义不变）。"""
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return float("inf")
    now = time.time()
    if now - _MEM_CACHE["ts"] < 15:
        return _MEM_CACHE["gib"]
    gib = -1.0
    try:
        if sys.platform == "win32":
            import ctypes

            class _MemStatus(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_uint64), ("ullAvailPhys", ctypes.c_uint64),
                    ("ullTotalPageFile", ctypes.c_uint64), ("ullAvailPageFile", ctypes.c_uint64),
                    ("ullTotalVirtual", ctypes.c_uint64), ("ullAvailVirtual", ctypes.c_uint64),
                    ("ullAvailExtendedVirtual", ctypes.c_uint64),
                ]

            st = _MemStatus()
            st.dwLength = ctypes.sizeof(st)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
                gib = st.ullAvailPhys / 2**30
        else:
            gib = _linux_host_avail_gib()
    except Exception:  # noqa: BLE001——读不到=哨兵值，判决面保守拒绝
        gib = -1.0
    _MEM_CACHE["ts"] = now
    _MEM_CACHE["gib"] = gib
    return gib


def _linux_host_avail_gib() -> float:
    """Linux 桥（WSL）宿主可用内存：powershell.exe interop 读宿主；非 WSL
    Linux 回落 /proc/meminfo MemAvailable。"""
    import subprocess

    try:
        out = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command",
             "(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory"],
            capture_output=True, text=True, timeout=20,
        ).stdout.strip()
        return float(out.split()[-1]) / 2**20  # KB→GiB
    except Exception:  # noqa: BLE001
        pass
    for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) / 2**20  # kB→GiB
    return -1.0


def _memory_admission(avail_gib: float, need_gib: float) -> tuple[bool, str]:
    """内存准入判决（纯函数可测）：avail<0（不可知）=**保守拒绝**（批 4-5
    fail-open 收口——内存维度缺位时放行等于计数闸独扛 14GB 重计算竞争）；
    低于需求=拒绝+人话。"""
    if avail_gib < 0:
        return False, (
            "无法确认本机当前可用内存（内存信息读取失败）——按保守策略拒绝受理"
            "出证（单张出证为重内存计算，内存维度不可知时不放行）。请稍后重试；"
            "若持续出现请排查本机内存信息读取通道（Windows GlobalMemoryStatusEx"
            " / WSL powershell interop）后重试"
        )
    if avail_gib < need_gib:
        return False, (
            f"本机当前可用内存 {avail_gib:.2f}GB 低于单张出证峰值需求 {need_gib:.1f}GB"
            "（AUTH/TRAIL 出证为重内存计算）——现在出证大概率互卡或拖垮整机"
            "（43b6b02 定谳：双任务零进展 25 分钟即此场景），请关闭内存占用后重试"
        )
    return True, ""


_RATE_MAX_PER_MIN = int(os.environ.get("FZ_PROVE_RATE_PER_MIN", "30"))
_RATE_WINDOWS: dict[str, list[float]] = {}
_RATE_LOCK = threading.Lock()


def _rate_limit_ip(request, max_per_min: int | None = None):
    """每 IP 简单限速（内存滑窗）——绑定面获取在并发闸之外，无闸洪泛的最低
    成本闸前移。request 缺席（直调/测试）=不限。返回 None=放行。"""
    if request is None or getattr(request, "client", None) is None:
        return None
    ip = getattr(request.client, "host", None)
    if not ip:
        return None
    limit = max_per_min if max_per_min is not None else _RATE_MAX_PER_MIN
    now = time.time()
    with _RATE_LOCK:
        q = _RATE_WINDOWS.setdefault(ip, [])
        while q and now - q[0] > 60.0:
            q.pop(0)
        if len(q) >= limit:
            return JSONResponse(
                status_code=429,
                content={"code": "rate_limited",
                         "message": "请求过于频繁（每 IP 每分钟 30 次）——请稍后重试"},
            )
        q.append(now)
    return None


class ProveStartIn(BaseModel):
    # 申请面（公开）
    plan_hash_hex: str
    nonce_hex: str
    class_id: int
    # 登记材料（本机浏览器持有——仅在飞手侧用于出证，永不上送授权服务）
    id_number: str
    cert_level: int
    sn: str
    salt_hex: str
    # 子凭证材料（RA 签发回执）
    id_prime_hex: str
    sig_hex: str
    expires_at: str
    holder_sk_hex: str
    holder_pk_hex: str


def _zksvc_dir() -> str:
    return os.environ.get("FZ_ZKSVC_DIR", "")


_ZK_PROFILE_MOD = None
# profile 单源管理的 env 键（WSLENV 透传清单来源——WSL 桥 → Windows zkc.exe）
_PROFILE_ENV_KEYS = (
    "FZ_ZK_ALLOW_AUTH", "FZ_ZK_ALLOW_TRAIL",
    "SM3_LUT", "PCS_INTERLEAVE", "PCS_BATCH_DEDUP", "PCS_VERIFY_STREAM",
    "RAYON_NUM_THREADS", "RUST_MIN_STACK",
    "FZ_ZK_FORBID_SPEC_KEY", "FZ_ZK_HOLDER_SK_HEX",
)
# 优化 2（跨证明确定性产物复用）：zkc 工件缓存目录——WSLENV 透传须带 /p 旗标
# （路径值：WSL→Windows 形态翻译，ext4 → \\wsl.localhost\… UNC），故不进
# _PROFILE_ENV_KEYS 平键清单，由 _build_wslenv 专项追加。
_ZK_CACHE_DIR_ENV = "FZ_ZK_CACHE_DIR"


def _zk_profile_mod():
    """构型 profile 单源模块（backend/app/zk/profile.py——批 4-4）。

    桥接进程与 backend 包不同根：按仓库相对路径把 backend 根挂 sys.path 后
    包导入（FZ_BACKEND_ROOT 可显式指定）；找不到=fail-closed 人话（部署形态
    不完整，不静默回落旧逐 env 拼装——单源纪律）。"""
    global _ZK_PROFILE_MOD
    if _ZK_PROFILE_MOD is None:
        import sys as _sys

        root = os.environ.get("FZ_BACKEND_ROOT", "")
        backend_root = Path(root) if root else Path(__file__).resolve().parents[2] / "backend"
        if str(backend_root) not in _sys.path:
            _sys.path.insert(0, str(backend_root))
        try:
            from app.zk import profile as _p
        except Exception as e:  # noqa: BLE001——不可达=人话拒绝，不静默降档
            raise RuntimeError(
                "构型 profile 单源不可达（"
                f"{backend_root / 'app' / 'zk' / 'profile.py'}）: {e}——"
                "桥接部署须与 backend 同仓，或以 FZ_BACKEND_ROOT 指定 backend 根"
            ) from e
        _ZK_PROFILE_MOD = _p
    return _ZK_PROFILE_MOD


def _cases_dir() -> Path:
    d = Path(os.environ.get("FZ_ZK_CASES_DIR", "/tmp/fz-zk-cases"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _workspace_dir() -> Path:
    """出证工作区（9p 规避——2026-10-04 并发阻塞根修批）。

    高频小文件 I/O（spec 写/出证产物写/轮询）在 9p（/mnt/c drvfs）上慢且在
    宿主内存压力下会悬挂 [43b6b02 实测定谳：双任务零进展 25 分钟，卡点候选
    =tmp.mkdir/spec write_text]——工作区与共享案卷面分离：
    - Linux 桥（WSL）：桥进程本地 ext4（~/fz-prove-tmp）——spec/产物走本地盘，
      zkc.exe 经 wslpath UNC（\\wsl.localhost\…）直读直写 ext4 [实测 sm3 读
      rc=0]；
    - Windows 桥：cases 目录本就在本地 NTFS——行为不变（与既有桥单测同构）；
    - FZ_PROVE_TMP_DIR 显式覆盖两形态。
    出证完成后产物一次性发布（copy+原子 rename）到共享案卷面供 backend/worker
    消费——桥的重 I/O 面（高频轮询/spec 写）零 9p 暴露。
    """
    env = os.environ.get("FZ_PROVE_TMP_DIR", "")
    if env:
        d = Path(env)
    elif sys.platform.startswith("linux"):
        d = Path.home() / "fz-prove-tmp"
    else:
        d = _cases_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d


def _publish_artifact(src: Path, dst: Path, tries: int = 3, gap: float = 1.0,
                      _replace=None) -> None:
    """产物发布：同卷 rename 直迁；跨卷（ext4 工作区→9p 案卷面）copyfile 到
    .part 后原子 rename（消费方只见完整文件）。9p 瞬态写失败短重试。"""
    import shutil

    replace = _replace or (lambda a, b: a.replace(b))
    last: OSError | None = None
    for _ in range(tries):
        try:
            try:
                replace(src, dst)
                return
            except OSError as e:
                if e.errno != errno.EXDEV:
                    raise
            part = dst.with_name(dst.name + ".part")
            shutil.copyfile(src, part)
            os.replace(part, dst)
            return
        except OSError as e:  # 9p 瞬态——短重试 ride-out
            last = e
            time.sleep(gap)
    raise last  # type: ignore[misc]


def _backend_api() -> str:
    return os.environ.get("FZ_API_BASE", "http://127.0.0.1:8000")


class BridgeHttpError(RuntimeError):
    """backend 非 2xx 的结构化透传（B3 人话化：后端 JSON 信封的 code/message
    不再被 HTTPError 打碎成"HTTP Error 403"——被吊销飞手能看到「该出示公钥
    已列入撤销名单」而不是通用网络错误）。status=原始 HTTP 状态码。"""

    def __init__(self, code: str, message: str, status: int) -> None:
        super().__init__(message or code)
        self.code = code
        self.message = message
        self.status = status


def _http_get(url: str) -> dict:
    import json as _json
    import urllib.error as _ue
    import urllib.request
    import uuid as _uuid

    # 回环调用禁系统代理（Windows 常见坑：代理拦 127.0.0.1 致线程挂死）。
    # X-Request-ID 跨程追踪（2026-10-02 乙5：桥→backend rid 不断链——backend
    # 侧优先取入站头作追踪号）。
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(url, headers={"X-Request-ID": _uuid.uuid4().hex[:16]})
    try:
        with opener.open(req, timeout=15) as r:
            return _json.loads(r.read().decode())
    except _ue.HTTPError as e:
        # B3：非 2xx 先试解 JSON 信封（{code,message,...}）——人话原样上抛；
        # 非 JSON 错误体（反代纯文本/500 裸页）回落 http_<status> 通用码，
        # 不伪造业务语义。
        try:
            body = _json.loads(e.read().decode())
        except Exception:  # noqa: BLE001 —— 非 JSON/空体=保留状态码丢正文
            body = None
        if isinstance(body, dict):
            code = str(body.get("code") or f"http_{e.code}")
            msg = str(body.get("message") or body.get("detail") or e.reason)
        else:
            code, msg = f"http_{e.code}", str(e)
        raise BridgeHttpError(code, msg, int(e.code)) from e


def _stage(task: dict, task_id: str, stage: str) -> None:
    """分段时间戳（2026-10-02 乙2 诊断收口：/prove/task 直出——并发卡死/慢段
    一眼定位，不再黑盒等待）。stage_ts[stage]=unix 秒。任务二批：同步镜像到
    prove_tasks 表（桥重启后段迹仍可查）。"""
    task.setdefault("stage_ts", {})[stage] = round(time.time(), 3)
    task["stage"] = stage
    _db_task_update(task_id, stage=stage, stage_ts=task["stage_ts"],
                    status=task.get("status"))


def _assemble_and_prove(task_id: str, body: ProveStartIn, binding: dict) -> None:
    """工作线程：见证→JobSpec→zkc prove。绑定面由 /prove/start 请求线程单源获取
    并随任务传入（R1 收口定谳：绑定含 t_epoch=now 非确定——客户端与桥接各自取
    必得双值，证明绑 A/申请交 B ⟹ 实例 21 必 mismatch；单源=桥接取、随响应回传、
    申请消费同一值）。失败原因写回任务（可读）。

    9p 规避（2026-10-04 根修批）：工作区 tmp 在桥本地盘（_workspace_dir）——
    spec 写/出证子进程 I/O 零 9p 暴露；产物完成后 _publish_artifact 一次性
    发布到共享案卷面（backend/worker 消费）。"""
    import json as _json

    task = _TASKS[task_id]
    case_dir = _cases_dir() / task["case_id"]
    tmp = _workspace_dir() / f"_tmp_{task_id}"
    # 构型档位打点（批 4-4：「哪个构型出的证」一望而知——日志+/prove/task 面）
    prof = _zk_profile_mod()
    task["zk_profile"] = prof.active_profile()
    print(f"[prover] {prof.describe()} kind=auth task={task_id[:8]}…", flush=True)
    _stage(task, task_id, "enter")
    try:
        tmp.mkdir(parents=True, exist_ok=True)
        _stage(task, task_id, "tmp_ready")
        # ② RA 公钥（公开面）
        _stage(task, task_id, "fetch_pub")
        pk = _http_get(f"{_backend_api()}/ra/pubkey")
        ra_pk_hex = pk["data"]["ra_pub_hex"]
        # ③ 撤销非成员见证（公开镜像）
        _stage(task, task_id, "fetch_witness")
        w = _http_get(
            f"{_backend_api()}/ra/revocation/witness?holder_pk_hex={body.holder_pk_hex}"
        )
        wd = w["data"]
        # ④ JobSpec 组装（秘密面——只落临时文件，prove 后即焚）
        exp_u = int(datetime.fromisoformat(body.expires_at).timestamp()) & 0xFFFFFFFF
        id_number_hex = body.id_number.encode().hex()
        serial_hex = body.sn.encode().hex()
        # 批 4-6 私钥交付通道裁决（先于 spec 落盘）：本地出证=env 通道——
        # holder_sk_hex 不落盘（job.json 零私钥字节，FZ_ZK_FORBID_SPEC_KEY=1
        # 由 profile 缺省置位把 spec 明文回落封死）；远程 prover 池=spec 文件
        # 通道（job.json 本就全量上传+用毕即焚，远端 env 不经本进程拼装——
        # 诚实保留）。
        remote = os.environ.get("FZ_PROVE_REMOTE", "")
        is_remote = remote.startswith("ssh:")
        extra_env: dict[str, str] = {}
        spec = {
            "profile": "auth",
            "reps": 16,
            "log_rate": 1,
            "binding": {
                "challenge_hex": binding["challenge_hex"],
                "pred_id": binding["pred_id"],
                "t_epoch": binding["t_epoch"],
                "required_level": binding["required_level"],
            },
            "input": {
                "kind": "auth",
                "ra_pk_hex": ra_pk_hex,
                "id_prime_hex": body.id_prime_hex,
                "salt_hex": body.salt_hex,
                "id_number_hex": id_number_hex,
                "cert_level": body.cert_level,
                "serial_hex": serial_hex,
                "holder_sk_hex": (body.holder_sk_hex if is_remote else ""),
                "holder_pk_hex": body.holder_pk_hex,
                "exp_u": exp_u,
                "class_id": body.class_id,
                "sig_hex": body.sig_hex,
                "smt_siblings_hex": "".join(wd["siblings_hex"]),
                "smt_root_hex": wd["root_hex"],
            },
        }
        if not is_remote:
            extra_env["FZ_ZK_HOLDER_SK_HEX"] = body.holder_sk_hex
        spec_path = tmp / "job.json"
        spec_path.write_text(_json.dumps(spec), encoding="utf-8")
        _stage(task, task_id, "spec_written")
        print(f"[prover] holder_sk 通道={'spec(远程池)' if is_remote else 'env(不落盘)'} "
              f"holder_sk_hex len={len(body.holder_sk_hex)} "
              f"holder_pk_hex len={len(body.holder_pk_hex)} "
              f"id_prime len={len(body.id_prime_hex)}", flush=True)
        task["status"] = "proving"
        _stage(task, task_id, "prove_spawn")
        # ⑤ 出证（双档）：FZ_PROVE_REMOTE=ssh:目标 时走服务器 prover 池（AUTH 内存
        # 密集 ~20GB，本机空闲不足时必需）；否则本地 zkc prove（透明 SNARK，
        # 飞手自身计算）。两档产物同为 proof/vp/instances/verdict 四件。
        if is_remote:
            _prove_remote(remote[4:], spec_path, tmp / "out")
        else:
            task["pid"] = _prove_local(spec_path, tmp / "out", extra_env=extra_env)
            _db_task_update(task_id, pid=task.get("pid"), status="proving")
        out = tmp / "out"
        # 优化 2：缓存命中/未命中阶段标记+秒数（prove 窗收益对账面）
        _mark_zk_cache_stage(task, task_id, tmp)
        # ⑥ 产物发布正式 case 目录（供 /authz/apply 与 worker 验证消费）——
        # 工作区与案卷面可能异卷（ext4→9p）：copyfile+.part 原子 rename。
        case_dir.mkdir(parents=True, exist_ok=True)
        for name in ("proof.bin", "verifier_param.bin", "instances.json", "verdict.json"):
            _publish_artifact(out / name, case_dir / name)
        # done 语义=按下载/消费路径自读可服务（9p 可见性窗口——同 TRAIL 线程）
        _await_case_artifacts(case_dir, ("proof.bin", "verifier_param.bin",
                                         "instances.json", "verdict.json"))
        # 终态防翻案（看门狗可能已判 failed——先到者赢）
        if task.get("status") == "failed":
            return
        task["status"] = "done"
        task["finished_at"] = time.time()
        task["case_id"] = task["case_id"]
        task["t_start"] = binding["t_epoch"]
        task["alt_max"] = binding["alt_max"]
        _db_task_finish(task_id, "done")
    except BridgeHttpError as e:
        # B3 人话化：后端信封拒绝（如 revoked=「该出示公钥已列入撤销名单」）
        # ——人话进 error、业务码进 error_code，随 /prove/task 直达前端分流。
        task["status"] = "failed"
        task["error"] = e.message[:400]
        task["error_code"] = e.code
        task["finished_at"] = time.time()
        _db_task_finish(task_id, "failed", task["error"], e.code)
    except Exception as e:  # noqa: BLE001——失败原因可读回传
        task["status"] = "failed"
        task["error"] = str(e)[:400]
        task["finished_at"] = time.time()
        _db_task_finish(task_id, "failed", task["error"])
    finally:
        # 秘密面即焚（A-P2-1 收口）：成功=整目录删除；失败=保留**脱敏现场**
        # （failure.json=错误+zkc stderr 尾部——诊断面），job.json（含身份证号/
        # 盐/出示私钥明文见证）即焚——隐私系统的磁盘取证面不滞留明文见证。
        import shutil

        if task.get("status") == "failed":
            for secret in ("job.json",):
                (tmp / secret).unlink(missing_ok=True)
            (tmp / "failure.json").write_text(
                _json.dumps(
                    {
                        "task_id": task_id,
                        "error": task.get("error", ""),
                        "error_code": task.get("error_code"),
                        "at": datetime.now().isoformat(),
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            _sweep_stale_failures()
        else:
            shutil.rmtree(tmp, ignore_errors=True)


def _sweep_stale_failures() -> None:
    """失败现场 TTL 清扫（A-P2-1）：脱敏现场保留 FZ_PROVE_FAILURE_TTL_S
    （缺省 24h）供排障，超时即焚——不再无限期滞留。清扫面=工作区+案卷面
    两根（工作区可能独立于 cases 目录——9p 规避批分离）。"""
    ttl_s = int(os.environ.get("FZ_PROVE_FAILURE_TTL_S", "86400"))
    now = time.time()
    import shutil

    for base in {_workspace_dir(), _cases_dir()}:
        for d in base.glob("_tmp_*"):
            try:
                if now - d.stat().st_mtime > ttl_s:
                    shutil.rmtree(d, ignore_errors=True)
            except OSError:
                continue


def _zkc_argv(exe: str, spec_path: Path, out_dir: Path, wsl: bool = False) -> list[str]:
    """zkc prove 参数构造（两形态单源——D-Ⅱ-1）。

    WSL 形态（桥接进程在 WSL 内、interop 调 Windows zkc.exe）：路径参数必须
    wslpath -w 转 Windows 形态。可消费两形态：C:\\ 本地盘（旧形态——spec/out
    同盘约束）与 \\\\wsl.localhost\\ UNC（9p 规避批——工作区在桥本地 ext4，
    zkc.exe 经 Plan9 直读直写，[实测 sm3 读 rc=0/写 mkdir ok]）。转换失败=
    fail-closed。
    """
    if not wsl:
        return [exe, "prove", "--spec", str(spec_path), "--out", str(out_dir)]
    conv = lambda p: subprocess.run(  # noqa: E731
        ["wslpath", "-w", str(p)], capture_output=True, text=True, timeout=10
    ).stdout.strip()
    spec_win, out_win = conv(spec_path), conv(out_dir)
    ok_prefix = ("C:\\", "C:/", "\\\\wsl.localhost\\", "\\\\wsl$\\")
    if not spec_win.startswith(ok_prefix) or not out_win.startswith(ok_prefix):
        raise RuntimeError(f"wslpath 转换异常: spec={spec_win!r} out={out_win!r}")
    return [exe, "prove", "--spec", spec_win, "--out", out_win]


def _wait_prove_exit(proc, soft_timeout_s: int, gap_s: float = 1.0) -> int | None:
    """出证子进程看门狗等待（Popen 轮询——2026-10-04 根修批）：软超时强杀并
    返回 None（调用方转人话 RuntimeError）。轮询间 poll——zkc 悬挂不再盲等
    subprocess.run 的 1800s 大限（且轮询点即看门狗裁决点）。"""
    deadline = time.time() + soft_timeout_s
    while True:
        rc = proc.poll()
        if rc is not None:
            return rc
        if time.time() > deadline:
            try:
                proc.kill()
                proc.wait(timeout=60)
            except Exception:  # noqa: BLE001——强杀尽力而为
                pass
            return None
        time.sleep(gap_s)


def _guard_cache_dir_ext4(env: dict) -> dict:
    """优化 2 缓存目录 ext4 纪律（WSL 桥形态）：/mnt/*（drvfs/9p）上的大工件
    缓存读写慢且在宿主内存压力下会悬挂 [43b6b02 同族实测]——顶替为桥本地
    工作区 zk-cache/（ext4）。就地改写并打日志自述；非 /mnt 前缀/未配置
    原样返回（纯函数面：单测直接断言改写语义）。"""
    d = (env.get(_ZK_CACHE_DIR_ENV) or "").strip()
    if d == "/mnt" or d.startswith("/mnt/"):
        local = _workspace_dir() / "zk-cache"
        env[_ZK_CACHE_DIR_ENV] = str(local)
        print(f"[zk-cache] 缓存目录在 /mnt（drvfs，禁）——已顶替为桥本地 ext4: "
              f"{local}", flush=True)
    return env


def _build_wslenv(env: dict) -> str:
    """WSL→Windows zkc.exe 的 env 透传声明（WSLENV 值）。

    - _PROFILE_ENV_KEYS 平键（旗标/数值——原样透传）；
    - FZ_ZK_CACHE_DIR 带 /p 旗标（路径翻译：WSL ext4 路径 → Windows UNC 形态，
      zkc.exe 经 \\\\wsl.localhost 直读直写 ext4——与 _zkc_argv 工作区同机制；
      未配置时不列入）；
    - 既有 WSLENV 值并入去重（运维追加项保留）。"""
    seen: set[str] = set()
    ordered = [
        v
        for v in (
            *(_PROFILE_ENV_KEYS),
            f"{_ZK_CACHE_DIR_ENV}/p" if env.get(_ZK_CACHE_DIR_ENV) else "",
            env.get("WSLENV", ""),
        )
        if v and not (v in seen or seen.add(v))
    ]
    return ":".join(ordered)


def _mark_zk_cache_stage(task: dict, task_id: str, tmp: Path) -> None:
    """优化 2 收益打点：解析 zkc stderr 的 [zk-cache] hit/miss 行（取最后一
    条——重试/多窗形态下最新为准）+ 判决件 setup/preprocess 秒数 → stage_ts
    阶段标记 cache_hit/cache_miss + 秒数（task["zk_cache_s"]：hit=缓存加载
    口径、miss=实算口径——prove 窗收益对账用）。

    stderr 无标记（缓存 Off/旧版 zkc/远程池无本地 stderr）→ 静默不打点（零
    行为影响）；打点失败绝不影响出证主流程。"""
    import json as _json
    import re as _re

    try:
        tail = (tmp / "zkc_stderr.log").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    m = None
    for m in _re.finditer(r"\[zk-cache\] (hit|miss) ([0-9a-f]{8})", tail):
        pass
    if m is None:
        return
    seconds = None
    try:
        v = _json.loads((tmp / "out" / "verdict.json").read_text(encoding="utf-8"))
        seconds = round(float(v.get("setup_s", 0.0)) + float(v.get("preprocess_s", 0.0)), 3)
    except (OSError, ValueError, TypeError):
        pass
    stage = "cache_hit" if m.group(1) == "hit" else "cache_miss"
    _stage(task, task_id, stage)
    if seconds is not None:
        task["zk_cache_s"] = seconds
    print(f"[zk-cache] {m.group(1)} key={m.group(2)} params_s={seconds} "
          f"(hit=加载口径/miss=实算口径)", flush=True)


def _prove_local(spec_path: Path, out_dir: Path, extra_env: dict | None = None) -> int:
    """本地出证：zkc prove 子进程（透明 SNARK——飞手自身计算）。返回子进程
    pid（任务表观测/看门狗强杀输入）。

    双宿主形态（D-Ⅱ-1）：Windows 直跑；WSL 内（S1/S2 拓扑——桥接必须与 SITL 同
    侧）经 interop 调 Windows zkc.exe：路径 wslpath 转换+env 经 WSLENV 声明透传
    （WSL→Windows 进程环境默认不透传——[实测 2026-09-22]，见阶段二实施计划）。

    构型 profile 单源（批 4-4）：子进程 env 经 app.zk.profile.zkc_env() 取值
    （FZ_ZK_PROFILE 三档；档名打任务日志——「哪个构型」一望而知）；extra_env
    =调用面私有注入（批 4-6：FZ_ZK_HOLDER_SK_HEX 私钥 env 通道）。

    看门狗（2026-10-04 并发阻塞根修批）：subprocess.run(timeout=1800) 盲等改
    Popen+轮询——软超时 FZ_PROVE_SOFT_TIMEOUT_S（缺省 1500s）强杀+人话
    RuntimeError（任务 failed 可重试）；stderr/stdout 落工作区文件（轮询尾读，
    不经管道防缓冲塞死）。
    """
    exe = os.path.join(_zksvc_dir(), "target", "release", "zkc.exe")
    prof = _zk_profile_mod()
    env = prof.zkc_env()
    if extra_env:
        env.update(extra_env)
    print(f"[prover] {prof.describe()} spec={spec_path.name}", flush=True)
    wsl = sys.platform.startswith("linux") and exe.endswith(".exe")
    if wsl:
        # 优化 2：缓存目录 ext4 纪律先行（/mnt 顶替后再进 WSLENV 路径翻译）
        _guard_cache_dir_ext4(env)
        env["WSLENV"] = _build_wslenv(env)
    argv = _zkc_argv(exe, spec_path, out_dir, wsl=wsl)
    err_log = spec_path.parent / "zkc_stderr.log"
    soft_s = int(os.environ.get("FZ_PROVE_SOFT_TIMEOUT_S", "1500"))
    try:
        with err_log.open("wb") as err_f:
            proc = subprocess.Popen(argv, stdout=err_f, stderr=err_f, env=env)
    except OSError as e:
        # 2026-09-26 队长实测：WSLInterop binfmt 条目静默消失 ⟹ Exec format
        # error（ENOEXEC）——人话+自愈指引直达调用方（原始 errno 无可操作信息）
        if e.errno == 8:
            raise RuntimeError(
                "WSL 互操作通道失效（无法启动 Windows 版证明器 zkc.exe）——"
                "在仓库根运行 bash scripts/up.sh 自动重注册互操作通道后重试"
            ) from e
        raise
    try:
        rc = _wait_prove_exit(proc, soft_s)
    finally:
        try:
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            pass
    tail = ""
    try:
        tail = err_log.read_text(encoding="utf-8", errors="replace")[-300:]
    except OSError:
        pass
    if rc is None:
        raise RuntimeError(
            f"zkc prove 软超时（>{soft_s}s）被看门狗强杀——任务失败可重试；"
            f"stderr 尾部: {tail}"
        )
    if rc != 0:
        raise RuntimeError(f"zkc prove exit {rc}: {tail}")
    return proc.pid


def _prove_remote(target: str, spec_path: Path, out_dir: Path) -> None:
    """服务器 prover 池出证（AUTH 内存 ~20GB，本机不足时的加速/可行档）。

    paramiko SSH：上传 spec → 服务器 zkc prove → 回传四件产物。
    秘密面声明：spec 含见证材料，prover 侧=飞手信任域（TCB 扩展，诚实标注）；
    隐私最优路径仍是本地出证（本机内存充足时）。
    """
    import json as _json

    import paramiko

    host = target
    cli = paramiko.SSHClient()
    # 🔴 主机钥 pinning（S5 安全修复——反驳手[重5]）：AutoAddPolicy=盲收任意主机钥
    # ⟹ MITM 可截获含身份证号/私钥的完整见证。必须预置 FZ_PROVE_REMOTE_HOSTKEY
    # （服务器 /etc/ssh/ssh_host_*_key.pub 的 base64 主体），不匹配即拒绝连接。
    hostkey_pin = os.environ.get("FZ_PROVE_REMOTE_HOSTKEY", "")
    if not hostkey_pin:
        raise RuntimeError(
            "远程出证需 FZ_PROVE_REMOTE_HOSTKEY（服务器 SSH 主机钥 base64——"
            "取自 /etc/ssh/ssh_host_ed25519_key.pub 第三字段）；拒绝盲连（MITM 防护）"
        )

    class _PinnedPolicy(paramiko.MissingHostKeyPolicy):
        def __init__(self, key_body: str) -> None:
            self._key_body = key_body

        def missing_host_key(self, client_, hostname, key) -> None:
            import base64 as _b64

            body = _b64.b64encode(key.asbytes()).decode().rstrip("=")
            if body != self._key_body.replace("=", ""):
                raise paramiko.SSHException(
                    "远程主机钥与 FZ_PROVE_REMOTE_HOSTKEY 不符——可能 MITM，拒绝连接"
                )

    cli.set_missing_host_key_policy(_PinnedPolicy(hostkey_pin))
    pw = os.environ.get("FZ_PROVE_REMOTE_PW")
    cli.connect(host.split("@")[-1], username=target.split("@")[0] if "@" in target else "root",
                password=pw, timeout=20) if pw else cli.connect(host.split("@")[-1], timeout=20)
    try:
        remote_dir = "/root/fz-prove/" + spec_path.parent.name
        _exec(cli, f"mkdir -p {remote_dir}")
        sftp = cli.open_sftp()
        sftp.put(str(spec_path), remote_dir + "/job.json")
        rc, out, err = _exec(
            cli,
            f"cd {remote_dir} && FZ_ZK_ALLOW_AUTH=1 FZ_ZKSVC_DIR=/root/zksvc "
            "FZ_ZK_CACHE_DIR=/root/fz-prove/cache "
            "RUST_MIN_STACK=536870912 /root/zksvc/target/release/zkc "
            "prove --spec job.json --out out",
        )
        if rc != 0:
            raise RuntimeError(f"远程 zkc prove exit {rc}: {(out + err)[-300:]}")
        out_dir.mkdir(parents=True, exist_ok=True)
        for name in ("proof.bin", "verifier_param.bin", "instances.json", "verdict.json"):
            sftp.get(f"{remote_dir}/out/{name}", str(out_dir / name))
        sftp.close()
        _exec(cli, f"rm -rf {remote_dir}")
    finally:
        cli.close()


def _exec(cli, cmd):
    """远程命令执行：返回 (rc, stdout, stderr)。"""
    _, stdout, stderr = cli.exec_command(cmd, timeout=1800)
    rc = stdout.channel.recv_exit_status()
    return rc, stdout.read().decode("utf-8", "replace"), stderr.read().decode("utf-8", "replace")


def _sign_trail_cp(auth_id, seq: int, anchor_head, fence_state) -> str:
    """设备钥签署 TRAIL 检查点（绑定语句锚定头=窗口末头+围栏态——与 zksvc
    verify_checkpoint_sig 的 checkpoint_message 同构）。"""
    from device_key import sign_checkpoint

    from server import _DEV_PRIV

    return sign_checkpoint(_DEV_PRIV, auth_id, seq, anchor_head, fence_state)


def _trail_window_rows(samples, sample_period_ms: int | None = None) -> tuple[bytes, bytes, int]:
    """TRAIL 语句窗口=规格行字节单源（装配器契约的对偶面，S4 雷①单源化）。

    行=14B/样本 `>IHii`（t BE4‖alt_cm BE2‖lat_1e7 i32 BE4‖lon_1e7 i32 BE4
    ——与 trail_host.rs sample_hash/sample_block 逐字段同构；🔴 lat/lon 是
    i32：SITL 默认原点在南半球，'I' 槽打包负纬度=struct 溢出 500）。行 t=
    段相对采样周期网格（二批换代改动2：时间门 Δt=sample_period_ms 实例钉
    消费口径；绝对 unix-ms 溢出 u32，段原点由链头锚定）。周期缺省自
    fence.SAMPLE_HZ 单源折算（1Hz=1000/2Hz=500/4Hz=250——不同采样率录制器
    同电路可验；非整分 Hz fail-closed 拒绝）。链头=自 GENESIS 对同一 rows
    字节重放——assemble.rs 装配面以 sample_hash 重算样本链并 fail-closed
    对账（h≠chain_head 即拒「换链头」），头与行任何双源分叉必被拒绝。
    返回 (rows, chain_head, t_start)。
    """
    from fence import GENESIS, SAMPLE_HZ
    from telemetry import sm3_bytes

    if sample_period_ms is None:
        if SAMPLE_HZ <= 0 or 1000 % SAMPLE_HZ != 0:
            raise ValueError(f"SAMPLE_HZ={SAMPLE_HZ} 非整分 1000（周期折算 fail-closed）")
        sample_period_ms = 1000 // SAMPLE_HZ
    base_ms = 0  # 段内相对周期网格（u32 域）
    parts: list[bytes] = []
    for i, s in enumerate(samples):
        try:
            parts.append(_struct.pack(">IHii", base_ms + i * sample_period_ms, s[1], s[2], s[3]))
        except (_struct.error, TypeError) as exc:
            # 诊断面：坏样本的索引/值直达调用方（500 只见溢出不见值=排障
            # 要再飞一轮——遥测面缺陷必须当场定位）
            raise ValueError(f"样本 {i} 字段越界：{s!r}（{exc}）") from exc
    rows = b"".join(parts)
    head = sm3_bytes(GENESIS)
    for j in range(0, len(rows), 14):
        head = sm3_bytes(head + rows[j : j + 14])
    return rows, head, base_ms


# 引擎绑定权威字段（二批改动3：围栏 4 界入绑定签名域——证明者不可自报）
_TRAIL_BINDING_KEYS = (
    "auth_id", "alt_max_cm", "chain_head_hex",
    "min_lat", "max_lat", "min_lon", "max_lon",
    "engine_pub_hex", "sig_hex",
)


def _fetch_trail_binding(auth_id: int, chain_head_hex: str) -> dict:
    """R4-P0-1 引擎签名轨迹绑定（二批 BIND2 扩域）：backend
    /engine/trail/binding（X-Engine-Token 门禁）以引擎钥签
    (auth_id‖alt_max_cm‖chain_head‖围栏 4 界)——高度上限与围栏矩形由授权
    链路权威供给，证明者不可自报（zksvc 装配面八查+验签 fail-closed）。"""
    import json as _json
    import urllib.request as _ur

    token = os.environ.get("FZ_ENGINE_TOKEN", "")
    opener = _ur.build_opener(_ur.ProxyHandler({}))  # 回环禁系统代理
    req = _ur.Request(
        f"{_backend_api()}/engine/trail/binding?auth_id={auth_id}&chain_head_hex={chain_head_hex}",
        headers={"X-Engine-Token": token},
    )
    with opener.open(req, timeout=15) as r:
        d = _json.loads(r.read().decode())
    data = d.get("data") or d
    for k in _TRAIL_BINDING_KEYS:
        if k not in data:
            raise ValueError(f"引擎绑定响应缺字段 {k}")
    return data


def _await_case_artifacts(case_dir, names, tries: int = 6, gap: float = 1.0) -> None:
    """案卷落盘自证（2026-09-27 队长实测：Windows zkc 写 → WSL 桥经 /mnt/c 读
    存在**非确定**可见性窗口——is_file 通过≠窗口关闭）。done 的诚实语义=
    本端按下载路径**真实读回**全部产物；窗口内重试 ride-out，超时=如实 failed。"""
    import time as _t

    deadline = _t.time() + tries * gap
    while _t.time() < deadline:
        try:
            for n in names:
                with open(case_dir / n, "rb") as f:
                    f.read(1)
            return
        except OSError:
            _t.sleep(gap)
    missing = [n for n in names if not (case_dir / n).is_file()]
    raise RuntimeError(f"案卷产物不可服务（自证 {tries}×{gap}s）: {', '.join(missing)}")


def _assemble_and_prove_trail(task_id: str, alt_max_cm: int, rows: bytes, t_start: int,
                              win_head: bytes, fence_state, auth_id, binding: dict,
                              window: int = 0, n_samples_total: int = 0,
                              fence_alt_cm: int = 0, sample_period_ms: int = 500) -> None:
    """TRAIL 出证工作线程（R1-6）：数据面=语句窗口行字节+锚定头（受理端点
    经 _trail_window_rows 单源计算传入——本线程不再二次打包）。检查点=设备钥
    签名绑定锚定头+围栏态；binding=引擎签名轨迹绑定（R4-P0-1 权威 alt_max；
    二批 BIND2：围栏 4 界同款权威供给）。sample_period_ms=录制周期（改动2
    时间门实例钉——声明与记录 Δt 不符由电路拒绝）。"""
    import json as _json

    task = _TASKS[task_id]
    case_dir = _cases_dir() / task["case_id"]
    tmp = _workspace_dir() / f"_tmp_{task_id}"
    # 构型档位打点（批 4-4：「哪个构型出的证」一望而知——日志+/prove/task 面）
    _prof_t = _zk_profile_mod()
    task["zk_profile"] = _prof_t.active_profile()
    print(f"[prover] {_prof_t.describe()} kind=trail task={task_id[:8]}…", flush=True)
    _stage(task, task_id, "enter")
    # 第三方期望面源（2026-10 换代：实例 1=alt_max/2=t_start；二批：3=周期/
    # 4..7=围栏 4 界——task API 透传实际授权/窗口参数，scenario 第三方复验经
    # /prove/task 取期望值，不圆证）。
    task["t_start"] = t_start
    task["alt_max"] = alt_max_cm
    task["sample_period_ms"] = sample_period_ms
    task["fence"] = {k: binding[k] for k in ("min_lat", "max_lat", "min_lon", "max_lon")}
    try:
        tmp.mkdir(parents=True, exist_ok=True)
        _stage(task, task_id, "tmp_ready")
        from server import _DEV_PUB  # 桥接单例（设备公钥）

        n_samples = len(rows) // 14
        # spec.binding=装配器消费面九字段（TrailBindingInput 契约，二批 BIND2
        # 扩域：+围栏 4 界；锚定证据不进 spec——证据随 binding.json 案卷发放
        # 供第三方复核）
        spec_binding = {k: binding[k] for k in _TRAIL_BINDING_KEYS}
        spec = {
            "profile": "trail",
            "reps": 16,
            "log_rate": 1,
            "input": {
                "kind": "trail",
                "rows_hex": rows.hex(),
                "alt_max_cm": alt_max_cm,
                "t_start": t_start,  # 段相对原点（与行内 t 同一网格——t_start 钉）
                "sample_period_ms": sample_period_ms,  # 采样周期（时间门实例 3 钉）
                "chain_head_hex": win_head.hex(),
                "auth_id": auth_id,
                "device_pk_hex": _DEV_PUB,
                # 围栏 4 界（电路 4 半平面门，实例 4..7 偏置编码；权威源=
                # 引擎绑定，八查+验签 fail-closed）
                "min_lat": binding["min_lat"],
                "max_lat": binding["max_lat"],
                "min_lon": binding["min_lon"],
                "max_lon": binding["max_lon"],
                # 检查点=设备钥对【最终链头】的签名（装配器契约：检查点绑定语句
                # 对象=锚定头；飞行中历史锚定走 B5 链上通道，与此正交）。
                # 设备钥在桥接进程（D16 TCB 声明：演示=桥接模拟设备钥）。
                "checkpoints": [
                    {
                        "seq": seq_i,
                        "fence_state_hex": fence_state.hex(),
                        "sig_hex": _sign_trail_cp(auth_id, seq_i, win_head, fence_state),
                    }
                    for seq_i in range(1, min(4, max(2, n_samples // 64)) + 1)
                ],
                # R4-P0-1 + 二批 BIND2：引擎绑定（权威 alt_max/围栏——装配面
                # 八查+引擎钥验签）
                "binding": spec_binding,
            },
        }
        task["status"] = "proving"
        spec_path = tmp / "trail_job.json"
        spec_path.write_text(_json.dumps(spec), encoding="utf-8")
        _stage(task, task_id, "spec_written")
        _stage(task, task_id, "prove_spawn")
        task["pid"] = _prove_local(spec_path, tmp / "out")
        _db_task_update(task_id, pid=task.get("pid"), status="proving")
        out = tmp / "out"
        # 优化 2：缓存命中/未命中阶段标记+秒数（TRAIL 每窗收益对账面）
        _mark_zk_cache_stage(task, task_id, tmp)
        case_dir.mkdir(parents=True, exist_ok=True)
        for name in ("proof.bin", "verifier_param.bin", "instances.json", "verdict.json"):
            _publish_artifact(out / name, case_dir / name)
        # C-P0-1：expected.json 随案卷发放（第三方复验的期望值=本端点公示链头；
        # 2026-10 换代：alt_max/t_start 进公开实例 1/2；二批：3=周期、4..7=
        # 围栏 4 界——期望随链头同发，zkc verify-instances 对实例 1..7
        # fail-closed 核对）。
        (case_dir / "expected.json").write_text(
            _json.dumps({
                "chain_head_hex": win_head.hex(),
                "alt_max_cm": alt_max_cm,
                "t_start": t_start,
                "sample_period_ms": sample_period_ms,
                "fence": task["fence"],
            }), encoding="utf-8"
        )
        # R4-P0-1 第三方复核层落地（2026-09-28 密码评审 P0：安全注记宣称
        # 「binding.json 随案卷发放，凭引擎公示钥离线验签+与实例 0 链头比对」，
        # 但案卷从未落此件=复核层空转）：引擎签名绑定随案卷归档。
        # 2026-09-28 锚定对拍批：binding.json=信封形态（binding 五字段+
        # anchor_evidence 锚定证据+其引擎签名）——第三方可离线验两签并
        # 与链上锚定时间线交叉核对（语义=一致性核对，非真实性证明）。
        binding_envelope = {
            "binding": spec_binding,
            "anchor_evidence": binding.get("anchor_evidence"),
            "anchor_evidence_sig_hex": binding.get("anchor_evidence_sig_hex"),
        }
        (case_dir / "binding.json").write_text(
            _json.dumps(binding_envelope, ensure_ascii=False), encoding="utf-8"
        )
        _await_case_artifacts(case_dir, ("proof.bin", "verifier_param.bin",
                                         "instances.json", "verdict.json",
                                         "expected.json", "binding.json"))
        # 终态防翻案（看门狗可能已判 failed——先到者赢）
        if task.get("status") == "failed":
            return
        task["status"] = "done"
        task["finished_at"] = time.time()
        _db_task_finish(task_id, "done")
        # 行程索引登记（成功路径——失败窗口不进清单，索引零虚报）
        try:
            _record_trip({
                "auth_id": auth_id, "window": window, "case_id": task["case_id"],
                "task_id": task_id, "chain_head_hex": win_head.hex(),
                "alt_max_cm": alt_max_cm, "n_samples_total": n_samples_total,
                "fence_alt_cm": fence_alt_cm, "created_at": datetime.now().isoformat(),
            })
        except OSError:
            pass  # 索引面故障不阻断出证主径
    except Exception as e:  # noqa: BLE001
        task["status"] = "failed"
        task["error"] = str(e)[:400]
        task["finished_at"] = time.time()
        _db_task_finish(task_id, "failed", task["error"])
        # 失败现场脱敏（2026-09-28 安全深检 B-P2，与 AUTH 路径同纪律）：
        # trail_job.json 含完整轨迹明文（rows_hex）——隐私系统的磁盘取证面
        # 不滞留轨迹；保留 failure.json 诊断面（错误+zkc stderr 无隐私）。
        (tmp / "trail_job.json").unlink(missing_ok=True)
        (tmp / "failure.json").write_text(
            _json.dumps(
                {"task_id": task_id, "kind": "trail",
                 "error": task.get("error", ""), "at": datetime.now().isoformat()},
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        _sweep_stale_failures()
    finally:
        if task.get("status") != "failed":
            import shutil

            shutil.rmtree(tmp, ignore_errors=True)


def _admit_task_locked(task_id: str, task: dict, *, kind: str, t_epoch: int | None = None):
    """受理登记（持锁调用）：TTL 回收→计数闸→内存感知准入→内存表+SQLite 双面
    登记（任务二：任务不因桥重启蒸发）。返回 None=受理成功；否则 429 响应。

    内存维度（2026-10-04 根修批）：计数闸之外的独立判决——可用内存低于单张
    出证峰值需求即拒绝（43b6b02：闸=2 双任务受理后零进展 25 分钟的阻塞现场，
    结构性拦截）。可用内存读不到=保守拒绝（批 4-5 fail-open 收口）。"""
    _purge_stale_tasks_locked()
    if _active_prove_count_locked() >= _PROVE_MAX:
        return JSONResponse(
            status_code=429,
            content={"code": "prove_busy",
                     "message": ("已有出证任务在进行（本机出证为重计算，串行执行）"
                                 "——请等待当前任务完成后再发起")},
        )
    ok, msg = _memory_admission(_host_avail_gib(), _MIN_AVAIL_GIB)
    if not ok:
        return JSONResponse(status_code=429, content={"code": "memory_insufficient", "message": msg})
    _TASKS[task_id] = task
    _db_task_insert(task_id, kind=kind, case_id=str(task.get("case_id") or ""),
                    status="assembling", t_epoch=t_epoch)
    return None


@router.post("/trail/start")
def start_trail(body: TrailStartIn) -> JSONResponse:
    """TRAIL 合规证明出证（R1-6）：本机遥测链→真出证→判决件三件套可下载
    （第三方可复验的合规证书，而非一个 JSON）。window=行程证书包窗口号
    （2026-09-28）：采样 ≥128(w+1) 时窗口 w=samples[128w:128(w+1)] 切片出证，
    每窗口自 GENESIS 重放独立成证（B6 窗口头自含语义不变）。"""
    from server import _chain

    if _chain is None or _chain.n < 128:
        n = _chain.n if _chain else 0
        return JSONResponse(
            status_code=409,
            content={"code": "no_telemetry",
                     "message": f"遥测样本 {n} < 128（TRAIL 定档 n=128，B6-d1）——继续采样"},
        )
    w = body.window
    n_windows = _chain.n // 128
    if w < 0 or w >= n_windows:
        return JSONResponse(
            status_code=409,
            content={"code": "window_out_of_range",
                     "message": f"窗口 {w} 不存在——当前样本 {_chain.n} 可出证窗口 0..{n_windows - 1}"},
        )
    # 语句公开面单源计算：窗口 128 样本行字节+锚定头（第三方复验的期望值
    # 来源=锚定值）。行格式/字段序/链头重放契约集中在 _trail_window_rows
    # （与 trail_host.rs 逐字段同构；此前的双处独立打包+epoch-t 头=换链头
    # 拒绝与 struct 溢出两类缺陷的根）。窗口切片后重放自 GENESIS 起——
    # 各窗口证书独立可验（行程=多证书包，索引见 /prove/trip/index）。
    samples = _chain.samples[128 * w : 128 * (w + 1)]
    # 采样周期（二批改动2）：fence.SAMPLE_HZ 单源折算——时间门实例 3 钉的
    # 声明源（录制节奏变更即随行，非整分 Hz fail-closed）。
    from fence import SAMPLE_HZ

    if SAMPLE_HZ <= 0 or 1000 % SAMPLE_HZ != 0:
        raise HTTPException(
            status_code=500,
            detail={"code": "bad_sample_rate", "err": f"SAMPLE_HZ={SAMPLE_HZ} 非整分 1000"},
        )
    sample_period_ms = 1000 // SAMPLE_HZ
    try:
        rows, win_head, t_start = _trail_window_rows(samples)
    except ValueError as exc:
        raise HTTPException(
            status_code=500,
            detail={"code": "bad_sample", "err": str(exc)[:300]},
        ) from exc
    case_id = secrets.token_hex(8)
    task_id = uuid.uuid4().hex
    # R4-P0-1：引擎绑定获取+权威 alt_max 对拍（链头=本窗口锚定头——绑定对象与
    # 语句对象一字不差）。不一致=任务失败（政策收紧/客户端陈旧值——证明者
    # 不可自报上限的桥侧守门）
    try:
        binding = _fetch_trail_binding(_chain.auth_id, win_head.hex())
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=503,
            detail={"code": "binding_unavailable", "err": f"引擎绑定获取失败: {exc}"[:300]},
        ) from exc
    if binding["alt_max_cm"] != body.alt_max_cm:
        return JSONResponse(
            status_code=409,
            content={
                "code": "alt_max_mismatch",
                "message": (
                    f"高度上限与引擎权威绑定不一致（请求 {body.alt_max_cm}cm vs "
                    f"授权 {binding['alt_max_cm']}cm——政策值以引擎绑定为准）"
                ),
            },
        )
    # P1 批（评审 B-P2 尾项）：fence_state×alt_max 交叉比对——链上检查点签名的
    # 围栏态（enable‖alt_max 米 BE16‖rsv）不得高于引擎授权上限：固件围栏被
    # 抬高（>授权）时，检查点证词与证书语义矛盾，拒绝出证。围栏=min(令牌,
    # 计划) 恒 ≤ 授权——正常路径零影响；越界=参数被篡改的诚实拒绝面。
    if len(_chain.fence_state) != 4 or _chain.fence_state[0] != 1:
        return JSONResponse(
            status_code=409,
            content={"code": "fence_state_invalid",
                     "message": "围栏态无效或未启用（fence_state）——检查点证词不成立"},
        )
    fence_alt_cm = int.from_bytes(_chain.fence_state[1:3], "big") * 100
    if fence_alt_cm > binding["alt_max_cm"]:
        return JSONResponse(
            status_code=409,
            content={"code": "fence_exceeds_auth",
                     "message": (f"固件围栏上限 {fence_alt_cm}cm 高于授权 "
                                 f"{binding['alt_max_cm']}cm——围栏参数与授权不符，拒绝出证")},
        )
    with _LOCK:
        resp = _admit_task_locked(
            task_id,
            {
                "status": "assembling", "case_id": case_id, "error": None,
                "t_start": None, "alt_max": body.alt_max_cm,
                "sample_period_ms": sample_period_ms, "fence": None,
                "kind": "trail", "stage_ts": {}, "stage": None,
                "prove_heartbeat": None, "pid": None,
            },
            kind="trail",
        )
        if resp is not None:
            return resp
    _spawn_heartbeat(task_id)
    threading.Thread(
        target=_assemble_and_prove_trail,
        args=(task_id, body.alt_max_cm, rows, t_start, win_head, _chain.fence_state,
              _chain.auth_id, binding), daemon=True,
        kwargs={"window": w, "n_samples_total": _chain.n, "fence_alt_cm": fence_alt_cm,
                "sample_period_ms": sample_period_ms},
    ).start()
    return JSONResponse(
        status_code=200,
        content={
            "code": "ok", "task_id": task_id, "case_id": case_id,
            "window": w, "n_windows": n_windows,
            "chain_head_hex": win_head.hex(),  # 锚定链头（复验期望值的公开来源）
            "sample_period_ms": sample_period_ms,  # 采样周期（时间门实例 3 钉）
        },
    )


@router.get("/trip/index")
def trip_index(auth_id: int, download: int = 0):
    """行程证书包索引（2026-09-28）：按授权号列出全部窗口证书（窗口号/案卷/
    链头/上限），供下载为行程索引 JSON——「一次飞行=多窗口证书包」的公开
    清单。download=1 时以附件形态下发。"""
    import json as _json

    from fastapi import Response

    wins = _load_trip(auth_id)
    doc = {
        "kind": "fz-trip-index", "auth_id": auth_id, "windows": len(wins),
        "items": [
            {
                "window": r.get("window"),
                "case_id": r.get("case_id"),
                "chain_head_hex": r.get("chain_head_hex"),
                "alt_max_cm": r.get("alt_max_cm"),
                "n_samples_total": r.get("n_samples_total"),
                "fence_alt_cm": r.get("fence_alt_cm"),
                "created_at": r.get("created_at"),
                "artifacts": [
                    f"/prove/case/{r.get('case_id')}/{a}"
                    for a in ("proof.bin", "verifier_param.bin", "verdict.json",
                              "instances.json", "expected.json", "binding.json")
                ],
            }
            for r in wins
        ],
    }
    headers = {}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="trip-index-{auth_id}.json"'
    return Response(
        content=_json.dumps(doc, ensure_ascii=False, indent=2),
        media_type="application/json", headers=headers,
    )


# ---- 出示包打包（丙-5 链上留痕深化 L2 批：飞手合规档案+出示工具） ----
#
# GET /prove/case/{case_id}/bundle：把一次飞行的证明材料聚合成一个 zip 出示包
# ——第三方（教练/雇主/监管）拿到后 5 秒独立验证。路由注册序=本端点必须先于
# /case/{case_id}/{artifact}（两段通配 {artifact} 会吞掉 "bundle" 字面量）。
#
# expected 选型定谳（本批深读结论，如实报告）：
# - 案卷自带 expected.json（TRAIL 全部——桥出证线程随卷发放；AUTH 历史案卷
#   97/242——worker 安全修 1e8fb21 前随卷归档）→ 直接打包；
# - AUTH 新案卷无 expected：① verdict.json 提取不可行——242 个 AUTH verdict
#   全键集实证无任何绑定字段（仅 proof_sm3/verifier_param_sm3/timing/verdict）；
#   ② backend /chain/record/{authId} 拉取拼入需 authId，桥侧无 case_id→auth_id
#   映射（prove_tasks 只记 case_id/t_epoch；trip_index 仅 TRAIL），补映射端点
#   =碰 backend（本批禁）。⟹ 如实跳过+manifest 标注缺失，README 给出从链上
#   留痕页补齐的指引（诚实降级，不编造期望值）。

_BUNDLE_ARTIFACTS = (
    "proof.bin", "verifier_param.bin", "instances.json", "verdict.json",
    "expected.json", "binding.json",
)
# 零身份红线（与 backend test_chain_panel 词表同思想）：出示包内全部**文本件**
# 不得出现任何身份/设备字段名——命中即 fail-closed 拒绝打包。防线冗余声明：
# 案卷件本就是公开面（证明/公开实例/公开参数），此闸保证「打包端」永不成为
# 第一个泄漏面（新增生成件 summary/README 也被同闸覆盖）。
_BUNDLE_BANNED = (
    "username", "id_number", "idNumber", "user_pub", "sn",
    "serial", "case_no", "sub_sig", "session_pk", "master_cred",
)
# zip 条目时间戳定值——同一案卷重复打包字节级一致（zip 整体 sha256 可公示）。
_BUNDLE_ZIP_EPOCH = (2026, 1, 1, 0, 0, 0)


def _sha256_hex(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def _bundle_read_case(case_dir: Path) -> dict[str, bytes]:
    """案卷件全量读回（**只读**——打包不改动源案卷；读失败的件如实按缺件）。"""
    out: dict[str, bytes] = {}
    for name in _BUNDLE_ARTIFACTS:
        p = case_dir / name
        if p.is_file():
            try:
                out[name] = p.read_bytes()
            except OSError:
                continue  # 9p 瞬态读失败=如实缺件（manifest 标注）
    return out


def _bundle_json(files: dict[str, bytes], name: str) -> dict | None:
    """案卷 JSON 件容错解析（损坏=按缺件语义 None——不阻断打包）。"""
    import json as _json

    raw = files.get(name)
    if raw is None:
        return None
    try:
        d = _json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return None
    return d if isinstance(d, dict) else None


def _bundle_task_window(case_id: str) -> dict | None:
    """授权窗线索①：prove_tasks 表按案卷号反查（AUTH：binding t_epoch=证明
    绑定的授权时间锚；桥重启后仍可查）。读面 best-effort——查不到如实 None。"""
    try:
        with _PROVE_DB_LOCK:
            row = _prove_db().execute(
                "SELECT kind, t_epoch, created_at, finished_at FROM prove_tasks"
                " WHERE case_id=? ORDER BY created_at DESC LIMIT 1",
                (case_id,),
            ).fetchone()
    except Exception:  # noqa: BLE001——索引面缺位不阻断打包
        return None
    if row is None:
        return None
    return {"source": "prove_tasks", "kind": row[0], "binding_t_epoch": row[1],
            "prove_started_at": row[2], "prove_finished_at": row[3]}


def _bundle_trip_row(case_id: str) -> dict | None:
    """授权窗线索②：trip_index.jsonl 按案卷号反查（TRAIL：授权号/窗口号/
    采样总数/归档时刻——全部公开面）。倒序取最新（重试案卷号相同）。"""
    import json as _json

    p = _trip_index_path()
    if not p.is_file():
        return None
    try:
        lines = p.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        try:
            r = _json.loads(line)
        except ValueError:
            continue
        if r.get("case_id") == case_id:
            return r
    return None


def _bundle_readme(case_id: str, profile: str, verdict: dict | None,
                   has_expected: bool, verify_base: str) -> str:
    """README-验证指引.txt（人话——面向教练/雇主等非技术第三方）。"""
    proved_at = ""
    if verdict and verdict.get("created_unix_ts"):
        proved_at = datetime.fromtimestamp(
            verdict["created_unix_ts"]).strftime("%Y-%m-%d %H:%M:%S")
    if profile == "trail":
        what = (
            "  飞行轨迹合规证明（TRAIL）——数学证明「本次飞行全程在授权高度上限与\n"
            "  电子围栏内进行，且飞行记录未被改动任何一个字节」。证明不披露任何\n"
            "  身份信息，也披露不了——这就是零知识证明。"
        )
        env_lines = (
            "   export FZ_TRAIL_CANONICAL_SPEC=trail_canonical_spec.json\n"
            "   export FZ_ZK_ALLOW_TRAIL=1"
        )
    elif profile == "auth":
        what = (
            "  飞手资质合规证明（AUTH）——数学证明「本次申请由持有效资质与授权的\n"
            "  飞手本人在有效期内发起」，全程零披露：身份证号、姓名等任何身份\n"
            "  信息都不在证明里，也不在本包里。"
        )
        env_lines = (
            "   export FZ_AUTH_CANONICAL_SPEC=auth_canonical_spec.json\n"
            "   export FZ_ZK_ALLOW_AUTH=1"
        )
    else:
        what = "  合规证明材料（案卷 verdict.json 缺失，类型未标注——件清单见 summary.json）"
        env_lines = (
            "   export FZ_TRAIL_CANONICAL_SPEC=trail_canonical_spec.json\n"
            "   export FZ_ZK_ALLOW_TRAIL=1"
        )
    expected_note = ""
    if not has_expected:
        expected_note = (
            "\n【如实说明：本包缺 expected.json】\n"
            "  此 AUTH 案卷归档时未随卷保存期望绑定件 expected.json（它存放在验证\n"
            "  服务端的归档里）。其余四件齐全；完整复验请到飞证系统「链上留痕」页\n"
            "  打开对应授权记录详情，取得期望绑定后保存为 expected.json 放进本目录，\n"
            "  再运行下方命令。除此之外本包内容与验证步骤不变。\n"
        )
    return (
        "飞证合规飞行证明包\n"
        "============================================================\n"
        "\n"
        "本包含有一次飞行的完整合规证明材料。\n"
        "\n"
        "【这份包证明什么】\n"
        f"{what}\n"
        f"- 案卷号：{case_id}\n"
        f"- 证明生成时间：{proved_at or '（verdict.json 缺失，未知）'}\n"
        f"- 出证机器判决：{(verdict or {}).get('verdict') or '（verdict.json 缺失，未知）'}\n"
        "- 每个文件的字节大小与 SHA-256 指纹见 summary.json——本包由飞证桥接\n"
        "  系统从本机案卷**原样**打包，未做任何改动。\n"
        "\n"
        "【如何独立验证（约 5 秒）】\n"
        "（需要一台电脑；不需要信任飞证平台，也不需要平台在线）\n"
        "1. 打开验证工具页 " + verify_base + "/verify/\n"
        "   下载验证器 zkc、校验和文件与语句契约文件\n"
        "   （若在其他电脑上打开，请把地址里的主机名换成飞证服务所在机器）\n"
        "2. 校验工具自身完整性（页面有现成命令）。\n"
        "3. 把本包解压到一个目录，与验证器放在一起，在该目录运行：\n"
        "\n"
        f"{env_lines}\n"
        "   zkc verify-instances --instances instances.json --proof proof.bin \\\n"
        "       --vp verifier_param.bin --expected expected.json\n"
        "\n"
        '4. 看到 "zkc verify-instances: OK" 即为真——本包任何文件被改动一个\n'
        "   字节，验证都会被拒绝。\n"
        "\n"
        "（无需信任飞证平台——验证只依赖数学与链上公示）\n"
        "\n"
        "【文件清单】\n"
        "  proof.bin             零知识证明本体（数学对象，不可伪造）\n"
        "  verifier_param.bin    验证参数（与证明配套，公开）\n"
        "  instances.json        公开实例（被证明的事实的公开指纹）\n"
        "  verdict.json          出证机器的判决与性能记录（出证时生成）\n"
        "  expected.json         期望绑定（验证方核对实例用的公开期望值）\n"
        "  binding.json          引擎签名的轨迹绑定（TRAIL 案卷；离线可验签）\n"
        "  summary.json          本包清单与各件 SHA-256（桥打包时生成）\n"
        f"{expected_note}"
    )


def _assert_bundle_zero_identity(texts: dict[str, str]) -> None:
    """打包前零身份自检：全部文本件（案卷 JSON+桥生成两件）逐一扫描禁用
    字段名——命中抛 ValueError（端点转 500 fail-closed，绝不带病出包）。"""
    for name, text in texts.items():
        for banned in _BUNDLE_BANNED:
            if banned in text:
                raise ValueError(
                    f"出示包零身份红线：{name} 含禁用字段名 {banned!r}——拒绝打包"
                )


def _build_case_bundle(case_id: str) -> tuple[bytes, dict]:
    """聚合出示包：读案卷→生成 README/summary→零身份自检→zip 字节。
    返回 (zip_bytes, summary_dict)——端点与单测共用（纯本地计算，无副作用，
    源案卷只读）。zip 条目时间戳定值+条目序固定 ⟹ 同案卷重复打包字节一致。"""
    import io
    import json as _json
    import zipfile

    case_dir = _cases_dir() / case_id
    files = _bundle_read_case(case_dir)
    if not files:
        raise FileNotFoundError("案卷不存在或无任何证明件")
    verdict = _bundle_json(files, "verdict.json")
    expected = _bundle_json(files, "expected.json")
    # 档位判定：verdict.profile 权威；verdict 缺失时按 expected 形态回落
    # （chain_head_hex 非空=TRAIL 判据，与 zksvc verify_instances 同口径）。
    if verdict and verdict.get("profile") in ("auth", "trail"):
        profile = verdict["profile"]
    elif expected and str(expected.get("chain_head_hex") or "").strip():
        profile = "trail"
    else:
        profile = "unknown"

    # 指纹摘要：verdict 记录值 + 本端对 proof.bin 重算 SM3 对账（tamper 面：
    # 案卷文件若被改动，对账即 False——如实呈现，不替验证方下结论）。
    proof_sm3_match = None
    if "proof.bin" in files and verdict and verdict.get("proof_sm3"):
        from telemetry import sm3_bytes

        proof_sm3_match = sm3_bytes(files["proof.bin"]).hex() == verdict["proof_sm3"]

    readme = _bundle_readme(
        case_id, profile, verdict, "expected.json" in files, _backend_api().rstrip("/")
    )

    # 授权窗（按档取最优线索；两处都查不到=如实 None——summary 呈现 null）
    window = _bundle_task_window(case_id) if profile != "trail" else None
    trip = _bundle_trip_row(case_id) if profile == "trail" else None

    summary: dict = {
        "kind": "fz-proof-bundle",
        "case_id": case_id,
        "profile": profile,
        "verdict": (verdict or {}).get("verdict"),
        "proved_at_unix": (verdict or {}).get("created_unix_ts"),
        "verify_seconds": (verdict or {}).get("verify_s"),
        "proof_fingerprints": {
            "proof_sm3_from_verdict": (verdict or {}).get("proof_sm3"),
            "verifier_param_sm3_from_verdict": (verdict or {}).get("verifier_param_sm3"),
            "proof_sm3_recheck_match": proof_sm3_match,
        },
        "auth_window": (
            {"source": "trip_index", **{
                k: trip.get(k) for k in (
                    "auth_id", "window", "n_samples_total", "fence_alt_cm", "created_at")
            }} if trip else window
        ),
        "trail_expectation": (
            {k: expected.get(k) for k in (
                "chain_head_hex", "alt_max_cm", "t_start", "sample_period_ms", "fence")}
            if profile == "trail" and expected else None
        ),
        "files": [
            {"name": "README-验证指引.txt", "bytes": len(readme.encode("utf-8")),
             "sha256": _sha256_hex(readme.encode("utf-8"))},
        ] + [
            {"name": n, "bytes": len(files[n]), "sha256": _sha256_hex(files[n])}
            for n in _BUNDLE_ARTIFACTS if n in files
        ],
        "missing": [n for n in _BUNDLE_ARTIFACTS if n not in files],
        "verify_command": (
            "zkc verify-instances --instances instances.json --proof proof.bin"
            " --vp verifier_param.bin --expected expected.json"
        ),
        "verify_tool_page": _backend_api().rstrip("/") + "/verify/",
        "generator": "fz-bridge bundle/1（确定性打包：同案卷重复打包字节一致——"
                     "zip 整体 sha256 可公示复核；打包时刻即 HTTP 响应时刻，"
                     "案卷时间面以 proved_at_unix 为准）",
    }

    # 零身份自检（红线 fail-closed——含桥自生成两件+案卷全部 JSON 件）
    texts = {
        "README-验证指引.txt": readme,
        "summary.json": _json.dumps(summary, ensure_ascii=False, indent=1),
    }
    for n in _BUNDLE_ARTIFACTS:
        if n.endswith(".json") and n in files:
            texts[n] = files[n].decode("utf-8", "replace")
    _assert_bundle_zero_identity(texts)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # 压缩选型（案卷 MB 级——实测定谳，见批报告）：proof.bin/vp 并非纯随机
        # 字节（承诺有序列结构），DEFLATED 实测 proof 71.8%/vp 9.9% 体积，
        # 22MB 档 CPU <0.5s——全件 DEFLATED。条目序=清单序+时间戳定值
        # （确定性 zip：同案卷重复打包字节一致）。
        for n in _BUNDLE_ARTIFACTS:
            if n not in files:
                continue
            zi = zipfile.ZipInfo(n, date_time=_BUNDLE_ZIP_EPOCH)
            zi.external_attr = 0o644 << 16
            zi.compress_type = zipfile.ZIP_DEFLATED  # ZipInfo 缺省 STORED——须显式
            zf.writestr(zi, files[n])
        for n, text in (("README-验证指引.txt", readme),
                        ("summary.json", texts["summary.json"])):
            zi = zipfile.ZipInfo(n, date_time=_BUNDLE_ZIP_EPOCH)
            zi.external_attr = 0o644 << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(zi, text.encode("utf-8"))
    return buf.getvalue(), summary


@router.get("/case/{case_id}/bundle")
def case_bundle(case_id: str, request: Request = None):
    """出示包打包端点（丙-5 L2）：案卷全部证明件+桥侧生成 summary.json/
    README-验证指引.txt 聚合为一个 zip——第三方拿到后 5 秒独立验证。
    响应 application/zip，文件名 fz-proof-{case_id[:8]}.zip。缺件如实跳过并
    在 summary.missing 标注；零身份红线 fail-closed（文本件含身份字段名=500
    拒绝打包，绝不带病出包）。"""
    import re as _re
    import time as _t

    from fastapi import Response

    limited = _rate_limit_ip(request)  # MB 级读+打包——下载面同限速纪律
    if limited is not None:
        return limited
    if not _re.fullmatch(r"[0-9a-f]{8,64}", case_id.lower()):
        return JSONResponse(status_code=400, content={"code": "bad_case_id"})
    # 9p 可见性窗口（与单件下载端点同纪律）：案卷空时短重试再判 404。
    try:
        for _ in range(3):
            try:
                zip_bytes, _summary = _build_case_bundle(case_id.lower())
                break
            except FileNotFoundError:
                _t.sleep(0.4)
        else:
            return JSONResponse(
                status_code=404,
                content={"code": "no_case", "message": "案卷不存在或无任何证明件"},
            )
    except ValueError as e:  # 零身份红线 fail-closed
        return JSONResponse(
            status_code=500,
            content={"code": "identity_leak_blocked", "message": str(e)},
        )
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={
            "Content-Disposition":
                f'attachment; filename="fz-proof-{case_id[:8]}.zip"',
        },
    )


@router.get("/case/{case_id}/{artifact}")
def case_artifact(case_id: str, artifact: str):
    """判决件三件套下载（R1-6 合规证书：proof/verifier_param/verdict）。
    ENOENT 短重试（3×0.4s）：Windows zkc 写 ↔ WSL 桥读的 9p 可见性窗口为
    非确定时长 [实测 0.1s~6s+]——重试在端点内 ride-out，对所有消费方生效。"""
    from fastapi import Response

    import re as _re
    import time as _t

    if not _re.fullmatch(r"[0-9a-f]{8,64}", case_id.lower()):
        return JSONResponse(status_code=400, content={"code": "bad_case_id"})
    if artifact not in ("proof.bin", "verifier_param.bin", "verdict.json", "instances.json", "expected.json", "binding.json"):
        return JSONResponse(status_code=404, content={"code": "no_artifact"})
    path = _cases_dir() / case_id.lower() / artifact
    for _ in range(3):
        if path.is_file():
            break
        _t.sleep(0.4)
    if not path.is_file():
        return JSONResponse(status_code=404, content={"code": "no_artifact"})
    media = "application/json" if artifact.endswith(".json") else "application/octet-stream"
    return Response(content=path.read_bytes(), media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="{artifact}"'})


@router.post("/start")
def start_prove(body: ProveStartIn, request: Request = None) -> JSONResponse:
    limited = _rate_limit_ip(request)  # 绑定面获取在闸外——无闸洪泛的最低成本闸前移
    if limited is not None:
        return limited
    case_id = secrets.token_hex(8)
    task_id = uuid.uuid4().hex
    # 出示钥 fail-fast（2026-10-01 一次性出示钥批终验）：空/坏形态的 sk′/pk′
    # 在受理面人话拒绝——放行到装配面只会烧一遍出证流程再 failed（换设备
    # 场景：sk′ 只存签发标签页会话域，新设备无 sk′ 应被指引重签而非空跑）。
    if not body.holder_sk_hex or len(body.holder_sk_hex) != 64:
        return JSONResponse(
            status_code=400,
            content={"code": "sub_key_missing",
                     "message": ("缺少本张子凭证的出示私钥 sk′——它只在签发子凭证的"
                                 "标签页会话中。请回到「我的记录」重新签发子凭证后再申请。")},
        )
    if not body.holder_pk_hex or len(body.holder_pk_hex) != 128:
        return JSONResponse(
            status_code=400,
            content={"code": "bad_input", "message": "出示公钥形态非法（须 128 hex X‖Y）"},
        )
    # 绑定面在请求线程单源获取（fail-fast：服务端不可达即同步报错，不进 assembling）。
    # 响应携带绑定快照（t_epoch/alt_max/required_level）——申请方 apply 必须消费
    # 这里的 t_epoch（与证明实例 21 同源），不得自行再取绑定面。
    try:
        b = _http_get(
            f"{_backend_api()}/authz/binding?class_id={body.class_id}"
            f"&plan_hash_hex={body.plan_hash_hex}&nonce_hex={body.nonce_hex}"
        )
        binding = b["data"]
    except BridgeHttpError as e:
        # B3 人话化：后端信封拒绝原样透传（code/message/status——前端按码分流）
        return JSONResponse(
            status_code=e.status,
            content={"code": e.code, "message": e.message},
        )
    except Exception as e:  # noqa: BLE001
        return JSONResponse(
            status_code=502,
            content={"code": "binding_unavailable", "message": f"绑定面获取失败: {e}"},
        )
    with _LOCK:
        resp = _admit_task_locked(
            task_id,
            {
                "status": "assembling",
                "case_id": case_id,
                "error": None,
                "t_start": binding.get("t_epoch"),
                "alt_max": binding.get("alt_max"),
                "kind": "auth", "stage_ts": {}, "stage": None,
                "prove_heartbeat": None, "pid": None,
            },
            kind="auth",
            t_epoch=binding.get("t_epoch"),
        )
        if resp is not None:
            return resp
    _spawn_heartbeat(task_id)
    t = threading.Thread(target=_assemble_and_prove, args=(task_id, body, binding), daemon=True)
    t.start()
    return JSONResponse(
        status_code=200,
        content={
            "code": "ok",
            "task_id": task_id,
            "case_id": case_id,
            "binding": {
                "t_epoch": binding.get("t_epoch"),
                "alt_max": binding.get("alt_max"),
                "required_level": binding.get("required_level"),
            },
        },
    )


@router.get("/task/{task_id}")
def task_status(task_id: str) -> JSONResponse:
    """任务状态查询：内存活任务优先（零 I/O），未命中读 prove_tasks 表（任务二
    ——桥重启后任务不蒸发：重启恢复面如实 failed 的任务仍可查）。响应含
    stage/stage_ts（分段迹）、prove_heartbeat（心跳）、lease_until（看门狗租约）
    ——并发卡死/慢段一眼定位。"""
    with _LOCK:
        t = _TASKS.get(task_id)
        snap = dict(t) if t is not None else None
    if snap is None:
        snap = _db_task_get(task_id)
    if snap is None:
        return JSONResponse(status_code=404, content={"code": "task_not_found", "message": "出证任务不存在", "data": None})
    return JSONResponse(status_code=200, content={
        "code": "ok",
        "data": {
            "status": snap.get("status"),
            "case_id": snap.get("case_id"),
            "error": snap.get("error"),
            # B3 人话化：后端信封业务码透传（revoked/stale_rev_root/…）——
            # 前端按码分流专属判词；通用失败=字段缺省 None（既有消费面不破）
            "error_code": snap.get("error_code"),
            "t_start": snap.get("t_start"),
            "alt_max": snap.get("alt_max"),
            # 二批换代：采样周期+围栏 4 界（第三方复验期望面——expected.json
            # 同源透传，复验不圆证）
            "sample_period_ms": snap.get("sample_period_ms"),
            "fence": snap.get("fence"),
            # 分段迹/心跳/租约（2026-10-02 乙2 打点+2026-10-04 根修批可观测面）
            "kind": snap.get("kind"),
            "stage": snap.get("stage"),
            # 构型档位（批 4-4）：出证子进程构型 profile——实测数字对应哪个构型
            # 一望而知（stage 观测面同源）
            "zk_profile": snap.get("zk_profile"),
            "stage_ts": snap.get("stage_ts") or {},
            "prove_heartbeat": snap.get("prove_heartbeat"),
            "lease_until": snap.get("lease_until"),
            "pid": snap.get("pid"),
        },
    })
