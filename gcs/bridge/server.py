"""gcs/bridge 主服务（B5）：地面站桥接 API（TCB 第①层声明）。

启动：uvicorn server:app --host 127.0.0.1 --port 8100
（PYTHONPATH=uas/backend:uas/gcs/bridge——backend app 包与 bridge 模块平级无冲突）
端点：POST /arm、POST /telemetry/start|sample|breach、GET /audit。
"""

from __future__ import annotations

import os
import threading
import time

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

_engine_pub_cache: str | None = None
from device_key import device_keypair
from fence import TelemetryChain
from sitl_link import FakeLink, FlightGate, SITLLink
from telemetry import LocalAudit

app = FastAPI(title="FZ-GCS-Bridge", version="0.1")

from prover import router as prove_router

app.include_router(prove_router)

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

_audit = LocalAudit()
# S2 真接线（R1-4）：FZ_GCS_LINK=sitl ⟹ 真 MAVLink 面替换替身（B5 配方连接串
# FZ_SITL_CONN，默认 tcp:127.0.0.1:5770 SERIAL0 单连接）；默认 fake=CI/单测面。
if os.environ.get("FZ_GCS_LINK") == "sitl":
    _link = SITLLink()
    # 舒适参数尽力写入（进程生命周期仅此一次——PILOT_SPEED_UP 在本构建无确认
    # 响应，12s 后 warn 即止；**严禁挪回 attempt_arm**：后台 set_param 持 _lock
    # 跑满 3×4s 超时循环，会毒化 ARM 关键路径 12s——2026-09-30 ARM ACK ~10s
    # 延迟的根因即 attempt_arm 内的冗余重复写入，已根修删除）
    _link.set_param_background("PILOT_SPEED_UP", 400)
else:
    _link = FakeLink()
_gate = FlightGate(_link, _audit)
_chain: TelemetryChain | None = None
_chain_started_ts: float | None = None
_breach_event_filed = False  # 违规事件已转发真链（前端切页重挂靠回放）

_SERIAL = os.environ.get("FZ_DEVICE_SERIAL", "FZ-SN-DEV-01")
_DEV_PRIV, _DEV_PUB = device_keypair(_SERIAL)


class ArmIn(BaseModel):
    token_payload_hex: str
    plan_hash_hex: str
    plan_altitude_m: int | None = None  # 计划作业高度（本机计划仓——围栏联动 min）


class ChainStartIn(BaseModel):
    auth_id: int
    fence_state_hex: str = "01007800"


class SampleIn(BaseModel):
    t_epoch: int
    alt_cm: int
    lat_1e7: int
    lon_1e7: int


@app.post("/arm")
def arm(body: ArmIn):
    return _gate.attempt_arm(
        bytes.fromhex(body.token_payload_hex), body.plan_hash_hex,
        plan_altitude_m=body.plan_altitude_m,
    )


def _require_armed():
    """授权前置（阶段一）：未 ARM 不产生"飞行记录"——遥测/起飞动作的统一门。"""
    if not getattr(_gate, "is_armed", False):
        return {"ok": False, "code": "not_armed",
                "message": "请先完成授权解锁（ARM）——无授权不产生飞行记录"}
    return None


@app.post("/telemetry/start")
def telemetry_start(body: ChainStartIn):
    global _chain
    denied = _require_armed()
    if denied:
        return denied
    _chain = TelemetryChain(body.auth_id, _DEV_PRIV, bytes.fromhex(body.fence_state_hex))
    # 新架次=干净账本（2026-09-29 实测：breach_seen 闩锁跨架次存活，第二架次
    # 遥测立刻带"已触发围栏"脏标志+伪造违规事件——起链即归零）
    _link.breach_seen = False
    _link.last_statustext = None
    global _chain_started_ts, _breach_event_filed
    _chain_started_ts = time.time()
    _breach_event_filed = False
    return {"ok": True, "genesis_head_hex": _chain.head.hex(), "device_pub_hex": _DEV_PUB}


@app.get("/telemetry/state")
def telemetry_state():
    """飞行链状态回放（2026-09-29 切页修复）：前端进入飞行页先问桥"现在到底
    什么状态"照实恢复——服务器是唯一事实源，页面刷新/切页往返不再装作没飞过。
    只读；chain_not_started=本架次尚未起链（前端按未开始渲染）。"""
    if _chain is None:
        return {"chain_active": False}
    enable = _chain.fence_state[0] if len(_chain.fence_state) >= 3 else 0
    alt_max_cm = int.from_bytes(_chain.fence_state[1:3], "big") if len(_chain.fence_state) >= 3 else 0
    last_cp = _chain.checkpoints[-1] if _chain.checkpoints else None
    fc_armed = getattr(_link, "last_fc_armed", None)
    return {
        "chain_active": True,
        "auth_id": _chain.auth_id,
        "genesis_head_hex": _chain.genesis_head.hex(),
        "head_hex": _chain.head.hex(),
        "n_samples": _chain.n,
        "alt_max_cm": alt_max_cm,
        "fence_enabled": bool(enable),
        "checkpoint_count": len(_chain.checkpoints),
        "last_checkpoint_seq": last_cp["seq"] if last_cp else 0,
        "anchored_seq": _chain.anchored_seq,
        "breach_seen": bool(getattr(_link, "breach_seen", False)),
        "breach_event_filed": _breach_event_filed,
        "fc_armed": fc_armed,
        "started_ts": _chain_started_ts,
    }


@app.post("/telemetry/sample")
def telemetry_sample(body: SampleIn):
    if os.environ.get("FZ_ALLOW_SYNTHETIC_SAMPLE") != "1":
        return JSONResponse(
            status_code=403,
            content={"ok": False, "code": "synthetic_disabled",
                     "message": "合成采样已关闭（真实测试策略）——真遥测走解锁后自动采样"},
        )
    denied = _require_armed()
    if denied:
        return denied
    if _chain is None:
        return {"ok": False, "code": "chain_not_started"}
    head = _chain.push(body.t_epoch, body.alt_cm, body.lat_1e7, body.lon_1e7)
    cp = _chain.maybe_checkpoint(time.time(), None)
    return {"ok": True, "head_hex": head.hex(), "n": _chain.n, "checkpoint": cp}


@app.get("/telemetry/sitl_sample")
def telemetry_sitl_sample(t_epoch: int):
    """SITL 真采样（R1-4）：高度取自真飞控 GLOBAL_POSITION_INT（relative_alt mm
    折 cm），入链+围栏触发检测（STATUSTEXT）一体。fake 链路下拒绝（fail-closed
    ——不伪造遥测）。"""
    denied = _require_armed()
    if denied:
        return denied
    if _chain is None:
        return {"ok": False, "code": "chain_not_started"}
    if not isinstance(_link, SITLLink):
        return {"ok": False, "code": "not_sitl_link", "message": "FZ_GCS_LINK!=sitl（无真实遥测面）"}
    pos = _link.global_position()
    if pos is None:
        return {"ok": False, "code": "telemetry_timeout"}
    # 相对高度地面抖动可为负（GPS/气压计噪声——实测 -1cm 即令 TRAIL 窗口行
    # u16 字段打包越界 500）。记录面归一：地下读数=地面基准 0（链行与窗口行
    # 同源一致；飞行中语义不受影响——真实高度恒 ≥0）。
    alt_cm = max(0, pos["alt_mm"] // 10)
    _link.drain(0)
    head = _chain.push(t_epoch, alt_cm, pos["lat_1e7"], pos["lon_1e7"])
    cp = _chain.maybe_checkpoint(time.time(), None)
    breached = _link.breach_seen
    event = None
    if breached:
        event = _chain.breach_event(t_epoch, alt_cm, 1)  # source=1 固件围栏
    # ③GCS 化旁路字段（姿态/飞控模式——仅 UI 态势面，不进 14B 链行）。
    att = getattr(_link, "last_attitude", None)
    mode = getattr(_link, "last_mode", None)
    return {
        "ok": True,
        "head_hex": head.hex(),
        "n": _chain.n,
        "alt_cm": alt_cm,
        "checkpoint": cp,
        "fence_breached": breached,
        "last_statustext": _link.last_statustext,
        "event": event,
        "att": att,
        "mode": mode,
        # 飞控侧上锁位旁路（UI 横幅：gate armed 但 FC 落地自动上锁=提醒重解锁）
        "armed": getattr(_link, "last_fc_armed", None),
        # P3 遥测真实感：电池/GPS/HUD（drain 缓存直读——全部 MAVLink 现成字段）
        "bat": getattr(_link, "last_bat", None),
        "gps": getattr(_link, "last_gps", None),
        "hud": getattr(_link, "last_hud", None),
    }


@app.post("/telemetry/breach")
def telemetry_breach(t_epoch: int, alt_cm: int, source: int = 2):
    denied = _require_armed()
    if denied:
        return denied
    if _chain is None:
        return {"ok": False, "code": "chain_not_started"}
    return {"ok": True, "event": _chain.breach_event(t_epoch, alt_cm, source)}


def _get_backend(path: str) -> dict:
    """backend GET 代理（R3-B2：/engine_pub 数据源——回环禁系统代理）。"""
    import json as _json
    import urllib.error as _ue
    import urllib.request as _ur

    opener = _ur.build_opener(_ur.ProxyHandler({}))
    with opener.open(_backend_api() + path, timeout=15) as r:
        return _json.loads(r.read().decode())


def _backend_api() -> str:
    import os as _os

    return _os.environ.get("FZ_API_BASE", "http://127.0.0.1:8000")


def _post_engine(path: str, body: dict) -> dict:
    """backend engine 面转发（阶段一 D-Ⅰ-8：检查点/事件上链——fail-closed 禁吞）。"""
    import json as _json
    import os as _os
    import urllib.error as _ue
    import urllib.request as _ur

    opener = _ur.build_opener(_ur.ProxyHandler({}))  # 回环禁系统代理
    headers = {"Content-Type": "application/json"}
    # R3-0.5（评审 P0-2）：engine 面认证头补齐——旧实现永不携带 ⟹ 检查点/
    # 事件上链产品路径 100% 401（单测自带头故全绿，产品路断）。token 由
    # 启动器与 backend 同源注入（FZ_ENGINE_TOKEN）。
    tok = _os.environ.get("FZ_ENGINE_TOKEN", "")
    if tok:
        headers["X-Engine-Token"] = tok
    req = _ur.Request(
        _backend_api() + path,
        data=_json.dumps(body).encode(),
        headers=headers,
        method="POST",
    )
    # R3-1（评审 S1 [3] 500 定谳）：URLError（回环瞬断/后端未就绪）原先直接
    # 裸抛 ⟹ 桥接 500 无结构化语义；改为 1 次重试后结构化返回（fail-closed
    # 仍由调用方裁决——锚定面返回 ok:False 可断点续锚）。
    for attempt in (0, 1):
        try:
            with opener.open(req, timeout=30) as r:
                return _json.loads(r.read().decode())
        except _ue.HTTPError as e:
            return _json.loads(e.read().decode())
        except (_ur.URLError, TimeoutError, ConnectionError) as e:
            if attempt == 0:
                import time as _t

                _t.sleep(1.0)
                continue
            return {"ok": False, "code": "backend_unreachable", "message": str(e)[:200]}


@app.post("/telemetry/anchor")
def telemetry_anchor():
    """检查点真链锚定（阶段一 D-Ⅰ-8）：pending 检查点逐个转发 backend /engine/anchor。

    推进 anchored_seq（只前进）；单条失败=停止并结构化回传（fail-closed——
    后续重试从断点续锚，不跳号不吞错）。
    """
    if _chain is None:
        return {"ok": False, "code": "chain_not_started"}
    results = []
    for cp in _chain.checkpoints:
        if cp["seq"] <= _chain.anchored_seq:
            continue
        r = _post_engine(
            "/engine/anchor",
            {
                "auth_id": cp["auth_id"],
                "seq": cp["seq"],
                "chain_head_hex": cp["chain_head_hex"],
                "fence_state_hex": cp["fence_state_hex"],
                "sig_hex": cp["sig_hex"],
                "device_pub_hex": _DEV_PUB,
            },
        )
        results.append({"seq": cp["seq"], "resp": r})
        if not r.get("ok"):
            return {"ok": False, "code": "anchor_failed", "detail": results[-1], "anchored_seq": _chain.anchored_seq}
        _chain.anchored_seq = cp["seq"]
    return {"ok": True, "anchored": len(results), "anchored_seq": _chain.anchored_seq, "results": results}


@app.post("/telemetry/event")
def telemetry_event(body: dict):
    """违规事件真链上链（阶段一 D-Ⅰ-8）：转发 backend /engine/event。

    body=event dict（/telemetry/sitl_sample 或 /telemetry/breach 产物：
    {auth_id, event_type, event_hash_hex, ...}——多余字段 backend 忽略）。
    """
    if _chain is None:
        return {"ok": False, "code": "chain_not_started"}
    if not {"auth_id", "event_type", "event_hash_hex"} <= set(body):
        return {"ok": False, "code": "bad_event"}
    global _breach_event_filed
    r = _post_engine(
        "/engine/event",
        {
            "auth_id": int(body["auth_id"]),
            "event_type": int(body["event_type"]),
            "event_hash_hex": body["event_hash_hex"],
        },
    )
    if r.get("ok"):
        _breach_event_filed = True  # 状态回放面：切页回来的页面知道事件已上链
    return r


@app.post("/sitl/wait_gps")
def sitl_wait_gps(timeout_s: int = 120):
    """等待 GPS 锁（B5：SITL 起后 fix_type≥3 才可 ARM）。fake 链路=直接 ok。"""
    if isinstance(_link, SITLLink):
        locked = _link.wait_gps_lock(timeout_s)
        return {"ok": locked, "mode": "sitl"}
    return {"ok": False, "code": "sitl_required", "mode": "fake"}


_CLIMB_ABORT = threading.Event()


@app.post("/sitl/abort")
def sitl_abort():
    """中止进行中的有界爬升（接管语义——手动爬升/悬停点击即停自动段）。"""
    _CLIMB_ABORT.set()
    return {"ok": True, "aborted": True}


@app.post("/sitl/climb")
def sitl_climb(pwm: int = 1700, hold_s: float = 2.0,
               until_alt_cm: int | None = None, timeout_s: float = 120.0,
               min_alt_cm: int | None = None):
    """油门杆指令（B5-d3：真实飞手形态）+围栏触发检测。

    控制语义（2026-09-27 队长实测「悬停落地」根修）：指令前自动切入定高模式
    （ALT_HOLD）——油门杆=升降率（1500 保持 / >1500 爬升 / <1500 下降）。
    STABILIZE 无定高回路，中立油门=缓降，「悬停」在其下必然落地。
    fake 链路=拒绝（不伪造飞行）。飞控侧已上锁=诚实拒绝（override 对上锁
    电机无效，静默 no-op 会让飞手误判系统故障）。

    2026-09-28 队长实测七（自动爬升锯齿/慢/接管乱根修）：
    - until_alt_cm 给定=桥侧**有界连续爬升**：内部循环脉冲直到目标高度或
      超时（脉冲段+回中段交替，恒定率无锯齿）——替代客户端逐拍 HTTP 调用
      的节奏抖动；期间每段检查飞控上锁位（回落即诚实中止）与围栏触发。
    - 中止：任何 /sitl/abort（手动爬升/悬停的接管动作）立即回中并返回
      code=aborted。
    - 脉冲模式（until 缺省）：单段油门+回中（手动爬升手感）。"""
    denied = _require_armed()
    if denied:
        return denied
    if not isinstance(_link, SITLLink):
        return {"ok": False, "code": "not_sitl_link", "message": "FZ_GCS_LINK!=sitl"}
    if getattr(_link, "last_fc_armed", None) is False:
        return {
            "ok": False,
            "code": "fc_disarmed",
            "message": "飞控已上锁（地面怠速自动上锁）——请重新点击「解锁起飞」（同一授权，无需重新出证）",
        }
    try:
        _link.set_flight_mode(SITLLink.COPTER_ALT_HOLD, "ALT_HOLD")
    except Exception as e:  # noqa: BLE001 —— 模式未确认=诚实拒绝（不盲发油门）
        return {"ok": False, "code": "mode_switch_failed", "message": str(e)}
    _CLIMB_ABORT.clear()
    if until_alt_cm is None:
        # 下降地面保护（2026-09-29 队长指令：下降最多到地面 0m）：下降脉冲
        # 且高度已达下限 → 不发下降油门，直接回中保持
        if pwm < 1500 and min_alt_cm is not None:
            alt_mm = _link.relative_alt_mm()
            if alt_mm is not None and alt_mm // 10 <= min_alt_cm:
                return {"ok": True, "code": "floor_reached",
                        "message": "已到地面保护高度——下降停止",
                        "alt_cm": alt_mm // 10,
                        "armed": getattr(_link, "last_fc_armed", None),
                        "mode": getattr(_link, "last_mode", None)}
        _link.rc_throttle_override(pwm, hold_s=hold_s)
        alt_mm = _link.relative_alt_mm()
        _link.drain(0)
        return {
            "ok": True,
            "alt_cm": (alt_mm // 10) if alt_mm is not None else None,
            "armed": getattr(_link, "last_fc_armed", None),
            "mode": getattr(_link, "last_mode", None),
            "fence_breached": _link.breach_seen,
            "last_statustext": _link.last_statustext,
        }
    # 有界连续爬升（桥侧闭环）
    import time as _t

    deadline = _t.time() + max(5.0, float(timeout_s))
    reached = False
    aborted = False
    while _t.time() < deadline:
        if _CLIMB_ABORT.is_set():
            aborted = True
            break
        if getattr(_link, "last_fc_armed", None) is False:
            _CLIMB_ABORT.set()
            return {
                "ok": False, "code": "fc_disarmed",
                "message": "飞控已上锁——自动爬升中止。请重新点击「解锁起飞」（同一授权延续）",
            }
        if _link.breach_seen:
            break  # 围栏触发——停止爬升（事件/取证由采样面负责）
        alt_mm = _link.relative_alt_mm()
        if alt_mm is not None and alt_mm // 10 >= until_alt_cm:
            reached = True
            break
        _link.rc_throttle_override(pwm, hold_s=0.5, neutral=None)  # 段间连续（不回中）
    _link.rc_throttle_override(1500, hold_s=0.05)  # 回中保持
    _link.drain(0)
    alt_mm = _link.relative_alt_mm()
    if aborted:
        return {"ok": False, "code": "aborted", "message": "自动爬升已被接管（回中保持）",
                "alt_cm": (alt_mm // 10) if alt_mm is not None else None}
    if not reached:
        return {"ok": False, "code": "timeout",
                "message": "自动爬升超时（未达目标——已回中保持）",
                "alt_cm": (alt_mm // 10) if alt_mm is not None else None,
                "fence_breached": _link.breach_seen}
    return {
        "ok": True, "reached": reached, "alt_cm": (alt_mm // 10) if alt_mm is not None else None,
        "armed": getattr(_link, "last_fc_armed", None),
        "mode": getattr(_link, "last_mode", None),
        "fence_breached": _link.breach_seen,
        "last_statustext": _link.last_statustext,
    }


@app.post("/sitl/disarm")
def sitl_disarm():
    """停转+释放 RC（判决收尾）。"""
    if not isinstance(_link, SITLLink):
        return {"ok": False, "code": "not_sitl_link"}
    _gate.disarm()
    return {"ok": True}


@app.get("/arm/status")
def arm_status(token_payload_hex: str):
    """令牌消费状态查询（2026-09-28 队长实测七）：解锁按钮状态的单一事实源
    =审计库（SQLite 持久，跨桥重启/页面刷新存活）。

    used=该令牌已有成功解锁记录；can_rearm=同会话授权延续窗口（授权门仍开 ∧
    飞控侧已回落上锁——重解锁路径可用，此时前端按钮应显式可点）。"""
    try:
        payload = bytes.fromhex(token_payload_hex)
    except ValueError:
        return {"ok": False, "code": "bad_hex", "message": "令牌须 hex"}
    used = _audit.first_arm(payload) is not None
    can_rearm = bool(
        used
        and getattr(_gate, "is_armed", False)
        and getattr(_link, "last_fc_armed", None) is False
    )
    return {"ok": True, "used": used, "can_rearm": can_rearm}


@app.get("/link_status")
def link_status():
    mode = "sitl" if isinstance(_link, SITLLink) else "fake"
    info = {"mode": mode, "conn": getattr(_link, "conn_str", None)}
    if mode == "sitl":
        info["breach_seen"] = _link.breach_seen
        info["last_statustext"] = _link.last_statustext
    return info


@app.get("/engine_pub")
def engine_pub():
    """引擎公钥（公开面——Web 端验签消费）。R3-B2：改代理 backend
    （/authz/engine/pub），桥进程不再持有 FZ_ENGINE_SK（TCB 对齐）。"""
    global _engine_pub_cache
    if _engine_pub_cache:
        return {"engine_pub_hex": _engine_pub_cache}
    try:
        r = _post_engine("/authz/engine/pub", {}) if False else _get_backend("/authz/engine/pub")
        d = r.get("data") or r
        _engine_pub_cache = d["engine_pub_hex"]
        return {"engine_pub_hex": _engine_pub_cache}
    except Exception as e:  # noqa: BLE001
        from fastapi import HTTPException

        raise HTTPException(status_code=503, detail=f"引擎公钥暂不可达: {e}") from e


@app.get("/audit")
def audit():
    return {"arms": _audit._c.execute(
        "SELECT token_hash_hex, auth_id, first_arm_at FROM token_arms").fetchall(),
        "denials": _audit.denials()}
