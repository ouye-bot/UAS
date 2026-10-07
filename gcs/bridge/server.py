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
from device_key import device_keypair, device_serial
from fence import SampleRejected, TelemetryChain
from sitl_link import (
    _REVOKE_CHECK_EVERY_N,
    FakeLink,
    FlightGate,
    SITLLink,
    is_real_link,
    param_delta_ok,
)
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

_SERIAL = device_serial()  # SN 单源（2026-10-06 换代：与桥第 6 查同源）
_DEV_PRIV, _DEV_PUB = device_keypair(_SERIAL)

# 取证面计数器（批1）：/telemetry/state 可见——拒样/围栏漂移/无会话 ARM 处置。
# B5 批2：revoke_alert_events=飞行中吊销复查命中拍数（闩锁存续期每 30s 一拍）。
_COUNTERS = {
    "rejected_samples": 0,
    "fence_drift_events": 0,
    "rogue_arm_events": 0,
    "revoke_alert_events": 0,
}


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
    # 围栏证词单源化（批1-1.3）：检查点签名的围栏态不再来自客户端请求体
    # （body.fence_state_hex 可与固件围栏任意背离=证词伪造面），改由闸门
    # 会话状态构造（ARM 序列写后回读断言过的 fence_state）；auth_id 同源
    # 核对——请求体无对应活跃会话=409。
    session_aid = getattr(_gate, "session_auth_id", None)
    gate_fs = getattr(_gate, "fence_state", None)
    if not getattr(_gate, "is_armed", False) or session_aid is None or gate_fs is None:
        return JSONResponse(
            status_code=409,
            content={
                "ok": False,
                "code": "no_active_session",
                "message": "无活跃授权会话——请先完成授权解锁（ARM），围栏证词由闸门会话单源供给",
            },
        )
    if int(body.auth_id) != int(session_aid):
        return JSONResponse(
            status_code=409,
            content={
                "ok": False,
                "code": "auth_session_mismatch",
                "message": (
                    f"请求 auth_id={body.auth_id} 与当前授权会话（auth_id={session_aid}）不符——"
                    "起链必须对应当前活跃授权（围栏证词单源）"
                ),
            },
        )
    _chain = TelemetryChain(session_aid, _DEV_PRIV, gate_fs)
    # 新架次=干净账本（2026-09-29 实测：breach_seen 闩锁跨架次存活，第二架次
    # 遥测立刻带"已触发围栏"脏标志+伪造违规事件——起链即归零）
    _link.breach_seen = False
    _link.last_statustext = None
    global _chain_started_ts, _breach_event_filed
    _chain_started_ts = time.time()
    _breach_event_filed = False
    return {
        "ok": True,
        "genesis_head_hex": _chain.head.hex(),
        "device_pub_hex": _DEV_PUB,
        "fence_state_hex": gate_fs.hex(),  # 证词源回显（客户端可见实际入链围栏态）
    }


@app.get("/telemetry/state")
def telemetry_state():
    """飞行链状态回放（2026-09-29 切页修复）：前端进入飞行页先问桥"现在到底
    什么状态"照实恢复——服务器是唯一事实源，页面刷新/切页往返不再装作没飞过。
    只读；chain_not_started=本架次尚未起链（前端按未开始渲染）。"""
    if _chain is None:
        return {"chain_active": False, "counters": dict(_COUNTERS),
                # 飞行中吊销告警（B5 批2）：未起链同样可见（闩锁值或 None）
                "revoke_alert": getattr(_gate, "revoke_alert", None)}
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
        # 飞行中吊销告警（B5 批2）：闩锁值或 None——前端切页回放不丢告警
        "revoke_alert": getattr(_gate, "revoke_alert", None),
        "fc_armed": fc_armed,
        "started_ts": _chain_started_ts,
        # 合理性门/取证面计数（批1-1.4/1.6）
        "rejected_count": _chain.rejected_count,
        "last_reject": _chain.last_reject,
        "counters": dict(_COUNTERS),
    }


_FENCE_PATROL_EVERY_N = 40  # 2Hz × 40 样本 = 每 20s 巡检一次（批1-1.2）


def _fence_patrol_if_due(t_srv: int, alt_cm: int) -> dict | None:
    """飞行中围栏巡检（批1-1.2）：每 40 样本（2Hz≈20s）回读
    FENCE_ENABLE/FENCE_ALT_MAX/FENCE_TYPE 与链证词值对拍——任一漂移=breach 类
    审计事件+日志+计数。行为语义=FENCE_ACTION 不动（不新增自动降落：只检测+
    取证，保持取证路径演示不破坏）。回读失败同样按漂移类取证（围栏状态不可
    确认=不可盲信仍在）。返回 None=本拍不巡检或无漂移；dict=漂移取证。"""
    if _chain is None or _chain.n == 0 or _chain.n % _FENCE_PATROL_EVERY_N != 0:
        return None
    fs = _chain.fence_state
    wants = (
        ("FENCE_ENABLE", float(fs[0])),
        ("FENCE_ALT_MAX", float(int.from_bytes(fs[1:3], "big"))),
        ("FENCE_TYPE", 3.0),
    )
    drifts: list[str] = []
    for name, wv in wants:
        try:
            got = _link.get_param(name)
        except Exception as e:  # noqa: BLE001 —— 回读失败=围栏状态不可确认
            drifts.append(f"{name} 回读失败（{str(e)[:80]}）")
            continue
        if not param_delta_ok(wv, got):
            drifts.append(f"{name} 飞控存量 {got} ≠ 证词值 {wv}")
    if not drifts:
        return None
    detail = "飞行中围栏巡检漂移: " + "; ".join(drifts)
    _audit.record_denial("fence_drift_detected", detail)
    _COUNTERS["fence_drift_events"] += 1
    print(f"[fence-patrol] {detail}", flush=True)
    return {"detail": detail, "event": _chain.breach_event(t_srv, alt_cm, 2)}  # source=2 地面站监测


@app.post("/telemetry/sample")
def telemetry_sample(body: SampleIn):
    # 结构性封禁（批1-1.5）：本端点只服务 fake 档受控测试面——真链路形态
    # （SITLLink 非 FakeLink）下手工注样整体不可用（env 开关不得越结构界）。
    if is_real_link(_link):
        return JSONResponse(
            status_code=403,
            content={
                "ok": False,
                "code": "structural_ban",
                "message": "真链路形态禁止手工注样——遥测唯一来源=飞控真采样"
                "（/telemetry/sitl_sample）；合成样仅限 fake 档受控测试",
            },
        )
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
    # 服务端时间轴单源（批1-1.4）：客户端 t_epoch 忽略——链行时间由桥端
    # time.time() 给定（倒拨/前拨不可达）；合理性门超界=拒样+计数。
    t_srv = int(time.time())
    try:
        head = _chain.push(t_srv, body.alt_cm, body.lat_1e7, body.lon_1e7, wall=time.time())
    except SampleRejected as e:
        _COUNTERS["rejected_samples"] += 1
        print(f"[telemetry] 合成样拒绝（{e.code}）: {e.message}", flush=True)
        return {"ok": False, "code": f"sample_{e.code}", "message": e.message,
                "rejected_count": _chain.rejected_count}
    cp = _chain.maybe_checkpoint(time.time(), None)
    return {"ok": True, "head_hex": head.hex(), "n": _chain.n, "checkpoint": cp,
            "t_epoch": t_srv}


@app.get("/telemetry/sitl_sample")
def telemetry_sitl_sample(t_epoch: int):
    """SITL 真采样（R1-4）：高度取自真飞控 GLOBAL_POSITION_INT（relative_alt mm
    折 cm），入链+围栏触发检测（STATUSTEXT）一体。fake 链路下拒绝（fail-closed
    ——不伪造遥测）。

    批1：t_epoch 参数忽略——服务端 time.time() 时间轴单源（客户端不可倒拨）；
    入链经合理性门（fence.push——超界拒样计数）；每 40 样本围栏巡检（漂移=取证
    事件）。"""
    denied = _require_armed()
    if denied:
        return denied
    if _chain is None:
        return {"ok": False, "code": "chain_not_started"}
    if not is_real_link(_link):
        return {"ok": False, "code": "not_sitl_link", "message": "FZ_GCS_LINK!=sitl（无真实遥测面）"}
    pos = _link.global_position()
    if pos is None:
        return {"ok": False, "code": "telemetry_timeout"}
    # 相对高度地面抖动可为负（GPS/气压计噪声——实测 -1cm 即令 TRAIL 窗口行
    # u16 字段打包越界 500）。记录面归一：地下读数=地面基准 0（链行与窗口行
    # 同源一致；飞行中语义不受影响——真实高度恒 ≥0）。
    alt_cm = max(0, pos["alt_mm"] // 10)
    _link.drain(0)
    t_srv = int(time.time())
    try:
        head = _chain.push(t_srv, alt_cm, pos["lat_1e7"], pos["lon_1e7"], wall=time.time())
    except SampleRejected as e:
        _COUNTERS["rejected_samples"] += 1
        print(f"[telemetry] 样本拒绝（{e.code}）: {e.message}", flush=True)
        return {"ok": False, "code": f"sample_{e.code}", "message": e.message,
                "rejected_count": _chain.rejected_count}
    cp = _chain.maybe_checkpoint(time.time(), None)
    breached = _link.breach_seen
    event = None
    drift = None
    if breached:
        event = _chain.breach_event(t_srv, alt_cm, 1)  # source=1 固件围栏
    else:
        drift = _fence_patrol_if_due(t_srv, alt_cm)
        if drift is not None:
            event = drift["event"]  # 前端存在即转发 /telemetry/event（取证上链）
    # 飞行中吊销复查（B5 批2）+授权窗到期收敛（信任根收口件2）：每 60 样本
    # （2Hz≈30s）对 /authz/status 复查。异常不炸采样循环（fail-safe——复查失败
    # 仅日志，遥测主径照常）。同拍（仅复查拍，非每样本——5s 超时网络面不得
    # 进入 2Hz 主径）顺带触发消费回报队列重试（信任根收口件1：采样循环=
    # 飞行期定时器；fail-safe 不炸主径）。
    try:
        rev_alert = _gate.revoke_recheck_if_due(_chain.n)
        if rev_alert is not None:
            _COUNTERS["revoke_alert_events"] += 1
        if _chain.n % _REVOKE_CHECK_EVERY_N == 0:
            _gate._retry_consume_pending()
    except Exception as e:  # noqa: BLE001 —— 复查/重试面故障不阻断取证主径
        rev_alert = None
        print(f"[revoke-alert] 复查异常（fail-safe 继续）: {e}", flush=True)
    # 信任根收口件2：授权窗到期=取证事件上链（source=2 地面站监测——复用
    # drift 事件转发语义，前端将 event 转发 /telemetry/event 落链，取证链
    # 保留）+检查点停锚（/telemetry/anchor 按 _gate.session_converged 拒锚）。
    if rev_alert is not None and rev_alert.get("kind") == "auth_window_expired" and event is None:
        event = _chain.breach_event(t_srv, alt_cm, 2)
        print("[expiry-alert] 到期取证事件已生成（随采样响应出桥上链）", flush=True)
    # ③GCS 化旁路字段（姿态/飞控模式——仅 UI 态势面，不进 14B 链行）。
    att = getattr(_link, "last_attitude", None)
    mode = getattr(_link, "last_mode", None)
    return {
        "ok": True,
        "head_hex": head.hex(),
        "n": _chain.n,
        "alt_cm": alt_cm,
        "t_epoch": t_srv,
        "checkpoint": cp,
        "fence_breached": breached,
        "last_statustext": _link.last_statustext,
        "event": event,
        "fence_drift": drift is not None,
        "fence_drift_detail": drift["detail"] if drift else None,
        "att": att,
        "mode": mode,
        # 飞行中吊销告警（B5 批2）：命中拍回传闩锁值（结构化）——前端即时显告
        "revoke_alert": rev_alert,
        # 飞控侧上锁位旁路（UI 横幅：gate armed 但 FC 落地自动上锁=提醒重解锁）
        "armed": getattr(_link, "last_fc_armed", None),
        # P3 遥测真实感：电池/GPS/HUD（drain 缓存直读——全部 MAVLink 现成字段）
        "bat": getattr(_link, "last_bat", None),
        "gps": getattr(_link, "last_gps", None),
        "hud": getattr(_link, "last_hud", None),
        "rejected_count": _chain.rejected_count,
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

    信任根收口件2（检查点停锚）：授权会话已收敛（撤销/授权窗到期闩锁命中）
    ⟹ 拒绝新锚定（复用 backend auth_revoked 停锚语义——授权终结后不再产生
    新锚定证词；已锚检查点=既成取证，不受影响不回滚）。
    """
    if _chain is None:
        return {"ok": False, "code": "chain_not_started"}
    if getattr(_gate, "session_converged", lambda: False)():
        why = "auth_revoked" if _gate.revoke_alert is not None else "auth_window_expired"
        return {
            "ok": False,
            "code": why,
            "message": (
                "授权会话已终结（{}）——检查点停锚（复用撤销停锚语义）：不再产生新锚定证词，"
                "已锚检查点取证保留".format("链上授权已撤销" if why == "auth_revoked" else "授权窗已到期")
            ),
            "anchored_seq": _chain.anchored_seq,
        }
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
    if is_real_link(_link):
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
    if not is_real_link(_link):
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
    if not is_real_link(_link):
        return {"ok": False, "code": "not_sitl_link"}
    global _last_legit_disarm_ts
    _gate.disarm()
    _last_legit_disarm_ts = time.time()  # 无会话监视的合法停转宽限窗起点
    return {"ok": True}


# ---- 无会话 ARM 监视器（批1-1.6）：FC armed 而闸门无活跃授权会话=令牌外解锁 ----

_ROGUE_ARM_INTERVAL_S = 2.0
_DISARM_GRACE_S = 10.0  # 合法停转后 FC 心跳 armed 位滞后窗——不误报
_last_legit_disarm_ts = 0.0
_rogue_thread_started = False


def rogue_arm_check() -> bool:
    """无会话 ARM 单次检查（后台监视线程每 _ROGUE_ARM_INTERVAL_S 调用）。

    FC armed 位=1 而 _gate 无活跃授权会话（is_armed=False）→ 令牌外解锁形态
    （rogue arm）。处置：立即 DISARM 尝试+结构化审计事件（rogue_arm_detected）
    +日志；事件计数入 /telemetry/state。返回 True=本次检出并已处置。
    单测注：直接调用本函数即可断言（不经线程——确定性）。"""
    fc_armed = getattr(_link, "last_fc_armed", None)
    if fc_armed is not True or getattr(_gate, "is_armed", False):
        return False
    if time.time() - _last_legit_disarm_ts < _DISARM_GRACE_S:
        return False  # 合法停转后的心跳滞后——非 rogue
    _gate.disarm()  # DISARM 尝试+RC 释放+授权态复位（幂等）
    _COUNTERS["rogue_arm_events"] += 1
    detail = "无会话 ARM 检出：FC armed 而桥无活跃授权会话——已发 DISARM 尝试（取证在案）"
    _audit.record_denial("rogue_arm_detected", detail)
    print(f"[rogue-arm] {detail}", flush=True)
    return True


def _start_rogue_arm_monitor() -> None:
    global _rogue_thread_started
    if _rogue_thread_started:
        return
    _rogue_thread_started = True

    def _loop():
        while True:
            try:
                rogue_arm_check()
            except Exception as e:  # noqa: BLE001 —— 监视线程不许死（异常照实留痕）
                print(f"[rogue-arm] 监视检查异常（继续）: {e}", flush=True)
            time.sleep(_ROGUE_ARM_INTERVAL_S)

    threading.Thread(target=_loop, daemon=True, name="rogue-arm-monitor").start()
    print("[rogue-arm] 无会话 ARM 监视器已挂载（2s 周期）", flush=True)


@app.get("/arm/status")
def arm_status(token_payload_hex: str):
    """令牌消费状态查询（2026-09-28 队长实测七）：解锁按钮状态的单一事实源
    =审计库（SQLite 持久，跨桥重启/页面刷新存活）。

    used=该令牌已有成功解锁记录；can_rearm=同会话授权延续窗口（授权门仍开 ∧
    飞控侧已回落上锁——重解锁路径可用，此时前端按钮应显式可点）。
    授权包配额制（2026-10-06 多架次拍板）：增 remaining/sorties（backend
    /authz/status 权威配额——前端「剩余架次 N」显示与新架次按钮判定）与
    local_sorties（本地架次账本计数）。查询面故障=配额三值 None（前端退化
    回令牌一次性显示；配额执法在闸门预检面，不受显示面故障影响）。"""
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
    from sitl_link import authz_quota_fetch

    quota = authz_quota_fetch(payload)
    return {
        "ok": True,
        "used": used,
        "can_rearm": can_rearm,
        "remaining": quota["remaining"],
        "sorties": quota["sorties"],
        "local_sorties": _audit.sortie_count(payload),
    }


@app.get("/link_status")
def link_status():
    # 批1-1.5：FakeLink 是 SITLLink 子类——裸 isinstance 在 fake 档误报
    # "sitl"（真档探活假绿）。真链路面判定单源 is_real_link。
    mode = "sitl" if is_real_link(_link) else "fake"
    info = {"mode": mode, "conn": getattr(_link, "conn_str", None)}
    if mode == "sitl":
        info["breach_seen"] = _link.breach_seen
        info["last_statustext"] = _link.last_statustext
    return info


@app.get("/engine_pub")
def engine_pub():
    """引擎公钥+本机序列号（公开面——Web 端验签与 SN 单源消费）。R3-B2：改代理
    backend（/authz/engine/pub），桥进程不再持有 FZ_ENGINE_SK（TCB 对齐）。

    device_serial（SN 单源根治 2026-10-07）：响应携带本机序列号读数（与第 6 查
    device_serial()、设备钥派生同一单源）——网页注册/申请自此取桥读数，网页自由
    文本与桥本机读数无对齐 ⟹ 首次 ARM 必 sn_mismatch 的产品缺口就此封死。
    安全注记：桥仅绑 127.0.0.1/WSL loopback（CORS 限 localhost/127.0.0.1），
    序号公开面=本机进程；demo 档设备钥本由 SN 派生（公开已知语义），生产档钥
    来自 SE、SN 公开无碍——公开本机 SN 不新增暴露面。"""
    global _engine_pub_cache
    if _engine_pub_cache:
        return {"engine_pub_hex": _engine_pub_cache, "device_serial": _SERIAL}
    # S1 编排期瞬态 503 根修（2026-10-07）：缓存仅成功后落位 ⟹ backend 刚起
    # 未完全就绪（监听未 accept/回环瞬断）时**首次**代理即 503 且无重试——
    # S1 stage0 钥域断言单发必崩（f_s1.log stage0:333）。/authz/engine/pub 为
    # 幂等 GET：有界重试 3 次×2s 退避（非幂等 POST 不在此列），任一次成功即
    # 缓存收口；3 次仍失败才 503——fail-closed 语义不变，仅消除瞬态误报。
    last_err: Exception | None = None
    for attempt in range(3):
        try:
            r = _get_backend("/authz/engine/pub")
            d = r.get("data") or r
            _engine_pub_cache = d["engine_pub_hex"]
            return {"engine_pub_hex": _engine_pub_cache, "device_serial": _SERIAL}
        except Exception as e:  # noqa: BLE001
            last_err = e
            if attempt < 2:
                time.sleep(2)
    from fastapi import HTTPException

    raise HTTPException(status_code=503, detail=f"引擎公钥暂不可达: {last_err}") from last_err


@app.get("/audit")
def audit():
    return {"arms": _audit._c.execute(
        "SELECT token_hash_hex, auth_id, first_arm_at FROM token_arms").fetchall(),
        "denials": _audit.denials()}


@app.on_event("startup")
def _prove_startup_recovery():
    """出证任务启动恢复（2026-10-04 任务二）：桥重启后库里进行中任务如实标
    failed（bridge_restarted——可重试，不虚报 done）+遗留 zkc 孤儿进程击杀；
    看门狗守护线程挂载（lease_until 超时强杀 stalled 任务）。失败不阻断启动
    （恢复面非关键路径——日志留痕）。"""
    from prover import _recover_tasks_on_startup, _start_prove_watchdog

    try:
        n = _recover_tasks_on_startup()
        if n:
            print(f"[bridge] 启动恢复：{n} 个进行中出证任务如实标 failed"
                  f"（bridge_restarted——可重新发起）", flush=True)
    except Exception as e:  # noqa: BLE001
        print(f"[bridge] 出证任务启动恢复失败（忽略）: {e}", flush=True)
    _start_prove_watchdog()
    # 无会话 ARM 监视器（批1-1.6）：FC armed 而闸门无活跃授权会话 →
    # DISARM 尝试+取证。守护线程——挂载失败不阻断启动。
    try:
        _start_rogue_arm_monitor()
    except Exception as e:  # noqa: BLE001
        print(f"[bridge] 无会话 ARM 监视器挂载失败（忽略）: {e}", flush=True)
