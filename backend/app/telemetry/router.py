"""engine 遥测锚定 API（阶段一 D-Ⅰ-7）：检查点/事件上链转发面。

端点：POST /engine/anchor（设备签名检查点→anchorCheckpoint 上链）、
POST /engine/event（违规事件→recordEvent 上链）、GET /engine/anchors
（fake 锚记录查询——测试/演示断言面）。

认证（红队评审 #6c）：锚定/事件端点须 X-Engine-Token 恒时比较——
无认证时 LAN 内攻击者可伪造锚定行（device_pub 自证）→ 审计节点被喂假数据。
"""

from __future__ import annotations

import hmac as _hmac
import os as _os
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db import get_session
from app.telemetry.service import (
    TelemetryError,
    anchor_checkpoint,
    get_deps,
    record_event,
    reset_deps,
)

router = APIRouter(prefix="/engine", tags=["engine-telemetry"])


def _require_engine_token(request: Request) -> None:
    """引擎转发面认证（恒时比较 X-Engine-Token）。"""
    supplied = request.headers.get("X-Engine-Token", "")
    want = _os.environ.get("FZ_ENGINE_TOKEN", "")
    if not supplied or not want or not _hmac.compare_digest(supplied, want):
        # R3-0.5 诊断（永久保留）：401 时打印长度指纹——区分「缺失」与「错值」
        print(
            f"[engine-auth] 401: supplied_len={len(supplied)} want_len={len(want)} "
            f"want_fp={(want[:6] + '…') if want else '∅'}",
            flush=True,
        )
        raise HTTPException(
            status_code=401, detail={"code": "engine_unauthorized", "message": "引擎令牌缺失/错误"}
        )


# fake 锚记录归 deps（进程内）——_reset_fake_state 供测试隔离
_fake_state_ref = None


def _reset_fake_state() -> None:
    """测试钩子：清 fake 锚记录+重建 deps。"""
    global _fake_state_ref
    reset_deps()
    _fake_state_ref = get_deps()


def _ok(data: Any) -> JSONResponse:
    return JSONResponse({"ok": True, "data": data})


def _deny(exc: TelemetryError) -> JSONResponse:
    return JSONResponse(
        {"ok": False, "code": exc.code, "message": exc.message}, status_code=exc.status
    )


class AnchorIn(BaseModel):
    auth_id: int = Field(..., ge=1, description="授权贯穿键")
    seq: int = Field(..., ge=1, description="检查点序号（单调从 1 起——合约强制）")
    chain_head_hex: str = Field(..., min_length=64, max_length=64)
    fence_state_hex: str = Field(..., min_length=8, max_length=8, description="4B 围栏态")
    sig_hex: str = Field(..., min_length=128, max_length=128, description="设备签名")
    device_pub_hex: str = Field(..., min_length=128, max_length=128)


class EventIn(BaseModel):
    auth_id: int = Field(..., ge=1)
    # 越界值（0/9/255）交业务层出 bad_event_type 语义码（pydantic 422 只拦形态）
    event_type: int = Field(..., ge=0, le=255)
    event_hash_hex: str = Field(..., min_length=64, max_length=64)


@router.post("/anchor")
def anchor(body: AnchorIn, request: Request, session: Session = Depends(get_session)):
    _require_engine_token(request)
    try:
        return _ok(
            anchor_checkpoint(
                get_deps(),
                session,
                auth_id=body.auth_id,
                seq=body.seq,
                chain_head_hex=body.chain_head_hex,
                fence_state_hex=body.fence_state_hex,
                sig_hex=body.sig_hex,
                device_pub_hex=body.device_pub_hex,
            )
        )
    except TelemetryError as e:
        return _deny(e)


@router.post("/event")
def event(body: EventIn, request: Request, session: Session = Depends(get_session)):
    _require_engine_token(request)
    try:
        return _ok(
            record_event(
                get_deps(),
                session,
                auth_id=body.auth_id,
                event_type=body.event_type,
                event_hash_hex=body.event_hash_hex,
            )
        )
    except TelemetryError as e:
        return _deny(e)


@router.get("/anchors")
def anchors():
    """fake 锚记录（真链模式返回空——留痕查询走链上 panel/trace）。"""
    d = get_deps()
    return _ok({"records": d.records, "events": d.events})


@router.post("/auths/{auth_id}/revoke")
def engine_auth_revoke(auth_id: int, request: Request):
    """紧急禁飞（R3-1.5，评审 P1-3）：链上 revokeAuth——授权撤销此前仅有
    烟测调用、无业务入口 ⟹ 监管"叫停某次飞行"不成立。撤销后遥测面
    auth_revoked 分支（原死代码）即刻生效：后续检查点/事件全部拒绝。"""
    import os as _os

    _require_engine_token(request)
    # 复用 backend 自身链写面（engine 交易钥）——与 worker recordAuth 同一
    # 交易钥域（FZ-CHAIN-SMOKE|engine），权限模型一致。
    from app.chain.client import ChainClient, ChainError
    from app.chain.contracts import load_binding
    from app.chain.signer import TxSigner
    from app.kms import chain_engine_tx_key
    from app.telemetry.service import _chain_addresses

    signer = TxSigner(chain_engine_tx_key())
    client = ChainClient(
        rpc_url=_os.environ.get("FZ_CHAIN_RPC", "http://127.0.0.1:8545"),
        from_addr=signer.address,
    )
    addr = _chain_addresses()
    fa = load_binding("FlightAuthRegistry", client, addr["FlightAuthRegistry"]["address"])
    try:
        receipt = fa.send_fn(signer, "revokeAuth", [auth_id])
    except ChainError as e:
        return {"ok": False, "code": "revoke_failed", "message": str(e)[:200]}
    status = None
    try:
        rec = fa.call_fn("getAuth", [auth_id])
        status = int(rec[8])
    except Exception:  # noqa: BLE001
        pass
    return {
        "ok": status == 1,
        "auth_id": auth_id,
        "status": status,
        "tx": str(receipt.get("transactionHash", "")) if isinstance(receipt, dict) else None,
    }


@router.get("/trail/binding")
def trail_binding(
    request: Request,
    auth_id: int,
    chain_head_hex: str,
    session: Session = Depends(get_session),
):
    """TRAIL 出证绑定（R4 复验 P0-1 + 二批 BIND2 扩域）：引擎钥对
    (auth_id‖alt_max_cm‖chain_head‖围栏 4 界) 出具 SM2 裸摘要签名
    （fold_be_integer 口径，与检查点验签同族）——轨迹证书的高度上限与
    矩形围栏（TRAIL 电路 4 半平面合规门）由授权链路（政策×机型）权威
    供给，证明者不可自报。

    alt_max 口径：政策当前值（get_rule(申请机型)）×100 cm——与 worker recordAuth
    同一推导链；围栏口径：get_fence(申请机型) i32×1e7（负值=南/西半球）。
    报文版本 FZ-TRAIL-BIND2=域分隔（旧格式签名在新验证面结构性失效）。
    X-Engine-Token 门禁。"""
    _require_engine_token(request)
    if len(chain_head_hex) != 64 or any(c not in "0123456789abcdefABCDEF" for c in chain_head_hex):
        raise HTTPException(status_code=400, detail="chain_head_hex 须 64 hex")
    from app.authz.models import Application, AuthRecord
    from app.authz.policy import PolicyError, get_fence, get_rule
    from app.crypto.sm2 import sign_digest
    from app.crypto.sm3 import sm3_bytes
    from app.kms import engine_signing_keypair

    rec = session.query(AuthRecord).filter(AuthRecord.auth_id == auth_id).first()
    if rec is None:
        raise HTTPException(status_code=404, detail="auth_id 不在案（无授权记录）")
    app_row = session.get(Application, rec.application_id)
    if app_row is None:
        raise HTTPException(status_code=404, detail="授权对应申请不在案")
    try:
        alt_max_m, _required = get_rule(app_row.class_id)
        min_lat, max_lat, min_lon, max_lon = get_fence(app_row.class_id)
    except PolicyError as e:
        raise HTTPException(status_code=403, detail=str(e)) from e
    alt_max_cm = alt_max_m * 100  # 单位契约：政策/令牌=meters，TRAIL 电路=cm
    # 锚定对拍（2026-09-28 安全深检 A-P1 演进兑现）：授权必须存在至少一次
    # 链上锚定检查点方可获轨迹绑定——从未留痕的授权拒绝出证绑定；随附最近
    # 锚定的**引擎签名证据**（binding.json 随证书发放，第三方凭公示公钥
    # 离线验签+与链上锚定时间线交叉核对）。语义边界=一致性核对（证书与
    # 锚定时间线机器可对），非"数据真实性证明"（真实性归录制器 TCB）。
    from app.telemetry.models import CheckpointAnchor

    cp = (
        session.query(CheckpointAnchor)
        .filter(CheckpointAnchor.auth_id == auth_id)
        .order_by(CheckpointAnchor.seq.desc())
        .first()
    )
    if cp is None:
        raise HTTPException(
            status_code=409,
            detail="no_anchored_checkpoint：该授权无任何链上锚定检查点——"
            "拒绝出具轨迹绑定（先完成飞行留痕锚定）",
        )
    head = chain_head_hex.lower()
    msg = (
        f"FZ-TRAIL-BIND2|{auth_id}|{alt_max_cm}|{head}|"
        f"{min_lat}|{max_lat}|{min_lon}|{max_lon}"
    )
    sk, engine_pub = engine_signing_keypair()
    sig = sign_digest(sk, sm3_bytes(msg.encode()))
    anchor_evidence = {
        "seq": cp.seq,
        "chain_head_hex": cp.chain_head_hex,
        "fence_state_hex": cp.fence_state_hex,
        "anchored_at": cp.logged_at.isoformat() if cp.logged_at else None,
    }
    evid_msg = f"FZ-ANCHOR-EVID|{auth_id}|{cp.seq}|{cp.chain_head_hex.lower()}"
    anchor_evidence_sig = sign_digest(sk, sm3_bytes(evid_msg.encode()))
    return _ok(
        {
            "auth_id": auth_id,
            "alt_max_cm": alt_max_cm,
            "chain_head_hex": head,
            # 二批 BIND2：围栏 4 界（政策权威值——随绑定签名一并供给）
            "min_lat": min_lat,
            "max_lat": max_lat,
            "min_lon": min_lon,
            "max_lon": max_lon,
            "engine_pub_hex": engine_pub,
            "sig_hex": sig,
            "anchor_evidence": anchor_evidence,
            "anchor_evidence_sig_hex": anchor_evidence_sig,
        }
    )
