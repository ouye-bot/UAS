"""审计台路由（B7；2026-09-29 账户批切换认证）——审计员工作面 API。

认证：会话 Cookie+角色守卫（require_role("auditor")）——X-Audit-Token 头
已随账户批退役（令牌外露粘贴模式根除）。401=未登录/会话失效，403=角色不符。
令状 append-only：本面无删除/改写端点。
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.accounts.deps import require_role
from app.audit.service import AuditDeps, AuditError, AuditService, ChainAuditAnchor
from app.chain.client import ChainError
from app.db import get_session
from app.ra.service import RaError

router = APIRouter(prefix="/audit", tags=["audit"])

_ERR_STATUS = {
    "warrant_not_found": 404,
    "warrant_not_on_chain": 409,
    "already_unlocked": 409,
    "chain_unreachable": 503,
}


def _ok(data: Any) -> JSONResponse:
    return JSONResponse(status_code=200, content={"code": "ok", "message": "", "data": data})


_deps_cache: dict[str, Any] = {}


def _reset_deps_cache() -> None:
    _deps_cache.pop("deps", None)


def _anchor() -> ChainAuditAnchor:
    if os.environ.get("FZ_CHAIN_ANCHOR", "fake") == "fake":
        st = _fake_chain_state()

        def fake_call(fn: str, args: list) -> None:
            if fn == "log_warrant":
                wh, scope = args
                if wh in st["warrants"]:
                    raise RuntimeError("warrant exists")
                st["warrants"][wh] = scope
            elif fn == "log_warrant_unlock":
                wh, cred = args
                if wh not in st["warrants"]:
                    raise RuntimeError("warrant not on file")
                if wh in st["unlocks"]:
                    raise RuntimeError("unlock already logged")
                st["unlocks"][wh] = cred
            else:
                raise RuntimeError(f"fake 链不支持 {fn}")
            st["calls"].append((fn, args))

        return ChainAuditAnchor(
            call=fake_call,
            warrant_on_chain=lambda wh: wh in st["warrants"],
            warrant_unlocked_on_chain=lambda wh: wh in st["unlocks"],
            chain_fingerprint=lambda: "fake",
        )
    return _real_chain_anchor()


def _fake_chain_state() -> dict:
    key = "fake_chain_state"
    _deps_cache.setdefault(key, {"warrants": {}, "unlocks": {}, "calls": []})
    return _deps_cache[key]


def _real_chain_anchor() -> ChainAuditAnchor:
    import json
    from pathlib import Path

    from app.chain.client import ChainClient
    from app.chain.contracts import load_binding
    from app.chain.signer import TxSigner
    from app.kms import chain_auditor_tx_key

    auditor = TxSigner(chain_auditor_tx_key())
    client = ChainClient(
        rpc_url=os.environ.get("FZ_CHAIN_RPC", "http://127.0.0.1:8545"),
        from_addr=auditor.address,
    )
    addr_path = Path(__file__).resolve().parents[3] / "contracts" / ".chain_addresses.json"
    addresses = json.loads(addr_path.read_text())
    ir = load_binding("IdentityRegistry", client, addresses["IdentityRegistry"]["address"])

    def call(fn: str, args: list) -> None:
        m = {"log_warrant": "logWarrant", "log_warrant_unlock": "logWarrantUnlock"}
        b32 = lambda v: bytes.fromhex(str(v).removeprefix("0x")) if isinstance(v, str) else v  # noqa: E731
        ir.send_fn(auditor, m[fn], [b32(a) for a in args])

    def trace_auth(auth_id: int) -> dict:
        fa = load_binding("FlightAuthRegistry", client, addresses["FlightAuthRegistry"]["address"])
        ta = load_binding("TelemetryAnchor", client, addresses["TelemetryAnchor"]["address"])
        out: dict[str, Any] = {"auth_id": auth_id}
        try:
            rec = fa.call_fn("getAuth", [auth_id])
            # 11 元组：tokenHash/nonce/classId/altMaxM/tStart/tEnd/subCredHash/
            # proofDigest/status/revokeReason/ts
            out["auth_record"] = {
                "token_hash": rec[0].hex() if hasattr(rec[0], "hex") else str(rec[0]),
                "nonce": rec[1].hex() if hasattr(rec[1], "hex") else str(rec[1]),
                "class_id": rec[2],
                "alt_max_m": rec[3],
                "t_start": rec[4],
                "t_end": rec[5],
                "sub_cred_hash": rec[6].hex() if hasattr(rec[6], "hex") else str(rec[6]),
                "proof_digest": rec[7].hex() if hasattr(rec[7], "hex") else str(rec[7]),
                "status": rec[8],
                "revoke_reason": rec[9],
                "ts": rec[10],
            }
        except Exception as e:  # noqa: BLE001  留痕缺失=显式空（记录缺失≠无罪）
            out["auth_record"] = None
            out["auth_record_error"] = str(e)[:120]
        # 检查点留痕回读（latest/anchoredHeads 合约状态面；事件为日志面——
        # EventRecorded 事件按需 getPastLogs，演示窗接线）
        try:
            head, seq, ts = ta.call_fn("latest", [auth_id])
            out["checkpoints"] = (
                [
                    {
                        "seq": seq,
                        "chain_head": head.hex() if hasattr(head, "hex") else str(head),
                        "ts": ts,
                    }
                ]
                if seq
                else []
            )
        except Exception:  # noqa: BLE001  无锚定=显式空（记录缺失≠无罪）
            out["checkpoints"] = []
        # 事件时间线（P1-C3：chain_events 投影——索引器增量回填；空=尚无事件）
        try:
            from sqlalchemy import select as _select

            from app.db import SessionLocal as _SL
            from app.telemetry.models import ChainEvent as _CE

            _s = _SL()
            try:
                rows = _s.scalars(
                    _select(_CE).where(_CE.auth_id == auth_id).order_by(_CE.block)
                ).all()
            finally:
                _s.close()
            out["events"] = [
                {
                    "event_type": r.event_type,
                    "event_hash_hex": r.event_hash_hex,
                    "block": r.block,
                    "tx_hash": r.tx_hash,
                    "logged_at": r.logged_at.isoformat() if r.logged_at else None,
                }
                for r in rows
            ]
        except Exception as e:  # noqa: BLE001  索引缺失=显式空
            out["events"] = []
            out["events_error"] = str(e)[:120]
        return out

    def fingerprint() -> str:
        return f"block={client.block_number()}"

    return ChainAuditAnchor(
        call=call,
        warrant_on_chain=lambda wh: bool(ir.call_fn("warrants", [wh])[0]),
        warrant_unlocked_on_chain=lambda wh: bool(ir.call_fn("warrantUnlocks", [wh])[0]),
        trace_auth=trace_auth,
        chain_fingerprint=fingerprint,
    )


def _ra_unlock(warrant_hash_hex: str, master_cred_hash_hex: str) -> dict:
    from app.ra.router import _svc as ra_svc

    return ra_svc(_session_for_unlock()).warrant_unlock(
        warrant_hash_hex=warrant_hash_hex, master_cred_hash_hex=master_cred_hash_hex
    )


def _session_for_unlock() -> Session:
    # 延迟导入避免环——同一请求作用域内新建会话（RA 服务独立事务）
    from app.db import SessionLocal

    return SessionLocal()


def _deps() -> AuditDeps:
    if "deps" not in _deps_cache:
        _deps_cache["deps"] = AuditDeps(
            anchor=_anchor(),
            ra_unlock=_ra_unlock,
        )
    return _deps_cache["deps"]


def _svc(session: Session) -> AuditService:
    return AuditService(session, _deps())


class WarrantIn(BaseModel):
    case_no: str = Field(min_length=1, max_length=128)
    legal_basis_hash_hex: str = Field(default="", max_length=64)
    # 依据摘要文本——服务端自动 SM3（用户不算哈希）
    legal_basis_text: str | None = Field(default=None)
    target_auth_id: int | None = None
    note: str = ""


class UnlockIn(BaseModel):
    master_cred_hash_hex: str | None = Field(default=None, min_length=64, max_length=64)
    # 随案协作函（RA 出具——工程值装进信封）
    collab_code: str | None = Field(default=None, min_length=8)


@router.get("/warrants")
def list_warrants(_p=Depends(require_role("auditor")), session: Session = Depends(get_session)):
    return _ok(_svc(session).list_warrants())


@router.get("/violations")
def violations(
    unfiled: bool = False,
    limit: int = 20,
    _p=Depends(require_role("auditor")),
    session: Session = Depends(get_session),
):
    """违规事件待办（F 席改造：发现违规→立案 的联动入口）。

    chain_events(event_type=1 围栏违规) 按 authId 聚合，左联令状归并出
    「未立案/已立案」态；零身份字段（与 /chain/panel 同纪律）。
    P1 批（评审）：unfiled=只看未立案过滤；limit=返回条数上限（默认 20，
    硬顶 100——长事件史下面板不再无限拉长，总量随 total 一并回传）。
    """
    from sqlalchemy import select

    from app.audit.models import Warrant
    from app.authz.models import AuthRecord
    from app.telemetry.models import ChainEvent

    rows = (
        session.execute(
            select(ChainEvent)
            .where(ChainEvent.event_type == 1)
            .order_by(ChainEvent.logged_at.desc())
            .limit(100)
        )
        .scalars()
        .all()
    )
    # 可立案口径与 create_warrant 同源（2026-09-30 评审 P0 根修：聚合面
    # （chain_events）与校验面（auth_records）分裂曾致收件箱 20/20 立案被拒
    # ——“死收件箱”。fileable=授权记录在案；不在案=历史线索，立案必拒。）
    fileable_ids = set(
        session.execute(select(AuthRecord.auth_id)).scalars().all()
    )
    agg: dict[int, dict] = {}
    for ev in rows:
        item = agg.setdefault(
            ev.auth_id,
            {
                "auth_id": ev.auth_id,
                "events": 0,
                "last_block": ev.block,
                "last_tx_hash": ev.tx_hash,
                "last_at": None,
                "warrants": [],
            },
        )
        item["events"] += 1
        item["last_block"] = max(item["last_block"], ev.block)
        item["last_at"] = ev.logged_at.isoformat() if ev.logged_at else None
    for w in session.execute(select(Warrant).where(Warrant.target_auth_id.is_not(None))).scalars():
        if w.target_auth_id in agg:
            agg[w.target_auth_id]["warrants"].append(
                {
                    "case_no": w.case_no,
                    "warrant_hash_hex": w.warrant_hash_hex,
                    "unlocked": w.unlocked_ts is not None,
                }
            )
    out = []
    for item in agg.values():
        out.append(
            {
                **{
                    k: item[k]
                    for k in ("auth_id", "events", "last_block", "last_tx_hash", "last_at")
                },
                "cases": item["warrants"],
                "case_count": len(item["warrants"]),
                "fileable": item["auth_id"] in fileable_ids,
            }
        )
    out.sort(key=lambda x: (x["fileable"], x["last_at"] or "", x["auth_id"]), reverse=True)
    if unfiled:
        out = [x for x in out if x["case_count"] == 0]
    limit = max(1, min(limit, 100))
    return _ok({"items": out[:limit], "total": len(out), "limit": limit, "unfiled": unfiled})


@router.post("/warrants")
def create_warrant(
    body: WarrantIn, _p=Depends(require_role("auditor")), session: Session = Depends(get_session)
):
    payload = body.model_dump()
    text = payload.pop("legal_basis_text", None)
    if not payload.get("legal_basis_hash_hex"):
        if not text:
            return JSONResponse(
                status_code=400,
                content={
                    "code": "missing_legal_basis",
                    "message": "需提供立案依据摘要",
                    "data": None,
                },
            )
        from app.crypto.sm3 import sm3_bytes as _sm3

        payload["legal_basis_hash_hex"] = _sm3(text.encode()).hex()
    # 原文随哈希双锚落库（0010 迁移列的本意——此前 pop 后未回传，API 路径
    # 断裂致原文永不落库；2026-09-29 双控批实测抓到：批准人须看到依据原文）
    payload["legal_basis_text"] = text
    try:
        return _ok(_svc(session).create_warrant(**payload))
    except AuditError as exc:
        return JSONResponse(
            status_code=_ERR_STATUS.get(exc.code, 400),
            content={"code": exc.code, "message": str(exc), "data": None},
        )
    except ChainError as exc:
        return JSONResponse(
            status_code=503,
            content={"code": "chain_unreachable",
                     "message": f"链不可达——令状未登记（无半截状态，请稍后重试）：{exc}",
                     "data": None},
        )
    except RaError as exc:
        return JSONResponse(
            status_code=getattr(exc, "status", 409) or 409,
            content={"code": exc.code, "message": str(exc), "data": None},
        )


@router.post("/warrants/{wh}/unlock")
def unlock(
    wh: str,
    body: UnlockIn,
    _p=Depends(require_role("auditor")),
    session: Session = Depends(get_session),
):
    # R3-B3（评审 P2-6）：双控第二因素**强制**。协作函=RA 出具的 SM4-GCM 封签。
    # FZC2（2026-09-28 F 席根修）：函-令状-凭证三方 AAD 绑定——函只能用于其
    # 出具时针对的那张令状；FZC1 旧函仅解析兼容（不再新发）。
    # 范围校验（F 席）：凭证与令状目标授权编号不一致=403 scope_mismatch——
    # 双控从"流程性"升级为"范围受限"；数据链不可验证（历史/演示数据）时不误判。
    from sqlalchemy import select as _select

    from app.audit.models import Warrant
    from app.ra.collab import CollabError, open_collab, open_collab_v2
    from app.ra.scope import scope_mismatch

    if not body.collab_code:
        return JSONResponse(
            status_code=400,
            content={
                "code": "missing_collab_code",
                "message": "双控第二因素必填——请向 RA 索取随案协作函（FZC2.…）",
                "data": None,
            },
        )
    w_row = session.execute(
        _select(Warrant).where(Warrant.warrant_hash_hex == wh)
    ).scalar_one_or_none()
    if w_row is None:
        return JSONResponse(
            status_code=404,
            content={
                "code": "warrant_not_found",
                "message": "令状未登记（本地索引无此哈希）",
                "data": None,
            },
        )
    try:
        if body.collab_code.strip().startswith("FZC2."):
            cred_hex = open_collab_v2(body.collab_code, w_row.warrant_hash_hex)
        else:
            cred_hex = open_collab(body.collab_code)  # FZC1 旧函兼容解析
    except CollabError as e:
        return JSONResponse(
            status_code=400,
            content={"code": "bad_collab_code", "message": str(e), "data": None},
        )
    mismatch = scope_mismatch(session, w_row.target_auth_id, cred_hex)
    if mismatch is True:
        return JSONResponse(
            status_code=403,
            content={
                "code": "scope_mismatch",
                "message": "协作函凭证与令状目标授权编号不一致——拒绝解锁（范围受限双控）",
                "data": None,
            },
        )
    try:
        return _ok(_svc(session).unlock(warrant_hash_hex=wh, master_cred_hash_hex=cred_hex))
    except AuditError as exc:
        return JSONResponse(
            status_code=_ERR_STATUS.get(exc.code, 400),
            content={"code": exc.code, "message": str(exc), "data": None},
        )
    except RaError as exc:
        # RA 层拒绝（通道② 解密失败等）——结构化诚实面（2026-09-29 实测：
        # 历史纪元凭证的信封以已轮换密钥封装，解封不可能=该立案的实名解锁
        # 密码学上不可达，须如实告知而非 500）
        return JSONResponse(
            status_code=getattr(exc, "status", 409) or 409,
            content={"code": exc.code, "message": str(exc), "data": None},
        )


# ---- 双控协作请求（2026-09-29 账户批 B3）：审计发函→机构批准→自动执行 ----

class CollabReqIn(BaseModel):
    warrant_hash_hex: str = Field(min_length=64, max_length=64)
    note: str = Field(min_length=1, max_length=2000)
    # 审计员钥签 SM3("FZ-COLLAB-REQ|v1|"+wh+"|"+note)——服务端验签后入队
    sig_hex: str = Field(min_length=16, max_length=512)


@router.post("/collab-requests")
def create_collab_request(
    body: CollabReqIn,
    request: Request,
    session: Session = Depends(get_session),
    _p=Depends(require_role("auditor")),
):
    from app.accounts import collab as collab_svc
    from app.accounts.deps import principal_from
    from app.accounts.service import get_account

    from app.accounts.deps import principal_from as _pf

    p = _pf(request, session)
    acc = get_account(session, p.username)
    try:
        row = collab_svc.create_request(
            session, auditor=acc, warrant_hash_hex=body.warrant_hash_hex,
            note=body.note, sig_hex=body.sig_hex,
        )
    except collab_svc.CollabError as exc:
        return JSONResponse(
            status_code=getattr(exc, "status", 400) or 400,
            content={"code": exc.code, "message": str(exc), "data": None},
        )
    return _ok(collab_svc.request_view(session, row))


@router.get("/collab-requests")
def list_collab_requests(
    status: str = "",
    session: Session = Depends(get_session),
    _p=Depends(require_role("auditor")),
):
    from app.accounts import collab as collab_svc

    return _ok({"items": collab_svc.list_requests(session, status or None)})


@router.get("/collab-requests/{req_id}/verify-sigs")
def verify_collab_sigs(
    req_id: int,
    session: Session = Depends(get_session),
    _p=Depends(require_role("auditor")),
):
    """历史签名复验（公钥纪元史消费面）：按签名时点公钥复核双控两签——
    换钥（密码重置）后旧签名仍验得过=双控不可抵赖（审计员自查面）。"""
    from app.accounts import collab as collab_svc

    try:
        out = collab_svc.verify_request_sigs(session, req_id)
    except collab_svc.CollabError as exc:
        return JSONResponse(
            status_code=getattr(exc, "status", 400) or 400,
            content={"code": exc.code, "message": str(exc), "data": None},
        )
    return _ok(out)


@router.post("/collab-requests/{req_id}/close")
def close_collab_request(
    req_id: int,
    request: Request,
    session: Session = Depends(get_session),
    _p=Depends(require_role("auditor")),
):
    """审计员结案（executed→closed）：解锁实名已核实，案件闭环
    （队长拍板：请求生命周期 待批准→已批准·待执行→已执行·待结案→已结案）。"""
    from app.accounts import collab as collab_svc
    from app.accounts.deps import principal_from as _pf
    from app.accounts.service import get_account

    p = _pf(request, session)
    acc = get_account(session, p.username)
    try:
        out = collab_svc.close_request(session, auditor=acc, request_id=req_id)
    except collab_svc.CollabError as exc:
        return JSONResponse(
            status_code=getattr(exc, "status", 400) or 400,
            content={"code": exc.code, "message": str(exc), "data": None},
        )
    return _ok(out)


@router.get("/warrants/{wh}/trace")
def trace(wh: str, _p=Depends(require_role("auditor")), session: Session = Depends(get_session)):
    try:
        return _ok(_svc(session).trace(warrant_hash_hex=wh))
    except AuditError as exc:
        return JSONResponse(
            status_code=_ERR_STATUS.get(exc.code, 404),
            content={"code": exc.code, "message": str(exc), "data": None},
        )
