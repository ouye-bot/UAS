"""/admin/* 机构台路由（2026-09-29 账户批 B3）：待批协作/批准/驳回/台账/账户总览。

语义：管理员是「批准」这一例外权力的唯一持有者——批准即以管理员钥签名
（服务端验签），随后系统自动完成 RA 出函（FZC2+台账）与审计侧解锁（范围
校验+链上留痕）。签发台账、按人吊销入口同挂本面（机构本职）。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.accounts import collab as collab_svc
from app.accounts.deps import principal_from, require_role
from app.accounts.models import Account
from app.accounts.service import AccountError, get_account
from app.audit.models import CollabIssued, Warrant
from app.db import get_session

router = APIRouter(prefix="/admin", tags=["admin"])


def _deny(exc: Exception) -> JSONResponse:
    status = getattr(exc, "status", 400) or 400
    return JSONResponse(
        status_code=status, content={"code": getattr(exc, "code", "error"), "message": str(exc), "data": None}
    )


class ApproveIn(BaseModel):
    sig_hex: str = Field(min_length=16, max_length=512)


class RejectIn(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)
    sig_hex: str = Field(min_length=16, max_length=512)


@router.get("/collab-requests")
def list_collab_requests(
    status: str = "",
    session: Session = Depends(get_session),
    _p=Depends(require_role("admin")),
):
    return JSONResponse(
        status_code=200,
        content={"code": "ok", "message": "", "data": {"items": collab_svc.list_requests(session, status or None)}},
    )


@router.post("/collab-requests/{req_id}/approve")
def approve(
    req_id: int,
    body: ApproveIn,
    request: Request,
    session: Session = Depends(get_session),
    _p=Depends(require_role("admin")),
):
    """批准（即返回）→自动执行在后台进行（真链推链不卡请求——批二异步化）。
    状态轮询：approved（执行中）→ executed | execute_failed（可重试）。"""
    p = principal_from(request, session)
    try:
        acc = get_account(session, p.username)
        out = collab_svc.approve_and_execute(session, admin=acc, request_id=req_id, sig_hex=body.sig_hex)
    except collab_svc.CollabError as exc:
        return _deny(exc)
    except AccountError as exc:
        return _deny(exc)
    return JSONResponse(
        status_code=200,
        content={
            "code": "ok",
            "message": "已批准——自动执行进行中（完成后状态自动流转）",
            "data": out,
        },
    )


@router.post("/collab-requests/{req_id}/retry")
def retry(
    req_id: int,
    request: Request,
    session: Session = Depends(get_session),
    _p=Depends(require_role("admin")),
):
    """执行失败重试（后台再执行）。"""
    p = principal_from(request, session)
    try:
        acc = get_account(session, p.username)
        out = collab_svc.retry_execute(session, admin=acc, request_id=req_id)
    except collab_svc.CollabError as exc:
        return _deny(exc)
    except AccountError as exc:
        return _deny(exc)
    return JSONResponse(status_code=200, content={"code": "ok", "message": "已重新执行（后台）", "data": out})


@router.post("/collab-requests/{req_id}/reject")
def reject(
    req_id: int,
    body: RejectIn,
    request: Request,
    session: Session = Depends(get_session),
    _p=Depends(require_role("admin")),
):
    p = principal_from(request, session)
    try:
        acc = get_account(session, p.username)
        out = collab_svc.reject_request(
            session, admin=acc, request_id=req_id, reason=body.reason, sig_hex=body.sig_hex
        )
    except collab_svc.CollabError as exc:
        return _deny(exc)
    except AccountError as exc:
        return _deny(exc)
    return JSONResponse(status_code=200, content={"code": "ok", "message": "已驳回（理由随请求留痕）", "data": out})


# 🔴 在线重置端点已下线（2026-09-30 密码重置收紧批，队长已批方案）：
# 原 /admin/accounts/{username}/reset-password 允许 admin 重置任意机构账户
# （含 auditor 与 admin 自己）——单管理员接管审计面=破坏双控独立性；
# 自重置/互重置一并禁止。唯一合法路径=离线种子脚本
# `seed_accounts.py --reset`（线下执行；重置动作逐笔入 account_admin_log
# 台账；公钥纪元史 append-only 保证换钥后历史签名可复验）。
# 负例回归（POST 该路径=404）见 test_accounts.py::test_online_reset_endpoint_retired。


@router.post("/accounts/{username}/delete")
def delete_orphan_account(
    username: str,
    request: Request,
    session: Session = Depends(get_session),
    _p=Depends(require_role("admin")),
):
    """删除孤儿账户（admin）：仅限「飞手+待补资料」态（半途注册残留——
    无凭证无链上痕迹，删除即释放用户名）。任何已激活/已签发账户不可删。"""
    from app.accounts.service import get_account

    try:
        row = get_account(session, username)
    except AccountError as exc:
        return _deny(exc)
    if row.role != "pilot" or row.status != "pending_profile":
        return JSONResponse(
            status_code=409,
            content={"code": "not_orphan", "message": "仅「待补资料」的飞手账户可删除（已激活/已签发账户走吊销面）", "data": None},
        )
    from app.accounts.models import WebSession
    for ws in session.query(WebSession).filter(WebSession.username == username).all():
        session.delete(ws)
    session.delete(row)
    session.commit()
    return JSONResponse(status_code=200, content={"code": "ok", "message": f"已删除孤儿账户 {username}", "data": None})


@router.get("/collab-requests/{req_id}/verify-sigs")
def verify_collab_sigs(
    req_id: int,
    session: Session = Depends(get_session),
    _p=Depends(require_role("admin")),
):
    """历史签名复验（公钥纪元史消费面）：按签名时点公钥复核双控两签——
    换钥后旧签名仍验得过（双控不可抵赖的演示判词）。"""
    try:
        out = collab_svc.verify_request_sigs(session, req_id)
    except collab_svc.CollabError as exc:
        return _deny(exc)
    return JSONResponse(status_code=200, content={"code": "ok", "message": "", "data": out})


@router.get("/overview")
def overview(session: Session = Depends(get_session), _p=Depends(require_role("admin"))):
    """机构台总览：待解锁令状/出具台账/账户概况/账户管理台账——签发台账是机构本职的可视面。"""
    warrants = session.scalars(
        select(Warrant).order_by(Warrant.id.desc()).limit(50)
    ).all()
    ledger = session.scalars(
        select(CollabIssued).order_by(CollabIssued.id.desc()).limit(50)
    ).all()
    accounts = session.scalars(select(Account).order_by(Account.id)).all()
    from app.accounts.models import AccountAdminLog

    reset_log = session.scalars(
        select(AccountAdminLog).order_by(AccountAdminLog.id.desc()).limit(50)
    ).all()
    return JSONResponse(
        status_code=200,
        content={
            "code": "ok",
            "message": "",
            "data": {
                "warrants": [
                    {
                        "warrant_hash_hex": w.warrant_hash_hex,
                        "case_no": w.case_no,
                        "target_auth_id": w.target_auth_id,
                        "unlocked": w.unlocked_ts is not None,
                        "created_ts": w.created_ts.isoformat() if w.created_ts else None,
                    }
                    for w in warrants
                ],
                "collab_ledger": [
                    {
                        "warrant_hash_hex": c.warrant_hash_hex,
                        "master_cred_hash_hex": c.master_cred_hash_hex,
                        "code_fingerprint_hex": c.code_fingerprint_hex,
                        "issued_at": c.issued_at.isoformat() if c.issued_at else None,
                    }
                    for c in ledger
                ],
                "accounts": [
                    {
                        "username": a.username,
                        "role": a.role,
                        "status": a.status,
                        "created_ts": a.created_ts.isoformat() if a.created_ts else None,
                    }
                    for a in accounts
                ],
                "reset_log": [
                    {
                        "ts": g.ts.isoformat() if g.ts else None,
                        "action": g.action,
                        "username": g.username,
                        "operator": g.operator,
                        "detail": g.detail,
                    }
                    for g in reset_log
                ],
            },
        },
    )
