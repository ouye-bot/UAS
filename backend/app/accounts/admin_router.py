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

# 运营方域（辖区分账 P0，复审洞 2 推荐案）：全局治理域动作（份额刷新）的
# operator 域限定=部署约定（org-a 为缺省部署域），非角色特权——监管全景归
# 审计台（/audit/* 豁免读过滤），机构台读面按域一律到底（org-a 不豁免）。
OPERATOR_DOMAIN = "org-a"


def _deny(exc: Exception) -> JSONResponse:
    status = getattr(exc, "status", 400) or 400
    return JSONResponse(
        status_code=status,
        content={
            "code": getattr(exc, "code", "error"),
            "message": str(exc),
            "data": None,
        },
    )


class ApproveIn(BaseModel):
    sig_hex: str = Field(min_length=16, max_length=512)


class RejectIn(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)
    sig_hex: str = Field(min_length=16, max_length=512)


class ResolveDisposalIn(BaseModel):
    """处置完成 body（A5/B2）：说明选填——管理员处置留痕（reason_prefill
    不入库，前端用案号+结论现拼）。"""

    note: str = Field(default="", max_length=2000)


@router.get("/collab-requests")
def list_collab_requests(
    request: Request,
    status: str = "",
    session: Session = Depends(get_session),
    _p=Depends(require_role("admin")),
):
    """协作请求列表（读面按域——辖区分账 2026-10-12：目标归属域过滤，org-a
    一律到底；未定域=全域待批保留）。"""
    p = principal_from(request, session)
    return JSONResponse(
        status_code=200,
        content={
            "code": "ok",
            "message": "",
            "data": {
                "items": collab_svc.list_requests(session, status or None, p.org_id),
            },
        },
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
        out = collab_svc.approve_and_execute(
            session, admin=acc, request_id=req_id, sig_hex=body.sig_hex
        )
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
    return JSONResponse(
        status_code=200, content={"code": "ok", "message": "已重新执行（后台）", "data": out}
    )


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
    return JSONResponse(
        status_code=200, content={"code": "ok", "message": "已驳回（理由随请求留痕）", "data": out}
    )


# 🔴 在线重置端点已下线（2026-09-30 密码重置收紧批，队长已批方案）：
# 原 /admin/accounts/{username}/reset-password 允许 admin 重置任意机构账户
# （含 auditor 与 admin 自己）——单管理员接管审计面=破坏双控独立性；
# 自重置/互重置一并禁止。唯一合法路径=离线种子脚本
# `seed_accounts.py --reset`（线下执行；重置动作逐笔入 account_admin_log
# 台账；公钥纪元史 append-only 保证换钥后历史签名可复验）。
# 负例回归（POST 该路径=404）见 test_accounts.py::test_online_reset_endpoint_retired。


# ---- 处置待办（2026-10-04 处置联动 A5/B2）：审计结案 verified 自动建单，机构处置 ----


@router.get("/disposal-todos")
def list_disposal_todos(
    request: Request,
    session: Session = Depends(get_session),
    _p=Depends(require_role("admin")),
):
    """处置待办清单（admin）：全部待办按 created_ts 倒序——审计定谳（verified）
    的下一棒是机构处置，逐单可见状态与处置说明。读面按域（辖区分账
    2026-10-12）：按目标实名归属域过滤，org-a 一律到底；未定域保留。"""
    from app.audit import disposal as disposal_svc

    p = principal_from(request, session)
    return JSONResponse(
        status_code=200,
        content={
            "code": "ok",
            "message": "",
            "data": {"items": disposal_svc.list_todos(session, p.org_id)},
        },
    )


@router.post("/disposal-todos/{todo_id}/resolve")
def resolve_disposal_todo(
    todo_id: int,
    body: ResolveDisposalIn,
    request: Request,
    session: Session = Depends(get_session),
    _p=Depends(require_role("admin")),
):
    """处置完成（pending→done）：说明入库留痕；已 done 再 resolve=409
    （条件 UPDATE 数据库仲裁——重复处置恰一胜者）。
    辖区分账 P0（2026-10-12）：跨域守卫——待办目标实名归属域==操作者域
    （实名缺位/用户不可得=未定域，域门跳过——0.1 工艺同款）。"""
    from app.audit import disposal as disposal_svc
    from app.ra.scope import OrgForbidden, org_guard, username_org_of

    p = principal_from(request, session)
    try:
        row = session.get(disposal_svc.DisposalRequest, todo_id)
        if row is None:
            raise disposal_svc.DisposalError("todo_not_found", "处置待办不存在", 404)
        try:
            org_guard(username_org_of(session, row.username), p.org_id, "处置待办")
        except OrgForbidden as exc:
            return _deny(exc)
        out = disposal_svc.resolve_todo(session, todo_id=todo_id, note=body.note)
    except disposal_svc.DisposalError as exc:
        return _deny(exc)
    return JSONResponse(
        status_code=200,
        content={"code": "ok", "message": "已标记处置完成", "data": out},
    )


@router.post("/accounts/{username}/delete")
def delete_orphan_account(
    username: str,
    request: Request,
    session: Session = Depends(get_session),
    _p=Depends(require_role("admin")),
):
    """删除孤儿账户（admin）：仅限「飞手+待补资料」态（半途注册残留——
    无凭证无链上痕迹，删除即释放用户名）。任何已激活/已签发账户不可删。
    辖区分账 P0（2026-10-12）：跨域守卫——目标账户 org_id==操作者域。"""
    from app.accounts.service import get_account
    from app.ra.scope import OrgForbidden, org_guard

    p = principal_from(request, session)
    try:
        row = get_account(session, username)
    except AccountError as exc:
        return _deny(exc)
    try:
        org_guard(row.org_id or None, p.org_id, "账户")
    except OrgForbidden as exc:
        return _deny(exc)
    if row.role != "pilot" or row.status != "pending_profile":
        return JSONResponse(
            status_code=409,
            content={
                "code": "not_orphan",
                "message": "仅「待补资料」的飞手账户可删除（已激活/已签发账户走吊销面）",
                "data": None,
            },
        )
    from app.accounts.models import WebSession

    for ws in session.query(WebSession).filter(WebSession.username == username).all():
        session.delete(ws)
    session.delete(row)
    session.commit()
    return JSONResponse(
        status_code=200,
        content={"code": "ok", "message": f"已删除孤儿账户 {username}", "data": None},
    )


@router.get("/collab-requests/{req_id}/verify-sigs")
def verify_collab_sigs(
    req_id: int,
    request: Request,
    session: Session = Depends(get_session),
    _p=Depends(require_role("admin")),
):
    """历史签名复验（公钥纪元史消费面）：按签名时点公钥复核双控两签——
    换钥后旧签名仍验得过（双控不可抵赖的演示判词）。
    辖区分账 P0（2026-10-12）：跨域守卫（读面按域——按 id 越域可读同属越域
    探测面）：目标请求归属域==操作者域（未定域跳过）。"""
    from app.accounts.models import CollabRequest
    from app.ra.scope import OrgForbidden, org_guard

    p = principal_from(request, session)
    r = session.get(CollabRequest, req_id)
    if r is not None:
        try:
            org_guard(collab_svc.request_target_org(session, r), p.org_id, "案件")
        except OrgForbidden as exc:
            return _deny(exc)
    try:
        out = collab_svc.verify_request_sigs(session, req_id)
    except collab_svc.CollabError as exc:
        return _deny(exc)
    return JSONResponse(status_code=200, content={"code": "ok", "message": "", "data": out})


@router.post("/threshold/reshare")
def threshold_reshare(
    request: Request,
    session: Session = Depends(get_session),
    _p=Depends(require_role("admin")),
):
    """份额刷新 API 面（1.3 件③，J2 止损闭环）：包装⑤站三步提案+份额刷新
    仪式（governor k-of-n 时间锁——治理面写入不绕过治理面）。幂等=链上
    PolicyRegistry version exists 拒重放（同纪元不可重放——合约级幂等）。
    owner-set 指纹门：提案时点链读 fp 携入仪式，执行窗漂移即拒（fail-closed）。
    耗时≈时间锁延迟（demo 档 FZ_GOVERNOR_DELAY_S=10s——管理面低频可接受）。
    辖区分账 P0（2026-10-12，复审洞 2 推荐案）：份额刷新=治理域动作——
    operator org 限**运营方域 org-a**（部署约定，如实标注非角色特权：org-a
    仅为缺省部署域；页面上该动作挂 /governance 治理语境呈现）。"""
    from app.ra.scope import OrgForbidden, org_guard
    from app.ra.threshold_sync import SyncError, propose_and_reshare

    p = principal_from(request, session)
    try:
        org_guard(OPERATOR_DOMAIN, p.org_id, "治理域动作（份额刷新）")
    except OrgForbidden as exc:
        return _deny(exc)

    try:
        out = propose_and_reshare()
    except SyncError as exc:
        return _deny(exc)
    return JSONResponse(
        status_code=200,
        content={
            "code": "ok",
            "message": "份额刷新完成（治理提案已 execute 公示+三域 re-share）",
            "data": out,
        },
    )


@router.get("/overview")
def overview(
    request: Request,
    session: Session = Depends(get_session),
    _p=Depends(require_role("admin")),
):
    """机构台总览：待解锁令状/出具台账/账户概况/账户管理台账——签发台账是机构本职的可视面。
    读面按域（辖区分账 2026-10-12 枚举清单面③，org-a 一律到底——监管全景
    归审计台）：四表逐行派生归属域过滤；未定域行恒保留（「全域」语义）。
    - warrants：target_auth_id→授权链凭证域，缺位回落解锁实名→用户域；
    - collab_ledger：出函凭证句柄→凭证域；
    - accounts/reset_log：账户 org_id 列直读（reset_log 按账户名派生）。"""
    from app.ra.scope import auth_org_of, cred_org_of, username_org_of

    p = principal_from(request, session)
    warrants_raw = session.scalars(select(Warrant).order_by(Warrant.id.desc()).limit(50)).all()
    ledger_raw = session.scalars(
        select(CollabIssued).order_by(CollabIssued.id.desc()).limit(50)
    ).all()
    accounts_raw = session.scalars(select(Account).order_by(Account.id)).all()
    from app.accounts.models import AccountAdminLog

    reset_raw = session.scalars(
        select(AccountAdminLog).order_by(AccountAdminLog.id.desc()).limit(50)
    ).all()

    def _keep(org: str | None) -> bool:
        return org is None or p.org_id == org

    warrant_orgs = {
        w.warrant_hash_hex: (
            auth_org_of(session, w.target_auth_id) or username_org_of(session, w.unlocked_username)
        )
        for w in warrants_raw
    }
    ledger_orgs = {
        c.master_cred_hash_hex: cred_org_of(session, c.master_cred_hash_hex) for c in ledger_raw
    }
    reset_orgs = {g.id: username_org_of(session, g.username) for g in reset_raw}
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
                        "org_id": warrant_orgs.get(w.warrant_hash_hex),
                        "unlocked": w.unlocked_ts is not None,
                        "created_ts": w.created_ts.isoformat() if w.created_ts else None,
                    }
                    for w in warrants_raw
                    if _keep(warrant_orgs.get(w.warrant_hash_hex))
                ],
                "collab_ledger": [
                    {
                        "warrant_hash_hex": c.warrant_hash_hex,
                        "master_cred_hash_hex": c.master_cred_hash_hex,
                        "org_id": ledger_orgs.get(c.master_cred_hash_hex),
                        "code_fingerprint_hex": c.code_fingerprint_hex,
                        "issued_at": c.issued_at.isoformat() if c.issued_at else None,
                    }
                    for c in ledger_raw
                    if _keep(ledger_orgs.get(c.master_cred_hash_hex))
                ],
                "accounts": [
                    {
                        "username": a.username,
                        "role": a.role,
                        "status": a.status,
                        "org_id": a.org_id,
                        "created_ts": a.created_ts.isoformat() if a.created_ts else None,
                    }
                    for a in accounts_raw
                    if _keep(a.org_id)
                ],
                "reset_log": [
                    {
                        "ts": g.ts.isoformat() if g.ts else None,
                        "action": g.action,
                        "username": g.username,
                        "operator": g.operator,
                        "detail": g.detail,
                    }
                    for g in reset_raw
                    if _keep(reset_orgs.get(g.id))
                ],
            },
        },
    )
