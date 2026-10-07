"""处置待办服务（2026-10-04 处置联动 A5/B2）：审计结案定谳（verified=属实）
→ 机构管理员处置——两台联动的最后一棒（处置动作逐单留痕：谁/何时/说明）。

语义契约（前端并行开发锚）：
- 建单：仅结案结论=verified 时由结案挂钩触发（app.audit.router close 端点
  成功后调用——audit 层挂钩，不动 collab.py）；req_hash 幂等——同请求重复
  触发不重复建单（ UNIQUE(req_hash) + 先查后插双保险）；
- username 取该请求解锁实名（warrants.unlocked_username——unlocked 数据；
  executed 前置=已回填；理论缺位如实存空串，不臆造）；
- 列表：全部待办按 created_ts 倒序（admin 可见全部——处置是机构本职面）；
- resolve：pending→done 条件 UPDATE（数据库仲裁，重复处置=409）；
  reason_prefill 不入库——前端用案号+结论现拼，本表只存管理员处置说明。
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.models import DisposalRequest, Warrant


class DisposalError(Exception):
    def __init__(self, code: str, message: str = "", status: int = 400) -> None:
        super().__init__(message or code)
        self.code = code
        self.status = status


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC).replace(tzinfo=None)


def todo_view(r: DisposalRequest) -> dict:
    """待办视图（契约面，前端并行开发逐字锚）。conclusion 恒为 verified——
    本表只收属实证，误报/无法查证根本不入表。"""
    return {
        "id": r.id,
        "case_no": r.case_no,
        "username": r.username,
        "conclusion": "verified",
        "created_ts": r.created_ts.isoformat() if r.created_ts else None,
        "status": r.status,
        "resolved_note": r.resolved_note,
    }


def create_disposal_request(
    session: Session,
    *,
    req_hash_hex: str,
    case_no: str,
    warrant_hash_hex: str | None = None,
) -> DisposalRequest:
    """verified 结案挂钩：按 req_hash 幂等建单（已存在原样返回，不重复建）。

    username 从令状行取解锁实名（unlocked 数据）——令状不在案/尚未回填时
    如实存空串（演示数据形态），不臆造实名。"""
    rh = (req_hash_hex or "").lower()
    existing = session.execute(
        select(DisposalRequest).where(DisposalRequest.req_hash_hex == rh)
    ).scalar_one_or_none()
    if existing is not None:
        return existing
    username = ""
    if warrant_hash_hex:
        w_row = session.execute(
            select(Warrant).where(Warrant.warrant_hash_hex == warrant_hash_hex.lower())
        ).scalar_one_or_none()
        if w_row is not None and w_row.unlocked_username:
            username = w_row.unlocked_username
    row = DisposalRequest(
        req_hash_hex=rh,
        case_no=case_no,
        username=username,
        created_ts=_utcnow(),
        status="pending",
    )
    session.add(row)
    session.commit()
    return row


def list_todos(session: Session) -> list[dict]:
    """全部处置待办（admin 可见全部），按 created_ts 倒序（id 作稳定次序锚）。"""
    rows = session.scalars(
        select(DisposalRequest).order_by(
            DisposalRequest.created_ts.desc(), DisposalRequest.id.desc()
        )
    ).all()
    return [todo_view(r) for r in rows]


def resolve_todo(session: Session, *, todo_id: int, note: str | None) -> dict:
    """处置完成（pending→done）：条件 UPDATE 数据库仲裁——并发/重复处置恰一
    胜者，输家 409（already_resolved）。说明入库（管理员处置留痕），时间戳落定。"""
    row = session.get(DisposalRequest, todo_id)
    if row is None:
        raise DisposalError("todo_not_found", "处置待办不存在", 404)
    rowcount = session.query(DisposalRequest).filter(
        DisposalRequest.id == todo_id, DisposalRequest.status == "pending"
    ).update(
        {
            "status": "done",
            "resolved_note": (note or "").strip() or None,
            "resolved_ts": _utcnow(),
        },
        synchronize_session=False,
    )
    session.commit()
    if rowcount == 0:
        session.expire(row)
        raise DisposalError("already_resolved", "该处置待办已完成——不可重复处置", 409)
    session.expire(row)  # 条件 UPDATE 绕过会话缓存——读视图前强制刷新
    return todo_view(row)
