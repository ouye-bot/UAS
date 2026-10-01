"""会话依赖（FastAPI）：Cookie→会话→角色守卫。

口径：审计/机构端点全部会话+角色约束（X-Audit-Token/X-RA-Token 已随账户批
退役）；401=未登录/会话失效，403=角色不符——两层语义分立，负例一等公民。
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.accounts.models import SESSION_TTL_HOURS  # noqa: F401  再出口（口径面）
from app.accounts.service import SESSION_COOKIE  # noqa: F401  再出口
from app.db import get_session


@dataclass
class Principal:
    username: str
    role: str
    status: str
    cred_hash_hex: str | None


def principal_from(request: Request, session: Session) -> Principal | None:
    from app.accounts.service import session_of

    token = request.cookies.get(SESSION_COOKIE, "")
    if not token:
        return None
    found = session_of(session, token)
    if found is None:
        return None
    _, acc = found
    return Principal(
        username=acc.username, role=acc.role, status=acc.status, cred_hash_hex=acc.cred_hash_hex
    )


def require_role(*roles: str):
    """角色守卫工厂：require_role("auditor") / require_role("admin")。
    会话校验走 get_session 依赖链（测试可覆盖；与业务端点同库同事务域）。"""

    def _dep(request: Request, session: Session = Depends(get_session)) -> Principal:
        p = principal_from(request, session)
        if p is None:
            raise HTTPException(
                status_code=401,
                detail={"code": "unauthorized", "message": "未登录或会话已失效——请重新登录"},
            )
        if p.role not in roles:
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "forbidden",
                    "message": f"本操作需 {'/'.join(roles)} 角色——当前 {p.role}",
                },
            )
        return p

    return _dep


__all__ = ["Principal", "SESSION_COOKIE", "SESSION_TTL_HOURS", "principal_from", "require_role"]
