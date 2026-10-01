"""/auth/* 路由（2026-09-29 账户门户批）：注册/预检/挑战/激活/登录/资料/会话。

统一信封 {code,message,data}；Cookie：HttpOnly+SameSite=Lax（fz_session）。
限速：challenge/activate/login 共享尝试窗（内存固定窗——多进程部署升共享存储）。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.accounts.deps import require_role
from app.accounts.service import (
    AccountError,
    SESSION_COOKIE,
    activate,
    auth_limiter,
    get_account,
    issue_challenge,
    keystore_of,
    keep_profile,
    login,
    prelogin,
    register_account,
    submit_profile,
)
from app.db import get_session

router = APIRouter(prefix="/auth", tags=["accounts"])


def _err(exc: AccountError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status, content={"code": exc.code, "message": str(exc), "data": None}
    )


def _client_key(request: Request, username: str) -> str:
    ip = request.client.host if request.client else "?"
    return f"{ip}|{username}"


class RegisterIn(BaseModel):
    username: str = Field(min_length=2, max_length=32)
    pubkey_hex: str = Field(min_length=128, max_length=128)
    sealed_blob: str = Field(min_length=32, max_length=8192)


class ActivateIn(BaseModel):
    username: str = Field(min_length=2, max_length=32)
    # KDF 核对子=16B KEK 的 hex（32 字符——与前端 deriveKek 输出同构）
    verifier_hex: str = Field(min_length=32, max_length=32)
    pubkey_hex: str = Field(min_length=128, max_length=128)
    sealed_blob: str = Field(min_length=32, max_length=8192)


class LoginIn(BaseModel):
    username: str = Field(min_length=2, max_length=32)
    nonce_hex: str = Field(min_length=64, max_length=64)
    sig_hex: str = Field(min_length=16, max_length=512)


class ProfileIn(BaseModel):
    id_number: str = Field(min_length=18, max_length=18)
    cert_level: int = Field(ge=1, le=4)
    sn: str = Field(min_length=1, max_length=64)
    class_id: int = Field(ge=0, le=255)


class ProfileKeepIn(BaseModel):
    # 密码 KEK 密封的 {cred,form}（零明文 PIII 落库——跨设备恢复面）
    sealed_profile: str = Field(min_length=32, max_length=65536)


@router.post("/register")
def register(body: RegisterIn, session: Session = Depends(get_session)):
    try:
        row = register_account(session, body.username, body.pubkey_hex, body.sealed_blob)
    except AccountError as exc:
        return _err(exc)
    return JSONResponse(
        status_code=201,
        content={
            "code": "ok",
            "message": "",
            "data": {"username": row.username, "role": row.role, "status": row.status},
        },
    )


@router.get("/prelogin/{username}")
def prelogin_route(username: str, request: Request, session: Session = Depends(get_session)):
    try:
        auth_limiter.check(f"prelogin|{_client_key(request, username)}")
        data = prelogin(session, username)
    except AccountError as exc:
        return _err(exc)
    return JSONResponse(status_code=200, content={"code": "ok", "message": "", "data": data})


@router.get("/keystore/{username}")
def keystore_route(username: str, session: Session = Depends(get_session)):
    """密封件下发（属主自取解封——公开网络面拿到密封件只有离线猜测面）。"""
    try:
        data = keystore_of(session, username)
    except AccountError as exc:
        return _err(exc)
    return JSONResponse(status_code=200, content={"code": "ok", "message": "", "data": data})


@router.post("/challenge/{username}")
def challenge_route(username: str, request: Request, session: Session = Depends(get_session)):
    try:
        auth_limiter.check(f"challenge|{_client_key(request, username)}")
        nonce = issue_challenge(session, username)
    except AccountError as exc:
        return _err(exc)
    return JSONResponse(status_code=200, content={"code": "ok", "message": "", "data": {"nonce_hex": nonce}})


@router.post("/activate")
def activate_route(body: ActivateIn, request: Request, session: Session = Depends(get_session)):
    try:
        auth_limiter.check(f"activate|{_client_key(request, body.username)}")
        activate(session, body.username, body.verifier_hex, body.pubkey_hex, body.sealed_blob)
    except AccountError as exc:
        return _err(exc)
    return JSONResponse(status_code=200, content={"code": "ok", "message": "激活成功——请继续登录", "data": None})


@router.post("/login")
def login_route(body: LoginIn, request: Request, session: Session = Depends(get_session)):
    try:
        auth_limiter.check(f"login|{_client_key(request, body.username)}")
        token, row = login(session, body.username, body.nonce_hex, body.sig_hex)
    except AccountError as exc:
        return _err(exc)
    auth_limiter.reset(f"login|{_client_key(request, body.username)}")
    resp = JSONResponse(
        status_code=200,
        content={
            "code": "ok",
            "message": "",
            "data": {
                "username": row.username,
                "role": row.role,
                "status": row.status,
                "cred_hash_hex": row.cred_hash_hex,
            },
        },
    )
    # Cookie 挂在实际返回对象上（挂注入 Response 参数会被返回值覆盖——实测教训）
    resp.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="lax",
        secure=False,  # 演示 http 档；生产 TLS 部署置 True（部署面开关）
        max_age=12 * 3600,
        path="/",
    )
    return resp


@router.post("/profile")
def profile_route(
    body: ProfileIn,
    session: Session = Depends(get_session),
    principal=Depends(require_role("pilot")),
):
    """资料补全→RA 签发上链（须 pilot 会话）。本端点=「上链注册」发生时刻；
    密封资料经 /auth/profile/keep 二相回存。"""
    try:
        row = get_account(session, principal.username)
        out = submit_profile(
            session,
            row,
            id_number=body.id_number,
            cert_level=body.cert_level,
            sn=body.sn,
            class_id=body.class_id,
        )
    except AccountError as exc:
        return _err(exc)
    return JSONResponse(status_code=200, content={"code": "ok", "message": "凭证已签发并上链", "data": out})


@router.post("/profile/keep")
def profile_keep_route(
    body: ProfileKeepIn,
    session: Session = Depends(get_session),
    principal=Depends(require_role("pilot")),
):
    """二相回存：{cred,form} 密码 KEK 密封件（零明文 PIII）。"""
    try:
        row = get_account(session, principal.username)
        keep_profile(session, row, body.sealed_profile)
    except AccountError as exc:
        return _err(exc)
    return JSONResponse(status_code=200, content={"code": "ok", "message": "", "data": None})


@router.get("/me")
def me_route(request: Request, session: Session = Depends(get_session)):
    from app.accounts.deps import principal_from

    p = principal_from(request, session)
    if p is None:
        return JSONResponse(
            status_code=401,
            content={"code": "unauthorized", "message": "未登录或会话已失效", "data": None},
        )
    try:
        row = get_account(session, p.username)
        data = {
            "username": row.username,
            "role": row.role,
            "status": row.status,
            "pubkey_hex": row.pubkey_hex,
            "cred_hash_hex": row.cred_hash_hex,
            "sealed_blob": row.sealed_blob,
            "sealed_profile": row.sealed_profile,
        }
    except AccountError as exc:
        return _err(exc)
    return JSONResponse(status_code=200, content={"code": "ok", "message": "", "data": data})


@router.post("/logout")
def logout_route(request: Request, session: Session = Depends(get_session)):
    from app.accounts.service import logout as _logout

    _logout(session, request.cookies.get(SESSION_COOKIE, ""))
    resp = JSONResponse(status_code=200, content={"code": "ok", "message": "", "data": None})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@router.get("/whoami")
def whoami_route(p=Depends(require_role("pilot", "auditor", "admin"))):
    """角色守卫自检面（前端路由诊断用）：401/403 语义与业务端点一致。"""
    return JSONResponse(
        status_code=200,
        content={
            "code": "ok",
            "message": "",
            "data": {"username": p.username, "role": p.role, "status": p.status},
        },
    )
