"""/auth/* 路由（2026-09-29 账户门户批；2026-10-04 批 2 密码底座升档）：
注册/预检/挑战/激活/登录/资料/会话/密封件惰性升级。

统一信封 {code,message,data}；Cookie：HttpOnly+SameSite=Lax（fz_session），
secure=FZ_COOKIE_SECURE（缺省 production 档自动 True）。
限速：challenge/activate/login 共享尝试窗（rate_limit_buckets 落库——
多副本部署共享同窗，重启不清零）。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.accounts.deps import principal_from, require_role
from app.accounts.service import (
    SESSION_COOKIE,
    AccountError,
    activate,
    auth_limiter,
    cookie_secure,
    get_account,
    issue_challenge,
    keep_profile,
    keystore_of,
    login,
    prelogin,
    register_account,
    submit_profile,
    upgrade_sealed_blob,
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
        auth_limiter.check(f"prelogin|{_client_key(request, username)}", session)
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


class KeystoreUpgradeIn(BaseModel):
    # v4 重封件（客户端解封存量 v3 后同口令重封回传——惰性升级面）
    sealed_blob: str = Field(min_length=32, max_length=8192)


@router.post("/keystore/upgrade")
def keystore_upgrade_route(
    body: KeystoreUpgradeIn, request: Request, session: Session = Depends(get_session)
):
    """密封件惰性升级回传（批 2-2.1）：登录/解锁会话内把 v3 存量密封件
    换成同口令 v4 重封件（属主自换——principal 即属主，路径无用户名参数）。"""
    p = principal_from(request, session)
    if p is None:
        return JSONResponse(
            status_code=401,
            content={"code": "unauthorized", "message": "未登录或会话已失效", "data": None},
        )
    try:
        upgrade_sealed_blob(session, p.username, body.sealed_blob)
    except AccountError as exc:
        return _err(exc)
    return JSONResponse(status_code=200, content={"code": "ok", "message": "", "data": None})


@router.post("/challenge/{username}")
def challenge_route(username: str, request: Request, session: Session = Depends(get_session)):
    try:
        auth_limiter.check(f"challenge|{_client_key(request, username)}", session)
        nonce = issue_challenge(session, username)
    except AccountError as exc:
        return _err(exc)
    return JSONResponse(status_code=200, content={"code": "ok", "message": "", "data": {"nonce_hex": nonce}})


@router.post("/activate")
def activate_route(body: ActivateIn, request: Request, session: Session = Depends(get_session)):
    try:
        auth_limiter.check(f"activate|{_client_key(request, body.username)}", session)
        activate(session, body.username, body.verifier_hex, body.pubkey_hex, body.sealed_blob)
    except AccountError as exc:
        return _err(exc)
    return JSONResponse(status_code=200, content={"code": "ok", "message": "激活成功——请继续登录", "data": None})


@router.post("/login")
def login_route(body: LoginIn, request: Request, session: Session = Depends(get_session)):
    try:
        auth_limiter.check(f"login|{_client_key(request, body.username)}", session)
        token, row = login(session, body.username, body.nonce_hex, body.sig_hex)
    except AccountError as exc:
        return _err(exc)
    auth_limiter.reset(f"login|{_client_key(request, body.username)}", session)
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
        secure=cookie_secure(),  # 批 2-2.5②：FZ_COOKIE_SECURE 配置化；production 档自动 True
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
