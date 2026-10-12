"""/auth/* 路由（2026-09-29 账户门户批；2026-10-04 批 2 密码底座升档）：
注册/预检/挑战/激活/登录/资料/会话/密封件惰性升级。

统一信封 {code,message,data}；Cookie：HttpOnly+SameSite=Lax（fz_session），
secure=FZ_COOKIE_SECURE（缺省 production 档自动 True）。
限速：challenge/login 共享尝试窗（ip|username 键）；activate 专窗 5 发/300s、
键=纯 username（激活面收紧批 2026-10-11——批量开户同出口 IP 不误伤）。
尝试窗落库 rate_limit_buckets——多副本部署共享同窗，重启不清零。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.accounts.deps import principal_from, require_role
from app.accounts.opaque import (
    audit_evaluate_failure,
    build_evaluate_response,
    opaque_enabled,
)
from app.accounts.service import (
    SESSION_COOKIE,
    AccountError,
    activate,
    activate_limiter,
    activation_rate_key,
    auth_limiter,
    change_password,
    cookie_secure,
    evaluate_limiter,
    get_account,
    issue_challenge,
    keep_profile,
    keystore_of,
    login,
    migrate_to_opaque,
    prelogin,
    register_account,
    submit_profile,
    upgrade_sealed_blob,
)
from app.crypto.oprf import OPRFError
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
    # ⑫O-3（gate on 必填——OPRF 记录材料，设计 §1.3/D-6/D-8）
    masking_key_hex: str | None = Field(default=None, min_length=64, max_length=64)
    kdf_salt_hex: str | None = Field(default=None, min_length=32, max_length=32)
    kdf_iter: int | None = None


class ActivateIn(BaseModel):
    username: str = Field(min_length=2, max_length=32)
    # KDF 核对子=16B KEK 的 hex（32 字符——与前端 deriveKek 输出同构）
    verifier_hex: str = Field(min_length=32, max_length=32)
    pubkey_hex: str = Field(min_length=128, max_length=128)
    sealed_blob: str = Field(min_length=32, max_length=8192)
    # 一次性激活码（2026-10-11 批③双因子）：仅档位启用（production/显式 env）
    # 时强制；demo 档缺省关，不传即走纯核对子流
    activation_code: str | None = Field(default=None, min_length=1, max_length=64)
    # ⑫O-3（gate on 必填——OPRF 记录材料，设计 §1.3/D-6/D-8）
    masking_key_hex: str | None = Field(default=None, min_length=64, max_length=64)
    kdf_salt_hex: str | None = Field(default=None, min_length=32, max_length=32)
    kdf_iter: int | None = None


class LoginIn(BaseModel):
    username: str = Field(min_length=2, max_length=32)
    nonce_hex: str = Field(min_length=64, max_length=64)
    sig_hex: str = Field(min_length=16, max_length=512)


class ProfileIn(BaseModel):
    id_number: str = Field(min_length=18, max_length=18)
    cert_level: int = Field(ge=1, le=4)
    sn: str = Field(min_length=1, max_length=64)
    class_id: int = Field(ge=0, le=255)
    # ⑥站多机构：受理机构域（缺省=账户 org_id→org-a——用户选机构受理面的域键）
    org_id: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9-]{0,31}$")


class ProfileKeepIn(BaseModel):
    # 密码 KEK 密封的 {cred,form}（零明文 PIII 落库——跨设备恢复面）
    sealed_profile: str = Field(min_length=32, max_length=65536)


@router.post("/register")
def register(body: RegisterIn, session: Session = Depends(get_session)):
    try:
        row = register_account(
            session,
            body.username,
            body.pubkey_hex,
            body.sealed_blob,
            masking_key_hex=body.masking_key_hex,
            kdf_salt_hex=body.kdf_salt_hex,
            kdf_iter=body.kdf_iter,
        )
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
def keystore_route(username: str, request: Request, session: Session = Depends(get_session)):
    """密封件下发（属主自取解封——v4 过渡存量面）。
    ⑫O-3 硬化（设计 §5.5——红线：先于任何迁移删除事务就位）：①限流桶先行
    （keystore|ip|username——原「无鉴权无限流=离线枚举面本体」缺口收口）；
    ②v6 账户=410（mode-B 掩码通道取代——服务层 opaque_migrated）。"""
    try:
        auth_limiter.check(f"keystore|{_client_key(request, username)}", session)
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


class PasswordChangeIn(BaseModel):
    """自助改密回传体：新密码 KEK 重封的信封（必填）+ 同口径重封的资料
    密封件（选填——pilot 有 sealed_profile 时必须同请求原子换新，否则旧密码
    仍可解资料=改密半吊子）。
    ⑫O-3：v6 账户（OPRF 记录在账）须 v6' blob+新 masking_key（原子换新——
    防「新 rwd 信封+旧掩码钥」的永不可解错配，设计 §5.6）；v4 存量=v4 语义
    零破坏（不得携带 masking_key）。"""

    sealed_blob: str = Field(min_length=32, max_length=8192)
    sealed_profile: str | None = Field(default=None, min_length=32, max_length=16384)
    masking_key_hex: str | None = Field(default=None, min_length=64, max_length=64)


@router.post("/password/change")
def password_change_route(
    body: PasswordChangeIn,
    request: Request,
    session: Session = Depends(get_session),
):
    """自助修改密码（2026-10-12 修整窗口 P1——pm 走查件 Q4-1「最大产品缺口」；
    ⑫O-3 扩展 v6 重封语义——落账校验收口 service.change_password 单源）。

    语义（改密码=重封不动钥）：私钥 sk 不变（登录挑战-应答、操作签名语义
    不受影响），仅换人肉防线的 KEK 源/rwd 根。会话延续（Cookie 会话与密码
    无涉）；逐笔记入 account_admin_log 台账（operator=self，与离线重置同流
    可审计）。属主自换（principal 即属主，无跨用户面）。"""
    p = principal_from(request, session)
    if p is None:
        return JSONResponse(
            status_code=401,
            content={"code": "unauthorized", "message": "未登录或会话已失效", "data": None},
        )
    try:
        change_password(
            session,
            p.username,
            body.sealed_blob,
            masking_key_hex=body.masking_key_hex,
            sealed_profile=body.sealed_profile,
        )
    except AccountError as exc:
        return _err(exc)
    return JSONResponse(
        status_code=200,
        content={
            "code": "ok",
            "message": "密码已更换——本会话延续；密封件与资料已按新密码重封",
            "data": None,
        },
    )


@router.post("/challenge/{username}")
def challenge_route(username: str, request: Request, session: Session = Depends(get_session)):
    try:
        auth_limiter.check(f"challenge|{_client_key(request, username)}", session)
        nonce = issue_challenge(session, username)
    except AccountError as exc:
        return _err(exc)
    return JSONResponse(
        status_code=200, content={"code": "ok", "message": "", "data": {"nonce_hex": nonce}}
    )


class OpaqueEvaluateIn(BaseModel):
    """OPAQUE evaluate 请求（RFC 9807 CredentialRequest/RegistrationRequest 统一
    对位——设计 §2.1）：username+盲化元素 α（128 hex）。"""

    username: str = Field(min_length=2, max_length=32)
    alpha_hex: str = Field(min_length=128, max_length=128)


@router.post("/opaque/evaluate")
def opaque_evaluate_route(
    body: OpaqueEvaluateIn, request: Request, session: Session = Depends(get_session)
):
    """⑫O-3 OPAQUE evaluate（设计 §2/§6）：恒五键响应（真实/fake 双态同形同长
    ——§6.1 fake-record=RFC 9807 §6.3.2.2 定长全零 envelope+随机 masking_key）；
    线协议第 2 消息。限流桶 10 发/300s（§6.6 Cheon 纪律）+异常事件台账
    （opaque_rate_limited/opaque_invalid_point——正常 evaluate 不入台账）。"""
    if not opaque_enabled():
        return _err(AccountError("opaque_disabled", "OPAQUE 通道未启用", 503))
    try:
        evaluate_limiter.check(f"opaque|{_client_key(request, body.username)}", session)
    except AccountError as exc:
        audit_evaluate_failure(
            session,
            action="opaque_rate_limited",
            username=body.username,
            detail="evaluate 配额耗尽（Cheon 纪律——10 发/300s 窗）",
        )
        session.commit()
        return _err(exc)
    owner = principal_from(request, session)
    try:
        data = build_evaluate_response(
            session,
            body.username,
            body.alpha_hex,
            session_owner=owner.username if owner is not None else None,
        )
    except OPRFError as exc:
        if exc.code == "invalid_point":
            audit_evaluate_failure(
                session,
                action="opaque_invalid_point",
                username=body.username,
                detail=f"O-1 前置拒绝：{exc}",
            )
            session.commit()
            return _err(AccountError("opaque_invalid_point", str(exc), 400))
        return _err(AccountError(exc.code, str(exc), 400))
    except AccountError as exc:
        return _err(exc)
    return JSONResponse(status_code=200, content={"code": "ok", "message": "", "data": data})


@router.post("/activate")
def activate_route(body: ActivateIn, session: Session = Depends(get_session)):
    try:
        # 限速键=纯 username（2026-10-11 批①：激活是账户变量不是网络路径变量
        # ——同机构出口 IP 批量开户为合法形态，IP 维度会误伤；5 发/窗专例，
        # 比 login/challenge 的共享窗更紧——核对子面=唯一凭初始口令即可绑定
        # 任意自选钥对的面）
        activate_limiter.check(activation_rate_key(body.username), session)
        activate(
            session,
            body.username,
            body.verifier_hex,
            body.pubkey_hex,
            body.sealed_blob,
            activation_code=body.activation_code,
            masking_key_hex=body.masking_key_hex,
            kdf_salt_hex=body.kdf_salt_hex,
            kdf_iter=body.kdf_iter,
        )
    except AccountError as exc:
        return _err(exc)
    return JSONResponse(
        status_code=200, content={"code": "ok", "message": "激活成功——请继续登录", "data": None}
    )


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
            org_id=body.org_id,
        )
    except AccountError as exc:
        return _err(exc)
    return JSONResponse(
        status_code=200, content={"code": "ok", "message": "凭证已签发并上链", "data": out}
    )


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


class OpaqueMigrateIn(BaseModel):
    """v4→v6 惰性重封回传体（设计 §5.1-3——**D-11**：迁移体携带与注册同构的
    D-8 四件套；资料槽可选同请求原子换新）。"""

    sealed_blob: str = Field(min_length=32, max_length=8192)
    masking_key_hex: str | None = Field(default=None, min_length=64, max_length=64)
    kdf_salt_hex: str | None = Field(default=None, min_length=32, max_length=32)
    kdf_iter: int | None = None
    sealed_profile: str | None = Field(default=None, min_length=32, max_length=16384)


@router.post("/opaque/migrate")
def opaque_migrate_route(
    body: OpaqueMigrateIn, request: Request, session: Session = Depends(get_session)
):
    """⑫O-4 v4→v6 惰性重封通道（设计 §5.1-3/§5.4——**删除事务**本体）：会话
    属主自迁移（v4 登录成功后客户端同口令走注册序→本端点回传）。原子换新+
    §5.5-3 keystore 收口运行时断言（O-3 先行红线）+回滚窗（失败零部分状态）+
    台账逐笔。gate off=503（迁移通道随总开关关闭）。"""
    p = principal_from(request, session)
    if p is None:
        return JSONResponse(
            status_code=401,
            content={"code": "unauthorized", "message": "未登录或会话已失效", "data": None},
        )
    try:
        migrate_to_opaque(
            session,
            p.username,
            body.sealed_blob,
            body.masking_key_hex,
            body.kdf_salt_hex,
            body.kdf_iter,
            sealed_profile=body.sealed_profile,
        )
    except AccountError as exc:
        return _err(exc)
    return JSONResponse(
        status_code=200,
        content={
            "code": "ok",
            "message": "已迁移 OPAQUE 封装——后续登录走掩码响应通道",
            "data": None,
        },
    )


@router.post("/logout")
def logout_route(request: Request, session: Session = Depends(get_session)):
    from app.accounts.service import logout as _logout

    _logout(session, request.cookies.get(SESSION_COOKIE, ""))
    resp = JSONResponse(status_code=200, content={"code": "ok", "message": "", "data": None})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@router.get("/whoami")
def whoami_route(
    p=Depends(require_role("pilot", "auditor", "admin")),
    session: Session = Depends(get_session),
):
    """角色守卫自检面（前端路由诊断用）：401/403 语义与业务端点一致。
    ⑥站多机构：org_id=机构域键（org-a 缺省域/org-b 第二机构 demo 域）。"""
    row = get_account(session, p.username)
    return JSONResponse(
        status_code=200,
        content={
            "code": "ok",
            "message": "",
            "data": {
                "username": p.username,
                "role": p.role,
                "status": p.status,
                "org_id": row.org_id if row is not None else "org-a",
            },
        },
    )
