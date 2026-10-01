"""账户服务（2026-09-29 账户门户批）：注册/激活/挑战-应答登录/会话/资料签发。

安全语义（docs/评审/2026-09-29-账户门户与三角色工作台/设计方案.md §2）：
- 服务端零密码材料：登录认证=SM2 挑战-应答签名（nonce 一次性+TTL）；
  预置机构账户首登激活用初始密码核对子（KDF 派生值）一次性核对后即焚。
- 私钥/身份资料仅存客户端密码 KEK 密封件——服务器无法解封，库泄露
  只得到离线猜测面（KDF 21000 轮拉高成本；OPAQUE 列演进项）。
- 密钥核对：解封出的私钥须与账户登记公钥派生一致（pubkey_from_priv），
  防密封件与公钥错配。
"""

from __future__ import annotations

import datetime as dt
import hmac
import json
import re
import secrets
import threading
import time

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.accounts.kdf import derive_kek
from app.accounts.models import (
    CHALLENGE_TTL_SECONDS,
    SESSION_TTL_HOURS,
    Account,
    AccountAdminLog,
    AccountPubkeyHistory,
    AuthChallenge,
    WebSession,
)
from app.crypto.sm2 import pubkey_from_priv, verify as sm2_verify
from app.crypto.sm3 import sm3_bytes

USERNAME_RE = re.compile(r"[A-Za-z0-9._\-]{2,32}")
LOGIN_MSG_PREFIX = "FZ-AUTH-LOGIN|"
_ROLES = ("pilot", "auditor", "admin")


def append_pubkey_epoch(session: Session, username: str, pubkey_hex: str) -> int:
    """公钥纪元追加（append-only 史的唯一写入口）：epoch=账户内 max+1。

    调用点=公钥真正入账的时刻（注册/激活）。重置不追加只关闭（retire）。"""
    top = session.execute(
        select(AccountPubkeyHistory.epoch)
        .where(AccountPubkeyHistory.username == username)
        .order_by(AccountPubkeyHistory.epoch.desc())
        .limit(1)
    ).scalar_one_or_none()
    epoch = (top or 0) + 1
    session.add(
        AccountPubkeyHistory(
            username=username, epoch=epoch, pubkey_hex=pubkey_hex.lower(), activated_ts=_utcnow()
        )
    )
    return epoch


def retire_active_pubkey_epoch(session: Session, username: str) -> int | None:
    """关闭当前活动纪元（密码重置时调用——行保留，仅打 retired_ts）。

    返回被关闭的 epoch（无活动纪元= None，如从未激活过的账户）。"""
    row = session.execute(
        select(AccountPubkeyHistory)
        .where(AccountPubkeyHistory.username == username, AccountPubkeyHistory.retired_ts.is_(None))
        .order_by(AccountPubkeyHistory.epoch.desc())
        .limit(1)
    ).scalar_one_or_none()
    if row is None:
        return None
    row.retired_ts = _utcnow()
    return row.epoch


def pubkey_at(session: Session, username: str, ts: dt.datetime) -> str | None:
    """签名时点公钥查询（历史签名复验的原子）：activated_ts<=ts<retired_ts
    （或活动行）。无匹配纪元（早于注册/晚于退休且未再激活）=None。"""
    row = session.execute(
        select(AccountPubkeyHistory)
        .where(
            AccountPubkeyHistory.username == username,
            AccountPubkeyHistory.activated_ts <= ts,
            (AccountPubkeyHistory.retired_ts.is_(None)) | (AccountPubkeyHistory.retired_ts > ts),
        )
        .order_by(AccountPubkeyHistory.epoch.desc())
        .limit(1)
    ).scalar_one_or_none()
    return row.pubkey_hex if row else None


def pubkey_epoch_at(session: Session, username: str, ts: dt.datetime) -> int | None:
    """同 pubkey_at 但返回纪元号（复验结果的归档面）。"""
    row = session.execute(
        select(AccountPubkeyHistory)
        .where(
            AccountPubkeyHistory.username == username,
            AccountPubkeyHistory.activated_ts <= ts,
            (AccountPubkeyHistory.retired_ts.is_(None)) | (AccountPubkeyHistory.retired_ts > ts),
        )
        .order_by(AccountPubkeyHistory.epoch.desc())
        .limit(1)
    ).scalar_one_or_none()
    return row.epoch if row else None


def log_account_action(
    session: Session, *, action: str, username: str, operator: str, detail: str | None = None
) -> None:
    """账户管理动作台账（append-only）：重置等敏感动作逐笔留痕。

    在线面已无重置入口（2026-09-30 收紧）——operator 恒为离线种子脚本。"""
    session.add(AccountAdminLog(action=action, username=username, operator=operator, detail=detail))

# 会话 Cookie 名与参数（HttpOnly+SameSite=Lax——演示 http 档不含 Secure，
# 生产 TLS 部署加 Secure 属部署面开关）
SESSION_COOKIE = "fz_session"


class AccountError(Exception):
    def __init__(self, code: str, message: str = "", status: int = 400) -> None:
        super().__init__(message or code)
        self.code = code
        self.status = status


# ---- /auth/* 尝试限速（内存固定窗：演示形态诚实注记——多进程部署须共享存储）----
class AttemptLimiter:
    def __init__(self, max_attempts: int = 10, window_s: float = 300.0) -> None:
        self._max = max_attempts
        self._win = window_s
        self._hits: dict[str, tuple[float, int]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            hit = self._hits.get(key)
            if hit and now - hit[0] < self._win:
                if hit[1] >= self._max:
                    raise AccountError(
                        "rate_limited",
                        "尝试过于频繁——请稍候再试（5 分钟窗口）",
                        429,
                    )
                self._hits[key] = (hit[0], hit[1] + 1)
            else:
                self._hits[key] = (now, 1)

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)


auth_limiter = AttemptLimiter()


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC).replace(tzinfo=None)


# ---- 密封件结构校验（fail-closed：坏结构在注册/激活即拒，不带病入库）----
def _validate_sealed_blob(blob_text: str, pubkey_hex: str) -> None:
    try:
        obj = json.loads(blob_text)
    except ValueError as e:
        raise AccountError("bad_blob", "密封件不是有效 JSON") from e
    if not isinstance(obj, dict) or obj.get("v") != 3 or obj.get("pk") != pubkey_hex:
        raise AccountError("bad_blob", "密封件形态不符（v3 信封且公钥须一致）")
    enc = obj.get("enc")
    if not isinstance(enc, dict):
        raise AccountError("bad_blob", "密封件缺少密码密封槽")
    for f, ln in (("salt", 32), ("nonce", 24), ("ct", 2), ("tag", 32)):
        v = enc.get(f)
        if not isinstance(v, str) or len(v) < ln or len(v) % 2:
            raise AccountError("bad_blob", f"密封槽字段 {f} 非法")
        try:
            bytes.fromhex(v)
        except ValueError as e:
            raise AccountError("bad_blob", f"密封槽字段 {f} 非法 hex") from e
    if len(enc["ct"]) < 2:
        raise AccountError("bad_blob", "密封密文为空")


def _validate_pubkey(pubkey_hex: str) -> None:
    if len(pubkey_hex) != 128:
        raise AccountError("bad_pubkey", "公钥须 128 hex（SM2 未压缩点无 04 前缀）")
    from app.crypto.sm2 import assert_pub

    try:
        assert_pub(pubkey_hex)
    except Exception as e:  # noqa: BLE001  曲线点校验失败=非法公钥
        raise AccountError("bad_pubkey", "公钥不是合法 SM2 曲线点") from e


def get_account(session: Session, username: str) -> Account:
    row = session.execute(
        select(Account).where(Account.username == username)
    ).scalar_one_or_none()
    if row is None:
        raise AccountError("user_not_found", "账户不存在", 404)
    return row


def register_account(
    session: Session, username: str, pubkey_hex: str, sealed_blob: str
) -> Account:
    """飞手自助注册：浏览器生成钥对+密码密封→上传密封件。账户=待补资料态，
    零链副作用（上链发生在资料补全、RA 签发时——账户≠凭证）。"""
    if not USERNAME_RE.fullmatch(username or ""):
        raise AccountError("bad_username", "用户名仅限字母/数字/._-（2..32）")
    _validate_pubkey(pubkey_hex)
    _validate_sealed_blob(sealed_blob, pubkey_hex)
    dup = session.execute(
        select(Account).where(Account.username == username)
    ).scalar_one_or_none()
    if dup is not None:
        raise AccountError("username_taken", "用户名已被占用", 409)
    row = Account(
        username=username,
        role="pilot",
        status="pending_profile",
        pubkey_hex=pubkey_hex.lower(),
        sealed_blob=sealed_blob,
    )
    session.add(row)
    append_pubkey_epoch(session, username, pubkey_hex)  # 纪元 1（append-only 史）
    session.commit()
    return row


def prelogin(session: Session, username: str) -> dict:
    """登录前置：返回认证模式。challenge=稳态（取密封件+签名）；activation=
    预置机构账户首登（KDF 核对子激活）。"""
    row = get_account(session, username)
    if row.status == "pending_activation":
        return {"mode": "activation", "kdf_salt_hex": row.init_kdf_salt_hex, "rounds": 21000}
    if row.status == "pending_profile":
        return {"mode": "challenge"}  # 已可登录（资料未补，工作台受限）
    return {"mode": "challenge"}


def keystore_of(session: Session, username: str) -> dict:
    """密封件下发（属主自取——登录必须先拿密封件才能解封签名）。"""
    row = get_account(session, username)
    if not row.sealed_blob or not row.pubkey_hex:
        raise AccountError("not_activated", "账户尚未激活（未生成密钥）", 409)
    return {"sealed_blob": row.sealed_blob, "pubkey_hex": row.pubkey_hex}


def issue_challenge(session: Session, username: str) -> str:
    row = get_account(session, username)
    if row.status != "active" and row.status != "pending_profile":
        raise AccountError("not_activated", "账户尚未激活", 409)
    if not row.pubkey_hex:
        raise AccountError("not_activated", "账户尚未激活（未生成密钥）", 409)
    nonce = secrets.token_hex(32)
    # 顺手清过期挑战（演示规模全表扫可接受；量大走索引+后台清理）
    cutoff = _utcnow() - dt.timedelta(seconds=CHALLENGE_TTL_SECONDS * 10)
    for stale in session.execute(
        select(AuthChallenge).where(AuthChallenge.created_ts < cutoff)
    ).scalars():
        session.delete(stale)
    session.add(AuthChallenge(nonce_hex=nonce, username=username))
    session.commit()
    return nonce


def activate(
    session: Session, username: str, verifier_hex: str, pubkey_hex: str, sealed_blob: str
) -> None:
    """预置机构账户首登激活：初始密码核对子一次性比对（恒时）→写入钥对→
    焚烧核对子——此后进入纯挑战-应答态（密码材料归零）。"""
    row = get_account(session, username)
    if row.status != "pending_activation":
        raise AccountError("not_activatable", "该账户不在待激活状态", 409)
    _validate_pubkey(pubkey_hex)
    _validate_sealed_blob(sealed_blob, pubkey_hex)
    want = row.init_verifier_hex or ""
    if not want or not hmac.compare_digest(verifier_hex.lower(), want):
        raise AccountError("activation_failed", "初始密码不正确", 401)
    row.pubkey_hex = pubkey_hex.lower()
    row.sealed_blob = sealed_blob
    row.init_verifier_hex = None
    row.init_kdf_salt_hex = None
    row.status = "active"
    append_pubkey_epoch(session, username, pubkey_hex)  # 首激活=纪元 1；重置后再激活=新纪元
    session.commit()


def verify_init_verifier(username: str, verifier_hex: str) -> bool:
    """种子脚本/测试用：核对子形态自检（16B KEK hex=32 字符；不查库）。"""
    return bool(verifier_hex) and len(verifier_hex) == 32


def login(session: Session, username: str, nonce_hex: str, sig_hex: str) -> tuple[str, Account]:
    """挑战-应答登录：nonce 一次性消费+SM2 验签→发会话 token（库存 SM3）。"""
    row = get_account(session, username)
    if not row.pubkey_hex:
        raise AccountError("not_activated", "账户尚未激活（未生成密钥）", 409)
    ch = session.execute(
        select(AuthChallenge).where(AuthChallenge.nonce_hex == nonce_hex)
    ).scalar_one_or_none()
    if ch is None or ch.consumed_ts is not None:
        raise AccountError("bad_challenge", "登录挑战无效或已使用——请重新获取", 401)
    if ch.username != username:
        raise AccountError("bad_challenge", "登录挑战与账户不匹配", 401)
    age = (_utcnow() - ch.created_ts).total_seconds()
    if age > CHALLENGE_TTL_SECONDS:
        raise AccountError("challenge_expired", "登录挑战已过期——请重新登录", 401)
    msg = (LOGIN_MSG_PREFIX + nonce_hex).encode()
    if not sm2_verify(row.pubkey_hex, msg, sig_hex):
        raise AccountError("auth_failed", "签名验证失败——密码错误或凭据被篡改", 401)
    ch.consumed_ts = _utcnow()
    token = secrets.token_hex(32)
    session.add(
        WebSession(
            token_hash_hex=sm3_bytes(token.encode()).hex(),
            username=username,
            role=row.role,
            expires_ts=_utcnow() + dt.timedelta(hours=SESSION_TTL_HOURS),
        )
    )
    row.last_login_ts = _utcnow()
    session.commit()
    return token, row


def session_of(session: Session, token: str) -> tuple[WebSession, Account] | None:
    if not token:
        return None
    row = session.execute(
        select(WebSession).where(WebSession.token_hash_hex == sm3_bytes(token.encode()).hex())
    ).scalar_one_or_none()
    if row is None or row.expires_ts < _utcnow():
        return None
    acc = session.execute(
        select(Account).where(Account.username == row.username)
    ).scalar_one_or_none()
    if acc is None:
        return None
    return row, acc


def logout(session: Session, token: str) -> None:
    if not token:
        return
    row = session.execute(
        select(WebSession).where(WebSession.token_hash_hex == sm3_bytes(token.encode()).hex())
    ).scalar_one_or_none()
    if row is not None:
        session.delete(row)
        session.commit()


def seed_institutional_account(
    session: Session, username: str, role: str, initial_password: str
) -> Account:
    """预置机构账户（审计员/管理员）：初始密码→KDF 核对子；首登激活后焚毁。
    幂等：待激活态可重置核对子（落台账）；active 态拒绝（防误覆盖已激活钥对）。"""
    if role not in ("auditor", "admin"):
        raise AccountError("bad_role", "预置账户角色限 auditor/admin")
    row = session.execute(
        select(Account).where(Account.username == username)
    ).scalar_one_or_none()
    if row is not None:
        if row.status == "pending_activation":
            salt = secrets.token_hex(16)
            row.init_kdf_salt_hex = salt
            row.init_verifier_hex = derive_kek(initial_password, salt)
            log_account_action(
                session, action="reseed_pending", username=username, operator="offline_seed_script"
            )
            session.commit()
            return row
        raise AccountError("account_active", "该账户已激活——重置须走账户管理面", 409)
    salt = secrets.token_hex(16)
    row = Account(
        username=username,
        role=role,
        status="pending_activation",
        init_kdf_salt_hex=salt,
        init_verifier_hex=derive_kek(initial_password, salt),
    )
    session.add(row)
    session.commit()
    return row


def reset_institutional_account(
    session: Session, username: str, new_password: str, *, operator: str = "offline_seed_script"
) -> Account:
    """已激活机构账户的密码重置（**唯一合法路径=离线种子脚本**——2026-09-30
    收紧：在线 admin 面的重置端点已下线，互不可重置/自重置禁止）：
    回到 pending_activation（新 KDF 核对子）+焚毁旧钥材料+清除全部会话——
    下次登录走首登激活（浏览器生成新钥对并以上新密码密封）。
    公钥纪元史 append-only：旧纪元只关闭不删除——换钥前的历史签名仍可按
    签名时点公钥复验（collab verify-sigs）；重置动作逐笔入台账。"""
    row = get_account(session, username)
    if row.role not in ("auditor", "admin"):
        raise AccountError("bad_role", "密码重置仅限机构账户（auditor/admin）", 403)
    salt = secrets.token_hex(16)
    closed_epoch = retire_active_pubkey_epoch(session, username)
    log_account_action(
        session,
        action="password_reset",
        username=username,
        operator=operator,
        detail=f"closed_epoch={closed_epoch}" if closed_epoch else "no_active_epoch",
    )
    row.status = "pending_activation"
    row.init_kdf_salt_hex = salt
    row.init_verifier_hex = derive_kek(new_password, salt)
    row.pubkey_hex = None
    row.sealed_blob = None
    row.sealed_profile = None
    row.last_login_ts = None
    for ws in session.execute(
        select(WebSession).where(WebSession.username == username)
    ).scalars():
        session.delete(ws)
    session.commit()
    return row


def submit_profile(
    session: Session,
    account: Account,
    *,
    id_number: str,
    cert_level: int,
    sn: str,
    class_id: int,
) -> dict:
    """资料补全→RA 签发上链（"上链注册"的时点）：复用 RA register 仪式原路
    （承诺计算+主凭证签发+链锚定）。密封资料经 keep_profile 二相回存。"""
    if account.role != "pilot":
        raise AccountError("not_pilot", "仅飞手账户需要补全飞行资料", 403)
    if account.status not in ("pending_profile", "active"):
        raise AccountError("bad_state", "账户状态不允许补资料", 409)
    if not account.pubkey_hex:
        raise AccountError("not_activated", "账户尚未激活（未生成密钥）", 409)
    from app.ra.router import _ra_deps
    from app.ra.service import RaError, RaService

    try:
        out = RaService(session, _ra_deps()).register(
            username=account.username,
            id_number=id_number,
            cert_level=cert_level,
            sn=sn,
            user_pub_hex=account.pubkey_hex,
            class_id=class_id,
        )
    except RaError as exc:
        raise AccountError(exc.code, str(exc), exc.status) from exc
    account.cred_hash_hex = out.get("master_cred_hash_hex")
    account.status = "active"
    session.commit()
    return out


def keep_profile(session: Session, account: Account, sealed_profile: str) -> None:
    """二相回存：客户端把 {cred,form}（签发响应+表单）以密码 KEK 密封后上传
    ——零明文 PIII 落库，跨设备登录解封恢复。"""
    if account.role != "pilot":
        raise AccountError("not_pilot", "仅飞手账户有密封资料", 403)
    if not account.cred_hash_hex:
        raise AccountError("no_cred", "尚未签发凭证——先完成资料补全", 409)
    account.sealed_profile = sealed_profile
    session.commit()


def cross_check_unsealed(pubkey_hex: str, sk_hex: str) -> bool:
    """密钥核对：解封私钥派生公钥须与账户登记公钥一致（前端解封后亦自校，
    此处供服务端测试面复用同一语义）。"""
    try:
        return pubkey_from_priv(sk_hex).lower() == pubkey_hex.lower()
    except Exception:  # noqa: BLE001  非法私钥=核对失败
        return False
