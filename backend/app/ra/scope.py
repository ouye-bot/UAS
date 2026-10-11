"""协作函范围校验（2026-09-28 F 席根修配套）：授权编号 ↔ 凭证 的一致性。

链路：AuthRecord(auth_id) → Application(sub_cred_hash) → SubCredential(
credential_id) → Credential(master_cred_hash)。凭证与授权编号对不上=
协作函超范围（scope_mismatch）。数据链不可验证（任一环缺失，如历史/
演示数据）时返回「不可验证」而非误判——调用方决定是否放行。

辖区分账域原语（2026-10-12 P0 安全补丁）：org_guard（0.1 工艺范式单源化
——目标归属域==操作者域，跨域 403 org_forbidden 双域判词）+ 归属域读时
派生三件（凭证域/授权域/用户名域——CollabRequest/DisposalRequest/Warrant
均无 org 列，append-only 台账不动 schema，读时沿授权链/实名链派生）。
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session


class OrgForbidden(Exception):
    """跨域操作拒绝（org_forbidden）：目标归属域 != 操作者域，403 fail-closed。

    各面自行映射为本地错误类型（RaError/CollabError/DisposalError/JSONResponse）
    ——code/status/判词三件在本类单源，双域信息随实例携带便于审计。"""

    def __init__(self, target_org: str | None, operator_org: str | None, object_noun: str) -> None:
        self.code = "org_forbidden"
        self.status = 403
        self.target_org = target_org
        self.operator_org = operator_org
        super().__init__(
            f"跨域操作拒绝：目标{object_noun}归属机构域={target_org}，"
            f"您的账户属={operator_org}——机构账户仅可操作本机构域{object_noun}"
            "（判词双域便于审计）"
        )


def org_guard(target_org: str | None, operator_org_id: str | None, object_noun: str) -> None:
    """org 域归属校验（0.1 工艺单源）：「有域可比而不同」才拒。

    - target_org=None：目标无归属域可派生（匿名立案位令状/实名缺位）——域门
      跳过（全域待批「未定域」语义，执行面既有兜底仍生效）；
    - operator_org_id=None：无操作者域上下文（服务层直调测试形态/匿名原像
      路径——B2-d4 既有设计）——按现行行为放行（test_ra_org_isolation 决策
      ②同款，非判空放松：HTTP 授权边界自会话主体恒传非 None）。
    """
    if target_org is None or operator_org_id is None or operator_org_id == target_org:
        return
    raise OrgForbidden(target_org, operator_org_id, object_noun)


def cred_org_of(session: Session, cred_hash_hex: str | None) -> str | None:
    """凭证归属域（读时派生）：owner_org_id 列单一权威（3.1）→ 列缺失回落
    users.org_id（0025 既有事实）→ 两不可得=None（未定域）。"""
    if not cred_hash_hex:
        return None
    from app.ra.models import Credential, User

    cred = session.execute(
        select(Credential).where(Credential.master_cred_hash_hex == cred_hash_hex.lower())
    ).scalar_one_or_none()
    if cred is None:
        return None
    if getattr(cred, "owner_org_id", None):
        return cred.owner_org_id
    u = session.get(User, cred.user_id) if cred.user_id is not None else None
    return u.org_id if u is not None and u.org_id else None


def auth_org_of(session: Session, auth_id: int | None) -> str | None:
    """授权编号归属域（读时派生）：auth_id → 授权链解析凭证 → 凭证域。"""
    if auth_id is None:
        return None
    return cred_org_of(session, resolve_cred_for_auth(session, int(auth_id)))


def username_org_of(session: Session, username: str | None) -> str | None:
    """用户名归属域（读时派生）：登记用户（ra User——实名/凭证域权威）→
    门户账户（accounts.Account——org-b 机构管理员等）→ 两不可得=None。"""
    if not username:
        return None
    from app.accounts.models import Account
    from app.ra.models import User

    u = session.execute(select(User).where(User.username == username)).scalar_one_or_none()
    if u is not None and u.org_id:
        return u.org_id
    acc = session.execute(select(Account).where(Account.username == username)).scalar_one_or_none()
    return acc.org_id if acc is not None and acc.org_id else None


def resolve_cred_for_auth(session: Session, auth_id: int) -> str | None:
    """auth_id → master_cred_hash_hex；任一环缺失返回 None（不可验证）。"""
    from app.authz.models import Application, AuthRecord
    from app.ra.models import Credential, SubCredential

    rec = session.execute(
        select(AuthRecord).where(AuthRecord.auth_id == auth_id)
    ).scalar_one_or_none()
    if rec is None:
        return None
    app_row = session.get(Application, rec.application_id)
    if app_row is None:
        return None
    sub = (
        session.execute(
            select(SubCredential).where(
                SubCredential.sub_cred_hash_hex == app_row.sub_cred_hash_hex
            )
        )
        .scalars()
        .first()
    )
    if sub is None:
        return None
    cred = session.get(Credential, sub.credential_id)
    if cred is None:
        return None
    return str(cred.master_cred_hash_hex).lower()


def scope_mismatch(session: Session, auth_id: int | None, cred_hash_hex: str) -> bool | None:
    """True=可验证且不匹配（超范围）；False=匹配；None=数据链不可验证。"""
    if auth_id is None:
        return None
    expected = resolve_cred_for_auth(session, int(auth_id))
    if expected is None:
        return None
    return expected != str(cred_hash_hex).lower()
