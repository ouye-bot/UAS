"""协作函范围校验（2026-09-28 F 席根修配套）：授权编号 ↔ 凭证 的一致性。

链路：AuthRecord(auth_id) → Application(sub_cred_hash) → SubCredential(
credential_id) → Credential(master_cred_hash)。凭证与授权编号对不上=
协作函超范围（scope_mismatch）。数据链不可验证（任一环缺失，如历史/
演示数据）时返回「不可验证」而非误判——调用方决定是否放行。
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session


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
