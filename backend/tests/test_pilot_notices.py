"""⑧站触达闭环定向测试：飞手提醒面（吊销/违规/子凭证到期）。

纯数据面直测 pilot_notice_rows（端点=一行 _ok 透传+pilot 会话守卫——守卫
依赖 require_role 为 admin 面既有实弹路径）。三段语义钉定：
① revoked=本用户吊销凭证+台账最新理由/纪元（status=1 不入）；
② violations=本用户 authId 的围栏违规（event_type=1）——他用户事件与
   非围栏事件（type=2）不入；
③ expiring_subs=未消费∧提醒窗内（7 天）——已消费/超窗/已过期不入。
"""

from __future__ import annotations

import datetime as dt

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.ra.router import SUB_EXPIRY_WINDOW_DAYS, pilot_notice_rows

NOW = dt.datetime.utcnow()


@pytest.fixture()
def session():
    eng = create_engine("sqlite:///:memory:")
    # 提醒面跨三域模型（ra+authz+telemetry）——三个 metadata 全建
    from app.authz.models import Base as AuthzBase
    from app.ra.models import Base as RaBase
    from app.telemetry.models import Base as TelemetryBase

    RaBase.metadata.create_all(eng)
    AuthzBase.metadata.create_all(eng)
    TelemetryBase.metadata.create_all(eng)
    s = sessionmaker(bind=eng, expire_on_commit=False)()
    try:
        yield s
    finally:
        s.close()


def _user(s, username: str):
    from app.ra.models import User

    u = User(username=username, pub_key_hex="11" * 64, org_id="org-a")
    s.add(u)
    s.flush()
    return u


def _cred(s, user_id: int, handle: str, status: int = 1):
    from app.ra.models import Credential

    c = Credential(
        user_id=user_id,
        commitment_hex="c" + handle[:15],
        master_cred_hash_hex=handle,
        sn_hash_hex="00" * 16,
        serial_hex="SN-" + handle[:8],
        id_cipher=b"",
        cert_level=3,
        expires_at=NOW + dt.timedelta(days=365),
        status=status,
    )
    s.add(c)
    s.flush()
    return c


def _sub(s, cred_id: int, h: str, *, consumed=False, in_days=3):
    from app.ra.models import SubCredential

    row = SubCredential(
        credential_id=cred_id,
        sub_cred_hash_hex=h,
        message_hex="ab" * 165,
        sig_hex="cd" * 64,
        holder_pub_hex="22" * 64,
        expires_at=NOW + dt.timedelta(days=in_days),
        consumed=consumed,
    )
    s.add(row)
    s.flush()
    return row


def _app(s, sub_hash: str, auth_id: int):
    from app.authz.models import Application

    row = Application(
        session_pk_hex="33" * 64,
        sub_sig_hex="44" * 64,
        sub_cred_hash_hex=sub_hash,
        nonce_hex="55" * 16,
        plan_hash_hex="66" * 32,
        class_id=1,
        policy_version="v1",
        rev_root_hex="77" * 32,
        status="approved",
        auth_id=auth_id,
    )
    s.add(row)
    s.flush()
    return row


def _event(s, auth_id: int, event_type: int):
    from app.telemetry.models import ChainEvent

    row = ChainEvent(
        auth_id=auth_id,
        event_type=event_type,
        event_hash_hex="88" * 32,
        block=1,
        tx_hash="0x" + "99" * 40,
    )
    s.add(row)
    s.flush()
    return row


def _ledger(s, handle: str, reason: str, epoch: int):
    from app.ra.models import RevocationLedger

    row = RevocationLedger(
        action="revoke",
        actor="admin",
        subject_hex=handle,
        reason=reason,
        epoch=epoch,
    )
    s.add(row)
    s.flush()
    return row


def test_revoked_section(session):
    u = _user(session, "pilot-a")
    good = _cred(session, u.id, "aa" * 32, status=1)
    bad = _cred(session, u.id, "bb" * 32, status=2)
    _ledger(session, bad.master_cred_hash_hex, "围栏违规依判词吊销", 5)
    out = pilot_notice_rows(session, "pilot-a")
    assert [r["master_cred_hash_hex"] for r in out["revoked"]] == [bad.master_cred_hash_hex]
    assert out["revoked"][0]["reason"] == "围栏违规依判词吊销"
    assert out["revoked"][0]["epoch"] == 5
    assert good.master_cred_hash_hex not in [r["master_cred_hash_hex"] for r in out["revoked"]]


def test_violations_section(session):
    u = _user(session, "pilot-b")
    cred = _cred(session, u.id, "cc" * 32)
    sub = _sub(session, cred.id, "dd" * 32)
    _app(session, sub.sub_cred_hash_hex, auth_id=7)
    _event(session, 7, event_type=1)  # 本用户围栏违规 ✓
    _event(session, 7, event_type=2)  # 非围栏（地面站）✗
    _event(session, 999, event_type=1)  # 他用户 authId ✗
    out = pilot_notice_rows(session, "pilot-b")
    assert len(out["violations"]) == 1
    assert out["violations"][0]["auth_id"] == 7
    assert out["violations"][0]["sub_cred_hash_hex"] == sub.sub_cred_hash_hex


def test_expiring_window(session):
    u = _user(session, "pilot-c")
    cred = _cred(session, u.id, "ee" * 32)
    in_window = _sub(session, cred.id, "f1" * 32, in_days=3)  # 窗内未消费 ✓
    _sub(session, cred.id, "f2" * 32, in_days=3, consumed=True)  # 已消费 ✗
    _sub(session, cred.id, "f3" * 32, in_days=SUB_EXPIRY_WINDOW_DAYS + 5)  # 超窗 ✗
    _sub(session, cred.id, "f4" * 32, in_days=-1)  # 已过期 ✗
    edge = _sub(session, cred.id, "f5" * 32, in_days=SUB_EXPIRY_WINDOW_DAYS)  # 窗边界 ✓
    out = pilot_notice_rows(session, "pilot-c")
    got = {r["sub_cred_hash_hex"]: r for r in out["expiring_subs"]}
    assert set(got) == {in_window.sub_cred_hash_hex, edge.sub_cred_hash_hex}
    assert got[in_window.sub_cred_hash_hex]["days_left"] == 3
    assert got[edge.sub_cred_hash_hex]["days_left"] == SUB_EXPIRY_WINDOW_DAYS


def test_unknown_user_empty(session):
    _user(session, "someone-else")
    out = pilot_notice_rows(session, "ghost")
    assert out == {"revoked": [], "violations": [], "expiring_subs": []}


def test_no_creds_empty(session):
    _user(session, "pilot-nothing")
    out = pilot_notice_rows(session, "pilot-nothing")
    assert out == {"revoked": [], "violations": [], "expiring_subs": []}
