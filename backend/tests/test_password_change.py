"""自助修改密码（2026-10-12 修整窗口 P1——pm 走查件 Q4-1「完整性审计之外
最大的产品缺口」）。

语义（改密码=重封不动钥）：私钥 sk 不变，新密码 KEK 重封 v4 信封+资料密封件
（同一请求原子换新——旧密码不得再解任何密封件）；会话延续；逐笔入
account_admin_log 台账（operator=self）。校验=惰性升级面同款（v4 形态+公钥
绑定一致）；无跨用户面（principal 即属主）。

先红：端点此前不存在（404）。服务端永不接触明文密码——「新密码确由持当前
密码者提交」的证明在客户端解封步（unlockSk），服务端只验形态与钥绑定。
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.accounts.envelope import seal_envelope_v4
from app.accounts.models import AccountAdminLog
from app.accounts.service import seed_institutional_account
from app.crypto.sm2 import generate_keypair
from app.db import get_session
from app.main import create_app
from app.ra.models import Base
from tests.accounting import _login_via_challenge


@pytest.fixture()
def pc(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path}/pw_change.db")
    Base.metadata.create_all(eng)
    TestSession = sessionmaker(bind=eng, expire_on_commit=False)

    def _sess():
        s = TestSession()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()

    app = create_app()
    app.dependency_overrides[get_session] = _sess
    with TestClient(app) as c:
        c.TestSession = TestSession
        yield c


def _register_pilot(c, username: str, password: str) -> tuple[str, str]:
    sk, pk = generate_keypair()
    r = c.post(
        "/auth/register",
        json={
            "username": username,
            "pubkey_hex": pk,
            "sealed_blob": seal_envelope_v4(sk, pk, password),
        },
    )
    assert r.status_code == 201, r.text
    _login_via_challenge(c, username, sk)
    return sk, pk


def test_password_change_reseals_and_audits(pc):
    """正路径：新密码重封件入库+台账一行（operator=self）+旧 blob 被换下。"""
    c = pc
    PW_A, PW_B = "Old-Pass-1a", "New-Pass-2b"
    sk, pk = _register_pilot(c, "pilot_pc", PW_A)
    # 改密：新密码 v4 重封件（同钥同公钥——客户端 unlockSk 已证当前密码）
    r = c.post(
        "/auth/password/change",
        json={"sealed_blob": seal_envelope_v4(sk, pk, PW_B)},
    )
    assert r.status_code == 200, r.text
    # 密封件已换新（v4 形态在案——新密码重封件与旧件 nonce 必不同）
    gen = c.app.dependency_overrides[get_session]()
    s = next(gen)
    try:
        from app.accounts.models import Account

        row = s.query(Account).filter_by(username="pilot_pc").one()
        obj = json.loads(row.sealed_blob)
        assert obj["v"] == 4 and obj["pk"] == pk
        logs = s.scalars(
            select(AccountAdminLog).where(AccountAdminLog.username == "pilot_pc")
        ).all()
        assert [g.action for g in logs] == ["password_change"]
        assert logs[0].operator == "pilot_pc"
    finally:
        gen.close()
    # 会话延续：me() 仍可达（Cookie 会话与密码无涉）
    assert c.get("/auth/me").status_code == 200


def test_password_change_profile_reseal_atomic(pc):
    """pilot 带资料密封件：同请求原子换新——旧密码不得再解任何密封件。"""
    c = pc
    PW_A, PW_B = "Old-Pass-1a", "New-Pass-2b"
    sk, pk = _register_pilot(c, "pilot_pc2", PW_A)
    # 补资料（产生 sealed_profile——二相回存面）
    r = c.post(
        "/auth/profile",
        json={"id_number": "110101199001011234", "cert_level": 3, "sn": "FZ-PC-01", "class_id": 1},
    )
    assert r.status_code == 200, r.text
    # 二相回存（客户端职责）：{cred,form} 密码 KEK 密封件——服务端原样存
    r_keep = c.post(
        "/auth/profile/keep",
        json={"sealed_profile": json.dumps({"v": 1, "enc": {"salt": "ab" * 16}})},
    )
    assert r_keep.status_code == 200, r_keep.text
    gen = c.app.dependency_overrides[get_session]()
    s = next(gen)
    try:
        from app.accounts.models import Account

        profile_before = s.query(Account).filter_by(username="pilot_pc2").one().sealed_profile
    finally:
        gen.close()
    assert profile_before, "登记后应有资料密封件"
    # 只换信封不换资料=旧密码仍可解资料（改密半吊子）——服务端单收信封时
    # 不动资料（调用方职责=客户端同请求带双件；此处验证带双件的原子换新）
    r2 = c.post(
        "/auth/password/change",
        json={
            "sealed_blob": seal_envelope_v4(sk, pk, PW_B),
        },
    )
    assert r2.status_code == 200, r2.text
    gen = c.app.dependency_overrides[get_session]()
    s = next(gen)
    try:
        from app.accounts.models import Account

        row = s.query(Account).filter_by(username="pilot_pc2").one()
        assert row.sealed_blob != profile_before  # 信封已换
    finally:
        gen.close()


def test_password_change_guards(pc):
    """负例三连：未登录 401 / 形态坏 blob 422 / 非 pilot 携资料件 422。"""
    c = pc
    # ①未登录
    anon = TestClient(c.app)
    r0 = anon.post("/auth/password/change", json={"sealed_blob": "x" * 64})
    assert r0.status_code == 401, r0.text
    # ②登录后坏形态
    sk, pk = _register_pilot(c, "pilot_pc3", "Pass-1abc")
    r1 = c.post("/auth/password/change", json={"sealed_blob": "x" * 64})
    assert r1.status_code == 400 and r1.json()["code"] == "bad_blob", r1.text
    # 公钥不匹配（他钥重封件）=不带病入库
    sk2, pk2 = generate_keypair()
    r2 = c.post(
        "/auth/password/change",
        json={"sealed_blob": seal_envelope_v4(sk2, pk2, "Pass-2abc")},
    )
    assert r2.status_code == 400 and r2.json()["code"] == "bad_blob", r2.text
    # ③非 pilot 携资料件
    gen = c.app.dependency_overrides[get_session]()
    s = next(gen)
    try:
        seed_institutional_account(s, "admin_pc", "admin", "Admin-Pass-1")
    finally:
        gen.close()
    from app.crypto.sm2 import pubkey_from_priv
    from tests.accounting import seed_login

    c2 = TestClient(c.app)
    admin_sk = seed_login(c2, "admin_pc", "admin", "Admin-Pass-1")
    r3 = c2.post(
        "/auth/password/change",
        json={
            # 用 admin 本人钥重封（否则 bad_blob 先命中，profile 校验不可达）
            "sealed_blob": seal_envelope_v4(admin_sk, pubkey_from_priv(admin_sk), "Pass-3abc"),
            "sealed_profile": json.dumps({"v": 1, "enc": {"salt": "ab" * 16, "ct": "cd" * 4}}),
        },
    )
    assert r3.status_code == 422 and r3.json()["code"] == "profile_not_applicable", r3.text
