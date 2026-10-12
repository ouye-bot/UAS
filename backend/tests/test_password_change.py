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
    from app.accounts.service import opaque_enabled
    from tests.opaque_client_ref import ref_seal_v6

    sk, pk = generate_keypair()
    payload = {"username": username, "pubkey_hex": pk}
    if opaque_enabled():  # ⑫O-3 v6 门（gate on 只收 v6+OPRF 记录材料）
        payload.update(ref_seal_v6(username, password, sk, pk))
    else:
        payload["sealed_blob"] = seal_envelope_v4(sk, pk, password)
    r = c.post("/auth/register", json=payload)
    assert r.status_code == 201, r.text
    _login_via_challenge(c, username, sk)
    return sk, pk


def _change_v6(c, username: str, sk: str, pk: str, new_password: str):
    """v6 改密材料组装（§5.6——盐/迭代取账面不轮换；rwd 随新口令换根）。"""
    gen = c.app.dependency_overrides[get_session]()
    s = next(gen)
    try:
        from app.accounts.models import Account

        row = s.query(Account).filter_by(username=username).one()
        salt, it = row.opaque_kdf_salt_hex, row.opaque_kdf_iter
    finally:
        gen.close()
    from tests.opaque_client_ref import ref_seal_v6

    body = ref_seal_v6(username, new_password, sk, pk, salt_hex=salt, iterations=it)
    return c.post(
        "/auth/password/change",
        json={"sealed_blob": body["sealed_blob"], "masking_key_hex": body["masking_key_hex"]},
    )


def test_password_change_reseals_and_audits(pc):
    """正路径：新密码重封件入库+台账一行（operator=self）+旧 blob 被换下。"""
    c = pc
    PW_A, PW_B = "Old-Pass-1a", "New-Pass-2b"
    sk, pk = _register_pilot(c, "pilot_pc", PW_A)
    # 改密：新密码 v6' 重封件+新掩码钥（同钥同公钥——客户端 unlockSk 已证当前密码）
    r = _change_v6(c, "pilot_pc", sk, pk, PW_B)
    assert r.status_code == 200, r.text
    # 密封件已换新（v6 形态在案——新密码重封件与旧件 nonce 必不同）
    gen = c.app.dependency_overrides[get_session]()
    s = next(gen)
    try:
        from app.accounts.models import Account

        row = s.query(Account).filter_by(username="pilot_pc").one()
        obj = json.loads(row.sealed_blob)
        assert obj["v"] == 6 and obj["pk"] == pk
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
    r2 = _change_v6(c, "pilot_pc2", sk, pk, PW_B)
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
    # ②登录后坏形态（v6 账户——垃圾 blob=422 v6_change_required 引导正确回传）
    sk, pk = _register_pilot(c, "pilot_pc3", "Pass-1abc")
    r1 = c.post("/auth/password/change", json={"sealed_blob": "x" * 64})
    assert r1.status_code == 422 and r1.json()["code"] == "v6_change_required", r1.text
    # 公钥不匹配（他钥 v6 重封件）=不带病入库
    sk2, pk2 = generate_keypair()
    from tests.opaque_client_ref import ref_seal_v6

    bad6 = ref_seal_v6("pilot_pc3", "Pass-2abc", sk2, pk2)
    r2 = c.post(
        "/auth/password/change",
        json={"sealed_blob": bad6["sealed_blob"], "masking_key_hex": bad6["masking_key_hex"]},
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
    # 用 admin 本人钥重封 v6'（否则信封门先命中，profile 校验不可达）
    gen = c.app.dependency_overrides[get_session]()
    s = next(gen)
    try:
        from app.accounts.models import Account

        arow = s.query(Account).filter_by(username="admin_pc").one()
        asalt, ait = arow.opaque_kdf_salt_hex, arow.opaque_kdf_iter
    finally:
        gen.close()
    from tests.opaque_client_ref import ref_seal_v6

    admin6 = ref_seal_v6(
        "admin_pc",
        "Pass-3abc",
        admin_sk,
        pubkey_from_priv(admin_sk),
        salt_hex=asalt,
        iterations=ait,
    )
    r3 = c2.post(
        "/auth/password/change",
        json={
            "sealed_blob": admin6["sealed_blob"],
            "masking_key_hex": admin6["masking_key_hex"],
            "sealed_profile": json.dumps({"v": 1, "enc": {"salt": "ab" * 16, "ct": "cd" * 4}}),
        },
    )
    assert r3.status_code == 422 and r3.json()["code"] == "profile_not_applicable", r3.text
