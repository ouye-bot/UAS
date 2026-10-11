"""读面按域（2026-10-12 辖区分账 P0——复审 A⑥ 枚举清单落地）。

枚举清单（机构台读面五面，org-a 平台管理员一律到底——监管全景归审计台）：
①GET /admin/collab-requests（目标归属域读时派生）②GET /admin/disposal-todos
（实名归属域）③GET /admin/overview（warrants/collab_ledger/accounts/reset_log
四表）④GET /ra/restore/requests（admin 面；auditor=治理份额域豁免——复核须
跨域可见）⑤GET /ra/collab/pending（目标授权归属域）。

显式豁免矩阵（不进本测试面，/audit/*、公示面、自域面、引擎面按设计全局）。
未定域（目标无归属域可派生）恒保留——「全域待批」徽标语义（跨域写面守卫
兜底，test_collab_org_guard 钉面）。
"""

from __future__ import annotations

import datetime as dt
import secrets

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.telemetry.models  # noqa: F401
from app.accounts.models import Account
from app.audit.models import DisposalRequest
from app.crypto.sm3 import sm3_bytes
from app.db import get_session
from app.main import create_app
from app.ra.models import Base
from tests.accounting import register_and_login, sign_canonical
from tests.test_collab_org_guard import _seed_org_auth, _seed_warrant

PW = "Read-Filter-Pass-1"


@pytest.fixture()
def rf(tmp_path, monkeypatch):
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "fake")
    eng = create_engine(f"sqlite:///{tmp_path}/read_filter.db")
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

    monkeypatch.setattr(
        __import__("app.db", fromlist=["SessionLocal"]), "SessionLocal", TestSession
    )
    app = create_app()
    app.dependency_overrides[get_session] = _sess
    with TestClient(app) as c:
        c.aud_sk = register_and_login(c, "auditor_rf", "auditor", PW)
        c.a_client = TestClient(app)
        c.a_sk = register_and_login(c.a_client, "admin_rf_a", "admin", PW)
        c.b_client = TestClient(app)
        c.b_sk = register_and_login(c.b_client, "admin_rf_b", "admin", PW)
        gen = c.app.dependency_overrides[get_session]()
        s = next(gen)
        try:
            s.query(Account).filter_by(username="admin_rf_b").one().org_id = "org-b"
            s.commit()
        finally:
            gen.close()
        yield c, TestSession
        import time as _t

        from app.accounts import collab as _cs

        deadline = _t.time() + 15
        while _t.time() < deadline and _cs._executing:
            _t.sleep(0.1)


def _db(rf):
    c, _TestSession = rf
    gen = c.app.dependency_overrides[get_session]()
    return gen, next(gen)


def _file(c, wh: str, note: str) -> dict:
    r = c.post(
        "/audit/collab-requests",
        json={
            "warrant_hash_hex": wh,
            "note": note,
            "sig_hex": sign_canonical(c.aud_sk, f"FZ-COLLAB-REQ|v1|{wh}|{note}"),
        },
    )
    assert r.status_code == 200, r.text
    return r.json()["data"]


def test_collab_requests_filtered_by_org(rf):
    """面①：org-b 管理员不见 org-a 待批（跨域行隐藏）；未定域（匿名令状）
    恒保留=全域待批。"""
    c, _TestSession = rf
    gen, s = _db(rf)
    try:
        auth_a, _ = _seed_org_auth(s, username="pilot_rf_a", org="org-a", auth_id=82001)
        auth_b, _ = _seed_org_auth(s, username="pilot_rf_b", org="org-b", auth_id=82002)
        wh_a = _seed_warrant(s, case_no="RF-A", target_auth_id=auth_a)
        wh_b = _seed_warrant(s, case_no="RF-B", target_auth_id=auth_b)
        wh_anon = _seed_warrant(s, case_no="RF-ANON", target_auth_id=None)
    finally:
        gen.close()
    _file(c, wh_a, "org-a 案")
    _file(c, wh_b, "org-b 案")
    _file(c, wh_anon, "匿名案")
    got_b = {x["case_no"] for x in c.b_client.get("/admin/collab-requests").json()["data"]["items"]}
    assert "RF-A" not in got_b, got_b
    assert "RF-B" in got_b and "RF-ANON" in got_b
    got_a = {x["case_no"] for x in c.a_client.get("/admin/collab-requests").json()["data"]["items"]}
    assert "RF-B" not in got_a, got_a
    assert "RF-A" in got_a and "RF-ANON" in got_a
    # 行携带派生域（前端徽标数据源）
    rows_a = c.a_client.get("/admin/collab-requests").json()["data"]["items"]
    org_of = {x["case_no"]: x["org_id"] for x in rows_a}
    assert org_of["RF-A"] == "org-a" and org_of["RF-ANON"] is None


def test_disposal_todos_filtered_by_org(rf):
    """面②：处置待办按实名归属域过滤；未定域（实名缺位）保留。"""
    c, _TestSession = rf
    gen, s = _db(rf)
    try:
        from app.ra.models import User

        s.add(User(username="pilot_rf_a", pub_key_hex=secrets.token_hex(64), org_id="org-a"))
        s.add(
            DisposalRequest(
                req_hash_hex=sm3_bytes(b"rf-a").hex(),
                case_no="RF-DISP-A",
                username="pilot_rf_a",
                created_ts=dt.datetime.utcnow(),
                status="pending",
            )
        )
        s.add(
            DisposalRequest(
                req_hash_hex=sm3_bytes(b"rf-anon").hex(),
                case_no="RF-DISP-ANON",
                username="",
                created_ts=dt.datetime.utcnow(),
                status="pending",
            )
        )
        s.commit()
    finally:
        gen.close()
    got_b = [x["case_no"] for x in c.b_client.get("/admin/disposal-todos").json()["data"]["items"]]
    assert "RF-DISP-A" not in got_b and "RF-DISP-ANON" in got_b, got_b
    got_a = [x["case_no"] for x in c.a_client.get("/admin/disposal-todos").json()["data"]["items"]]
    assert "RF-DISP-A" in got_a and "RF-DISP-ANON" in got_a


def test_overview_accounts_filtered_by_org(rf):
    """面③：/admin/overview accounts 表按账户 org 过滤（org-b 账户对 org-a
    管理员不可见）；行携带 org_id。"""
    c, _TestSession = rf
    got_a = {x["username"] for x in c.a_client.get("/admin/overview").json()["data"]["accounts"]}
    assert "admin_rf_b" not in got_a, got_a
    assert "admin_rf_a" in got_a
    got_b = {x["username"] for x in c.b_client.get("/admin/overview").json()["data"]["accounts"]}
    assert "admin_rf_b" in got_b and "admin_rf_a" not in got_b


def test_restore_requests_admin_filtered_auditor_exempt(rf):
    """面④：admin 面按句柄归属域过滤；auditor（治理份额域/复核职能）豁免
    ——复核须跨域可见待复核集。"""
    c, TestSession = rf
    gen, s = _db(rf)
    try:
        from app.ra.models import Credential, RestoreRequest

        for org, tag in (("org-a", "ra"), ("org-b", "rb")):
            from app.ra.models import User

            u = User(username=f"pilot_rf_{tag}", pub_key_hex=secrets.token_hex(64), org_id=org)
            s.add(u)
            s.flush()
            s.add(
                Credential(
                    user_id=u.id,
                    commitment_hex=secrets.token_hex(32),
                    master_cred_hash_hex=sm3_bytes(f"handle-{tag}".encode()).hex(),
                    sn_hash_hex="00" * 16,
                    serial_hex=secrets.token_hex(8),
                    id_cipher=b"",
                    cert_level=3,
                    expires_at=dt.datetime.utcfromtimestamp(1900000000),
                    owner_org_id=org,
                )
            )
            s.add(
                RestoreRequest(
                    handle_hex=sm3_bytes(f"handle-{tag}".encode()).hex(),
                    reason="误吊销经复核无异常",
                    requested_by="admin_rf_a",
                    admin_sig_hex="00" * 64,
                    status="pending",
                    created_ts=dt.datetime.utcnow(),
                )
            )
        s.commit()
    finally:
        gen.close()
    got_a = {
        x["handle_hex"][:8] for x in c.a_client.get("/ra/restore/requests").json()["data"]["items"]
    }

    ha = sm3_bytes(b"handle-ra").hex()[:8]
    hb = sm3_bytes(b"handle-rb").hex()[:8]
    assert ha in got_a and hb not in got_a, got_a
    got_b = {
        x["handle_hex"][:8] for x in c.b_client.get("/ra/restore/requests").json()["data"]["items"]
    }
    assert hb in got_b and ha not in got_b
    # auditor 豁免：双域行全可见（复核前置）
    got_aud = {x["handle_hex"][:8] for x in c.get("/ra/restore/requests").json()["data"]["items"]}
    assert {ha, hb} <= got_aud


def test_collab_pending_filtered_by_org(rf):
    """面⑤：待协作令状（手工出函工作面）按目标授权归属域过滤+行携带域。"""
    c, _TestSession = rf
    gen, s = _db(rf)
    try:
        auth_a, _ = _seed_org_auth(s, username="pilot_rf_a", org="org-a", auth_id=82003)
        auth_b, _ = _seed_org_auth(s, username="pilot_rf_b", org="org-b", auth_id=82004)
        _seed_warrant(s, case_no="RF-PEND-A", target_auth_id=auth_a)
        _seed_warrant(s, case_no="RF-PEND-B", target_auth_id=auth_b)
        _seed_warrant(s, case_no="RF-PEND-ANON", target_auth_id=None)
    finally:
        gen.close()
    got_a = {x["case_no"]: x["org_id"] for x in c.a_client.get("/ra/collab/pending").json()["data"]}
    assert "RF-PEND-B" not in got_a, got_a
    assert got_a.get("RF-PEND-A") == "org-a" and got_a.get("RF-PEND-ANON") is None
    got_b = {x["case_no"] for x in c.b_client.get("/ra/collab/pending").json()["data"]}
    assert "RF-PEND-A" not in got_b and "RF-PEND-B" in got_b and "RF-PEND-ANON" in got_b
