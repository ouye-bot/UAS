"""P2 两件查询面（2026-10-12 修整窗口——回执级联常设化+设备飞行记录）。

①GET /ra/revocation/linkage（主凭证级联视图）：从 append-only 撤销台账反查
句柄的联动撤销授权（吊销回执是一次性的——公示撤销清单任一叶事后可查其联动
授权）；读面按域（跨域句柄枚举=信息泄露面）。
②GET /ra/fleet/device/flights（设备飞行记录）：设备子凭证→申请→授权记录
纯 DB join（零链读，匿名红线不破——Application 零身份列）；读面按域。
"""

from __future__ import annotations

import datetime as dt
import json
import secrets

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.ra.router as ra_router_mod
import app.telemetry.models  # noqa: F401
from app.authz.models import Application, AuthRecord
from app.crypto.sm3 import sm3_bytes
from app.db import get_session
from app.kms import ra_signing_keypair
from app.main import create_app
from app.ra.models import (
    Base,
    Credential,
    RevocationLedger,
    SubCredential,
    User,
)
from app.ra.service import ChainAnchor, RaDeps, RaService
from tests.accounting import register_and_login

PW = "P2-Query-Pass-1"


@pytest.fixture()
def q(tmp_path, monkeypatch):
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "fake")
    eng = create_engine(f"sqlite:///{tmp_path}/p2q.db")
    Base.metadata.create_all(eng)
    import app.authz.models as _am

    _am.Base.metadata.create_all(eng)
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

    priv, pub = ra_signing_keypair()

    def make_ra(session):
        anchor = ChainAnchor(call=lambda fn, args: None, warrant_on_chain=lambda wh: True)
        return RaService(session, RaDeps(ra_priv_hex=priv, ra_pub_hex=pub, anchor=anchor))

    monkeypatch.setattr(ra_router_mod, "_svc", make_ra)
    ra_router_mod._reset_deps_cache()
    app = create_app()
    app.dependency_overrides[get_session] = _sess
    with TestClient(app) as c:
        c.a_sk = register_and_login(c, "admin_q_a", "admin", PW)
        c.b_client = TestClient(app)
        c.b_sk = register_and_login(c.b_client, "admin_q_b", "admin", PW)
        gen = c.app.dependency_overrides[get_session]()
        s = next(gen)
        try:
            from app.accounts.models import Account

            s.query(Account).filter_by(username="admin_q_b").one().org_id = "org-b"
            s.commit()
        finally:
            gen.close()
        yield c


def _db(q):
    gen = q.app.dependency_overrides[get_session]()
    return gen, next(gen)


def _seed_device_with_flight(session, *, org: str, handle: str, auth_id: int):
    """播种设备（kind=2 形态）+一张子凭证+一次授权记录（纯 DB join 面）。"""
    u = User(username="dev-" + secrets.token_hex(3), pub_key_hex=secrets.token_hex(64), org_id=org)
    session.add(u)
    session.flush()
    cred = Credential(
        user_id=None,
        commitment_hex=secrets.token_hex(32),
        master_cred_hash_hex=handle,
        sn_hash_hex="00" * 16,
        serial_hex=secrets.token_hex(8),
        id_cipher=b"",
        cert_level=3,
        expires_at=dt.datetime.utcfromtimestamp(1900000000),
        owner_org_id=org,
        cred_kind=2,
        device_no="FZ-P2Q-E2E-0000D1",
    )
    session.add(cred)
    session.flush()
    sub_hex = sm3_bytes(f"sub-{auth_id}".encode()).hex()
    session.add(
        SubCredential(
            credential_id=cred.id,
            sub_cred_hash_hex=sub_hex,
            message_hex=f"sub-{auth_id}".encode().hex(),
            sig_hex="00" * 64,
            holder_pub_hex="11" * 64,
            expires_at=dt.datetime.utcfromtimestamp(1900000000),
        )
    )
    session.commit()
    app_row = Application(
        session_pk_hex="11" * 64,
        sub_sig_hex="00" * 64,
        sub_cred_hash_hex=sub_hex,
        nonce_hex=secrets.token_hex(16),
        plan_hash_hex=secrets.token_hex(32),
        class_id=1,
        policy_version="test",
        rev_root_hex="00" * 32,
        status="approved",
    )
    session.add(app_row)
    session.flush()
    app_row.auth_id = auth_id
    session.add(
        AuthRecord(
            auth_id=auth_id,
            application_id=app_row.id,
            token_hash_hex=secrets.token_hex(32),
            proof_digest_hex=secrets.token_hex(32),
        )
    )
    session.commit()


def test_revocation_linkage_cross_domain_and_content(q):
    """①级联视图：台账反查 linked_auth_ids+skip 明细；跨域 403（域门先于
    内容回显——跨域句柄枚举=信息泄露面）。"""
    q_a = q
    handle = sm3_bytes(b"p2-handle-a").hex()
    gen, s = _db(q_a)
    try:
        # 凭证行在案（owner_org_id=org-a）——句柄归属域派生面（未定域跳过语义
        # 由 test_collab_org_guard 钉面；此处测的是「有域可比而不同」的 403）
        from app.ra.models import Credential as _Cred

        s.add(
            _Cred(
                user_id=None,
                commitment_hex=secrets.token_hex(32),
                master_cred_hash_hex=handle,
                sn_hash_hex="00" * 16,
                serial_hex=secrets.token_hex(8),
                id_cipher=b"",
                cert_level=3,
                expires_at=dt.datetime.utcfromtimestamp(1900000000),
                owner_org_id="org-a",
            )
        )
        s.commit()
        s.add(
            RevocationLedger(
                action="revoke",
                actor="admin_q_a",
                subject_hex=handle,
                reason="围栏违规成立",
                sig_hex="00" * 64,
                epoch=6,
                detail=json.dumps({"handles": [handle], "linked_auth_ids": [9100, 9101]}),
            )
        )
        s.commit()
    finally:
        gen.close()
    r = q.get(f"/ra/revocation/linkage?handle_hex={handle}")
    assert r.status_code == 200, r.text
    data = r.json()["data"]
    assert data["linked_auth_ids"] == [9100, 9101]
    assert data["org_id"] is None or data["org_id"] == "org-a"
    assert data["ledger_rows"][0]["epoch"] == 6
    # 跨域：org-b 管理员查 org-a 句柄 → 403（先红：旧版无此端点/无域门）
    rb = q.b_client.get(f"/ra/revocation/linkage?handle_hex={handle}")
    assert rb.status_code == 403 and rb.json()["code"] == "org_forbidden", rb.text


def test_fleet_device_flights_join(q):
    """②设备飞行记录：子凭证→申请→授权记录 join 回显；跨域 403。"""
    handle = sm3_bytes(b"p2-device-b").hex()
    gen, s = _db(q)
    try:
        _seed_device_with_flight(s, org="org-a", handle=handle, auth_id=8801)
    finally:
        gen.close()
    r = q.get(f"/ra/fleet/device/flights?master_cred_hash_hex={handle}")
    assert r.status_code == 200, r.text
    data = r.json()["data"]
    assert data["device_no"] == "FZ-P2Q-E2E-0000D1"
    assert len(data["flights"]) == 1
    assert data["flights"][0]["auth_id"] == 8801
    assert data["flights"][0]["status"] == "approved"
    # 跨域拒绝
    rb = q.b_client.get(f"/ra/fleet/device/flights?master_cred_hash_hex={handle}")
    assert rb.status_code == 403 and rb.json()["code"] == "org_forbidden", rb.text
    # 不在案 404（本域管理员——域门后存在性如实）
    r404 = q.get(f"/ra/fleet/device/flights?master_cred_hash_hex={'ee' * 32}")
    assert r404.status_code == 404, r404.text
