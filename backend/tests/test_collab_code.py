"""阶段三 随案协作函测试：RA 出具→审计台解封（双控语义不变，工程值装进信封）。

- 密封/解封 roundtrip：cred hash 进、cred hash 出
- 篡改/伪造=拒绝（GCM 认证）
- 解锁接口支持 collab_code 替代裸 master_cred_hash_hex（脚本兼容保留）
- 依据文本自动哈希（legal_basis_text——用户不再手算哈希）
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.audit.router as audit_router_mod
import app.ra.router as ra_router_mod
from app.crypto.sm3 import sm3_bytes
from app.db import get_session
from app.main import create_app
from app.ra.models import Base
from tests.accounting import register_and_login

_AUD = "auditor_c"


@pytest.fixture()
def app_client(tmp_path, monkeypatch):
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "fake")
    eng = create_engine(f"sqlite:///{tmp_path}/collab_test.db")
    Base.metadata.create_all(eng)
    TestSession = sessionmaker(bind=eng, expire_on_commit=False)

    import app.audit.router as audit_router_mod

    audit_router_mod._reset_deps_cache()

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
        register_and_login(c, _AUD, "auditor", "Audit-Pass-1")
        yield c, TestSession


def test_collab_seal_open_roundtrip():
    """协作函 roundtrip：cred hash 进、cred hash 出；篡改=拒。"""
    from app.ra.collab import CollabError, open_collab, seal_collab

    cred = sm3_bytes(b"cred").hex()
    code = seal_collab(cred)
    assert open_collab(code) == cred
    bad = code[:-4] + "0000"
    with pytest.raises(CollabError):
        open_collab(bad)


def test_unlock_via_collab_code(app_client, monkeypatch):
    """解锁接口吃 collab_code（审计员不再手输 64 位哈希）。
    账户批：立案=审计员会话；出函=机构管理员会话（双控两席分立）。"""
    c, TestSession = app_client
    c_admin = TestClient(c.app)
    register_and_login(c_admin, "admin_c", "admin", "Admin-Pass-1")
    # 登记一个真实身份（拿 master_cred_hash）
    from app.crypto.sm2 import generate_keypair

    pk = generate_keypair()[1]
    r = c.post(
        "/ra/register",
        json={
            "username": "collab-u",
            "id_number": "110101199001011234",
            "cert_level": 3,
            "sn": "FZ-CL-01",
            "user_pub_hex": pk,
            "class_id": 1,
        },
    )
    assert r.status_code == 200
    mch = r.json()["data"]["master_cred_hash_hex"]
    # 令状（先立案——FZC2 出具必须绑定令状，2026-09-28 F 席根修）
    r3 = c.post(
        "/audit/warrants",
        json={
            "case_no": "CL-001",
            "legal_basis_hash_hex": sm3_bytes(b"law").hex(),
            "target_auth_id": None,
        },
    )
    assert r3.status_code == 200
    wh = r3.json()["data"]["warrant_hash_hex"]
    # RA 出具协作函（机构管理员会话门禁；FZC2：函-令状-凭证三方绑定）
    r2 = c_admin.post(
        "/ra/collab-code",
        json={"warrant_hash_hex": wh, "master_cred_hash_hex": mch},  # 匿名立案位：RA 显式供凭证
    )
    assert r2.status_code == 200, r2.text
    code = r2.json()["data"]["code"]
    # 解锁的 RA 会话定向到测试库（audit/_ra_unlock 默认走 SessionLocal 真库）
    monkeypatch.setattr(audit_router_mod, "_session_for_unlock", lambda: TestSession())
    # RA 假锚种子：令状在案（模拟 RA 链上公示——双控第二关的 RA 侧）

    ra_router_mod._ra_deps().anchor.warrant_on_chain = lambda wh_bytes: wh_bytes.hex() == wh
    r4 = c.post(
        f"/audit/warrants/{wh}/unlock",
        json={"collab_code": code},
    )
    assert r4.status_code == 200, f"collab_code 解锁失败: {r4.text}"
    assert r4.json()["data"]["unlocked"]["username"] == "collab-u"


def test_collab_bad_code_rejected(app_client):
    """坏协作函=拒绝（非 500——结构化错误）。"""
    c, _TS = app_client
    r = c.post(
        "/audit/warrants",
        json={
            "case_no": "CL-002",
            "legal_basis_hash_hex": sm3_bytes(b"law2").hex(),
            "target_auth_id": None,
        },
    )
    wh = r.json()["data"]["warrant_hash_hex"]
    r2 = c.post(
        f"/audit/warrants/{wh}/unlock",
        json={"collab_code": "deadbeef"},
    )
    assert r2.status_code in (400, 403), r2.text


def test_legal_basis_text_auto_hash(app_client):
    """依据摘要文本 → 服务端自动 SM3（用户不算哈希）。"""
    c, _TS = app_client
    r = c.post(
        "/audit/warrants",
        json={
            "case_no": "CL-003",
            "legal_basis_text": "依据《无人驾驶航空器条例》第 X 条",
            "target_auth_id": None,
        },
    )
    assert r.status_code == 200, r.text
    d = r.json()["data"]
    assert (
        d["legal_basis_hash_hex"] == sm3_bytes("依据《无人驾驶航空器条例》第 X 条".encode()).hex()
    )
