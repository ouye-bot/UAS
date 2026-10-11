"""门限仪式留痕（2026-10-12 辖区分账 P0 后端增补①——B3 仪式可视化）。

案甲（响应附带）：request_decrypt_share(with_meta) 逐域四关判定元数据 →
unwrap_any 聚合 ceremony（**上限 k 域如实**——凑足 k 即停，第三域不被征询）
→ warrant_unlock 响应附 ceremony 块 → 审计 unlock/结案浮层自然继承。
案乙（回放只读面）：GET /ra/threshold/ceremony 按令状哈希回放各域 append-only
审计（B3 审计报告原建议）——机构台/审计台轮询行渲染「逐域四关」。

诚实红线（复审洞 4）：「三域全列」即失真——成功路径只画**应召域**；失败路径
才全域留痕（denied 行）。fake 档四关全拒=常态而非事故（演示须真链档）。
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.audit.router as audit_router_mod
import app.ra.router as ra_router_mod
import app.telemetry.models  # noqa: F401 —— checkpoint_anchors 注册进共享 Base
from app.authz.service import AuthzError, threshold_wrap, unwrap_any
from app.crypto.sm3 import sm3_bytes
from app.db import get_session
from app.main import create_app
from app.ra import threshold_shares
from app.ra.models import Base
from app.ra.threshold_shares import ceremony_replay, initialize_if_absent
from tests.accounting import register_and_login

_CTX = {
    "warrant_hash_hex": "ab" * 32,
    "cred_hash_hex": "cd" * 32,
    "request_sha256_hex": "12" * 32,
}


def _hooks(all_true: bool) -> dict:
    if all_true:
        return {
            "request_registered": lambda sha, wh, ch: True,
            "warrant_on_chain": lambda wh: True,
            "collab_approved": lambda sha: True,
        }
    return {
        "request_registered": lambda sha, wh, ch: False,
        "warrant_on_chain": lambda wh: False,
        "collab_approved": lambda sha: False,
    }


@pytest.fixture(autouse=True)
def _isolated_root(tmp_path, monkeypatch):
    monkeypatch.setenv("FZ_THRESHOLD_ROOT_DIR", str(tmp_path / "threshold_root"))
    yield


def test_unwrap_ceremony_success_k_domain_truthful():
    """成功路径仪式留痕：应召 2/3 域（admin+ra granted），第三域未被征询
    （not_summoned 如实——凑足即停=少一次份额点出借的正确安全姿态）。"""
    initialize_if_absent()
    blob = threshold_wrap(b"ceremony-ok")
    ceremony: dict = {}
    plain = unwrap_any(blob, share_hooks=_hooks(True), unlock_ctx=dict(_CTX), ceremony_out=ceremony)
    assert plain == b"ceremony-ok"
    assert ceremony["k"] == 2 and ceremony["domains"] == ["admin", "ra", "auditor"]
    assert ceremony["summoned"] == ["admin", "ra"], ceremony
    assert ceremony["granted"] == ["admin", "ra"]
    assert ceremony["not_summoned"] == ["auditor"]
    assert len(ceremony["rows"]) == 2
    for row in ceremony["rows"]:
        assert row["decision"] == "granted"
        assert row["checks"]["request_registered"] is True
        assert row["checks"]["warrant_on_chain"] is True
        assert row["checks"]["collab_approved"] is True


def test_unwrap_ceremony_denied_all_domains():
    """失败路径全域留痕：三域全被征询、逐域 denied 行（denied:xxx 判词）。"""
    initialize_if_absent()
    blob = threshold_wrap(b"ceremony-denied")
    ceremony: dict = {}
    with pytest.raises(AuthzError) as ei:
        unwrap_any(blob, share_hooks=_hooks(False), unlock_ctx=dict(_CTX), ceremony_out=ceremony)
    assert ei.value.code == "threshold_denied"
    assert ceremony["summoned"] == ["admin", "ra", "auditor"]
    assert ceremony["granted"] == []
    assert len(ceremony["rows"]) == 3
    for row in ceremony["rows"]:
        assert row["decision"].startswith("denied:")


def test_ceremony_replay_reads_domain_audits():
    """案乙回放：按令状哈希过滤各域 audit_{role}.jsonl decrypt_share 行+
    unlock_requests 受理登记；他令状行/非本动作行不入。"""
    initialize_if_absent()
    wh = "ab" * 32
    threshold_shares._audit(
        "admin",
        {
            "action": "decrypt_share",
            "warrant_hash_hex": wh,
            "checks": {"request_registered": True},
            "decision": "granted",
        },
    )
    threshold_shares._audit(
        "ra",
        {
            "action": "decrypt_share",
            "warrant_hash_hex": wh,
            "checks": {"request_registered": True},
            "decision": "granted",
        },
    )
    threshold_shares._audit(
        "admin",
        {
            "action": "decrypt_share",
            "warrant_hash_hex": "ff" * 32,  # 他令状——不得混入
            "checks": {},
            "decision": "granted",
        },
    )
    out = ceremony_replay(wh)
    assert out["threshold"] == "2-of-3"
    assert len(out["rows"]) == 2
    assert {r["role"] for r in out["rows"]} == {"admin", "ra"}
    assert all(r["decision"] == "granted" for r in out["rows"])
    # 未发生令状=零行零请求（如实空，不臆造）
    empty = ceremony_replay("ee" * 32)
    assert empty["rows"] == [] and empty["requests"] == []


@pytest.fixture()
def app_client(tmp_path, monkeypatch):
    """HTTP 面（test_collab_code 同构）：fake 锚+测试库+审计解锁桥接测试库。"""
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "fake")
    eng = create_engine(f"sqlite:///{tmp_path}/ceremony.db")
    Base.metadata.create_all(eng)
    TestSession = sessionmaker(bind=eng, expire_on_commit=False)
    audit_router_mod._reset_deps_cache()
    ra_router_mod._reset_deps_cache()

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
        c.aud_sk = register_and_login(c, "auditor_ce", "auditor", "Audit-Pass-1")
        c.adm_client = TestClient(app)
        c.adm_sk = register_and_login(c.adm_client, "admin_ce", "admin", "Admin-Pass-1")
        yield c, TestSession
        import time as _t

        from app.accounts import collab as _cs

        deadline = _t.time() + 15
        while _t.time() < deadline and _cs._executing:
            _t.sleep(0.1)


def test_warrant_unlock_response_carries_ceremony(app_client, monkeypatch):
    """案甲端到端：v5 信封解锁成功响应附 ceremony（k/已出份额域/逐域四关）。
    hooks 替位注入形态（3 关真值；第④关缺席=跳过——替位注入既有语义）。"""
    c, TestSession = app_client
    c_admin = TestClient(c.app)
    register_and_login(c_admin, "admin_ce2", "admin", "Admin-Pass-1")
    from app.crypto.sm2 import generate_keypair

    pk = generate_keypair()[1]
    r = c.post(
        "/ra/register",
        json={
            "username": "ceremony-u",
            "id_number": "110101199001011234",
            "cert_level": 3,
            "sn": "FZ-CE-01",
            "user_pub_hex": pk,
            "class_id": 1,
        },
    )
    assert r.status_code == 200
    mch = r.json()["data"]["master_cred_hash_hex"]
    r3 = c.post(
        "/audit/warrants",
        json={
            "case_no": "CE-001",
            "legal_basis_hash_hex": sm3_bytes(b"law").hex(),
            "target_auth_id": None,
        },
    )
    assert r3.status_code == 200
    wh = r3.json()["data"]["warrant_hash_hex"]
    r2 = c_admin.post("/ra/collab-code", json={"warrant_hash_hex": wh, "master_cred_hash_hex": mch})
    assert r2.status_code == 200, r2.text
    code = r2.json()["data"]["code"]
    monkeypatch.setattr(audit_router_mod, "_session_for_unlock", lambda: TestSession())
    ra_router_mod._ra_deps().anchor.warrant_on_chain = lambda wh_bytes: wh_bytes.hex() == wh
    ra_router_mod._ra_deps().threshold_hooks = {
        "request_registered": lambda sha, w, c_: True,
        "warrant_on_chain": lambda w_hex: w_hex == wh,
        "collab_approved": lambda sha: True,
    }
    r4 = c.post(f"/audit/warrants/{wh}/unlock", json={"collab_code": code})
    assert r4.status_code == 200, r4.text
    data = r4.json()["data"]
    assert data["unlocked"]["username"] == "ceremony-u"
    cer = data.get("ceremony")
    assert cer is not None, "解锁响应缺 ceremony 块（案甲未接线）"
    assert cer["granted"] == ["admin", "ra"], cer
    assert cer["not_summoned"] == ["auditor"]
    assert all(row["decision"] == "granted" for row in cer["rows"])
    # 案乙同令状回放可得（轮询行渲染源）
    r5 = c.adm_client.get(f"/ra/threshold/ceremony?warrant_hash_hex={wh}")
    assert r5.status_code == 200 and len(r5.json()["data"]["rows"]) >= 2


def test_threshold_ceremony_endpoint_roles(app_client):
    """回放端点双面（admin+auditor）+pilot 403（审计台红牌/机构台卡片共用
    数据源——治理份额域双角色语义）。"""
    c, _TestSession = app_client
    r = c.adm_client.get("/ra/threshold/ceremony?warrant_hash_hex=" + "ee" * 32)
    assert r.status_code == 200 and r.json()["data"]["rows"] == []
    r2 = c.get("/ra/threshold/ceremony?warrant_hash_hex=" + "ee" * 32)
    assert r2.status_code == 200
    c_pilot = TestClient(c.app)
    register_and_login(c_pilot, "pilot_ce", "pilot", "Pilot-Pass-1")
    r3 = c_pilot.get("/ra/threshold/ceremony?warrant_hash_hex=" + "ee" * 32)
    assert r3.status_code == 403
    r4 = c.adm_client.get("/ra/threshold/ceremony?warrant_hash_hex=short")
    assert r4.status_code == 400
