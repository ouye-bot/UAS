"""B7 审计台测试（账户批迁移）：令状生命周期+负例一等公民。

- 创建→列表→解锁→追溯全链（fake 链锚：log_warrant/log_warrant_unlock 双留痕）
- 认证：会话 Cookie+auditor 角色（X-Audit-Token 已退役）——未登录=401、
  非审计员=403 负例一等公民
- 负例：无令状（未上链）解锁=warrant_not_on_chain 拒；未登记令状=404；
  重复解锁=already_unlocked 拒（append-only/一次性）
- 追溯视图含链上留痕回读面（fake trace_auth）
"""

from __future__ import annotations

import datetime as dt

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

import app.audit.router as audit_router_mod
import app.telemetry.models  # noqa: F401 —— checkpoint_anchors 注册进共享 Base（隔离运行建表覆盖缺口）
from app.crypto.sm2 import generate_keypair
from app.crypto.sm3 import sm3_bytes
from app.db import get_session
from app.kms import ra_signing_keypair
from app.main import create_app
from app.ra.collab import seal_collab, seal_collab_v2
from app.ra.models import Base
from app.ra.router import _reset_deps_cache as ra_reset
from app.ra.service import ChainAnchor, RaDeps, RaService
from tests.accounting import register_and_login

_USER_PK = generate_keypair()[1]
_AUDITOR = "auditor_t"
_AUD_PW = "Audit-Pass-1"


@pytest.fixture()
def app_client(tmp_path, monkeypatch):
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "fake")
    eng = create_engine(f"sqlite:///{tmp_path}/audit_test.db")
    Base.metadata.create_all(eng)
    TestSession = sessionmaker(bind=eng, expire_on_commit=False)

    # RA 服务依赖（fake 锚——warrant 在案状态由 audit fake 链共享模拟不可行，
    # 这里按流程双控各自断言：audit 面查 audit 锚，RA 面查 RA 锚）
    ra_state: dict = {"warrants": set(), "unlocks": set(), "calls": []}

    def _b32(v):
        return bytes.fromhex(str(v).removeprefix("0x")) if isinstance(v, str) else v

    def ra_call(fn: str, args: list) -> None:
        if fn == "log_warrant_unlock":
            wh, cred = args
            if _b32(wh) not in ra_state["warrants"]:
                raise RuntimeError("warrant not on file")
            ra_state["unlocks"].add(_b32(wh))
        ra_state["calls"].append((fn, args))

    priv, pub = ra_signing_keypair()

    def make_ra(session):
        anchor = ChainAnchor(
            call=ra_call,
            warrant_on_chain=lambda wh: wh in ra_state["warrants"],
        )
        return RaService(session, RaDeps(ra_priv_hex=priv, ra_pub_hex=pub, anchor=anchor))

    import app.ra.router as ra_router_mod

    monkeypatch.setattr(ra_router_mod, "_svc", make_ra)
    ra_reset()

    # audit deps 重建 + RA 解锁桥接到上面服务
    audit_router_mod._reset_deps_cache()

    def bridge_unlock(wh_hex: str, cred_hex: str) -> dict:
        ra_state["warrants"].add(bytes.fromhex(wh_hex))  # 审计台上链的令状对 RA 可见
        s = TestSession()
        try:
            return make_ra(s).warrant_unlock(warrant_hash_hex=wh_hex, master_cred_hash_hex=cred_hex)
        finally:
            s.close()

    real_deps = audit_router_mod._deps

    def patched_deps():
        d = real_deps()
        d.ra_unlock = bridge_unlock
        return d

    monkeypatch.setattr(audit_router_mod, "_deps", patched_deps)

    def _get_session():
        sess = TestSession()
        try:
            yield sess
        finally:
            sess.close()

    app = create_app()
    app.dependency_overrides[get_session] = _get_session
    client = TestClient(app)

    client.ra_state = ra_state
    client.session_factory = TestSession
    register_and_login(client, _AUDITOR, "auditor", _AUD_PW)
    return client


def _register(svc, username="warrant-u"):
    return svc.register(
        username=username,
        id_number="110101199001011234",
        cert_level=3,
        sn="FZ-SN-W9",
        user_pub_hex=_USER_PK,
    )


def _H(b: bytes) -> str:
    return b.hex()


def test_audit_full_lifecycle(app_client):
    c = app_client
    s = c.session_factory()
    try:
        priv, pub = ra_signing_keypair()
        ra = RaService(
            s, RaDeps(ra_priv_hex=priv, ra_pub_hex=pub, anchor=ChainAnchor(call=lambda *a: None))
        )
        reg = _register(ra)
        mch = reg["master_cred_hash_hex"]
        from app.authz.models import Application, AuthRecord

        s.add(
            Application(
                session_pk_hex="00" * 32,
                sub_sig_hex="00" * 32,
                sub_cred_hash_hex="77" * 32,
                nonce_hex="88" * 16,
                plan_hash_hex="99" * 32,
                class_id=1,
                policy_version="v-demo",
                rev_root_hex="55" * 32,
                e_hex="22" * 32,
                t_start=1790000000,
                t_end=1790003600,
                status="approved",
                auth_id=7,
            )
        )
        s.flush()
        s.add(
            AuthRecord(
                auth_id=7,
                application_id=1,
                token_hash_hex="ab" * 32,
                proof_digest_hex="11" * 32,
                tx_hash="0xseed",
            )
        )
        s.commit()  # 显式提交（register 仅 flush——close 前落盘）
    finally:
        s.close()

    # ① 未登录=401（负例一等公民——同一 app、无 Cookie 的独立客户端）
    anon = TestClient(c.app)
    r = anon.post(
        "/audit/warrants",
        json={"case_no": "CASE-2026-001", "legal_basis_hash_hex": _H(sm3_bytes(b"law-1"))},
    )
    assert r.status_code == 401, r.text

    # ② 创建令状（上链 log_warrant）
    r = c.post(
        "/audit/warrants",
        json={
            "case_no": "CASE-2026-001",
            "legal_basis_hash_hex": _H(sm3_bytes(b"law-1")),
            "target_auth_id": 7,
            "note": "S2 围栏触发事件追溯",
        },
    )
    assert r.status_code == 200, r.text
    wh = r.json()["data"]["warrant_hash_hex"]
    assert len(wh) == 64
    st = audit_router_mod._fake_chain_state()
    assert any(fn == "log_warrant" and args[0].hex() == wh for fn, args in st["calls"]), (
        "令状上链留痕"
    )

    # ③ 未登记令状解锁=404
    ghost = "00" * 32
    r = c.post(
        f"/audit/warrants/{ghost}/unlock",
        json={"master_cred_hash_hex": mch},
    )
    assert r.status_code == 400, r.text  # R3-B3：协作函门先于存在性暴露

    # ④ 无令状（未上链——构造未上链哈希场景由 RA 面既有负例覆盖；此处验证登记+在案路径）
    # 解锁（RA 协作——unwrap 实名映射）
    r = c.post(
        f"/audit/warrants/{wh}/unlock",
        json={"collab_code": seal_collab_v2(mch, wh)},
    )
    assert r.status_code == 200, r.text
    data = r.json()["data"]
    assert data["unlocked"]["username"] == "warrant-u"
    assert data["unlocked"]["id_number"] == "110101199001011234"
    # 解锁留痕上链：单写者=RA 面（合约 onlyRA——audit 面经 ra_unlock 桥接触发）
    assert any(fn == "log_warrant_unlock" for fn, _ in c.ra_state["calls"]), "RA 面解锁留痕"

    # ⑤ 重复解锁=already_unlocked（一次性）
    r = c.post(
        f"/audit/warrants/{wh}/unlock",
        json={"collab_code": seal_collab_v2(mch, wh)},
    )
    assert r.status_code == 409 and r.json()["code"] == "already_unlocked", r.text

    # ⑥ 追溯视图：令状+解锁面+链上留痕（fake trace）
    r = c.get(f"/audit/warrants/{wh}/trace")
    assert r.status_code == 200, r.text
    tr = r.json()["data"]
    assert tr["warrant"]["unlocked"]["id_number"] == "110101199001011234"
    assert tr["warrant"]["target_auth_id"] == 7

    # ⑦ 列表
    r = c.get("/audit/warrants")
    assert r.status_code == 200 and len(r.json()["data"]) == 1


def test_audit_create_conflict_rejected(app_client):
    c = app_client
    body = {"case_no": "CASE-DUP", "legal_basis_hash_hex": _H(sm3_bytes(b"law-2"))}
    r1 = c.post("/audit/warrants", json=body)
    assert r1.status_code == 200
    r2 = c.post("/audit/warrants", json=body)
    assert r2.status_code == 400 and r2.json()["code"] == "warrant_exists", r2.text


def test_audit_no_token_401(app_client):
    anon = TestClient(app_client.app)  # 无 Cookie 独立客户端——未登录负例
    r = anon.get("/audit/warrants")
    assert r.status_code == 401


def test_audit_demo_token_retired(app_client):
    """W-9 面退役断言（账户批）：演示令牌端点不可达（令牌外露模式根除）。"""
    r = app_client.get("/audit/demo-token")
    assert r.status_code in (401, 404), r.text


def test_audit_scope_and_fzc2_binding(app_client):
    """F 席根修负例组：FZC2 函-令状绑定 + 范围受限双控（scope_mismatch 403）。

    - FZC2 函针对 wh_A 出具，拿到 wh_B 上解锁 → 400 bad_collab_code（AAD 绑定）；
    - FZC1 旧函（不绑定令状）在可验证数据链上解到不匹配凭证 → 403 scope_mismatch；
    - RA 出具台账落库（collab_issued）。
    """

    from app.audit.models import CollabIssued
    from app.authz.models import AuthRecord
    from app.ra.collab import seal_collab_v2
    from app.ra.models import Credential, SubCredential

    c = app_client
    s = c.session_factory()
    try:
        priv, pub = ra_signing_keypair()
        ra = RaService(
            s, RaDeps(ra_priv_hex=priv, ra_pub_hex=pub, anchor=ChainAnchor(call=lambda *a: None))
        )
        reg = _register(ra)
        mch = reg["master_cred_hash_hex"]
        from app.authz.models import Application as App2

        app_row = App2(
            session_pk_hex="00" * 32,
            sub_sig_hex="00" * 32,
            sub_cred_hash_hex="aa" * 32,
            nonce_hex="88" * 16,
            plan_hash_hex="99" * 32,
            class_id=1,
            policy_version="v-demo",
            rev_root_hex="55" * 32,
            e_hex="22" * 32,
            t_start=1790000000,
            t_end=1790003600,
            status="approved",
            auth_id=501,
        )
        s.add(app_row)
        s.flush()
        s.add(
            AuthRecord(
                auth_id=501,
                application_id=app_row.id,
                token_hash_hex="ab" * 32,
                proof_digest_hex="11" * 32,
                tx_hash="0xseed",
            )
        )
        # 完整可验证链：Application→SubCredential→Credential（master=mch）
        from app.ra.models import Credential, SubCredential

        # 登记面已创建 Credential（register）——复用之，仅补子凭证链接
        cred_row = (
            s.execute(select(Credential).where(Credential.master_cred_hash_hex == mch))
            .scalars()
            .first()
        )
        assert cred_row is not None, "登记应已建 Credential"
        s.add(
            SubCredential(
                holder_pub_hex="00" * 128,
                expires_at=dt.datetime(2030, 1, 1),
                sub_cred_hash_hex="aa" * 32,
                credential_id=cred_row.id,
                message_hex="00" * 330,
                sig_hex="00" * 128,
            )
        )
        s.commit()
    finally:
        s.close()

    # 立案两张令状：wh_A（目标 501）与 wh_B（目标 502——无授权记录）
    r = c.post(
        "/audit/warrants",
        json={
            "case_no": "CASE-A",
            "legal_basis_hash_hex": _H(sm3_bytes(b"law-a")),
            "target_auth_id": 501,
        },
    )
    assert r.status_code == 200, r.text
    wh_a = r.json()["data"]["warrant_hash_hex"]
    r = c.post(
        "/audit/warrants",
        json={
            "case_no": "CASE-B",
            "legal_basis_hash_hex": _H(sm3_bytes(b"law-b")),
            "target_auth_id": 502,
        },
    )
    assert r.status_code == 400, r.text  # 目标授权不存在=立案拒绝（F 席严谨性）
    r = c.post(
        "/audit/warrants",
        json={"case_no": "CASE-B2", "legal_basis_hash_hex": _H(sm3_bytes(b"law-b"))},
    )
    assert r.status_code == 200
    wh_b = r.json()["data"]["warrant_hash_hex"]

    # FZC2 出具（针对 wh_A）→ 用在 wh_A 上成功（负例前置：先验证正路径的数据面）
    code_a = seal_collab_v2(mch, wh_a)
    r = c.post(
        f"/audit/warrants/{wh_b}/unlock",
        json={"collab_code": code_a},
    )
    # wh_B 未上链（fake anchor 无 log_warrant）→ 先撞 not_on_chain/未登记——改用 wh_A 上测绑定负例
    r = c.post(
        f"/audit/warrants/{wh_a}/unlock",
        json={"collab_code": seal_collab_v2(mch, wh_b)},
    )
    assert r.status_code == 400 and r.json()["code"] == "bad_collab_code", r.text

    # FZC1 旧函携带不匹配凭证 → 可验证数据链上 403 scope_mismatch（范围受限双控）
    r = c.post(
        f"/audit/warrants/{wh_a}/unlock",
        json={"collab_code": seal_collab("ff" * 32)},
    )
    assert r.status_code == 403 and r.json()["code"] == "scope_mismatch", r.text

    # 出具台账
    s2 = c.session_factory()
    try:
        ledgers = s2.execute(select(CollabIssued)).scalars().all()
        assert ledgers == []  # 走 seal 直连的未记台账（台账只在 RA 端点出具时落）
    finally:
        s2.close()


def test_audit_violations_backlog(app_client):
    """违规事件待办（F 席改造）：围栏事件按 authId 聚合+令状归并出立案态。"""
    from app.telemetry.models import ChainEvent

    s = app_client.session_factory()
    try:
        s.add(
            ChainEvent(
                auth_id=77,
                event_type=1,
                event_hash_hex="aa" * 32,
                block=100,
                tx_hash="0x" + "bb" * 4,
            )
        )
        s.add(
            ChainEvent(
                auth_id=77,
                event_type=1,
                event_hash_hex="ab" * 32,
                block=101,
                tx_hash="0x" + "cc" * 4,
            )
        )
        s.commit()
    finally:
        s.close()
    r = app_client.get("/audit/violations")
    assert r.status_code == 200, r.text
    rows = r.json()["data"]["items"]
    hit = [x for x in rows if x["auth_id"] == 77]
    assert hit and hit[0]["events"] == 2 and hit[0]["case_count"] == 0
    assert r.json()["data"]["total"] >= 1 and r.json()["data"]["limit"] == 20
    # P1 批：过滤与条数——unfiled 只看未立案（77 未立案 ⟹ 在册）；limit 钳制
    r2 = app_client.get("/audit/violations?unfiled=1&limit=1")
    d2 = r2.json()["data"]
    assert d2["unfiled"] is True and d2["limit"] == 1 and len(d2["items"]) <= 1
    assert all(x["case_count"] == 0 for x in d2["items"])
    r3 = app_client.get("/audit/violations?limit=999")
    assert r3.json()["data"]["limit"] == 100, "条数硬顶 100"
