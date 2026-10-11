"""跨域写面守卫（2026-10-12 辖区分账 P0 安全补丁——先红后绿）。

缺口（前端修整复审 A⑥/洞 3）：approve/reject/retry（accounts/collab.py 只查
role 不查域）/POST /ra/collab-code（ra/router.py 只查 role）/POST
/admin/disposal-todos/{id}/resolve /POST /admin/accounts/{username}/delete
（admin_router.py 只查 role）允许任一域管理员批准/出函/结办/删除**他机构**
对象——实名解锁是最敏感动作，读面过滤后此洞更隐蔽（UI 看不见仍可直打）。

修法（与 ra 服务层 _org_guard 同 0.1 工艺——⑦复评 §5.3 范式平移）：
目标案件归属域==操作者账户 org_id，跨域 403 org_forbidden 双域判词；
- 协作族目标域=令状 target_auth_id → 授权链解析凭证 → owner_org_id（读时
  派生——CollabRequest 无 org 列，append-only 台账不动 schema）；
- 匿名立案位令状（target_auth_id=None）无域可派生 → 域门跳过（全域待批
  「未定域」语义，与读面过滤同一文案体系——执行面 cred_required 仍兜底）；
- 处置待办目标域=解锁实名 → 用户归属域；孤儿户删除目标域=账户 org_id；
- 份额刷新=治理域动作，operator org 限运营方域 org-a（部署约定，复审洞 2
  推荐案——页面上挂 /governance 语境，守卫照加并如实标注）。
"""

from __future__ import annotations

import datetime as dt
import secrets

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.db as db_mod
import app.telemetry.models  # noqa: F401 —— checkpoint_anchors 注册进共享 Base
from app.accounts.models import Account
from app.audit.models import DisposalRequest, Warrant
from app.crypto.sm3 import sm3_bytes
from app.db import get_session
from app.main import create_app
from app.ra.models import Base, Credential, SubCredential, User
from tests.accounting import register_and_login, sign_canonical

AUD = "auditor_og"
ADM_A = "admin_og_a"
ADM_B = "admin_og_b"
PW = "Org-Guard-Pass-1"


@pytest.fixture()
def og(tmp_path, monkeypatch):
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "fake")
    eng = create_engine(f"sqlite:///{tmp_path}/collab_org_guard.db")
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

    # 后台执行线程走 app.db.SessionLocal（非依赖注入）——必须打桩到测试库
    monkeypatch.setattr(db_mod, "SessionLocal", TestSession)
    app = create_app()
    app.dependency_overrides[get_session] = _sess
    with TestClient(app) as c:
        c.auditor_sk = register_and_login(c, AUD, "auditor", PW)
        c.admin_a_client = TestClient(app)
        c.admin_a_sk = register_and_login(c.admin_a_client, ADM_A, "admin", PW)
        c.admin_b_client = TestClient(app)
        c.admin_b_sk = register_and_login(c.admin_b_client, ADM_B, "admin", PW)
        # admin_b 翻域 org-b（accounts.org_id 直改——域归属夹具手段，0.3 Gap2 同款）
        gen, s = _db_entry(c)
        try:
            acc = s.query(Account).filter_by(username=ADM_B).one()
            acc.org_id = "org-b"
            s.commit()
        finally:
            _close_entry(gen, s)
        yield c
        # 排空后台执行线程再拆夹具（test_collab_dual_control 同款纪律）
        import time as _t

        from app.accounts import collab as _cs

        deadline = _t.time() + 15
        while _t.time() < deadline and _cs._executing:
            _t.sleep(0.1)


def _db_entry(c):
    ov = c.app.dependency_overrides.get(get_session)
    gen = ov()
    return gen, next(gen)


def _close_entry(gen, sess):
    gen.close()


def _seed_org_auth(session, *, username: str, org: str, auth_id: int):
    """播种 org 域授权链：User→Credential(owner_org_id)→SubCredential→
    Application→AuthRecord——令状 target_auth_id 的域派生链（scope.resolve_cred_
    for_auth 同链路）。返回 (auth_id, master_cred_hash_hex)。"""
    user = User(
        username=username,
        pub_key_hex=secrets.token_hex(64),
        org_id=org,
    )
    session.add(user)
    session.flush()
    cred_hex = secrets.token_hex(32)
    cred = Credential(
        user_id=user.id,
        commitment_hex=secrets.token_hex(32),
        master_cred_hash_hex=cred_hex,
        sn_hash_hex="00" * 16,
        serial_hex=secrets.token_hex(8),
        id_cipher=b"",
        cert_level=3,
        expires_at=dt.datetime.utcfromtimestamp(1900000000),
        owner_org_id=org,
    )
    session.add(cred)
    session.flush()
    sub_hex = sm3_bytes(f"sub-{username}".encode()).hex()
    session.add(
        SubCredential(
            credential_id=cred.id,
            sub_cred_hash_hex=sub_hex,
            message_hex=f"sub-{username}".encode().hex(),
            sig_hex="00" * 64,
            holder_pub_hex="11" * 64,
            expires_at=dt.datetime.utcfromtimestamp(1900000000),
        )
    )
    session.commit()
    # Application/AuthRecord（authz 域——共享 Base 同库）
    from app.authz.models import Application, AuthRecord

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
        auth_id=None,
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
    return auth_id, cred_hex


def _seed_warrant(session, *, case_no: str, target_auth_id: int | None) -> str:
    wh = sm3_bytes(f"warrant-{case_no}".encode()).hex()
    session.add(
        Warrant(
            warrant_hash_hex=wh,
            case_no=case_no,
            scope_hash_hex=secrets.token_hex(32),
            legal_basis_hash_hex=secrets.token_hex(32),
            legal_basis_text="围栏触发事件调查",
            target_auth_id=target_auth_id,
        )
    )
    session.commit()
    return wh


def _file(c, wh: str, note: str) -> dict:
    r = c.post(
        "/audit/collab-requests",
        json={
            "warrant_hash_hex": wh,
            "note": note,
            "sig_hex": sign_canonical(c.auditor_sk, f"FZ-COLLAB-REQ|v1|{wh}|{note}"),
        },
    )
    assert r.status_code == 200, r.text
    return r.json()["data"]


def test_cross_domain_approve_rejected(og):
    """org-b 管理员批准 org-a 实名解锁 → 403 org_forbidden 双域判词；行保持
    pending 零副作用；本域管理员随后照常批准（守卫不误伤同域）。先红：现状
    只查 role——org-b 批准 org-a 请求 200 成功。"""
    c = og
    gen, s = _db_entry(c)
    try:
        auth_id, _cred = _seed_org_auth(s, username="pilot_og_a", org="org-a", auth_id=91001)
        wh = _seed_warrant(s, case_no="OG-APPROVE-1", target_auth_id=auth_id)
    finally:
        _close_entry(gen, s)
    req = _file(c, wh, "核实超限事件当事人实名")
    sig_b = sign_canonical(c.admin_b_sk, f"FZ-COLLAB-REQ|v1|{wh}|核实超限事件当事人实名")
    r = c.admin_b_client.post(
        f"/admin/collab-requests/{req['id']}/approve", json={"sig_hex": sig_b}
    )
    assert r.status_code == 403, r.text
    assert r.json()["code"] == "org_forbidden", r.text
    assert "org-a" in r.json()["message"] and "org-b" in r.json()["message"], r.text
    # 零副作用：请求行保持 pending（域门先于状态迁移）
    rows = c.admin_a_client.get("/admin/collab-requests").json()["data"]["items"]
    cur = next(x for x in rows if x["id"] == req["id"])
    assert cur["status"] == "pending", cur
    # 同域管理员照常批准（200——批准即返回，执行后台异步）
    sig_a = sign_canonical(c.admin_a_sk, f"FZ-COLLAB-REQ|v1|{wh}|核实超限事件当事人实名")
    r2 = c.admin_a_client.post(
        f"/admin/collab-requests/{req['id']}/approve", json={"sig_hex": sig_a}
    )
    assert r2.status_code == 200, r2.text


def test_cross_domain_reject_rejected(og):
    """org-b 管理员驳回 org-a 请求 → 403；本域驳回照常。"""
    c = og
    gen, s = _db_entry(c)
    try:
        auth_id, _cred = _seed_org_auth(s, username="pilot_og_a", org="org-a", auth_id=91002)
        wh = _seed_warrant(s, case_no="OG-REJECT-1", target_auth_id=auth_id)
    finally:
        _close_entry(gen, s)
    req = _file(c, wh, "核实超限事件当事人实名")
    reason = "立案依据不充分——请补充材料后重新发起"
    r = c.admin_b_client.post(
        f"/admin/collab-requests/{req['id']}/reject",
        json={
            "reason": reason,
            "sig_hex": sign_canonical(
                c.admin_b_sk, f"FZ-COLLAB-REJECT|v1|{wh}|核实超限事件当事人实名|{reason}"
            ),
        },
    )
    assert r.status_code == 403 and r.json()["code"] == "org_forbidden", r.text
    # 本域照常驳回
    r2 = c.admin_a_client.post(
        f"/admin/collab-requests/{req['id']}/reject",
        json={
            "reason": reason,
            "sig_hex": sign_canonical(
                c.admin_a_sk, f"FZ-COLLAB-REJECT|v1|{wh}|核实超限事件当事人实名|{reason}"
            ),
        },
    )
    assert r2.status_code == 200, r2.text


def test_cross_domain_retry_rejected(og):
    """org-b 管理员重试 org-a 执行失败请求 → 403（域门先于状态检查）。"""
    c = og
    gen, s = _db_entry(c)
    try:
        auth_id, _cred = _seed_org_auth(s, username="pilot_og_a", org="org-a", auth_id=91003)
        wh = _seed_warrant(s, case_no="OG-RETRY-1", target_auth_id=auth_id)
        from app.accounts.models import CollabRequest

        row = CollabRequest(
            warrant_hash_hex=wh,
            case_no="OG-RETRY-1",
            target_auth_id=auth_id,
            legal_basis_text="调查",
            note="核实超限事件当事人实名",
            req_hash_hex=sm3_bytes(b"retry-og").hex(),
            status="execute_failed",
            execute_error="服务重启——后台执行被中断，请重试执行",
            auditor_username=AUD,
            auditor_sig_hex="00" * 64,
        )
        s.add(row)
        s.commit()
        req_id = row.id
    finally:
        _close_entry(gen, s)
    r = c.admin_b_client.post(f"/admin/collab-requests/{req_id}/retry")
    assert r.status_code == 403 and r.json()["code"] == "org_forbidden", r.text


def test_cross_domain_collab_code_rejected(og):
    """org-b 管理员对 org-a 令状手工出函（FZC2）→ 403；本域出函照常。"""
    c = og
    gen, s = _db_entry(c)
    try:
        auth_id, _cred = _seed_org_auth(s, username="pilot_og_a", org="org-a", auth_id=91004)
        wh = _seed_warrant(s, case_no="OG-CODE-1", target_auth_id=auth_id)
    finally:
        _close_entry(gen, s)
    r = c.admin_b_client.post("/ra/collab-code", json={"warrant_hash_hex": wh})
    assert r.status_code == 403 and r.json()["code"] == "org_forbidden", r.text
    r2 = c.admin_a_client.post("/ra/collab-code", json={"warrant_hash_hex": wh})
    assert r2.status_code == 200 and r2.json()["code"] == "ok", r2.text


def test_cross_domain_disposal_resolve_rejected(og):
    """org-b 管理员结办 org-a 处置待办 → 403；本域结办照常。"""
    c = og
    gen, s = _db_entry(c)
    try:
        # 待办目标实名的归属域来源（ra User——username_org_of 权威首查）
        s.add(User(username="pilot_og_a", pub_key_hex=secrets.token_hex(64), org_id="org-a"))
        todo = DisposalRequest(
            req_hash_hex=sm3_bytes(b"todo-og").hex(),
            case_no="OG-DISPOSAL-1",
            username="pilot_og_a",
            created_ts=dt.datetime.utcnow(),
            status="pending",
        )
        s.add(todo)
        s.commit()
        todo_id = todo.id
    finally:
        _close_entry(gen, s)
    r = c.admin_b_client.post(f"/admin/disposal-todos/{todo_id}/resolve", json={})
    assert r.status_code == 403 and r.json()["code"] == "org_forbidden", r.text
    r2 = c.admin_a_client.post(
        f"/admin/disposal-todos/{todo_id}/resolve", json={"note": "已依判词吊销"}
    )
    assert r2.status_code == 200, r2.text


def test_cross_domain_verify_sigs_rejected(og):
    """org-b 管理员复验 org-a 请求历史签名（单项读）→ 403 org_forbidden
    （读面按域——按 id 越域可读同属越域探测面）；本域照常 200。"""
    c = og
    gen, s = _db_entry(c)
    try:
        auth_id, _cred = _seed_org_auth(s, username="pilot_og_a", org="org-a", auth_id=91005)
        wh = _seed_warrant(s, case_no="OG-SIGS-1", target_auth_id=auth_id)
    finally:
        _close_entry(gen, s)
    req = _file(c, wh, "核实超限事件当事人实名")
    r = c.admin_b_client.get(f"/admin/collab-requests/{req['id']}/verify-sigs")
    assert r.status_code == 403 and r.json()["code"] == "org_forbidden", r.text
    r2 = c.admin_a_client.get(f"/admin/collab-requests/{req['id']}/verify-sigs")
    assert r2.status_code == 200, r2.text


def test_cross_domain_delete_orphan_rejected(og):
    """org-a 管理员删除 org-b 孤儿户 → 403；本域孤儿户照常删除。"""
    c = og
    gen, s = _db_entry(c)
    try:
        s.add(
            Account(username="orphan_og_b", role="pilot", status="pending_profile", org_id="org-b")
        )
        s.add(
            Account(username="orphan_og_a", role="pilot", status="pending_profile", org_id="org-a")
        )
        s.commit()
    finally:
        _close_entry(gen, s)
    r = c.admin_a_client.post("/admin/accounts/orphan_og_b/delete")
    assert r.status_code == 403 and r.json()["code"] == "org_forbidden", r.text
    r2 = c.admin_b_client.post("/admin/accounts/orphan_og_b/delete")
    assert r2.status_code == 200, r2.text
    r3 = c.admin_a_client.post("/admin/accounts/orphan_og_a/delete")
    assert r3.status_code == 200, r3.text


def test_reshare_operator_domain_guard(og):
    """份额刷新=治理域动作：operator org 限运营方域 org-a（部署约定，复审
    洞 2 推荐案——org-b 管理员触发全域钥匙重分割=越域 403 org_forbidden）。"""
    c = og
    r = c.admin_b_client.post("/admin/threshold/reshare")
    assert r.status_code == 403 and r.json()["code"] == "org_forbidden", r.text


def test_anonymous_warrant_all_domain_semantics(og):
    """匿名立案位令状（target_auth_id=None）无域可派生 → 域门跳过（全域待批
    「未定域」语义）——org-b 管理员批准可达 approved 态（执行面 cred_required
    仍兜底拒绝，复审洞 3 一句话修法原文）。"""
    c = og
    gen, s = _db_entry(c)
    try:
        wh = _seed_warrant(s, case_no="OG-ANON-1", target_auth_id=None)
    finally:
        _close_entry(gen, s)
    req = _file(c, wh, "匿名立案位令状核实")
    r = c.admin_b_client.post(
        f"/admin/collab-requests/{req['id']}/approve",
        json={"sig_hex": sign_canonical(c.admin_b_sk, f"FZ-COLLAB-REQ|v1|{wh}|匿名立案位令状核实")},
    )
    assert r.status_code == 200, r.text
    assert r.json()["data"]["status"] in ("approved", "executing", "executed", "execute_failed")
