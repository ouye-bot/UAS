"""处置待办测试（2026-10-04 处置联动 A5/B2）：审计结案 verified 自动建单→
机构管理员处置——两台联动闭环。

覆盖面：
- verified 结案挂钩建单：契约字段逐字锚（id/case_no/username/conclusion/
  created_ts/status/resolved_note）+ username=解锁实名（unlocked 数据）；
- 幂等：同 req_hash 重复挂钩不重复建单（UNIQUE+先查后插）；
- 误报（mistaken）/无法查证（inconclusive）不建单；
- resolve 成功（pending→done+说明+时间戳落库）与重复 resolve=409；
- 角色门三态：未登录 401 / pilot 403 / auditor 403 / admin 200；
- resolve 不存在待办=404（诚实面）。
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

import app.audit.router as audit_router_mod
import app.ra.router as ra_router_mod
import app.telemetry.models  # noqa: F401 —— checkpoint_anchors 注册进共享 Base
from app.audit.models import DisposalRequest
from app.db import get_session
from app.kms import ra_signing_keypair
from app.main import create_app
from app.ra.models import Base
from app.ra.service import ChainAnchor, RaDeps, RaService
from tests.accounting import register_and_login, sign_canonical

AUD = "auditor_disp"
ADM = "admin_disp"
PILOT = "pilot_disp"
AUD_PW = "Audit-Pass-1"
ADM_PW = "Admin-Pass-1"
PILOT_PW = "Pilot-Pass-1"


@pytest.fixture()
def dsp(tmp_path, monkeypatch):
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "fake")
    eng = create_engine(f"sqlite:///{tmp_path}/disposal.db")
    Base.metadata.create_all(eng)
    TestSession = sessionmaker(bind=eng, expire_on_commit=False)

    # RA 服务 fake 锚 + 解锁桥接（与 test_collab_dual_control 同构）
    ra_state: dict = {"warrants": set(), "unlocks": set(), "calls": []}
    priv, pub = ra_signing_keypair()

    def make_ra(session):
        anchor = ChainAnchor(
            call=lambda fn, args: ra_state["calls"].append((fn, args)),
            warrant_on_chain=lambda wh: wh in ra_state["warrants"],
        )
        return RaService(session, RaDeps(ra_priv_hex=priv, ra_pub_hex=pub, anchor=anchor))

    monkeypatch.setattr(ra_router_mod, "_svc", make_ra)
    ra_router_mod._reset_deps_cache()
    audit_router_mod._reset_deps_cache()

    def bridge_unlock(wh_hex: str, cred_hex: str) -> dict:
        ra_state["warrants"].add(bytes.fromhex(wh_hex))
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
    import app.db as db_mod

    monkeypatch.setattr(db_mod, "SessionLocal", TestSession)

    app = create_app()
    app.dependency_overrides[get_session] = _sess
    with TestClient(app) as c:
        c.auditor_sk = register_and_login(c, AUD, "auditor", AUD_PW)
        c.admin_client = TestClient(app)
        c.admin_client.auditor_sk = c.auditor_sk
        c.admin_sk = register_and_login(c.admin_client, ADM, "admin", ADM_PW)
        c.pilot_client = TestClient(app)
        c.pilot_client.auditor_sk = c.auditor_sk
        c.pilot_sk = register_and_login(c.pilot_client, PILOT, "pilot", PILOT_PW)
        yield c
        # 排空后台执行线程再拆夹具（与 test_collab_dual_control 同纪律）
        import time as _t

        deadline = _t.time() + 15
        from app.accounts import collab as _cs

        while _t.time() < deadline and _cs._executing:
            _t.sleep(0.1)


def _warrant(c, case_no="DSP-001", target=None):
    r = c.post(
        "/audit/warrants",
        json={"case_no": case_no, "legal_basis_text": "围栏触发事件调查", "target_auth_id": target},
    )
    assert r.status_code == 200, r.text
    return r.json()["data"]["warrant_hash_hex"]


def _file(c, wh, note="核实超限事件当事人实名"):
    return c.post(
        "/audit/collab-requests",
        json={
            "warrant_hash_hex": wh,
            "note": note,
            "sig_hex": sign_canonical(c.auditor_sk, f"FZ-COLLAB-REQ|v1|{wh}|{note}"),
        },
    )


def _seed_executable_chain(c, auth_id: int) -> str:
    """造完整授权链（与 test_collab_dual_control 同构）——自动执行可达 executed。"""
    import datetime as dt

    from app.authz.models import Application, AuthRecord
    from app.authz.service import wrap_secret
    from app.ra.models import Credential, SubCredential, User

    cred_hex = f"{auth_id:064x}"
    sub_hex = f"{auth_id + 1:064x}"
    blob = lambda n: f"{n:064x}"  # noqa: E731  ——authId 派生唯一 blob（unique 列族）
    gen = c.app.dependency_overrides[get_session]()
    sess = next(gen)
    try:
        sess.add(Application(
            session_pk_hex=blob(auth_id + 10), sub_sig_hex="00" * 32, sub_cred_hash_hex=sub_hex,
            nonce_hex=f"{auth_id + 20:032x}", plan_hash_hex="99" * 32, class_id=1,
            policy_version="v-dsp", rev_root_hex="55" * 32, e_hex="22" * 32,
            t_start=1790000000, t_end=1790003600, status="approved", auth_id=auth_id,
        ))
        sess.flush()
        sess.add(AuthRecord(auth_id=auth_id, application_id=1, token_hash_hex=blob(auth_id + 30),
                            proof_digest_hex=blob(auth_id + 40), tx_hash=f"0x{auth_id:x}"))
        u = User(username=f"dc-pilot-{auth_id}", pub_key_hex="00" * 128)
        sess.add(u)
        sess.flush()
        envelope = f"dc-pilot-{auth_id}|110101199001{auth_id:04d}|hdl-{auth_id}".encode()
        cred = Credential(
            user_id=u.id, id_cipher=b"", id_store_cipher=wrap_secret(envelope),
            sn_hash_hex=blob(auth_id + 50), cert_level=3, class_id=1,
            commitment_hex=blob(auth_id + 60), master_cred_hash_hex=cred_hex,
            expires_at=dt.datetime(2030, 1, 1), status=1,
        )
        sess.add(cred)
        sess.flush()
        sess.add(SubCredential(
            holder_pub_hex="00" * 128, expires_at=dt.datetime(2030, 1, 1),
            sub_cred_hash_hex=sub_hex, credential_id=cred.id,
            message_hex="00" * 330, sig_hex="00" * 128,
        ))
        sess.commit()
    finally:
        gen.close()
    return cred_hex


def _drive_to_executed(c, case_no: str, auth_id: int, note: str) -> dict:
    """立案（指向已种子授权）→发函→批准→轮询 executed。返回请求行视图。"""
    import json
    import time as _time

    wh = _warrant(c, case_no, target=auth_id)
    r = _file(c, wh, note=note)
    assert r.status_code == 200, r.text
    req_id = r.json()["data"]["id"]
    r2 = c.admin_client.post(
        f"/admin/collab-requests/{req_id}/approve",
        json={"sig_hex": sign_canonical(c.admin_sk, f"FZ-COLLAB-REQ|v1|{wh}|{note}")},
    )
    assert r2.status_code == 200, r2.text
    final = None
    for _ in range(100):
        rows = c.get("/audit/collab-requests").json()["data"]["items"]
        cur = next(x for x in rows if x["id"] == req_id)
        if cur["status"] in ("executed", "execute_failed"):
            final = cur
            break
        _time.sleep(0.1)
    assert final is not None, "后台执行未在 10s 内到达终态"
    assert final["status"] == "executed", json.dumps(final, ensure_ascii=False)
    return final


def _close_body(sk: str, req_hash_hex: str, conclusion: str, text: str) -> dict:
    return {
        "conclusion": conclusion,
        "conclusion_text": text,
        "sig_hex": sign_canonical(sk, f"FZ-COLLAB-CLOSE|v1|{req_hash_hex}|{conclusion}|{text}"),
    }


def _todos(c):
    r = c.admin_client.get("/admin/disposal-todos")
    assert r.status_code == 200, r.text
    return r.json()["data"]["items"]


def test_verified_close_creates_disposal_todo(dsp):
    """verified 结案 → 自动建单：契约字段逐字锚 + username=解锁实名。"""
    c = dsp
    _seed_executable_chain(c, 9101)
    final = _drive_to_executed(c, "DSP-V1", 9101, "处置联动验证")
    rc = c.post(
        f"/audit/collab-requests/{final['id']}/close",
        json=_close_body(c.auditor_sk, final["req_hash_hex"], "verified", "实名已核实——属实"),
    )
    assert rc.status_code == 200, rc.text
    items = _todos(c)
    assert len(items) == 1, items
    it = items[0]
    # 契约面逐字锚（前端并行开发）：恰此七字段，无多余
    assert set(it.keys()) == {
        "id", "case_no", "username", "conclusion", "created_ts", "status", "resolved_note",
    }, it
    assert it["case_no"] == "DSP-V1"
    assert it["username"] == "dc-pilot-9101"  # 解锁实名（unlocked 数据回填）
    assert it["conclusion"] == "verified"
    assert it["status"] == "pending"
    assert it["resolved_note"] is None
    assert it["created_ts"]
    # 建单幂等锚=req_hash（与请求行同源）
    gen = c.app.dependency_overrides[get_session]()
    sess = next(gen)
    try:
        row = sess.execute(select(DisposalRequest)).scalar_one()
        assert row.req_hash_hex == final["req_hash_hex"] and row.status == "pending"
    finally:
        gen.close()


def test_close_mistaken_and_inconclusive_no_todo(dsp):
    """误报/无法查证不建单——处置对象只在属实证。"""
    c = dsp
    assert _todos(c) == []
    _seed_executable_chain(c, 9102)
    f1 = _drive_to_executed(c, "DSP-MIS", 9102, "误报结案验证")
    rc1 = c.post(
        f"/audit/collab-requests/{f1['id']}/close",
        json=_close_body(c.auditor_sk, f1["req_hash_hex"], "mistaken", ""),
    )
    assert rc1.status_code == 200, rc1.text
    _seed_executable_chain(c, 9103)
    f2 = _drive_to_executed(c, "DSP-INC", 9103, "无法查证结案验证")
    rc2 = c.post(
        f"/audit/collab-requests/{f2['id']}/close",
        json=_close_body(c.auditor_sk, f2["req_hash_hex"], "inconclusive", "链上留痕不足"),
    )
    assert rc2.status_code == 200, rc2.text
    assert _todos(c) == [], "误报/无法查证不得产生处置待办"


def test_create_disposal_request_idempotent_on_req_hash(dsp):
    """幂等：同 req_hash 重复挂钩（重复触发/服务层重放）不重复建单；
    不同 req_hash 各自成单（UNIQUE 锚不误伤新案）。"""
    c = dsp
    from app.audit.disposal import create_disposal_request

    _seed_executable_chain(c, 9104)
    final = _drive_to_executed(c, "DSP-IDEM", 9104, "幂等验证")
    rc = c.post(
        f"/audit/collab-requests/{final['id']}/close",
        json=_close_body(c.auditor_sk, final["req_hash_hex"], "verified", "实名已核实——属实"),
    )
    assert rc.status_code == 200, rc.text
    first = _todos(c)
    assert len(first) == 1
    # 重复挂钩（同 req_hash）×3——HTTP 面单量不变
    gen = c.app.dependency_overrides[get_session]()
    sess = next(gen)
    try:
        for _ in range(3):
            create_disposal_request(
                sess,
                req_hash_hex=final["req_hash_hex"],
                case_no="DSP-IDEM",
                warrant_hash_hex=final["warrant_hash_hex"],
            )
    finally:
        gen.close()
    again = _todos(c)
    assert len(again) == 1 and again[0]["id"] == first[0]["id"]
    # 不同 req_hash = 新案新单
    gen = c.app.dependency_overrides[get_session]()
    sess = next(gen)
    try:
        create_disposal_request(
            sess, req_hash_hex="ab" * 32, case_no="DSP-IDEM-2", warrant_hash_hex=None
        )
        rows = sess.execute(select(DisposalRequest)).scalars().all()
        assert {r.req_hash_hex for r in rows} == {final["req_hash_hex"], "ab" * 32}
    finally:
        gen.close()


def test_resolve_success_and_duplicate_409(dsp):
    """resolve：pending→done+说明+时间戳落库；重复 resolve=409（已 done）。"""
    c = dsp
    _seed_executable_chain(c, 9105)
    final = _drive_to_executed(c, "DSP-RES", 9105, "处置验证")
    rc = c.post(
        f"/audit/collab-requests/{final['id']}/close",
        json=_close_body(c.auditor_sk, final["req_hash_hex"], "verified", "实名已核实——属实"),
    )
    assert rc.status_code == 200, rc.text
    todo_id = _todos(c)[0]["id"]
    # 成功：说明入库，status=done
    r = c.admin_client.post(f"/admin/disposal-todos/{todo_id}/resolve", json={"note": "已移交查处"})
    assert r.status_code == 200, r.text
    d = r.json()["data"]
    assert d["status"] == "done" and d["resolved_note"] == "已移交查处"
    # 库内时间戳落定
    gen = c.app.dependency_overrides[get_session]()
    sess = next(gen)
    try:
        row = sess.get(DisposalRequest, todo_id)
        assert row.status == "done" and row.resolved_ts is not None
    finally:
        gen.close()
    # 重复 resolve=409（条件 UPDATE 输家）
    r2 = c.admin_client.post(f"/admin/disposal-todos/{todo_id}/resolve", json={"note": "再处置"})
    assert r2.status_code == 409 and r2.json()["code"] == "already_resolved", r2.text
    # 列表面如实呈现 done+说明
    it = next(x for x in _todos(c) if x["id"] == todo_id)
    assert it["status"] == "done" and it["resolved_note"] == "已移交查处"
    # 不带 note 的 resolve（选填）→ resolved_note=None 诚实缺省
    _seed_executable_chain(c, 9106)
    f2 = _drive_to_executed(c, "DSP-RES2", 9106, "处置验证二")
    c.post(
        f"/audit/collab-requests/{f2['id']}/close",
        json=_close_body(c.auditor_sk, f2["req_hash_hex"], "verified", "属实二"),
    )
    items = _todos(c)
    # 列表按 created_ts 倒序（契约锚）
    ts = [x["created_ts"] for x in items]
    assert ts == sorted(ts, reverse=True), ts
    todo2 = next(x["id"] for x in items if x["status"] == "pending")
    r3 = c.admin_client.post(f"/admin/disposal-todos/{todo2}/resolve", json={})
    assert r3.status_code == 200 and r3.json()["data"]["resolved_note"] is None, r3.text
    # 不存在的待办=404（诚实面）
    r4 = c.admin_client.post("/admin/disposal-todos/99999/resolve", json={"note": "x"})
    assert r4.status_code == 404 and r4.json()["code"] == "todo_not_found", r4.text


def test_disposal_role_gate_three_states(dsp):
    """角色门三态（两端点）：未登录 401 / pilot 403 / auditor 403 / admin 200。"""
    c = dsp
    # 种一单真待办（admin 面 200 有实物的对照）
    _seed_executable_chain(c, 9107)
    final = _drive_to_executed(c, "DSP-ROLE", 9107, "角色门验证")
    c.post(
        f"/audit/collab-requests/{final['id']}/close",
        json=_close_body(c.auditor_sk, final["req_hash_hex"], "verified", "实名已核实——属实"),
    )
    todo_id = _todos(c)[0]["id"]

    def _gate(client, expect_list: int, expect_resolve: int, *, tag: str):
        r1 = client.get("/admin/disposal-todos")
        assert r1.status_code == expect_list, (tag, r1.status_code, r1.text)
        r2 = client.post(f"/admin/disposal-todos/{todo_id}/resolve", json={"note": "试探"})
        assert r2.status_code == expect_resolve, (tag, r2.status_code, r2.text)

    _gate(c.pilot_client, 403, 403, tag="pilot")
    _gate(c, 403, 403, tag="auditor")  # 审计员不是处置权持有者
    _gate(TestClient(c.app), 401, 401, tag="anon")  # 未登录
    # 负例零副作用：待办仍 pending
    it = next(x for x in _todos(c) if x["id"] == todo_id)
    assert it["status"] == "pending", it
    _gate(c.admin_client, 200, 200, tag="admin")
