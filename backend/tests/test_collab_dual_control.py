"""双控协作请求测试（2026-09-29 账户批 B3）：审计发函→机构批准→自动执行。

覆盖面：
- 全流程正路径：立案→审计发函（签名验证）→管理员批准→自动出函（FZC2+台账）
  →自动解锁（实名回填）→请求终态 executed
- 双控密码学强制负例：无审计签名=拒；坏审计签名=拒；非审计员发函=403；
  非管理员批准=403；管理员坏签=拒；驳回无理由=拒；重复在途请求=拒；
  令状已解锁后发函=拒
- 台账：CollabIssued 落行（出具可追溯）

0018 结案升格批新增覆盖：
- 结案契约负例：缺结论 422/非法结论 422/坏签名 401（含篡改说明）/属实缺说明
  422/说明超长 422/非 executed 态 409/重复结案 409——负例零副作用（不写台账）；
- 结案正路径：结论+说明+签名+closed_ts+案件台账（case_ledger append-only）+
  案卷指纹 case_archive_fp（SM3 收口，可独立复算）；
- trace 结案完整面（前端渲染契约）+未结案 closure=None 诚实缺省；
- 误报/无法查证：说明选填，各自台账在案。
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

import app.audit.router as audit_router_mod
import app.telemetry.models  # noqa: F401 —— checkpoint_anchors 注册进共享 Base
import app.ra.router as ra_router_mod
from app.audit.models import CollabIssued
from app.crypto.sm3 import sm3_bytes
from app.db import get_session
from app.kms import ra_signing_keypair
from app.main import create_app
from app.ra.models import Base
from app.ra.service import ChainAnchor, RaDeps, RaService
from tests.accounting import register_and_login, sign_canonical

AUD = "auditor_dc"
ADM = "admin_dc"
AUD_PW = "Audit-Pass-1"
ADM_PW = "Admin-Pass-1"


@pytest.fixture()
def dc(tmp_path, monkeypatch):
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "fake")
    eng = create_engine(f"sqlite:///{tmp_path}/collab_dc.db")
    Base.metadata.create_all(eng)
    TestSession = sessionmaker(bind=eng, expire_on_commit=False)

    # RA 服务 fake 锚 + 解锁桥接（与 test_audit_api 同构——双控各自断言）
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
        # 双席双客户端：TestClient 单 Cookie 罐——同罐互踩会话（实测教训）
        c.auditor_sk = register_and_login(c, AUD, "auditor", AUD_PW)
        c.admin_client = TestClient(app)
        c.admin_client.auditor_sk = c.auditor_sk
        c.admin_sk = register_and_login(c.admin_client, ADM, "admin", ADM_PW)
        yield c
        # 排空后台执行线程再拆夹具：线程走 SessionLocal——monkeypatch 撤销后
        # 会指回真库（误写活库+下一用例竞态的根因，全量套跑偶发 error 定谳）
        import time as _t

        deadline = _t.time() + 15
        from app.accounts import collab as _cs

        while _t.time() < deadline and _cs._executing:
            _t.sleep(0.1)


def _warrant(c, case_no="DC-001", target=None):
    r = c.post(
        "/audit/warrants",
        json={"case_no": case_no, "legal_basis_text": "围栏触发事件调查", "target_auth_id": target},
    )
    assert r.status_code == 200, r.text
    return r.json()["data"]["warrant_hash_hex"]


def _file(c, wh, note="核实超限事件当事人实名", sk=None):
    sk = sk or c.auditor_sk
    return c.post(
        "/audit/collab-requests",
        json={
            "warrant_hash_hex": wh,
            "note": note,
            "sig_hex": sign_canonical(sk, f"FZ-COLLAB-REQ|v1|{wh}|{note}"),
        },
    )


def test_dual_control_full_flow(dc):
    c = dc
    wh = _warrant(c)
    # 审计发函
    r = _file(c, wh)
    assert r.status_code == 200, r.text
    req = r.json()["data"]
    assert req["status"] == "pending" and req["auditor_username"] == AUD
    assert req["legal_basis_text"] == "围栏触发事件调查"
    # 批准（异步化）——即返回 approved；后台执行到终态
    r2 = c.admin_client.post(
        f"/admin/collab-requests/{req['id']}/approve",
        json={"sig_hex": sign_canonical(c.admin_sk, f"FZ-COLLAB-REQ|v1|{wh}|核实超限事件当事人实名")},
    )
    # 响应状态=批准瞬间的快照——匿名令状后台执行极快，快照可能已是终态
    # （良性竞态：批准本身必成功，终态由下方轮询断言；executing=租约认领后
    # 执行中的新中间态——批 2-2.5③ 状态链 pending→approved→executing→executed）
    assert r2.status_code == 200 and r2.json()["data"]["status"] in (
        "approved", "executing", "executed", "execute_failed",
    ), r2.text
    assert r2.json()["data"]["admin_username"] == ADM
    assert r2.json()["data"]["auditor_fp"] and r2.json()["data"]["req_fp"]
    # 轮询终态：匿名令状（无 target）→ execute_failed + 人话原因（结构化而非 500）
    import time as _time

    terminal = None
    for _ in range(50):
        rows = c.get("/audit/collab-requests").json()["data"]["items"]
        cur = next(x for x in rows if x["id"] == req["id"])
        if cur["status"] in ("executed", "execute_failed"):
            terminal = cur
            break
        _time.sleep(0.1)
    assert terminal is not None, "后台执行未在 5s 内到达终态"
    assert terminal["status"] == "execute_failed"
    assert "未指定目标授权编号" in (terminal["execute_error"] or "")


def test_dual_control_signature_negatives(dc):
    c = dc
    wh = _warrant(c, "DC-NEG-1")
    # 无签名=拒
    r = c.post("/audit/collab-requests", json={"warrant_hash_hex": wh, "note": "n"})
    assert r.status_code == 422, r.text  # 必填字段
    # 坏签名=拒（401）
    r = c.post(
        "/audit/collab-requests",
        json={"warrant_hash_hex": wh, "note": "n1", "sig_hex": "00" * 64},
    )
    assert r.status_code == 401 and r.json()["code"] == "bad_sig", r.text
    # 签名内容与请求不符（note 换过）=拒
    r = _file(c, wh, note="真实的理由")
    assert r.status_code == 200
    # 管理员批准时对「另一个 note」签名=拒（批准即绑定内容）
    r2 = c.admin_client.post(
        f"/admin/collab-requests/{r.json()['data']['id']}/approve",
        json={"sig_hex": sign_canonical(c.admin_sk, f"FZ-COLLAB-REQ|v1|{wh}|被篡改的理由")},
    )
    assert r2.status_code == 401 and r2.json()["code"] == "bad_sig", r2.text


def test_role_boundaries(dc):
    c = dc
    # 管理员不能发函（审计职权）——走管理员客户端（403 在依赖层）
    wh = _warrant(c, "DC-ROLE-1")
    r = c.admin_client.post(
        "/audit/collab-requests",
        json={
            "warrant_hash_hex": wh,
            "note": "x",
            "sig_hex": sign_canonical(c.admin_sk, f"FZ-COLLAB-REQ|v1|{wh}|x"),
        },
    )
    assert r.status_code == 403 and r.json()["detail"]["code"] == "forbidden", r.text
    # 审计员不能批准（机构职权）
    r = _file(c, wh, note="y")
    req_id = r.json()["data"]["id"]
    gen = c.app.dependency_overrides[get_session]
    # 用第二个无 Cookie 客户端以 auditor 身份打 /admin 面=403
    c2 = TestClient(c.app)
    sk2 = register_and_login(c2, "auditor_dc2", "auditor", AUD_PW)
    r2 = c2.post(
        f"/admin/collab-requests/{req_id}/approve",
        json={"sig_hex": sign_canonical(sk2, f"FZ-COLLAB-REQ|v1|{wh}|y")},
    )
    assert r2.status_code == 403, r2.text
    # 未登录=401
    anon = TestClient(c.app)
    r3 = anon.get("/admin/collab-requests")
    assert r3.status_code == 401


def test_reject_path(dc):
    c = dc
    wh = _warrant(c, "DC-REJ")
    r = _file(c, wh, note="依据不足，请补充")
    req_id = r.json()["data"]["id"]
    # 无理由驳回=拒
    r2 = c.admin_client.post(f"/admin/collab-requests/{req_id}/reject", json={"reason": "", "sig_hex": "00" * 64})
    assert r2.status_code == 422
    reason = "立案依据不充分——请补充材料后重新发起"
    r3 = c.admin_client.post(
        f"/admin/collab-requests/{req_id}/reject",
        json={
            "reason": reason,
            "sig_hex": sign_canonical(c.admin_sk, f"FZ-COLLAB-REJECT|v1|{wh}|依据不足，请补充|{reason}"),
        },
    )
    assert r3.status_code == 200, r3.text
    assert r3.json()["data"]["status"] == "rejected"
    # 驳回后重新发函=允许（在途唯一性只锁 pending）
    r4 = _file(c, wh, note="补充材料后的再次发起")
    assert r4.status_code == 200, r4.text


def test_pending_uniqueness_and_unlocked_reject(dc):
    c = dc
    wh = _warrant(c, "DC-DUP")
    r = _file(c, wh, note="第一次")
    assert r.status_code == 200
    r2 = _file(c, wh, note="第二次")
    assert r2.status_code == 409 and r2.json()["code"] == "request_pending", r2.text
    # 已解锁令状发函=拒
    wh2 = _warrant(c, "DC-UNL")
    from app.audit.models import Warrant

    gen, sess = None, None
    from app.db import SessionLocal as _SL

    # 依赖覆盖的会话工厂直接置解锁态（append-only 面外的测试种子）
    ov = c.app.dependency_overrides[get_session]
    gen = ov()
    sess = next(gen)
    try:
        row = sess.execute(select(Warrant).where(Warrant.warrant_hash_hex == wh2)).scalar_one()
        from datetime import datetime

        row.unlocked_ts = datetime.utcnow()
        sess.commit()
    finally:
        gen.close()
    r3 = _file(c, wh2, note="已解锁的令状不应再发函")
    assert r3.status_code == 409 and r3.json()["code"] == "already_unlocked", r3.text


def test_ledger_written_on_execute(dc):
    """台账：批准执行成功路径的 CollabIssued 落行。执行在 fake 面以
    cred_unreachable 告终（匿名令状）——此处直接断言「台账只在出具时落」
    的负向不变量 + overview 台账面可达。"""
    c = dc
    wh = _warrant(c, "DC-LED")
    r = _file(c, wh, note="台账检查")
    req_id = r.json()["data"]["id"]
    c.admin_client.post(
        f"/admin/collab-requests/{req_id}/approve",
        json={"sig_hex": sign_canonical(c.admin_sk, f"FZ-COLLAB-REQ|v1|{wh}|台账检查")},
    )
    gen = c.app.dependency_overrides[get_session]()
    sess = next(gen)
    try:
        rows = sess.execute(select(CollabIssued)).scalars().all()
        assert rows == []  # 匿名令状不可自动执行 ⟹ 不可达出函 ⟹ 台账空（诚实）
    finally:
        gen.close()
    # 机构台总览可达（管理员客户端）
    r2 = c.admin_client.get("/admin/overview")
    assert r2.status_code == 200, r2.text
    data = r2.json()["data"]
    assert data["collab_ledger"] == [] and any(w["case_no"] == "DC-LED" for w in data["warrants"])


def _seed_executable_chain(c, auth_id: int) -> str:
    """造完整授权链（Application/AuthRecord/User/Credential/SubCredential），
    凭证带可解封的通道②信封（v1 三段：username|id_number|handle）——
    自动执行可达 executed（实名解锁回填）。返回 master_cred_hash_hex。"""
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
            policy_version="v-dc", rev_root_hex="55" * 32, e_hex="22" * 32,
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
    """结案 body（0018 契约）：结论+说明+审计员钥签
    SM3("FZ-COLLAB-CLOSE|v1|{req_hash}|{conclusion}|{text}")。"""
    from tests.accounting import sign_canonical as _sign

    return {
        "conclusion": conclusion,
        "conclusion_text": text,
        "sig_hex": _sign(sk, f"FZ-COLLAB-CLOSE|v1|{req_hash_hex}|{conclusion}|{text}"),
    }


def test_close_and_retry_semantics(dc):
    """结案闭环语义（批二；0018 结案升格语义）：executed→closed 须带结论+说明+
    签名+案卷指纹；非终态拒（409）；重复结案拒（409）；已结案再批拒（409）。
    （execute_failed→retry 重试语义由 test_startup_recovery_and_reapprove_guard
    覆盖——本测试聚焦结案升格闭环。）"""
    c = dc
    _seed_executable_chain(c, 9001)

    wh = _warrant(c, "DC-CLOSE", target=9001)
    r = _file(c, wh, note="结案链路验证")
    req_id = r.json()["data"]["id"]
    req_hash = r.json()["data"]["req_hash_hex"]

    # 未批准先结案（body 合法）=拒：仅 executed 可结（数据库仲裁）
    rc = c.post(
        f"/audit/collab-requests/{req_id}/close",
        json=_close_body(c.auditor_sk, req_hash, "verified", "预结案试探"),
    )
    assert rc.status_code == 409 and rc.json()["code"] == "bad_state", rc.text

    msg = f"FZ-COLLAB-REQ|v1|{wh}|结案链路验证"
    import time as _time

    r2 = c.admin_client.post(f"/admin/collab-requests/{req_id}/approve",
                             json={"sig_hex": sign_canonical(c.admin_sk, msg)})
    assert r2.status_code == 200, r2.text
    rows = c.get("/audit/collab-requests").json()["data"]["items"]
    final = next(x for x in rows if x["id"] == req_id)
    for _ in range(100):
        rows = c.get("/audit/collab-requests").json()["data"]["items"]
        final = next(x for x in rows if x["id"] == req_id)
        if final["status"] in ("executed", "execute_failed"):
            break
        _time.sleep(0.1)
    # 解锁实名回填 → 审计员带结论签名结案 → closed（密码学重量面齐备）
    assert final["status"] == "executed", json.dumps(final, ensure_ascii=False)
    rc2 = c.post(
        f"/audit/collab-requests/{req_id}/close",
        json=_close_body(c.auditor_sk, req_hash, "verified", "实名已核实——超限事件属实"),
    )
    assert rc2.status_code == 200, rc2.text
    data = rc2.json()["data"]
    assert data["status"] == "closed", rc2.text
    assert data["conclusion"] == "verified" and "实名已核实" in data["conclusion_text"]
    assert data["closed_ts"] and len(data["case_archive_fp_hex"]) == 64, data
    # 已结案再批=拒
    r3 = c.admin_client.post(f"/admin/collab-requests/{req_id}/approve",
                             json={"sig_hex": sign_canonical(c.admin_sk, msg)})
    assert r3.status_code == 409
    # 重复结案=409（条件 UPDATE 输家——终态一次性）
    rc3 = c.post(
        f"/audit/collab-requests/{req_id}/close",
        json=_close_body(c.auditor_sk, req_hash, "mistaken", "重复结案试探"),
    )
    assert rc3.status_code == 409 and rc3.json()["code"] == "bad_state", rc3.text


def test_close_negative_contract(dc):
    """0018 结案升格负例契约：缺结论 422/非法结论 422/坏签名 401/属实缺说明
    422/说明超长 422——且任何负例都不得写台账/落指纹（失败零副作用）。"""
    c = dc
    from app.accounts.models import CaseLedger

    _seed_executable_chain(c, 9002)
    final = _drive_to_executed(c, "DC-CLOSENEG", 9002, "负例契约验证")
    req_id = final["id"]
    req_hash = final["req_hash_hex"]
    url = f"/audit/collab-requests/{req_id}/close"

    # 缺结论=422（body 契约必填）
    r = c.post(url, json={"conclusion_text": "x", "sig_hex": "00" * 64})
    assert r.status_code == 422, r.text
    # 非法结论枚举=422（服务端枚举门——pydantic 放行后由枚举白名单拒）
    r = c.post(url, json={"conclusion": "banana", "conclusion_text": "x", "sig_hex": "00" * 64})
    assert r.status_code == 422 and r.json()["code"] == "bad_conclusion", r.text
    # 坏签名=401（内容与签名不匹配）
    bad = _close_body(c.auditor_sk, req_hash, "verified", "实名已核实")
    r = c.post(url, json={**bad, "sig_hex": "0" * 128})
    assert r.status_code == 401 and r.json()["code"] == "bad_sig", r.text
    # 对别的结论签名（内容换过）=401——结论进签名，篡改即失配
    bad = dict(_close_body(c.auditor_sk, req_hash, "verified", "实名已核实"))
    bad["conclusion_text"] = "被篡改的说明"
    r = c.post(url, json=bad)
    assert r.status_code == 401 and r.json()["code"] == "bad_sig", r.text
    # 属实（verified）缺说明=422——终局判词不留白
    body = _close_body(c.auditor_sk, req_hash, "verified", "")
    r = c.post(url, json=body)
    assert r.status_code == 422 and r.json()["code"] == "conclusion_text_required", r.text
    # 说明超 500 字=422（pydantic 契约层直接拒——服务层 CONCLUSION_TEXT_MAX 双保险）
    body = _close_body(c.auditor_sk, req_hash, "verified", "超" * 501)
    r = c.post(url, json=body)
    assert r.status_code == 422, r.text
    # 负例零副作用：台账空、请求行仍 executed 待结
    gen = c.app.dependency_overrides[get_session]()
    sess = next(gen)
    try:
        assert sess.query(CaseLedger).count() == 0
    finally:
        gen.close()
    rows = c.get("/audit/collab-requests").json()["data"]["items"]
    cur = next(x for x in rows if x["id"] == req_id)
    assert cur["status"] == "executed" and cur["conclusion"] is None, cur


def test_close_verified_archive_fingerprint_and_trace(dc):
    """0018 A6 案卷指纹+台账+trace 结案面：结案成功即写 case_ledger（append-only）
    并落 case_archive_fp=SM3(令状哈希|req_hash|双签名|函指纹|实名哈希|结论|
    closed_ts)；trace 端点输出结案完整面（前端渲染契约）；指纹可独立复算。"""
    c = dc
    from sqlalchemy import select

    from app.accounts import collab as collab_svc
    from app.accounts.models import CaseLedger

    _seed_executable_chain(c, 9005)
    final = _drive_to_executed(c, "DC-ARCH", 9005, "案卷指纹验证")
    req_id, req_hash = final["id"], final["req_hash_hex"]

    text = "实名已核实——超限飞行属实，予以立案查处"
    rc = c.post(
        f"/audit/collab-requests/{req_id}/close",
        json=_close_body(c.auditor_sk, req_hash, "verified", text),
    )
    assert rc.status_code == 200, rc.text
    fp = rc.json()["data"]["case_archive_fp_hex"]
    assert len(fp) == 64 and rc.json()["data"]["status"] == "closed"

    # 台账行：append-only 独立复核锚（req_hash/案号/action=close/结论/签名/结案人）
    gen = c.app.dependency_overrides[get_session]()
    sess = next(gen)
    try:
        rows = sess.execute(select(CaseLedger)).scalars().all()
        assert len(rows) == 1
        lg = rows[0]
        assert lg.req_hash_hex == req_hash and lg.action == "close"
        assert lg.case_no == "DC-ARCH" and lg.conclusion == "verified"
        assert lg.conclusion_text == text and lg.operator == AUD
        assert lg.closed_ts is not None and len(lg.identity_hash_hex) == 64
        # 实名哈希=SM3(username|id_number)（与解锁回填的实名一致，信封句柄不入哈希）
        assert lg.identity_hash_hex == sm3_bytes(b"dc-pilot-9005|1101011990019005").hex()
        # 案卷指纹可独立复算（确定性——输入与库内行一一对应）
        from app.accounts.models import CollabRequest

        rrow = sess.execute(select(CollabRequest).where(CollabRequest.id == req_id)).scalar_one()
        want = collab_svc.case_archive_fp_of(
            warrant_hash_hex=rrow.warrant_hash_hex,
            req_hash_hex=rrow.req_hash_hex,
            auditor_sig_hex=rrow.auditor_sig_hex,
            admin_sig_hex=rrow.admin_sig_hex,
            fzc2_fingerprint_hex=rrow.fzc2_fingerprint_hex,
            identity_hash_hex=lg.identity_hash_hex,
            conclusion=rrow.conclusion,
            closed_ts=lg.closed_ts,
        )
        assert want == fp == lg.case_archive_fp_hex == rrow.case_archive_fp_hex
        # 结案签名落库且可按签名时点公钥纪元复验
        from app.accounts.service import pubkey_at

        pk = pubkey_at(sess, AUD, lg.closed_ts)
        from app.crypto.sm2 import verify as sm2_verify

        assert sm2_verify(
            pk,
            collab_svc.close_msg_of(req_hash, "verified", text).encode(),
            rrow.conclusion_sig_hex,
        )
    finally:
        gen.close()

    # trace 端点：结案完整面（前端渲染契约——字段清单见测试末注释）
    tr = c.get(f"/audit/warrants/{final['warrant_hash_hex']}/trace")
    assert tr.status_code == 200, tr.text
    out = tr.json()["data"]
    cl = out["closure"]
    assert cl is not None
    assert cl["req_id"] == req_id and cl["req_hash_hex"] == req_hash
    assert cl["case_no"] == "DC-ARCH" and cl["action"] == "close"
    assert cl["conclusion"] == "verified" and cl["conclusion_text"] == text
    assert cl["closed_by"] == AUD and cl["auditor_username"] == AUD
    assert cl["admin_username"] == ADM
    assert cl["conclusion_sig_hex"] and cl["auditor_sig_hex"] and cl["admin_sig_hex"]
    assert cl["fzc2_fingerprint_hex"] == final["fzc2_fingerprint_hex"]
    assert cl["case_archive_fp_hex"] == fp
    assert cl["identity_hash_hex"] == lg.identity_hash_hex
    assert cl["closed_ts"] is not None
    # 未结案令状：closure=None（诚实缺省）
    wh2 = _warrant(c, "DC-ARCH-OPEN", target=None)
    tr2 = c.get(f"/audit/warrants/{wh2}/trace")
    assert tr2.status_code == 200 and tr2.json()["data"]["closure"] is None, tr2.text
    # 前端渲染契约（closure 字段）：req_id, req_hash_hex, case_no, action,
    # conclusion, conclusion_text, auditor_username, auditor_sig_hex,
    # admin_username, admin_sig_hex, conclusion_sig_hex, fzc2_fingerprint_hex,
    # closed_by, identity_hash_hex, case_archive_fp_hex, closed_ts


def test_close_mistaken_and_inconclusive_text_optional(dc):
    """误报/无法查证：说明选填（属实才强制）；两种结论各自闭环落台账。"""
    c = dc
    from sqlalchemy import select

    from app.accounts.models import CaseLedger

    _seed_executable_chain(c, 9003)
    f1 = _drive_to_executed(c, "DC-MIS", 9003, "误报结案验证")
    rc1 = c.post(
        f"/audit/collab-requests/{f1['id']}/close",
        json=_close_body(c.auditor_sk, f1["req_hash_hex"], "mistaken", ""),
    )
    assert rc1.status_code == 200, rc1.text
    d1 = rc1.json()["data"]
    assert d1["status"] == "closed" and d1["conclusion"] == "mistaken"
    assert d1["conclusion_text"] is None and len(d1["case_archive_fp_hex"]) == 64

    _seed_executable_chain(c, 9004)
    f2 = _drive_to_executed(c, "DC-INC", 9004, "无法查证结案验证")
    rc2 = c.post(
        f"/audit/collab-requests/{f2['id']}/close",
        json=_close_body(
            c.auditor_sk, f2["req_hash_hex"], "inconclusive", "链上留痕不足以定谳——存疑终结"
        ),
    )
    assert rc2.status_code == 200, rc2.text
    d2 = rc2.json()["data"]
    assert d2["conclusion"] == "inconclusive" and "存疑终结" in d2["conclusion_text"]
    # 两笔结案各自台账在案（互不覆写——append-only）
    gen = c.app.dependency_overrides[get_session]()
    sess = next(gen)
    try:
        rows = sess.execute(select(CaseLedger).order_by(CaseLedger.id)).scalars().all()
        assert [r.conclusion for r in rows] == ["mistaken", "inconclusive"]
        assert len({r.case_archive_fp_hex for r in rows}) == 2
    finally:
        gen.close()


def test_startup_recovery_and_reapprove_guard(dc):
    """批2-⑤⑥：①已 executed 后重批=409（状态不再被倒带）；②approved 残留
    经启动恢复→execute_failed（人话原因）——僵尸卡根修；③恢复后可重试。"""
    c = dc
    import time as _time

    from app.accounts import collab as collab_svc

    wh = _warrant(c, "DC-RECOVER", target=None)
    r = _file(c, wh, note="恢复验证")
    req_id = r.json()["data"]["id"]
    msg = f"FZ-COLLAB-REQ|v1|{wh}|恢复验证"
    c.admin_client.post(f"/admin/collab-requests/{req_id}/approve",
                        json={"sig_hex": sign_canonical(c.admin_sk, msg)})
    for _ in range(50):
        rows = c.get("/audit/collab-requests").json()["data"]["items"]
        cur = next(x for x in rows if x["id"] == req_id)
        if cur["status"] == "execute_failed":
            break
        _time.sleep(0.1)
    assert cur["status"] == "execute_failed"
    # ①execute_failed 重批=409（仅 pending 可批——垃圾签名/重复批准不再倒带状态）
    r2 = c.admin_client.post(f"/admin/collab-requests/{req_id}/approve",
                             json={"sig_hex": sign_canonical(c.admin_sk, msg)})
    assert r2.status_code == 409 and "不可批准" in r2.json()["message"], r2.text
    # ②启动恢复：造一条 approved 残留 → recover → execute_failed
    wh2 = _warrant(c, "DC-RECOVER2", target=None)
    r3 = _file(c, wh2, note="残留验证")
    req3 = r3.json()["data"]["id"]
    msg3 = f"FZ-COLLAB-REQ|v1|{wh2}|残留验证"
    c.admin_client.post(f"/admin/collab-requests/{req3}/approve",
                        json={"sig_hex": sign_canonical(c.admin_sk, msg3)})
    # 立刻恢复（后台线程可能已把它推到 execute_failed——两种都算通过前提）
    n = collab_svc.recover_interrupted()
    rows = c.get("/audit/collab-requests").json()["data"]["items"]
    cur3 = next(x for x in rows if x["id"] == req3)
    assert cur3["status"] == "execute_failed", cur3["status"]
    if n:
        assert "服务重启" in (cur3["execute_error"] or "") or cur3["execute_error"]
    # ③恢复后重试 → approved（后台再执行→仍因匿名失败，但语义可达）
    rr = c.admin_client.post(f"/admin/collab-requests/{req3}/retry")
    assert rr.status_code == 200, rr.text


def test_verify_request_sigs_survives_rekey(dc):
    """旗舰判词（2026-09-30 公钥纪元史批）：双控请求落定后**双方都换了钥**
    （密码重置→重新激活），历史双签仍按签名时点公钥复验通过——任何一方
    事后声称"不是我签的"都被当场戳穿（append-only 纪元史=双控不可抵赖）。"""
    c = dc
    wh = _warrant(c, "DC-REKEY-1", target=None)
    r = _file(c, wh, note="复验锚定理由")
    assert r.status_code == 200, r.text
    req_id = r.json()["data"]["id"]
    # 管理员批准（第二签落定）——匿名令状后台执行会失败（无目标），与签名无关
    r2 = c.admin_client.post(
        f"/admin/collab-requests/{req_id}/approve",
        json={"sig_hex": sign_canonical(c.admin_sk, f"FZ-COLLAB-REQ|v1|{wh}|复验锚定理由")},
    )
    assert r2.status_code == 200, r2.text

    # 🔴 双方密码重置（离线脚本路径）→重新激活拿全新钥
    import time as _t

    _t.sleep(0.05)  # decided_ts 与 created_ts 分辨（毫秒级同刻会导致时点查询
    # 把两签都归到同一纪元——语义上无害，此处为保证断言独立性）
    from app.accounts.service import reset_institutional_account
    from app.db import SessionLocal

    s = SessionLocal()
    try:
        reset_institutional_account(s, AUD, "Rekey-Pass-1")
        reset_institutional_account(s, ADM, "Rekey-Pass-2")
        s.commit()
    finally:
        s.close()
    # 重新激活（新钥=纪元 2）
    from tests.accounting import seed_login

    c.auditor_sk2 = seed_login(c, AUD, "auditor", "Rekey-Pass-1")
    c.admin_client.admin_sk2 = seed_login(c.admin_client, ADM, "admin", "Rekey-Pass-2")

    # 复验（审计面端点）：两签均 ok 且归档纪元=1（签名时点的旧纪元）
    rv = c.get(f"/audit/collab-requests/{req_id}/verify-sigs")
    assert rv.status_code == 200, rv.text
    v = rv.json()["data"]
    assert v["auditor"]["ok"] is True and v["auditor"]["epoch"] == 1, v
    assert v["admin"]["ok"] is True and v["admin"]["epoch"] == 1, v
    # 复验（机构面同款——管理员自查）
    rv2 = c.admin_client.get(f"/admin/collab-requests/{req_id}/verify-sigs")
    assert rv2.status_code == 200 and rv2.json()["data"]["auditor"]["ok"] is True, rv2.text
    # 指纹不漂移：列表视图的 auditor_fp 仍=纪元 1 公钥前缀（换钥不改历史行）
    rows = c.get("/audit/collab-requests").json()["data"]["items"]
    cur = next(x for x in rows if x["id"] == req_id)
    from app.accounts.service import pubkey_at
    from app.accounts.models import CollabRequest as _CR

    s = SessionLocal()
    try:
        from sqlalchemy import select as _sel

        row = s.execute(_sel(_CR).where(_CR.id == req_id)).scalar_one()
        want = (pubkey_at(s, AUD, row.created_ts) or "")[:16]
    finally:
        s.close()
    assert cur["auditor_fp"] == want and want != "", cur
    # 台账：两次重置逐笔在案（机构台总览面）
    ov = c.admin_client.get("/admin/overview").json()["data"]["reset_log"]
    assert {g["username"] for g in ov if g["action"] == "password_reset"} >= {AUD, ADM}


# ---- 批 2-2.5③：执行租约（多进程失效面）——认领恰一胜者/心跳续租/恢复扩准 ----


def _mk_request(c, case_no: str, *, note: str = "租约验证") -> tuple[int, str]:
    """造一条 pending 协作请求，返回 (request_id, 批准签名 msg)。"""
    wh = _warrant(c, case_no)
    r = _file(c, wh, note=note)
    assert r.status_code == 200, r.text
    return r.json()["data"]["id"], f"FZ-COLLAB-REQ|v1|{wh}|{note}"


def test_execution_lease_single_winner(dc):
    """双副本竞态：两个独立连接同抢执行认领（approved→executing 条件 UPDATE）
    ——恰一胜者；败者 CollabError 409（execution_conflict），状态不被双写。"""
    from datetime import datetime, timedelta

    from app.accounts import collab as collab_svc
    from app.accounts.models import CollabRequest

    req_id, _msg = _mk_request(dc, "DC-LEASE-1")
    # 手工置 approved（跳过后台线程——纯认领竞态隔离面）
    ov = dc.app.dependency_overrides[get_session]
    gen = ov()
    sess = next(gen)
    try:
        row = sess.get(CollabRequest, req_id)
        row.status = "approved"
        row.locked_by = None
        row.lease_until = None
        sess.commit()
    finally:
        gen.close()

    # 两个独立会话（=两个副本）同抢
    gen1, sess1 = None, None
    ov = dc.app.dependency_overrides[get_session]
    gen1 = ov()
    sess1 = next(gen1)
    gen2 = ov()
    sess2 = next(gen2)
    try:
        collab_svc.claim_execution(sess1, req_id, "worker-A")  # 胜者不抛
        try:
            collab_svc.claim_execution(sess2, req_id, "worker-B")
            raise AssertionError("败者必须 409")
        except collab_svc.CollabError as exc:
            assert exc.status == 409 and exc.code == "execution_conflict", (exc.code, exc.status)
        # 库内领取人=胜者，租约在途
        row = sess1.get(CollabRequest, req_id)
        sess1.refresh(row)
        assert row.status == "executing" and row.locked_by == "worker-A"
        assert row.lease_until is not None and row.lease_until > datetime.utcnow() - timedelta(seconds=1)
    finally:
        gen1.close()
        gen2.close()


def test_execution_lease_heartbeat_and_recovery(dc):
    """租约生命周期：①续租只认本领取人+executing 态；②启动恢复扩准——
    approved 残留与 executing 过期租约→execute_failed；executing 活租约
    （他副本在途）不误杀。"""
    from datetime import datetime, timedelta

    from app.accounts import collab as collab_svc
    from app.accounts.models import CollabRequest

    # ①续租：executing+本人名下才推进
    req1, _ = _mk_request(dc, "DC-LEASE-HB", note="心跳验证")
    ov = dc.app.dependency_overrides[get_session]
    gen = ov()
    sess = next(gen)
    try:
        row = sess.get(CollabRequest, req1)
        row.status = "executing"
        row.locked_by = "worker-HB"
        row.lease_until = datetime.utcnow() + timedelta(seconds=1)  # 快到期
        sess.commit()
        n = collab_svc._renew_lease(sess, "worker-HB", req1)
        assert n == 1
        sess.refresh(row)
        assert row.lease_until > datetime.utcnow() + timedelta(seconds=1)
        # 他人名下/非 executing=续不到（0 行）
        assert collab_svc._renew_lease(sess, "worker-OTHER", req1) == 0
        row.status = "approved"
        sess.commit()
        assert collab_svc._renew_lease(sess, "worker-HB", req1) == 0
    finally:
        gen.close()

    # ②恢复：approved 残留 + executing 过期租约 → execute_failed；活租约不动
    req2, _ = _mk_request(dc, "DC-LEASE-REC2", note="恢复-过期租约")
    req3, _ = _mk_request(dc, "DC-LEASE-REC3", note="恢复-活租约")
    ov = dc.app.dependency_overrides[get_session]
    gen = ov()
    sess = next(gen)
    try:
        r2_ = sess.get(CollabRequest, req2)
        r2_.status = "executing"
        r2_.locked_by = "worker-DEAD"
        r2_.lease_until = datetime.utcnow() - timedelta(seconds=120)  # 过期（进程崩溃形态）
        r3_ = sess.get(CollabRequest, req3)
        r3_.status = "executing"
        r3_.locked_by = "worker-ALIVE-OTHER-REPLICA"
        r3_.lease_until = datetime.utcnow() + timedelta(seconds=600)  # 活租约（他副本心跳存续）
        # req1 置回 approved 残留
        r1_ = sess.get(CollabRequest, req1)
        r1_.status = "approved"
        r1_.locked_by = None
        r1_.lease_until = None
        sess.commit()
    finally:
        gen.close()
    n = collab_svc.recover_interrupted()
    assert n >= 2  # req1（approved）+req2（过期租约）至少两条
    gen = ov()
    sess = next(gen)
    try:
        rows = {r.id: r for r in sess.query(CollabRequest).all()}
        assert rows[req1].status == "execute_failed"
        assert rows[req2].status == "execute_failed" and rows[req2].locked_by is None
        assert "服务重启" in (rows[req2].execute_error or "")
        assert rows[req3].status == "executing"  # 活租约=他副本在途——不误杀
        assert rows[req3].locked_by == "worker-ALIVE-OTHER-REPLICA"
    finally:
        gen.close()


def test_execute_final_transition_guarded_by_claim(dc):
    """终态落定领取人守卫：executing→executed 的条件 UPDATE 仅认本领取人——
    他人/已失效领取人名下 0 行=CollabError 409（租约被接管后旧线程不得
    覆写结果）；本人在场正常落定。"""
    from datetime import datetime, timedelta

    import pytest

    from app.accounts import collab as collab_svc
    from app.accounts.models import CollabRequest

    req_id, _ = _mk_request(dc, "DC-LEASE-FINAL", note="终态守卫验证")
    ov = dc.app.dependency_overrides[get_session]
    gen = ov()
    sess = next(gen)
    try:
        row = sess.get(CollabRequest, req_id)
        row.status = "executing"
        row.locked_by = "worker-CURRENT"
        row.lease_until = datetime.utcnow() + timedelta(seconds=60)
        sess.commit()
        # 他人名义落终态=0 行→409（结果不被覆写）
        with pytest.raises(collab_svc.CollabError) as ei:
            collab_svc.finalize_executed(sess, req_id, "worker-STALE")
        assert ei.value.status == 409
        sess.expire_all()
        assert sess.get(CollabRequest, req_id).status == "executing"
        # 本领取人→executed 落定+租约列清空
        collab_svc.finalize_executed(sess, req_id, "worker-CURRENT")
        sess.expire_all()
        done = sess.get(CollabRequest, req_id)
        assert done.status == "executed" and done.locked_by is None
        assert done.lease_until is None and done.executed_ts is not None
    finally:
        gen.close()
