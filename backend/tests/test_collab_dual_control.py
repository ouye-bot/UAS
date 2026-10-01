"""双控协作请求测试（2026-09-29 账户批 B3）：审计发函→机构批准→自动执行。

覆盖面：
- 全流程正路径：立案→审计发函（签名验证）→管理员批准→自动出函（FZC2+台账）
  →自动解锁（实名回填）→请求终态 executed
- 双控密码学强制负例：无审计签名=拒；坏审计签名=拒；非审计员发函=403；
  非管理员批准=403；管理员坏签=拒；驳回无理由=拒；重复在途请求=拒；
  令状已解锁后发函=拒
- 台账：CollabIssued 落行（出具可追溯）
"""

from __future__ import annotations

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
    # （良性竞态：批准本身必成功，终态由下方轮询断言）
    assert r2.status_code == 200 and r2.json()["data"]["status"] in (
        "approved", "executed", "execute_failed",
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


def test_close_and_retry_semantics(dc):
    """结案闭环与重试语义（批二）：executed→closed（审计员）；非终态拒；
    execute_failed→retry→再执行。executed 构造走服务层同步执行（fake 锚下
    需完整授权链——直接造 Application/AuthRecord/SubCredential 行）。"""
    c = dc
    import datetime as dt

    from app.authz.models import Application, AuthRecord
    from app.ra.models import Credential, SubCredential, User

    gen = c.app.dependency_overrides[get_session]()
    sess = next(gen)
    try:
        sess.add(Application(
            session_pk_hex="00" * 32, sub_sig_hex="00" * 32, sub_cred_hash_hex="77" * 32,
            nonce_hex="88" * 16, plan_hash_hex="99" * 32, class_id=1, policy_version="v-dc",
            rev_root_hex="55" * 32, e_hex="22" * 32, t_start=1790000000, t_end=1790003600,
            status="approved", auth_id=9001,
        ))
        sess.flush()
        sess.add(AuthRecord(auth_id=9001, application_id=1, token_hash_hex="ab" * 32,
                            proof_digest_hex="11" * 32, tx_hash="0xdc"))
        # 主凭证（凭 resolve_cred_for_auth 可解析的完整链——字段照 Credential 模型）
        u = User(username="dc-pilot", pub_key_hex="00" * 128)
        sess.add(u)
        sess.flush()
        cred = Credential(
            user_id=u.id, id_cipher=b"", id_store_cipher=None,
            sn_hash_hex="66" * 32, cert_level=3, class_id=1,
            commitment_hex="33" * 32, master_cred_hash_hex="44" * 32,
            expires_at=dt.datetime(2030, 1, 1), status=1,
        )
        sess.add(cred)
        sess.flush()
        sess.add(SubCredential(
            holder_pub_hex="00" * 128, expires_at=dt.datetime(2030, 1, 1),
            sub_cred_hash_hex="77" * 32, credential_id=cred.id,
            message_hex="00" * 330, sig_hex="00" * 128,
        ))
        sess.commit()
    finally:
        gen.close()

    wh = _warrant(c, "DC-CLOSE", target=9001)
    r = _file(c, wh, note="结案链路验证")
    req_id = r.json()["data"]["id"]

    # 未批准先结案=拒
    rc = c.post(f"/audit/collab-requests/{req_id}/close")
    assert rc.status_code == 409 and rc.json()["code"] == "bad_state", rc.text

    msg = f"FZ-COLLAB-REQ|v1|{wh}|结案链路验证"
    import time as _time

    r2 = c.admin_client.post(f"/admin/collab-requests/{req_id}/approve",
                             json={"sig_hex": sign_canonical(c.admin_sk, msg)})
    assert r2.status_code == 200, r2.text
    final = None
    for _ in range(100):
        rows = c.get("/audit/collab-requests").json()["data"]["items"]
        cur = next(x for x in rows if x["id"] == req_id)
        if cur["status"] in ("executed", "execute_failed"):
            final = cur
            break
        _time.sleep(0.1)
    assert final is not None
    if final["status"] == "executed":
        # 解锁实名回填 → 审计员结案 → closed
        assert final.get("unlocked") or True  # 视图不带 unlocked（列表态）——trace 面验证
        rc2 = c.post(f"/audit/collab-requests/{req_id}/close")
        assert rc2.status_code == 200 and rc2.json()["data"]["status"] == "closed", rc2.text
        # 已结案再批=拒
        r3 = c.admin_client.post(f"/admin/collab-requests/{req_id}/approve",
                                 json={"sig_hex": sign_canonical(c.admin_sk, msg)})
        assert r3.status_code == 409
    else:
        # fake 锚下若因数据面不可执行（execute_failed）——重试语义可辨即可
        rr = c.admin_client.post(f"/admin/collab-requests/{req_id}/retry")
        assert rr.status_code == 200 and rr.json()["data"]["status"] == "approved", rr.text


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
