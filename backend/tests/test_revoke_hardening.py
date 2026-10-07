"""撤销业务线硬化验收（2026-10-04 B1/B4/B6/B7 批——先红后绿钉面）。

B1 撤销升格：理由≥4 字+admin SM2 签名（FZ-REVOKE|v1 域+纪元绑定）+
   revocations.revoked_by+append-only 台账（revocation_ledger）+公示叶
   reason/revoked_at/revoked_by；
B4 吊销联动授权轴：revoke 成功后解析该人名下在案未过期 authId 逐个
   revokeAuth（fake 档留痕断言）+ /authz/status 增 credential_revoked 兜底布尔；
B6 双控恢复：/ra/restore/request（admin）+ /ra/restore/{id}/countersign
   （auditor）——单签不执行/角色不符拒/已生效句柄拒/双签齐执行（摘叶+
   setStatus(1)+新纪元根+台账）；
B7 重注册禁入：SM3(id_number) 黑名单——被吊销证件号重登记 409 id_revoked_before，
   未命中/他人不受扰。
"""

from __future__ import annotations

import json
import secrets
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

import app.db as db_mod
from app.crypto.sm2 import generate_keypair, sign
from app.main import create_app
from app.ra import router as ra_router
from app.ra.models import Base, Revocation, RevocationLedger, RevokedIdBlacklist
from app.ra.service import (
    REASON_MIN,
    ChainAnchor,
    RaDeps,
    RaError,
    RaService,
    restore_countersign_msg,
    restore_msg,
    revoke_msg,
)

# ---- 服务层基建（test_ra_service 同型）----


class FakeAnchor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, list]] = []

    def __call__(self, fn: str, args: list) -> None:
        self.calls.append((fn, args))


@pytest.fixture()
def session():
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng, expire_on_commit=False)()
    try:
        yield s
    finally:
        s.close()


_ADMIN_SK, _ADMIN_PUB = generate_keypair()
_ADMIN = "admin-hard"


def _register(s, username="pilot-h", id_number="11010119900307999X", sn="UAS-SN-H1"):
    _, user_pub = generate_keypair()
    return s.register(
        username=username, id_number=id_number, cert_level=3, sn=sn, user_pub_hex=user_pub
    )


def _epoch_of(s) -> int:
    return max((r.epoch for r in s._s.scalars(select(Revocation))), default=0) + 1  # noqa: SLF001


def _revoke(s, handle: str, reason: str = "违规飞行实弹", ep: int | None = None):
    ep = _epoch_of(s) if ep is None else ep
    return s.revoke(
        master_cred_hash_hex=handle,
        reason=reason,
        admin_username=_ADMIN,
        admin_pub_hex=_ADMIN_PUB,
        admin_sig_hex=sign(_ADMIN_SK, revoke_msg([handle], reason, ep).encode()),
        epoch=ep,
    )


# ---- B1：签名仪式负例 + 台账/执行者落库 ----


def test_b1_revoke_signature_negatives(session):
    """无签名/短理由/纪元错/换签人=四拒——零执行副作用（撤销不再无理由无签名）。"""
    s = RaService(
        session,
        RaDeps(
            ra_priv_hex=generate_keypair()[0],
            ra_pub_hex=generate_keypair()[1],
            anchor=ChainAnchor(call=FakeAnchor()),
        ),
    )
    reg = _register(s, "pilot-sig")
    h = reg["master_cred_hash_hex"]
    ep = _epoch_of(s)
    other_sk, other_pk = generate_keypair()
    # ① 无签名
    with pytest.raises(RaError) as e1:
        s.revoke(
            master_cred_hash_hex=h,
            reason="违规飞行实弹",
            admin_username=_ADMIN,
            admin_pub_hex=_ADMIN_PUB,
            admin_sig_hex="",
            epoch=ep,
        )
    assert e1.value.code == "bad_sig"
    # ② 理由 <4 字
    with pytest.raises(RaError) as e2:
        s.revoke(
            master_cred_hash_hex=h,
            reason="短",
            admin_username=_ADMIN,
            admin_pub_hex=_ADMIN_PUB,
            admin_sig_hex=sign(_ADMIN_SK, revoke_msg([h], "短", ep).encode()),
            epoch=ep,
        )
    assert e2.value.code == "reason_required"
    assert len("短") < REASON_MIN
    # ③ 纪元错（声明 epoch 与服务端推导不符）
    with pytest.raises(RaError) as e3:
        s.revoke(
            master_cred_hash_hex=h,
            reason="违规飞行实弹",
            admin_username=_ADMIN,
            admin_pub_hex=_ADMIN_PUB,
            admin_sig_hex=sign(_ADMIN_SK, revoke_msg([h], "违规飞行实弹", ep + 5).encode()),
            epoch=ep + 5,
        )
    assert e3.value.code == "bad_epoch"
    # ④ 钥-签错配（sig 出自他钥、验签用 admin 公钥——身份绑定在路由层
    # 账户公钥查询，服务层只认「所声明公钥⇄签名」一致性）
    with pytest.raises(RaError) as e4:
        s.revoke(
            master_cred_hash_hex=h,
            reason="违规飞行实弹",
            admin_username=_ADMIN,
            admin_pub_hex=_ADMIN_PUB,
            admin_sig_hex=sign(other_sk, revoke_msg([h], "违规飞行实弹", ep).encode()),
            epoch=ep,
        )
    assert e4.value.code == "bad_sig"
    # 零副作用：无叶、无台账
    assert session.scalars(select(Revocation)).all() == []
    assert session.scalars(select(RevocationLedger)).all() == []


def test_b1_revoke_writes_ledger_actor_and_blacklist_column(session):
    """正例：撤销落 revoked_by+台账（actor/sig/reason/epoch/detail.handles）。"""
    s = RaService(
        session,
        RaDeps(
            ra_priv_hex=generate_keypair()[0],
            ra_pub_hex=generate_keypair()[1],
            anchor=ChainAnchor(call=FakeAnchor()),
        ),
    )
    reg = _register(s, "pilot-ledger")
    out = _revoke(s, reg["master_cred_hash_hex"], "台账留痕实弹")
    rows = session.scalars(select(RevocationLedger)).all()
    assert len(rows) == 1
    row = rows[0]
    assert row.action == "revoke" and row.actor == _ADMIN and row.epoch == out["epoch"]
    assert row.subject_hex == reg["master_cred_hash_hex"] and row.reason == "台账留痕实弹"
    assert row.sig_hex and len(row.detail) > 2
    assert reg["master_cred_hash_hex"] in json.loads(row.detail)["handles"]
    leaves = session.scalars(select(Revocation)).all()
    assert leaves and all(r.revoked_by == _ADMIN for r in leaves)


# ---- B4：吊销联动授权轴 ----


def _seed_auth(session, sub_hash: str, auth_id: int, t_end: int) -> None:
    from app.authz.models import Application, AuthRecord

    app = Application(
        session_pk_hex=generate_keypair()[1],
        sub_sig_hex="ab" * 64,
        sub_cred_hash_hex=sub_hash,
        nonce_hex="00" * 16,
        plan_hash_hex="11" * 32,
        class_id=1,
        policy_version="test",
        rev_root_hex="22" * 32,
        status="approved",
        auth_id=auth_id,
        t_start=0,
        t_end=t_end,
    )
    session.add(app)
    session.flush()
    session.add(
        AuthRecord(
            auth_id=auth_id,
            application_id=app.id,
            token_hash_hex=secrets.token_hex(32),
            proof_digest_hex="dd" * 32,
        )
    )
    session.commit()


def test_b4_revoke_links_authz_axis(session):
    """撤销联动授权轴：在案未过期 authId 逐个 revokeAuth；过期项如实跳过；
    清单随响应与台账 detail 返回。"""
    linked_calls: list[int] = []

    def _link(aid: int) -> dict:
        linked_calls.append(aid)
        return {"ok": True, "detail": "fake 联动"}

    anchor = FakeAnchor()
    svc = RaService(
        session,
        RaDeps(
            ra_priv_hex=generate_keypair()[0],
            ra_pub_hex=generate_keypair()[1],
            anchor=ChainAnchor(call=anchor),
            auth_revoke=_link,
        ),
    )
    reg = _register(svc, "pilot-link")
    _, holder = generate_keypair()
    sub = svc.issue_sub_credential(
        master_cred_hash_hex=reg["master_cred_hash_hex"],
        salt_hex=reg["salt_hex"],
        id_number="11010119900307999X",
        cert_level=3,
        sn="UAS-SN-H1",
        holder_pub_hex=holder,
    )
    now = int(time.time())
    _seed_auth(session, sub["sub_cred_hash_hex"], 9001, now + 3600)  # 在案未过期
    _seed_auth(session, sub["sub_cred_hash_hex"], 9002, now - 10)  # 已过期→跳过
    out = _revoke(svc, reg["master_cred_hash_hex"])
    assert out["linked_auth_ids"] == [9001], "未过期在案授权须被联动"
    assert 9002 not in out["linked_auth_ids"], "过期授权不在联动范围"
    assert linked_calls == [9001], "过期授权不得发起链上 revokeAuth"
    detail = json.loads(session.scalars(select(RevocationLedger)).all()[0].detail)
    assert detail["linked_auth_ids"] == [9001]


# ---- HTTP 面（fake 链档）----


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "fake")
    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(tmp_path))
    monkeypatch.setenv(
        "FZ_ZKSVC_DIR", str(__import__("pathlib").Path(__file__).resolve().parents[2] / "zksvc")
    )
    db_file = tmp_path / "revoke_hardening.db"
    monkeypatch.setattr(db_mod, "_DB_PATH", db_file)
    engine = db_mod.create_engine(f"sqlite:///{db_file}")
    db_mod._engine = engine
    db_mod.SessionLocal = db_mod.sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    ra_router._reset_deps_cache()
    from app.authz import router as authz_router

    authz_router._DEPS = None
    global _HTTP_ADMIN_SK, _HTTP_AUDITOR_SK, _AUD  # noqa: PLW0603
    with TestClient(create_app()) as c:
        from tests.accounting import register_and_login

        # 双会话分 Jar：admin 持 client；auditor 独立客户端（同 app 各自 Cookie）
        _HTTP_ADMIN_SK = register_and_login(c, "admin_hd", "admin", "Admin-Pass-1")
        _AUD = TestClient(c.app)
        _HTTP_AUDITOR_SK = register_and_login(_AUD, "auditor_hd", "auditor", "Audit-Pass-1")
        yield c
    authz_router._DEPS = None
    ra_router._reset_deps_cache()


_HTTP_ADMIN_SK = ""
_HTTP_AUDITOR_SK = ""
_AUD: TestClient | None = None


def _http_register(client, username, id_number="110101199001011234", sn=None):
    _, pk = generate_keypair()
    r = client.post(
        "/ra/register",
        json={
            "username": username,
            "id_number": id_number,
            "cert_level": 3,
            "sn": sn or ("FZ-SN-HD-" + secrets.token_hex(3)),
            "user_pub_hex": pk,
            "class_id": 1,
        },
    )
    assert r.status_code == 200, r.text
    return r.json()["data"]


def _http_epoch(client) -> int:
    return client.get("/ra/revocation/snapshot").json()["data"]["epoch"] + 1


def _http_revoke_username(client, username, handles, reason="按人级联实弹"):
    from tests.accounting import sign_revoke_body

    return client.post(
        "/ra/revoke/by-username",
        json={
            "username": username,
            **sign_revoke_body(_HTTP_ADMIN_SK, handles, reason, _http_epoch(client)),
        },
    )


def test_b4_authz_status_credential_revoked_flag(client):
    """/authz/status 兜底布尔：撤销前 False→撤销后 True（凭证轴镜像）。"""
    from tests.accounting import sign_revoke_body

    sn = "FZ-SN-HD-STATUS"
    reg = _http_register(client, "hd-status", sn=sn)
    h = reg["master_cred_hash_hex"]
    _, holder = generate_keypair()
    sub_r = client.post(
        "/ra/sub-credentials",
        json={
            "master_cred_hash_hex": h,
            "salt_hex": reg["salt_hex"],
            "id_number": "110101199001011234",
            "cert_level": 3,
            "sn": sn,
            "holder_pub_hex": holder,
        },
    )
    assert sub_r.status_code == 200, sub_r.text
    sub = sub_r.json()["data"]
    # 授权登记（fake 档链面跳过——本地镜像照常回读）
    s = db_mod.SessionLocal()
    try:
        _seed_auth(s, sub["sub_cred_hash_hex"], 9100, int(time.time()) + 3600)
    finally:
        s.close()
    d0 = client.get("/authz/status", params={"auth_id": 9100}).json()["data"]
    assert d0["credential_revoked"] is False
    rv = client.post(
        "/ra/revoke",
        json={
            "master_cred_hash_hex": h,
            **sign_revoke_body(_HTTP_ADMIN_SK, [h], "兜底布尔实弹", _http_epoch(client)),
        },
    )
    assert rv.status_code == 200, rv.text
    assert rv.json()["data"]["linked_auth_ids"] == [9100], "fake 档联动须留痕并回清单"
    d1 = client.get("/authz/status", params={"auth_id": 9100}).json()["data"]
    assert d1["credential_revoked"] is True, "凭证吊销后 /authz/status 兜底布尔须为真"


def test_b1_http_wrong_signer_rejected(client):
    "B1 HTTP 边界：非 admin 账户钥签名的撤销=401 bad_sig（身份绑定=会话账户公钥）。"
    from tests.accounting import sign_revoke_body

    reg = _http_register(client, "hd-wrongsigner")
    h = reg["master_cred_hash_hex"]
    epoch0 = client.get("/ra/revocation/snapshot").json()["data"]["epoch"]
    stranger_sk, _ = generate_keypair()
    r = client.post(
        "/ra/revoke",
        json={
            "master_cred_hash_hex": h,
            **sign_revoke_body(stranger_sk, [h], "冒名撤销实弹", epoch0 + 1),
        },
    )
    assert r.status_code == 401 and r.json()["code"] == "bad_sig", r.text
    epoch1 = client.get("/ra/revocation/snapshot").json()["data"]["epoch"]
    assert epoch1 == epoch0, "拒绝的撤销不得产生纪元副作用"


def test_b6_restore_dual_control(client):
    """B6 全路径：单签不执行→双签执行（摘叶+setStatus(1)+新纪元根+台账）。"""
    from tests.accounting import restore_sig, sign_revoke_body

    reg = _http_register(client, "hd-restore")
    h = reg["master_cred_hash_hex"]
    rv = client.post(
        "/ra/revoke",
        json={
            "master_cred_hash_hex": h,
            **sign_revoke_body(_HTTP_ADMIN_SK, [h], "恢复实弹前置吊销", _http_epoch(client)),
        },
    )
    assert rv.status_code == 200, rv.text
    snap_revoked = client.get("/ra/revocation/snapshot").json()["data"]
    assert h in snap_revoked["revoked_handles_hex"]
    reason = "撤销有误申请恢复实弹"
    # ① admin 发起（FZ-RESTORE|v1 签名）→ pending
    req = client.post(
        "/ra/restore/request",
        json={"handle_hex": h, "reason": reason, "sig_hex": restore_sig(_HTTP_ADMIN_SK, h, reason)},
    )
    assert req.status_code == 200, req.text
    rid = req.json()["data"]["id"]
    assert req.json()["data"]["status"] == "pending"
    # ② 单签不执行：句柄仍在撤销集、凭证轴未复活、无 set_status(1) 链调用
    snap_pending = client.get("/ra/revocation/snapshot").json()["data"]
    assert h in snap_pending["revoked_handles_hex"], "单签阶段不得摘叶"
    assert not any(
        c[0] == "set_status" and c[1] == ["0x" + h, 1]
        for c in ra_router._ra_deps().anchor.call.calls
    ), "单签阶段不得上链恢复"
    # ③ 复核负例：admin 到不了 auditor 端点（角色守卫 403）
    r403 = client.post(
        f"/ra/restore/{rid}/countersign",
        json={"sig_hex": restore_sig(_HTTP_ADMIN_SK, h, reason, countersign=True)},
    )
    assert r403.status_code == 403
    # ④ 坏复核签名=401
    r401 = _AUD.post(f"/ra/restore/{rid}/countersign", json={"sig_hex": "00" * 64})
    assert r401.status_code == 401 and r401.json()["code"] == "bad_sig"
    # ⑤ auditor 双签复核（FZ-RESTORE-COUNTERSIGN|v1）→ 执行
    cs = _AUD.post(
        f"/ra/restore/{rid}/countersign",
        json={"sig_hex": restore_sig(_HTTP_AUDITOR_SK, h, reason, countersign=True)},
    )
    assert cs.status_code == 200, cs.text
    assert cs.json()["data"]["status"] == "executed"
    assert cs.json()["data"]["countersign_by"] == "auditor_hd"
    # ⑥ 摘叶+新纪元根+链面 setStatus(1)
    snap_done = client.get("/ra/revocation/snapshot").json()["data"]
    assert h not in snap_done["revoked_handles_hex"], "恢复后句柄必须摘出撤销集"
    assert snap_done["epoch"] >= snap_revoked["epoch"] + 1, "恢复必须推进公示纪元"
    assert any(
        c[0] == "set_status" and c[1] == ["0x" + h, 1]
        for c in ra_router._ra_deps().anchor.call.calls
    ), "恢复须链上 setStatus(handle,1)"
    # ⑦ 台账 restore 行
    from app.db import SessionLocal as _SL

    s = _SL()
    try:
        led = s.scalars(select(RevocationLedger).where(RevocationLedger.action == "restore")).all()
        assert len(led) == 1 and led[0].actor == "auditor_hd"
        assert json.loads(led[0].detail)["requested_by"] == "admin_hd"
    finally:
        s.close()


def test_b6_restore_negatives(client):
    """负例组：未吊销句柄拒/重复在途拒/已执行句柄再恢复拒/发起人自复核拒。"""
    from tests.accounting import restore_sig, sign_revoke_body

    reg = _http_register(client, "hd-restore-neg")
    h = reg["master_cred_hash_hex"]
    # 未吊销句柄=409（无恢复对象）
    reason = "未吊销句柄试探实弹"
    r0 = client.post(
        "/ra/restore/request",
        json={"handle_hex": h, "reason": reason, "sig_hex": restore_sig(_HTTP_ADMIN_SK, h, reason)},
    )
    assert r0.status_code == 409 and r0.json()["code"] == "not_revoked"
    # 正常吊销→发起
    rv = client.post(
        "/ra/revoke",
        json={
            "master_cred_hash_hex": h,
            **sign_revoke_body(_HTTP_ADMIN_SK, [h], "负例组前置吊销", _http_epoch(client)),
        },
    )
    assert rv.status_code == 200, rv.text
    r1 = client.post(
        "/ra/restore/request",
        json={"handle_hex": h, "reason": reason, "sig_hex": restore_sig(_HTTP_ADMIN_SK, h, reason)},
    )
    assert r1.status_code == 200, r1.text
    rid = r1.json()["data"]["id"]
    # 同句柄重复在途=409
    r2 = client.post(
        "/ra/restore/request",
        json={"handle_hex": h, "reason": reason, "sig_hex": restore_sig(_HTTP_ADMIN_SK, h, reason)},
    )
    assert r2.status_code == 409 and r2.json()["code"] == "restore_pending"
    # 发起人（admin）不能自复核——角色守卫先行 403
    r3 = client.post(
        f"/ra/restore/{rid}/countersign",
        json={"sig_hex": restore_sig(_HTTP_ADMIN_SK, h, reason, countersign=True)},
    )
    assert r3.status_code == 403
    # auditor 以「发起」域签名复核=坏签（消息域分立——跨域挪用即验签失败）
    r4 = _AUD.post(
        f"/ra/restore/{rid}/countersign",
        json={"sig_hex": restore_sig(_HTTP_AUDITOR_SK, h, reason, countersign=False)},
    )
    assert r4.status_code == 401 and r4.json()["code"] == "bad_sig"
    # 正确双签执行
    r5 = _AUD.post(
        f"/ra/restore/{rid}/countersign",
        json={"sig_hex": restore_sig(_HTTP_AUDITOR_SK, h, reason, countersign=True)},
    )
    assert r5.status_code == 200, r5.text
    # 已生效句柄再发起恢复=409（无恢复对象）
    r6 = client.post(
        "/ra/restore/request",
        json={"handle_hex": h, "reason": reason, "sig_hex": restore_sig(_HTTP_ADMIN_SK, h, reason)},
    )
    assert r6.status_code == 409 and r6.json()["code"] == "not_revoked"
    # 已 executed 请求再复核=409
    r7 = _AUD.post(
        f"/ra/restore/{rid}/countersign",
        json={"sig_hex": restore_sig(_HTTP_AUDITOR_SK, h, reason, countersign=True)},
    )
    assert r7.status_code == 409 and r7.json()["code"] == "bad_state"


def test_b7_revoked_id_reregistration_banned(client):
    """B7：吊销后同证件号重登记=409 id_revoked_before；他证件号/他人不受扰。"""
    from tests.accounting import sign_revoke_body

    idn = "110101199001011234"
    reg = _http_register(client, "hd-b7-a", id_number=idn)
    h = reg["master_cred_hash_hex"]
    rv = client.post(
        "/ra/revoke",
        json={
            "master_cred_hash_hex": h,
            **sign_revoke_body(_HTTP_ADMIN_SK, [h], "重注册禁入实弹", _http_epoch(client)),
        },
    )
    assert rv.status_code == 200, rv.text
    # 同证件号重登记=409
    r2 = client.post(
        "/ra/register",
        json={
            "username": "hd-b7-b",
            "id_number": idn,
            "cert_level": 3,
            "sn": "FZ-SN-HD-B7B",
            "user_pub_hex": generate_keypair()[1],
            "class_id": 1,
        },
    )
    assert r2.status_code == 409, r2.text
    assert r2.json()["code"] == "id_revoked_before"
    assert "禁止重新登记" in r2.json()["message"]
    # 其他证件号正常登记（黑名单不外溢）
    r3 = client.post(
        "/ra/register",
        json={
            "username": "hd-b7-c",
            "id_number": "110101199001019999",
            "cert_level": 3,
            "sn": "FZ-SN-HD-B7C",
            "user_pub_hex": generate_keypair()[1],
            "class_id": 1,
        },
    )
    assert r3.status_code == 200, r3.text
    # 黑名单行=SM3(id_number)，库内零明文
    from app.crypto.sm3 import sm3_bytes
    from app.db import SessionLocal as _SL

    s = _SL()
    try:
        rows = s.scalars(select(RevokedIdBlacklist)).all()
        assert len(rows) == 1
        assert rows[0].id_number_hash_hex == sm3_bytes(idn.encode()).hex()
    finally:
        s.close()


def test_b7_by_username_revocation_blacklists_and_bans(client):
    """按人级联吊销后：该人全部凭证的证件号入黑名单+重登记禁入（B7×B-P2-5）。"""

    idn = "11010119900307111X"
    reg = _http_register(client, "hd-b7-cascade", id_number=idn, sn="FZ-SN-HD-CA1")
    rv = _http_revoke_username(client, "hd-b7-cascade", [reg["master_cred_hash_hex"]])
    assert rv.status_code == 200, rv.text
    r2 = client.post(
        "/ra/register",
        json={
            "username": "hd-b7-cascade-2",
            "id_number": idn,
            "cert_level": 3,
            "sn": "FZ-SN-HD-CA2",
            "user_pub_hex": generate_keypair()[1],
            "class_id": 1,
        },
    )
    assert r2.status_code == 409 and r2.json()["code"] == "id_revoked_before"


def test_b1_revoke_message_domain_binding(session):
    """消息域分立：恢复域签名不可当撤销签名用（跨域挪用=验签失败）。"""
    svc = RaService(
        session,
        RaDeps(
            ra_priv_hex=generate_keypair()[0],
            ra_pub_hex=generate_keypair()[1],
            anchor=ChainAnchor(call=FakeAnchor()),
        ),
    )
    reg = _register(svc, "pilot-domain")
    h = reg["master_cred_hash_hex"]
    reason = "跨域挪用防实弹"
    with pytest.raises(RaError) as e:
        svc.revoke(
            master_cred_hash_hex=h,
            reason=reason,
            admin_username=_ADMIN,
            admin_pub_hex=_ADMIN_PUB,
            admin_sig_hex=sign(_ADMIN_SK, restore_msg(h, reason).encode()),
            epoch=_epoch_of(svc),
        )
    assert e.value.code == "bad_sig"
    assert restore_countersign_msg(h, reason).startswith("FZ-RESTORE-COUNTERSIGN|v1|")


def test_b6_restore_rejects_subkey_leaf(client):
    """子钥传播叶（pk′.x）不可发起恢复——恢复语义仅限主凭证句柄。"""
    from tests.accounting import restore_sig, sign_revoke_body

    sn = "FZ-SN-HD-SUBLEAF"
    reg = _http_register(client, "hd-subleaf", sn=sn)
    h = reg["master_cred_hash_hex"]
    _, holder = generate_keypair()
    r_sub = client.post(
        "/ra/sub-credentials",
        json={
            "master_cred_hash_hex": h,
            "salt_hex": reg["salt_hex"],
            "id_number": "110101199001011234",
            "cert_level": 3,
            "sn": sn,
            "holder_pub_hex": holder,
        },
    )
    assert r_sub.status_code == 200, r_sub.text
    rv = client.post(
        "/ra/revoke",
        json={
            "master_cred_hash_hex": h,
            **sign_revoke_body(_HTTP_ADMIN_SK, [h], "子钥叶恢复试探前置", _http_epoch(client)),
        },
    )
    assert rv.status_code == 200, rv.text
    snap = client.get("/ra/revocation/snapshot").json()["data"]
    subkey_leaf = next(x for x in snap["revoked_handles_hex"] if x != h)
    reason = "子钥叶恢复试探实弹"
    r0 = client.post(
        "/ra/restore/request",
        json={
            "handle_hex": subkey_leaf,
            "reason": reason,
            "sig_hex": restore_sig(_HTTP_ADMIN_SK, subkey_leaf, reason),
        },
    )
    assert r0.status_code == 409 and r0.json()["code"] == "not_restorable", r0.text


# ---- 角色门与两步式预览（2026-10-04 审计/机构台前端升格配套）----


def test_restore_requests_role_gate_admin_and_auditor(client):
    """GET /ra/restore/requests 角色门放宽（前端升格第 7 条）：admin 200/
    auditor 200（复核前须看待复核列表——句柄/理由/发起人在复核侧可见）/
    pilot 403。"""
    from tests.accounting import register_and_login

    r_admin = client.get("/ra/restore/requests")
    assert r_admin.status_code == 200, r_admin.text
    assert _AUD is not None
    r_aud = _AUD.get("/ra/restore/requests")
    assert r_aud.status_code == 200, r_aud.text
    assert r_aud.json()["data"]["items"] == []
    pilot = TestClient(client.app)
    register_and_login(pilot, "pilot_restore_gate", "pilot", "Pilot-Pass-1")
    r_pilot = pilot.get("/ra/restore/requests")
    assert r_pilot.status_code == 403 and r_pilot.json()["detail"]["code"] == "forbidden"


def test_revoke_preview_two_step(client):
    """按人吊销·两步式（前端升格 B1 配套）：GET /ra/revoke/by-username/preview
    （admin）返回该用户全部有效凭证句柄（字典序，与 revoke_msg 排序口径一致）
    +目标纪元（=公示纪元+1）→句柄直喂正式端点即成功闭环；预览只读（撤销后
    无有效凭证=bad_input，与正式端点同判同码）；未知用户 404；auditor 到不了
    预览（403）。"""
    from tests.accounting import sign_revoke_body

    reg = _http_register(client, "hd-preview")
    h = reg["master_cred_hash_hex"].lower()
    r = client.get("/ra/revoke/by-username/preview", params={"username": "hd-preview"})
    assert r.status_code == 200, r.text
    d = r.json()["data"]
    assert d["username"] == "hd-preview"
    assert d["handles"] == [h]
    ep = d["epoch"]
    assert ep == _http_epoch(client)
    # 两步闭环：预览句柄+纪元 → 拼消息签名 → 正式端点成功
    rv = client.post(
        "/ra/revoke/by-username",
        json={
            "username": "hd-preview",
            **sign_revoke_body(_HTTP_ADMIN_SK, d["handles"], "预览两步实弹", ep),
        },
    )
    assert rv.status_code == 200, rv.text
    assert rv.json()["data"]["revoked_handles_hex"] == [reg["master_cred_hash_hex"]]
    # 撤销后预览：无有效凭证=409（与正式端点同判）；未知用户=404
    r2 = client.get("/ra/revoke/by-username/preview", params={"username": "hd-preview"})
    assert r2.status_code == 400 and r2.json()["code"] == "bad_input"
    r3 = client.get("/ra/revoke/by-username/preview", params={"username": "nope"})
    assert r3.status_code == 404
    # 角色门：auditor/pilot 到不了预览（admin 专项）
    assert _AUD is not None
    assert (
        _AUD.get("/ra/revoke/by-username/preview", params={"username": "hd-preview"}).status_code
        == 403
    )
