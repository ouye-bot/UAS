"""多机构一期授权面 org 域隔离硬化验收（2026-10-10 ⑦复评 §1.2 缺口+§5.3 立即
执行项——先红后绿钉面）。

缺口（复评锚 A7）：revoke / revoke-by-username（含 preview 两步式第一拍）/
restore 双控（request+countersign）/ issue-sub-credential 的 API 面只有角色
守卫（accounts/deps.py 只查 role 不查 org）——任一机构管理员可对**他机构**
凭证签名吊销并无条件推动共享树全局换纪元。

修法（§5.3 一字不差）：ra 服务层补 org 归属校验——目标凭证归属域==
操作者账户 org_id，跨域 403 org_forbidden fail-closed，判词带双域信息
（目标凭证归属域/操作者域）便于审计。

本文件的「无操作者域上下文」口径（operator_org_id=None）：HTTP 授权边界
（路由层）恒传会话主体域（accounts.org_id NOT NULL server_default=org-a）；
None 仅存在于服务层直调测试形态与**匿名原像路径**（/ra/sub-credentials 飞手
自持原像知识认证——B2-d4 既有设计，e2e_cross_org [X3]/[Z2] 用户侧流程语义，
不归本门管）。None=按现行行为放行的决策依据详见提交信息。
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

import app.db as db_mod
from app.accounts.models import Account
from app.crypto.sm2 import generate_keypair, sign
from app.main import create_app
from app.ra import router as ra_router
from app.ra.models import (
    Base,
    Credential,
    RestoreRequest,
    Revocation,
    User,
)
from app.ra.service import (
    ChainAnchor,
    RaDeps,
    RaError,
    RaService,
    restore_countersign_msg,
    restore_msg,
    revoke_msg,
)

# ---- 服务层基建（test_revoke_hardening 同型：FakeAnchor+内存库）----


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


def _svc(session) -> RaService:
    ra_priv, ra_pub = generate_keypair()
    return RaService(
        session,
        RaDeps(ra_priv_hex=ra_priv, ra_pub_hex=ra_pub, anchor=ChainAnchor(call=FakeAnchor())),
    )


def _register(
    s: RaService,
    username="pilot-org",
    org_id="org-a",
    sn="UAS-SN-ORG-1",
    id_number="11010119900307999X",
) -> dict:
    _, user_pub = generate_keypair()
    return s.register(
        username=username,
        id_number=id_number,
        cert_level=3,
        sn=sn,
        user_pub_hex=user_pub,
        org_id=org_id,
    )


_ADMIN_SK, _ADMIN_PUB = generate_keypair()
_ADMIN = "admin-org"
_AUD_SK, _AUD_PUB = generate_keypair()
_AUD = "auditor-org"


def _seed_accounts(session) -> None:
    """服务层直调形态的签名账户（restore 双控经 accounts 表取钥——_account_pub）。"""
    session.add(Account(username=_ADMIN, role="admin", status="active", pubkey_hex=_ADMIN_PUB))
    session.add(Account(username=_AUD, role="auditor", status="active", pubkey_hex=_AUD_PUB))
    session.flush()


def _epoch_of(s: RaService) -> int:
    led = s._s.scalar(select(Revocation.epoch).order_by(Revocation.epoch.desc()).limit(1))  # noqa: SLF001
    return (int(led) if led is not None else 0) + 1


def _signed_revoke(
    s: RaService,
    handle: str,
    reason: str,
    *,
    operator_org_id: str | None,
) -> dict:
    return s.revoke(
        master_cred_hash_hex=handle,
        reason=reason,
        admin_username=_ADMIN,
        admin_pub_hex=_ADMIN_PUB,
        admin_sig_hex=sign(_ADMIN_SK, revoke_msg([handle], reason, _epoch_of(s)).encode()),
        epoch=_epoch_of(s),
        operator_org_id=operator_org_id,
    )


# ---- 负例一等公民：跨域 403 fail-closed（先红）----


def test_org_guard_revoke_cross_domain_denied(session):
    """org-b 管理员吊销 org-a 凭证 → 403 org_forbidden，判词带双域；零副作用
    （不上链不落叶不换纪元——复评 §1.2「越权吊销推全局根」缺口封堵实证）。"""
    s = _svc(session)
    reg = _register(s)
    h = reg["master_cred_hash_hex"]
    anchor = s._d.anchor  # noqa: SLF001
    with pytest.raises(RaError) as e:
        _signed_revoke(s, h, "跨域越权吊销实弹", operator_org_id="org-b")
    assert e.value.code == "org_forbidden"
    assert getattr(e.value, "status", None) == 403
    msg = str(e.value)
    assert "org-a" in msg and "org-b" in msg, f"判词须带双域（目标域/操作者域）: {msg}"
    # 零副作用：除注册登记外零链调用（无 setStatus/setRevocationRoot/机构锚）、
    # 无撤销叶、凭证轴未动
    assert [c[0] for c in anchor.call.calls] == ["register_commitment"], (
        "跨域拒绝不得产生任何撤销链上副作用"
    )
    assert session.scalars(select(Revocation)).all() == []
    cred = session.scalar(select(Credential).where(Credential.master_cred_hash_hex == h))
    assert cred.status == 1


def test_org_guard_revoke_same_domain_allowed(session):
    """同域正例不误伤：org-a 操作者对 org-a 凭证吊销照常成功（450 基线语义）。"""
    s = _svc(session)
    reg = _register(s)
    out = _signed_revoke(
        s, reg["master_cred_hash_hex"], "本域合规吊销实弹", operator_org_id="org-a"
    )
    assert out["epoch"] >= 1 and out["ledger_id"] > 0


def test_org_guard_org_b_pair_symmetric(session):
    """双域对称：org-b 操作者管 org-b 用户=放行；org-a 操作者管 org-b 用户=403。"""
    s = _svc(session)
    reg_b = _register(s, "pilot-org-b", org_id="org-b", sn="UAS-SN-ORG-B")
    out = _signed_revoke(
        s, reg_b["master_cred_hash_hex"], "B 域管理员本域吊销", operator_org_id="org-b"
    )
    assert out["ledger_id"] > 0
    reg_b2 = _register(
        s, "pilot-org-b2", org_id="org-b", sn="UAS-SN-ORG-B2", id_number="110101199004045678"
    )
    with pytest.raises(RaError) as e:
        _signed_revoke(
            s, reg_b2["master_cred_hash_hex"], "A 域越权吊销 B 域", operator_org_id="org-a"
        )
    assert e.value.code == "org_forbidden" and getattr(e.value, "status", None) == 403


def test_org_guard_revoke_by_username_and_preview_cross(session):
    """按人级联（含两步式 preview 第一拍）：org-b 操作者对 org-a 用户 → 403 双域。"""
    s = _svc(session)
    reg = _register(s, "pilot-byname")
    with pytest.raises(RaError) as ep:
        s.revoke_preview_by_username(username="pilot-byname", operator_org_id="org-b")
    assert ep.value.code == "org_forbidden"
    with pytest.raises(RaError) as e:
        s.revoke_by_username(
            username="pilot-byname",
            reason="跨域按人吊销实弹",
            admin_username=_ADMIN,
            admin_pub_hex=_ADMIN_PUB,
            admin_sig_hex=sign(
                _ADMIN_SK,
                revoke_msg(
                    [reg["master_cred_hash_hex"]], "跨域按人吊销实弹", _epoch_of(s)
                ).encode(),
            ),
            epoch=_epoch_of(s),
            operator_org_id="org-b",
        )
    assert e.value.code == "org_forbidden"
    msg = str(e.value)
    assert "org-a" in msg and "org-b" in msg, f"判词须带双域: {msg}"
    cred = session.scalar(
        select(Credential).where(Credential.master_cred_hash_hex == reg["master_cred_hash_hex"])
    )
    assert cred.status == 1, "跨域拒绝不得改凭证轴状态"


def test_org_guard_issue_sub_credential_cross(session):
    """子凭证签发归属语义（任务点④）：已登录 org-b 操作者对 org-a 凭证签发=403；
    匿名原像路径（operator_org_id=None——飞手自持原像知识认证，用户侧流程）
    不误伤照常签发；org-a 操作者对 org-a 凭证=放行。"""
    s = _svc(session)
    reg = _register(s)
    kw = {
        "master_cred_hash_hex": reg["master_cred_hash_hex"],
        "salt_hex": reg["salt_hex"],
        "id_number": "11010119900307999X",
        "cert_level": 3,
        "sn": "UAS-SN-ORG-1",
    }
    _, holder_pub = generate_keypair()
    with pytest.raises(RaError) as e:
        s.issue_sub_credential(holder_pub_hex=holder_pub, operator_org_id="org-b", **kw)
    assert e.value.code == "org_forbidden" and getattr(e.value, "status", None) == 403
    # 匿名原像路径（None）——用户侧流程语义在岗
    out_anon = s.issue_sub_credential(holder_pub_hex=holder_pub, operator_org_id=None, **kw)
    assert out_anon["sub_cred_hash_hex"]
    # 同域已登录操作者=放行
    _, holder2 = generate_keypair()
    out_same = s.issue_sub_credential(holder_pub_hex=holder2, operator_org_id="org-a", **kw)
    assert out_same["sub_cred_hash_hex"]


def test_org_guard_restore_dual_control_cross(session):
    """恢复双控归属（§1.2 同构缺口：router.py:533-572 两腿）：org-a 句柄由
    org-b 管理员发起恢复=403；org-a 管理员发起 pending 后 org-b 审计员复核=403
    且不执行（句柄仍在撤销集）；org-a 审计员复核=执行。"""
    s = _svc(session)
    _seed_accounts(session)
    reg = _register(s, "pilot-restore")
    h = reg["master_cred_hash_hex"]
    _signed_revoke(s, h, "恢复双控前置吊销", operator_org_id="org-a")
    reason = "跨域恢复试探实弹"
    b_sk, _b_pub = generate_keypair()
    with pytest.raises(RaError) as e1:
        s.restore_request(
            handle_hex=h,
            reason=reason,
            admin_username="admin-b-x",
            admin_sig_hex=sign(b_sk, restore_msg(h, reason).encode()),
            operator_org_id="org-b",
        )
    assert e1.value.code == "org_forbidden" and getattr(e1.value, "status", None) == 403
    # 同域发起 → pending
    row = s.restore_request(
        handle_hex=h,
        reason=reason,
        admin_username=_ADMIN,
        admin_sig_hex=sign(_ADMIN_SK, restore_msg(h, reason).encode()),
        operator_org_id="org-a",
    )
    rid = row["id"]
    _, aud_b_pub = generate_keypair()
    with pytest.raises(RaError) as e2:
        s.restore_countersign(
            request_id=rid,
            auditor_username="auditor-b-x",
            countersign_sig_hex=sign(_AUD_SK, restore_countersign_msg(h, reason).encode()),
            operator_org_id="org-b",
        )
    assert e2.value.code == "org_forbidden"
    assert "org-a" in str(e2.value) and "org-b" in str(e2.value)
    # 未执行：请求仍 pending、句柄仍在撤销集
    assert session.get(RestoreRequest, rid).status == "pending"
    assert session.scalar(select(Revocation).where(Revocation.handle_hex == h)) is not None, (
        "跨域复核被拒不得摘叶"
    )
    # 同域复核 → 执行
    out = s.restore_countersign(
        request_id=rid,
        auditor_username=_AUD,
        countersign_sig_hex=sign(_AUD_SK, restore_countersign_msg(h, reason).encode()),
        operator_org_id="org-a",
    )
    assert out["status"] == "executed"


# ---- HTTP 面（TestClient——授权边界=会话主体域恒传实证）----


@pytest.fixture()
def iso_client(tmp_path, monkeypatch):
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "fake")
    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(tmp_path))
    from pathlib import Path as _P

    monkeypatch.setenv("FZ_ZKSVC_DIR", str(_P(__file__).resolve().parents[2] / "zksvc"))
    db_file = tmp_path / "org_isolation.db"
    monkeypatch.setattr(db_mod, "_DB_PATH", db_file)
    engine = db_mod.create_engine(f"sqlite:///{db_file}")
    db_mod._engine = engine
    db_mod.SessionLocal = db_mod.sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    ra_router._reset_deps_cache()
    from app.authz import router as authz_router

    authz_router._DEPS = None
    with TestClient(create_app()) as c:
        yield c
    authz_router._DEPS = None
    ra_router._reset_deps_cache()


def _org_account(session_factory, username: str, org_id: str) -> None:
    s = session_factory()
    try:
        acc = s.query(Account).filter_by(username=username).one()
        acc.org_id = org_id
        s.commit()
    finally:
        s.close()


def _http_register(client: TestClient, username: str, sn: str, org_id="org-a") -> dict:
    _, pk = generate_keypair()
    body = {
        "username": username,
        "id_number": "110101199001011234",
        "cert_level": 3,
        "sn": sn,
        "user_pub_hex": pk,
        "class_id": 1,
    }
    if org_id != "org-a":
        body["org_id"] = org_id
    r = client.post("/ra/register", json=body)
    assert r.status_code == 200, r.text
    return r.json()["data"]


def test_org_isolation_http_admin_b_denied(iso_client):
    """HTTP 端到端负例：org-b 管理员会话对 org-a 凭证——签名吊销/按人吊销预览/
    已登录子凭证签发全 403 org_forbidden（双域判词）；匿名原像路径与本域管理员
    不受扰。红形态=修前跨域管理员 200 成功（缺口复现）。"""
    from tests.accounting import register_and_login, sign_revoke_body

    c = iso_client
    admin_b_sk = register_and_login(c, "admin_iso_b", "admin", "Admin-Iso-B-1")
    ca = TestClient(c.app)  # org-a 管理员独立 Jar（同 app 各自 Cookie）
    admin_a_sk = register_and_login(ca, "admin_iso_a", "admin", "Admin-Iso-A-1")
    _org_account(db_mod.SessionLocal, "admin_iso_b", "org-b")
    reg = _http_register(c, "pilot-iso-a", "FZ-SN-ISO-A")
    h = reg["master_cred_hash_hex"]
    # ① 匿名原像路径（用户侧流程）不误伤：照常 200
    _, holder_anon = generate_keypair()
    rs_anon = TestClient(c.app).post(
        "/ra/sub-credentials",
        json={
            "master_cred_hash_hex": h,
            "salt_hex": reg["salt_hex"],
            "id_number": "110101199001011234",
            "cert_level": 3,
            "sn": "FZ-SN-ISO-A",
            "holder_pub_hex": holder_anon,
        },
    )
    assert rs_anon.status_code == 200, rs_anon.text
    # ② org-b 管理员签名吊销 org-a 凭证 → 403 org_forbidden 双域
    epoch = c.get("/ra/revocation/snapshot").json()["data"]["epoch"] + 1
    r = c.post(
        "/ra/revoke",
        json={
            "master_cred_hash_hex": h,
            **sign_revoke_body(admin_b_sk, [h], "跨域越权吊销 HTTP 实弹", epoch),
        },
    )
    assert r.status_code == 403, r.text
    assert r.json()["code"] == "org_forbidden"
    assert "org-a" in r.json()["message"] and "org-b" in r.json()["message"]
    # ③ 按人吊销预览（两步式第一拍）→ 403
    rp = c.get("/ra/revoke/by-username/preview", params={"username": "pilot-iso-a"})
    assert rp.status_code == 403 and rp.json()["code"] == "org_forbidden", rp.text
    # ④ 已登录 org-b 管理员子凭证签发（原像正确的合法原像亦拒——域门在原像
    #    验证之前，越权探测面收窄）→ 403
    _, holder = generate_keypair()
    rs = c.post(
        "/ra/sub-credentials",
        json={
            "master_cred_hash_hex": h,
            "salt_hex": reg["salt_hex"],
            "id_number": "110101199001011234",
            "cert_level": 3,
            "sn": "FZ-SN-ISO-A",
            "holder_pub_hex": holder,
        },
    )
    assert rs.status_code == 403 and rs.json()["code"] == "org_forbidden", rs.text
    # ⑤ org-a 管理员（本域）同操作 → 200（负例不误伤正例）
    epoch2 = c.get("/ra/revocation/snapshot").json()["data"]["epoch"] + 1
    r2 = ca.post(
        "/ra/revoke",
        json={
            "master_cred_hash_hex": h,
            **sign_revoke_body(admin_a_sk, [h], "本域合规吊销 HTTP 实弹", epoch2),
        },
    )
    assert r2.status_code == 200, r2.text
    assert r2.json()["data"]["ledger_id"] > 0


def test_org_isolation_http_org_b_pair_allowed(iso_client):
    """HTTP 同域正例：org-b 管理员对 org-b 用户凭证吊销照常 200（e2e_cross_org
    [X4] 的 pytest 级镜像——域门不回退已交付的 B 域管理语义）。"""
    from tests.accounting import register_and_login, sign_revoke_body

    c = iso_client
    admin_b_sk = register_and_login(c, "admin_iso_b2", "admin", "Admin-Iso-B2-1")
    _org_account(db_mod.SessionLocal, "admin_iso_b2", "org-b")
    reg = _http_register(c, "pilot-iso-b", "FZ-SN-ISO-B", org_id="org-b")
    h = reg["master_cred_hash_hex"]
    s = db_mod.SessionLocal()
    try:
        u = s.query(User).filter_by(username="pilot-iso-b").one()
        assert u.org_id == "org-b"
    finally:
        s.close()
    epoch = c.get("/ra/revocation/snapshot").json()["data"]["epoch"] + 1
    r = c.post(
        "/ra/revoke",
        json={
            "master_cred_hash_hex": h,
            **sign_revoke_body(admin_b_sk, [h], "B 域管理员本域吊销 HTTP", epoch),
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["data"]["ledger_id"] > 0
