"""撤销端到端负例（R4 整改第二批 A-P1-2/B-P2-4）：B4 宣称「撤销即时」从
机制真升验证真——HTTP 全链分层防线断言。

覆盖（与 e2e_auth_full.py ⑫ 段同构，本文件=check.sh 门禁档[pytest]，
e2e=真链实弹档）：
  ① 吊销前：子凭证可签发+非成员见证可取（基线）
  ② /ra/revoke（X-RA-Token 门禁）→ 纪元根更迭
  ③ 旧子凭证 apply（旧撤销根）→ 409 stale_rev_root（受理门控廉价拦截）
  ④ 重取见证 → 403 revoked（RA fail-fast——不烧 2 分钟出证）
  ⑤ 二次签发子凭证 → 403 cred_revoked（RA 拒新签发）
"""

from __future__ import annotations

import json
import secrets

import pytest
from fastapi.testclient import TestClient

import app.db as db_mod
from app.crypto.sm2 import generate_keypair as _gen_kp
from app.main import create_app
from app.ra import router as ra_router
from app.ra.models import Base


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("FZ_CHAIN_ANCHOR", "fake")
    monkeypatch.setenv("FZ_ZK_CASES_DIR", str(tmp_path))
    # pin 门=真实 MANIFEST（uas/zksvc——受理门控④的 fail-closed 面不 stub）
    monkeypatch.setenv(
        "FZ_ZKSVC_DIR", str(__import__("pathlib").Path(__file__).resolve().parents[2] / "zksvc")
    )
    db_file = tmp_path / "revoke_e2e.db"
    monkeypatch.setattr(db_mod, "_DB_PATH", db_file)
    engine = db_mod.create_engine(f"sqlite:///{db_file}")
    db_mod._engine = engine
    db_mod.SessionLocal = db_mod.sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    ra_router._reset_deps_cache()
    # 用 router 真实 _deps()（fake 档：rev_root=本地 RA 镜像同源——撤销后根真实
    # 更迭；chain_pin 缺省 stub=None 跳过、nonce/sub 查重 stub——与 CI 档一致）
    from app.authz import router as authz_router

    authz_router._DEPS = None
    global _ADMIN_SK  # noqa: PLW0603  B1 契约：撤销签名钥（测试面）
    with TestClient(create_app()) as c:
        from tests.accounting import register_and_login

        _ADMIN_SK = register_and_login(c, "admin_rv", "admin", "Admin-Pass-1")
        yield c
    authz_router._DEPS = None
    ra_router._reset_deps_cache()


_ADMIN_SK = ""


def _mk_case_files() -> str:
    """出证产物目录（受理面前置完整性——gate 在 rev_root 检查处拦截，
    不消费实例内容；仍按真实三件形态落盘）。"""
    import os

    case_id = secrets.token_hex(8)
    zk_dir = os.environ["FZ_ZK_CASES_DIR"]
    d = os.path.join(zk_dir, case_id)
    os.makedirs(d, exist_ok=True)
    inst = ["00" * 32] * 26
    for name, blob in (
        ("proof.bin", b"proof"),
        ("verifier_param.bin", b"vp"),
    ):
        with open(os.path.join(d, name), "wb") as f:
            f.write(blob)
    with open(os.path.join(d, "instances.json"), "w", encoding="utf-8") as f:
        json.dump({"instances": inst}, f)
    return case_id


def test_revoke_layered_defense(client):
    holder_sk, holder_pk = _gen_kp()
    id_number = "110101199001011234"
    sn = "FZ-SN-REVOKE-" + secrets.token_hex(2)
    reg = client.post(
        "/ra/register",
        json={
            "username": "revoke-e2e-" + secrets.token_hex(3),
            "id_number": id_number,
            "cert_level": 3,
            "sn": sn,
            "user_pub_hex": holder_pk,
            "class_id": 1,
        },
    )
    assert reg.status_code == 200, reg.text
    cred = reg.json()["data"]

    sub_in = {
        "master_cred_hash_hex": cred["master_cred_hash_hex"],
        "salt_hex": cred["salt_hex"],
        "id_number": id_number,
        "cert_level": 3,
        "sn": sn,
        "holder_pub_hex": holder_pk,
    }
    # ① 吊销前基线：子凭证可签发+见证可取
    sub = client.post("/ra/sub-credentials", json=sub_in)
    assert sub.status_code == 200, sub.text
    sub = sub.json()["data"]
    w0 = client.get(f"/ra/revocation/witness?holder_pk_hex={holder_pk}")
    assert w0.status_code == 200 and "siblings_hex" in w0.json()["data"]
    old_root = client.get("/ra/revocation/snapshot").json()["data"]["root_hex"]

    # ② 吊销（机构管理员会话门禁；未登录=401 负例——独立无 Cookie 客户端）
    from fastapi.testclient import TestClient as _TC

    from tests.accounting import sign_revoke_body

    anon = _TC(client.app)
    assert (
        anon.post(
            "/ra/revoke", json={"master_cred_hash_hex": cred["master_cred_hash_hex"]}
        ).status_code
        == 401
    )
    # B1 契约：无签名/短理由/纪元错=信封语义拒（先于执行）
    for bad_body in (
        {"master_cred_hash_hex": cred["master_cred_hash_hex"], "reason": "e2e 负例"},  # 无签名
        {
            "master_cred_hash_hex": cred["master_cred_hash_hex"],
            "reason": "短",
            **sign_revoke_body(_ADMIN_SK, [cred["master_cred_hash_hex"]], "短", 1),
        },  # 理由 <4 字
    ):
        r_bad = client.post("/ra/revoke", json=bad_body)
        assert r_bad.status_code in (400, 401), r_bad.text
        assert r_bad.json()["code"] in ("bad_sig", "reason_required", "bad_epoch"), r_bad.text
    handles = [cred["master_cred_hash_hex"]]
    epoch = client.get("/ra/revocation/snapshot").json()["data"]["epoch"] + 1
    rv = client.post(
        "/ra/revoke",
        json={
            "master_cred_hash_hex": handles[0],
            **sign_revoke_body(_ADMIN_SK, handles, "e2e 负例", epoch),
        },
    )
    assert rv.status_code == 200, rv.text
    new_root = rv.json()["data"]["root_hex"]
    assert new_root != old_root, "撤销后纪元根必须更迭"
    assert rv.json()["data"]["ledger_id"] >= 1, "撤销动作须入 append-only 台账"

    # ③ 旧子凭证以吊销前撤销根申请 → 409 stale_rev_root（诚实滞后者）
    apply_body = {
        "session_pk_hex": holder_pk,
        "sub_cred_message_hex": sub["message_hex"],
        "sub_sig_hex": sub["sig_hex"],
        "sub_cred_hash_hex": sub["sub_cred_hash_hex"],
        "nonce_hex": secrets.token_bytes(16).hex(),
        "plan_hash_hex": secrets.token_bytes(32).hex(),
        "class_id": 1,
        "case_id": _mk_case_files(),
        "rev_root_hex": old_root,
        "t_start": 1900000000,
        "t_end": 1900003600,
    }
    resp = client.post("/authz/apply", json=apply_body)
    assert resp.status_code == 409, resp.text
    assert resp.json()["code"] == "stale_rev_root"

    # ④ 重取见证 → 403 revoked（fail-fast：不让申请烧完出证后死于电路）
    w1 = client.get(f"/ra/revocation/witness?holder_pk_hex={holder_pk}")
    assert w1.status_code == 403
    assert w1.json()["code"] == "revoked"

    # ⑤ 二次签发 → 403 cred_revoked（撤销后拒新子凭证）
    sub2 = client.post("/ra/sub-credentials", json=sub_in)
    assert sub2.status_code == 403
    assert sub2.json()["code"] == "cred_revoked"
